use std::sync::Arc;

use actix_web::web::{self, Bytes};
use actix_web::{HttpRequest, HttpResponse};
use aleph_tee::traits::TeeBackend;
use serde::Deserialize;

use crate::attestation::get_fresh_report;

/// Hop-by-hop headers (RFC 7230 6.1, plus the `Proxy-*` family). These are
/// connection-scoped and MUST NOT be forwarded by a proxy: relaying a client's
/// `Transfer-Encoding` alongside reqwest's own `Content-Length`, for instance,
/// is a request-smuggling / response-desync vector. Compared case-insensitively.
const HOP_BY_HOP_HEADERS: &[&str] = &[
    "connection",
    "keep-alive",
    "transfer-encoding",
    "te",
    "trailer",
    "upgrade",
    "proxy-authenticate",
    "proxy-authorization",
    "proxy-connection",
];

/// Returns true if `name` is a hop-by-hop header that must not cross the proxy.
fn is_hop_by_hop(name: &str) -> bool {
    HOP_BY_HOP_HEADERS
        .iter()
        .any(|h| name.eq_ignore_ascii_case(h))
}

/// Shared application state for the attestation agent.
pub struct AppState {
    /// TEE backend used to generate attestation reports.
    pub backend: Arc<dyn TeeBackend>,
    /// Raw bytes of the agent's served TLS public key. The fresh-attestation
    /// endpoint binds this into every report (channel binding), so a relayed
    /// fresh report cannot be reused against a different key.
    pub served_public_key_raw: Vec<u8>,
    /// Upstream application URL (e.g., "http://127.0.0.1:8080").
    pub upstream: String,
    /// HTTP client for proxying requests to the upstream application.
    pub http_client: reqwest::Client,
}

/// Query parameters for the attestation endpoint.
#[derive(Deserialize)]
pub struct AttestationQuery {
    /// Hex-encoded nonce to bind to the attestation report.
    pub nonce: String,
}

/// GET `/.well-known/attestation?nonce=<hex>`
///
/// Decodes the hex nonce and requests a fresh attestation report bound to BOTH
/// the agent's served TLS public key AND the nonce (canonical `fresh_report_data`
/// scheme). Binding the served key prevents a relayed fresh report from being
/// reused for a different TLS channel, and the domain tag prevents any collision
/// with the key-bound report scheme. Returns the report as JSON.
pub async fn attestation_endpoint(
    state: web::Data<AppState>,
    query: web::Query<AttestationQuery>,
) -> HttpResponse {
    // Decode the hex nonce.
    let nonce = match hex::decode(&query.nonce) {
        Ok(n) => n,
        Err(e) => {
            return HttpResponse::BadRequest()
                .json(serde_json::json!({"error": format!("invalid hex nonce: {e}")}));
        }
    };

    // Request a fresh report bound to the agent's real served key and the nonce.
    match get_fresh_report(state.backend.as_ref(), &state.served_public_key_raw, &nonce) {
        Ok(report) => HttpResponse::Ok().json(report),
        Err(e) => {
            tracing::error!("attestation report failed: {e:#}");
            HttpResponse::InternalServerError()
                .json(serde_json::json!({"error": format!("attestation failed: {e:#}")}))
        }
    }
}

/// Default handler: reverse-proxy all requests to the upstream application.
///
/// Forwards the HTTP method, path, query string, headers, and body to the
/// upstream URL, then returns the upstream's response to the caller.
pub async fn proxy_handler(
    state: web::Data<AppState>,
    req: HttpRequest,
    body: Bytes,
) -> HttpResponse {
    // Build the upstream URL preserving path and query string.
    let upstream_url = if let Some(qs) = req.uri().query() {
        format!("{}{path}?{qs}", state.upstream, path = req.uri().path())
    } else {
        format!("{}{path}", state.upstream, path = req.uri().path())
    };

    // Build the proxied request.
    // actix-web uses http 0.2 Method, reqwest uses http 1.x Method;
    // convert via the string representation.
    let method = reqwest::Method::from_bytes(req.method().as_str().as_bytes())
        .unwrap_or(reqwest::Method::GET);
    let mut proxy_req = state.http_client.request(method, &upstream_url);

    // Forward end-to-end headers only. Skip Host (reqwest sets it) and all
    // hop-by-hop headers: relaying a client Transfer-Encoding next to reqwest's
    // own Content-Length is a request-smuggling / desync vector, so we let
    // reqwest frame the request itself.
    for (name, value) in req.headers() {
        if name != actix_web::http::header::HOST
            && !is_hop_by_hop(name.as_str())
            && let Ok(v) = value.to_str()
        {
            proxy_req = proxy_req.header(name.as_str(), v);
        }
    }

    proxy_req = proxy_req.body(body.to_vec());

    // Send the proxied request.
    match proxy_req.send().await {
        Ok(upstream_resp) => {
            let status = actix_web::http::StatusCode::from_u16(upstream_resp.status().as_u16())
                .unwrap_or(actix_web::http::StatusCode::BAD_GATEWAY);

            let mut resp = HttpResponse::build(status);

            // Forward end-to-end response headers only. Dropping hop-by-hop
            // headers (e.g. Transfer-Encoding) lets actix frame the response and
            // avoids a Content-Length / Transfer-Encoding desync to the client.
            for (name, value) in upstream_resp.headers() {
                if !is_hop_by_hop(name.as_str())
                    && let Ok(v) = value.to_str()
                {
                    resp.insert_header((name.as_str(), v));
                }
            }

            match upstream_resp.bytes().await {
                Ok(resp_body) => resp.body(resp_body),
                Err(e) => {
                    tracing::error!("failed to read upstream response body: {e:#}");
                    HttpResponse::BadGateway()
                        .json(serde_json::json!({"error": "failed to read upstream response"}))
                }
            }
        }
        Err(e) => {
            tracing::error!("proxy request to {upstream_url} failed: {e:#}");
            HttpResponse::BadGateway()
                .json(serde_json::json!({"error": format!("upstream unreachable: {e:#}")}))
        }
    }
}
