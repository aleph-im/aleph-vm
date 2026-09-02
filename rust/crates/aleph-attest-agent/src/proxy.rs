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

/// Upper bound on the decoded nonce accepted by the attestation endpoint.
///
/// The nonce is hashed into `report_data` (see `aleph_tee::report_data`), so
/// its length carries no security value beyond the entropy a caller wants to
/// commit; 32 bytes is the conventional size, 128 leaves generous room. The
/// cap only exists so a caller cannot make the agent hex-decode and hash an
/// arbitrarily long query string.
pub const MAX_NONCE_LEN: usize = 128;

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
    // Bound the nonce before decoding so an oversized query string is
    // rejected without being hex-decoded first.
    if query.nonce.len() > MAX_NONCE_LEN * 2 {
        return HttpResponse::BadRequest().json(serde_json::json!({
            "error": format!("nonce too long: at most {MAX_NONCE_LEN} bytes ({} hex chars)", MAX_NONCE_LEN * 2)
        }));
    }
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
            // The full error (backend, device path, firmware status) stays in
            // the guest log; the client only learns that the report failed.
            tracing::error!("attestation report failed: {e:#}");
            HttpResponse::InternalServerError()
                .json(serde_json::json!({"error": "attestation report failed"}))
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
    // Build the upstream URL preserving path and query string. Trim any
    // trailing slash on the configured upstream so it does not collide with the
    // leading slash of the request path (`http://host//path`).
    let base = state.upstream.trim_end_matches('/');
    let upstream_url = if let Some(qs) = req.uri().query() {
        format!("{base}{path}?{qs}", path = req.uri().path())
    } else {
        format!("{base}{path}", path = req.uri().path())
    };

    // Build the proxied request.
    // actix-web uses http 0.2 Method, reqwest uses http 1.x Method;
    // convert via the string representation.
    let method = reqwest::Method::from_bytes(req.method().as_str().as_bytes())
        .unwrap_or(reqwest::Method::GET);
    let mut proxy_req = state.http_client.request(method, &upstream_url);

    // Forward end-to-end headers only. Skip Host (reqwest sets it), all
    // hop-by-hop headers, and Content-Length: relaying a client
    // Transfer-Encoding or Content-Length next to reqwest's own body framing is
    // a request-smuggling / desync vector, so we let reqwest frame the request
    // itself from the actual body below.
    for (name, value) in req.headers() {
        if name != actix_web::http::header::HOST
            && !is_hop_by_hop(name.as_str())
            && !name.as_str().eq_ignore_ascii_case("content-length")
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
            // headers (e.g. Transfer-Encoding) and Content-Length lets actix
            // frame the response from the buffered body below, avoiding a
            // Content-Length / Transfer-Encoding desync to the client.
            for (name, value) in upstream_resp.headers() {
                if !is_hop_by_hop(name.as_str())
                    && !name.as_str().eq_ignore_ascii_case("content-length")
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
            // Same split as above: the reqwest error names the upstream
            // address and the failure detail, which belong in the log only.
            tracing::error!("proxy request to {upstream_url} failed: {e:#}");
            HttpResponse::BadGateway().json(serde_json::json!({"error": "upstream unreachable"}))
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use actix_web::body::to_bytes;
    use actix_web::http::StatusCode;
    use aleph_tee::types::{AttestationReport, TeeType};
    use anyhow::Result;

    /// Echoes `report_data` into the blob so the test can see what was bound.
    struct MockBackend;

    impl TeeBackend for MockBackend {
        fn tee_type(&self) -> TeeType {
            TeeType::SevSnp
        }

        fn get_report(&self, report_data: &[u8; 64]) -> Result<AttestationReport> {
            Ok(AttestationReport {
                tee_type: TeeType::SevSnp,
                data: report_data.to_vec(),
            })
        }

        fn parse_report(&self, _raw: &[u8]) -> Result<AttestationReport> {
            unimplemented!("not needed for these tests")
        }
    }

    fn state() -> web::Data<AppState> {
        web::Data::new(AppState {
            backend: Arc::new(MockBackend),
            served_public_key_raw: vec![0x42; 97],
            upstream: "http://127.0.0.1:1".to_string(),
            http_client: reqwest::Client::new(),
        })
    }

    /// The plain-HTTP local mode runs the agent on aleph-tee's NoTeeBackend:
    /// the attestation endpoint must fail closed with a 500 (never a
    /// fabricated report).
    fn no_tee_state() -> web::Data<AppState> {
        web::Data::new(AppState {
            backend: Arc::new(aleph_tee::none::NoTeeBackend::new()),
            served_public_key_raw: Vec::new(),
            upstream: "http://127.0.0.1:1".to_string(),
            http_client: reqwest::Client::new(),
        })
    }

    #[actix_web::test]
    async fn attestation_endpoint_fails_closed_without_a_tee() {
        let resp = attestation_endpoint(
            no_tee_state(),
            web::Query(AttestationQuery {
                nonce: "ab".to_string(),
            }),
        )
        .await;
        assert_eq!(resp.status(), StatusCode::INTERNAL_SERVER_ERROR);
    }

    async fn attest(nonce: &str) -> (StatusCode, String) {
        let resp = attestation_endpoint(
            state(),
            web::Query(AttestationQuery {
                nonce: nonce.to_string(),
            }),
        )
        .await;
        let status = resp.status();
        let body = to_bytes(resp.into_body()).await.expect("body");
        (status, String::from_utf8_lossy(&body).into_owned())
    }

    #[actix_web::test]
    async fn nonce_at_the_cap_is_accepted() {
        let (status, _) = attest(&"ab".repeat(MAX_NONCE_LEN)).await;
        assert_eq!(status, StatusCode::OK);
    }

    #[actix_web::test]
    async fn nonce_over_the_cap_is_rejected_before_decoding() {
        // One byte over the cap, and deliberately NOT valid hex: the length
        // check must fire first, so the error names the bound, not the hex.
        let too_long = format!("{}zz", "ab".repeat(MAX_NONCE_LEN));
        let (status, body) = attest(&too_long).await;
        assert_eq!(status, StatusCode::BAD_REQUEST);
        assert!(body.contains("nonce too long"), "{body}");
    }

    #[actix_web::test]
    async fn invalid_hex_nonce_is_rejected() {
        let (status, body) = attest("zz").await;
        assert_eq!(status, StatusCode::BAD_REQUEST);
        assert!(body.contains("invalid hex nonce"), "{body}");
    }
}
