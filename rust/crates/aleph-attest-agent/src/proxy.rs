use std::sync::Arc;
use std::time::Duration;

use actix_web::body::{BodyStream, SizedStream};
use actix_web::http::StatusCode;
use actix_web::http::header::{CONTENT_LENGTH, HOST, TRANSFER_ENCODING};
use actix_web::web::{self, Bytes};
use actix_web::{HttpRequest, HttpResponse};
use aleph_tee::report_data::gpu_nonce;
use aleph_tee::traits::TeeBackend;
use futures_util::{Stream, StreamExt};
use serde::{Deserialize, Serialize};

use crate::attestation::get_fresh_report;
use crate::gpu::{GpuEvidence, GpuEvidenceSource};

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
    /// GPU evidence source and boot claims; `None` on runtimes without a GPU.
    pub gpu: Option<Arc<GpuState>>,
}

/// GPU attestation state, present only when init handed the agent the
/// claims its boot-time verification produced (`--gpu-claims`) and the
/// collector command (`--gpu-collector`).
pub struct GpuState {
    pub source: Box<dyn GpuEvidenceSource>,
    /// The per-GPU claims NVIDIA's local verifier produced at boot. Served
    /// as information for the client; nothing in it replaces a client-side
    /// cryptographic check.
    pub boot_claims: serde_json::Value,
    /// One SPDM exchange at a time: concurrent callers queue. In its own `Arc`
    /// so the guard can move into the blocking task that runs the collector.
    pub lock: Arc<tokio::sync::Mutex<()>>,
    /// How long a caller queues for the exchange before being told to
    /// retry. A collection takes well under a second, so a queue this deep
    /// means the collector is wedged; failing fast keeps a pile-up from
    /// holding worker threads for the whole collector timeout each.
    pub lock_wait: Duration,
}

/// Default for [`GpuState::lock_wait`].
pub const GPU_LOCK_WAIT: Duration = Duration::from_secs(10);

/// The `Retry-After` a busy GPU route advertises, in whole seconds: one more
/// `lock_wait`, derived so a tuned wait cannot advertise a stale number.
/// Rounded up and never zero, or the client would come straight back.
fn retry_after_secs(lock_wait: Duration) -> u64 {
    let rounded_up = lock_wait.as_secs() + u64::from(lock_wait.subsec_nanos() > 0);
    rounded_up.max(1)
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
    let nonce = match decode_nonce(&query.nonce) {
        Ok(n) => n,
        Err(resp) => return resp,
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

#[derive(Serialize)]
pub struct GpuAttestationResponse<'a> {
    pub tee_type: &'static str,
    pub client_nonce: &'a str,
    pub gpus: Vec<GpuEvidence>,
    /// Borrowed from the agent's state: the same document for the life of the
    /// process, so a response serializes it in place.
    pub boot_claims: &'a serde_json::Value,
}

/// Decode and bound the hex nonce shared by both attestation routes.
fn decode_nonce(nonce_hex: &str) -> Result<Vec<u8>, HttpResponse> {
    if nonce_hex.len() > MAX_NONCE_LEN * 2 {
        return Err(HttpResponse::BadRequest().json(serde_json::json!({
            "error": format!("nonce too long: at most {MAX_NONCE_LEN} bytes ({} hex chars)", MAX_NONCE_LEN * 2)
        })));
    }
    hex::decode(nonce_hex).map_err(|e| {
        HttpResponse::BadRequest()
            .json(serde_json::json!({"error": format!("invalid hex nonce: {e}")}))
    })
}

/// GET `/.well-known/attestation/gpu?nonce=<hex>`
///
/// Returns fresh GPU evidence for every attached GPU, each answering the
/// SPDM nonce `gpu_nonce(served_key, client_nonce)`. The client recomputes
/// that nonce, so a report relayed from another channel or another request
/// cannot match. Served over the same attested TLS channel as the SNP
/// report, which is what makes the document guest-authored.
pub async fn gpu_attestation_endpoint(
    state: web::Data<AppState>,
    query: web::Query<AttestationQuery>,
) -> HttpResponse {
    let Some(gpu) = state.gpu.as_ref() else {
        return HttpResponse::NotFound()
            .json(serde_json::json!({"error": "no gpu attestation on this runtime"}));
    };
    let client_nonce = match decode_nonce(&query.nonce) {
        Ok(n) => n,
        Err(resp) => return resp,
    };
    let nonce = gpu_nonce(&state.served_public_key_raw, &client_nonce);
    let Ok(serialized) =
        tokio::time::timeout(gpu.lock_wait, Arc::clone(&gpu.lock).lock_owned()).await
    else {
        return HttpResponse::ServiceUnavailable()
            .insert_header(("Retry-After", retry_after_secs(gpu.lock_wait).to_string()))
            .json(serde_json::json!({"error": "gpu attestation busy"}));
    };
    // The collector is a blocking child process, so it runs off the async
    // workers, and the guard travels with it: a client that disconnects must
    // not release the GPU while the driver is still in the exchange.
    let gpu_for_task = Arc::clone(gpu);
    let collected = web::block(move || {
        let _serialized = serialized;
        gpu_for_task.source.collect(&nonce)
    })
    .await;
    match collected {
        Ok(Ok(gpus)) => HttpResponse::Ok().json(GpuAttestationResponse {
            tee_type: "nvidia-cc",
            client_nonce: &query.nonce,
            gpus,
            boot_claims: &gpu.boot_claims,
        }),
        Ok(Err(e)) => {
            tracing::error!("gpu evidence collection failed: {e:#}");
            HttpResponse::InternalServerError()
                .json(serde_json::json!({"error": "gpu evidence collection failed"}))
        }
        Err(e) => {
            tracing::error!("gpu evidence task failed: {e:#}");
            HttpResponse::InternalServerError()
                .json(serde_json::json!({"error": "gpu evidence collection failed"}))
        }
    }
}

/// The body length a message declares, or `None` when it is framed some other
/// way: a `Transfer-Encoding` makes any `Content-Length` next to it meaningless
/// (RFC 7230 3.3.3), and so does one that does not parse.
fn declared_content_length(content_length: Option<&[u8]>, chunked: bool) -> Option<u64> {
    if chunked {
        return None;
    }
    std::str::from_utf8(content_length?)
        .ok()?
        .trim()
        .parse()
        .ok()
}

/// actix hands the request body to the handler as a `!Send` stream while
/// reqwest wants a `Send` body: pump it through a channel from a task on this
/// worker thread. Dropping the reqwest side stops the pump.
fn send_bridge(
    mut payload: web::Payload,
) -> impl Stream<Item = Result<Bytes, actix_web::error::PayloadError>> + Send {
    let (tx, mut rx) = tokio::sync::mpsc::channel(1);
    actix_web::rt::spawn(async move {
        while let Some(chunk) = payload.next().await {
            if tx.send(chunk).await.is_err() {
                break;
            }
        }
    });
    futures_util::stream::poll_fn(move |cx| rx.poll_recv(cx))
}

/// Default handler: reverse-proxy all requests to the upstream application.
///
/// Forwards the HTTP method, path, query string, headers, and body to the
/// upstream URL, then returns the upstream's response to the caller. Both
/// bodies are relayed as they arrive, never buffered.
pub async fn proxy_handler(
    state: web::Data<AppState>,
    req: HttpRequest,
    payload: web::Payload,
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

    // Forward end-to-end headers only. Skip Host (reqwest sets it) and the
    // hop-by-hop set. Content-Length is not copied but re-derived from the
    // client's framing below, so a client Transfer-Encoding can never travel
    // next to a length (request-smuggling / desync vector).
    for (name, value) in req.headers() {
        if name != HOST
            && name != CONTENT_LENGTH
            && !is_hop_by_hop(name.as_str())
            && let Ok(v) = value.to_str()
        {
            proxy_req = proxy_req.header(name.as_str(), v);
        }
    }

    // Stream the request body through instead of extracting it: `web::Bytes`
    // would hold uploads in agent memory and cap them at actix's 256 KiB
    // default. With the client's own Content-Length reqwest frames the body
    // by that length; a chunked client body stays chunked.
    let chunked = req.headers().contains_key(TRANSFER_ENCODING);
    let content_length = declared_content_length(
        req.headers().get(CONTENT_LENGTH).map(|v| v.as_bytes()),
        chunked,
    );
    if let Some(len) = content_length {
        proxy_req = proxy_req.header("content-length", len);
    }
    if chunked || content_length.is_some_and(|len| len > 0) {
        proxy_req = proxy_req.body(reqwest::Body::wrap_stream(send_bridge(payload)));
    }

    // Send the proxied request.
    match proxy_req.send().await {
        Ok(upstream_resp) => {
            let status = StatusCode::from_u16(upstream_resp.status().as_u16())
                .unwrap_or(StatusCode::BAD_GATEWAY);

            let mut resp = HttpResponse::build(status);

            // Forward end-to-end response headers only; Content-Length is
            // re-applied below from the upstream's framing, so it can never
            // sit next to a chunked body.
            for (name, value) in upstream_resp.headers() {
                if !is_hop_by_hop(name.as_str())
                    && !name.as_str().eq_ignore_ascii_case("content-length")
                    && let Ok(v) = value.to_str()
                {
                    resp.insert_header((name.as_str(), v));
                }
            }

            // Relay chunks as the upstream produces them: buffering the whole
            // body would hold back server-sent events (token streaming) until
            // the upstream closes the response. The stream goes in as a body,
            // not through `streaming()`, which invents a Content-Type the
            // upstream never sent. Once the status is committed a mid-body
            // upstream error can only abort the connection; actix logs it.
            let content_length = declared_content_length(
                upstream_resp
                    .headers()
                    .get("content-length")
                    .map(|v| v.as_bytes()),
                upstream_resp.headers().contains_key("transfer-encoding"),
            );
            let body = upstream_resp.bytes_stream();
            if status == StatusCode::NO_CONTENT || status == StatusCode::NOT_MODIFIED {
                // Even an empty stream body makes actix's h1 encoder write a
                // chunked terminator after a head that announced no framing,
                // which desyncs the keep-alive connection.
                resp.finish()
            } else if let Some(len) = content_length {
                // Keep the upstream's exact framing rather than re-chunking a
                // sized body: the client keeps its length, and HTTP/1.0
                // clients keep working.
                resp.no_chunking(len);
                resp.body(SizedStream::new(len, body))
            } else {
                resp.body(BodyStream::new(body))
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
    use aleph_tee::types::{AttestationReport, TeeType};
    use anyhow::Result;
    use std::sync::atomic::{AtomicUsize, Ordering};
    use tokio::io::{AsyncReadExt, AsyncWriteExt};
    use tokio::net::{TcpListener, TcpStream};
    use tokio::sync::oneshot;

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

    fn app_state(
        backend: Arc<dyn TeeBackend>,
        served_public_key_raw: Vec<u8>,
        upstream: &str,
        gpu: Option<Arc<GpuState>>,
    ) -> web::Data<AppState> {
        web::Data::new(AppState {
            backend,
            served_public_key_raw,
            upstream: upstream.to_string(),
            http_client: reqwest::Client::new(),
            gpu,
        })
    }

    fn state() -> web::Data<AppState> {
        state_with_upstream("http://127.0.0.1:1")
    }

    fn state_with_upstream(upstream: &str) -> web::Data<AppState> {
        app_state(Arc::new(MockBackend), vec![0x42; 97], upstream, None)
    }

    const SSE_HEAD_AND_FIRST_CHUNK: &[u8] =
        b"HTTP/1.1 200 OK\r\ncontent-type: text/event-stream\r\n\
        transfer-encoding: chunked\r\n\r\n5\r\nfirst\r\n";

    /// Reads one request off `sock`: the head, then as many body bytes as its
    /// Content-Length announces. `None` when the peer closes before a head.
    async fn read_request(sock: &mut TcpStream) -> Option<(String, usize)> {
        let mut buf = Vec::new();
        let mut chunk = [0u8; 4096];
        while !buf.windows(4).any(|w| w == b"\r\n\r\n") {
            let n = sock.read(&mut chunk).await.ok()?;
            if n == 0 {
                return None;
            }
            buf.extend_from_slice(&chunk[..n]);
        }
        let head_end = buf.windows(4).position(|w| w == b"\r\n\r\n").expect("head") + 4;
        let head = String::from_utf8_lossy(&buf[..head_end]).into_owned();
        let declared = head
            .lines()
            .find_map(|l| {
                l.to_ascii_lowercase()
                    .strip_prefix("content-length:")?
                    .trim()
                    .parse()
                    .ok()
            })
            .unwrap_or(0usize);
        let mut body_len = buf.len() - head_end;
        while body_len < declared {
            let n = sock.read(&mut chunk).await.ok()?;
            if n == 0 {
                break;
            }
            body_len += n;
        }
        Some((head, body_len))
    }

    async fn upstream_listener() -> (TcpListener, String) {
        let listener = TcpListener::bind("127.0.0.1:0").await.expect("bind");
        let addr = listener.local_addr().expect("addr");
        (listener, format!("http://{addr}"))
    }

    /// A raw HTTP/1.1 upstream that answers one request with `head` (status
    /// line, headers and any leading body bytes), waits for `release`, then
    /// sends `tail` (if any) and closes the connection.
    async fn raw_upstream(
        head: &'static [u8],
        tail: Option<&'static [u8]>,
    ) -> (String, oneshot::Sender<()>) {
        let (listener, url) = upstream_listener().await;
        let (release, released) = oneshot::channel::<()>();
        tokio::spawn(async move {
            let (mut sock, _) = listener.accept().await.expect("accept");
            read_request(&mut sock).await.expect("request head");
            sock.write_all(head).await.expect("write head");
            let _ = released.await;
            if let Some(tail) = tail {
                sock.write_all(tail).await.expect("write tail");
            }
        });
        (url, release)
    }

    /// A raw HTTP/1.1 upstream serving `responses` in order, one per request,
    /// across however many connections the proxy's client opens.
    async fn scripted_upstream(responses: Vec<&'static [u8]>) -> String {
        let (listener, url) = upstream_listener().await;
        let responses = Arc::new(std::sync::Mutex::new(std::collections::VecDeque::from(
            responses,
        )));
        tokio::spawn(async move {
            loop {
                let (mut sock, _) = listener.accept().await.expect("accept");
                let responses = Arc::clone(&responses);
                tokio::spawn(async move {
                    while read_request(&mut sock).await.is_some() {
                        let next = responses.lock().expect("lock").pop_front();
                        let Some(response) = next else { return };
                        sock.write_all(response).await.expect("write response");
                    }
                });
            }
        });
        url
    }

    /// A raw upstream that drains one request and reports what it saw: the
    /// request head and how many body bytes followed it.
    async fn counting_upstream() -> (String, oneshot::Receiver<(String, usize)>) {
        let (listener, url) = upstream_listener().await;
        let (report, seen) = oneshot::channel();
        tokio::spawn(async move {
            let (mut sock, _) = listener.accept().await.expect("accept");
            let request = read_request(&mut sock).await.expect("request");
            sock.write_all(b"HTTP/1.1 200 OK\r\ncontent-length: 0\r\n\r\n")
                .await
                .expect("write response");
            let _ = report.send(request);
        });
        (url, seen)
    }

    /// Drives the handler for one bodiless POST, as the App would.
    async fn proxy_response(upstream: &str) -> HttpResponse {
        use actix_web::FromRequest;

        let (req, mut inner) = actix_web::test::TestRequest::post()
            .uri("/v1/chat/completions")
            .to_http_parts();
        let payload = web::Payload::from_request(&req, &mut inner)
            .await
            .expect("payload extractor");
        proxy_handler(state_with_upstream(upstream), req, payload).await
    }

    /// Proxies one POST and returns the status, the body, and its first chunk,
    /// all under one deadline: a buffering proxy blocks inside the handler.
    async fn proxy_first_chunk(
        upstream: &str,
    ) -> (
        StatusCode,
        std::pin::Pin<Box<actix_web::body::BoxBody>>,
        Option<Result<Bytes, Box<dyn std::error::Error>>>,
    ) {
        use actix_web::body::MessageBody;

        tokio::time::timeout(Duration::from_secs(5), async {
            let resp = proxy_response(upstream).await;
            let status = resp.status();
            let mut body = Box::pin(resp.into_body());
            let first = std::future::poll_fn(|cx| body.as_mut().poll_next(cx)).await;
            (status, body, first)
        })
        .await
        .expect("the first chunk must arrive while the upstream is still open")
    }

    /// Server-sent events (token streaming) must reach the client as the
    /// upstream writes them, not once the upstream closes the response.
    #[actix_web::test]
    async fn proxy_relays_body_chunks_before_the_upstream_finishes() {
        let (upstream, release) =
            raw_upstream(SSE_HEAD_AND_FIRST_CHUNK, Some(b"4\r\nlast\r\n0\r\n\r\n")).await;
        let (status, body, first) = proxy_first_chunk(&upstream).await;
        assert_eq!(status, StatusCode::OK);
        let first = first.expect("body ended early").expect("body error");
        assert_eq!(&first[..], b"first");

        release.send(()).expect("upstream task gone");
        let rest = to_bytes(body).await.expect("rest of body");
        assert_eq!(&rest[..], b"last");
    }

    /// A sized upstream body keeps its Content-Length across the proxy
    /// instead of being re-framed as chunked.
    #[actix_web::test]
    async fn sized_upstream_body_keeps_its_content_length() {
        let (upstream, _release) = raw_upstream(
            b"HTTP/1.1 200 OK\r\ncontent-type: text/plain\r\ncontent-length: 5\r\n\r\nhello",
            None,
        )
        .await;
        let resp = proxy_response(&upstream).await;
        assert_eq!(resp.status(), StatusCode::OK);
        let content_length = resp.headers().get(CONTENT_LENGTH).expect("content-length");
        assert_eq!(content_length, "5");
        assert!(resp.headers().get(TRANSFER_ENCODING).is_none());
        let body = to_bytes(resp.into_body()).await.expect("body");
        assert_eq!(&body[..], b"hello");
    }

    /// The proxy relays the upstream's headers; it does not invent a
    /// Content-Type for a response that came without one.
    #[actix_web::test]
    async fn no_content_type_is_invented_for_the_upstream() {
        let (upstream, _release) =
            raw_upstream(b"HTTP/1.1 200 OK\r\ncontent-length: 2\r\n\r\nok", None).await;
        let resp = proxy_response(&upstream).await;
        assert_eq!(resp.status(), StatusCode::OK);
        assert!(
            resp.headers()
                .get(actix_web::http::header::CONTENT_TYPE)
                .is_none(),
            "{:?}",
            resp.headers()
        );
    }

    /// Request bodies stream to the upstream with the client's own length,
    /// not through the `web::Bytes` extractor and its 256 KiB cap.
    #[actix_web::test]
    async fn request_bodies_stream_to_the_upstream_uncapped() {
        let (upstream, seen) = counting_upstream().await;
        let app = actix_web::test::init_service(
            actix_web::App::new()
                .app_data(state_with_upstream(&upstream))
                .default_service(web::to(proxy_handler)),
        )
        .await;
        let body_len = 1024 * 1024;
        let req = actix_web::test::TestRequest::post()
            .uri("/v1/chat/completions")
            .set_payload(vec![b'x'; body_len])
            .to_request();
        let resp = actix_web::test::call_service(&app, req).await;
        assert_eq!(resp.status(), StatusCode::OK);

        let (head, received) = seen.await.expect("upstream saw the request");
        assert_eq!(received, body_len);
        let head = head.to_ascii_lowercase();
        assert!(
            head.contains(&format!("content-length: {body_len}\r\n")),
            "{head}"
        );
        assert!(!head.contains("transfer-encoding"), "{head}");
    }

    /// Runs the proxy behind a real actix server on a loopback port, so a
    /// test can look at the bytes on the wire.
    async fn serve_proxy(upstream: &str) -> (std::net::SocketAddr, actix_web::dev::ServerHandle) {
        let state = state_with_upstream(upstream);
        let server = actix_web::HttpServer::new(move || {
            actix_web::App::new()
                .app_data(state.clone())
                .default_service(web::to(proxy_handler))
        })
        .workers(1)
        .disable_signals()
        .bind(("127.0.0.1", 0))
        .expect("bind proxy");
        let addr = server.addrs()[0];
        let server = server.run();
        let handle = server.handle();
        actix_web::rt::spawn(server);
        (addr, handle)
    }

    async fn raw_request(addr: std::net::SocketAddr) -> TcpStream {
        TcpStream::connect(addr).await.expect("connect to proxy")
    }

    /// Reads from `sock` until the bytes read contain `marker`.
    async fn read_until(sock: &mut TcpStream, marker: &[u8]) -> Vec<u8> {
        tokio::time::timeout(Duration::from_secs(5), async {
            let mut out = Vec::new();
            let mut buf = [0u8; 4096];
            while !out.windows(marker.len()).any(|w| w == marker) {
                let n = sock.read(&mut buf).await.expect("read");
                assert!(n > 0, "connection closed before {marker:?}: {out:?}");
                out.extend_from_slice(&buf[..n]);
            }
            out
        })
        .await
        .unwrap_or_else(|_| panic!("timed out waiting for {marker:?}"))
    }

    /// Reads until the proxy closes the connection; a reset counts as closed.
    async fn read_to_close(sock: &mut TcpStream) -> Vec<u8> {
        tokio::time::timeout(Duration::from_secs(5), async {
            let mut out = Vec::new();
            let _ = sock.read_to_end(&mut out).await;
            out
        })
        .await
        .expect("the proxy must close the connection")
    }

    /// Once the status is committed, an upstream that dies mid-body can only
    /// surface on the wire as a truncated response: the connection closes
    /// without the chunked terminator, never with a 502 and never as if the
    /// body were complete.
    #[actix_web::test]
    async fn upstream_failing_mid_body_aborts_the_response() {
        let (upstream, release) = raw_upstream(SSE_HEAD_AND_FIRST_CHUNK, None).await;
        let (addr, proxy) = serve_proxy(&upstream).await;
        let mut sock = raw_request(addr).await;
        sock.write_all(
            b"POST /v1/chat/completions HTTP/1.1\r\nhost: agent\r\ncontent-length: 0\r\n\r\n",
        )
        .await
        .expect("send request");
        let mut wire = read_until(&mut sock, b"first").await;
        assert!(wire.starts_with(b"HTTP/1.1 200 OK\r\n"), "{wire:?}");

        release.send(()).expect("upstream task gone");
        wire.extend(read_to_close(&mut sock).await);
        assert!(
            !wire.ends_with(b"0\r\n\r\n"),
            "a truncated upstream body must not be terminated as if complete: {wire:?}"
        );
        proxy.stop(true).await;
    }

    /// A bodiless upstream status must not leave a stray chunked terminator
    /// on the connection, or the next keep-alive response starts with it. The
    /// second response also pins the sized framing on the wire.
    #[actix_web::test]
    async fn bodiless_statuses_leave_no_chunked_terminator_on_the_connection() {
        let upstream = scripted_upstream(vec![
            b"HTTP/1.1 204 No Content\r\n\r\n",
            b"HTTP/1.1 200 OK\r\ncontent-type: text/plain\r\ncontent-length: 5\r\n\r\nhello",
        ])
        .await;
        let (addr, proxy) = serve_proxy(&upstream).await;
        let mut sock = raw_request(addr).await;

        sock.write_all(b"DELETE /thing HTTP/1.1\r\nhost: agent\r\n\r\n")
            .await
            .expect("send first request");
        let first = read_until(&mut sock, b"\r\n\r\n").await;
        assert!(
            first.starts_with(b"HTTP/1.1 204 No Content\r\n"),
            "{first:?}"
        );

        sock.write_all(b"GET /thing HTTP/1.1\r\nhost: agent\r\n\r\n")
            .await
            .expect("send second request");
        let second = read_until(&mut sock, b"hello").await;
        assert!(second.starts_with(b"HTTP/1.1 200 OK\r\n"), "{second:?}");
        let head = String::from_utf8_lossy(&second).to_ascii_lowercase();
        assert!(head.contains("content-length: 5\r\n"), "{head}");
        assert!(!head.contains("transfer-encoding"), "{head}");
        proxy.stop(true).await;
    }

    /// The plain-HTTP unattested mode runs the agent on aleph-tee's NoTeeBackend:
    /// the attestation endpoint must fail closed with a 500 (never a
    /// fabricated report).
    fn no_tee_state() -> web::Data<AppState> {
        app_state(
            Arc::new(aleph_tee::none::NoTeeBackend::new()),
            Vec::new(),
            "http://127.0.0.1:1",
            None,
        )
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

    struct FakeGpu;
    impl crate::gpu::GpuEvidenceSource for FakeGpu {
        fn collect(&self, nonce: &[u8; 32]) -> anyhow::Result<Vec<crate::gpu::GpuEvidence>> {
            Ok(vec![crate::gpu::GpuEvidence {
                arch: "BLACKWELL".into(),
                nonce: hex::encode(nonce),
                evidence: "ZXZpZGVuY2U=".into(),
                certificate: "Y2VydA==".into(),
            }])
        }
    }

    fn gpu_state(gpu: Option<Arc<GpuState>>) -> web::Data<AppState> {
        app_state(
            Arc::new(MockBackend),
            b"served-key".to_vec(),
            "http://127.0.0.1:1",
            gpu,
        )
    }

    async fn gpu_attest_response(state: web::Data<AppState>, nonce: &str) -> HttpResponse {
        let query = web::Query(AttestationQuery {
            nonce: nonce.to_string(),
        });
        gpu_attestation_endpoint(state, query).await
    }

    async fn gpu_attest(
        state: web::Data<AppState>,
        nonce: &str,
    ) -> (StatusCode, serde_json::Value) {
        let resp = gpu_attest_response(state, nonce).await;
        let status = resp.status();
        let body = to_bytes(resp.into_body()).await.unwrap();
        (status, serde_json::from_slice(&body).unwrap())
    }

    #[actix_web::test]
    async fn gpu_route_derives_the_nonce_from_key_and_client_nonce() {
        let state = gpu_state(Some(Arc::new(GpuState {
            source: Box::new(FakeGpu),
            boot_claims: serde_json::json!([{"measres": "Success"}]),
            lock: Arc::new(tokio::sync::Mutex::new(())),
            lock_wait: GPU_LOCK_WAIT,
        })));
        let client_nonce = hex::encode(b"client-nonce");
        let (status, body) = gpu_attest(state, &client_nonce).await;
        assert_eq!(status, StatusCode::OK);
        assert_eq!(body["tee_type"], "nvidia-cc");
        assert_eq!(body["client_nonce"], client_nonce);
        // Pinned in aleph-tee's report_data tests: gpu_nonce(b"served-key", b"client-nonce").
        assert_eq!(
            body["gpus"][0]["nonce"],
            "20e597c53ba9506fc210a99757a7aef042b6d907c5492fa4b3ae91497d5dc71b"
        );
        assert_eq!(body["gpus"][0]["arch"], "BLACKWELL");
        assert_eq!(body["boot_claims"][0]["measres"], "Success");
    }

    #[actix_web::test]
    async fn gpu_route_is_404_on_a_runtime_without_gpu_attestation() {
        let (status, body) = gpu_attest(gpu_state(None), "00").await;
        assert_eq!(status, StatusCode::NOT_FOUND);
        assert_eq!(body["error"], "no gpu attestation on this runtime");
    }

    #[actix_web::test]
    async fn gpu_route_bounds_and_decodes_the_nonce_like_the_snp_route() {
        let state = gpu_state(Some(Arc::new(GpuState {
            source: Box::new(FakeGpu),
            boot_claims: serde_json::Value::Null,
            lock: Arc::new(tokio::sync::Mutex::new(())),
            lock_wait: GPU_LOCK_WAIT,
        })));
        let (status, _) = gpu_attest(state.clone(), &"a".repeat(MAX_NONCE_LEN * 2 + 2)).await;
        assert_eq!(status, StatusCode::BAD_REQUEST);
        let (status, _) = gpu_attest(state, "zz").await;
        assert_eq!(status, StatusCode::BAD_REQUEST);
    }

    /// A caller that cannot get its turn at the GPU within the wait is told
    /// to retry, instead of queueing behind a wedged collection.
    #[actix_web::test]
    async fn gpu_route_is_503_while_the_exchange_stays_busy() {
        let gpu = Arc::new(GpuState {
            source: Box::new(FakeGpu),
            boot_claims: serde_json::Value::Null,
            lock: Arc::new(tokio::sync::Mutex::new(())),
            lock_wait: Duration::from_millis(50),
        });
        let held = gpu.lock.lock().await;
        let resp = gpu_attest_response(gpu_state(Some(Arc::clone(&gpu))), "00").await;
        assert_eq!(resp.status(), StatusCode::SERVICE_UNAVAILABLE);
        assert_eq!(
            resp.headers().get("Retry-After").unwrap(),
            "1",
            "the header must follow the 50 ms lock_wait, not a constant"
        );
        let body = to_bytes(resp.into_body()).await.unwrap();
        let body: serde_json::Value = serde_json::from_slice(&body).unwrap();
        assert_eq!(body["error"], "gpu attestation busy");
        drop(held);
        let (status, _) = gpu_attest(gpu_state(Some(gpu)), "00").await;
        assert_eq!(status, StatusCode::OK);
    }

    /// The retry the busy answer advertises follows the configured wait, so
    /// a deployment that tunes the wait does not advertise a stale number.
    #[test]
    fn the_advertised_retry_rounds_the_wait_up_to_a_whole_second() {
        // A sub-second wait still asks for a whole second: the header has no
        // finer unit, and zero would send the client straight back.
        assert_eq!(retry_after_secs(Duration::from_millis(50)), 1);
        assert_eq!(retry_after_secs(Duration::ZERO), 1);
        assert_eq!(retry_after_secs(Duration::from_millis(2500)), 3);
        assert_eq!(retry_after_secs(Duration::from_secs(3)), 3);
        assert_eq!(retry_after_secs(GPU_LOCK_WAIT), 10);
    }

    /// How long [`GatedGpu`] parks before giving up on the gate. A failing
    /// assertion must never leave a blocking thread parked forever: the
    /// runtime waits for its blocking tasks when the test ends.
    const GATE_CAP: Duration = Duration::from_secs(5);

    /// A collector that parks inside `collect()` until the test opens its
    /// gate, recording how many callers were inside at the same time.
    struct GatedGpu {
        entries: Arc<AtomicUsize>,
        inside: Arc<AtomicUsize>,
        peak: Arc<AtomicUsize>,
        gate: Arc<(std::sync::Mutex<bool>, std::sync::Condvar)>,
    }

    impl crate::gpu::GpuEvidenceSource for GatedGpu {
        fn collect(&self, nonce: &[u8; 32]) -> anyhow::Result<Vec<crate::gpu::GpuEvidence>> {
            self.entries.fetch_add(1, Ordering::SeqCst);
            let now = self.inside.fetch_add(1, Ordering::SeqCst) + 1;
            self.peak.fetch_max(now, Ordering::SeqCst);
            let (open, condvar) = &*self.gate;
            let deadline = std::time::Instant::now() + GATE_CAP;
            let mut open = open.lock().expect("gate");
            while !*open {
                let left = deadline.saturating_duration_since(std::time::Instant::now());
                if left.is_zero() {
                    break;
                }
                open = condvar.wait_timeout(open, left).expect("gate").0;
            }
            drop(open);
            self.inside.fetch_sub(1, Ordering::SeqCst);
            Ok(vec![crate::gpu::GpuEvidence {
                arch: "BLACKWELL".into(),
                nonce: hex::encode(nonce),
                evidence: "ZXZpZGVuY2U=".into(),
                certificate: "Y2VydA==".into(),
            }])
        }
    }

    /// A client that goes away mid-collection must not hand the GPU to the
    /// next caller: the abandoned collector still owns the driver.
    #[actix_web::test]
    async fn a_dropped_client_keeps_the_gpu_taken_until_the_collection_ends() {
        let entries = Arc::new(AtomicUsize::new(0));
        let inside = Arc::new(AtomicUsize::new(0));
        let peak = Arc::new(AtomicUsize::new(0));
        let gate = Arc::new((std::sync::Mutex::new(false), std::sync::Condvar::new()));
        let gpu = Arc::new(GpuState {
            source: Box::new(GatedGpu {
                entries: Arc::clone(&entries),
                inside: Arc::clone(&inside),
                peak: Arc::clone(&peak),
                gate: Arc::clone(&gate),
            }),
            boot_claims: serde_json::Value::Null,
            lock: Arc::new(tokio::sync::Mutex::new(())),
            lock_wait: Duration::from_millis(500),
        });

        // Dropping the handler future is what actix does to a handler whose
        // client disconnected.
        let mut first = Box::pin(gpu_attestation_endpoint(
            gpu_state(Some(Arc::clone(&gpu))),
            web::Query(AttestationQuery {
                nonce: "00".to_string(),
            }),
        ));
        let deadline = std::time::Instant::now() + GATE_CAP;
        while entries.load(Ordering::SeqCst) == 0 {
            assert!(
                std::time::Instant::now() < deadline,
                "the first request never reached the collector, so there is \
                 nothing for the second one to be locked out of"
            );
            let _ = tokio::time::timeout(Duration::from_millis(5), &mut first).await;
        }
        drop(first);

        // The abandoned collection still owns the GPU, so the next caller is
        // told to retry rather than starting a concurrent SPDM exchange.
        let second = tokio::time::timeout(
            Duration::from_secs(2),
            gpu_attest(gpu_state(Some(Arc::clone(&gpu))), "00"),
        )
        .await;
        assert_eq!(
            peak.load(Ordering::SeqCst),
            1,
            "the collector was entered twice at once"
        );
        let (status, body) = second.expect("the second caller must be answered, not left queueing");
        assert_eq!(status, StatusCode::SERVICE_UNAVAILABLE);
        assert_eq!(body["error"], "gpu attestation busy");

        // Once the abandoned collection ends, the GPU is free again.
        {
            let (open, condvar) = &*gate;
            *open.lock().expect("gate") = true;
            condvar.notify_all();
        }
        let deadline = std::time::Instant::now() + GATE_CAP;
        while inside.load(Ordering::SeqCst) > 0 {
            assert!(
                std::time::Instant::now() < deadline,
                "the abandoned collection never left the collector, so the \
                 GPU was never handed back"
            );
            tokio::time::sleep(Duration::from_millis(5)).await;
        }
        let (status, _) = gpu_attest(gpu_state(Some(gpu)), "00").await;
        assert_eq!(status, StatusCode::OK);
        assert_eq!(peak.load(Ordering::SeqCst), 1);
        assert_eq!(
            entries.load(Ordering::SeqCst),
            2,
            "the caller that was told to retry must never reach the collector"
        );
    }
}
