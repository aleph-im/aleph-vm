use std::sync::Arc;
use std::time::Duration;

use actix_web::web::{self, Bytes};
use actix_web::{HttpRequest, HttpResponse};
use aleph_tee::report_data::gpu_nonce;
use aleph_tee::traits::TeeBackend;
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
    /// One SPDM exchange at a time: concurrent callers queue. Held in its
    /// own `Arc` so the guard can be owned and moved into the blocking task
    /// that runs the collector, which outlives the request handler.
    pub lock: Arc<tokio::sync::Mutex<()>>,
    /// How long a caller queues for the exchange before being told to
    /// retry. A collection takes well under a second, so a queue this deep
    /// means the collector is wedged; failing fast keeps a pile-up from
    /// holding worker threads for the whole collector timeout each.
    pub lock_wait: Duration,
}

/// Default for [`GpuState::lock_wait`].
pub const GPU_LOCK_WAIT: Duration = Duration::from_secs(10);

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
    /// Borrowed from the agent's state: the boot claims are the same
    /// document for the life of the process, so a response serializes them
    /// in place rather than cloning the tree per request.
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
            .insert_header(("Retry-After", "10"))
            .json(serde_json::json!({"error": "gpu attestation busy"}));
    };
    // The collector is a blocking child process; keep it off the async
    // workers. The guard travels into the blocking task rather than staying
    // in this future: a client that disconnects drops the handler but not
    // the collection it started, and releasing the GPU here would let the
    // next caller open a second SPDM exchange against a driver still busy
    // with the first.
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
    use std::sync::atomic::{AtomicUsize, Ordering};

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
            gpu: None,
        })
    }

    /// The plain-HTTP unattested mode runs the agent on aleph-tee's NoTeeBackend:
    /// the attestation endpoint must fail closed with a 500 (never a
    /// fabricated report).
    fn no_tee_state() -> web::Data<AppState> {
        web::Data::new(AppState {
            backend: Arc::new(aleph_tee::none::NoTeeBackend::new()),
            served_public_key_raw: Vec::new(),
            upstream: "http://127.0.0.1:1".to_string(),
            http_client: reqwest::Client::new(),
            gpu: None,
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
        web::Data::new(AppState {
            backend: Arc::new(MockBackend),
            served_public_key_raw: b"served-key".to_vec(),
            upstream: "http://127.0.0.1:1".into(),
            http_client: reqwest::Client::new(),
            gpu,
        })
    }

    async fn gpu_attest(
        state: web::Data<AppState>,
        nonce: &str,
    ) -> (StatusCode, serde_json::Value) {
        let query = web::Query(AttestationQuery {
            nonce: nonce.to_string(),
        });
        let resp = gpu_attestation_endpoint(state, query).await;
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
        let (status, body) = gpu_attest(gpu_state(Some(Arc::clone(&gpu))), "00").await;
        assert_eq!(status, StatusCode::SERVICE_UNAVAILABLE);
        assert_eq!(body["error"], "gpu attestation busy");
        drop(held);
        let (status, _) = gpu_attest(gpu_state(Some(gpu)), "00").await;
        assert_eq!(status, StatusCode::OK);
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
    /// next caller: the collector keeps running to its own timeout, so a
    /// second exchange started now would talk to the driver at the same
    /// time as the abandoned one.
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

        // Poll the first request until its collection has started, then drop
        // the handler future: that is exactly what actix does to a handler
        // whose client disconnected.
        let mut first = Box::pin(gpu_attestation_endpoint(
            gpu_state(Some(Arc::clone(&gpu))),
            web::Query(AttestationQuery {
                nonce: "00".to_string(),
            }),
        ));
        while entries.load(Ordering::SeqCst) == 0 {
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
        while inside.load(Ordering::SeqCst) > 0 {
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
