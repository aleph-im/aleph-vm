mod attestation;
mod proxy;
mod secrets;
mod tls;

use std::sync::Arc;

use actix_web::web;
use actix_web::{App, HttpServer};
use aleph_tee::none::NoTeeBackend;
use aleph_tee::sev_snp::SevSnpBackend;
use aleph_tee::traits::TeeBackend;
use anyhow::{Context, Result};
use clap::Parser;
use tracing::info;

use proxy::{AppState, attestation_endpoint, proxy_handler};
use secrets::{OwnerAuth, SecretStore, inject_secret_handler};
use tls::{build_rustls_config, generate_attested_tls_identity};

/// Aleph attestation agent: in-VM sidecar that provides attested HTTPS
/// reverse-proxying and an attestation endpoint.
#[derive(Parser, Debug)]
#[command(name = "aleph-attest-agent")]
struct Cli {
    /// Port to listen on for HTTPS connections.
    #[arg(long, default_value = "8443")]
    port: u16,

    /// Upstream application URL to proxy requests to.
    #[arg(long, default_value = "http://127.0.0.1:8080")]
    upstream: String,

    /// AMD product name for the SEV-SNP backend (e.g., "Milan", "Genoa", "Turin").
    #[arg(long, default_value = "Genoa")]
    amd_product: String,

    /// Owner address (0x + 40 hex) allowed to inject secrets. When set, every
    /// inject-secret request must carry a valid EIP-191 owner signature bound to
    /// this agent's TLS key. When unset, injection is unauthenticated one-shot
    /// (v-program images).
    #[arg(long)]
    owner: Option<String>,

    /// LOCAL TESTING ONLY. Serve plain HTTP with no TEE backend: no
    /// attestation report, no attested TLS identity, no /dev/sev-guest.
    /// The proxy and inject-secret routes behave as in production; the
    /// attestation endpoint answers 500. Selected by the guest init when the
    /// measured kernel cmdline carries `aleph_local=1` (which no production
    /// launch path can emit without changing the launch measurement).
    #[arg(long)]
    insecure_plain_http: bool,
}

/// Normalize and validate a `--owner` value: lowercase it, then require it is
/// exactly `0x` followed by 40 hex digits. Returns the normalized (lowercase)
/// address.
fn validate_owner(raw: &str) -> Result<String> {
    let normalized = raw.to_lowercase();
    let hex_part = normalized
        .strip_prefix("0x")
        .context("--owner must start with 0x")?;
    if hex_part.len() != 40 || !hex_part.chars().all(|c| c.is_ascii_hexdigit()) {
        anyhow::bail!("--owner must be 0x followed by 40 hex characters, got: {raw}");
    }
    Ok(normalized)
}

#[actix_web::main]
async fn main() -> Result<()> {
    // Initialize tracing.
    tracing_subscriber::fmt()
        .with_env_filter(
            tracing_subscriber::EnvFilter::from_default_env()
                .add_directive(tracing::Level::INFO.into()),
        )
        .init();

    // 1. Parse CLI args.
    let cli = Cli::parse();
    let owner = cli.owner.as_deref().map(validate_owner).transpose()?;
    info!(
        port = cli.port, upstream = %cli.upstream, product = %cli.amd_product,
        owner_mode = owner.is_some(),
        "starting aleph-attest-agent"
    );

    // 2 to 4. Backend and identity. Plain-HTTP local mode has no TEE and
    // therefore no attested identity: the served key is empty and the
    // attestation endpoint fails closed through NoTeeBackend.
    let (backend, identity): (Arc<dyn TeeBackend>, Option<tls::AttestedTlsIdentity>) =
        if cli.insecure_plain_http {
            tracing::warn!("INSECURE: plain HTTP, no TEE; local testing only");
            (Arc::new(NoTeeBackend::new()), None)
        } else {
            // Explicit dyn type: unsized coercion does not happen inside a
            // tuple, so the concrete Arc must be widened here.
            let backend: Arc<dyn TeeBackend> = Arc::new(SevSnpBackend::new(&cli.amd_product));
            let identity = generate_attested_tls_identity(backend.as_ref())
                .context("failed to generate attested TLS identity")?;
            info!("generated attested TLS identity");
            (backend, Some(identity))
        };
    let rustls_config = identity
        .as_ref()
        .map(|identity| build_rustls_config(identity).context("failed to build rustls config"))
        .transpose()?;
    let served_public_key_raw = identity
        .as_ref()
        .map(|identity| identity.public_key_raw.clone())
        .unwrap_or_default();

    // 5. Create shared application state.
    // Owner-auth data, built from the same served key: `None` on v-program
    // images (unauthenticated one-shot injection, unchanged), `Some` on
    // confidential-instance images (owner-signature-gated, overwriting).
    let owner_auth = web::Data::new(owner.map(|owner| OwnerAuth {
        owner,
        server_public_key_raw: served_public_key_raw.clone(),
    }));
    let app_state = web::Data::new(AppState {
        backend,
        served_public_key_raw,
        upstream: cli.upstream.clone(),
        // A reverse proxy relays 3xx responses to the caller; it must never
        // follow them itself, or an upstream redirect would make the agent
        // fetch (and serve, over the attested channel) whatever the redirect
        // points at, which can be anything reachable from inside the guest.
        http_client: reqwest::Client::builder()
            .redirect(reqwest::redirect::Policy::none())
            .build()
            .context("failed to build upstream HTTP client")?,
    });
    // Secret store: one-shot without --owner, overwriting with --owner (see
    // secrets::inject_secret_handler). Writes to the production
    // /tmp/secrets directory.
    let secret_store = web::Data::new(SecretStore::with_default_dir());

    // 6. Start actix-web HTTP(S) server.
    // inject-secret's `web::Bytes` extractor is governed by actix-web's
    // `PayloadConfig`, whose default is 256 KiB, unlike the `web::Json`
    // extractor's 2 MiB default. The store allows up to
    // `MAX_SECRETS` (16) * `MAX_VALUE_SIZE` (64 KiB) =~ 1 MiB of secret
    // values alone, plus JSON structure, key names, and (in owner mode) the
    // signature field. Raise the cap to 2 MiB, matching the prior
    // `web::Json` default, to restore headroom for both the unauthenticated
    // v-program path and the new owner-authenticated path. Scoped to this
    // route only: the attestation GET and the proxy default-service never
    // read `web::Bytes`/`web::String` bodies, so they are unaffected either way.
    const INJECT_SECRET_BODY_LIMIT: usize = 2 * 1024 * 1024;

    // Dual-stack: [::] accepts IPv6 AND IPv4 connections (Linux default
    // IPV6_V6ONLY=0; actix-web does not set the sockopt), so the existing
    // IPv4 reachability path keeps working while the DHCPv6-assigned guest
    // address is served too. 0.0.0.0 was IPv4-only, which made a routable
    // guest IPv6 useless for reaching the agent.
    let bind_addr = format!("[::]:{}", cli.port);
    let server = HttpServer::new(move || {
        App::new()
            .app_data(app_state.clone())
            .app_data(secret_store.clone())
            .app_data(owner_auth.clone())
            .route(
                "/.well-known/attestation",
                web::get().to(attestation_endpoint),
            )
            .service(
                web::resource("/confidential/inject-secret")
                    .app_data(web::PayloadConfig::new(INJECT_SECRET_BODY_LIMIT))
                    .route(web::post().to(inject_secret_handler)),
            )
            .default_service(web::to(proxy_handler))
    });
    match rustls_config {
        Some(rustls_config) => {
            info!(addr = %bind_addr, "binding HTTPS server");
            server
                .bind_rustls_0_23(&bind_addr, rustls_config)
                .context("failed to bind HTTPS server")?
                .run()
                .await
                .context("HTTPS server exited with error")?;
        }
        None => {
            info!(addr = %bind_addr, "binding plain HTTP server (insecure local mode)");
            server
                .bind(&bind_addr)
                .context("failed to bind HTTP server")?
                .run()
                .await
                .context("HTTP server exited with error")?;
        }
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn plain_http_flag_is_off_by_default_and_parses() {
        let cli = Cli::parse_from(["aleph-attest-agent"]);
        assert!(!cli.insecure_plain_http);
        let cli = Cli::parse_from(["aleph-attest-agent", "--insecure-plain-http"]);
        assert!(cli.insecure_plain_http);
    }
}
