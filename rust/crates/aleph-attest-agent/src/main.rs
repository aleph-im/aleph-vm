mod attestation;
mod proxy;
mod secrets;
mod tls;

use std::sync::Arc;

use actix_web::web;
use actix_web::{App, HttpServer};
use aleph_tee::sev_snp::SevSnpBackend;
use anyhow::{Context, Result};
use clap::Parser;
use tracing::info;

use proxy::{AppState, attestation_endpoint, proxy_handler};
use secrets::{SecretStore, inject_secret_handler};
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
    info!(port = cli.port, upstream = %cli.upstream, product = %cli.amd_product, "starting aleph-attest-agent");

    // 2. Create SEV-SNP backend.
    let backend = Arc::new(SevSnpBackend::new(&cli.amd_product));

    // 3. Generate attested TLS identity (ephemeral key + attestation cert).
    let identity = generate_attested_tls_identity(backend.as_ref())
        .context("failed to generate attested TLS identity")?;
    info!("generated attested TLS identity");

    // 4. Build rustls config.
    let rustls_config = build_rustls_config(&identity).context("failed to build rustls config")?;

    // 5. Create shared application state.
    // The fresh-attestation endpoint binds the agent's real served public key
    // into every report, so capture it here before `identity` is consumed.
    let served_public_key_raw = identity.public_key_raw.clone();
    let app_state = web::Data::new(AppState {
        backend,
        served_public_key_raw,
        upstream: cli.upstream.clone(),
        http_client: reqwest::Client::new(),
    });
    // One-shot secret store, writing to the production /tmp/secrets directory.
    let secret_store = web::Data::new(SecretStore::with_default_dir());

    // 6. Start actix-web HTTPS server.
    // Dual-stack: [::] accepts IPv6 AND IPv4 connections (Linux default
    // IPV6_V6ONLY=0; actix-web does not set the sockopt), so the existing
    // IPv4 reachability path keeps working while the DHCPv6-assigned guest
    // address is served too. 0.0.0.0 was IPv4-only, which made a routable
    // guest IPv6 useless for reaching the agent.
    let bind_addr = format!("[::]:{}", cli.port);
    info!(addr = %bind_addr, "binding HTTPS server");

    HttpServer::new(move || {
        App::new()
            .app_data(app_state.clone())
            .app_data(secret_store.clone())
            .route(
                "/.well-known/attestation",
                web::get().to(attestation_endpoint),
            )
            .route(
                "/confidential/inject-secret",
                web::post().to(inject_secret_handler),
            )
            .default_service(web::to(proxy_handler))
    })
    .bind_rustls_0_23(&bind_addr, rustls_config)
    .context("failed to bind HTTPS server")?
    .run()
    .await
    .context("HTTPS server exited with error")?;

    Ok(())
}
