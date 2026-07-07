mod client;
mod verify;

use anyhow::{Context, Result};
use clap::{Parser, Subcommand};

#[derive(Parser)]
#[command(
    name = "aleph-attest-cli",
    about = "Client-side TEE attestation verifier"
)]
struct Cli {
    #[command(subcommand)]
    command: Command,
}

/// Common arguments shared by all subcommands.
#[derive(Parser)]
struct CommonArgs {
    /// URL to connect to.
    #[arg(long)]
    url: String,

    /// AMD product name for certificate chain validation.
    #[arg(long, default_value = "Genoa")]
    amd_product: String,

    /// Expected VM measurement (launch digest) as a hex string.
    /// If provided, the TLS handshake is aborted if the attestation report's
    /// measurement doesn't match, so the client never sends application data to
    /// a VM running unexpected code.
    #[arg(long)]
    expected_measurement: Option<String>,
}

impl CommonArgs {
    fn parse_expected_measurement(&self) -> Result<Option<Vec<u8>>> {
        self.expected_measurement
            .as_deref()
            .map(|hex_str| hex::decode(hex_str).context("invalid hex in --expected-measurement"))
            .transpose()
    }
}

#[derive(Subcommand)]
enum Command {
    /// Make an API call with TLS-bound attestation verification (Layer 2).
    Attest(CommonArgs),

    /// Request fresh attestation with a random nonce (Layer 3).
    FreshAttest(CommonArgs),

    /// Inject secrets into a confidential VM via attested TLS.
    InjectSecret {
        #[command(flatten)]
        common: CommonArgs,

        /// Secret to inject as key=value (can be repeated).
        #[arg(long = "secret", value_parser = parse_key_value)]
        secrets: Vec<(String, String)>,
    },
}

fn parse_key_value(s: &str) -> Result<(String, String), String> {
    let pos = s
        .find('=')
        .ok_or_else(|| format!("invalid key=value pair: no '=' found in '{s}'"))?;
    Ok((s[..pos].to_string(), s[pos + 1..].to_string()))
}

#[tokio::main]
async fn main() -> Result<()> {
    rustls::crypto::ring::default_provider()
        .install_default()
        .expect("failed to install rustls crypto provider");
    tracing_subscriber::fmt::init();

    let cli = Cli::parse();

    match cli.command {
        Command::Attest(args) => {
            let expected = args.parse_expected_measurement()?;
            println!("Making attested request to {}...", args.url);

            let response =
                client::attested_request(&args.url, &args.amd_product, expected.as_deref()).await?;

            println!("Attestation valid: {}", response.attestation_valid);
            println!("Summary:           {}", response.attestation_summary);
            println!("Measurement:       {}", hex::encode(&response.measurement));
            println!("HTTP status:       {}", response.status);
            println!("Response body:");
            println!("{}", response.body);
        }
        Command::FreshAttest(args) => {
            let expected = args.parse_expected_measurement()?;
            println!("Requesting fresh attestation from {}...", args.url);

            let report =
                client::fresh_attestation(&args.url, &args.amd_product, expected.as_deref())
                    .await?;

            // Derive display values from the AMD-signed blob (the report carries
            // no standalone measurement / report_data copies).
            let parsed = aleph_tee::sev_snp::report::parse_sev_snp_report(&report.data)
                .context("failed to parse verified report blob for display")?;
            println!("Fresh attestation verified successfully!");
            println!("  TEE type:     {:?}", report.tee_type);
            println!(
                "  Measurement:  {}",
                hex::encode(aleph_tee::sev_snp::report::extract_measurement(&parsed))
            );
            println!(
                "  Report data:  {}",
                hex::encode(aleph_tee::sev_snp::report::extract_report_data(&parsed))
            );
        }
        Command::InjectSecret { common, secrets } => {
            let expected = common.parse_expected_measurement()?;

            if secrets.is_empty() {
                anyhow::bail!("at least one --secret key=value is required");
            }

            println!(
                "Injecting {} secret(s) into {}...",
                secrets.len(),
                common.url
            );

            let resp = client::inject_secret(
                &common.url,
                &common.amd_product,
                expected.as_deref(),
                &secrets,
            )
            .await?;

            println!("Secrets injected successfully!");
            for key in &resp.injected {
                println!("  - {}", key);
            }
        }
    }

    Ok(())
}
