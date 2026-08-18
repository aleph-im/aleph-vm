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

        /// Owner private key as 32-byte hex (optionally 0x-prefixed), used to
        /// sign the injection envelope. Required by confidential-instance
        /// agents (those started with `--owner`); omit it for v-program agents,
        /// which take the unauthenticated legacy body.
        #[arg(long = "owner-key")]
        owner_key: Option<String>,
    },
}

fn parse_key_value(s: &str) -> Result<(String, String), String> {
    let pos = s
        .find('=')
        .ok_or_else(|| format!("invalid key=value pair: no '=' found in '{s}'"))?;
    Ok((s[..pos].to_string(), s[pos + 1..].to_string()))
}

/// Parse `--owner-key`: exactly 64 hex characters (32 bytes), optionally
/// `0x`-prefixed, forming a valid secp256k1 scalar.
fn parse_owner_key(s: &str) -> Result<k256::ecdsa::SigningKey> {
    let digits = s
        .strip_prefix("0x")
        .or_else(|| s.strip_prefix("0X"))
        .unwrap_or(s);
    if digits.len() != 64 {
        anyhow::bail!(
            "--owner-key must be exactly 64 hex characters (32 bytes), optionally 0x-prefixed; \
             got {} characters",
            digits.len()
        );
    }
    // Never echo the key material itself in an error message.
    let bytes =
        hex::decode(digits).map_err(|_| anyhow::anyhow!("--owner-key is not valid hexadecimal"))?;
    k256::ecdsa::SigningKey::from_slice(&bytes)
        .map_err(|_| anyhow::anyhow!("--owner-key is not a valid secp256k1 private key"))
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
        Command::InjectSecret {
            common,
            secrets,
            owner_key,
        } => {
            let expected = common.parse_expected_measurement()?;

            if secrets.is_empty() {
                anyhow::bail!("at least one --secret key=value is required");
            }

            let owner_key = owner_key.as_deref().map(parse_owner_key).transpose()?;

            // Show the address the envelope will be signed for, so an operator
            // can check it against the instance's configured owner before the
            // secret goes anywhere.
            if let Some(ref key) = owner_key {
                println!(
                    "Owner address:     {}",
                    aleph_tee::owner_auth::address_from_verifying_key(key.verifying_key())
                );
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
                owner_key.as_ref(),
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

#[cfg(test)]
mod tests {
    use super::*;

    const KEY_HEX: &str = "4242424242424242424242424242424242424242424242424242424242424242";

    /// 64 hex chars parse, with or without the 0x prefix, to the same key.
    #[test]
    fn owner_key_accepts_64_hex_with_optional_prefix() {
        let plain = parse_owner_key(KEY_HEX).unwrap();
        let prefixed = parse_owner_key(&format!("0x{KEY_HEX}")).unwrap();
        assert_eq!(plain.to_bytes(), prefixed.to_bytes());
        assert_eq!(plain.to_bytes().as_slice(), &[0x42u8; 32]);
    }

    /// Anything that is not exactly 32 bytes of valid hex, or is not a valid
    /// secp256k1 scalar, is a clean error rather than a panic. The key material
    /// must not be echoed back in the message.
    #[test]
    fn owner_key_rejects_malformed_input() {
        let zero = "0".repeat(64);
        for bad in [
            "",
            "0x",
            KEY_HEX.trim_end_matches("42"), // 62 chars
            &format!("{KEY_HEX}42"),        // 66 chars
            &"z".repeat(64),                // right length, not hex
            &zero,                          // valid hex, invalid scalar
        ] {
            let err = match parse_owner_key(bad) {
                Ok(_) => panic!("must reject {bad:?}"),
                Err(e) => e.to_string(),
            };
            assert!(err.contains("--owner-key"), "unhelpful error: {err}");
            // Key-length inputs are (near-)key material: they must never be
            // echoed back into an error an operator might paste somewhere.
            assert!(
                bad.len() < 16 || !err.contains(bad),
                "the error must not echo the key material: {err}"
            );
        }
    }

    /// The printed address is the standard Ethereum address of the signing key,
    /// i.e. exactly what an operator configured as the agent's `--owner`.
    #[test]
    fn owner_key_derives_the_expected_address() {
        let key = parse_owner_key(KEY_HEX).unwrap();
        let address = aleph_tee::owner_auth::address_from_verifying_key(key.verifying_key());
        assert!(
            address.starts_with("0x") && address.len() == 42,
            "{address}"
        );
        // Stable across runs: the same key always yields the same address.
        assert_eq!(
            address,
            aleph_tee::owner_auth::address_from_verifying_key(
                parse_owner_key(&format!("0x{KEY_HEX}"))
                    .unwrap()
                    .verifying_key()
            )
        );
    }
}
