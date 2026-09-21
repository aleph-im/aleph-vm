# aleph-tee

AMD SEV-SNP and Intel TDX attestation for the [aleph.im](https://aleph.im)
network: report and quote parsing, chain and signature verification against
pinned vendor roots, AMD KDS and Intel PCS collateral clients, and the X.509
extension that embeds an attestation report in a TLS certificate.

Pure Rust: x509-parser for structure, ring for signature math, `sev` with
`crypto_nossl`. No OpenSSL, so the crate cross-compiles wherever rustls does.

## Features

| Feature | On by default | Provides |
|---|---|---|
| `guest` | yes | The SEV-SNP firmware backend (`/dev/sev-guest`), for the in-guest agent. |
| `verify` | yes | Chain verification, KDS and PCS clients, the TDX verifier. |

Always available: the SEV-SNP report parser, QEMU launch arguments for an
SEV-SNP guest, the `report_data` binding schemes, the owner-auth envelope,
and the X.509 extension.

## Verifying a TDX quote

```rust,no_run
use std::time::SystemTime;
use aleph_tee::tdx::pcs::{collateral_request, fetch_collateral};
use aleph_tee::tdx::quote::parse_tdx_quote;
use aleph_tee::tdx::tcb::TdxTcbPolicy;
use aleph_tee::tdx::verify::verify_tdx_quote;

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    let raw_quote = std::fs::read("quote.bin")?;
    let quote = parse_tdx_quote(&raw_quote)?;
    let now = SystemTime::now();
    let request = collateral_request(&quote.signature.pck_chain_pem)?;
    let collateral = fetch_collateral(&request, now).await?;
    let verified = verify_tdx_quote(&quote, &collateral, now, &TdxTcbPolicy::default())?;
    // `verified.registers` and `verified.report_data` are now Intel-attested;
    // pin the registers and bind `report_data` before trusting the guest.
    println!("{:?}", verified.registers);
    Ok(())
}
```

The example is compiled as a doctest of the `verify` feature, so it cannot
drift from the API.

A verified quote or report is not a decision to trust a guest: the caller
still compares the registers against the measurement it expects and binds
`report_data` to its own key or nonce. See the module docs.

## Where this crate is going

It is published from the [aleph-vm](https://github.com/aleph-im/aleph-vm)
repository for now and will move to a dedicated project alongside the
supervisor and the measured runtimes. The API is pre-1.0 and changes between
minor versions.

## Licence

MIT.
