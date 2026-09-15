# SEV-SNP fixtures

A genuine AMD Milan attestation report and the VCEK certificate AMD's KDS
issued for its chip, used by the `aleph_tee::sev_snp::verify` tests to
exercise AMD's real RSASSA-PSS/SHA-384 chain and ECDSA P-384 report
signature offline. The ARK and ASK come from the `sev` crate's builtin
roots at test time.

| File | Source | Licence | Notes |
|---|---|---|---|
| `report_milan.hex` | [virtee/sev](https://github.com/virtee/sev) `tests/certs_data/report_milan.hex`, via aleph-rs `crates/aleph-sdk/src/attest/testdata` | Apache-2.0 | 1184-byte report, hex text. |
| `vcek_milan.der` | AMD KDS, for the chip and TCB in `report_milan.hex`, via aleph-rs `crates/aleph-sdk/src/attest/testdata` | AMD-issued certificate, public | Valid 2023 to 2030; tests inject 2026-08-18. |
