# TDX quote fixtures

Real Intel TDX quotes vendored from open-source projects, used by the
`aleph_tee::tdx` parser and verifier tests. aleph-vm is MIT-licensed; both
source licences below permit redistribution with attribution.

| File | Source | Licence | Notes |
|---|---|---|---|
| `phala_tdx_quote.bin` | [Phala-Network/dcap-qvl](https://github.com/Phala-Network/dcap-qvl) `sample/tdx_quote` | MIT | Quote v4, TD report 1.0. 70 bytes of zero padding after the signature data. |
| `go_tdx_prod_quote_spr_v4.bin` | [google/go-tdx-guest](https://github.com/google/go-tdx-guest) `testing/testdata/tdx_prod_quote_SPR_E4.dat` | Apache-2.0 | Quote v4 from production Sapphire Rapids silicon. Carries a deliberate trailing marker (`extra bytes(only for testing purpose)`) upstream added to test that parsers ignore bytes after the signature data. |
| `go_quote_v5.bin` | [google/go-tdx-guest](https://github.com/google/go-tdx-guest) `testing/testdata/quote_sample_v5.dat` | Apache-2.0 | Quote v5, TD report 1.5 body (type 3, 648 bytes). |
| `automata_quote_v5.bin` | [automata-network/automata-dcap-attestation](https://github.com/automata-network/automata-dcap-attestation) `rust-crates/samples/quotev5.dat` | MIT | Quote v5, TD report 1.5, non-zero `mrservicetd`. Independent of the go-tdx-guest fixtures. |

Properties verified at vendoring time, for all four quotes:

- header `tee_type` is 0x81 (TDX) and the QE vendor id is Intel's
  (`939a7233f79c4ca9940a0db3957f0607`);
- the quote signature verifies over the byte range preceding the
  signature-data length field under the embedded attestation key (for v5
  that range includes the body descriptor);
- the QE report's `report_data` opens with
  `SHA-256(attestation_key || qe_auth_data)`;
- the certification data nests exactly: type 6 (QE report) wrapping type 5
  (a three-certificate PEM PCK chain);
- `mrconfigid` and `rtmr3` are all-zero.

The files are byte-identical to upstream. Do not regenerate or re-encode
them; tests pin exact register values.
