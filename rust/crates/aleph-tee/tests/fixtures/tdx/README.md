# TDX quote fixtures

Real Intel TDX quotes vendored from open-source projects, used by the
`aleph_tee::tdx` parser and verifier tests. Both sources are MIT-licensed
(their licence texts sit next to this file); aleph-vm is MIT too, so
redistribution is clean.

| File | Source | Licence | Notes |
|---|---|---|---|
| `tdx_quote_v4.bin` | [Phala-Network/dcap-qvl](https://github.com/Phala-Network/dcap-qvl) `sample/tdx_quote`, branch `master` @ `7cb5cace` | MIT (`LICENSE.dcap-qvl`) | Quote v4, TD report 1.0. 70 bytes of zero padding after the signature data. |
| `tdx_quote_v5.bin` | [automata-network/automata-dcap-attestation](https://github.com/automata-network/automata-dcap-attestation) `rust-crates/samples/quotev5.dat`, branch `main` @ `41aedff9` | MIT (`LICENSE.automata-dcap-attestation`) | Quote v5, TD report 1.5 body (type 3, 648 bytes), non-zero `mrservicetd`. |

The two remaining accepted-format cases have no public fixture and are
synthesized in the tests instead: trailing non-zero bytes after the
signature data (appended to the v4 quote) and a v5 quote carrying a TD
report 1.0 body (spliced from the v5 quote).

Properties verified at vendoring time, for both quotes:

- header `tee_type` is 0x81 (TDX) and the QE vendor id is Intel's
  (`939a7233f79c4ca9940a0db3957f0607`);
- the quote signature verifies over the byte range preceding the
  signature-data length field under the embedded attestation key (for v5
  that range includes the body descriptor) — also re-verified by the test
  suite on every run;
- the QE report's `report_data` opens with
  `SHA-256(attestation_key || qe_auth_data)`;
- the certification data nests exactly: type 6 (QE report) wrapping type 5
  (a three-certificate PEM PCK chain);
- `mrconfigid` and `rtmr3` are all-zero.

The files are byte-identical to upstream at the commits pinned above. Do
not regenerate or re-encode them; tests pin exact register values.
