# TDX quote fixtures

Real Intel TDX quotes used by the `aleph_tee::tdx` parser and verifier
tests: one set captured on aleph-vm's own hardware, the rest vendored from
open-source projects. The vendored sources are MIT-licensed (their licence
texts sit next to this file); aleph-vm is MIT too, so redistribution is
clean.

## Captured on aleph-vm hardware

Produced on 2026-09-29 by the measured `tdxImage` runtime (nix flake output
of this repository) running as a TD on a Xeon 6731E (Sierra Forest, FMSPC
`20A06F000000`) under QEMU 10.2.4, edk2 202602 TDVF and Intel's DCAP stack
(QGS through a local PCCS registered with Intel PCS). No licence question:
the bytes are ours.

| File | Notes |
|---|---|
| `tdx_ratls_xeon6_cert.pem` | The attested-TLS certificate the runtime's attest agent served on `/.well-known/attestation`'s TLS port: rcgen self-signed, P-384 key, extension `1.3.6.1.4.1.60000.1.1` carrying `{"tee_type":"tdx","data":<hex quote>}`. |
| `tdx_quote_xeon6_ratls.bin` | The quote inside that certificate, byte-identical. Quote v4, TD report 1.0, 307 bytes of zero padding after the signature data (configfs-tsm's buffer). `report_data` is `key_bound_report_data(subjectPublicKey)` of the certificate's key; `mrconfigid` is SHA-384 of the empty string (the TD booted with an empty descriptor suffix); `mrtd`/`rtmr1`/`rtmr2` equal the runtime's predicted `measurements.json`; `rtmr3` is zero. |
| `tdx_quote_xeon6_ratls_collateral.json` | The matching collateral as served by PCCS on the same day, reshaped into the `TdxCollateral` JSON layout (CRLs hex DER, issuer chains from the response headers, TCB Info and QE Identity bodies verbatim with their detached signatures). Windows: PCK CRL and TCB Info to 2026-10-29, TDX QE Identity to 2026-10-29T00:40Z, root CRL to 2027-02-26; tests inject 2026-10-01. |

What makes this set worth keeping next to the vendored ones: the platform
runs ROM 1.10 firmware (microcode CPUSVN and TDX module SVN 7 behind
Intel's TCB-R), so its PCK lands ON the TCB Info's third level, dated
2024-11-13 and `OutOfDate` with eight advisories (INTEL-SA-01268, -01273,
-01278, -01192, -01245, -01312, -01313, -01367); the TDX module identity
`TDX_01` lands on its `isvsvn 6` OutOfDate rung (adding no advisory) and
the TD QE is `UpToDate`. The vendored "outdated" quote never reaches a
level, so this is the only genuine OutOfDate appraisal in the suite. It is
also the only quote with a non-zero `mrconfigid` and a key-bound
`report_data`.

## Vendored

| File | Source | Licence | Notes |
|---|---|---|---|
| `tdx_quote_v4.bin` | [Phala-Network/dcap-qvl](https://github.com/Phala-Network/dcap-qvl) `sample/tdx_quote`, branch `master` @ `7cb5cace` | MIT (`LICENSE.dcap-qvl`) | Quote v4, TD report 1.0. 70 bytes of zero padding after the signature data. |
| `tdx_quote_v5.bin` | [automata-network/automata-dcap-attestation](https://github.com/automata-network/automata-dcap-attestation) `rust-crates/samples/quotev5.dat`, branch `main` @ `41aedff9` | MIT (`LICENSE.automata-dcap-attestation`) | Quote v5, TD report 1.5 body (type 3, 648 bytes), non-zero `mrservicetd`. |
| `tdx_quote_collateral.json` | Phala dcap-qvl `sample/tdx_quote_collateral.json`, same commit | MIT (`LICENSE.dcap-qvl`) | Complete DCAP collateral matching `tdx_quote_v4.bin`. All validity windows expired (PCK CRL and TCB Info to 2025-07-19); verifier tests inject a clock inside them. |
| `tdx_quote_outdated.bin` | Phala dcap-qvl `sample/tdx_quote_outdated`, same commit | MIT (`LICENSE.dcap-qvl`) | Quote v5 from a lagging platform; the chain and signatures are genuine. Its PCK reports SGX component 7 at SVN 3 while every level of the matching TCB Info demands 5, so the walk lands below every level rather than on an OutOfDate one. |
| `tdx_quote_outdated_collateral.json` | Phala dcap-qvl `sample/tdx_quote_outdated_collateral.json`, same commit | MIT (`LICENSE.dcap-qvl`) | Collateral matching the outdated quote (windows to 2026-03-20). |

The two remaining accepted-format cases have no public fixture and are
synthesized in the tests instead: trailing non-zero bytes after the
signature data (appended to the v4 quote) and a v5 quote carrying a TD
report 1.0 body (spliced from the v5 quote).

Properties verified at vendoring time, for both vendored quotes (and
holding for the captured one too, except the last):

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

The vendored files are byte-identical to upstream at the commits pinned
above and the captured ones to what the hardware produced. Do not
regenerate or re-encode any of them; tests pin exact register values.
