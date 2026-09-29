# TDX quote fixtures

Real Intel TDX quotes vendored from open-source projects, used by the
`aleph_tee::tdx` parser and verifier tests. Both sources are MIT-licensed
(their licence texts sit next to this file); aleph-vm is MIT too, so
redistribution is clean.

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

# TDX boot measurement vectors

Hardware vectors for `aleph_tee::tdx::measure` (and its Python mirror
`aleph.vm.vprogram.tdx_measurement`), taken on 2026-09-29 from a PhoenixNAP
DL320 Gen12 / Xeon 6731E node running QEMU 10.2.4 with the edk2 202602
IntelTdxX64 TDVF (`nix/tdvf.nix`) direct-booting an Ubuntu kernel. The
inputs are tens of megabytes and are not vendored; this is the Tier 2 check
to run whenever the walk or the event model changes:

| Input | SHA-256 | Size | Register |
|---|---|---|---|
| TDVF `OVMF.fd` | `6e0fc1c5ce4b0052e1baaf1ab5ea005557a878f2f19625b9328ca24d64b52941` | | MRTD `d4f5ee3d5fe9a5a3cbb1df8c40946714f55d5918b9b0e9ecd82a1d8adeea668495901baee134e3152dd5e0e2d1781262` |
| `vmlinuz-7.0.0-34-generic` | `73d9c6e40b210deb638070d6af591a68bb6d7ff0280d0ec34c9ccf705a4f47ac` | 17009032 B | RTMR1 `dc26aab111d74fb3e36bf597bc19fbd9c152183237fcebe5b362007fa8a6135b0a7cb172de3a0815a9ec1fcac4f889b7` |
| initrd | `fae29cf71e03be42cbc47ab448a37939db1407cd33769b4b9918ffc278b391b8` | 82864902 B | RTMR2 `972547466cb6bcb8a23cd479e9258c3affbbc4f0ba2805d732477200d0dff8432447c7a775e70453cdb51f018a306ece` (with the cmdline below) |

Kernel cmdline: `root=LABEL=cloudimg-rootfs ro console=ttyS0`. Two of its
components need no large file and are asserted by the unit tests in both
languages:

- LoadOptions event digest, `sha384(utf16le("initrd=initrd " + cmdline) || 0x0000)`:
  `b8c85d40a1d555a451571e24d7d7c4c331bc15721d6e4b2a5cb5093214c44174822a0916aa4d622d4309644de99cd59c`
- initrd event digest, `sha384(initrd)`:
  `88de90bedcc560064688c74ccd6609a25ed9d48b0a0e13d8b2a558212724d8755b2c8114dcf04b8d51ea4cf7782e3091`

Replaying those two into a zeroed register gives the RTMR2 above. RTMR1 is
the Authenticode SHA-384 of the RAW kernel file (QEMU leaves the setup header
alone under `confidential-guest-support`) followed by the four constant edk2
events `Calling EFI Application from Boot Option`, `00 00 00 00`,
`Exit Boot Services Invocation`, `Exit Boot Services Returned with Success`.
The Authenticode range selection was additionally checked against the
`messageDigest` embedded in the signatures of three signed PEs (a 6.6 bzImage
signed with sbsign, `mmx64.efi`, `grubx64.efi.signed`), swapping the hash for
SHA-256 for the comparison.
