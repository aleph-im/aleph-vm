# Operating Intel TDX hosts

This runbook covers what a CRN operator does on the host to run V-PROGRAM
workloads as Intel TDX trust domains: BIOS and kernel prerequisites, the
QEMU and Intel DCAP quoting stack, confirming the CRN advertises the
capability, and the failure signatures when something is wrong. It does
not cover guest-side or client-side verification; see
[`../architecture/confidential.md`](../architecture/confidential.md) for
the trust model and the code that implements it. Confidential instances
and confidential GPUs are SEV-SNP only for now; a TDX host serves
V-PROGRAMs.

## 1. Requirements

- **CPU**: Intel Xeon with TDX (4th generation Xeon Scalable and newer,
  Xeon 6 included). Verified end to end on a Xeon 6731E.
- **BIOS settings**, all required, in this order of dependency: TME (Total
  Memory Encryption), TME-MT/TME-MK (multi-key) with a key split of at
  least 1 (the `KeySplit` or "TME-MK keys" knob; TDX needs private keys
  carved out of the TME-MK key space), SGX, TDX, and the TDX SEAM loader.
  A missing SGX or SEAM loader leaves `kvm_intel.tdx` off even with TDX
  itself enabled: the TDX module is loaded by SEAMLDR and quotes are
  produced by an SGX enclave.
- **Kernel**: 6.16 or newer (the first line with KVM TDX host support), booted
  with `kvm_intel.tdx=1` and `nohibernate`. The TDX module refuses to
  initialize while hibernation is possible, and the kernel then leaves
  TDX off without a BIOS-looking symptom; check `dmesg | grep -i tdx` for
  `virt/tdx: module initialized` versus an `initialization failed` line.
  The capability probe reads `/sys/module/kvm_intel/parameters/tdx`; it
  must say `Y`.
- **QEMU**: 10.1 or newer, built with libnuma. The TDX launch reuses the
  SNP `memory-backend-memfd` object with `host-nodes`/`policy=bind`, so a
  QEMU without NUMA support refuses every confidential create on a
  multi-socket host, TDX or not. Verified with 10.2.
- **TDVF**: nothing to install. The firmware ships in the runtime bundle
  (its `OVMF.fd` member is TDVF for a `platform: "tdx"` runtime) and its
  MRTD is part of the runtime's published measurements.
- **Intel DCAP quoting stack**, from Intel's SGX/DCAP package repository:
  - `tdx-qgs`: the Quote Generation Service. It listens on the unix
    socket `/var/run/tdx-qgs/qgs.socket`, which the daemon hands to QEMU
    as the TD's `quote-generation-socket`. If it runs elsewhere, set
    `ALEPH_VM_TDX_QGS_SOCKET` in the daemon's environment. No vsock is
    involved.
  - `libsgx-dcap-default-qpl`: the quote provider library QGS uses to
    fetch PCK certificates and collateral; `/etc/sgx_default_qcnl.conf`
    points it at the local PCCS below.
  - `sgx-dcap-pccs`: the Provisioning Certificate Caching Service. Its
    installer asks for an Intel PCS API key
    (api.portal.trustedservices.intel.com). Without it QGS can build a
    quote but no certificate chain, and every client verification fails.
  - `sgx-pck-id-retrieval-tool` (`PCKIDRetrievalTool`): **mandatory**, not an
    optimisation. Xeon 6 platforms are unknown to Intel PCS until their
    platform manifest is registered (PCS answers 404 for the PPID and QGS
    reports `No certificate data for this platform`). Run
    `PCKIDRetrievalTool -url https://localhost:8081 -user_token <PCCS user
    token> -use_secure_cert false` once after PCCS is up: PCCS registers the
    manifest with Intel and caches the PCK certificates, TCB info and CRLs.
    A BIOS `SgxFactoryReset` produces a new manifest and needs a re-run.
- **TCB status.** Clients appraise the quote against Intel's current TCB
  level. A host on old firmware (microcode CPUSVN or TDX module SVN behind
  Intel's TCB-R) verifies cryptographically but is reported `OutOfDate` with
  the matching INTEL-SA advisories, and the default client policy rejects it.
  Firmware updates fix that on the host side; nothing on the CRN can.
- **Daemon settings** (`src/aleph/vm/conf.py`):
  `ENABLE_CONFIDENTIAL_COMPUTING=true` and `ENABLE_QEMU_SUPPORT=true`. The
  daemon's startup check accepts a TDX host without `sevctl` or the AMD
  SEV modules: the TDX probe stands in for those gates.

### HPE servers

- **e820 fragmentation.** The TDX module wants convertible memory in a
  bounded number of contiguous ranges. Some HPE ROM revisions publish an
  e820 map with many small reserved holes, and the module then fails to
  initialize with a `too many memory regions` style message in `dmesg`.
  Merging the holes with a `memmap=<len>$<base>` kernel argument
  (reserving the fragmented span outright) works around it at the cost of
  that memory.
- **DIMM population.** ROMs newer than 1.10 refuse to enable SGX/TDX on
  DIMM populations HPE has not validated for them, and the BIOS knobs
  either disappear or silently stay off. Check the population against
  HPE's validated list before filing the BIOS ticket.

## 2. Confirm the advertisement

```bash
curl -s http://<crn>/about/capability | jq .tee
```

`tee.tdx` (`{"qgs": true}`) must be present. It is advertised only when
BOTH conditions hold: `/sys/module/kvm_intel/parameters/tdx` is `Y` and
a connection to the QGS socket succeeds. A TD without a reachable QGS
boots but can never be quoted, so a host with TDX on and QGS down is not
a TDX CRN. `properties.cpu.features` lists `tdx` under the same rule, and
the daemon's `HostInfo.tdx_supported` feeds both.

When the kernel has TDX on but `tee.tdx` is missing, `tee_unavailable_reason`
in the same response says why:
`TDX is enabled but the Quote Generation Service does not answer on
/var/run/tdx-qgs/qgs.socket`. Check `systemctl status qgsd` and that the
socket path matches `ALEPH_VM_TDX_QGS_SOCKET`. When the kernel has TDX off,
no reason is given: fix section 1 first.

The scheduler places `backend: "tdx"` V-PROGRAMs on CRNs advertising
`tee.tdx`, so a node that stops advertising it stops receiving them, with
no operator action.

## 3. What a TDX launch looks like

Useful when reading a QEMU argv or a guest console:

- `-machine q35,kernel-irqchip=split,confidential-guest-support=tdx0,...`
  and `-object {"qom-type":"tdx-guest","id":"tdx0","mrconfigid":"<b64>",
  "quote-generation-socket":{"type":"unix","path":"..."}}` with `-cpu host`.
  No `kernel-hashes`, no policy, no CPU-model pin: TDX measures the kernel,
  initrd and cmdline itself, and the registers do not depend on the model.
- The cmdline is the same for every deployment of a runtime:
  `console=ttyS0 root=/dev/mapper/verity-root ro roothash=<runtime>
  aleph_tdx_descriptor=1`. The per-deployment tokens (workload root hash,
  verified volumes) are on a 64 KiB raw drive attached LAST, starting with
  the line `ALEPH-TDX-DESCRIPTOR-v1`, and `mrconfigid` is the SHA-384 of
  that token line. The guest init checks the two against each other from a
  local TDREPORT before using the tokens, and powers off on a mismatch. The
  one exception is a plain-QEMU local run whose cmdline carries
  `aleph_insecure_unattested=1` (the CLI's `vprogram run`, never a CRN):
  there is no TD to report, so the init takes the tokens unchecked behind an
  `init: WARNING: INSECURE UNATTESTED MODE` console line.
- Memory floor: 2 GiB per TD (guest-side need, not a measurement input).
- A guest reboot ends the QEMU process: TD reset is not supported by the
  platform, so a TD that "reboots" is gone and shows up as an exited VM.

## 4. Failure signatures

- **`kvm_intel.tdx` reads `N` after a reboot with the parameter set.** The
  TDX module did not initialize. `dmesg | grep -i 'virt/tdx'` names the
  reason: a missing BIOS knob (section 1), hibernation still possible (add
  `nohibernate`), or the memory-region limit (HPE note above).
- **`tee.tdx` absent, `tee_unavailable_reason` names the QGS socket.** QGS
  is down or on another path. `ss -xl | grep qgs` shows what it listens
  on; `journalctl -u qgsd` shows why it is not up (usually the QPL cannot
  reach PCCS).
- **`a TDX guest needs at least 2048 MiB` in the allocation response (or
  `InvalidBackend ... TDX guests need at least 2048 MiB` on `CreateVm`).**
  The message asked for less memory than a TD boots with; the agent refuses
  before staging, the daemon backstops it. Nothing to fix on the host.
- **`declares a confidential GPU, which TDX guests do not support` (or
  `InvalidBackend ... GPU passthrough is not supported on TDX guests`).**
  A TDX V-PROGRAM with a `gpu` block; confidential GPUs are an SEV-SNP
  feature today. Nothing to fix on the host.
- **`declares TEE backend 'sev_snp' but runtime ... is a tdx runtime`** (or
  the reverse). The message was measured for one platform but points at a
  runtime manifest of the other; the agent refuses the mismatch rather than
  boot a VM none of the message's registers describe. The CCN rejects the
  pair too, so this only shows up for a message that bypassed it.
- **`needs Intel TDX, which this host does not support`.** The scheduler
  placed a TDX V-PROGRAM on a host that does not advertise `tee.tdx` (see
  section 2 for the QGS and `kvm_intel.tdx` checks behind that flag).
- **Guest console: `init: FATAL: aleph_tdx_descriptor=1 but no TDX
  descriptor drive found`.** The descriptor drive did not reach the guest
  within the wait. Check the QEMU argv for the `<rootfs>.tdx_descriptor`
  drive as the last `-drive`.
- **Guest console: `init: FATAL: TDX descriptor rejected`, preceded by the
  attest-agent's reason on the same console.** Either the descriptor's
  token line does not hash to the launch's `mrconfigid` (the drive or the
  QEMU object was altered after the daemon wrote them), or the guest could
  not read a TDREPORT (`/dev/tdx_guest` missing: the runtime kernel lacks
  the TDX guest driver, so this is a runtime problem, not a host one).
  The guest fails closed and powers off.
- **Guest console: `init: FATAL: configfs mount failed`.** The runtime
  kernel has no configfs; again a runtime problem. Every published TDX
  runtime ships it.
- **Attested calls fail with `host quote service unreachable`.** The
  guest asked for a quote through configfs-tsm and QGS did not answer
  within 60 s. QGS died after the capability probe, or the socket path in
  the QEMU argv is stale (the daemon reads `ALEPH_VM_TDX_QGS_SOCKET` at
  create time). Restart `qgsd`; the next quote request succeeds without
  restarting the TD.
- **Attested calls fail at the client with a certificate or collateral
  error while quotes are produced.** PCCS has no PCK certificate for this
  platform: the API key is missing or wrong, or `PCKIDRetrievalTool` was
  never run. `journalctl -u pccs` on the host and PCCS's `/sgx/certification/v4/pckcert`
  responses tell which.

## 5. What the CRN never does

- **No per-deployment text in the cmdline.** The daemon derives the TDX
  cmdline from the runtime's dm-verity root hash alone and refuses a
  `tee.kernel_cmdline` supplied by the agent; the deployment's tokens
  travel on the descriptor drive, bound by `mrconfigid`.
- **No quote verification on the host.** The CRN launches the TD and
  passes the QGS socket through; verifying the quote, the register pins
  and Intel's collateral is the client's job at the RA-TLS handshake.
- **No Intel PCS traffic from the daemon.** PCCS is the only host process
  that talks to Intel, and it is part of the DCAP stack, not of aleph-vm.
