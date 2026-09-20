# Operating confidential GPUs (NVIDIA CC)

This runbook covers everything a CRN operator does on the host to make one
NVIDIA confidential-computing GPU available to V-PROGRAM workloads: BIOS and
kernel prerequisites, binding the card away from the host driver, flipping
the card into CC mode once, confirming the CRN advertises it, and reading
the failure signatures when something is wrong. It does not cover guest-side
or client-side verification; see
[`../architecture/confidential.md`](../architecture/confidential.md),
"Confidential GPUs (NVIDIA CC)", for the trust model and the code that
implements it.

## 1. Requirements

- **Card**: NVIDIA RTX PRO 6000 Blackwell **Server Edition** (SPT CC), or
  NVIDIA Hopper H100/H200, PCIe or NVL (SPT CC, one card per VM). Verified
  end to end on an H200 NVL (`10de:233b`). The Workstation and Max-Q
  editions of the RTX PRO 6000 have no CC mode; only the Server Edition
  does.
- **VBIOS**: the card's VBIOS must be a version NVIDIA has published a
  reference manifest (RIM) for. The guest's verifier fetches the RIM for
  the card's exact VBIOS version at boot; there is no fallback if none is
  published. Check before deploying a card:

  ```bash
  curl -s https://rim.attestation.nvidia.com/v1/rim/ids | tr , '\n' | grep <board id>
  ```

  `<board id>` is the id as NVIDIA's RIM catalog spells it, e.g.
  `NV_GPU_VBIOS_1010_0230_894_9600D9000E` (board id, then the VBIOS version
  with the dots removed). A card whose VBIOS has no published RIM fails
  attestation with `RIM Not Found` in the guest console, and the guest
  powers off; update the VBIOS with the server vendor's firmware package to
  fix it.
- **Host CPU**: AMD EPYC Genoa or newer, with SEV-SNP enabled in the BIOS.
  A confidential GPU only ever attaches to an SEV-SNP guest; there is no
  confidential-GPU path for SEV or SEV-ES.
- **BIOS settings**: IOMMU on, above-4G decoding on, resizable BAR on. All
  three are needed for `vfio-pci` to bind the card and for OVMF to place its
  BAR1 in the 64-bit MMIO window the daemon sizes for it.
- **VFIO mapping limit**: `vfio_iommu_type1 dma_entry_limit=16777216`
  (`/etc/modprobe.d/`). An SNP guest's memory is tracked at page granularity,
  and the default limit of 65535 makes QEMU refuse the card with "possibly
  running out of DMA mappings".
- **QEMU**: 9.1 or newer. This is the existing SEV-SNP requirement, not a
  GPU-specific one: any host that can already launch a plain SNP guest meets
  it. See "Host requirements for SEV-SNP" in
  [`../architecture/confidential.md`](../architecture/confidential.md).
- **Daemon settings** (`src/aleph/vm/conf.py`): `ENABLE_GPU_SUPPORT=true`
  and `ENABLE_QEMU_SUPPORT=true`. `ENABLE_QEMU_SUPPORT` defaults to `true`
  already; `ENABLE_GPU_SUPPORT` defaults to `false` and must be set
  explicitly. The daemon's `check()` asserts `ENABLE_QEMU_SUPPORT` whenever
  `ENABLE_GPU_SUPPORT` is on, so the two must be set together.

## 2. Bind the card to vfio-pci at boot

The host must never load the NVIDIA driver: a driver holding the card would
both block `vfio-pci` from binding it and make the BAR0 CC-mode register
unreadable from outside the driver (or, worse, put the card in a state a
guest cannot verify). Bind the card to `vfio-pci` the same way any other
GPU-passthrough card on this host is bound, using the existing GPU
passthrough setup for this fleet (module blacklist for `nouveau`/`nvidia`,
`vfio-pci.ids=` or a udev/driver-override binding at boot). A card that the
host driver has grabbed is not vfio-bound and never appears in the
supervisor's GPU inventory at all, confidential or not.

If the NVIDIA host driver package is ever installed on this host, even
temporarily, a `softdep nvidia pre: vfio-pci` ordering in
`/etc/modprobe.d/` is not enough: on the next reboot the host driver still
grabs the card before `vfio-pci` gets a turn. What works is blacklisting
the driver outright:

```
blacklist nvidia
blacklist nvidia_drm
blacklist nvidia_modeset
blacklist nvidia_uvm
blacklist nouveau
install nvidia /bin/false
options vfio-pci ids=<vendor:device>
```

in `/etc/modprobe.d/`. Simplest is not installing the NVIDIA host driver
package on this host at all.

An unbound or vfio-bound card with no VM attached to it runtime-suspends
into D3hot when idle; a manual BAR0 read of a suspended card comes back all
ones, indistinguishable at a glance from a probe failure. This needs no
operator action: the daemon's CC-mode probe pins the card awake for the
duration of the read before touching BAR0, and releases it afterward, so a
correctly bound and CC-mode card still probes cleanly regardless of how
long it sat idle.

## 3. Enable CC mode once

CC mode is a setting on the card itself and persists across host reboots,
so this is a one-time step per card, not something the CRN or the daemon
manages at runtime.

```bash
git clone https://github.com/NVIDIA/gpu-admin-tools
sudo python3 nvidia_gpu_tools.py --devices gpus --query-cc-mode
sudo python3 nvidia_gpu_tools.py --devices <bdf> --set-cc-mode=on --reset-after-cc-mode-switch
sudo python3 nvidia_gpu_tools.py --devices <bdf> --query-cc-mode   # expect: on
```

`<bdf>` is the card's PCI bus/device/function (e.g. `0000:07:00.0`), the
same identifier the card shows up under in `lspci`. The reset the second
command performs is required for the mode change to take effect; running
`--query-cc-mode` again afterward is the confirmation step, not optional.

A card reporting `devtools` instead of `on` is a valid NVIDIA mode, used for
driver development, but it lifts confidentiality guarantees and is refused
by the CRN: `snp_config_slice` (`rust/crates/supervisor-daemon/src/lifecycle.rs`)
only ever admits a card whose probed mode is exactly `On`.

## 4. Confirm the advertisement

Once the card is bound to `vfio-pci` and in CC mode, the daemon's inventory
refresh (triggered by `GetHostInfo`, which the agent polls) probes the
card's BAR0 register and caches the result. Confirm the CRN sees it:

```bash
curl -s http://<crn>/about/capability | jq .tee
```

The response's `tee.nvidia_cc.devices` lists every card currently probed
`on` and not attached to a running VM; `tee.sev_snp` must also be present,
since `nvidia_cc` is only advertised alongside a working SNP launch
capability. This list can still include a card another user's in-flight
request already reserved: reservations are an agent-side, in-memory,
TTL-bound ledger (`CapacityManager.holds`,
`src/aleph/vm/agent/capacity.py`) that never reaches the daemon's
`HostInfo` or `get_machine_capability()`, so the capability advertisement
is not proof a listed card is free to take right this instant. A request
that loses that race is only rejected at create time, with the
`InsufficientResourcesError` naming `confidential_gpu` covered in
section 5. For the full per-card picture including cards attached to a VM
or in `devtools`/`off`, check:

```bash
curl -s http://<crn>/about/usage/system | jq '.gpu.devices[] | {device_id, arch, cc_mode}'
```

`cc_mode` is one of `"on"`, `"devtools"`, `"off"`, or absent (the field is
`null`/omitted when the probe has not run or failed for that card).

If `nvidia_cc` is absent from `/about/capability` while
`nvidia_gpu_tools.py --query-cc-mode` reports `on` on the host:

- Check that `sev_snp` is advertised in the same response. The `nvidia_cc`
  block is gated on it (`nvidia_cc_properties`,
  `src/aleph/vm/agent/resources.py`): a CC-mode card on a host that cannot
  currently launch SNP is not advertised as a usable capability.
- Check the daemon log for `GPU CC mode probe failed` or similar
  (`DaemonError::GpuProbe`, `rust/crates/supervisor-daemon/src/gpu_cc.rs`).
  The probe reads the card's BAR0 through
  `/sys/bus/pci/devices/<bdf>/resource0`; that file must be readable by the
  daemon's user (root by default). A permissions problem, a card not bound
  to `vfio-pci`, or a card of an unrecognized device ID all yield a silent
  "unknown" (advertises nothing) rather than an error surfaced to the API,
  so the daemon log is the only place this shows up.

## 5. Failure signatures

- **A V-PROGRAM powers off within a minute of boot, with
  `init: FATAL: gpu attestation failed: ...` in its console log.** The
  guest's `nvattest attest` call (`nix/init-gpu.sh`) could not complete
  RIM/OCSP verification. Two common causes: the guest could not reach
  `rim.attestation.nvidia.com` or `ocsp.ndis.nvidia.com` over the host's
  network (check egress from the VM's network namespace/bridge), or the
  driver RIM for the shipped driver version is not yet published on
  NVIDIA's RIM service (check NVIDIA's RIM service for the exact driver
  version pinned in the runtime manifest's `gpu.driver_version`). Since
  init fails closed and powers the VM off rather than booting without
  verification, this always shows as a launch that never reaches
  `RUNNING` with a live attested endpoint, not as a VM that boots and then
  behaves oddly.
- **`InvalidBackend ... is not in NVIDIA confidential-computing mode` on
  `CreateVm`.** The daemon's `snp_config_slice` probe saw the card's mode
  as `off`, `devtools`, or unknown (unprobed), not `on`. Re-run step 3's
  `--query-cc-mode` and step 4's checks.
- **`InsufficientResourcesError` with `confidential_gpu` in its
  `required` field.** Fewer CC-mode cards of the requested architecture
  (and of the requested `models`, when the message narrows them) are free
  than the message's `count`: the rest are held (by another V-PROGRAM's
  placement hold) or attached to a running VM. This is distinct from a
  plain `gpu_device_id` shortage (`resolve_confidential_gpus`,
  `src/aleph/vm/agent/capacity.py`), so the log and the scheduler can tell
  a confidential-GPU shortage from an ordinary one.
- **A multi-card V-PROGRAM boots but the driver refuses one or more
  cards.** The CRN attaches as many CC-mode cards as the message's `count`
  names (up to the schema's eight), and every stage is per card. What is
  not per card is NVIDIA's validation: multi-GPU confidential computing is
  validated on HGX B200/B300 with driver R590 or newer over encrypted
  NVLink, Hopper is one card per VM, and the RTX PRO 6000 Blackwell Server
  Edition lists it as not yet validated. The guest's `swiotlb` reservation
  is also sized per VM, not per card. Until a multi-card host has run the
  hardware pass, expect a two-card V-PROGRAM to be an experiment.

Quick reference for lower-level signatures, seen in the QEMU log or the
guest console directly rather than in an API response:

| Symptom | Cause | Fix |
| --- | --- | --- |
| QEMU log: `vfio ... possibly running out of DMA mappings ... Maximum possible DMA mappings: 65535` | Default `vfio_iommu_type1` `dma_entry_limit` is too small for an SNP guest's page-granular memory tracking | Set `dma_entry_limit=16777216` (section 1's VFIO mapping limit) |
| Guest console: `libspdm_check_crypto_backend: Error - libspdm expects LKCA but found stubs!` followed by `RmInitAdapter failed` | The GPU runtime image predates the kernel-crypto fix | Use a current GPU runtime |
| Guest console: `osInitNvMapping: *** Cannot attach gpu` on every client after the first one attached successfully | In CC mode the adapter initializes once per GPU reset; persistence mode was not enabled before the first client | Use a current GPU runtime (enables persistence mode before attestation) |
| Guest console: `RIM Not Found`, then `init: FATAL: gpu attestation failed: ...` | The card's VBIOS has no published reference manifest | Update the VBIOS (see section 1) |

## 6. What the CRN never does

- **No NVIDIA driver on the host.** The card is bound to `vfio-pci` for its
  entire life on this host; the NVIDIA kernel modules and userland live
  only inside the measured guest image (`nix/nvidia.nix`, `nix/init-gpu.sh`).
- **No RIM or OCSP traffic from the host.** RIM and OCSP verification is
  the guest's job at boot (`nvattest attest` inside `init-gpu.sh`), reached
  over the guest's own network path. The CRN process never talks to
  `rim.attestation.nvidia.com` or `ocsp.ndis.nvidia.com` itself.
- **No reading of the CC register while a VM owns the card.** The daemon's
  probe (`rust/crates/supervisor-daemon/src/gpu_cc.rs`) only ever runs
  against a card no VM's world-view entry currently attaches
  (`refresh_cc_modes_with`, `rust/crates/supervisor-daemon/src/service.rs`);
  once a card is attached to a guest, its cached mode is left untouched
  until the guest releases it.
