//! The QEMU argv builder, process spawn and graceful-stop escalation, a 1:1
//! port of the Python `QemuVM` (src/aleph/vm/hypervisors/qemu/qemuvm.py) for
//! the non-confidential persistent path.
//!
//! `build_argv` is the parity core: it reproduces `QemuVM.start()`'s argv
//! byte for byte (the Python controller is the oracle; the conformance
//! fixtures pin the bytes). `run` spawns qemu with stdout/stderr wired to the
//! systemd journal (matching the `vm-{hash}-stdout` / `-stderr` tags), blocks
//! on the child, and escalates a graceful stop on SIGTERM.

use std::path::Path;
use std::process::Stdio;
use std::time::Duration;

use tokio::process::{Child, Command};

use crate::config::{Gpu, HostVolume, QemuConfig};
use crate::cpuid::SevHostInfo;
use crate::journal;
use crate::qmp;

/// The closed error vocabulary for the QEMU launch paths: the pre-launch
/// guards (`confidential_prelaunch_check`) and the spawn/supervise lifecycle
/// (`spawn_and_supervise`). Every variant reproduces a message the deleted
/// `Result<_, String>` code used to build inline; `main.rs`'s
/// `ControllerError::Qemu` wraps this transparently, so the rendered text at
/// the process boundary is unchanged.
#[derive(Debug, thiserror::Error)]
pub enum QemuError {
    #[error("Not running on an AMD SEV platform?")]
    NotSevPlatform,

    #[error("Missing guest owner certificates, cannot start the VM.")]
    MissingCerts,

    #[error("cannot spawn qemu: {source}")]
    Spawn { source: std::io::Error },

    #[error("cannot install the SIGTERM handler: {source}")]
    Sigterm { source: std::io::Error },

    #[error("cannot wait for qemu: {source}")]
    Wait { source: std::io::Error },

    #[error("cannot wait for qemu after stop: {source}")]
    WaitAfterStop { source: std::io::Error },
}

/// Seconds to wait for guest ACPI shutdown before escalating to QMP `quit`.
/// Shorter than the systemd `TimeoutStopSec=60` so QEMU still has time to
/// flush disk caches via `quit` before the SIGKILL deadline
/// (`GRACEFUL_SHUTDOWN_TIMEOUT` in qemuvm.py).
pub const GRACEFUL_SHUTDOWN_TIMEOUT: Duration = Duration::from_secs(50);

/// The `TimeoutStopSec` the systemd unit gives the controller; the remaining
/// budget after the ACPI wait is what QEMU gets to exit after a QMP `quit`.
pub const UNIT_STOP_TIMEOUT: Duration = Duration::from_secs(60);

/// Hard ceiling on a single QMP round-trip during the escalation. The blocking
/// client bounds itself to `qmp::COMMAND_DEADLINE`; this outer wrap guarantees
/// the escalation still advances (ACPI wait -> quit -> final wait) even if the
/// blocking-pool task were somehow slow to return, so a wedged or chatty
/// monitor can never eat into the 50s process-exit wait, let alone the 60s
/// systemd SIGKILL deadline this code exists to beat.
const QMP_CALL_BUDGET: Duration = Duration::from_secs(qmp::COMMAND_DEADLINE.as_secs() + 3);

/// The qga chardev socket path as the Python f-string renders it. Python
/// interpolates `qga_socket_path` unconditionally, so a `None` renders as the
/// literal string "None" (the create path always sets it, so this only bites a
/// hand-written config with the field absent). Shared by both argv builders.
fn qga_socket_or_none(config: &QemuConfig) -> &str {
    config.qga_socket_path.as_deref().unwrap_or("None")
}

/// Port of `QemuVM._get_host_volumes_args`: one `-drive` per host volume,
/// `format=raw`, readonly toggled by the volume flag. Shared by both builders
/// (the confidential `start()` reuses the same helper).
fn host_volume_args(host_volumes: &[HostVolume]) -> Vec<String> {
    let mut args = Vec::with_capacity(host_volumes.len() * 2);
    for volume in host_volumes {
        let read_only = if volume.read_only { "on" } else { "off" };
        args.push("-drive".into());
        args.push(format!(
            "file={},format=raw,readonly={read_only},media=disk,if=virtio",
            volume.path_on_host
        ));
    }
    args
}

/// Port of `QemuVM._get_gpu_args`: nothing when no GPUs, otherwise the
/// `-cpu host,host-phys-bits-limit=0x28` prefix and one vfio-pci `-device` per
/// GPU (`x-vga=on` when the GPU supports it). Shared by both builders. Note the
/// confidential base argv already carries an identical `-cpu` line, so the
/// GPU-mode confidential argv repeats it, exactly as the Python does.
fn gpu_args(gpus: &[Gpu]) -> Vec<String> {
    if gpus.is_empty() {
        return Vec::new();
    }
    let mut args = vec!["-cpu".into(), "host,host-phys-bits-limit=0x28".into()];
    for gpu in gpus {
        let mut device = format!("vfio-pci,host={},rombar=0", gpu.pci_host);
        if gpu.supports_x_vga {
            device.push_str(",x-vga=on");
        }
        args.push("-device".into());
        args.push(device);
    }
    args
}

/// The NUMA / hugetlb option suffix appended to a `memory-backend-memfd`
/// object. The order is byte-identical to the aleph-tee generator
/// (`sev_snp_qemu_args`): the hugetlb options FIRST
/// (`,hugetlb=on,hugetlbsize={1G|2M}`), then the NUMA binding
/// (`,host-nodes={node},policy=bind`). Empty when neither is set, so a config
/// without a placement renders no suffix at all. `hugepage_size` is the QEMU
/// `hugetlbsize` literal ("1G" or "2M") the daemon's allocator selected.
///
/// Shared by the plain, SEV/SEV-ES and SNP memory backends so the numa/hugepage
/// fragment is emitted identically wherever a memory backend appears.
fn memory_backend_suffix(numa_node: Option<u32>, hugepage_size: Option<&str>) -> String {
    // Invariant: the daemon only ever selects a hugepage size for a VM it also
    // placed on a NUMA node (`place_vm_numa` sets `numa_node` and
    // `hugepage_size` together). Make it explicit so no future caller can emit a
    // bare `hugetlb=on` fragment without the matching `host-nodes` binding on
    // the SNP `ram1` object. Debug-only, so release behaviour is unchanged.
    debug_assert!(
        hugepage_size.is_none() || numa_node.is_some(),
        "hugepage_size set without numa_node: refusing to emit hugetlb without host-nodes"
    );
    let mut suffix = String::new();
    if let Some(size) = hugepage_size {
        suffix.push_str(&format!(",hugetlb=on,hugetlbsize={size}"));
    }
    if let Some(node) = numa_node {
        suffix.push_str(&format!(",host-nodes={node},policy=bind"));
    }
    suffix
}

/// Build the QEMU argv for a non-confidential persistent VM, byte-identical
/// to `QemuVM.start()`. `argv[0]` is the qemu binary path (the exec target).
///
/// NUMA memory binding (increment C2): when `config.numa_node` is set (the
/// supervisor placed this VM on a node of a >1-node host), a
/// `memory-backend-memfd,id=pcram,...` object is added and wired via
/// `memory-backend=pcram` on the EFFECTIVE (last) `-machine` line, binding guest
/// RAM to that host node with `policy=bind` (plus optional `hugetlb`). When
/// `numa_node` is absent the argv is EXACTLY the pre-C2 bytes (no memory
/// backend, `-m` sizing unchanged), so single-node / no-NUMA hosts are byte
/// identical to the Python oracle.
pub fn build_argv(config: &QemuConfig) -> Vec<String> {
    // Q35 when GPUs are attached (i440FX cannot expose PCIe config space);
    // plain `pc` otherwise.
    let machine_type = if config.gpus.is_empty() { "pc" } else { "q35" };

    let qga_socket_path = qga_socket_or_none(config);

    // NUMA memory binding (C2): the `,memory-backend=pcram` machine suffix goes
    // on the LAST `-machine` line QEMU sees. In no-GPU mode that is the
    // migration-pin `pc-i440fx-6.2` line appended below, so the FIRST machine
    // takes no suffix; in GPU mode the first (q35) machine is the only one, so
    // it takes the suffix. Empty when the VM is not NUMA-placed (pre-C2 parity).
    let numa_active = config.numa_node.is_some();
    let machine_backend_suffix = if numa_active {
        ",memory-backend=pcram"
    } else {
        ""
    };
    let first_machine = if config.gpus.is_empty() {
        machine_type.to_string()
    } else {
        format!("{machine_type}{machine_backend_suffix}")
    };

    let mut args: Vec<String> = vec![
        config.qemu_bin_path.clone(),
        "-machine".into(),
        first_machine,
        "-enable-kvm".into(),
        "-nodefaults".into(),
        "-m".into(),
        // .count(): the bare MiB count QEMU expects ("-m 2048"); MiB's
        // Display would render "2048 MiB".
        config.mem_size_mb.count().to_string(),
        "-smp".into(),
        config.vcpu_count.to_string(),
        "-drive".into(),
        format!(
            "file={},media=disk,if=virtio,file.locking=off",
            config.image_path
        ),
        "-display".into(),
        "none".into(),
        "-monitor".into(),
        format!("unix:{},server,nowait", config.monitor_socket_path),
        "-device".into(),
        "virtio-serial".into(),
        "-chardev".into(),
        format!("socket,path={qga_socket_path},server=on,wait=off,id=qga0"),
        "-device".into(),
        "virtserialport,chardev=qga0,name=org.qemu.guest_agent.0".into(),
        "-qmp".into(),
        format!("unix:{},server,nowait", config.qmp_socket_path),
        "-serial".into(),
        "stdio".into(),
        "-nographic".into(),
        "-boot".into(),
        "order=c,reboot-timeout=1".into(),
    ];

    // NUMA memory backend (C2): a memfd bound to the placed host node. Only
    // emitted when the VM is NUMA-placed; otherwise the argv stays pre-C2. The
    // `-machine ...,memory-backend=pcram` wiring is added above. `-m` still
    // carries the sizing; QEMU sizes the backend from `size=` and binds it.
    if numa_active {
        args.push("-object".into());
        args.push(format!(
            "memory-backend-memfd,id=pcram,size={}M,share=on{}",
            config.mem_size_mb.count(),
            memory_backend_suffix(config.numa_node, config.hugepage_size.as_deref())
        ));
    }

    // NIC: only when interface_name is truthy (Python truthiness, so an empty
    // string is skipped, not just None).
    if let Some(interface_name) = &config.interface_name
        && !interface_name.is_empty()
    {
        args.push("-device".into());
        args.push("virtio-net-pci,netdev=net0,rombar=0".into());
        args.push("-netdev".into());
        args.push(format!(
            "tap,id=net0,ifname={interface_name},script=no,downscript=no"
        ));
    }

    // cloud-init drive: only when the path is truthy.
    if let Some(cloud_init_drive_path) = &config.cloud_init_drive_path
        && !cloud_init_drive_path.is_empty()
    {
        args.push("-drive".into());
        args.push(format!(
            "file={cloud_init_drive_path},media=cdrom,readonly=on,if=virtio"
        ));
    }

    // Memory ballooning is skipped when GPUs are passed through (vfio-pci
    // pins guest memory, conflicting with free-page reclaim).
    if config.gpus.is_empty() {
        args.push("-device".into());
        args.push("virtio-balloon-pci,free-page-reporting=on".into());
    }

    args.extend(host_volume_args(&config.host_volumes));

    // The no-GPU migration pin: a deliberate SECOND -machine (QEMU takes the
    // last) plus a migratable CPU. GPU mode uses its own -cpu below.
    if config.gpus.is_empty() {
        args.push("-machine".into());
        // The migration-pin machine is the LAST `-machine`, so the C2 NUMA
        // memory-backend wiring lands here in no-GPU mode (empty otherwise).
        args.push(format!("pc-i440fx-6.2{machine_backend_suffix}"));
        args.push("-cpu".into());
        args.push("host,migratable=on".into());
    }

    // GPU args appended last.
    args.extend(gpu_args(&config.gpus));

    args
}

/// Build the QEMU argv for a SEV / SEV-ES confidential persistent VM,
/// byte-identical to `QemuConfidentialVM.start()`
/// (src/aleph/vm/hypervisors/qemu_confidential/qemuvm.py). SEV-SNP is a
/// separate path (increment B1).
///
/// `sev` carries the host-CPUID-derived `cbitpos` / `reduced-phys-bits`,
/// injected (not read here) so the builder is testable off-SEV. The four
/// confidential fields (`ovmf_path`, `sev_dh_cert_file`, `sev_session_file`,
/// `sev_policy`) must be present; the dispatcher only routes here for a
/// confidential-shaped config, so their absence is an internal invariant
/// violation.
pub fn build_confidential_argv(config: &QemuConfig, sev: SevHostInfo) -> Vec<String> {
    // The four `.expect()`s below rely on `select_run_target` only dispatching a
    // confidential-shaped config here (all four SEV fields present). A future
    // unguarded caller trips this in debug builds instead of panicking
    // cryptically on one of the `.expect()`s. Release behavior is unchanged.
    debug_assert!(
        config.is_confidential(),
        "build_confidential_argv requires a confidential config (all four SEV fields present)"
    );

    let qga_socket_path = qga_socket_or_none(config);
    let ovmf_path = config
        .ovmf_path
        .as_deref()
        .expect("confidential config carries ovmf_path");
    let godh = config
        .sev_dh_cert_file
        .as_deref()
        .expect("confidential config carries sev_dh_cert_file");
    let session = config
        .sev_session_file
        .as_deref()
        .expect("confidential config carries sev_session_file");
    // Python stores `self.sev_policy = hex(config.sev_policy)`, so the policy is
    // rendered as a Python `hex()` string: lowercase, "0x"-prefixed, no leading
    // zeros (hex(1)=="0x1", hex(5)=="0x5", hex(48)=="0x30"). `format!("0x{:x}")`
    // reproduces it exactly.
    let policy = config
        .sev_policy
        .expect("confidential config carries sev_policy");
    let sev_policy = format!("0x{policy:x}");

    // NUMA memory binding (C2): a placed confidential VM binds its guest RAM to
    // the host node via a memfd wired onto the `confidential-guest-support=sev0`
    // machine line (`memory-backend=pcram`). Absent when unplaced, so the SEV /
    // SEV-ES argv stays byte-identical to pre-C2.
    let numa_active = config.numa_node.is_some();
    let confidential_machine = if numa_active {
        "q35,confidential-guest-support=sev0,memory-backend=pcram".to_string()
    } else {
        "q35,confidential-guest-support=sev0".to_string()
    };

    let mut args: Vec<String> = vec![
        config.qemu_bin_path.clone(),
        "-enable-kvm".into(),
        "-nodefaults".into(),
        "-m".into(),
        // .count(): the bare MiB count QEMU expects ("-m 2048"); MiB's
        // Display would render "2048 MiB".
        config.mem_size_mb.count().to_string(),
        "-smp".into(),
        config.vcpu_count.to_string(),
        // OVMF pflash FIRST, then the qcow2 rootfs (no file.locking=off here).
        "-drive".into(),
        format!("if=pflash,format=raw,unit=0,file={ovmf_path},readonly=on"),
        "-drive".into(),
        format!(
            "file={},media=disk,if=virtio,format=qcow2",
            config.image_path
        ),
        "-display".into(),
        "none".into(),
        // The confidential path keeps --no-reboot (the plain path dropped it).
        "--no-reboot".into(),
        "-monitor".into(),
        format!("unix:{},server,nowait", config.monitor_socket_path),
        // Note the ordering differs from the plain path: -qmp comes BEFORE the
        // qga chardev / virtio-serial block here.
        "-qmp".into(),
        format!("unix:{},server,nowait", config.qmp_socket_path),
        "-chardev".into(),
        format!("socket,path={qga_socket_path},server=on,wait=off,id=qga0"),
        "-device".into(),
        "virtio-serial".into(),
        "-device".into(),
        "virtserialport,chardev=qga0,name=org.qemu.guest_agent.0".into(),
        "-serial".into(),
        "stdio".into(),
        "-nographic".into(),
        "-boot".into(),
        "order=c,reboot-timeout=1".into(),
        // Start paused: the CPU is resumed externally after secret injection,
        // NOT by this controller.
        "-S".into(),
        "-object".into(),
        format!(
            "sev-guest,id=sev0,policy={sev_policy},cbitpos={},reduced-phys-bits={},\
             dh-cert-file={godh},session-file={session}",
            sev.cbitpos, sev.reduced_phys_bits
        ),
        "-machine".into(),
        confidential_machine,
        // Always host CPU with host-phys-bits-limit (the plain path only did
        // this in GPU mode).
        "-cpu".into(),
        "host,host-phys-bits-limit=0x28".into(),
    ];

    // NUMA memory backend (C2): the memfd the machine line binds to. Only
    // emitted for a NUMA-placed VM, keeping the unplaced argv pre-C2.
    if numa_active {
        args.push("-object".into());
        args.push(format!(
            "memory-backend-memfd,id=pcram,size={}M,share=on{}",
            config.mem_size_mb.count(),
            memory_backend_suffix(config.numa_node, config.hugepage_size.as_deref())
        ));
    }

    // NIC WITHOUT rombar=0 (the plain path adds rombar=0). Python truthiness:
    // an empty string is skipped.
    if let Some(interface_name) = &config.interface_name
        && !interface_name.is_empty()
    {
        args.push("-device".into());
        args.push("virtio-net-pci,netdev=net0".into());
        args.push("-netdev".into());
        args.push(format!(
            "tap,id=net0,ifname={interface_name},script=no,downscript=no"
        ));
    }

    // cloud-init drive: identical to the plain path.
    if let Some(cloud_init_drive_path) = &config.cloud_init_drive_path
        && !cloud_init_drive_path.is_empty()
    {
        args.push("-drive".into());
        args.push(format!(
            "file={cloud_init_drive_path},media=cdrom,readonly=on,if=virtio"
        ));
    }

    // Host volumes then GPU args, reusing the shared helpers. No balloon and no
    // migration pin on the confidential path.
    args.extend(host_volume_args(&config.host_volumes));
    args.extend(gpu_args(&config.gpus));

    args
}

/// The TEE machine/object fragment for an SEV-SNP launch, byte-identical to
/// `aleph_tee::sev_snp::qemu::sev_snp_qemu_args` for the B1 (no NUMA, no
/// hugepage) case. Emitted self-contained here so the controller does not take
/// a runtime dependency on `aleph-tee` (which pulls openssl/reqwest); a
/// dev-dependency conformance test asserts this matches the generator
/// byte-for-byte. The fragment is:
///   -cpu EPYC-v4
///   -machine q35,confidential-guest-support=sev0,memory-backend=ram1,vmport=off
///   -object memory-backend-memfd,id=ram1,size={mem}M,share=true
///   -object sev-snp-guest,id=sev0,cbitpos={cbitpos},reduced-phys-bits={reduced_phys_bits},kernel-hashes=on,policy={policy}
///   -nodefaults
///   -bios {ovmf}
///
/// `cbitpos` / `reduced_phys_bits` are HOST hardware properties read from CPUID
/// leaf `0x8000001F` at launch (via [`SevHostInfo`]), NOT hardcoded and NOT
/// measurement inputs: they configure memory encryption, not the launch digest,
/// so reading them from the host keeps the supervisor architecture-agnostic
/// without affecting the measurement. On the current EPYC target CPUID reports
/// `cbitpos=51, reduced_phys_bits=1`. `-cpu EPYC-v4` (a fixed vcpu-type that IS
/// a measurement input via the VMSA) stays fixed so measurements are
/// host-independent. See divergence 68.
///
/// `kernel-hashes=on` makes OVMF hash-verify the -kernel/-initrd/-append blobs;
/// `policy` is rendered `hex()`-style (`0x{:x}`) from the daemon-carried u32,
/// defaulting to 0x30000 upstream when the spec left it empty.
///
/// NUMA memory binding + hugepages (increment C2): when `numa_node` is set the
/// `ram1` memfd gains `,host-nodes={node},policy=bind`, and when `hugepage_size`
/// is set it gains `,hugetlb=on,hugetlbsize={1G|2M}` (hugetlb BEFORE host-nodes,
/// matching the generator). Both absent renders the exact B1 fragment, so an
/// unplaced SNP VM stays byte-identical to pre-C2. The aleph-tee generator
/// already carries this logic via `VmConfig.numa_node`/`hugepage_size`, so the
/// oracle test drives both with the same values.
///
/// `pub` so the conformance test can assert byte-parity against the aleph-tee
/// generator (the oracle).
pub fn snp_tee_fragment(
    mem_size_mb: u64,
    sev_policy: u32,
    ovmf_path: &str,
    numa_node: Option<u32>,
    hugepage_size: Option<&str>,
    cbitpos: u32,
    reduced_phys_bits: u32,
) -> Vec<String> {
    let policy = format!("0x{sev_policy:x}");
    let suffix = memory_backend_suffix(numa_node, hugepage_size);
    vec![
        "-cpu".into(),
        "EPYC-v4".into(),
        "-machine".into(),
        "q35,confidential-guest-support=sev0,memory-backend=ram1,vmport=off".into(),
        "-object".into(),
        format!("memory-backend-memfd,id=ram1,size={mem_size_mb}M,share=true{suffix}"),
        "-object".into(),
        format!(
            "sev-snp-guest,id=sev0,cbitpos={cbitpos},reduced-phys-bits={reduced_phys_bits},\
             kernel-hashes=on,policy={policy}"
        ),
        "-nodefaults".into(),
        "-bios".into(),
        ovmf_path.to_string(),
    ]
}

/// Build the QEMU argv for an SEV-SNP measured-boot persistent VM (increment
/// B1). Unlike the SEV/SEV-ES path this is a MEASURED DIRECT-KERNEL boot: the
/// exact OVMF + kernel + initrd + append + `EPYC-v4` + vcpu count are what the
/// B2a Nix flake's `sev-snp-measure` covered, so they must be presented
/// verbatim or attestation will not match. There is NO session/godh file and NO
/// launch-secret injection (SNP secrets are injected at runtime via the in-guest
/// attest-agent), and the VM boots DIRECTLY (no `-S`), matching the aleph-cvm
/// donor.
///
/// Disk layout for the dm-verity rootfs: the rootfs (verity DATA device) is the
/// first virtio drive (`/dev/vda`), the hash tree is the daemon-inserted first
/// host volume (`/dev/vdb`); the guest `init` opens `veritysetup` with the
/// roothash carried in the measured cmdline.
///
/// The five SNP fields (`ovmf_path`, `kernel_path`, `initrd_path`,
/// `kernel_cmdline`, `sev_policy`) must be present; the dispatcher only routes
/// an SNP-marked config here, so their absence is an internal invariant
/// violation.
///
/// Unlike `build_argv` and `build_confidential_argv`, this path emits NO GPU
/// passthrough devices: confidential GPU passthrough (NVIDIA CC) into an SNP
/// guest is not supported yet. The daemon fails closed on an SNP spec that
/// carries GPUs (`snp_config_slice`), so an SNP config reaching here always has
/// an empty `gpus`; nothing is silently dropped.
///
/// `sev` carries the host-CPUID-derived `cbitpos` / `reduced-phys-bits`,
/// injected (not read here) so the builder is testable off-SEV and the argv is
/// architecture-agnostic. These are memory-encryption parameters, NOT
/// measurement inputs, so reading them from the host does not affect the launch
/// measurement (which pins `-cpu EPYC-v4`, the OVMF, kernel, initrd, cmdline and
/// vcpu count).
pub fn build_snp_argv(config: &QemuConfig, sev: SevHostInfo) -> Vec<String> {
    debug_assert!(
        config.is_snp(),
        "build_snp_argv requires an SNP config (sev_snp marker set)"
    );

    let qga_socket_path = qga_socket_or_none(config);
    let ovmf_path = config
        .ovmf_path
        .as_deref()
        .expect("SNP config carries ovmf_path");
    let kernel = config
        .kernel_path
        .as_deref()
        .expect("SNP config carries kernel_path");
    let initrd = config
        .initrd_path
        .as_deref()
        .expect("SNP config carries initrd_path");
    let cmdline = config
        .kernel_cmdline
        .as_deref()
        .expect("SNP config carries kernel_cmdline");
    let policy = config.sev_policy.expect("SNP config carries sev_policy");

    let mut args: Vec<String> = vec![
        config.qemu_bin_path.clone(),
        "-enable-kvm".into(),
        "-m".into(),
        config.mem_size_mb.count().to_string(),
        "-smp".into(),
        config.vcpu_count.to_string(),
        // Measured direct-kernel boot. OVMF (via -bios in the TEE fragment)
        // loads and hash-verifies these exact blobs; the cmdline carries the
        // dm-verity roothash. This trio plus the vcpu count and EPYC-v4 CPU
        // type is precisely what sev-snp-measure covered in B2a.
        "-kernel".into(),
        kernel.to_string(),
        "-initrd".into(),
        initrd.to_string(),
        "-append".into(),
        cmdline.to_string(),
        // rootfs = dm-verity DATA device (/dev/vda), read-only raw.
        "-drive".into(),
        format!(
            "file={},format=raw,if=virtio,readonly=on,media=disk",
            config.image_path
        ),
    ];

    // dm-verity hash tree (/dev/vdb) then any further host volumes, in order.
    args.extend(host_volume_args(&config.host_volumes));

    args.extend([
        "-display".into(),
        "none".into(),
        // SNP keeps --no-reboot like the SEV path.
        "--no-reboot".into(),
        "-monitor".into(),
        format!("unix:{},server,nowait", config.monitor_socket_path),
        // -qmp so the graceful-stop escalation (system_powerdown / quit) works;
        // SNP attestation itself is direct client-to-guest, not via this socket.
        "-qmp".into(),
        format!("unix:{},server,nowait", config.qmp_socket_path),
        "-chardev".into(),
        format!("socket,path={qga_socket_path},server=on,wait=off,id=qga0"),
        "-device".into(),
        "virtio-serial".into(),
        "-device".into(),
        "virtserialport,chardev=qga0,name=org.qemu.guest_agent.0".into(),
        "-serial".into(),
        "stdio".into(),
        "-nographic".into(),
    ]);

    // NIC WITHOUT rombar=0 (like the SEV path). Python truthiness: an empty
    // interface name is skipped. The measured cmdline carries NO `ip=`, so the
    // guest configures the interface via DHCP (measurement determinism).
    if let Some(interface_name) = &config.interface_name
        && !interface_name.is_empty()
    {
        args.push("-device".into());
        args.push("virtio-net-pci,netdev=net0".into());
        args.push("-netdev".into());
        args.push(format!(
            "tap,id=net0,ifname={interface_name},script=no,downscript=no"
        ));
    }

    // The SEV-SNP TEE fragment LAST (donor `build_qemu_command` appends the TEE
    // args last), byte-identical to the aleph-tee generator. NUMA node +
    // hugepage size (C2) bind the ram1 memfd when the VM was placed.
    args.extend(snp_tee_fragment(
        config.mem_size_mb.count(),
        policy,
        ovmf_path,
        config.numa_node,
        config.hugepage_size.as_deref(),
        sev.cbitpos,
        sev.reduced_phys_bits,
    ));

    args
}

/// Spawn qemu and supervise it: block on the child, and on SIGTERM run the
/// graceful-stop escalation. The port of `execute_persistent_vm` +
/// `handle_persistent_vm` for the non-confidential QEMU path.
pub async fn run(vm_hash: &str, config: &QemuConfig) -> Result<i32, QemuError> {
    let argv = build_argv(config);
    spawn_and_supervise(vm_hash, config, argv).await
}

/// Launch an existing SEV / SEV-ES confidential VM, the port of
/// `QemuConfidentialVM.start()` plus its two pre-launch guards. The VM starts
/// paused (`-S`); this controller does NOT inject the launch secret or resume
/// the CPU (that is the supervisor session flow).
pub async fn run_confidential(vm_hash: &str, config: &QemuConfig) -> Result<i32, QemuError> {
    // Read the host SEV info, then run the two pre-launch guards (factored into
    // `confidential_prelaunch_check` so they are unit-testable off-SEV). The
    // real read returns None off-SEV, which the check turns into the platform
    // refusal; on a real SEV host the behavior is unchanged.
    let sev = confidential_prelaunch_check(config, SevHostInfo::read())?;
    let argv = build_confidential_argv(config, sev);
    spawn_and_supervise(vm_hash, config, argv).await
}

/// Launch an SEV-SNP measured-boot VM (increment B1). There is NO
/// owner-certificate pre-launch guard (SNP has no session/godh handshake): the
/// VM boots directly and its secrets are injected at runtime over the attested
/// TLS channel by the in-guest attest-agent.
///
/// Like the SEV/SEV-ES path, `cbitpos` / `reduced-phys-bits` are read from the
/// host at launch via `SevHostInfo::read()` (CPUID leaf 0x8000001F), keeping the
/// supervisor architecture-agnostic. These are memory-encryption parameters, not
/// measurement inputs, so the host-derived value does not change the launch
/// measurement (which pins the fixed `-cpu EPYC-v4`). An SNP VM cannot run off
/// an AMD SEV platform, so a `None` read is refused up front.
pub async fn run_snp(vm_hash: &str, config: &QemuConfig) -> Result<i32, QemuError> {
    let sev = SevHostInfo::read().ok_or(QemuError::NotSevPlatform)?;
    let argv = build_snp_argv(config, sev);
    spawn_and_supervise(vm_hash, config, argv).await
}

/// The two confidential pre-launch guards, factored out as a pure function so
/// they are testable without SEV hardware. `sev` is the result of
/// `SevHostInfo::read()`:
///
/// - `None` (not an AMD SEV platform) becomes the platform refusal the Python
///   `secure_encryption_info()` returning None raises ("Not running on an AMD
///   SEV platform?").
/// - a `godh` or session file that does not exist as a file becomes the
///   missing-certificate refusal (Python raises `FileNotFoundError`).
/// - otherwise the `SevHostInfo` passes through unchanged.
fn confidential_prelaunch_check(
    config: &QemuConfig,
    sev: Option<SevHostInfo>,
) -> Result<SevHostInfo, QemuError> {
    // The two `.expect()`s rely on `select_run_target` only dispatching a
    // confidential-shaped config here; a future unguarded caller trips this in
    // debug builds instead of panicking cryptically.
    debug_assert!(
        config.is_confidential(),
        "confidential_prelaunch_check requires a confidential config (all four SEV fields present)"
    );

    // Guard (a): must be on an AMD SEV platform.
    let sev = sev.ok_or(QemuError::NotSevPlatform)?;

    // Guard (b): the guest-owner certificate + session files must exist. The
    // dispatcher only routes a confidential-shaped config here, so both fields
    // are present.
    let godh = config
        .sev_dh_cert_file
        .as_deref()
        .expect("confidential config carries sev_dh_cert_file");
    let session = config
        .sev_session_file
        .as_deref()
        .expect("confidential config carries sev_session_file");
    if !Path::new(godh).is_file() || !Path::new(session).is_file() {
        return Err(QemuError::MissingCerts);
    }

    Ok(sev)
}

/// The shared spawn + supervise lifecycle for both the plain and confidential
/// paths: wire stdout/stderr to the systemd journal, block on the child, and
/// on SIGTERM run the graceful-stop escalation. Only the argv differs between
/// the two callers.
async fn spawn_and_supervise(
    vm_hash: &str,
    config: &QemuConfig,
    argv: Vec<String>,
) -> Result<i32, QemuError> {
    tracing::debug!(?argv, "QEMU args");

    // stdout/stderr to the systemd journal, tagged like the Python controller
    // (journalctl -t vm-{hash}-stdout -t vm-{hash}-stderr).
    let stdout = journal::stream(&format!("vm-{vm_hash}-stdout"));
    let stderr = journal::stream(&format!("vm-{vm_hash}-stderr"));

    let mut command = Command::new(&argv[0]);
    command
        .args(&argv[1..])
        .stdin(Stdio::null())
        .stdout(stdout)
        .stderr(stderr);
    let mut child = command
        .spawn()
        .map_err(|source| QemuError::Spawn { source })?;
    tracing::info!(
        pid = child.id(),
        "Started QemuVm {vm_hash}. Log: journalctl -t vm-{vm_hash}-stdout -t vm-{vm_hash}-stderr"
    );

    let mut sigterm = tokio::signal::unix::signal(tokio::signal::unix::SignalKind::terminate())
        .map_err(|source| QemuError::Sigterm { source })?;

    let status = tokio::select! {
        status = child.wait() => {
            status.map_err(|source| QemuError::Wait { source })?
        }
        _ = sigterm.recv() => {
            tracing::debug!("Received SIGTERM");
            stop(vm_hash, config, &mut child).await;
            child
                .wait()
                .await
                .map_err(|source| QemuError::WaitAfterStop { source })?
        }
    };

    let code = status.code().unwrap_or(-1);
    tracing::warn!("Process terminated with {code}");
    Ok(code)
}

/// Graceful shutdown escalation, the port of `QemuVM.stop()`: ACPI powerdown,
/// wait up to `GRACEFUL_SHUTDOWN_TIMEOUT`, then QMP `quit` and wait the
/// remaining budget. QEMU flushing its caches on `quit` avoids the qcow2
/// corruption a SIGKILL would cause.
async fn stop(vm_hash: &str, config: &QemuConfig, child: &mut Child) {
    let qmp_socket_path = config.qmp_socket_path.clone();

    tracing::info!("Sending shutdown message to VM {vm_hash}");
    send_qmp(&qmp_socket_path, "system_powerdown").await;

    match tokio::time::timeout(GRACEFUL_SHUTDOWN_TIMEOUT, child.wait()).await {
        Ok(_) => {
            tracing::info!("VM {vm_hash} shut down gracefully after ACPI powerdown");
            return;
        }
        Err(_) => tracing::warn!(
            "VM {vm_hash} did not shut down within {}s, sending QMP quit",
            GRACEFUL_SHUTDOWN_TIMEOUT.as_secs()
        ),
    }

    // The guest ignored ACPI: tell QEMU to exit cleanly (flushes caches).
    send_qmp(&qmp_socket_path, "quit").await;

    let remaining = UNIT_STOP_TIMEOUT.saturating_sub(GRACEFUL_SHUTDOWN_TIMEOUT);
    match tokio::time::timeout(remaining, child.wait()).await {
        Ok(_) => tracing::info!("VM {vm_hash} exited after QMP quit"),
        Err(_) => tracing::warn!(
            "VM {vm_hash} still running {}s after QMP quit, systemd SIGKILL will handle it",
            remaining.as_secs()
        ),
    }
}

/// Send one fire-and-forget QMP command (`system_powerdown` or `quit`),
/// connecting only if the socket exists (`QemuVM._get_qmpclient`). Blocking
/// socket work runs on the blocking pool; failures are logged, not fatal
/// (the escalation continues regardless).
async fn send_qmp(qmp_socket_path: &str, command: &'static str) {
    let path = qmp_socket_path.to_string();
    let task = tokio::task::spawn_blocking(move || qmp::send_command(&path, command));
    // Cap the await so a hung monitor cannot stall the escalation: the blocking
    // client is self-bounded, and the orphaned task (if any) finishes on its
    // own deadline without holding up the next escalation step.
    match tokio::time::timeout(QMP_CALL_BUDGET, task).await {
        Ok(Ok(Ok(()))) => {}
        Ok(Ok(Err(error))) => tracing::warn!("QMP {command} failed: {error}"),
        Ok(Err(error)) => tracing::warn!("QMP {command} task panicked: {error}"),
        Err(_) => tracing::warn!(
            "QMP {command} did not complete within {}s, continuing escalation",
            QMP_CALL_BUDGET.as_secs()
        ),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// The remaining post-`quit` wait is the unit stop budget minus the ACPI
    /// wait: 60s - 50s = 10s. Pins the escalation arithmetic (`stop()` uses
    /// `UNIT_STOP_TIMEOUT.saturating_sub(GRACEFUL_SHUTDOWN_TIMEOUT)`). The full
    /// escalation against a real qemu is deferred to A3.
    #[test]
    fn the_post_quit_wait_is_ten_seconds() {
        assert_eq!(
            UNIT_STOP_TIMEOUT.saturating_sub(GRACEFUL_SHUTDOWN_TIMEOUT),
            Duration::from_secs(10)
        );
    }

    /// The per-command QMP budget must stay well under the process-exit wait so
    /// a wedged monitor cannot eat into the graceful-stop window.
    #[test]
    fn the_qmp_call_budget_is_well_under_the_graceful_wait() {
        assert!(QMP_CALL_BUDGET < GRACEFUL_SHUTDOWN_TIMEOUT);
        assert!(QMP_CALL_BUDGET >= qmp::COMMAND_DEADLINE);
    }

    /// Build a minimal confidential `QemuConfig` with the given godh / session
    /// paths, so the pre-launch guard can be exercised off-SEV.
    fn confidential_config(godh: &str, session: &str) -> QemuConfig {
        let json = format!(
            r#"{{"qemu_bin_path":"/usr/bin/qemu-system-x86_64",
                "image_path":"/img.qcow2","monitor_socket_path":"/m.sock",
                "qmp_socket_path":"/q.sock","vcpu_count":2,"mem_size_mb":2048,
                "host_volumes":[],"gpus":[],"ovmf_path":"/OVMF_CODE.fd",
                "sev_session_file":{session:?},"sev_dh_cert_file":{godh:?},
                "sev_policy":1}}"#
        );
        let config = QemuConfig::from_json(&json).expect("confidential config parses");
        assert!(config.is_confidential());
        config
    }

    /// Guard (a): `sev = None` (not an AMD SEV platform) yields the platform
    /// refusal, before any certificate check.
    #[test]
    fn prelaunch_check_refuses_when_not_on_a_sev_platform() {
        let config = confidential_config("/nonexistent/godh.b64", "/nonexistent/session.b64");
        let error = confidential_prelaunch_check(&config, None).unwrap_err();
        assert!(matches!(error, QemuError::NotSevPlatform));
        assert_eq!(error.to_string(), "Not running on an AMD SEV platform?");
    }

    /// Guard (b): a missing godh OR session file yields the missing-certificate
    /// refusal even on a (simulated) SEV platform. A tempdir holds one file
    /// present and one absent, covering both halves of the `||`.
    #[test]
    fn prelaunch_check_refuses_when_a_certificate_file_is_missing() {
        let dir = tempfile::tempdir().unwrap();
        let godh = dir.path().join("vm_godh.b64");
        let session = dir.path().join("vm_session.b64");
        let sev = SevHostInfo {
            cbitpos: 51,
            reduced_phys_bits: 1,
        };

        // godh present, session absent.
        std::fs::write(&godh, b"cert").unwrap();
        let config = confidential_config(godh.to_str().unwrap(), session.to_str().unwrap());
        let error = confidential_prelaunch_check(&config, Some(sev)).unwrap_err();
        assert!(matches!(error, QemuError::MissingCerts));
        assert_eq!(
            error.to_string(),
            "Missing guest owner certificates, cannot start the VM."
        );

        // session present, godh absent.
        std::fs::remove_file(&godh).unwrap();
        std::fs::write(&session, b"blob").unwrap();
        let config = confidential_config(godh.to_str().unwrap(), session.to_str().unwrap());
        let error = confidential_prelaunch_check(&config, Some(sev)).unwrap_err();
        assert!(matches!(error, QemuError::MissingCerts));
        assert_eq!(
            error.to_string(),
            "Missing guest owner certificates, cannot start the VM."
        );
    }

    /// Happy path: on a SEV platform with both certificate files present, the
    /// injected `SevHostInfo` passes through unchanged.
    #[test]
    fn prelaunch_check_passes_when_platform_and_certificates_are_present() {
        let dir = tempfile::tempdir().unwrap();
        let godh = dir.path().join("vm_godh.b64");
        let session = dir.path().join("vm_session.b64");
        std::fs::write(&godh, b"cert").unwrap();
        std::fs::write(&session, b"blob").unwrap();
        let config = confidential_config(godh.to_str().unwrap(), session.to_str().unwrap());
        let sev = SevHostInfo {
            cbitpos: 51,
            reduced_phys_bits: 1,
        };
        let checked = confidential_prelaunch_check(&config, Some(sev)).unwrap();
        assert_eq!(checked, sev);
    }

    // ── NUMA memory binding + hugepages (increment C2) ──────────────────
    //
    // These have NO Python oracle (Python never bound memory to a NUMA node),
    // so the with-node argv is pinned directly here. The without-node parity
    // (byte-identical to pre-C2) is proven both by the existing Python-generated
    // fixtures (which carry no numa_node) and by the explicit diffs below.

    /// A minimal plain config as JSON, with optional numa_node / hugepage_size.
    fn plain_config(numa_node: Option<u32>, hugepage_size: Option<&str>) -> QemuConfig {
        let numa = numa_node
            .map(|node| format!(r#","numa_node":{node}"#))
            .unwrap_or_default();
        let huge = hugepage_size
            .map(|size| format!(r#","hugepage_size":"{size}""#))
            .unwrap_or_default();
        let json = format!(
            r#"{{"qemu_bin_path":"/usr/bin/qemu-system-x86_64","image_path":"/img.qcow2",
                "monitor_socket_path":"/m.sock","qmp_socket_path":"/q.sock",
                "qga_socket_path":"/g.sock","vcpu_count":2,"mem_size_mb":2048,
                "host_volumes":[],"gpus":[]{numa}{huge}}}"#
        );
        QemuConfig::from_json(&json).expect("plain config parses")
    }

    #[test]
    fn plain_without_numa_is_byte_identical_to_pre_c2() {
        // No numa_node: no memory-backend object, no memory-backend= on either
        // machine line. This is the pre-C2 argv exactly.
        let argv = build_argv(&plain_config(None, None));
        assert!(
            !argv.iter().any(|arg| arg.contains("memory-backend")),
            "no memory-backend when unplaced: {argv:?}"
        );
        // The effective (last) machine is the bare migration pin.
        assert!(argv.contains(&"pc-i440fx-6.2".to_string()));
    }

    #[test]
    fn plain_with_numa_binds_memory_to_the_node() {
        let argv = build_argv(&plain_config(Some(1), None));
        // The memfd object bound to node 1, regular pages (no hugetlb).
        assert!(
            argv.contains(
                &"memory-backend-memfd,id=pcram,size=2048M,share=on,host-nodes=1,policy=bind"
                    .to_string()
            ),
            "{argv:?}"
        );
        assert!(!argv.iter().any(|arg| arg.contains("hugetlb")));
        // Wired onto the effective (last) machine, the no-GPU migration pin.
        assert!(argv.contains(&"pc-i440fx-6.2,memory-backend=pcram".to_string()));
        // The first machine keeps its bare form (QEMU takes the last -machine).
        assert!(argv.contains(&"pc".to_string()));
        // -m sizing is unchanged.
        let m = argv.iter().position(|a| a == "-m").unwrap();
        assert_eq!(argv[m + 1], "2048");
    }

    #[test]
    fn plain_with_numa_and_hugepages_adds_hugetlb() {
        let argv = build_argv(&plain_config(Some(0), Some("1G")));
        assert!(
            argv.contains(&"memory-backend-memfd,id=pcram,size=2048M,share=on,hugetlb=on,hugetlbsize=1G,host-nodes=0,policy=bind".to_string()),
            "{argv:?}"
        );
    }

    #[test]
    fn plain_gpu_wires_the_backend_onto_the_q35_machine() {
        // In GPU mode there is no migration pin, so the memory-backend= wiring
        // lands on the single q35 machine line.
        let json = r#"{"qemu_bin_path":"/usr/bin/qemu-system-x86_64","image_path":"/img.qcow2",
            "monitor_socket_path":"/m.sock","qmp_socket_path":"/q.sock",
            "qga_socket_path":"/g.sock","vcpu_count":2,"mem_size_mb":2048,
            "host_volumes":[],"gpus":[{"pci_host":"0000:01:00.0"}],"numa_node":1}"#;
        let argv = build_argv(&QemuConfig::from_json(json).unwrap());
        assert!(
            argv.contains(&"q35,memory-backend=pcram".to_string()),
            "{argv:?}"
        );
        assert!(
            argv.contains(
                &"memory-backend-memfd,id=pcram,size=2048M,share=on,host-nodes=1,policy=bind"
                    .to_string()
            )
        );
    }

    /// A minimal SEV/SEV-ES confidential config with optional numa_node.
    fn sev_config(numa_node: Option<u32>) -> QemuConfig {
        let numa = numa_node
            .map(|node| format!(r#","numa_node":{node}"#))
            .unwrap_or_default();
        let json = format!(
            r#"{{"qemu_bin_path":"/usr/bin/qemu-system-x86_64","image_path":"/img.qcow2",
                "monitor_socket_path":"/m.sock","qmp_socket_path":"/q.sock",
                "qga_socket_path":"/g.sock","vcpu_count":2,"mem_size_mb":2048,
                "host_volumes":[],"gpus":[],"ovmf_path":"/OVMF.fd",
                "sev_session_file":"/s.b64","sev_dh_cert_file":"/d.b64","sev_policy":1{numa}}}"#
        );
        let config = QemuConfig::from_json(&json).expect("sev config parses");
        assert!(config.is_confidential());
        config
    }

    #[test]
    fn sev_without_numa_is_byte_identical_to_pre_c2() {
        let sev = SevHostInfo {
            cbitpos: 51,
            reduced_phys_bits: 1,
        };
        let argv = build_confidential_argv(&sev_config(None), sev);
        assert!(!argv.iter().any(|arg| arg.contains("memory-backend")));
        assert!(argv.contains(&"q35,confidential-guest-support=sev0".to_string()));
    }

    #[test]
    fn sev_with_numa_binds_memory_on_the_sev0_machine() {
        let sev = SevHostInfo {
            cbitpos: 51,
            reduced_phys_bits: 1,
        };
        let argv = build_confidential_argv(&sev_config(Some(1)), sev);
        assert!(
            argv.contains(&"q35,confidential-guest-support=sev0,memory-backend=pcram".to_string()),
            "{argv:?}"
        );
        assert!(
            argv.contains(
                &"memory-backend-memfd,id=pcram,size=2048M,share=on,host-nodes=1,policy=bind"
                    .to_string()
            )
        );
    }

    /// A complete SNP config with optional numa/hugepage overlay.
    fn snp_config(numa_node: Option<u32>, hugepage_size: Option<&str>) -> QemuConfig {
        let numa = numa_node
            .map(|node| format!(r#","numa_node":{node}"#))
            .unwrap_or_default();
        let huge = hugepage_size
            .map(|size| format!(r#","hugepage_size":"{size}""#))
            .unwrap_or_default();
        let json = format!(
            r#"{{"qemu_bin_path":"/usr/bin/qemu-system-x86_64","image_path":"/img.ext4",
                "monitor_socket_path":"/m.sock","qmp_socket_path":"/q.sock",
                "qga_socket_path":"/g.sock","vcpu_count":2,"mem_size_mb":2048,
                "host_volumes":[],"gpus":[],"sev_snp":true,"ovmf_path":"/OVMF.fd",
                "sev_policy":196608,"kernel_path":"/bzImage","initrd_path":"/initrd",
                "kernel_cmdline":"console=ttyS0 roothash=abc"{numa}{huge}}}"#
        );
        let config = QemuConfig::from_json(&json).expect("snp config parses");
        assert!(config.is_snp());
        config
    }

    /// The EPYC target's host CPUID values, injected into the SNP builder in
    /// tests (the real launch path reads these from `SevHostInfo::read()`).
    fn epyc_sev_host_info() -> SevHostInfo {
        SevHostInfo {
            cbitpos: 51,
            reduced_phys_bits: 1,
        }
    }

    #[test]
    fn snp_without_numa_leaves_the_ram1_memfd_bare() {
        let argv = build_snp_argv(&snp_config(None, None), epyc_sev_host_info());
        assert!(
            argv.contains(&"memory-backend-memfd,id=ram1,size=2048M,share=true".to_string()),
            "{argv:?}"
        );
    }

    #[test]
    fn snp_with_numa_and_hugepages_binds_the_ram1_memfd() {
        let argv = build_snp_argv(&snp_config(Some(1), Some("2M")), epyc_sev_host_info());
        assert!(
            argv.contains(&"memory-backend-memfd,id=ram1,size=2048M,share=true,hugetlb=on,hugetlbsize=2M,host-nodes=1,policy=bind".to_string()),
            "{argv:?}"
        );
    }

    #[test]
    fn snp_cbit_params_come_from_the_injected_host_info() {
        // Inject a non-EPYC (cbitpos, reduced_phys_bits) pair and confirm the
        // SNP object reflects the host-derived values, not a hardcoded 51/1.
        let argv = build_snp_argv(
            &snp_config(None, None),
            SevHostInfo {
                cbitpos: 47,
                reduced_phys_bits: 2,
            },
        );
        assert!(
            argv.iter().any(|a| a.contains("sev-snp-guest")
                && a.contains("cbitpos=47")
                && a.contains("reduced-phys-bits=2")),
            "{argv:?}"
        );
        assert!(
            !argv.iter().any(|a| a.contains("cbitpos=51")),
            "cbitpos=51 must not be hardcoded: {argv:?}"
        );
    }
}
