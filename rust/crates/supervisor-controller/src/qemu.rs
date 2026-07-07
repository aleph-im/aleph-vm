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

/// Build the QEMU argv for a non-confidential persistent VM, byte-identical
/// to `QemuVM.start()`. `argv[0]` is the qemu binary path (the exec target).
pub fn build_argv(config: &QemuConfig) -> Vec<String> {
    // Q35 when GPUs are attached (i440FX cannot expose PCIe config space);
    // plain `pc` otherwise.
    let machine_type = if config.gpus.is_empty() { "pc" } else { "q35" };

    let qga_socket_path = qga_socket_or_none(config);

    let mut args: Vec<String> = vec![
        config.qemu_bin_path.clone(),
        "-machine".into(),
        machine_type.into(),
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
        args.push("pc-i440fx-6.2".into());
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
        "q35,confidential-guest-support=sev0".into(),
        // Always host CPU with host-phys-bits-limit (the plain path only did
        // this in GPU mode).
        "-cpu".into(),
        "host,host-phys-bits-limit=0x28".into(),
    ];

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

/// The SEV-SNP guest C-bit position, hardcoded to 51 to match BOTH the
/// aleph-tee `sev_snp_qemu_args` generator (the byte-parity oracle) and the
/// B2a launch measurement, which was computed for `--vcpu-type EPYC-v4`. On an
/// AMD EPYC part the CPUID-reported C-bit position IS 51, so this is not a
/// guess: it is the fixed value the measurement assumes. Reading it from host
/// CPUID (as the SEV/SEV-ES path does via `SevHostInfo`) would produce the same
/// 51 on the measured target but break byte-parity with the generator, which
/// hardcodes it. See divergence 68.
const SNP_CBITPOS: u32 = 51;

/// The SEV-SNP guest reduced-phys-bits, hardcoded to 1 to match the generator
/// and the measurement (same rationale as [`SNP_CBITPOS`]).
const SNP_REDUCED_PHYS_BITS: u32 = 1;

/// The TEE machine/object fragment for an SEV-SNP launch, byte-identical to
/// `aleph_tee::sev_snp::qemu::sev_snp_qemu_args` for the B1 (no NUMA, no
/// hugepage) case. Emitted self-contained here so the controller does not take
/// a runtime dependency on `aleph-tee` (which pulls openssl/reqwest); a
/// dev-dependency conformance test asserts this matches the generator
/// byte-for-byte. The fragment is:
///   -cpu EPYC-v4
///   -machine q35,confidential-guest-support=sev0,memory-backend=ram1,vmport=off
///   -object memory-backend-memfd,id=ram1,size={mem}M,share=true
///   -object sev-snp-guest,id=sev0,cbitpos=51,reduced-phys-bits=1,kernel-hashes=on,policy={policy}
///   -nodefaults
///   -bios {ovmf}
///
/// `kernel-hashes=on` makes OVMF hash-verify the -kernel/-initrd/-append blobs;
/// `policy` is rendered `hex()`-style (`0x{:x}`) from the daemon-carried u32,
/// defaulting to 0x30000 upstream when the spec left it empty.
///
/// `pub` so the conformance test can assert byte-parity against the aleph-tee
/// generator (the oracle).
pub fn snp_tee_fragment(mem_size_mb: u64, sev_policy: u32, ovmf_path: &str) -> Vec<String> {
    let policy = format!("0x{sev_policy:x}");
    vec![
        "-cpu".into(),
        "EPYC-v4".into(),
        "-machine".into(),
        "q35,confidential-guest-support=sev0,memory-backend=ram1,vmport=off".into(),
        "-object".into(),
        format!("memory-backend-memfd,id=ram1,size={mem_size_mb}M,share=true"),
        "-object".into(),
        format!(
            "sev-snp-guest,id=sev0,cbitpos={SNP_CBITPOS},reduced-phys-bits={SNP_REDUCED_PHYS_BITS},\
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
pub fn build_snp_argv(config: &QemuConfig) -> Vec<String> {
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
    // args last), byte-identical to the aleph-tee generator.
    args.extend(snp_tee_fragment(
        config.mem_size_mb.count(),
        policy,
        ovmf_path,
    ));

    args
}

/// Spawn qemu and supervise it: block on the child, and on SIGTERM run the
/// graceful-stop escalation. The port of `execute_persistent_vm` +
/// `handle_persistent_vm` for the non-confidential QEMU path.
pub async fn run(vm_hash: &str, config: &QemuConfig) -> Result<i32, String> {
    let argv = build_argv(config);
    spawn_and_supervise(vm_hash, config, argv).await
}

/// Launch an existing SEV / SEV-ES confidential VM, the port of
/// `QemuConfidentialVM.start()` plus its two pre-launch guards. The VM starts
/// paused (`-S`); this controller does NOT inject the launch secret or resume
/// the CPU (that is the supervisor session flow).
pub async fn run_confidential(vm_hash: &str, config: &QemuConfig) -> Result<i32, String> {
    // Read the host SEV info, then run the two pre-launch guards (factored into
    // `confidential_prelaunch_check` so they are unit-testable off-SEV). The
    // real read returns None off-SEV, which the check turns into the platform
    // refusal; on a real SEV host the behavior is unchanged.
    let sev = confidential_prelaunch_check(config, SevHostInfo::read())?;
    let argv = build_confidential_argv(config, sev);
    spawn_and_supervise(vm_hash, config, argv).await
}

/// Launch an SEV-SNP measured-boot VM (increment B1). Unlike the SEV/SEV-ES
/// path there is NO host-CPUID read (cbitpos/reduced-phys-bits are the fixed
/// EPYC-v4 values the measurement assumes) and NO owner-certificate pre-launch
/// guard (SNP has no session/godh handshake): the VM boots directly and its
/// secrets are injected at runtime over the attested TLS channel by the in-guest
/// attest-agent.
pub async fn run_snp(vm_hash: &str, config: &QemuConfig) -> Result<i32, String> {
    let argv = build_snp_argv(config);
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
) -> Result<SevHostInfo, String> {
    // The two `.expect()`s rely on `select_run_target` only dispatching a
    // confidential-shaped config here; a future unguarded caller trips this in
    // debug builds instead of panicking cryptically.
    debug_assert!(
        config.is_confidential(),
        "confidential_prelaunch_check requires a confidential config (all four SEV fields present)"
    );

    // Guard (a): must be on an AMD SEV platform.
    let sev = sev.ok_or_else(|| "Not running on an AMD SEV platform?".to_string())?;

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
        return Err("Missing guest owner certificates, cannot start the VM.".to_string());
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
) -> Result<i32, String> {
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
        .map_err(|error| format!("cannot spawn qemu: {error}"))?;
    tracing::info!(
        pid = child.id(),
        "Started QemuVm {vm_hash}. Log: journalctl -t vm-{vm_hash}-stdout -t vm-{vm_hash}-stderr"
    );

    let mut sigterm = tokio::signal::unix::signal(tokio::signal::unix::SignalKind::terminate())
        .map_err(|error| format!("cannot install the SIGTERM handler: {error}"))?;

    let status = tokio::select! {
        status = child.wait() => {
            status.map_err(|error| format!("cannot wait for qemu: {error}"))?
        }
        _ = sigterm.recv() => {
            tracing::debug!("Received SIGTERM");
            stop(vm_hash, config, &mut child).await;
            child
                .wait()
                .await
                .map_err(|error| format!("cannot wait for qemu after stop: {error}"))?
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
        assert_eq!(error, "Not running on an AMD SEV platform?");
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
        assert_eq!(
            error,
            "Missing guest owner certificates, cannot start the VM."
        );

        // session present, godh absent.
        std::fs::remove_file(&godh).unwrap();
        std::fs::write(&session, b"blob").unwrap();
        let config = confidential_config(godh.to_str().unwrap(), session.to_str().unwrap());
        let error = confidential_prelaunch_check(&config, Some(sev)).unwrap_err();
        assert_eq!(
            error,
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
}
