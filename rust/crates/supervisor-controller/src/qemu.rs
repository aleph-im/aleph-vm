//! The QEMU argv builder, process spawn and graceful-stop escalation, a 1:1
//! port of the Python `QemuVM` (src/aleph/vm/hypervisors/qemu/qemuvm.py) for
//! the non-confidential persistent path.
//!
//! `build_argv` is the parity core: it reproduces `QemuVM.start()`'s argv
//! byte for byte (the Python controller is the oracle; the conformance
//! fixtures pin the bytes). `run` spawns qemu with stdout/stderr wired to the
//! systemd journal (matching the `vm-{hash}-stdout` / `-stderr` tags), blocks
//! on the child, and escalates a graceful stop on SIGTERM.

use std::process::Stdio;
use std::time::Duration;

use tokio::process::{Child, Command};

use crate::config::QemuConfig;
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

/// Build the QEMU argv for a non-confidential persistent VM, byte-identical
/// to `QemuVM.start()`. `argv[0]` is the qemu binary path (the exec target).
pub fn build_argv(config: &QemuConfig) -> Vec<String> {
    // Q35 when GPUs are attached (i440FX cannot expose PCIe config space);
    // plain `pc` otherwise.
    let machine_type = if config.gpus.is_empty() { "pc" } else { "q35" };

    // Python interpolates qga_socket_path unconditionally; a None renders as
    // the literal string "None" in the f-string. Reproduce that quirk (the
    // create path always sets it, so this only matters for a hand-written
    // config with the field absent).
    let qga_socket_path = config.qga_socket_path.as_deref().unwrap_or("None");

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

    for volume in &config.host_volumes {
        let read_only = if volume.read_only { "on" } else { "off" };
        args.push("-drive".into());
        args.push(format!(
            "file={},format=raw,readonly={read_only},media=disk,if=virtio",
            volume.path_on_host
        ));
    }

    // The no-GPU migration pin: a deliberate SECOND -machine (QEMU takes the
    // last) plus a migratable CPU. GPU mode uses its own -cpu below.
    if config.gpus.is_empty() {
        args.push("-machine".into());
        args.push("pc-i440fx-6.2".into());
        args.push("-cpu".into());
        args.push("host,migratable=on".into());
    }

    // GPU args appended last.
    if !config.gpus.is_empty() {
        args.push("-cpu".into());
        args.push("host,host-phys-bits-limit=0x28".into());
        for gpu in &config.gpus {
            let mut device = format!("vfio-pci,host={},rombar=0", gpu.pci_host);
            if gpu.supports_x_vga {
                device.push_str(",x-vga=on");
            }
            args.push("-device".into());
            args.push(device);
        }
    }

    args
}

/// Spawn qemu and supervise it: block on the child, and on SIGTERM run the
/// graceful-stop escalation. The port of `execute_persistent_vm` +
/// `handle_persistent_vm` for the QEMU path.
pub async fn run(vm_hash: &str, config: &QemuConfig) -> Result<i32, String> {
    let argv = build_argv(config);
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
}
