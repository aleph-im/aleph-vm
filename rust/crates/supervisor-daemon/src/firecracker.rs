//! The ephemeral Firecracker launcher (increment 4).
//!
//! A literal port of the Python spawn/teardown mechanics for non-persistent
//! programs: `MicroVM` (src/aleph/vm/hypervisors/firecracker/microvm.py),
//! the `FirecrackerConfig` pydantic models
//! (src/aleph/vm/hypervisors/firecracker/config.py) and the
//! `SpecFirecrackerProgram.setup()` config assembly
//! (src/aleph/vm/supervisor/controllers/firecracker/spec_program.py).
//! Ephemeral programs are direct children of the daemon (design doc
//! decision 8): jailer chroot prep and setfacl, the Firecracker config
//! JSON (byte-for-byte the pydantic `model_dump_json(by_alias=True,
//! exclude_none=True, indent=4)` output, pinned by the committed
//! `firecracker-config.json` fixture), stdout/stderr wired to journald
//! under the `vm-{hash}-stdout`/`-stderr` identifiers, the vsock ready
//! handshake on `{vsock}_{ready_port}`, and kill-based teardown. No
//! systemd involvement, no graceful-stop dance.
//!
//! The [`ProgramLauncher`] seam keeps cargo tests hermetic: production uses
//! [`FirecrackerLauncher`], tests use [`FakeProgramLauncher`].

use std::io::{Read, Write};
use std::os::unix::net::{UnixListener, UnixStream};
use std::path::{Path, PathBuf};
use std::process::{Child, Command, Stdio};
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

use serde::Serialize;

use crate::config::Settings;

/// microvm.py VSOCK_PATH.
const VSOCK_PATH: &str = "/tmp/v.sock";

/// The runtime's control port (utils/runtime_channel.py
/// RUNTIME_CONTROL_PORT): the halt signal and RunProgramCode both dial
/// `CONNECT 52`, whatever ready_port the spec's guest channel names.
const RUNTIME_CONTROL_PORT: u32 = 52;

// ── The Firecracker config JSON (config.py, byte parity) ────────────────

/// `BootSource.args(enable_console, writable)`.
pub fn boot_args(enable_console: bool, writable: bool) -> String {
    let mut args = String::from(
        "reboot=k panic=1 pci=off nomodule swiotlb=noforce random.trust_cpu=on \
         i8042.noaux i8042.nomux i8042.dumbkbd",
    );
    args.push_str(if writable { " rw" } else { " ro" });
    if enable_console {
        format!("console=ttyS0 {args}")
    } else {
        args
    }
}

#[derive(Debug, Serialize)]
pub struct BootSource {
    pub kernel_image_path: String,
    pub boot_args: String,
}

#[derive(Debug, Serialize)]
pub struct Drive {
    pub drive_id: String,
    pub path_on_host: String,
    pub is_root_device: bool,
    pub is_read_only: bool,
}

#[derive(Debug, Serialize)]
pub struct MachineConfig {
    pub vcpu_count: u32,
    pub mem_size_mib: u64,
    pub smt: bool,
}

#[derive(Debug, Serialize)]
pub struct Vsock {
    pub vsock_id: String,
    pub guest_cid: u32,
    pub uds_path: String,
}

impl Default for Vsock {
    fn default() -> Self {
        Self {
            vsock_id: "1".to_string(),
            guest_cid: 3,
            uds_path: VSOCK_PATH.to_string(),
        }
    }
}

#[derive(Debug, Serialize)]
pub struct NetworkInterface {
    pub iface_id: String,
    pub guest_mac: String,
    pub host_dev_name: String,
}

/// The `FirecrackerConfig` model; field order follows the pydantic
/// declaration and `None` fields are excluded like `exclude_none`. Only
/// the TOP-LEVEL keys carry the `-` alias generator (config.py declares it
/// on FirecrackerConfig alone); nested models keep snake_case, which is
/// exactly the mixed convention Firecracker's own config format uses.
#[derive(Debug, Serialize)]
pub struct FirecrackerConfig {
    #[serde(rename = "boot-source")]
    pub boot_source: BootSource,
    pub drives: Vec<Drive>,
    #[serde(rename = "machine-config")]
    pub machine_config: MachineConfig,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub vsock: Option<Vsock>,
    #[serde(rename = "network-interfaces", skip_serializing_if = "Option::is_none")]
    pub network_interfaces: Option<Vec<NetworkInterface>>,
}

impl FirecrackerConfig {
    /// The exact bytes `MicroVM.save_configuration_file` writes:
    /// `model_dump_json(by_alias=True, exclude_none=True, indent=4)`
    /// (pydantic-core also renders through serde_json's pretty formatter).
    pub fn to_json(&self) -> String {
        let mut buffer = Vec::new();
        let formatter = serde_json::ser::PrettyFormatter::with_indent(b"    ");
        let mut serializer = serde_json::Serializer::with_formatter(&mut buffer, formatter);
        self.serialize(&mut serializer)
            .expect("a FirecrackerConfig always serializes");
        String::from_utf8(buffer).expect("serde_json emits UTF-8")
    }
}

/// `MicroVM.compute_device_name`: extra drives are vdb, vdc, ...
pub fn compute_device_name(index: usize) -> String {
    let letter = (b'a' + 1 + index as u8) as char;
    format!("vd{letter}")
}

// ── The launcher seam ────────────────────────────────────────────────────

/// Everything one ephemeral boot needs; resolved by the create path.
#[derive(Debug, Clone)]
pub struct ProgramBootRequest {
    pub vm_index: i64,
    pub vm_hash: String,
    pub kernel_path: String,
    pub rootfs_path: String,
    /// EXTRA disks in spec order: (host path, read_only).
    pub extra_disks: Vec<(String, bool)>,
    pub vcpus: u32,
    pub memory_mib: u64,
    /// `vmtap{vm_index}` when the VM got a tap.
    pub tap_device: Option<String>,
    /// The guest connects to `{vsock}_{ready_port}` to signal readiness.
    pub ready_port: u32,
    /// spec.guest_channel.ready_timeout_secs, or settings.INIT_TIMEOUT.
    pub init_timeout: Duration,
}

/// The launch failure vocabulary the wire distinguishes.
#[derive(Debug)]
pub enum ProgramBootError {
    /// MicroVMFailedInitError: the guest never signalled ready. The Python
    /// exception carries an empty message and maps to INTERNAL with the
    /// MICROVM_INIT_FAILED trailer code.
    InitTimeout,
    /// Everything else (spawn failures, config staging errors).
    Failed(String),
}

/// A booted program: what the world entry records.
pub struct BootedProgram {
    /// Host UDS endpoint of the guest channel (`MicroVM.vsock_path`).
    pub vsock_path: String,
    /// Raw bytes from the guest's ready signal (`MicroVM.init_payload`).
    pub ready_payload: Vec<u8>,
    pub handle: Arc<dyn ProgramHandle>,
}

/// Handle on a running ephemeral program. `teardown` is the MicroVM
/// teardown: halt attempt over the channel, kill, reap, artifact removal.
/// Idempotent (Python calls it twice on failed boots).
pub trait ProgramHandle: Send + Sync + std::fmt::Debug {
    fn teardown(&self);
}

pub trait ProgramLauncher: Send + Sync {
    /// Boot an ephemeral Firecracker program, blocking through the vsock
    /// ready handshake. On failure the launcher has already torn down its
    /// own artifacts (process, chroot, sockets); the caller owns the
    /// tap/nftables cleanup, like the Python VmExecution.start except
    /// branch.
    fn boot(&self, request: &ProgramBootRequest) -> Result<BootedProgram, ProgramBootError>;
}

// ── The production launcher (MicroVM port) ──────────────────────────────

pub struct FirecrackerLauncher {
    pub firecracker_path: PathBuf,
    pub jailer_path: PathBuf,
    pub jailer_base_dir: PathBuf,
    pub use_jailer: bool,
    /// settings.PRINT_SYSTEM_LOGS: guest console + journald wiring.
    pub enable_console: bool,
    /// The 1-second graces of MicroVM.teardown; tests shrink it.
    pub teardown_grace: Duration,
}

impl FirecrackerLauncher {
    pub fn from_settings(settings: &Settings) -> Self {
        Self {
            firecracker_path: settings.firecracker_path.clone(),
            jailer_path: settings.jailer_path.clone(),
            jailer_base_dir: settings.jailer_base_dir.clone(),
            use_jailer: settings.use_jailer,
            enable_console: settings.print_system_logs,
            teardown_grace: Duration::from_secs(1),
        }
    }
}

/// The MicroVM path derivations.
#[derive(Debug, Clone)]
struct MicroVmPaths {
    vm_index: i64,
    firecracker_bin: PathBuf,
    jailer_base_dir: PathBuf,
    use_jailer: bool,
}

impl MicroVmPaths {
    /// `{jailer_base_dir}/{firecracker_bin_name}/{vm_index}`.
    fn namespace_path(&self) -> PathBuf {
        let bin_name = self
            .firecracker_bin
            .file_name()
            .map(|name| name.to_string_lossy().into_owned())
            .unwrap_or_default();
        self.jailer_base_dir
            .join(bin_name)
            .join(self.vm_index.to_string())
    }

    fn jailer_root(&self) -> PathBuf {
        self.namespace_path().join("root")
    }

    fn socket_path(&self) -> PathBuf {
        if self.use_jailer {
            self.jailer_root().join("run/firecracker.socket")
        } else {
            PathBuf::from(format!("/tmp/firecracker-{}.socket", self.vm_index))
        }
    }

    /// `MicroVM.vsock_path`: `{jailer_root}{VSOCK_PATH}` jailed (string
    /// concatenation in Python), the fixed `/tmp/v.sock` otherwise.
    fn vsock_path(&self) -> String {
        if self.use_jailer {
            format!("{}{}", self.jailer_root().display(), VSOCK_PATH)
        } else {
            VSOCK_PATH.to_string()
        }
    }
}

/// `system(command)`: run, warn on failure, never fail the caller.
fn system(command: &mut Command) {
    let rendered = format!("{command:?}");
    match command.status() {
        Ok(status) if status.success() => {}
        Ok(status) => tracing::warn!(command = rendered, %status, "shell command failed"),
        Err(error) => tracing::warn!(command = rendered, %error, "cannot run shell command"),
    }
}

/// `setfacl()`: give the daemon's user access to /dev/kvm when it lacks
/// it. Best-effort, exactly like the Python helper.
fn setfacl() {
    // Python: os.access("/dev/kvm", R_OK | W_OK).
    let kvm = std::ffi::CString::new("/dev/kvm").expect("static path");
    // SAFETY: access(2) with a valid NUL-terminated path.
    if unsafe { libc::access(kvm.as_ptr(), libc::R_OK | libc::W_OK) } == 0 {
        return;
    }
    // SAFETY: geteuid has no preconditions.
    let uid = unsafe { libc::geteuid() };
    system(
        Command::new("sudo")
            .arg("setfacl")
            .arg("-m")
            .arg(format!("u:{uid}:rw"))
            .arg("/dev/kvm"),
    );
}

/// getpwnam("jailman") uid/gid, the jailer drop-privileges identity.
fn jailman_ids() -> Result<(u32, u32), String> {
    let name = std::ffi::CString::new("jailman").expect("static name");
    // SAFETY: getpwnam with a valid NUL-terminated name; the returned
    // struct is only read before any other getpwnam call on this thread.
    let record = unsafe { libc::getpwnam(name.as_ptr()) };
    if record.is_null() {
        return Err("user 'jailman' does not exist".to_string());
    }
    // SAFETY: non-null record from getpwnam.
    unsafe { Ok(((*record).pw_uid, (*record).pw_gid)) }
}

/// Hardlink `source` to `{jailer_root}/opt/{filename}`, copying across
/// devices; an existing target is tolerated (Python enable_kernel /
/// enable_file_rootfs / enable_drive). Returns the in-jail path.
fn stage_into_jail(jailer_root: &Path, source: &str) -> Result<String, String> {
    let source_path = Path::new(source);
    let file_name = source_path
        .file_name()
        .ok_or_else(|| format!("path {source} has no file name"))?;
    let jail_relative = format!("/opt/{}", file_name.to_string_lossy());
    let target = jailer_root.join(&jail_relative[1..]);
    match std::fs::hard_link(source_path, &target) {
        Ok(()) => {}
        Err(error) if error.kind() == std::io::ErrorKind::AlreadyExists => {
            tracing::debug!(path = jail_relative, "file already exists in the jail");
        }
        Err(error) if error.raw_os_error() == Some(libc::EXDEV) => {
            // Cross-device link: copy instead, like the Python EXDEV branch.
            std::fs::copy(source_path, &target)
                .map_err(|error| format!("cannot copy {source} into the jail: {error}"))?;
        }
        Err(error) => return Err(format!("cannot link {source} into the jail: {error}")),
    }
    Ok(jail_relative)
}

/// sd_journal_stream_fd(3): a stream socket to journald carrying the
/// identifier header, exactly what the Python `journal.stream(identifier)`
/// wires the child's stdout/stderr to (priority LOG_INFO, no level prefix).
fn journal_stream(identifier: &str) -> Result<UnixStream, String> {
    let stream = UnixStream::connect("/run/systemd/journal/stdout")
        .map_err(|error| format!("cannot connect to the journald stream socket: {error}"))?;
    let header = format!("{identifier}\n\n6\n0\n0\n0\n0\n");
    (&stream)
        .write_all(header.as_bytes())
        .map_err(|error| format!("cannot write the journald stream header: {error}"))?;
    Ok(stream)
}

/// The mutable process half of a running (or torn down) program.
#[derive(Debug, Default)]
struct FcState {
    child: Option<Child>,
    journal_stdout: Option<UnixStream>,
    journal_stderr: Option<UnixStream>,
    ready_listener: Option<UnixListener>,
    torn_down: bool,
}

/// The production [`ProgramHandle`]: MicroVM.teardown over the recorded
/// paths.
struct FirecrackerHandle {
    paths: MicroVmPaths,
    vsock_path: String,
    /// Set only on the jailed path, like `MicroVM.config_file_path`; the
    /// unjailed temp file is deliberately left behind (Python parity).
    config_file_path: Option<PathBuf>,
    state: Mutex<FcState>,
    teardown_grace: Duration,
}

impl std::fmt::Debug for FirecrackerHandle {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter
            .debug_struct("FirecrackerHandle")
            .field("vm_index", &self.paths.vm_index)
            .field("vsock_path", &self.vsock_path)
            .finish()
    }
}

impl FirecrackerHandle {
    /// `MicroVM.shutdown()`: ask the guest init to halt over the channel;
    /// every failure is a warning.
    fn shutdown(&self) {
        let deadline = Duration::from_secs(5);
        let stream = match UnixStream::connect(&self.vsock_path) {
            Ok(stream) => stream,
            Err(error) => {
                tracing::warn!(
                    vm_index = self.paths.vm_index,
                    %error,
                    "VM cannot receive shutdown signal"
                );
                return;
            }
        };
        let _ = stream.set_read_timeout(Some(deadline));
        let _ = stream.set_write_timeout(Some(deadline));
        let mut stream = stream;
        if let Err(error) = stream.write_all(format!("CONNECT {RUNTIME_CONTROL_PORT}\n").as_bytes())
        {
            tracing::warn!(vm_index = self.paths.vm_index, %error, "shutdown write failed");
            return;
        }
        if let Err(error) = stream.write_all(b"halt") {
            tracing::warn!(vm_index = self.paths.vm_index, %error, "shutdown write failed");
            return;
        }
        let mut reader = std::io::BufReader::new(stream);
        let mut read_line = || -> Option<String> {
            use std::io::BufRead;
            let mut line = String::new();
            match reader.read_line(&mut line) {
                Ok(_) => Some(line),
                Err(_) => None,
            }
        };
        let _ack = read_line();
        let _msg = read_line();
        let stop = read_line();
        match stop {
            Some(line) if line == "STOPZ\n" => {}
            Some(line) => {
                tracing::warn!(
                    vm_index = self.paths.vm_index,
                    response = line.trim(),
                    "unexpected response from VM"
                );
            }
            None => {}
        }
    }
}

impl ProgramHandle for FirecrackerHandle {
    fn teardown(&self) {
        let mut state = self
            .state
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        if state.torn_down {
            return;
        }
        state.torn_down = true;

        // Best-effort guest halt (Python wraps shutdown() in wait_for(5);
        // here the socket timeouts bound it).
        self.shutdown();
        std::thread::sleep(self.teardown_grace);

        // stop(): terminate + kill, tolerate a process already gone; wait
        // reaps the zombie.
        if let Some(mut child) = state.child.take() {
            let _ = child.kill();
            let _ = child.wait();
        }
        // Close the journald streams and the ready listener.
        state.journal_stdout.take();
        state.journal_stderr.take();
        state.ready_listener.take();
        drop(state);

        // Removing files: the jailed config path (unjailed temp files stay
        // behind, Python parity) and the whole namespace directory.
        if let Some(config) = &self.config_file_path
            && let Err(error) = std::fs::remove_file(config)
            && error.kind() != std::io::ErrorKind::NotFound
        {
            tracing::warn!(path = %config.display(), %error, "cannot remove the config file");
        }
        let namespace = self.paths.namespace_path();
        if namespace.exists()
            && let Err(error) = std::fs::remove_dir_all(&namespace)
        {
            tracing::warn!(path = %namespace.display(), %error, "cannot remove the namespace");
        }
    }
}

impl FirecrackerLauncher {
    fn build_config(
        &self,
        paths: &MicroVmPaths,
        request: &ProgramBootRequest,
    ) -> Result<FirecrackerConfig, String> {
        // enable_kernel / enable_rootfs / enable_drive: stage files into
        // the chroot when jailed, pass host paths through otherwise. Block
        // device rootfs (the Python device-mapper branch) is not ported:
        // the spec path only ever stages regular files (ledgered).
        let rootfs_metadata = std::fs::metadata(&request.rootfs_path).map_err(|error| {
            format!(
                "Not a file or a block device: {}: {error}",
                request.rootfs_path
            )
        })?;
        if !rootfs_metadata.is_file() {
            return Err(format!(
                "Not a file or a block device: {}",
                request.rootfs_path
            ));
        }
        let jailer_root = paths.jailer_root();
        let (kernel_path, rootfs_path) = if paths.use_jailer {
            (
                stage_into_jail(&jailer_root, &request.kernel_path)?,
                stage_into_jail(&jailer_root, &request.rootfs_path)?,
            )
        } else {
            (request.kernel_path.clone(), request.rootfs_path.clone())
        };
        let mut drives = vec![Drive {
            drive_id: "rootfs".to_string(),
            path_on_host: rootfs_path,
            is_root_device: true,
            is_read_only: true,
        }];
        for (index, (path, read_only)) in request.extra_disks.iter().enumerate() {
            let path_on_host = if paths.use_jailer {
                stage_into_jail(&jailer_root, path)?
            } else {
                path.clone()
            };
            drives.push(Drive {
                drive_id: compute_device_name(index),
                path_on_host,
                is_root_device: false,
                is_read_only: *read_only,
            });
        }
        Ok(FirecrackerConfig {
            boot_source: BootSource {
                kernel_image_path: kernel_path,
                boot_args: boot_args(self.enable_console, false),
            },
            drives,
            machine_config: MachineConfig {
                vcpu_count: request.vcpus,
                mem_size_mib: request.memory_mib,
                smt: false,
            },
            vsock: Some(Vsock::default()),
            network_interfaces: Some(
                request
                    .tap_device
                    .iter()
                    .map(|device| NetworkInterface {
                        iface_id: "eth0".to_string(),
                        guest_mac: "AA:FC:00:00:00:01".to_string(),
                        host_dev_name: device.clone(),
                    })
                    .collect(),
            ),
        })
    }

    /// `MicroVM.prepare_jailer()`.
    fn prepare_jailer(&self, paths: &MicroVmPaths) -> Result<(), String> {
        let root = paths.jailer_root();
        if root.exists() {
            std::fs::remove_dir_all(&root)
                .map_err(|error| format!("cannot clear the jail {}: {error}", root.display()))?;
        }
        for dir in ["tmp", "opt", "dev/mapper"] {
            let path = root.join(dir);
            std::fs::create_dir_all(&path)
                .map_err(|error| format!("cannot create {}: {error}", path.display()))?;
        }
        system(
            Command::new("chown")
                .arg("jailman:jailman")
                .arg(root.join("tmp")),
        );
        Ok(())
    }

    /// `MicroVM.save_configuration_file`: the jailed path writes
    /// `{jailer_root}/tmp/config.json`; the unjailed path a temp file,
    /// chmod 0644 either way.
    fn save_configuration_file(
        &self,
        paths: &MicroVmPaths,
        config: &FirecrackerConfig,
    ) -> Result<PathBuf, String> {
        use std::os::unix::fs::PermissionsExt;
        let path = if paths.use_jailer {
            paths.jailer_root().join("tmp/config.json")
        } else {
            let file = tempfile::NamedTempFile::new()
                .map_err(|error| format!("cannot create the config temp file: {error}"))?;
            // delete=False: the file persists, like the Python tempfile.
            file.into_temp_path()
                .keep()
                .map_err(|error| format!("cannot persist the config temp file: {error}"))?
        };
        std::fs::write(&path, config.to_json())
            .map_err(|error| format!("cannot write {}: {error}", path.display()))?;
        std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o644))
            .map_err(|error| format!("cannot chmod {}: {error}", path.display()))?;
        Ok(path)
    }

    /// Spawn firecracker (or the jailer); stdout/stderr to journald when
    /// the console is enabled, /dev/null otherwise.
    fn spawn(
        &self,
        paths: &MicroVmPaths,
        request: &ProgramBootRequest,
        config_path: &Path,
        state: &mut FcState,
    ) -> Result<(), String> {
        let stdout_name = format!("vm-{}-stdout", request.vm_hash);
        let stderr_name = format!("vm-{}-stderr", request.vm_hash);
        let (stdout, stderr): (Stdio, Stdio) = if self.enable_console {
            let out = journal_stream(&stdout_name)?;
            let err = journal_stream(&stderr_name)?;
            let stdio_out: Stdio =
                std::os::fd::OwnedFd::from(out.try_clone().map_err(|error| error.to_string())?)
                    .into();
            let stdio_err: Stdio =
                std::os::fd::OwnedFd::from(err.try_clone().map_err(|error| error.to_string())?)
                    .into();
            state.journal_stdout = Some(out);
            state.journal_stderr = Some(err);
            (stdio_out, stdio_err)
        } else {
            (Stdio::null(), Stdio::null())
        };

        let mut command = if paths.use_jailer {
            let (uid, gid) = jailman_ids()?;
            let config_name = config_path
                .file_name()
                .map(|name| name.to_string_lossy().into_owned())
                .unwrap_or_default();
            let mut command = Command::new(&self.jailer_path);
            command
                .arg("--id")
                .arg(paths.vm_index.to_string())
                .arg("--exec-file")
                .arg(&self.firecracker_path)
                .arg("--uid")
                .arg(uid.to_string())
                .arg("--gid")
                .arg(gid.to_string())
                .arg("--chroot-base-dir")
                .arg(&self.jailer_base_dir)
                .arg("--")
                .arg("--config-file")
                .arg(format!("/tmp/{config_name}"));
            command
        } else {
            // start_firecracker: clear the fixed sockets a previous life
            // left behind.
            for stale in [PathBuf::from(VSOCK_PATH), paths.socket_path()] {
                if stale.exists() {
                    std::fs::remove_file(&stale).map_err(|error| {
                        format!(
                            "cannot remove the stale socket {}: {error}",
                            stale.display()
                        )
                    })?;
                }
            }
            let mut command = Command::new(&self.firecracker_path);
            command
                .arg("--api-sock")
                .arg(paths.socket_path())
                .arg("--config-file")
                .arg(config_path);
            command
        };
        tracing::debug!(command = ?command, "starting firecracker");
        let child = command
            .stdin(Stdio::piped())
            .stdout(stdout)
            .stderr(stderr)
            .spawn()
            .map_err(|error| format!("cannot spawn firecracker: {error}"))?;
        state.child = Some(child);
        Ok(())
    }

    /// `MicroVM.wait_for_init`: bind `{vsock}_{ready_port}`, wait for the
    /// guest's connection and keep its raw payload.
    fn wait_for_init(
        &self,
        paths: &MicroVmPaths,
        ready_port: u32,
        timeout: Duration,
        state: &mut FcState,
    ) -> Result<Vec<u8>, ProgramBootError> {
        let ready_path = format!("{}_{}", paths.vsock_path(), ready_port);
        // asyncio.start_unix_server unlinks an existing socket at the path.
        if let Ok(metadata) = std::fs::symlink_metadata(&ready_path) {
            use std::os::unix::fs::FileTypeExt;
            if metadata.file_type().is_socket() {
                let _ = std::fs::remove_file(&ready_path);
            }
        }
        let listener = UnixListener::bind(&ready_path).map_err(|error| {
            ProgramBootError::Failed(format!(
                "cannot bind the ready socket {ready_path}: {error}"
            ))
        })?;
        if paths.use_jailer {
            system(
                Command::new("chown")
                    .arg("jailman:jailman")
                    .arg(&ready_path),
            );
        }
        listener.set_nonblocking(true).map_err(|error| {
            ProgramBootError::Failed(format!("cannot configure the ready socket: {error}"))
        })?;

        let deadline = Instant::now() + timeout;
        let stream = loop {
            match listener.accept() {
                Ok((stream, _)) => break stream,
                Err(error) if error.kind() == std::io::ErrorKind::WouldBlock => {
                    if Instant::now() >= deadline {
                        tracing::warn!(
                            vm_index = paths.vm_index,
                            "never received signal from init"
                        );
                        state.ready_listener = Some(listener);
                        return Err(ProgramBootError::InitTimeout);
                    }
                    std::thread::sleep(Duration::from_millis(10));
                }
                Err(error) => {
                    state.ready_listener = Some(listener);
                    return Err(ProgramBootError::Failed(format!(
                        "the ready socket failed: {error}"
                    )));
                }
            }
        };
        // The Python callback reads up to 1 MB in one StreamReader.read.
        stream.set_nonblocking(false).ok();
        let remaining = deadline.saturating_duration_since(Instant::now());
        let _ = stream.set_read_timeout(Some(remaining.max(Duration::from_millis(1))));
        let mut payload = vec![0u8; 1_000_000];
        let mut stream = stream;
        let read = match stream.read(&mut payload) {
            Ok(size) => size,
            Err(error)
                if matches!(
                    error.kind(),
                    std::io::ErrorKind::WouldBlock | std::io::ErrorKind::TimedOut
                ) =>
            {
                state.ready_listener = Some(listener);
                return Err(ProgramBootError::InitTimeout);
            }
            Err(error) => {
                state.ready_listener = Some(listener);
                return Err(ProgramBootError::Failed(format!(
                    "reading the ready signal failed: {error}"
                )));
            }
        };
        payload.truncate(read);
        // The listener stays open for the VM's lifetime, like the Python
        // server (closed at teardown).
        state.ready_listener = Some(listener);
        tracing::debug!(vm_index = paths.vm_index, "signal from init received");
        Ok(payload)
    }
}

impl ProgramLauncher for FirecrackerLauncher {
    fn boot(&self, request: &ProgramBootRequest) -> Result<BootedProgram, ProgramBootError> {
        let paths = MicroVmPaths {
            vm_index: request.vm_index,
            firecracker_bin: self.firecracker_path.clone(),
            jailer_base_dir: self.jailer_base_dir.clone(),
            use_jailer: self.use_jailer,
        };
        let handle = Arc::new(FirecrackerHandle {
            paths: paths.clone(),
            vsock_path: paths.vsock_path(),
            config_file_path: None,
            state: Mutex::new(FcState::default()),
            teardown_grace: self.teardown_grace,
        });

        let booted = (|| -> Result<Vec<u8>, ProgramBootError> {
            if self.use_jailer {
                self.prepare_jailer(&paths)
                    .map_err(ProgramBootError::Failed)?;
            }
            setfacl();
            let config = self
                .build_config(&paths, request)
                .map_err(ProgramBootError::Failed)?;
            let config_path = self
                .save_configuration_file(&paths, &config)
                .map_err(ProgramBootError::Failed)?;
            {
                let mut state = handle
                    .state
                    .lock()
                    .unwrap_or_else(std::sync::PoisonError::into_inner);
                self.spawn(&paths, request, &config_path, &mut state)
                    .map_err(ProgramBootError::Failed)?;
                self.wait_for_init(&paths, request.ready_port, request.init_timeout, &mut state)
            }
        })();

        match booted {
            Ok(ready_payload) => Ok(BootedProgram {
                vsock_path: paths.vsock_path(),
                ready_payload,
                handle,
            }),
            Err(error) => {
                // The Python failure paths run the full fvm teardown (start's
                // except branch and VmExecution.start's) before propagating.
                handle.teardown();
                Err(error)
            }
        }
    }
}

// ── The guest channel exchange (RunProgramCode) ──────────────────────────

/// Failure vocabulary of one run-code exchange.
#[derive(Debug)]
pub enum ChannelError {
    /// VmInitNotConnectedError("MicroVM may have crashed").
    NotConnected,
    /// asyncio.TimeoutError: the wire message is empty (str(TimeoutError())).
    Timeout,
    Io(String),
}

/// The `_run_code_over_channel` wire exchange: `CONNECT 52\n` plus the
/// msgpack RunCodePayload, one ack line back, then the raw reply until EOF.
///
/// The scope msgpack passes through opaquely: the payload map
/// `{"scope": <scope>}` is assembled by prefixing the msgpack fixmap/fixstr
/// header to the request's own scope bytes, so the daemon never decodes
/// what the client encoded.
pub fn run_code_over_channel(
    channel_path: &str,
    scope_msgpack: &[u8],
    timeout_secs: f64,
) -> Result<Vec<u8>, ChannelError> {
    let stream = match UnixStream::connect(channel_path) {
        Ok(stream) => stream,
        Err(error)
            if matches!(
                error.kind(),
                std::io::ErrorKind::NotFound | std::io::ErrorKind::ConnectionRefused
            ) =>
        {
            return Err(ChannelError::NotConnected);
        }
        Err(error) => return Err(ChannelError::Io(error.to_string())),
    };
    if !timeout_secs.is_finite() || timeout_secs <= 0.0 {
        // asyncio.wait_for(..., timeout=0) times out immediately.
        return Err(ChannelError::Timeout);
    }
    let deadline = Instant::now() + Duration::from_secs_f64(timeout_secs);
    let remaining = |now: Instant| deadline.saturating_duration_since(now);

    let mut payload = format!("CONNECT {RUNTIME_CONTROL_PORT}\n").into_bytes();
    // msgpack {"scope": <scope>}: fixmap(1), fixstr(5) "scope", raw bytes.
    payload.push(0x81);
    payload.push(0xa5);
    payload.extend_from_slice(b"scope");
    payload.extend_from_slice(scope_msgpack);

    let mut stream = stream;
    let _ = stream.set_write_timeout(Some(
        remaining(Instant::now()).max(Duration::from_millis(1)),
    ));
    stream
        .write_all(&payload)
        .map_err(|error| ChannelError::Io(error.to_string()))?;

    // One ack line, then the reply until EOF, all under the deadline.
    let mut reply = Vec::new();
    let mut buffer = [0u8; 65536];
    let mut saw_ack = false;
    loop {
        let now = Instant::now();
        if now >= deadline {
            return Err(ChannelError::Timeout);
        }
        let _ = stream.set_read_timeout(Some(remaining(now).max(Duration::from_millis(1))));
        match stream.read(&mut buffer) {
            Ok(0) => break,
            Ok(size) => {
                let mut chunk = &buffer[..size];
                if !saw_ack {
                    // The ack terminates at the first newline; everything
                    // after it is reply payload (readline() + read()).
                    match chunk.iter().position(|byte| *byte == b'\n') {
                        Some(position) => {
                            saw_ack = true;
                            chunk = &chunk[position + 1..];
                        }
                        None => continue,
                    }
                }
                reply.extend_from_slice(chunk);
            }
            Err(error)
                if matches!(
                    error.kind(),
                    std::io::ErrorKind::WouldBlock | std::io::ErrorKind::TimedOut
                ) =>
            {
                return Err(ChannelError::Timeout);
            }
            Err(error) => return Err(ChannelError::Io(error.to_string())),
        }
    }
    Ok(reply)
}

// ── The hermetic fake ────────────────────────────────────────────────────

/// Test double: records boots and teardowns, no processes involved.
#[derive(Debug, Default)]
pub struct FakeProgramLauncher {
    inner: Mutex<FakeLauncherState>,
    /// Shared teardown log, visible to the entries' handles.
    teardowns: Arc<Mutex<Vec<String>>>,
}

#[derive(Debug, Default)]
struct FakeLauncherState {
    boots: Vec<ProgramBootRequest>,
    fail_next: Option<ProgramBootError>,
}

/// The payload every fake guest sends with its ready signal.
pub const FAKE_READY_PAYLOAD: &[u8] = b"fake-runtime-ready";

#[derive(Debug)]
struct FakeHandle {
    vm_hash: String,
    teardowns: Arc<Mutex<Vec<String>>>,
}

impl ProgramHandle for FakeHandle {
    fn teardown(&self) {
        self.teardowns
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
            .push(self.vm_hash.clone());
    }
}

impl FakeProgramLauncher {
    pub fn new() -> Self {
        Self::default()
    }

    pub fn boots(&self) -> Vec<ProgramBootRequest> {
        self.inner
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
            .boots
            .clone()
    }

    pub fn teardowns(&self) -> Vec<String> {
        self.teardowns
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
            .clone()
    }

    /// The next boot fails with this error.
    pub fn fail_next(&self, error: ProgramBootError) {
        self.inner
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
            .fail_next = Some(error);
    }
}

impl ProgramLauncher for FakeProgramLauncher {
    fn boot(&self, request: &ProgramBootRequest) -> Result<BootedProgram, ProgramBootError> {
        let mut inner = self
            .inner
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        if let Some(error) = inner.fail_next.take() {
            return Err(error);
        }
        inner.boots.push(request.clone());
        Ok(BootedProgram {
            vsock_path: format!("/tmp/fake-vsock-{}", request.vm_index),
            ready_payload: FAKE_READY_PAYLOAD.to_vec(),
            handle: Arc::new(FakeHandle {
                vm_hash: request.vm_hash.clone(),
                teardowns: self.teardowns.clone(),
            }),
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn the_config_json_matches_the_committed_pydantic_fixture() {
        // Byte parity with MicroVM.save_configuration_file for the fixture
        // inputs of scripts/generate_rust_fixtures.py (unjailed paths).
        let config = FirecrackerConfig {
            boot_source: BootSource {
                kernel_image_path: "/opt/firecracker/vmlinux.bin".to_string(),
                boot_args: boot_args(true, false),
            },
            drives: vec![
                Drive {
                    drive_id: "rootfs".to_string(),
                    path_on_host: "/var/cache/aleph/runtime.squashfs".to_string(),
                    is_root_device: true,
                    is_read_only: true,
                },
                Drive {
                    drive_id: compute_device_name(0),
                    path_on_host: "/var/cache/aleph/data.img".to_string(),
                    is_root_device: false,
                    is_read_only: false,
                },
            ],
            machine_config: MachineConfig {
                vcpu_count: 1,
                mem_size_mib: 256,
                smt: false,
            },
            vsock: Some(Vsock::default()),
            network_interfaces: Some(vec![NetworkInterface {
                iface_id: "eth0".to_string(),
                guest_mac: "AA:FC:00:00:00:01".to_string(),
                host_dev_name: "vmtap4".to_string(),
            }]),
        };
        let fixture = std::fs::read_to_string(
            crate::test_fixtures::fixtures_dir().join("firecracker-config.json"),
        )
        .unwrap();
        assert_eq!(config.to_json(), fixture);
    }

    #[test]
    fn boot_args_match_the_python_bootsource() {
        assert_eq!(
            boot_args(true, false),
            "console=ttyS0 reboot=k panic=1 pci=off nomodule swiotlb=noforce \
             random.trust_cpu=on i8042.noaux i8042.nomux i8042.dumbkbd ro"
        );
        assert_eq!(
            boot_args(false, true),
            "reboot=k panic=1 pci=off nomodule swiotlb=noforce \
             random.trust_cpu=on i8042.noaux i8042.nomux i8042.dumbkbd rw"
        );
    }

    #[test]
    fn extra_drives_name_vdb_onwards() {
        assert_eq!(compute_device_name(0), "vdb");
        assert_eq!(compute_device_name(1), "vdc");
        assert_eq!(compute_device_name(24), "vdz");
    }

    #[test]
    fn microvm_paths_match_the_python_properties() {
        let jailed = MicroVmPaths {
            vm_index: 7,
            firecracker_bin: PathBuf::from("/opt/firecracker/firecracker"),
            jailer_base_dir: PathBuf::from("/var/lib/aleph/vm/jailer"),
            use_jailer: true,
        };
        assert_eq!(
            jailed.namespace_path(),
            PathBuf::from("/var/lib/aleph/vm/jailer/firecracker/7")
        );
        assert_eq!(
            jailed.vsock_path(),
            "/var/lib/aleph/vm/jailer/firecracker/7/root/tmp/v.sock"
        );
        assert_eq!(
            jailed.socket_path(),
            PathBuf::from("/var/lib/aleph/vm/jailer/firecracker/7/root/run/firecracker.socket")
        );
        let unjailed = MicroVmPaths {
            use_jailer: false,
            ..jailed
        };
        assert_eq!(unjailed.vsock_path(), "/tmp/v.sock");
        assert_eq!(
            unjailed.socket_path(),
            PathBuf::from("/tmp/firecracker-7.socket")
        );
    }

    #[test]
    fn the_ready_handshake_captures_the_guest_payload() {
        // A fake guest connects to {vsock}_{port} and sends its payload;
        // wait_for_init must capture it raw.
        let tmp = tempfile::tempdir().unwrap();
        let launcher = FirecrackerLauncher {
            firecracker_path: PathBuf::from("/bin/false"),
            jailer_path: PathBuf::from("/bin/false"),
            jailer_base_dir: tmp.path().to_path_buf(),
            use_jailer: false,
            enable_console: false,
            teardown_grace: Duration::ZERO,
        };
        // Unjailed vsock_path is the fixed /tmp/v.sock; use a jailed-shaped
        // fake instead to keep the test parallel-safe.
        let paths = MicroVmPaths {
            vm_index: 900,
            firecracker_bin: PathBuf::from("firecracker"),
            jailer_base_dir: tmp.path().to_path_buf(),
            use_jailer: true,
        };
        std::fs::create_dir_all(paths.jailer_root().join("tmp")).unwrap();
        let ready_path = format!("{}_52", paths.vsock_path());

        let guest = std::thread::spawn({
            let ready_path = ready_path.clone();
            move || {
                for _ in 0..200 {
                    if let Ok(mut stream) = UnixStream::connect(&ready_path) {
                        stream.write_all(b"\x81\xa7version\xa52.0.0").unwrap();
                        return;
                    }
                    std::thread::sleep(Duration::from_millis(10));
                }
                panic!("the ready socket never appeared");
            }
        });
        let mut state = FcState::default();
        // use_jailer=true would chown; tolerated as a warning.
        let payload = launcher
            .wait_for_init(&paths, 52, Duration::from_secs(5), &mut state)
            .unwrap();
        guest.join().unwrap();
        assert_eq!(payload, b"\x81\xa7version\xa52.0.0");
        assert!(state.ready_listener.is_some());
    }

    #[test]
    fn a_silent_guest_times_out_as_microvm_init_failed() {
        let tmp = tempfile::tempdir().unwrap();
        let launcher = FirecrackerLauncher {
            firecracker_path: PathBuf::from("/bin/false"),
            jailer_path: PathBuf::from("/bin/false"),
            jailer_base_dir: tmp.path().to_path_buf(),
            use_jailer: false,
            enable_console: false,
            teardown_grace: Duration::ZERO,
        };
        let paths = MicroVmPaths {
            vm_index: 901,
            firecracker_bin: PathBuf::from("firecracker"),
            jailer_base_dir: tmp.path().to_path_buf(),
            use_jailer: true,
        };
        std::fs::create_dir_all(paths.jailer_root().join("tmp")).unwrap();
        let mut state = FcState::default();
        match launcher.wait_for_init(&paths, 52, Duration::from_millis(30), &mut state) {
            Err(ProgramBootError::InitTimeout) => {}
            other => panic!("expected InitTimeout, got {other:?}"),
        }
    }

    #[test]
    fn run_code_wraps_the_scope_opaquely_and_reads_the_reply() {
        // A fake runtime: reads the request, answers with an ack line and
        // a reply, closes. The daemon must send CONNECT 52 plus the
        // msgpack {"scope": <raw scope bytes>} and return the raw reply.
        let tmp = tempfile::tempdir().unwrap();
        let channel = tmp.path().join("v.sock");
        let listener = UnixListener::bind(&channel).unwrap();
        let server = std::thread::spawn(move || {
            let (mut stream, _) = listener.accept().unwrap();
            let mut request = vec![0u8; 4096];
            let read = stream.read(&mut request).unwrap();
            request.truncate(read);
            stream.write_all(b"OK 52\n").unwrap();
            stream.write_all(b"raw-reply-bytes").unwrap();
            request
        });

        let scope = b"\x81\xa4path\xa1/"; // msgpack {"path": "/"}
        let reply = run_code_over_channel(channel.to_str().unwrap(), scope, 5.0).unwrap();
        assert_eq!(reply, b"raw-reply-bytes");
        let request = server.join().unwrap();
        let mut expected = b"CONNECT 52\n".to_vec();
        expected.extend_from_slice(b"\x81\xa5scope");
        expected.extend_from_slice(scope);
        assert_eq!(request, expected);
    }

    #[test]
    fn run_code_reports_a_missing_channel_as_not_connected() {
        match run_code_over_channel("/nonexistent/v.sock", b"\x80", 1.0) {
            Err(ChannelError::NotConnected) => {}
            other => panic!("expected NotConnected, got {other:?}"),
        }
    }

    #[test]
    fn run_code_with_a_zero_timeout_times_out_like_wait_for() {
        let tmp = tempfile::tempdir().unwrap();
        let channel = tmp.path().join("v.sock");
        let _listener = UnixListener::bind(&channel).unwrap();
        match run_code_over_channel(channel.to_str().unwrap(), b"\x80", 0.0) {
            Err(ChannelError::Timeout) => {}
            other => panic!("expected Timeout, got {other:?}"),
        }
    }

    #[test]
    fn the_fake_launcher_records_boots_and_teardowns() {
        let launcher = FakeProgramLauncher::new();
        let request = ProgramBootRequest {
            vm_index: 4,
            vm_hash: "aa".to_string(),
            kernel_path: "/k".to_string(),
            rootfs_path: "/r".to_string(),
            extra_disks: vec![],
            vcpus: 1,
            memory_mib: 128,
            tap_device: None,
            ready_port: 52,
            init_timeout: Duration::from_secs(1),
        };
        let booted = launcher.boot(&request).unwrap();
        assert_eq!(booted.ready_payload, FAKE_READY_PAYLOAD);
        booted.handle.teardown();
        booted.handle.teardown();
        assert_eq!(launcher.boots().len(), 1);
        assert_eq!(
            launcher.teardowns(),
            vec!["aa".to_string(), "aa".to_string()]
        );
    }
}
