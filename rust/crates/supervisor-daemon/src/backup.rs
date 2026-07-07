//! Backups and restore (increment 5), a 1:1 port of the Python
//! `LocalSupervisor` backup surface (src/aleph/vm/supervisor/local.py) plus
//! the disk helpers it drives (src/aleph/vm/supervisor/controllers/qemu/backup.py).
//!
//! A backup is a `qemu-img convert -c` compressed copy of the VM's rootfs
//! (plus its non-read-only host volumes when `include_volumes` is set),
//! archived into an uncompressed `tar` next to a `.tar.sha256` checksum
//! sidecar and a `.tar.meta.json` metadata sidecar. The archive on disk is
//! the record; only in-flight and failed runs live in memory. Completed
//! archives are shared byte-for-byte with the Python daemon: a rollback
//! reads whatever the Rust daemon wrote and vice versa.
//!
//! `qemu-img` is a subprocess seam ([`DiskTools`]) so the archive-management
//! logic is unit-testable without a live QEMU. The restore paths (which stop
//! and restart the VM) live in `lifecycle.rs`, which owns the stop/start
//! machinery; they call the pure helpers here.

use std::collections::HashMap;
use std::io::Read;
use std::path::{Path, PathBuf};
use std::sync::{Arc, Mutex};
use std::time::{SystemTime, UNIX_EPOCH};

use sha2::{Digest, Sha256};
use supervisor_proto::pb;

use crate::lifecycle::RpcError;
use crate::ports::civil_from_days;
use crate::service::DaemonState;

/// `BACKUP_TTL_HOURS` (backup.py): archives older than this are expired
/// (cleanup at StartBackup) and no longer count as a fresh existing backup.
pub const BACKUP_TTL_HOURS: u64 = 24;

/// The rootfs archive member, always present in a backup. With
/// include_volumes the VM's non-read-only persistent volumes are added
/// alongside it, named by their on-disk basename stem plus `.qcow2`.
pub const BACKUP_ROOTFS_MEMBER: &str = "rootfs.qcow2";

/// `_BACKUP_DOWNLOAD_CHUNK_BYTES`: DownloadBackup streams the tar in 1 MiB
/// chunks with byte offsets so the client can detect gaps and resume.
pub const BACKUP_DOWNLOAD_CHUNK_BYTES: usize = 1024 * 1024;

// ── qemu-img seam ────────────────────────────────────────────────────────

/// A `qemu-img check` outcome. The Python `verify_qemu_disk` raises
/// `subprocess.CalledProcessError` when the image is invalid, which
/// `restore_from_image` catches to map a bad upload to InvalidBackendError
/// (a 400) while anything else (qemu-img missing) stays INTERNAL.
#[derive(Debug)]
pub enum QemuImgError {
    /// `qemu-img check` ran and reported a non-zero exit (a corrupt image);
    /// Python's `except subprocess.CalledProcessError`.
    CheckFailed(String),
    /// qemu-img could not be run at all (missing binary, spawn failure);
    /// Python's uncaught FileNotFoundError -> InternalSupervisorError.
    Unavailable(String),
}

/// The `qemu-img` operations the backup surface drives. A subprocess seam so
/// the archive-management logic is testable without a QEMU tree.
pub trait DiskTools: Send + Sync {
    /// `create_qemu_disk_backup`: `qemu-img convert -U -O qcow2 -c src dest`,
    /// a standalone compressed copy with no backing-file dependency.
    fn convert_compressed(&self, source: &Path, dest: &Path) -> Result<(), String>;
    /// `verify_qemu_disk`: `qemu-img check path`.
    fn check(&self, path: &Path) -> Result<(), QemuImgError>;
    /// `get_qemu_disk_virtual_size`: `qemu-img info --force-share
    /// --output=json path`, the `virtual-size` field.
    fn virtual_size(&self, path: &Path) -> Result<u64, String>;
}

/// Production [`DiskTools`]: shells out to `qemu-img` exactly like the Python
/// `run_in_subprocess` calls.
pub struct QemuImgTools;

impl QemuImgTools {
    fn qemu_img() -> Result<PathBuf, String> {
        // Python `_require_qemu_img`: `shutil.which("qemu-img")` or
        // FileNotFoundError("qemu-img not found in PATH").
        crate::checks::which("qemu-img").ok_or_else(|| "qemu-img not found in PATH".to_string())
    }
}

impl DiskTools for QemuImgTools {
    fn convert_compressed(&self, source: &Path, dest: &Path) -> Result<(), String> {
        let qemu_img = Self::qemu_img()?;
        let output = std::process::Command::new(qemu_img)
            .args(["convert", "-U", "-O", "qcow2", "-c"])
            .arg(source)
            .arg(dest)
            .output()
            .map_err(|error| format!("cannot run qemu-img convert: {error}"))?;
        if !output.status.success() {
            return Err(format!(
                "qemu-img convert failed ({}): {}",
                output.status,
                String::from_utf8_lossy(&output.stderr).trim()
            ));
        }
        Ok(())
    }

    fn check(&self, path: &Path) -> Result<(), QemuImgError> {
        let qemu_img = Self::qemu_img().map_err(QemuImgError::Unavailable)?;
        let output = std::process::Command::new(qemu_img)
            .arg("check")
            .arg(path)
            .output()
            .map_err(|error| {
                QemuImgError::Unavailable(format!("cannot run qemu-img check: {error}"))
            })?;
        if !output.status.success() {
            return Err(QemuImgError::CheckFailed(format!(
                "qemu-img check failed ({}): {}",
                output.status,
                String::from_utf8_lossy(&output.stderr).trim()
            )));
        }
        Ok(())
    }

    fn virtual_size(&self, path: &Path) -> Result<u64, String> {
        let qemu_img = Self::qemu_img()?;
        let output = std::process::Command::new(qemu_img)
            .args(["info", "--force-share", "--output=json"])
            .arg(path)
            .output()
            .map_err(|error| format!("cannot run qemu-img info: {error}"))?;
        if !output.status.success() {
            return Err(format!(
                "qemu-img info failed ({}): {}",
                output.status,
                String::from_utf8_lossy(&output.stderr).trim()
            ));
        }
        let value: serde_json::Value = serde_json::from_slice(&output.stdout)
            .map_err(|error| format!("cannot parse qemu-img info JSON: {error}"))?;
        value
            .get("virtual-size")
            .and_then(serde_json::Value::as_u64)
            .ok_or_else(|| "qemu-img info has no virtual-size".to_string())
    }
}

/// A hermetic [`DiskTools`] for tests: `convert` writes the source's bytes
/// (or a marker) to the destination so the archive path produces real files,
/// `check` succeeds, and `virtual_size` returns a configured constant. No
/// qemu-img subprocess is ever spawned.
pub struct FakeDiskTools {
    pub virtual_size: u64,
    pub check_ok: bool,
}

impl Default for FakeDiskTools {
    fn default() -> Self {
        Self {
            virtual_size: 1024,
            check_ok: true,
        }
    }
}

impl DiskTools for FakeDiskTools {
    fn convert_compressed(&self, source: &Path, dest: &Path) -> Result<(), String> {
        // Copy the source through so the archive carries deterministic bytes;
        // fall back to a marker when the source does not exist.
        match std::fs::copy(source, dest) {
            Ok(_) => Ok(()),
            Err(_) => std::fs::write(dest, b"fake-qcow2")
                .map_err(|error| format!("fake convert failed: {error}")),
        }
    }

    fn check(&self, _path: &Path) -> Result<(), QemuImgError> {
        if self.check_ok {
            Ok(())
        } else {
            Err(QemuImgError::CheckFailed("fake check failed".to_string()))
        }
    }

    fn virtual_size(&self, _path: &Path) -> Result<u64, String> {
        Ok(self.virtual_size)
    }
}

// ── In-memory job registry ───────────────────────────────────────────────

/// Backup bookkeeping. Completed archives live on disk (the source of
/// truth); the registry only holds in-flight (RUNNING) and FAILED runs, and
/// the per-VM serialization locks shared with the restore paths. Mirrors the
/// Python `_backup_jobs` / `_backup_tasks` / `_backup_locks` triple.
#[derive(Default)]
pub struct BackupRegistry {
    /// By backup_id, like `_backup_jobs`.
    jobs: Mutex<HashMap<String, pb::BackupInfo>>,
    /// The in-flight run per VM, like `_backup_tasks` (a done handle no
    /// longer counts as running).
    tasks: Mutex<HashMap<String, tokio::task::JoinHandle<()>>>,
    /// Per-VM lock shared by StartBackup's run and the restore paths: neither
    /// may touch the disks while the other converts or swaps them. Mirrors
    /// `_backup_locks`.
    locks: Mutex<HashMap<String, Arc<Mutex<()>>>>,
}

impl BackupRegistry {
    /// The per-VM disk lock, created on first use (`setdefault`).
    pub fn vm_lock(&self, vm_id: &str) -> Arc<Mutex<()>> {
        self.locks
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
            .entry(vm_id.to_string())
            .or_default()
            .clone()
    }

    fn job(&self, backup_id: &str) -> Option<pb::BackupInfo> {
        self.jobs
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
            .get(backup_id)
            .cloned()
    }

    fn jobs_for(&self, vm_id: Option<&str>) -> Vec<pb::BackupInfo> {
        self.jobs
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
            .values()
            .filter(|job| vm_id.is_none_or(|id| job.vm_id == id))
            .cloned()
            .collect()
    }

    fn running_job_for(&self, vm_id: &str) -> Option<pb::BackupInfo> {
        self.jobs
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
            .values()
            .find(|job| job.vm_id == vm_id && job.status == pb::BackupStatus::Running as i32)
            .cloned()
    }

    fn task_running(&self, vm_id: &str) -> bool {
        self.tasks
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
            .get(vm_id)
            .is_some_and(|handle| !handle.is_finished())
    }

    fn insert_job(&self, job: pb::BackupInfo) {
        self.jobs
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
            .insert(job.backup_id.clone(), job);
    }

    /// This run supersedes earlier FAILED attempts for the VM (Python drops
    /// them before registering the new RUNNING job).
    fn drop_failed_jobs_for(&self, vm_id: &str) {
        self.jobs
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
            .retain(|_, job| {
                !(job.vm_id == vm_id && job.status == pb::BackupStatus::Failed as i32)
            });
    }

    fn remove_job(&self, backup_id: &str) -> Option<pb::BackupInfo> {
        self.jobs
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
            .remove(backup_id)
    }

    fn set_task(&self, vm_id: &str, handle: tokio::task::JoinHandle<()>) {
        self.tasks
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
            .insert(vm_id.to_string(), handle);
    }

    fn clear_task(&self, vm_id: &str) {
        self.tasks
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
            .remove(vm_id);
    }
}

// ── Pure helpers (id validation, archive format) ─────────────────────────

/// `get_backup_directory`: BACKUP_DIRECTORY (default EXECUTION_ROOT/backups),
/// created if absent.
pub fn backup_directory(state: &DaemonState) -> Result<PathBuf, RpcError> {
    let dir = state.host.settings.backup_directory.clone();
    std::fs::create_dir_all(&dir).map_err(|error| {
        RpcError::Internal(format!("cannot create the backup directory: {error}"))
    })?;
    Ok(dir)
}

/// `_validate_backup_id`: reject ids that are not this VM's or that could
/// escape the backup directory (the id becomes a file name). Maps to
/// BackupNotFoundError with the backup_id as the message.
pub fn validate_backup_id(vm_id: &str, backup_id: &str) -> Result<(), RpcError> {
    let malformed = backup_id.is_empty()
        || backup_id.contains('/')
        || backup_id.contains('\\')
        || backup_id.contains("..");
    if malformed || !backup_id.starts_with(&format!("{vm_id}-")) {
        return Err(RpcError::BackupNotFound(backup_id.to_string()));
    }
    Ok(())
}

/// The `.tar.sha256` / `.tar.meta.json` / `.tar.partial` / `.restore.qcow2`
/// sidecar of a `<id>.tar` archive. Python composes these with
/// `Path.with_suffix(".tar.<x>")`, which for a single-suffix `<id>.tar` is
/// exactly the tar path with `.<x>` appended.
fn sidecar(tar_path: &Path, extra_suffix: &str) -> PathBuf {
    let mut name = tar_path.as_os_str().to_os_string();
    name.push(extra_suffix);
    PathBuf::from(name)
}

fn sha256_file(path: &Path) -> std::io::Result<String> {
    let mut file = std::fs::File::open(path)?;
    let mut hasher = Sha256::new();
    let mut buffer = [0u8; 65_536];
    loop {
        let read = file.read(&mut buffer)?;
        if read == 0 {
            break;
        }
        hasher.update(&buffer[..read]);
    }
    Ok(format!("{:x}", hasher.finalize()))
}

/// `_create_tar_and_checksum`: the uncompressed tar (members in the given
/// order), the sha256 sidecar (`{digest}  {name}\n`) and the meta.json
/// sidecar, written to a `.tar.partial` staging path and renamed into place
/// last so the `.tar` never holds a half-written archive.
fn create_tar_and_checksum(
    tar_path: &Path,
    backup_files: &[(String, PathBuf)],
    vm_hash: &str,
    timestamp: &str,
    source_sizes: &HashMap<String, u64>,
) -> Result<(), String> {
    let staging = sidecar(tar_path, ".partial");
    let build = || -> Result<(), String> {
        let file = std::fs::File::create(&staging)
            .map_err(|error| format!("cannot create the backup archive: {error}"))?;
        let mut builder = tar::Builder::new(file);
        for (member_name, source_path) in backup_files {
            builder
                .append_path_with_name(source_path, member_name)
                .map_err(|error| format!("cannot add {member_name} to the archive: {error}"))?;
        }
        builder
            .into_inner()
            .and_then(|file| file.sync_all())
            .map_err(|error| format!("cannot finalize the archive: {error}"))?;

        let checksum = sha256_file(&staging)
            .map_err(|error| format!("cannot checksum the archive: {error}"))?;
        let tar_name = tar_path
            .file_name()
            .and_then(|name| name.to_str())
            .unwrap_or_default();
        std::fs::write(
            sidecar(tar_path, ".sha256"),
            format!("{checksum}  {tar_name}\n"),
        )
        .map_err(|error| format!("cannot write the checksum sidecar: {error}"))?;

        let meta = BackupMetaFile {
            vm_hash: vm_hash.to_string(),
            created_at: timestamp.to_string(),
            source_sizes: if source_sizes.is_empty() {
                None
            } else {
                Some(source_sizes.clone())
            },
        };
        std::fs::write(
            sidecar(tar_path, ".meta.json"),
            serde_json::to_string(&meta)
                .map_err(|error| format!("cannot encode the metadata: {error}"))?,
        )
        .map_err(|error| format!("cannot write the metadata sidecar: {error}"))?;

        std::fs::rename(&staging, tar_path)
            .map_err(|error| format!("cannot move the archive into place: {error}"))?;
        Ok(())
    };
    build().inspect_err(|_| {
        let _ = std::fs::remove_file(&staging);
    })
}

/// `create_backup_archive`: `{vm_hash}-{timestamp}.tar` from the member map.
pub fn create_backup_archive(
    vm_hash: &str,
    backup_files: &[(String, PathBuf)],
    destination_dir: &Path,
    source_sizes: &HashMap<String, u64>,
    timestamp: &str,
) -> Result<PathBuf, String> {
    let tar_path = destination_dir.join(format!("{vm_hash}-{timestamp}.tar"));
    create_tar_and_checksum(&tar_path, backup_files, vm_hash, timestamp, source_sizes)?;
    Ok(tar_path)
}

/// `cleanup_expired_backups`: drop `.tar.partial` files and `.tar` archives
/// (plus their sidecars) older than the TTL. Returns the count of expired
/// archives deleted.
pub fn cleanup_expired_backups(backup_dir: &Path, ttl_hours: u64) -> u64 {
    let cutoff = now_unix_secs().saturating_sub(ttl_hours * 3600);
    let mut deleted = 0;
    let Ok(entries) = std::fs::read_dir(backup_dir) else {
        return 0;
    };
    let mut tars = Vec::new();
    for entry in entries.flatten() {
        let path = entry.path();
        let name = path
            .file_name()
            .and_then(|name| name.to_str())
            .unwrap_or_default();
        if name.ends_with(".tar.partial") {
            if file_mtime_secs(&path).is_some_and(|mtime| mtime < cutoff)
                && std::fs::remove_file(&path).is_ok()
            {
                tracing::info!(archive = name, "Deleted stale partial backup");
            }
        } else if name.ends_with(".tar") {
            tars.push(path);
        }
    }
    for tar_path in tars {
        if file_mtime_secs(&tar_path).is_some_and(|mtime| mtime < cutoff)
            && std::fs::remove_file(&tar_path).is_ok()
        {
            let _ = std::fs::remove_file(sidecar(&tar_path, ".sha256"));
            let _ = std::fs::remove_file(sidecar(&tar_path, ".meta.json"));
            tracing::info!(
                archive = tar_path
                    .file_name()
                    .and_then(|name| name.to_str())
                    .unwrap_or_default(),
                "Deleted expired backup"
            );
            deleted += 1;
        }
    }
    deleted
}

/// `find_existing_backup`: the newest non-expired `{vm_hash}-*.tar`, if any.
pub fn find_existing_backup(backup_dir: &Path, vm_hash: &str, ttl_hours: u64) -> Option<PathBuf> {
    let cutoff = now_unix_secs().saturating_sub(ttl_hours * 3600);
    let prefix = format!("{vm_hash}-");
    let mut matches: Vec<PathBuf> = std::fs::read_dir(backup_dir)
        .ok()?
        .flatten()
        .map(|entry| entry.path())
        .filter(|path| {
            let name = path
                .file_name()
                .and_then(|name| name.to_str())
                .unwrap_or_default();
            name.starts_with(&prefix) && name.ends_with(".tar")
        })
        .collect();
    // sorted(..., reverse=True): the lexicographically greatest name, which
    // is the most recent timestamp.
    matches.sort();
    matches
        .into_iter()
        .rev()
        .find(|tar_path| file_mtime_secs(tar_path).is_some_and(|mtime| mtime >= cutoff))
}

/// The metadata read back from a backup's sidecars.
#[derive(Debug, Default)]
struct BackupMeta {
    /// The `sha256:`-prefixed checksum, or empty when the sidecar is missing.
    checksum: String,
    /// The archive member names, read from the tar index.
    volumes: Vec<String>,
    source_sizes: HashMap<String, u64>,
}

/// `backup_metadata`: the checksum sidecar (prefixed `sha256:`), the tar
/// member names, and the source sizes from the meta sidecar. Any read/parse
/// failure yields an empty meta, exactly like `_backup_info_from_tar`'s
/// `except (tarfile.TarError, OSError)` fallback (widened here to any corrupt
/// sidecar, a hostile-state edge; ledger entry 47).
fn backup_metadata(tar_path: &Path) -> BackupMeta {
    let checksum = std::fs::read_to_string(sidecar(tar_path, ".sha256"))
        .ok()
        .and_then(|text| text.split_whitespace().next().map(str::to_string))
        .map(|digest| format!("sha256:{digest}"))
        .unwrap_or_default();

    let volumes = match std::fs::File::open(tar_path) {
        Ok(file) => match tar::Archive::new(file).entries() {
            Ok(entries) => {
                let mut names = Vec::new();
                for entry in entries {
                    let Ok(entry) = entry else {
                        return BackupMeta::default();
                    };
                    match entry.path() {
                        Ok(path) => names.push(path.to_string_lossy().into_owned()),
                        Err(_) => return BackupMeta::default(),
                    }
                }
                names
            }
            Err(_) => return BackupMeta::default(),
        },
        Err(_) => return BackupMeta::default(),
    };

    let source_sizes = std::fs::read_to_string(sidecar(tar_path, ".meta.json"))
        .ok()
        .and_then(|text| serde_json::from_str::<BackupMetaFile>(&text).ok())
        .and_then(|meta| meta.source_sizes)
        .unwrap_or_default();

    BackupMeta {
        checksum,
        volumes,
        source_sizes,
    }
}

/// The `.tar.meta.json` sidecar shape. Field order matches the Python
/// `json.dumps` key order; the serialization is compact where Python uses
/// `", "`/`": "` separators (semantically identical, ledger entry 6).
#[derive(Debug, serde::Serialize, serde::Deserialize)]
struct BackupMetaFile {
    vm_hash: String,
    created_at: String,
    #[serde(skip_serializing_if = "Option::is_none", default)]
    source_sizes: Option<HashMap<String, u64>>,
}

/// `_backup_info_from_tar`: a COMPLETE BackupInfo for an on-disk archive.
pub fn backup_info_from_tar(tar_path: &Path, vm_id: &str) -> Result<pb::BackupInfo, RpcError> {
    let metadata = std::fs::metadata(tar_path)
        .map_err(|error| RpcError::Internal(format!("cannot stat the backup archive: {error}")))?;
    let meta = backup_metadata(tar_path);
    let backup_id = tar_path
        .file_stem()
        .and_then(|stem| stem.to_str())
        .unwrap_or_default()
        .to_string();
    Ok(pb::BackupInfo {
        vm_id: vm_id.to_string(),
        backup_id,
        status: pb::BackupStatus::Complete as i32,
        size_bytes: metadata.len(),
        created_at_unix_secs: file_mtime_secs(tar_path).unwrap_or(0),
        error_message: String::new(),
        checksum: meta.checksum,
        volumes: meta.volumes,
        source_sizes: meta.source_sizes,
    })
}

/// `_extract_rootfs_member`: stream the rootfs member of a backup archive to
/// *destination*. Member-streamed on purpose (no extractall): archive member
/// names never touch the filesystem, so a crafted archive cannot escape.
pub fn extract_rootfs_member(tar_path: &Path, destination: &Path) -> Result<(), RpcError> {
    let tar_name = tar_path
        .file_name()
        .and_then(|name| name.to_str())
        .unwrap_or_default();
    let file = std::fs::File::open(tar_path)
        .map_err(|error| RpcError::Internal(format!("cannot open the backup archive: {error}")))?;
    let mut archive = tar::Archive::new(file);
    let entries = archive
        .entries()
        .map_err(|error| RpcError::Internal(format!("cannot read the backup archive: {error}")))?;
    for entry in entries {
        let mut entry = entry.map_err(|error| {
            RpcError::Internal(format!("cannot read an archive member: {error}"))
        })?;
        let path = entry.path().map_err(|error| {
            RpcError::Internal(format!("cannot read an archive member path: {error}"))
        })?;
        if path.to_string_lossy() == BACKUP_ROOTFS_MEMBER {
            if !entry.header().entry_type().is_file() {
                return Err(RpcError::Internal(format!(
                    "Backup member {BACKUP_ROOTFS_MEMBER} in {tar_name} is not a regular file"
                )));
            }
            let mut dst = std::fs::File::create(destination).map_err(|error| {
                RpcError::Internal(format!("cannot create the restore staging file: {error}"))
            })?;
            std::io::copy(&mut entry, &mut dst).map_err(|error| {
                RpcError::Internal(format!("cannot extract the rootfs member: {error}"))
            })?;
            return Ok(());
        }
    }
    Err(RpcError::Internal(format!(
        "Backup archive {tar_name} has no {BACKUP_ROOTFS_MEMBER} member"
    )))
}

/// `_restore_rootfs_sync`: copy the new image to a staging file in the rootfs
/// directory, move the current rootfs aside as `.pre-restore-<ts>.qcow2`, and
/// atomically rename the staging file into place. On failure, roll back.
/// Returns the path the old rootfs was saved to.
pub fn restore_rootfs(new_rootfs: &Path, current_rootfs: &Path) -> Result<PathBuf, RpcError> {
    let timestamp = strftime_compact(false);
    let old_backup = with_extension(current_rootfs, &format!("pre-restore-{timestamp}.qcow2"));
    let staging = with_extension(current_rootfs, "restore-staging.qcow2");
    let run = || -> std::io::Result<()> {
        std::fs::copy(new_rootfs, &staging)?;
        std::fs::rename(current_rootfs, &old_backup)?;
        std::fs::rename(&staging, current_rootfs)?;
        Ok(())
    };
    if let Err(error) = run() {
        // Rollback: if the old rootfs moved but the staging rename failed,
        // restore it from the backup.
        if !current_rootfs.exists() && old_backup.exists() {
            let _ = std::fs::rename(&old_backup, current_rootfs);
        }
        let _ = std::fs::remove_file(&staging);
        return Err(RpcError::Internal(format!(
            "cannot restore the rootfs: {error}"
        )));
    }
    tracing::info!(
        new = new_rootfs.file_name().and_then(|name| name.to_str()).unwrap_or_default(),
        current = %current_rootfs.display(),
        old = %old_backup.display(),
        "Restored rootfs"
    );
    Ok(old_backup)
}

/// Python `Path.with_suffix`: replace the final extension. The rootfs path is
/// `X.qcow2`; replacing `.qcow2` with the given suffix gives `X.<suffix>`.
fn with_extension(path: &Path, suffix: &str) -> PathBuf {
    path.with_extension(suffix)
}

// ── Disk selection ───────────────────────────────────────────────────────

/// `_qemu_rootfs_path` + `_backup_disk_paths`: the archive members for a
/// backup. The rootfs is always `rootfs.qcow2`; with include_volumes the
/// VM's non-read-only host volumes follow, each named by its basename stem
/// plus `.qcow2`. Member order is insertion order (rootfs first), like the
/// Python dict.
pub fn backup_disk_paths(
    entry: &crate::world::VmEntry,
    include_volumes: bool,
) -> Result<Vec<(String, PathBuf)>, RpcError> {
    let mut paths = vec![(BACKUP_ROOTFS_MEMBER.to_string(), qemu_rootfs_path(entry)?)];
    if include_volumes {
        for volume in &entry.config.host_volumes {
            if volume.read_only {
                continue;
            }
            let volume_path = PathBuf::from(&volume.path_on_host);
            let stem = volume_path
                .file_stem()
                .and_then(|stem| stem.to_str())
                .unwrap_or_default();
            paths.push((format!("{stem}.qcow2"), volume_path));
        }
    }
    Ok(paths)
}

/// `_qemu_rootfs_path`: the on-disk rootfs of a QEMU VM; backups and restores
/// operate on it. InvalidBackend for a program (no rootfs image), Internal
/// when the config carries no image path.
pub fn qemu_rootfs_path(entry: &crate::world::VmEntry) -> Result<PathBuf, RpcError> {
    if entry.is_program {
        return Err(RpcError::InvalidBackend(
            "Backups operate on the rootfs disk image; only QEMU VMs have one".to_string(),
        ));
    }
    if entry.config.image_path.is_empty() {
        return Err(RpcError::Internal(format!(
            "VM {} has no rootfs disk image",
            entry.vm_hash
        )));
    }
    Ok(PathBuf::from(&entry.config.image_path))
}

// ── Timestamps ───────────────────────────────────────────────────────────

fn now_unix_secs() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .as_secs()
}

fn file_mtime_secs(path: &Path) -> Option<u64> {
    std::fs::metadata(path)
        .and_then(|metadata| metadata.modified())
        .ok()?
        .duration_since(UNIX_EPOCH)
        .ok()
        .map(|elapsed| elapsed.as_secs())
}

/// `datetime.now(tz=utc).strftime(...)`. With microseconds:
/// `%Y%m%dT%H%M%S%fZ` (the backup id / archive stem). Without:
/// `%Y%m%dT%H%M%SZ` (the pre-restore backup name).
pub fn strftime_compact(with_micros: bool) -> String {
    let now = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default();
    let secs = now.as_secs();
    let micros = now.subsec_micros();
    let (year, month, day) = civil_from_days((secs / 86_400) as i64);
    let seconds_of_day = secs % 86_400;
    let hour = seconds_of_day / 3600;
    let minute = (seconds_of_day % 3600) / 60;
    let second = seconds_of_day % 60;
    if with_micros {
        format!("{year:04}{month:02}{day:02}T{hour:02}{minute:02}{second:02}{micros:06}Z")
    } else {
        format!("{year:04}{month:02}{day:02}T{hour:02}{minute:02}{second:02}Z")
    }
}

// ── RPC orchestration (the archive-management half) ──────────────────────

/// A snapshot of the world entry a backup needs, cloned out under the read
/// lock so the blocking disk work never holds it.
fn entry_snapshot(state: &DaemonState, vm_id: &str) -> Option<crate::world::VmEntry> {
    state.world.blocking_read().entries.get(vm_id).cloned()
}

/// `LocalSupervisor.start_backup`: idempotent per VM; a running job or a
/// fresh archive answers a second call. Otherwise it registers a RUNNING job,
/// spawns the background run, and returns that job. Takes `Arc<DaemonState>`
/// because the spawned run outlives this call.
pub fn start_backup(
    state: Arc<DaemonState>,
    vm_id: &str,
    quiesce_guest: bool,
    include_volumes: bool,
) -> Result<pb::BackupInfo, RpcError> {
    let entry =
        entry_snapshot(&state, vm_id).ok_or_else(|| RpcError::NotFound(vm_id.to_string()))?;
    let disk_paths = backup_disk_paths(&entry, include_volumes)?;
    let backup_dir = backup_directory(&state)?;
    cleanup_expired_backups(&backup_dir, BACKUP_TTL_HOURS);

    // Idempotent: a backup already running for this VM is the answer, not a
    // conflict.
    if state.backups.task_running(vm_id)
        && let Some(job) = state.backups.running_job_for(vm_id)
    {
        return Ok(job);
    }

    // A non-expired archive is also the answer (24h TTL defines freshness).
    if let Some(existing) = find_existing_backup(&backup_dir, vm_id, BACKUP_TTL_HOURS) {
        return backup_info_from_tar(&existing, vm_id);
    }

    // Best-effort disk-space check: the summed virtual size against the free
    // space of the backup directory. InsufficientResources on shortfall.
    let mut needed: u64 = 0;
    for (_, source) in &disk_paths {
        needed = needed.saturating_add(
            state
                .disk_tools
                .virtual_size(source)
                .map_err(RpcError::Internal)?,
        );
    }
    let free = crate::host::available_disk_bytes(&backup_dir)
        .map_err(|error| RpcError::Internal(error.to_string()))?;
    if free < needed {
        return Err(RpcError::InsufficientResources(format!(
            "Insufficient disk space: {free} bytes available, {needed} bytes required for {} disk(s)",
            disk_paths.len()
        )));
    }

    // Microsecond precision: a retry right after a failed run gets a fresh id
    // (also the tar stem, dash-free so list_backups' rsplit stays exact).
    let timestamp = strftime_compact(true);
    let backup_id = format!("{vm_id}-{timestamp}");
    let job = pb::BackupInfo {
        vm_id: vm_id.to_string(),
        backup_id: backup_id.clone(),
        status: pb::BackupStatus::Running as i32,
        size_bytes: 0,
        created_at_unix_secs: now_unix_secs(),
        error_message: String::new(),
        checksum: String::new(),
        volumes: Vec::new(),
        source_sizes: HashMap::new(),
    };
    state.backups.drop_failed_jobs_for(vm_id);
    state.backups.insert_job(job.clone());

    let run_state = state.clone();
    let run_vm_id = vm_id.to_string();
    let run_disk_paths = disk_paths.clone();
    let run_backup_dir = backup_dir.clone();
    let handle = tokio::runtime::Handle::current().spawn_blocking(move || {
        run_backup(
            run_state,
            &run_vm_id,
            &backup_id,
            &timestamp,
            &run_disk_paths,
            &run_backup_dir,
            quiesce_guest,
        );
    });
    state.backups.set_task(vm_id, handle);
    Ok(job)
}

/// `LocalSupervisor._run_backup`: convert each disk, verify, archive; drop
/// the RUNNING job on success or record a FAILED one; always clean up the
/// intermediate disk backups and the task slot. Runs under the per-VM disk
/// lock (shared with restore).
fn run_backup(
    state: Arc<DaemonState>,
    vm_id: &str,
    backup_id: &str,
    timestamp: &str,
    disk_paths: &[(String, PathBuf)],
    backup_dir: &Path,
    quiesce_guest: bool,
) {
    let lock = state.backups.vm_lock(vm_id);
    let mut disk_backups: Vec<PathBuf> = Vec::new();
    let outcome = {
        let _guard = lock
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        run_backup_locked(
            &state,
            vm_id,
            backup_id,
            timestamp,
            disk_paths,
            backup_dir,
            quiesce_guest,
            &mut disk_backups,
        )
    };
    if let Err(error) = outcome {
        tracing::error!(backup_id, error, "Backup failed");
        state.backups.insert_job(pb::BackupInfo {
            vm_id: vm_id.to_string(),
            backup_id: backup_id.to_string(),
            status: pb::BackupStatus::Failed as i32,
            size_bytes: 0,
            created_at_unix_secs: now_unix_secs(),
            error_message: error,
            checksum: String::new(),
            volumes: Vec::new(),
            source_sizes: HashMap::new(),
        });
    }
    for disk_backup in &disk_backups {
        let _ = std::fs::remove_file(disk_backup);
    }
    state.backups.clear_task(vm_id);
}

#[allow(clippy::too_many_arguments)]
fn run_backup_locked(
    state: &DaemonState,
    vm_id: &str,
    backup_id: &str,
    timestamp: &str,
    disk_paths: &[(String, PathBuf)],
    backup_dir: &Path,
    quiesce_guest: bool,
    disk_backups: &mut Vec<PathBuf>,
) -> Result<(), String> {
    // Best-effort guest fs-freeze while running, thawed after the copy.
    let frozen = if quiesce_guest && vm_running(state, vm_id) {
        try_fsfreeze(state, vm_id)
    } else {
        None
    };

    let mut backup_files: Vec<(String, PathBuf)> = Vec::new();
    let mut convert = || -> Result<(), String> {
        for (member_name, source_path) in disk_paths {
            let disk_backup = create_qemu_disk_backup(state, vm_id, source_path, backup_dir)?;
            disk_backups.push(disk_backup.clone());
            backup_files.push((member_name.clone(), disk_backup));
        }
        Ok(())
    };
    let convert_result = convert();
    if let Some(qga_socket) = frozen {
        try_fsthaw(&qga_socket, vm_id);
    }
    convert_result?;

    for disk_backup in disk_backups.iter() {
        match state.disk_tools.check(disk_backup) {
            Ok(()) => {}
            Err(QemuImgError::CheckFailed(message)) | Err(QemuImgError::Unavailable(message)) => {
                return Err(message);
            }
        }
    }

    let mut source_sizes = HashMap::new();
    for (name, source) in disk_paths {
        let size = std::fs::metadata(source)
            .map(|metadata| metadata.len())
            .map_err(|error| format!("cannot stat {}: {error}", source.display()))?;
        source_sizes.insert(name.clone(), size);
    }
    create_backup_archive(vm_id, &backup_files, backup_dir, &source_sizes, timestamp)?;
    // The archive on disk is now the record; drop the live job.
    state.backups.remove_job(backup_id);
    Ok(())
}

/// `create_qemu_disk_backup`: `{vm_hash}-{%Y%m%dT%H%M%SZ}.qcow2` compressed
/// copy. The intermediate name uses second precision, so multiple disks
/// backed up within one second collide on the destination path (a Python
/// wart, ported bug-for-bug; ledger entry 48).
fn create_qemu_disk_backup(
    state: &DaemonState,
    vm_hash: &str,
    source: &Path,
    destination_dir: &Path,
) -> Result<PathBuf, String> {
    let timestamp = strftime_compact(false);
    let dest = destination_dir.join(format!("{vm_hash}-{timestamp}.qcow2"));
    tracing::info!(dest = %dest.display(), source = %source.display(), "Creating backup");
    state.disk_tools.convert_compressed(source, &dest)?;
    Ok(dest)
}

fn vm_running(state: &DaemonState, vm_id: &str) -> bool {
    let Some(entry) = entry_snapshot(state, vm_id) else {
        return false;
    };
    if entry.is_program {
        return entry.times.starting_at_ns != 0 && entry.times.stopping_at_ns == 0;
    }
    let unit = entry.unit_name();
    state
        .units
        .active_states(std::slice::from_ref(&unit))
        .map(|states| states.get(&unit).copied().unwrap_or(false))
        .unwrap_or(false)
}

/// `_try_fsfreeze`: best-effort guest fs-freeze over the QEMU guest agent;
/// the backup proceeds unfrozen when the agent is unavailable. Returns the
/// QGA socket path to thaw on success.
fn try_fsfreeze(state: &DaemonState, vm_id: &str) -> Option<PathBuf> {
    let entry = entry_snapshot(state, vm_id)?;
    let qga_socket = PathBuf::from(entry.config.qga_socket_path.as_ref()?);
    match crate::qmp::qga_fsfreeze_freeze(&qga_socket) {
        Ok(frozen) => {
            tracing::info!(vm_id, frozen, "Froze filesystem(s)");
            Some(qga_socket)
        }
        Err(error) => {
            tracing::warn!(vm_id, error, "fsfreeze unavailable, proceeding without");
            None
        }
    }
}

/// `_try_fsthaw`: best-effort thaw; a failure is logged, never fatal.
fn try_fsthaw(qga_socket: &Path, vm_id: &str) {
    if let Err(error) = crate::qmp::qga_fsfreeze_thaw(qga_socket) {
        tracing::error!(vm_id, error, "Failed to thaw filesystems");
    }
}

/// `LocalSupervisor.get_backup_status`: the on-disk archive if present, else
/// the in-memory job, else BackupNotFound.
pub fn get_backup_status(
    state: &DaemonState,
    vm_id: &str,
    backup_id: &str,
) -> Result<pb::BackupInfo, RpcError> {
    validate_backup_id(vm_id, backup_id)?;
    let tar_path = backup_directory(state)?.join(format!("{backup_id}.tar"));
    if tar_path.exists() {
        return backup_info_from_tar(&tar_path, vm_id);
    }
    state
        .backups
        .job(backup_id)
        .ok_or_else(|| RpcError::BackupNotFound(backup_id.to_string()))
}

/// `LocalSupervisor.list_backups`: the on-disk archives (sorted by name) plus
/// the in-memory jobs. The archive stem is `<vm_id>-<timestamp>`, neither
/// part containing a dash, so `rsplit('-', 1)` is exact.
pub fn list_backups(
    state: &DaemonState,
    vm_id: Option<&str>,
) -> Result<Vec<pb::BackupInfo>, RpcError> {
    let backup_dir = backup_directory(state)?;
    let prefix = vm_id.map(|id| format!("{id}-"));
    let mut tars: Vec<PathBuf> = std::fs::read_dir(&backup_dir)
        .map_err(|error| RpcError::Internal(format!("cannot list the backup directory: {error}")))?
        .flatten()
        .map(|entry| entry.path())
        .filter(|path| {
            let name = path
                .file_name()
                .and_then(|name| name.to_str())
                .unwrap_or_default();
            name.ends_with(".tar")
                && prefix
                    .as_ref()
                    .is_none_or(|prefix| name.starts_with(prefix))
        })
        .collect();
    tars.sort();
    let mut infos = Vec::new();
    for tar_path in tars {
        let stem = tar_path
            .file_stem()
            .and_then(|stem| stem.to_str())
            .unwrap_or_default();
        let owner = stem.rsplit_once('-').map_or(stem, |(before, _)| before);
        infos.push(backup_info_from_tar(&tar_path, owner)?);
    }
    infos.extend(state.backups.jobs_for(vm_id));
    Ok(infos)
}

/// `LocalSupervisor.download_backup`'s validation half: resolve the archive
/// path, or BackupNotFound. The stream is produced by the service handler.
pub fn resolve_download(
    state: &DaemonState,
    vm_id: &str,
    backup_id: &str,
) -> Result<PathBuf, RpcError> {
    validate_backup_id(vm_id, backup_id)?;
    let tar_path = backup_directory(state)?.join(format!("{backup_id}.tar"));
    if !tar_path.exists() {
        return Err(RpcError::BackupNotFound(backup_id.to_string()));
    }
    Ok(tar_path)
}

/// `LocalSupervisor.delete_backup`: remove the archive and its sidecars (and
/// any FAILED record). A RUNNING job refuses; a wholly unknown id is
/// BackupNotFound.
pub fn delete_backup(state: &DaemonState, vm_id: &str, backup_id: &str) -> Result<(), RpcError> {
    validate_backup_id(vm_id, backup_id)?;
    if let Some(job) = state.backups.job(backup_id)
        && job.status == pb::BackupStatus::Running as i32
    {
        return Err(RpcError::Internal(format!(
            "Backup {backup_id} is still running"
        )));
    }
    let tar_path = backup_directory(state)?.join(format!("{backup_id}.tar"));
    let existed = tar_path.exists();
    let _ = std::fs::remove_file(&tar_path);
    let _ = std::fs::remove_file(sidecar(&tar_path, ".sha256"));
    let _ = std::fs::remove_file(sidecar(&tar_path, ".meta.json"));
    // Deleting a FAILED (or any in-memory) record is also a valid delete.
    if state.backups.remove_job(backup_id).is_none() && !existed {
        return Err(RpcError::BackupNotFound(backup_id.to_string()));
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::config::Settings;
    use crate::service::{DaemonState, HostState};
    use crate::units::FakeSystemd;

    const VM: &str = "abc123";

    fn state_with(disk_tools: Arc<dyn DiskTools>, root: &Path) -> Arc<DaemonState> {
        let settings = Settings::from_vars(
            [(
                "ALEPH_VM_EXECUTION_ROOT".to_string(),
                root.to_string_lossy().into_owned(),
            )]
            .into_iter(),
        )
        .unwrap();
        let host = HostState {
            settings,
            host_ipv4: String::new(),
            network_interface: None,
            gpus: Vec::new(),
            dns_nameservers: None,
        };
        let mut state = DaemonState::hermetic(
            host,
            crate::world::WorldView::default(),
            Arc::new(FakeSystemd::new()),
            Arc::new(crate::logs::StaticLogSource::default()),
        );
        state.disk_tools = disk_tools;
        Arc::new(state)
    }

    fn write_source(dir: &Path, name: &str, bytes: &[u8]) -> PathBuf {
        let path = dir.join(name);
        std::fs::write(&path, bytes).unwrap();
        path
    }

    #[test]
    fn validate_backup_id_rejects_foreign_and_traversal_ids() {
        assert!(validate_backup_id(VM, &format!("{VM}-20260101T000000000000Z")).is_ok());
        for bad in [
            "",
            "other-x",
            &format!("{VM}-../escape"),
            &format!("{VM}-a/b"),
        ] {
            assert!(matches!(
                validate_backup_id(VM, bad),
                Err(RpcError::BackupNotFound(_))
            ));
        }
    }

    #[test]
    fn archive_roundtrips_through_the_sidecars() {
        let tmp = tempfile::tempdir().unwrap();
        let dir = tmp.path();
        let rootfs = write_source(dir, "root.bin", b"rootfs-bytes");
        let data = write_source(dir, "data.bin", b"volume-bytes");
        let members = vec![
            (BACKUP_ROOTFS_MEMBER.to_string(), rootfs),
            ("data.qcow2".to_string(), data),
        ];
        let mut source_sizes = HashMap::new();
        source_sizes.insert(BACKUP_ROOTFS_MEMBER.to_string(), 12u64);
        source_sizes.insert("data.qcow2".to_string(), 12u64);
        let timestamp = "20260101T000000000000Z";
        let tar_path = create_backup_archive(VM, &members, dir, &source_sizes, timestamp).unwrap();
        assert_eq!(tar_path, dir.join(format!("{VM}-{timestamp}.tar")));

        // The sha256 sidecar is `{digest}  {name}\n`.
        let sha = std::fs::read_to_string(sidecar(&tar_path, ".sha256")).unwrap();
        assert!(sha.ends_with(&format!("  {VM}-{timestamp}.tar\n")));
        assert_eq!(sha.split_whitespace().count(), 2);

        let info = backup_info_from_tar(&tar_path, VM).unwrap();
        assert_eq!(info.status, pb::BackupStatus::Complete as i32);
        assert_eq!(info.backup_id, format!("{VM}-{timestamp}"));
        assert!(info.checksum.starts_with("sha256:"));
        assert_eq!(info.volumes, vec![BACKUP_ROOTFS_MEMBER, "data.qcow2"]);
        assert_eq!(info.source_sizes.get("data.qcow2"), Some(&12));
    }

    #[test]
    fn find_existing_and_cleanup_respect_the_ttl() {
        let tmp = tempfile::tempdir().unwrap();
        let dir = tmp.path();
        let fresh = dir.join(format!("{VM}-20260102T000000000000Z.tar"));
        std::fs::write(&fresh, b"tar").unwrap();
        // A fresh archive is found (24h TTL) and not swept.
        assert_eq!(
            find_existing_backup(dir, VM, BACKUP_TTL_HOURS),
            Some(fresh.clone())
        );
        assert_eq!(cleanup_expired_backups(dir, BACKUP_TTL_HOURS), 0);
        assert!(fresh.exists());

        // Backdate an archive past the TTL: it is neither found nor kept.
        let stale = dir.join(format!("{VM}-20260101T000000000000Z.tar"));
        std::fs::write(&stale, b"tar").unwrap();
        std::fs::write(sidecar(&stale, ".sha256"), b"x  y\n").unwrap();
        let two_days_ago = SystemTime::now() - std::time::Duration::from_secs(48 * 3600);
        std::fs::File::options()
            .write(true)
            .open(&stale)
            .unwrap()
            .set_modified(two_days_ago)
            .unwrap();
        // find still returns the fresh one, never the stale one.
        assert_eq!(
            find_existing_backup(dir, VM, BACKUP_TTL_HOURS),
            Some(fresh.clone())
        );
        assert_eq!(cleanup_expired_backups(dir, BACKUP_TTL_HOURS), 1);
        assert!(!stale.exists());
        assert!(!sidecar(&stale, ".sha256").exists());
        assert!(fresh.exists());
    }

    #[test]
    fn run_backup_writes_the_archive_and_drops_the_running_job() {
        let tmp = tempfile::tempdir().unwrap();
        let root = tmp.path();
        let state = state_with(Arc::new(FakeDiskTools::default()), root);
        let backup_dir = backup_directory(&state).unwrap();
        let rootfs = write_source(root, "rootfs.qcow2", b"guest-disk");
        let disk_paths = vec![(BACKUP_ROOTFS_MEMBER.to_string(), rootfs)];
        let backup_id = format!("{VM}-20260101T000000000000Z");
        state.backups.insert_job(pb::BackupInfo {
            vm_id: VM.to_string(),
            backup_id: backup_id.clone(),
            status: pb::BackupStatus::Running as i32,
            ..Default::default()
        });
        run_backup(
            state.clone(),
            VM,
            &backup_id,
            "20260101T000000000000Z",
            &disk_paths,
            &backup_dir,
            false,
        );
        assert!(backup_dir.join(format!("{backup_id}.tar")).exists());
        assert!(
            state.backups.job(&backup_id).is_none(),
            "the running job is dropped"
        );
        // The intermediate .qcow2 was cleaned up and no .tar.partial lingers.
        let leftovers: Vec<_> = std::fs::read_dir(&backup_dir)
            .unwrap()
            .flatten()
            .filter(|entry| {
                let name = entry.file_name();
                let name = name.to_string_lossy();
                name.ends_with(".qcow2") || name.ends_with(".partial")
            })
            .collect();
        assert!(leftovers.is_empty(), "intermediate files left behind");
    }

    #[test]
    fn run_backup_records_a_failed_job_when_verify_fails() {
        let tmp = tempfile::tempdir().unwrap();
        let root = tmp.path();
        let disk_tools = Arc::new(FakeDiskTools {
            virtual_size: 1,
            check_ok: false,
        });
        let state = state_with(disk_tools, root);
        let backup_dir = backup_directory(&state).unwrap();
        let rootfs = write_source(root, "rootfs.qcow2", b"guest-disk");
        let disk_paths = vec![(BACKUP_ROOTFS_MEMBER.to_string(), rootfs)];
        let backup_id = format!("{VM}-20260101T000000000000Z");
        run_backup(
            state.clone(),
            VM,
            &backup_id,
            "20260101T000000000000Z",
            &disk_paths,
            &backup_dir,
            false,
        );
        let job = state
            .backups
            .job(&backup_id)
            .expect("a FAILED job is recorded");
        assert_eq!(job.status, pb::BackupStatus::Failed as i32);
        assert!(!job.error_message.is_empty());
        assert!(!backup_dir.join(format!("{backup_id}.tar")).exists());
    }

    #[test]
    fn start_backup_returns_a_fresh_existing_archive_idempotently() {
        let tmp = tempfile::tempdir().unwrap();
        let root = tmp.path();
        let state = state_with(Arc::new(FakeDiskTools::default()), root);
        // Register the VM so start_backup finds it and resolves the rootfs.
        register_qemu_vm(&state, root);
        let backup_dir = backup_directory(&state).unwrap();
        let existing = backup_dir.join(format!("{VM}-20260101T000000000000Z.tar"));
        std::fs::write(&existing, b"tar-bytes").unwrap();
        let info = start_backup(state.clone(), VM, false, false).unwrap();
        assert_eq!(info.status, pb::BackupStatus::Complete as i32);
        assert_eq!(info.backup_id, format!("{VM}-20260101T000000000000Z"));
    }

    #[test]
    fn start_backup_refuses_when_disk_space_is_short() {
        let tmp = tempfile::tempdir().unwrap();
        let root = tmp.path();
        let disk_tools = Arc::new(FakeDiskTools {
            virtual_size: u64::MAX / 2,
            check_ok: true,
        });
        let state = state_with(disk_tools, root);
        register_qemu_vm(&state, root);
        let error = start_backup(state, VM, false, false).unwrap_err();
        assert!(matches!(error, RpcError::InsufficientResources(_)));
    }

    #[test]
    fn delete_and_status_cover_the_backup_lifecycle() {
        let tmp = tempfile::tempdir().unwrap();
        let root = tmp.path();
        let state = state_with(Arc::new(FakeDiskTools::default()), root);
        let backup_dir = backup_directory(&state).unwrap();
        let backup_id = format!("{VM}-20260101T000000000000Z");
        let tar_path = backup_dir.join(format!("{backup_id}.tar"));
        std::fs::write(&tar_path, b"tar").unwrap();
        std::fs::write(sidecar(&tar_path, ".sha256"), b"deadbeef  x\n").unwrap();

        // status reads the on-disk archive as COMPLETE.
        let info = get_backup_status(&state, VM, &backup_id).unwrap();
        assert_eq!(info.status, pb::BackupStatus::Complete as i32);
        // list surfaces it.
        assert_eq!(list_backups(&state, Some(VM)).unwrap().len(), 1);
        // an unknown id is BackupNotFound.
        assert!(matches!(
            get_backup_status(&state, VM, &format!("{VM}-nope")),
            Err(RpcError::BackupNotFound(_))
        ));
        // delete removes the archive and the sidecar.
        delete_backup(&state, VM, &backup_id).unwrap();
        assert!(!tar_path.exists());
        assert!(!sidecar(&tar_path, ".sha256").exists());
        // a second delete is BackupNotFound.
        assert!(matches!(
            delete_backup(&state, VM, &backup_id),
            Err(RpcError::BackupNotFound(_))
        ));
    }

    #[test]
    fn a_program_entry_cannot_be_backed_up() {
        let entry = crate::world::VmEntry::test_program(VM);
        assert!(matches!(
            backup_disk_paths(&entry, false),
            Err(RpcError::InvalidBackend(_))
        ));
    }

    fn register_qemu_vm(state: &DaemonState, root: &Path) {
        let rootfs = write_source(root, "rootfs.qcow2", b"guest-disk");
        let entry = crate::world::VmEntry::test_qemu(VM, &rootfs.to_string_lossy());
        state.world.blocking_write().insert_entry(entry);
    }
}
