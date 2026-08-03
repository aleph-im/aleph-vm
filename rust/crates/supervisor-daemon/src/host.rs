//! Live host figures for GetHostInfo, read from the same primary sources as
//! the Python daemon (see LocalSupervisor.get_host_info in
//! src/aleph/vm/supervisor/local.py):
//!
//! - cpu_count: sysconf(_SC_NPROCESSORS_ONLN), what os.cpu_count() calls
//! - memory_mib: MemTotal from /proc/meminfo, what psutil's total is;
//!   truncated to MiB like `int(total / (1024 * 1024))`
//! - kernel_version / hostname: uname(2) release / nodename, like os.uname()
//! - available_disk_bytes: statvfs f_bavail * f_frsize, what
//!   shutil.disk_usage().free reports for PERSISTENT_VOLUMES_DIR;
//!   available_disk_bytes_pooled sums this across every volume pool

use std::os::unix::fs::MetadataExt;
use std::path::Path;
use std::path::PathBuf;

use crate::error::DaemonError;

/// Number of online CPUs, the value `os.cpu_count()` returns on Linux.
pub fn cpu_count() -> u32 {
    // SAFETY: sysconf with a valid name has no preconditions.
    let count = unsafe { libc::sysconf(libc::_SC_NPROCESSORS_ONLN) };
    u32::try_from(count).unwrap_or(0)
}

/// Total physical memory in MiB, truncated like the Python
/// `int(psutil.virtual_memory().total / (1024 * 1024))`.
pub fn memory_total_mib() -> Result<u64, DaemonError> {
    let content =
        std::fs::read_to_string("/proc/meminfo").map_err(|source| DaemonError::ReadFile {
            path: "/proc/meminfo".into(),
            source,
        })?;
    parse_meminfo_total_mib(&content)
        .ok_or_else(|| DaemonError::Internal("MemTotal not found in /proc/meminfo".to_string()))
}

fn parse_meminfo_total_mib(meminfo: &str) -> Option<u64> {
    let line = meminfo.lines().find(|line| line.starts_with("MemTotal:"))?;
    let kib: u64 = line.split_whitespace().nth(1)?.parse().ok()?;
    // psutil reports MemTotal kB * 1024 bytes; the Python daemon divides by
    // 1024 * 1024 and truncates.
    Some(kib * 1024 / (1024 * 1024))
}

/// uname(2) release and nodename, the `os.uname()` fields Python serves.
pub fn uname_release_and_nodename() -> Result<(String, String), DaemonError> {
    let mut name: libc::utsname = unsafe { std::mem::zeroed() };
    // SAFETY: uname fills the buffer we own; a non-zero return is an error.
    if unsafe { libc::uname(&mut name) } != 0 {
        return Err(DaemonError::Io(std::io::Error::last_os_error()));
    }
    Ok((
        c_chars_to_string(&name.release),
        c_chars_to_string(&name.nodename),
    ))
}

fn c_chars_to_string(chars: &[libc::c_char]) -> String {
    let bytes: Vec<u8> = chars
        .iter()
        .take_while(|c| **c != 0)
        .map(|c| *c as u8)
        .collect();
    String::from_utf8_lossy(&bytes).into_owned()
}

/// Free disk space for new volumes in bytes: statvfs f_bavail * f_frsize on
/// PERSISTENT_VOLUMES_DIR, exactly what shutil.disk_usage().free reports in
/// VmPool.calculate_available_disk. The per-execution reservation delta the
/// Python sum adds is zero for every adopted execution (spec-built resources
/// carry no requested sizes: message_content is None and volumes have no
/// size_mib), so free space alone is the exact post-restart figure until the
/// create path lands in increment 3.
pub fn available_disk_bytes(path: &Path) -> Result<u64, DaemonError> {
    let c_path = std::ffi::CString::new(path.as_os_str().as_encoded_bytes()).map_err(|_| {
        DaemonError::Internal(format!("path contains a NUL byte: {}", path.display()))
    })?;
    let mut stat: libc::statvfs = unsafe { std::mem::zeroed() };
    // SAFETY: statvfs fills the buffer we own; a non-zero return is an error.
    if unsafe { libc::statvfs(c_path.as_ptr(), &mut stat) } != 0 {
        return Err(DaemonError::Statvfs {
            path: path.to_path_buf(),
            source: std::io::Error::last_os_error(),
        });
    }
    // The casts are no-ops on 64-bit Linux but keep 32-bit targets correct
    // (fsblkcnt_t and fsword_t are narrower there).
    #[allow(clippy::unnecessary_cast)]
    Ok(stat.f_bavail as u64 * stat.f_frsize as u64)
}

/// Free disk space for new volumes across every volume pool, in bytes:
/// the statvfs sum with filesystems deduplicated by st_dev (two pool
/// directories on one filesystem count once), matching the agent's
/// pools_disk_usage. Unreachable pools contribute zero instead of failing
/// GetHostInfo: a dead disk must not take Health down.
pub fn available_disk_bytes_pooled(paths: &[PathBuf]) -> u64 {
    let mut seen_devices = std::collections::HashSet::new();
    let mut free = 0u64;
    for path in paths {
        let device = match std::fs::metadata(path) {
            Ok(metadata) => metadata.dev(),
            Err(error) => {
                tracing::warn!(path = %path.display(), %error, "volume pool inaccessible, ignoring");
                continue;
            }
        };
        if !seen_devices.insert(device) {
            continue;
        }
        match available_disk_bytes(path) {
            Ok(bytes) => free += bytes,
            Err(error) => {
                tracing::warn!(path = %path.display(), %error, "statvfs failed, ignoring pool");
            }
        }
    }
    free
}

#[cfg(test)]
mod tests {
    use std::path::PathBuf;

    use super::*;

    #[test]
    fn pooled_disk_dedups_same_filesystem_and_skips_dead_pools() {
        let root = PathBuf::from("/");
        // The same filesystem listed twice counts once...
        let once = available_disk_bytes_pooled(std::slice::from_ref(&root));
        let twice = available_disk_bytes_pooled(&[root.clone(), PathBuf::from("/etc")]);
        // ("/" and "/etc" are usually one filesystem; when they are, the sums
        // match. Different-filesystem hosts still satisfy the >= invariant.)
        assert!(twice >= once);
        assert_eq!(
            available_disk_bytes_pooled(&[root.clone(), root.clone()]),
            once
        );
        // A nonexistent pool contributes zero instead of erroring.
        assert_eq!(
            available_disk_bytes_pooled(&[root, PathBuf::from("/nonexistent-pool")]),
            once
        );
        assert_eq!(available_disk_bytes_pooled(&[]), 0);
    }

    #[test]
    fn meminfo_total_is_parsed_and_truncated() {
        let meminfo = "MemTotal:       32794620 kB\nMemFree:         1000000 kB\n";
        // 32794620 KiB = 33581690880 bytes; // 2**20 = 32025 MiB (truncated).
        assert_eq!(parse_meminfo_total_mib(meminfo), Some(32025));
        assert_eq!(parse_meminfo_total_mib("MemFree: 12 kB\n"), None);
    }

    #[test]
    fn live_values_are_sane() {
        assert!(cpu_count() >= 1);
        assert!(memory_total_mib().unwrap() > 0);
        let (release, nodename) = uname_release_and_nodename().unwrap();
        assert!(!release.is_empty());
        assert!(!nodename.is_empty());
        assert!(available_disk_bytes(Path::new("/")).is_ok());
    }
}
