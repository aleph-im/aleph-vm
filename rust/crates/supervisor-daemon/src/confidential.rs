//! Confidential-VM mutations (increment 6), a 1:1 port of the Python
//! `LocalSupervisor.initialize_confidential` / `get_measurement` /
//! `inject_secret` (src/aleph/vm/supervisor/local.py).
//!
//! Scope (design doc section 7 row 6, "Confidential stubs"): the daemon does
//! the non-hardware work exactly as Python does. `initialize_confidential`
//! writes the owner's SEV session certificates and starts the controller
//! unit (no SEV hardware involved). `get_measurement` and `inject_secret` are
//! QMP passthrough to a running confidential QEMU: the protocol is ported
//! (src/qmp.rs), but the SEV data path only answers on an SEV host, so those
//! two are HARDWARE-GATED like the Python Tier-2 path. The real attestation
//! stack is Phase 3 (aleph-cvm); nothing here invents SEV behavior beyond
//! what Python already performs. See ledger entry 49 for the boundary.

use std::path::PathBuf;

use supervisor_proto::pb;

use crate::lifecycle::RpcError;
use crate::service::DaemonState;

const SEV_ES_POLICY_BIT: u32 = 0x4;

fn entry_snapshot(state: &DaemonState, vm_id: &str) -> Option<crate::world::VmEntry> {
    state.world.blocking_read().entries.get(vm_id).cloned()
}

/// `initialize_confidential`: persist the owner's SEV session certificates
/// and start the VM. Writes `vm_session.b64` / `vm_godh.b64` under the per-VM
/// confidential session directory, then enables and starts the controller
/// service so the guest reaches the launch-secret state.
pub fn initialize_confidential(
    state: &DaemonState,
    vm_id: &str,
    session_bytes: &[u8],
    godh_bytes: &[u8],
) -> Result<(), RpcError> {
    let entry =
        entry_snapshot(state, vm_id).ok_or_else(|| RpcError::NotFound(vm_id.to_string()))?;
    let session_dir = state
        .host
        .settings
        .confidential_session_directory
        .join(vm_id);
    std::fs::create_dir_all(&session_dir).map_err(|error| {
        RpcError::Internal(format!("cannot create the session directory: {error}"))
    })?;
    std::fs::write(session_dir.join("vm_session.b64"), session_bytes)
        .map_err(|error| RpcError::Internal(format!("cannot write vm_session.b64: {error}")))?;
    std::fs::write(session_dir.join("vm_godh.b64"), godh_bytes)
        .map_err(|error| RpcError::Internal(format!("cannot write vm_godh.b64: {error}")))?;
    crate::units::enable_and_start(&*state.units, &entry.unit_name())
        .map_err(|error| RpcError::Internal(error.to_string()))?;
    Ok(())
}

/// `get_measurement`: the SEV launch measurement plus the platform state the
/// owner verifies before injecting the secret. QMP passthrough to the
/// running confidential QEMU (hardware-gated).
pub fn get_measurement(state: &DaemonState, vm_id: &str) -> Result<pb::Measurement, RpcError> {
    let entry =
        entry_snapshot(state, vm_id).ok_or_else(|| RpcError::NotFound(vm_id.to_string()))?;
    let mut client =
        crate::qmp::QmpClient::connect(std::path::Path::new(&entry.config.qmp_socket_path))
            .map_err(|error| RpcError::Internal(error.to_string()))?;
    let sev_info = client
        .query_sev_info()
        .map_err(|error| RpcError::Internal(error.to_string()))?;
    let launch_measure = client
        .query_launch_measure()
        .map_err(|error| RpcError::Internal(error.to_string()))?;
    // The TEE generation comes from the VM's confidential config (an input
    // the supervisor holds). SEV covers SEV and SEV-ES (the client refines
    // via sev_info.policy); SEV-SNP is a distinct launch path not emitted
    // here, so tee_backend is always SEV.
    let _mode = confidential_mode(&entry);
    Ok(pb::Measurement {
        vm_id: vm_id.to_string(),
        measurement_bytes: Vec::new(),
        tee_backend: pb::TeeBackend::Sev as i32,
        sev_info: Some(pb::SevInfo {
            enabled: sev_info.enabled,
            api_major: sev_info.api_major,
            api_minor: sev_info.api_minor,
            build_id: sev_info.build_id,
            policy: sev_info.policy,
            state: sev_info.state,
            handle: sev_info.handle,
        }),
        launch_measure,
    })
}

/// `inject_secret`: inject the encrypted secret into the SEV secret area and
/// resume the guest. The header and secret cross the boundary as bytes; QMP's
/// command takes the base64 strings.
pub fn inject_secret(
    state: &DaemonState,
    vm_id: &str,
    secret_header_bytes: &[u8],
    secret_bytes: &[u8],
) -> Result<(), RpcError> {
    let entry =
        entry_snapshot(state, vm_id).ok_or_else(|| RpcError::NotFound(vm_id.to_string()))?;
    // Python decodes the bytes as UTF-8 (base64 strings); a non-UTF-8 payload
    // raises there too (UnicodeDecodeError -> INTERNAL).
    let header = std::str::from_utf8(secret_header_bytes).map_err(|error| {
        RpcError::Internal(format!("secret header is not valid UTF-8: {error}"))
    })?;
    let secret = std::str::from_utf8(secret_bytes)
        .map_err(|error| RpcError::Internal(format!("secret is not valid UTF-8: {error}")))?;
    let mut client =
        crate::qmp::QmpClient::connect(std::path::Path::new(&entry.config.qmp_socket_path))
            .map_err(|error| RpcError::Internal(error.to_string()))?;
    client
        .inject_secret(header, secret)
        .map_err(|error| RpcError::Internal(error.to_string()))?;
    client
        .continue_execution()
        .map_err(|error| RpcError::Internal(error.to_string()))?;
    Ok(())
}

/// The per-VM confidential session directory (also where confidential
/// CreateVm points the controller config's session/godh paths).
pub fn session_dir(state: &DaemonState, vm_id: &str) -> PathBuf {
    state
        .host
        .settings
        .confidential_session_directory
        .join(vm_id)
}

fn confidential_mode(entry: &crate::world::VmEntry) -> pb::ConfidentialMode {
    if entry.config.snp().is_some() {
        return pb::ConfidentialMode::SevSnp;
    }
    match entry.config.confidential() {
        None => pb::ConfidentialMode::None,
        Some(config) if config.sev_policy & SEV_ES_POLICY_BIT != 0 => pb::ConfidentialMode::SevEs,
        Some(_) => pb::ConfidentialMode::Sev,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::Arc;

    use crate::config::Settings;
    use crate::service::{DaemonState, HostState};
    use crate::units::FakeSystemd;

    const VM: &str = "cafe";

    fn test_state(root: &std::path::Path) -> (DaemonState, Arc<FakeSystemd>) {
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
        let systemd = Arc::new(FakeSystemd::new());
        let state = DaemonState::hermetic(
            host,
            crate::world::WorldView::default(),
            systemd.clone(),
            Arc::new(crate::logs::StaticLogSource::default()),
        );
        (state, systemd)
    }

    #[test]
    fn initialize_confidential_writes_the_session_and_starts_the_unit() {
        let tmp = tempfile::tempdir().unwrap();
        let (state, systemd) = test_state(tmp.path());
        state
            .world
            .blocking_write()
            .insert_entry(crate::world::VmEntry::test_qemu(VM, "/tmp/rootfs.qcow2"));

        initialize_confidential(&state, VM, b"session-blob", b"godh-blob").unwrap();

        let session_dir = state.host.settings.confidential_session_directory.join(VM);
        assert_eq!(
            std::fs::read(session_dir.join("vm_session.b64")).unwrap(),
            b"session-blob"
        );
        assert_eq!(
            std::fs::read(session_dir.join("vm_godh.b64")).unwrap(),
            b"godh-blob"
        );
        let unit = format!("aleph-vm-controller@{VM}.service");
        assert_eq!(
            systemd.actions(),
            vec![format!("enable {unit}"), format!("start {unit}")]
        );
    }

    #[test]
    fn initialize_confidential_for_an_unknown_vm_is_not_found() {
        let tmp = tempfile::tempdir().unwrap();
        let (state, _) = test_state(tmp.path());
        assert!(matches!(
            initialize_confidential(&state, "nope", b"", b""),
            Err(RpcError::NotFound(_))
        ));
    }

    #[test]
    fn measurement_and_secret_report_not_found_before_the_vm_exists() {
        let tmp = tempfile::tempdir().unwrap();
        let (state, _) = test_state(tmp.path());
        assert!(matches!(
            get_measurement(&state, "nope"),
            Err(RpcError::NotFound(_))
        ));
        assert!(matches!(
            inject_secret(&state, "nope", b"", b""),
            Err(RpcError::NotFound(_))
        ));
    }

    #[test]
    fn measurement_and_secret_report_internal_when_the_qmp_socket_is_missing() {
        // The VM exists (past the NotFound guard) but its QMP socket does not,
        // so the QMP connect fails with the Python "VM is not running" text,
        // surfaced as INTERNAL. This is the pre-hardware path a real
        // GetMeasurement/InjectSecret hits without a live confidential QEMU.
        let tmp = tempfile::tempdir().unwrap();
        let (state, _) = test_state(tmp.path());
        let mut entry = crate::world::VmEntry::test_qemu(VM, "/tmp/rootfs.qcow2");
        entry.config.qmp_socket_path = tmp.path().join("absent-qmp.socket").display().to_string();
        state.world.blocking_write().insert_entry(entry);

        for result in [
            get_measurement(&state, VM).err(),
            inject_secret(&state, VM, b"aGVhZGVy", b"c2VjcmV0").err(),
        ] {
            match result {
                Some(RpcError::Internal(message)) => {
                    assert_eq!(message, "VM is not running (QMP socket missing)");
                }
                other => panic!("expected INTERNAL for a missing QMP socket, got {other:?}"),
            }
        }
    }
}
