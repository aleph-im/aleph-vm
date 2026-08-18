//! aleph-vm-controller entry point: the process lifecycle port of
//! `src/aleph/vm/supervisor/controllers/__main__.py` for the non-confidential
//! persistent QEMU path.
//!
//! Arg parse (`--config`, `--print-settings`, `-vv`), validate the one
//! settings field Network cannot default (`NETWORK_INTERFACE`), wait for the
//! supervisor-created `vmtap{vm_id}` interface, then dispatch to the QEMU
//! runner which spawns qemu, blocks on it, and stops it gracefully on SIGTERM.

use std::path::PathBuf;
use std::process::ExitCode;
use std::time::Duration;

use clap::Parser;
use supervisor_controller::config::{
    ConfigError, Configuration, HypervisorType, QemuConfig, RootfsOverride, VmConfiguration,
};
use supervisor_controller::qemu;
use supervisor_controller::qemu::QemuError;

/// The `__main__.main` network pre-check budget: wait up to 120s for the tap.
const MAX_TAP_WAIT: Duration = Duration::from_secs(120);

#[derive(Debug, Parser)]
#[command(name = "instance", about = "Aleph.im Instance Client")]
struct Cli {
    /// Path to the `{vm_hash}-controller.json` config (required).
    #[arg(short = 'c', long = "config", value_name = "PATH")]
    config_path: PathBuf,

    /// Dump the controller settings slice as JSON and continue.
    #[arg(short = 'p', long = "print-settings", default_value_t = false)]
    print_settings: bool,

    /// Set loglevel to DEBUG. Python accepts `-v`, `-vv` and `--very-verbose`,
    /// all mapping to DEBUG; a `Count` action accepts any repeat of `-v` (and
    /// the long form) without erroring, where a bare flag rejects `-vv`.
    #[arg(short = 'v', long = "very-verbose", action = clap::ArgAction::Count)]
    verbose: u8,
}

/// A fatal controller error. `main` logs it once and turns it into a
/// non-zero exit; each variant is one of the `exit(1)` sites (or the
/// uncaught-exception exit) in the Python `__main__.main`. The launch-error
/// variants ([`select_run_target`]'s three and [`wait_for_tap`]'s one) each
/// reproduce a message the deleted `String` payload used to build inline;
/// `Qemu` wraps the typed [`qemu::QemuError`] transparently; the rest attach
/// the context (the config path, the failing operation) that Python logged
/// inline.
#[derive(Debug, thiserror::Error)]
enum ControllerError {
    #[error("Configuration file {} not found", .0.display())]
    ConfigNotFound(PathBuf),

    #[error("cannot load {}: {source}", .path.display())]
    ConfigLoad { path: PathBuf, source: ConfigError },

    #[error("Controller config {} carries no NETWORK_INTERFACE", .0.display())]
    NoNetworkInterface(PathBuf),

    #[error(
        "this controller does not run Firecracker VMs (hypervisor=firecracker); \
         it implements the QEMU (plain and SEV/SEV-ES confidential) paths only"
    )]
    NotAFirecrackerController,

    #[error(
        "SEV-SNP backend marker (sev_snp=true) is set but the config is missing a \
         measured-boot field (ovmf_path/sev_policy/kernel_path/initrd_path/kernel_cmdline); \
         refusing to launch a partial SNP config"
    )]
    PartialSnpConfig,

    #[error(
        "SNP config carries a half-populated rootfs override (image_format present without \
         image_readonly, or vice versa); the writer always sets both together, refusing to \
         guess which is intended"
    )]
    MalformedRootfsOverride,

    #[error("this controller only runs QEMU VMs, not Firecracker")]
    OnlyQemu,

    #[error(
        "Tap interface {interface} was not created after {seconds}s. The supervisor may \
         not be running or may have classified this execution as dead. Exiting."
    )]
    TapTimeout { interface: String, seconds: u64 },

    #[error("cannot start the async runtime: {0}")]
    Runtime(#[source] std::io::Error),

    #[error(transparent)]
    Qemu(#[from] QemuError),
}

fn main() -> ExitCode {
    let cli = Cli::parse();

    // logging.basicConfig(level=DEBUG if -v/-vv/--very-verbose else INFO).
    let filter = if cli.verbose > 0 { "debug" } else { "info" };
    tracing_subscriber::fmt()
        .with_env_filter(tracing_subscriber::EnvFilter::new(filter))
        .with_writer(std::io::stderr)
        .init();

    // Python's `main` logs at each `exit(1)` and lets the runtime set the
    // status; here the fallible body returns the error and this one site logs
    // it and maps it to the exit code.
    //
    // Plain Display, not `{error:#}`: this crate's error Displays are
    // self-contained by design (they inline their sources), so anyhow's
    // alternate render would double-print the chain. See the matching
    // comment in supervisor-daemon/src/main.rs.
    match run(&cli) {
        Ok(()) => ExitCode::SUCCESS,
        Err(error) => {
            tracing::error!("{error}");
            ExitCode::FAILURE
        }
    }
}

/// The controller's fallible body: the port of `__main__.main` after logging
/// setup. Each `?` is one of Python's `exit(1)` sites. Like Python (which
/// returns after `asyncio.run` regardless of QEMU's return code), the QEMU
/// exit code is not propagated: a VM that boots and later exits, cleanly or
/// not, is still a successful controller run.
///
/// `ControllerError` stays the typed mid-layer (tests downcast into it); this
/// signature is `anyhow::Result` only so `main` has one uniform sink.
fn run(cli: &Cli) -> anyhow::Result<()> {
    if !cli.config_path.is_file() {
        return Err(ControllerError::ConfigNotFound(cli.config_path.clone()).into());
    }

    let config = Configuration::from_file(&cli.config_path).map_err(|source| {
        ControllerError::ConfigLoad {
            path: cli.config_path.clone(),
            source,
        }
    })?;

    if cli.print_settings {
        println!("{}", config.settings.to_print_json());
    }

    // The config predates this process (written at VM creation, possibly by an
    // older aleph-vm): validate the one field Network cannot default.
    if config
        .settings
        .network_interface
        .as_deref()
        .unwrap_or("")
        .is_empty()
    {
        return Err(ControllerError::NoNetworkInterface(cli.config_path.clone()).into());
    }

    // Dispatch with Python's `execute_persistent_vm` precedence: the hypervisor
    // field first (firecracker rejected), then SNP, then the confidential-
    // superset shape, then the plain QEMU path.
    let target = select_run_target(&config)?;

    // Wait for the supervisor to create the tap interface. The controller
    // starts before the supervisor finishes loading persistent executions, so
    // the tap may not exist yet. Do NOT create it here.
    wait_for_tap(config.vm_id)?;

    let runtime = tokio::runtime::Builder::new_multi_thread()
        .enable_all()
        .build()
        .map_err(ControllerError::Runtime)?;
    let result = match &target {
        RunTarget::Plain(qemu_config) => runtime.block_on(qemu::run(&config.vm_hash, qemu_config)),
        RunTarget::Confidential(qemu_config) => {
            runtime.block_on(qemu::run_confidential(&config.vm_hash, qemu_config))
        }
        RunTarget::Snp(qemu_config) => {
            runtime.block_on(qemu::run_snp(&config.vm_hash, qemu_config))
        }
    };
    result.map_err(ControllerError::from)?;
    Ok(())
}

/// Block until `vmtap{vm_id}` exists, up to [`MAX_TAP_WAIT`]. Port of the
/// `__main__.main` wait loop: log every 10s, `exit(1)` if the tap never
/// appears. Existence is a `/sys/class/net/{name}` check, the same probe the
/// Rust daemon's tap backend uses for `Network.interface_exists`.
fn wait_for_tap(vm_id: i64) -> Result<(), ControllerError> {
    let interface_name = format!("vmtap{vm_id}");
    let mut waited = 0u64;
    let max = MAX_TAP_WAIT.as_secs();
    while !interface_exists(&interface_name) {
        if waited >= max {
            return Err(ControllerError::TapTimeout {
                interface: interface_name,
                seconds: max,
            });
        }
        if waited.is_multiple_of(10) {
            tracing::info!("Waiting for network interface {interface_name} ({waited}/{max}s)...");
        }
        std::thread::sleep(Duration::from_secs(1));
        waited += 1;
    }
    Ok(())
}

fn interface_exists(interface_name: &str) -> bool {
    std::path::Path::new("/sys/class/net")
        .join(interface_name)
        .exists()
}

/// The selected QEMU run path: plain (`QemuVM.start()`), SEV/SEV-ES
/// confidential (`QemuConfidentialVM.start()`), or SEV-SNP measured boot
/// (increment B1).
enum RunTarget {
    Plain(QemuConfig),
    Confidential(QemuConfig),
    Snp(QemuConfig),
}

/// Select the QEMU run path, replicating the Python `execute_persistent_vm`
/// precedence: check `config.hypervisor == firecracker` FIRST (fails closed for
/// a QEMU-shaped payload mislabelled firecracker, and for a config with the
/// field absent, which defaults to firecracker), then route a confidential
/// QEMU payload (all four SEV fields present, the `isinstance
/// QemuConfidentialVMConfiguration` branch) to the confidential path, then the
/// plain QEMU path. The Rust rejects where Python would assert; both fail
/// closed, never open.
fn select_run_target(config: &Configuration) -> Result<RunTarget, ControllerError> {
    if config.hypervisor == HypervisorType::Firecracker {
        return Err(ControllerError::NotAFirecrackerController);
    }
    match &config.vm_configuration {
        // SEV-SNP is checked first: it is a distinct measured-boot path with no
        // session/godh, so it is NOT `is_confidential()`, but routing it
        // explicitly keeps the intent clear. `is_snp()` requires ALL of the
        // fields `build_snp_argv` `.expect()`s, so this only routes a complete
        // config into the SNP builder (its debug_assert can never trip).
        // A complete SNP config with a half-populated rootfs override
        // (image_format present without image_readonly, or vice versa) is
        // refused here too, BEFORE the Snp/PartialSnpConfig split below: the
        // writer always sets the pair together, so this can only be a
        // corrupt or hand-edited config, and build_snp_argv must never be
        // asked to guess which half is right (its own debug_assert only
        // documents the invariant, it does not enforce it in release builds).
        VmConfiguration::Qemu(qemu_config)
            if qemu_config.is_snp()
                && matches!(qemu_config.rootfs_override(), RootfsOverride::Malformed) =>
        {
            Err(ControllerError::MalformedRootfsOverride)
        }
        VmConfiguration::Qemu(qemu_config) if qemu_config.is_snp() => {
            Ok(RunTarget::Snp((**qemu_config).clone()))
        }
        // The SNP marker is set but a measured field is missing (a corrupt or
        // partial controller JSON). Refuse CLEANLY rather than panic-looping in
        // the SNP builder or, worse, falling through to a silent plain/SEV
        // launch of a config the daemon meant to be measured. This mirrors the
        // daemon-side `QemuVmConfig::snp` soft-fail (marker set, field missing
        // -> `None`, treated as non-SNP fail-closed).
        VmConfiguration::Qemu(qemu_config) if qemu_config.is_snp_marked() => {
            Err(ControllerError::PartialSnpConfig)
        }
        VmConfiguration::Qemu(qemu_config) if qemu_config.is_confidential() => {
            Ok(RunTarget::Confidential((**qemu_config).clone()))
        }
        VmConfiguration::Qemu(qemu_config) => Ok(RunTarget::Plain((**qemu_config).clone())),
        VmConfiguration::Firecracker => Err(ControllerError::OnlyQemu),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const QEMU_VM_CONFIG: &str = r#""qemu_bin_path":"q","image_path":"i",
        "monitor_socket_path":"m","qmp_socket_path":"p","vcpu_count":1,
        "mem_size_mb":2048,"host_volumes":[],"gpus":[]"#;

    fn parse(hypervisor: &str, vm_configuration: &str) -> Configuration {
        let json = format!(
            r#"{{"vm_id":1,"vm_hash":"abc","settings":{{}},
                "vm_configuration":{{{vm_configuration}}},"hypervisor":"{hypervisor}"}}"#
        );
        Configuration::from_json(&json).unwrap()
    }

    fn cli_for(config_path: PathBuf) -> Cli {
        Cli {
            config_path,
            print_settings: false,
            verbose: 0,
        }
    }

    #[test]
    fn run_reports_a_missing_config_file() {
        // First `exit(1)` site: the path is not a file. `run` must fail with
        // ConfigNotFound before touching anything else (no tap wait, no
        // runtime), so this returns immediately.
        let cli = cli_for(PathBuf::from("/definitely/not/a/real/controller.json"));
        let error = run(&cli).unwrap_err();
        assert!(matches!(
            error.downcast_ref::<ControllerError>(),
            Some(ControllerError::ConfigNotFound(_))
        ));
    }

    #[test]
    fn run_reports_an_unparseable_config_as_config_load() {
        // Second `exit(1)` site: the file exists but does not parse. The
        // ConfigError source is preserved so the operator sees why.
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("broken-controller.json");
        std::fs::write(&path, b"{ not valid json").unwrap();
        let error = run(&cli_for(path)).unwrap_err();
        assert!(matches!(
            error.downcast_ref::<ControllerError>(),
            Some(ControllerError::ConfigLoad { .. })
        ));
    }

    #[test]
    fn a_plain_qemu_config_dispatches_to_the_plain_runner() {
        let config = parse("qemu", QEMU_VM_CONFIG);
        assert!(matches!(
            select_run_target(&config),
            Ok(RunTarget::Plain(_))
        ));
    }

    #[test]
    fn a_firecracker_labelled_config_is_rejected_even_with_a_qemu_shape() {
        // Python checks hypervisor==firecracker FIRST and asserts on the shape
        // (fails closed); the Rust must reject, not boot.
        let config = parse("firecracker", QEMU_VM_CONFIG);
        assert!(select_run_target(&config).is_err());
    }

    #[test]
    fn an_absent_hypervisor_field_defaults_to_firecracker_and_is_rejected() {
        // The pydantic default for `hypervisor` is firecracker: a QEMU-shaped
        // config with the field absent still fails closed.
        let json = format!(
            r#"{{"vm_id":1,"vm_hash":"abc","settings":{{}},
                "vm_configuration":{{{QEMU_VM_CONFIG}}}}}"#
        );
        let config = Configuration::from_json(&json).unwrap();
        assert_eq!(config.hypervisor, HypervisorType::Firecracker);
        assert!(select_run_target(&config).is_err());
    }

    #[test]
    fn a_confidential_shaped_config_dispatches_to_the_confidential_runner() {
        // All four SEV fields present: the Python `isinstance
        // QemuConfidentialVMConfiguration` branch. Routes to the confidential
        // path, not rejected (was the A1 behavior).
        let confidential = format!(
            r#"{QEMU_VM_CONFIG},"ovmf_path":"o","sev_session_file":"s",
               "sev_dh_cert_file":"d","sev_policy":5"#
        );
        let config = parse("qemu", &confidential);
        assert!(matches!(
            select_run_target(&config),
            Ok(RunTarget::Confidential(_))
        ));
    }

    #[test]
    fn a_confidential_config_mislabelled_firecracker_is_still_rejected() {
        // The hypervisor field wins first: a confidential-shaped payload
        // labelled firecracker fails closed, never boots confidential.
        let confidential = format!(
            r#"{QEMU_VM_CONFIG},"ovmf_path":"o","sev_session_file":"s",
               "sev_dh_cert_file":"d","sev_policy":5"#
        );
        let config = parse("firecracker", &confidential);
        assert!(select_run_target(&config).is_err());
    }

    #[test]
    fn an_snp_marked_config_dispatches_to_the_snp_runner() {
        // The daemon writes sev_snp:true plus the measured-boot fields; SNP is
        // NOT is_confidential (no session/godh), so it must route via the SNP
        // branch, not the plain one.
        let snp = format!(
            r#"{QEMU_VM_CONFIG},"sev_snp":true,"ovmf_path":"/OVMF.fd",
               "sev_policy":196608,"kernel_path":"/bzImage","initrd_path":"/initrd",
               "kernel_cmdline":"console=ttyS0 root=/dev/mapper/verity-root ro roothash=abc""#
        );
        let config = parse("qemu", &snp);
        assert!(matches!(select_run_target(&config), Ok(RunTarget::Snp(_))));
    }

    #[test]
    fn a_partial_snp_config_is_refused_cleanly_not_dispatched_to_the_snp_builder() {
        // sev_snp=true but the measured cmdline is absent (a corrupt/partial
        // controller JSON). `build_snp_argv` `.expect()`s that field, so
        // dispatching here would panic-loop under systemd. select_run_target
        // must return a clean Err instead (no panic), and it must NOT fall
        // through to the plain or confidential builder.
        let partial = format!(
            r#"{QEMU_VM_CONFIG},"sev_snp":true,"ovmf_path":"/OVMF.fd",
               "sev_policy":196608,"kernel_path":"/bzImage","initrd_path":"/initrd""#
        );
        let config = parse("qemu", &partial);
        match select_run_target(&config) {
            Err(error) => {
                let message = error.to_string();
                assert!(
                    message.contains("SEV-SNP") && message.contains("missing"),
                    "unexpected refusal message: {message}"
                );
            }
            Ok(target) => panic!(
                "a partial SNP config must be refused, not dispatched to {}",
                match target {
                    RunTarget::Plain(_) => "plain",
                    RunTarget::Confidential(_) => "confidential",
                    RunTarget::Snp(_) => "snp",
                }
            ),
        }
    }

    #[test]
    fn a_luks_snp_config_dispatches_to_the_snp_runner() {
        // The opaque-cmdline SEV-SNP arm (Task 8/9): both rootfs-override
        // keys present together must still route to the SNP runner, exactly
        // like a verity SNP config.
        let luks = format!(
            r#"{QEMU_VM_CONFIG},"sev_snp":true,"ovmf_path":"/OVMF.fd",
               "sev_policy":196608,"kernel_path":"/bzImage","initrd_path":"/initrd",
               "kernel_cmdline":"console=ttyS0 root=/dev/vda rw",
               "image_format":"qcow2","image_readonly":false"#
        );
        let config = parse("qemu", &luks);
        assert!(matches!(select_run_target(&config), Ok(RunTarget::Snp(_))));
    }

    #[test]
    fn a_half_populated_rootfs_override_is_refused_cleanly_not_dispatched_to_the_snp_builder() {
        // image_format present without image_readonly (or vice versa) on an
        // otherwise-complete SNP config is a corrupt/hand-edited config: the
        // writer always sets both together. select_run_target must refuse
        // rather than guess, and never fall through to the SNP builder
        // (whose own debug_assert only fires in debug builds).
        for extra in [r#""image_format":"qcow2""#, r#""image_readonly":false"#] {
            let half = format!(
                r#"{QEMU_VM_CONFIG},"sev_snp":true,"ovmf_path":"/OVMF.fd",
                   "sev_policy":196608,"kernel_path":"/bzImage","initrd_path":"/initrd",
                   "kernel_cmdline":"console=ttyS0 root=/dev/vda rw",
                   {extra}"#
            );
            let config = parse("qemu", &half);
            match select_run_target(&config) {
                Err(error) => {
                    let message = error.to_string();
                    assert!(
                        message.contains("half-populated") && message.contains("rootfs"),
                        "unexpected refusal message: {message}"
                    );
                }
                Ok(target) => panic!(
                    "a half-populated rootfs override must be refused, not dispatched to {}",
                    match target {
                        RunTarget::Plain(_) => "plain",
                        RunTarget::Confidential(_) => "confidential",
                        RunTarget::Snp(_) => "snp",
                    }
                ),
            }
        }
    }

    #[test]
    fn an_snp_config_mislabelled_firecracker_is_still_rejected() {
        let snp = format!(
            r#"{QEMU_VM_CONFIG},"sev_snp":true,"ovmf_path":"/OVMF.fd",
               "sev_policy":196608,"kernel_path":"/bzImage","initrd_path":"/initrd",
               "kernel_cmdline":"console=ttyS0 root=/dev/mapper/verity-root ro roothash=abc""#
        );
        let config = parse("firecracker", &snp);
        assert!(select_run_target(&config).is_err());
    }

    #[test]
    fn a_firecracker_shaped_config_is_rejected() {
        let firecracker = r#""use_jailer":true,
            "firecracker_bin_path":"/opt/firecracker/firecracker",
            "jailer_bin_path":"/opt/firecracker/jailer",
            "config_file_path":"/var/lib/aleph/vm/abc.json","init_timeout":5.0"#;
        let config = parse("firecracker", firecracker);
        assert!(select_run_target(&config).is_err());
    }
}
