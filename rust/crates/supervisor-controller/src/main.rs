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
use supervisor_controller::config::{Configuration, HypervisorType, QemuConfig, VmConfiguration};
use supervisor_controller::qemu;

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

fn main() -> ExitCode {
    let cli = Cli::parse();

    // logging.basicConfig(level=DEBUG if -v/-vv/--very-verbose else INFO).
    let filter = if cli.verbose > 0 { "debug" } else { "info" };
    tracing_subscriber::fmt()
        .with_env_filter(tracing_subscriber::EnvFilter::new(filter))
        .with_writer(std::io::stderr)
        .init();

    if !cli.config_path.is_file() {
        tracing::error!("Configuration file {} not found", cli.config_path.display());
        return ExitCode::FAILURE;
    }

    let config = match Configuration::from_file(&cli.config_path) {
        Ok(config) => config,
        Err(error) => {
            tracing::error!("cannot load {}: {error}", cli.config_path.display());
            return ExitCode::FAILURE;
        }
    };

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
        tracing::error!(
            "Controller config {} carries no NETWORK_INTERFACE",
            cli.config_path.display()
        );
        return ExitCode::FAILURE;
    }

    // A1 drives the non-confidential QEMU path only. Dispatch with Python's
    // precedence: the hypervisor field first, then the vm_configuration shape.
    let qemu_config = match select_qemu_config(&config) {
        Ok(qemu_config) => qemu_config,
        Err(error) => {
            tracing::error!("{error}");
            return ExitCode::FAILURE;
        }
    };

    // Wait for the supervisor to create the tap interface. The controller
    // starts before the supervisor finishes loading persistent executions, so
    // the tap may not exist yet. Do NOT create it here.
    if let Err(error) = wait_for_tap(config.vm_id) {
        tracing::error!("{error}");
        return ExitCode::FAILURE;
    }

    let runtime = match tokio::runtime::Builder::new_multi_thread()
        .enable_all()
        .build()
    {
        Ok(runtime) => runtime,
        Err(error) => {
            tracing::error!("cannot start the async runtime: {error}");
            return ExitCode::FAILURE;
        }
    };
    match runtime.block_on(qemu::run(&config.vm_hash, &qemu_config)) {
        Ok(_) => ExitCode::SUCCESS,
        Err(error) => {
            tracing::error!("{error}");
            ExitCode::FAILURE
        }
    }
}

/// Block until `vmtap{vm_id}` exists, up to [`MAX_TAP_WAIT`]. Port of the
/// `__main__.main` wait loop: log every 10s, `exit(1)` if the tap never
/// appears. Existence is a `/sys/class/net/{name}` check, the same probe the
/// Rust daemon's tap backend uses for `Network.interface_exists`.
fn wait_for_tap(vm_id: i64) -> Result<(), String> {
    let interface_name = format!("vmtap{vm_id}");
    let mut waited = 0u64;
    let max = MAX_TAP_WAIT.as_secs();
    while !interface_exists(&interface_name) {
        if waited >= max {
            return Err(format!(
                "Tap interface {interface_name} was not created after {max}s. \
                 The supervisor may not be running or may have classified this \
                 execution as dead. Exiting."
            ));
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

/// Select the QEMU runner config, replicating the Python `execute_persistent_vm`
/// precedence: check `config.hypervisor == firecracker` FIRST (fails closed for
/// a QEMU-shaped payload mislabelled firecracker, and for a config with the
/// field absent, which defaults to firecracker), then reject a confidential
/// QEMU payload (that is A2), then run the plain QEMU path. The Rust A1 rejects
/// where Python would assert/NotImplemented; both fail closed, never open.
fn select_qemu_config(config: &Configuration) -> Result<QemuConfig, String> {
    if config.hypervisor == HypervisorType::Firecracker {
        return Err(
            "this controller does not run Firecracker VMs (hypervisor=firecracker); \
             A1 implements the non-confidential QEMU path only"
                .to_string(),
        );
    }
    match &config.vm_configuration {
        VmConfiguration::Qemu(qemu_config) if qemu_config.is_confidential() => Err(
            "confidential VMs are not supported by this controller yet (increment A2)".to_string(),
        ),
        VmConfiguration::Qemu(qemu_config) => Ok((**qemu_config).clone()),
        VmConfiguration::Firecracker => {
            Err("this controller only runs QEMU VMs, not Firecracker".to_string())
        }
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

    #[test]
    fn a_plain_qemu_config_dispatches_to_the_qemu_runner() {
        let config = parse("qemu", QEMU_VM_CONFIG);
        assert!(select_qemu_config(&config).is_ok());
    }

    #[test]
    fn a_firecracker_labelled_config_is_rejected_even_with_a_qemu_shape() {
        // Python checks hypervisor==firecracker FIRST and asserts on the shape
        // (fails closed); the Rust must reject, not boot.
        let config = parse("firecracker", QEMU_VM_CONFIG);
        assert!(select_qemu_config(&config).is_err());
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
        assert!(select_qemu_config(&config).is_err());
    }

    #[test]
    fn a_confidential_shaped_config_is_rejected() {
        let confidential = format!(
            r#"{QEMU_VM_CONFIG},"ovmf_path":"o","sev_session_file":"s",
               "sev_dh_cert_file":"d","sev_policy":5"#
        );
        let config = parse("qemu", &confidential);
        assert!(select_qemu_config(&config).is_err());
    }

    #[test]
    fn a_firecracker_shaped_config_is_rejected() {
        let firecracker = r#""use_jailer":true,
            "firecracker_bin_path":"/opt/firecracker/firecracker",
            "jailer_bin_path":"/opt/firecracker/jailer",
            "config_file_path":"/var/lib/aleph/vm/abc.json","init_timeout":5.0"#;
        let config = parse("firecracker", firecracker);
        assert!(select_qemu_config(&config).is_err());
    }
}
