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
use supervisor_controller::config::{Configuration, VmConfiguration};
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

    /// Set loglevel to DEBUG (the Python `-vv`).
    #[arg(short = 'v', long = "very-verbose", default_value_t = false)]
    very_verbose: bool,
}

fn main() -> ExitCode {
    let cli = Cli::parse();

    // logging.basicConfig(level=DEBUG if -vv else INFO).
    let filter = if cli.very_verbose { "debug" } else { "info" };
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

    // A1 drives the non-confidential QEMU path only. A confidential QEMU
    // config is A2; a Firecracker config is a different backend entirely.
    let qemu_config = match &config.vm_configuration {
        VmConfiguration::Qemu(qemu_config) if qemu_config.is_confidential() => {
            tracing::error!(
                "confidential VMs are not supported by this controller yet (increment A2)"
            );
            return ExitCode::FAILURE;
        }
        VmConfiguration::Qemu(qemu_config) => qemu_config.clone(),
        VmConfiguration::Firecracker => {
            tracing::error!("this controller only runs QEMU VMs, not Firecracker");
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
