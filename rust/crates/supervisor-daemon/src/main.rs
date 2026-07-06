//! aleph-vm-supervisor: the Rust supervisor daemon (increments 1 and 2).
//!
//! Serves the aleph.supervisor.v1 contract on the Unix socket at
//! ALEPH_VM_SUPERVISOR_GRPC_SOCKET (default {EXECUTION_ROOT}/supervisor.sock).
//! Configuration comes from ALEPH_VM_* environment variables; under systemd
//! the unit's EnvironmentFile= provides them, for dev runs --env-file does.
//!
//! Boot order mirrors the Python daemon (run_daemon): resolve host facts,
//! rebuild the world view from disk/systemd/sqlite (adoption steps 1-4),
//! then bind the socket and serve.

use std::process::ExitCode;
use std::sync::Arc;

use clap::Parser;
use supervisor_daemon::config::Settings;
use supervisor_daemon::envfile::apply_env_file;
use supervisor_daemon::error::DaemonError;
use supervisor_daemon::logs::JournalctlLogSource;
use supervisor_daemon::server::{self, SocketGuard};
use supervisor_daemon::service::{DaemonState, HostState};
use supervisor_daemon::units::ZbusUnitStates;
use supervisor_daemon::world;

#[derive(Debug, Parser)]
#[command(
    name = "aleph-vm-supervisor",
    about = "Aleph VM supervisor daemon (gRPC over a Unix socket)"
)]
struct Cli {
    /// Source KEY=VALUE pairs from this file into the environment before
    /// reading configuration. Existing variables win. Dev convenience: under
    /// systemd, EnvironmentFile= plays this role.
    #[arg(long, value_name = "PATH")]
    env_file: Option<std::path::PathBuf>,

    /// Unix socket path (default: settings). Overrides the settings-derived
    /// path, like the Python daemon.py --socket.
    #[arg(long, value_name = "PATH")]
    socket: Option<std::path::PathBuf>,

    /// Debug logging, like the Python daemon.py -v/--verbose.
    #[arg(short, long)]
    verbose: bool,
}

fn main() -> ExitCode {
    let cli = Cli::parse();

    // Before tracing and before the runtime: the env file may carry RUST_LOG,
    // and mutating the environment is only sound while single-threaded.
    if let Some(path) = &cli.env_file
        && let Err(error) = apply_env_file(path)
    {
        eprintln!("aleph-vm-supervisor: {error}");
        return ExitCode::FAILURE;
    }

    // -v raises everything to DEBUG, the Python daemon.py behavior
    // (logging.basicConfig(level=DEBUG if args.verbose else INFO)).
    let filter = if cli.verbose {
        tracing_subscriber::EnvFilter::new("debug")
    } else {
        tracing_subscriber::EnvFilter::try_from_default_env()
            .unwrap_or_else(|_| tracing_subscriber::EnvFilter::new("info"))
    };
    tracing_subscriber::fmt()
        .with_env_filter(filter)
        .with_writer(std::io::stderr)
        .init();

    match run(&cli) {
        Ok(()) => ExitCode::SUCCESS,
        Err(error) => {
            tracing::error!(%error, "supervisor daemon failed");
            ExitCode::FAILURE
        }
    }
}

fn run(cli: &Cli) -> Result<(), DaemonError> {
    let mut settings = Settings::from_env()?;
    // --socket overrides the settings-derived path, after settings
    // resolution, like `args.socket or default_socket_path()` in daemon.py.
    if let Some(socket) = &cli.socket {
        settings.supervisor_grpc_socket = socket.clone();
    }
    tracing::info!(
        execution_root = %settings.execution_root.display(),
        socket = %settings.supervisor_grpc_socket.display(),
        "starting the Rust supervisor daemon"
    );

    server::prepare_directories(&settings)?;
    let guard = Arc::new(SocketGuard::new(settings.supervisor_grpc_socket.clone()));
    let host = HostState::initialize(settings)?;

    // Adoption steps 1-4 (design doc section 4), before the socket exists,
    // like the Python daemon's load_persistent_executions before serve_unix.
    // Blocking on purpose: no runtime is up yet, and the sources (files,
    // one D-Bus round trip, sqlite) are all local.
    let units = Arc::new(ZbusUnitStates::new());
    let world = world::build_world_view(&host.settings, units.as_ref());
    tracing::info!(vm_count = world.len(), "adopted the on-disk world view");
    let state = Arc::new(DaemonState {
        host,
        world: tokio::sync::RwLock::new(world),
        units,
        logs: Arc::new(JournalctlLogSource),
    });

    let runtime = tokio::runtime::Builder::new_multi_thread()
        .enable_all()
        .build()?;
    runtime.block_on(async {
        // Handlers must be installed before the socket is bound: a client
        // that sees the socket may send SIGTERM right away, and an
        // uninstalled handler would mean death without cleanup.
        let shutdown = spawn_signal_task(guard.clone())?;
        server::serve(state, guard, shutdown).await
    })
}

/// Install SIGTERM/SIGINT handling, the two signals the Python daemon
/// handles, and return a channel that flips to true on the first one.
///
/// The task keeps listening after the first signal (dropping the streams
/// would leave later signals with no handler): a second SIGTERM/SIGINT
/// skips the 5 second grace the server gives in-flight RPCs (the Python
/// server.stop(grace=5) equivalent lives in server::serve), unlinks our
/// socket (identity-checked) and exits immediately.
fn spawn_signal_task(
    guard: Arc<SocketGuard>,
) -> Result<tokio::sync::watch::Receiver<bool>, DaemonError> {
    use tokio::signal::unix::{SignalKind, signal};

    let mut sigterm = signal(SignalKind::terminate())?;
    let mut sigint = signal(SignalKind::interrupt())?;
    let (shutdown_tx, shutdown_rx) = tokio::sync::watch::channel(false);
    tokio::spawn(async move {
        tokio::select! {
            _ = sigterm.recv() => tracing::info!("SIGTERM received"),
            _ = sigint.recv() => tracing::info!("SIGINT received"),
        }
        let _ = shutdown_tx.send(true);

        tokio::select! {
            _ = sigterm.recv() => (),
            _ = sigint.recv() => (),
        }
        tracing::warn!("second shutdown signal received, exiting immediately");
        guard.cleanup();
        std::process::exit(0);
    });
    Ok(shutdown_rx)
}
