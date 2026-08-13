//! aleph-vm-supervisor: the Rust supervisor daemon (increments 1-3).
//!
//! Serves the aleph.supervisor.v1 contract on the Unix socket at
//! ALEPH_VM_SUPERVISOR_GRPC_SOCKET (default {EXECUTION_ROOT}/supervisor.sock).
//! Configuration comes from ALEPH_VM_* environment variables; under systemd
//! the unit's EnvironmentFile= provides them, for dev runs --env-file does.
//!
//! Boot order mirrors the Python daemon (run_daemon): resolve host facts,
//! run the settings.check() preconditions and the pool.setup() counterparts
//! (store schema, forwarding sysctls, base nftables ruleset), rebuild the
//! world view from disk/systemd/sqlite (adoption steps 1-4), reconcile the
//! kernel/service state of running VMs (step 5), then bind the socket and
//! serve.

use std::process::ExitCode;
use std::sync::Arc;

use clap::Parser;
use supervisor_daemon::config::Settings;
use supervisor_daemon::envfile::apply_env_file;
use supervisor_daemon::error::DaemonError;
use supervisor_daemon::lifecycle::{self, Pacing};
use supervisor_daemon::logs::JournalctlLogSource;
use supervisor_daemon::ndppd::{NdpProxy, SystemNdppd};
use supervisor_daemon::nft::NftCli;
use supervisor_daemon::server::{self, SocketGuard};
use supervisor_daemon::service::{DaemonState, HostState};
use supervisor_daemon::tap::IpCommand;
use supervisor_daemon::units::ZbusUnitStates;
use supervisor_daemon::{checks, hugepages, numa, ports, world};

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

    // Plain Display, not `{error:#}`: this crate's error Displays are
    // self-contained by design (they inline their sources to keep
    // byte-identical text across the type-strictness series), but they also
    // expose those same sources via `Error::source()` (thiserror auto-links
    // any field named `source`). anyhow's alternate `{:#}` walks that chain
    // and appends each source again, so switching this sink to `{:#}`
    // without first stripping embedded sources from the Display templates
    // would double-print (e.g. "cannot open X: msg: msg").
    match run(&cli) {
        Ok(()) => ExitCode::SUCCESS,
        Err(error) => {
            tracing::error!(%error, "supervisor daemon failed");
            ExitCode::FAILURE
        }
    }
}

fn run(cli: &Cli) -> anyhow::Result<()> {
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

    // settings.check() slice: the startup preconditions the lifecycle RPCs
    // depend on. Aborts like daemon.py main(), after setup.
    checks::check(&host.settings, host.network_interface.as_deref())?;

    // pool.setup() counterparts: the port-mapping store schema, the legacy
    // port-mapping migration, the forwarding sysctls, the NDP proxy, the
    // base nftables ruleset.
    ports::ensure_schema(&host.settings.supervisor_database)?;
    // Before adoption, like pool.setup(): a node upgraded from the
    // pre-split layout and flipped straight to this daemon must adopt its
    // VMs with their persisted forwards, not with zero forwards.
    ports::migrate_port_mappings_from_legacy_db(
        &host.settings.execution_database,
        &host.settings.supervisor_database,
    )?;
    let ndp = if host.settings.allow_vm_networking {
        enable_forwarding_sysctls(&host.settings);
        host.settings.use_ndp_proxy.then(|| {
            Arc::new(NdpProxy::new(
                host.network_interface.clone().unwrap_or_default(),
                Arc::new(SystemNdppd),
            ))
        })
    } else {
        None
    };

    // Adoption steps 1-4 (design doc section 4), before the socket exists,
    // like the Python daemon's load_persistent_executions before serve_unix.
    // Blocking on purpose: no runtime is up yet, and the sources (files,
    // one D-Bus round trip, sqlite) are all local.
    let units = Arc::new(ZbusUnitStates::new());
    let world = world::build_world_view(&host.settings, units.as_ref(), &host.gpus);
    tracing::info!(vm_count = world.len(), "adopted the on-disk world view");
    let allow_networking = host.settings.allow_vm_networking;
    // NUMA topology (increment C1): detected once. A detection failure (no
    // sysfs, unreadable) disables CPU pinning rather than aborting the
    // daemon, mirroring how the other host-capability probes degrade.
    let mut numa = numa::NumaTopology::detect().unwrap_or_else(|error| {
        tracing::warn!(
            error = format!("{error:#}"),
            "NUMA topology detection failed; CPU pinning disabled"
        );
        numa::NumaTopology::empty()
    });
    tracing::info!(nodes = numa.num_nodes(), "detected NUMA topology");
    // Hugepage reservation (increment C2) is OPT-IN and only meaningful on a
    // >1-node host (placement is inert otherwise). It writes host-wide
    // nr_hugepages and updates the topology's per-node 2M pool in place, which
    // the allocator built just below then draws from. Fail-safe per node.
    if host.settings.numa_hugepages && numa.is_placement_active() {
        tracing::info!(
            headroom_mb = host.settings.numa_hugepages_headroom_mb,
            limit_mb = host.settings.numa_hugepages_limit_mb,
            "ALEPH_VM_NUMA_HUGEPAGES on: reserving 2M hugepages per NUMA node"
        );
        hugepages::reserve_2m_hugepages(
            &mut numa,
            host.settings.numa_hugepages_headroom_mb,
            host.settings.numa_hugepages_limit_mb,
        );
    }
    let numa_ledger = std::sync::Mutex::new(numa::NumaAllocator::new(numa.clone()));
    // The ephemeral Firecracker launcher (increment 4): programs are direct
    // children of this daemon (design doc decision 8).
    let launcher: Arc<dyn supervisor_daemon::firecracker::ProgramLauncher> = Arc::new(
        supervisor_daemon::firecracker::FirecrackerLauncher::from_settings(&host.settings),
    );
    let state = Arc::new(DaemonState {
        host,
        world: tokio::sync::RwLock::new(world),
        units,
        logs: Arc::new(JournalctlLogSource),
        nft: Arc::new(NftCli),
        taps: Arc::new(IpCommand),
        dhcp: Arc::new(supervisor_daemon::dhcp::SystemdRunDhcp),
        ndp,
        port_cursor: Default::default(),
        creation_lock: std::sync::Mutex::new(()),
        vm_locks: std::sync::Mutex::new(Default::default()),
        net_lock: std::sync::Mutex::new(()),
        pacing: Pacing::default(),
        events: supervisor_daemon::events::EventHub::default(),
        programs: launcher,
        log_follows: Arc::new(tokio::sync::Semaphore::new(
            supervisor_daemon::service::MAX_CONCURRENT_LOG_FOLLOWS,
        )),
        download_streams: Arc::new(tokio::sync::Semaphore::new(
            supervisor_daemon::service::MAX_CONCURRENT_DOWNLOADS,
        )),
        disk_tools: Arc::new(supervisor_daemon::backup::QemuImgTools),
        backups: supervisor_daemon::backup::BackupRegistry::default(),
        numa,
        numa_ledger,
    });

    let runtime = tokio::runtime::Builder::new_multi_thread()
        .enable_all()
        .build()?;
    runtime.block_on(async {
        // Rebuild the NUMA placement ledger from adopted VMs' effective
        // AllowedCPUs drop-ins (increment C1), before serving and
        // independent of networking: the ledger must be consistent even
        // with ALLOW_VM_NETWORKING off. Adopted VMs with no drop-in stay
        // unpinned (design section 8: unknown placement is not node 0).
        {
            let numa_state = state.clone();
            tokio::task::spawn_blocking(move || {
                lifecycle::reconcile_numa_ledger(&numa_state);
            })
            .await
            .map_err(|error| anyhow::anyhow!("the NUMA reconcile task failed: {error}"))?;
        }

        // Base ruleset + adoption step 5 inside the runtime (the ndppd
        // debounce and the blocking-pool hops need it), still before the
        // socket exists, like the Python network.setup() +
        // load_persistent_executions before serve_unix.
        if allow_networking {
            let boot_state = state.clone();
            tokio::task::spawn_blocking(move || {
                if let Err(error) = lifecycle::initialize_nftables(&boot_state) {
                    // The Python execute edge only logs nft failures too.
                    tracing::error!(%error, "failed to initialize nftables");
                }
                lifecycle::reconcile_boot(&boot_state);
            })
            .await
            .map_err(|error| anyhow::anyhow!("the boot reconcile task failed: {error}"))?;
        }

        // Retry VMs whose reattach failed above (e.g. host networking not
        // ready yet); self-terminates once nothing is left to retry, like
        // the Python run_reattach_retry_loop task.
        spawn_reattach_retry_loop(state.clone());

        // Handlers must be installed before the socket is bound: a client
        // that sees the socket may send SIGTERM right away, and an
        // uninstalled handler would mean death without cleanup.
        let shutdown = spawn_signal_task(guard.clone())?;
        server::serve(state, guard, shutdown).await?;
        Ok(())
    })
}

/// The `Network.setup()` sysctl half: enable IPv4 (always) and IPv6 (when
/// configured) forwarding. Python writes "1" only when the CURRENT value
/// parses as int 0 (`if not get_ipv6_forwarding_state()`), so a host whose
/// IPv6 forwarding sysctl is "2" (forwarding with RA acceptance) is left
/// alone; clobbering it to "1" would silently drop the host's accept-RA
/// behavior. Failures (unreadable, unparseable or unwritable files) are
/// logged, not fatal: the Python daemon dies here without CAP_NET_ADMIN,
/// which would break the container/CI boots increment 2 deliberately
/// supports (ledger entry 20).
fn enable_forwarding_sysctls(settings: &Settings) {
    enable_forwarding_sysctl(std::path::Path::new("/proc/sys/net/ipv4/ip_forward"));
    if settings.ipv6_forwarding_enabled {
        enable_forwarding_sysctl(std::path::Path::new(
            "/proc/sys/net/ipv6/conf/all/forwarding",
        ));
    } else {
        tracing::warn!("IPv6 forwarding is disabled, VMs will not have internet access on IPv6");
    }
}

/// One sysctl: write "1" only when the current value parses as int 0.
fn enable_forwarding_sysctl(path: &std::path::Path) {
    match std::fs::read_to_string(path) {
        // Python: int(value); only a current value of exactly 0 is
        // "disabled" and gets the write.
        Ok(current) => match current.trim().parse::<i64>() {
            Ok(0) => {
                if let Err(error) = std::fs::write(path, "1") {
                    tracing::error!(path = %path.display(), %error, "cannot enable forwarding");
                }
            }
            Ok(_) => {}
            Err(error) => {
                tracing::error!(path = %path.display(), %error, "cannot parse the forwarding state");
            }
        },
        Err(error) => {
            tracing::error!(path = %path.display(), %error, "cannot read the forwarding state");
        }
    }
}

/// The background reattach retry loop (Python pool.run_reattach_retry_loop):
/// while any queued failed reattach is not exhausted, sleep the interval and
/// run one retry pass on the blocking pool. A clean startup (no failures)
/// returns immediately, exactly like the Python task.
fn spawn_reattach_retry_loop(state: Arc<DaemonState>) {
    tokio::spawn(async move {
        loop {
            let pending = {
                let state = state.clone();
                tokio::task::spawn_blocking(move || lifecycle::has_pending_reattach(&state))
                    .await
                    .unwrap_or(false)
            };
            if !pending {
                return;
            }
            tokio::time::sleep(std::time::Duration::from_secs(
                lifecycle::REATTACH_RETRY_INTERVAL_SECONDS,
            ))
            .await;
            let state = state.clone();
            if let Err(error) = tokio::task::spawn_blocking(move || {
                lifecycle::retry_failed_reattachments_once(&state)
            })
            .await
            {
                tracing::error!(%error, "the reattach retry pass panicked");
            }
        }
    });
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

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn the_forwarding_sysctl_write_matches_the_python_falsy_gate() {
        // Python enable_ipv6_forwarding: write "1" only when int(current)
        // is 0. A value of "2" (forwarding with RA acceptance) must be
        // LEFT ALONE; clobbering it to "1" turns off the host's accept-RA.
        let tmp = tempfile::tempdir().unwrap();
        let sysctl = tmp.path().join("forwarding");
        for (current, expected) in [("0\n", "1"), ("1\n", "1\n"), ("2\n", "2\n")] {
            std::fs::write(&sysctl, current).unwrap();
            enable_forwarding_sysctl(&sysctl);
            assert_eq!(
                std::fs::read_to_string(&sysctl).unwrap(),
                expected,
                "current {current:?}"
            );
        }
        // Unparseable values are logged and left alone (the Python int()
        // would raise and kill the daemon; graceful here, ledger entry 20).
        std::fs::write(&sysctl, "garbage").unwrap();
        enable_forwarding_sysctl(&sysctl);
        assert_eq!(std::fs::read_to_string(&sysctl).unwrap(), "garbage");
    }
}
