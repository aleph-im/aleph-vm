//! Command-line surface of alephctl. Parsing only: dispatch lives in
//! main.rs, handlers in commands/.

use std::path::PathBuf;

use clap::{Parser, Subcommand};

#[derive(Parser, Debug)]
#[command(
    name = "alephctl",
    about = "Debug CLI for the aleph-vm supervisor (gRPC over its Unix socket)"
)]
pub struct Cli {
    /// Supervisor Unix socket. Default: $ALEPH_VM_SUPERVISOR_GRPC_SOCKET,
    /// then $ALEPH_VM_EXECUTION_ROOT/supervisor.sock, then
    /// /var/lib/aleph/vm/supervisor.sock.
    #[arg(long, global = true)]
    pub socket: Option<PathBuf>,

    /// Print raw responses as JSON (streams: one JSON object per line).
    #[arg(long, global = true)]
    pub json: bool,

    #[command(subcommand)]
    pub command: Command,
}

#[derive(Subcommand, Debug)]
pub enum Command {
    /// Supervisor health and VM count.
    Health,
    /// Host hardware, TEE and networking facts.
    HostInfo,
    /// VM lifecycle and inspection.
    #[command(subcommand)]
    Vm(VmCommand),
    /// Fetch or follow a VM's logs.
    Logs {
        vm_id: String,
        /// Stream new lines as they arrive (StreamLogs).
        #[arg(long, short = 'f')]
        follow: bool,
        /// Only the most recent N lines (GetLogs from the tail).
        #[arg(long, conflicts_with = "follow")]
        tail: Option<u32>,
    },
    /// Stream VM lifecycle events until interrupted.
    Events,
    /// Port forwards.
    #[command(subcommand)]
    Ports(PortsCommand),
}

#[derive(Subcommand, Debug)]
pub enum VmCommand {
    /// List all VMs.
    List,
    /// Show a VM's current state.
    Get { vm_id: String },
    /// Show the spec a VM was created from.
    Spec { vm_id: String },
    /// Start a stopped VM.
    Start { vm_id: String },
    /// Stop a VM without releasing its definition.
    Stop { vm_id: String },
    /// Reboot a VM (soft reboot).
    Reboot { vm_id: String },
    /// Delete a VM (prompts unless --yes).
    Delete {
        vm_id: String,
        #[arg(long, short = 'y')]
        yes: bool,
    },
}

#[derive(Subcommand, Debug)]
pub enum PortsCommand {
    /// List port forwards (all VMs, or one).
    List { vm_id: Option<String> },
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parses_global_flags_and_vm_delete() {
        let cli =
            Cli::try_parse_from(["alephctl", "--json", "vm", "delete", "vm-1", "--yes"]).unwrap();
        assert!(cli.json);
        assert!(cli.socket.is_none());
        match cli.command {
            Command::Vm(VmCommand::Delete { vm_id, yes }) => {
                assert_eq!(vm_id, "vm-1");
                assert!(yes);
            }
            other => panic!("unexpected parse: {other:?}"),
        }
    }

    #[test]
    fn parses_socket_after_the_subcommand() {
        let cli = Cli::try_parse_from(["alephctl", "health", "--socket", "/tmp/s.sock"]).unwrap();
        assert_eq!(cli.socket, Some(std::path::PathBuf::from("/tmp/s.sock")));
        assert!(matches!(cli.command, Command::Health));
    }

    #[test]
    fn logs_tail_conflicts_with_follow() {
        let error = Cli::try_parse_from(["alephctl", "logs", "vm-1", "--follow", "--tail", "10"])
            .unwrap_err();
        assert_eq!(error.kind(), clap::error::ErrorKind::ArgumentConflict);
    }
}
