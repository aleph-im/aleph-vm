//! alephctl: debug CLI for the aleph-vm supervisor. Thin glue only: parse,
//! resolve the socket, connect, dispatch to supervisor_cli::commands.

use clap::Parser;
use supervisor_cli::cli::{Cli, Command, PortsCommand, VmCommand};
use supervisor_cli::{client, commands};

#[tokio::main]
async fn main() {
    let cli = Cli::parse();
    if let Err(error) = run(cli).await {
        eprintln!("alephctl: {error:#}");
        std::process::exit(1);
    }
}

async fn run(cli: Cli) -> anyhow::Result<()> {
    let socket = client::resolve_socket_path(cli.socket.clone(), |name| std::env::var(name).ok());
    let mut client = client::connect(&socket).await?;
    let mut out = std::io::stdout().lock();
    let json = cli.json;
    match cli.command {
        Command::Health => commands::host::health(&mut client, &mut out, json).await,
        Command::HostInfo => commands::host::host_info(&mut client, &mut out, json).await,
        Command::Vm(VmCommand::List) => commands::vm::list(&mut client, &mut out, json).await,
        Command::Vm(VmCommand::Get { vm_id }) => {
            commands::vm::get(&mut client, &mut out, &vm_id, json).await
        }
        Command::Vm(VmCommand::Spec { vm_id }) => {
            commands::vm::spec(&mut client, &mut out, &vm_id, json).await
        }
        Command::Vm(VmCommand::Start { vm_id }) => {
            commands::vm::start(&mut client, &mut out, &vm_id, json).await
        }
        Command::Vm(VmCommand::Stop { vm_id }) => {
            commands::vm::stop(&mut client, &mut out, &vm_id, json).await
        }
        Command::Vm(VmCommand::Reboot { vm_id }) => {
            commands::vm::reboot(&mut client, &mut out, &vm_id, json).await
        }
        Command::Vm(VmCommand::Delete { vm_id, yes }) => {
            let mut input = std::io::stdin().lock();
            commands::vm::delete(&mut client, &mut out, &mut input, &vm_id, yes, json).await
        }
        Command::Logs {
            vm_id,
            follow,
            tail,
        } => commands::logs::logs(&mut client, &mut out, &vm_id, follow, tail, json).await,
        Command::Events => commands::logs::events(&mut client, &mut out, json).await,
        Command::Ports(PortsCommand::List { vm_id }) => {
            commands::ports::list(&mut client, &mut out, vm_id, json).await
        }
    }
}
