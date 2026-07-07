use clap::Parser;
use supervisor_cli::cli::Cli;

fn main() {
    // Dispatch lands with the command handlers (Task 10); parsing already
    // works so `alephctl --help` documents the full surface.
    let cli = Cli::parse();
    eprintln!("alephctl: {:?}: not implemented yet", cli.command);
    std::process::exit(2);
}
