use anyhow::Result;
use clap::Parser;

use vaultd::cli::Cli;
use vaultd::commands;

fn main() -> Result<()> {
    let cli = Cli::parse();

    commands::run(cli.command)?;

    Ok(())
}
