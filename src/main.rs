mod cli;
mod commands;
mod crypto;
mod daemon;
mod error;
mod storage;
mod vault;

use anyhow::Result;
use clap::Parser;

use cli::Cli;

fn main() -> Result<()> {
    let cli = Cli::parse();

    commands::run(cli.command)?;

    Ok(())
}
