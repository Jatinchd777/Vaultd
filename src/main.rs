use anyhow::Result;
use clap::Parser;

use vaultd::cli::Cli;
use vaultd::commands;

fn main() -> Result<()> {
    unsafe {
        libc::umask(0o077);
    }

    let cli = Cli::parse();

    commands::run(cli.command)?;

    Ok(())
}
