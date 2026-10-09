use anyhow::Result;
use clap::Parser;

use vaultd::cli::Cli;
use vaultd::commands;

fn main() -> Result<()> {
    // Defense in depth for the world-readable-permissions class: no file
    // created by this process (vault files, daemon sockets, temp files)
    // is ever group/other-accessible, even if an explicit chmod is missed.
    unsafe {
        libc::umask(0o077);
    }

    let cli = Cli::parse();

    commands::run(cli.command)?;

    Ok(())
}
