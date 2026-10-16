use anyhow::Result;
use clap::Parser;
use std::process::ExitCode;

use vaultd::cli::Cli;
use vaultd::commands;

fn main() -> Result<ExitCode> {
    unsafe {
        libc::umask(0o077);
    }

    let cli = Cli::parse();

    commands::run(cli.command)
}
