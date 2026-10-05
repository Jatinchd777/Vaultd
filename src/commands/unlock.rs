use anyhow::Result;
use std::io::{self, Write};

use crate::{daemon::server, vault::vault::Vault};

pub fn run() -> Result<()> {
    if server::is_running()? {
        anyhow::bail!("vaultd daemon is already running");
    }

    let password = prompt_password("Master password: ")?;
    let vault = Vault::unlock(&password)?;

    // Forks the daemon (Unix-socket IPC, pidfd-monitored) and execs the
    // dedicated vault shell in this process. When that shell exits the
    // daemon breaks its loop, drops Vault (Zeroize), unlinks the socket,
    // and exits. `vaultd lock` remains an explicit shutdown path.
    server::spawn_daemon_and_shell(vault)?;

    Ok(())
}

fn prompt_password(prompt: &str) -> Result<String> {
    print!("{prompt}");
    io::stdout().flush()?;

    Ok(rpassword::read_password()?)
}
