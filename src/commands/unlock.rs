use anyhow::Result;
use std::io::{self, Write};

use crate::{daemon::server, vault::store::Vault};

pub fn run() -> Result<()> {
    let socket_path = server::current_project_socket_path()?;

    if server::is_running()? {
        anyhow::bail!("vaultd daemon is already running for this project");
    }

    let password = prompt_password("Master password: ")?;
    let vault = Vault::unlock(&password)?;

    server::spawn_daemon_and_shell(vault, socket_path)?;

    Ok(())
}

fn prompt_password(prompt: &str) -> Result<String> {
    print!("{prompt}");
    io::stdout().flush()?;

    Ok(rpassword::read_password()?)
}
