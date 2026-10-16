use std::{
    ffi::OsString,
    io::{self, Write},
    os::unix::process::ExitStatusExt,
    process::{Command, ExitCode},
};

use anyhow::{Context, Result};
use zeroize::{Zeroize, Zeroizing};

use crate::{commands::env::valid_name, vault::store::Vault};

pub fn run(command: Vec<OsString>) -> Result<ExitCode> {
    let mut command = command.into_iter();
    let program = command
        .next()
        .context("missing program; use `vaultd run -- <program> [args...]`")?;
    let args = command.collect::<Vec<_>>();

    let password = prompt_password()?;
    let mut vault = Vault::unlock(&password)?;

    for credential in vault.credentials() {
        if !valid_name(&credential.name) {
            anyhow::bail!("invalid environment variable name: {}", credential.name);
        }
    }

    let status = {
        let mut child = Command::new(&program);
        child
            .args(args)
            .envs(
                vault
                    .credentials()
                    .iter()
                    .map(|credential| (&credential.name, &credential.value)),
            )
            .status()
            .with_context(|| format!("failed to execute {program:?}"))?
    };

    vault.zeroize();

    Ok(exit_code(status))
}

fn prompt_password() -> Result<Zeroizing<String>> {
    print!("Master password: ");
    io::stdout().flush()?;

    Ok(Zeroizing::new(rpassword::read_password()?))
}

fn exit_code(status: std::process::ExitStatus) -> ExitCode {
    let code = status
        .code()
        .unwrap_or_else(|| 128 + status.signal().unwrap_or(1))
        .clamp(0, 255);
    ExitCode::from(code as u8)
}
