use anyhow::Result;

use crate::daemon::{client, server};

pub fn run(shell: Option<String>) -> Result<()> {
    let shell = match shell {
        Some(name) => server::parse_shell_name(&name)?,
        None => server::detect_shell()?,
    };
    let socket_path = server::socket_path()?;
    let token = server::load_client_token()?;
    let environment = client::environment()?;
    let fish = shell == server::Shell::Fish;

    emit("VAULTD_SOCKET", &socket_path.to_string_lossy(), fish);
    emit("VAULTD_TOKEN", &server::encode_token_hex(&token), fish);

    for (name, value) in &environment {
        if !valid_name(name) {
            anyhow::bail!("invalid environment variable name: {name}");
        }

        emit(name, value, fish);
    }

    Ok(())
}

fn emit(name: &str, value: &str, fish: bool) {
    if fish {
        println!("set -gx {name} {}", shell_escape(value));
    } else {
        println!("export {name}={}", shell_escape(value));
    }
}

fn valid_name(name: &str) -> bool {
    let mut chars = name.chars();

    matches!(
        chars.next(),
        Some(c) if c == '_' || c.is_ascii_alphabetic()
    ) && chars.all(|c| c == '_' || c.is_ascii_alphanumeric())
}

fn shell_escape(value: &str) -> String {
    format!("'{}'", value.replace('\'', "'\\''"))
}
