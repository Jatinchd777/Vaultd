use anyhow::Result;

use crate::daemon::{client, server};

pub fn run() -> Result<()> {
    let socket_path = server::socket_path()?;
    let token = server::load_client_token()?;
    let environment = client::environment()?;

    println!(
        "export {}={}",
        server::SOCKET_ENV,
        shell_escape(&socket_path.to_string_lossy())
    );
    println!(
        "export {}={}",
        server::TOKEN_ENV,
        shell_escape(&server::encode_token_hex(&token))
    );

    for (name, value) in &environment {
        if !valid_name(name) {
            anyhow::bail!("invalid environment variable name: {name}");
        }

        println!("export {name}={}", shell_escape(value));
    }

    Ok(())
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
