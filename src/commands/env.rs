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

    // Auto-lock hook: a vault shell sitting at its prompt exits cleanly
    // by itself once the daemon socket is gone, so `lock` from inside
    // returns to the outer shell with no `killed` report. (zsh travels
    // via the generated `ZDOTDIR` init instead: functions die at `exec`.)
    match shell {
        server::Shell::Bash => {
            println!("_vaultd_autolock() {{ [ -S \"${{VAULTD_SOCKET:-}}\" ] || exit 0; }}");
            println!("export -f _vaultd_autolock 2>/dev/null || true");
            println!(
                "if [ -n \"${{PROMPT_COMMAND:-}}\" ]; then PROMPT_COMMAND=\"_vaultd_autolock;$PROMPT_COMMAND\"; else PROMPT_COMMAND=\"_vaultd_autolock\"; fi"
            );
            println!("export PROMPT_COMMAND");
        }
        server::Shell::Fish => {
            println!("function _vaultd_autolock --on-event fish_prompt");
            println!("    test -S \"$VAULTD_SOCKET\"; or exit 0");
            println!("end");
        }
        server::Shell::Zsh => {}
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

pub(crate) fn valid_name(name: &str) -> bool {
    let mut chars = name.chars();

    matches!(
        chars.next(),
        Some(c) if c == '_' || c.is_ascii_alphabetic()
    ) && chars.all(|c| c == '_' || c.is_ascii_alphanumeric())
}

fn shell_escape(value: &str) -> String {
    format!("'{}'", value.replace('\'', "'\\''"))
}
