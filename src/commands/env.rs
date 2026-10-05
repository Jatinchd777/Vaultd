// use anyhow::Result;
//
// use crate::daemon::client;
//
// fn valid_name(name: &str) -> bool {
//     let mut chars = name.chars();
//
//     matches!(
//         chars.next(),
//         Some(c) if c == '_' || c.is_ascii_alphabetic()
//     ) && chars.all(|c| c == '_' || c.is_ascii_alphanumeric())
// }
//
// pub fn run() -> Result<()> {
//     let environment = client::environment()?;
//
//     for (name, value) in environment {
//         if !valid_name(&name) {
//             anyhow::bail!("invalid environment variable name: {name}");
//         }
//
//         println!("export {name}={}", shell_escape(&value));
//     }
//
//     Ok(())
// }
//
// fn shell_escape(value: &str) -> String {
//     format!("'{}'", value.replace('\'', "'\\''"))
// }

use anyhow::Result;

use crate::daemon::client;

pub fn run() -> Result<()> {
    let environment = client::environment()?;

    for (name, value) in &environment {
        if !valid_name(name) {
            anyhow::bail!("invalid environment variable name: {name}");
        }

        println!("export {name}={}", shell_escape(value));
    }

    if !environment.is_empty() {
        println!();
        println!("export _VAULTD_EXPORTED='{}'", exported_names(&environment));
        println!();
        println!("vaultd-clear() {{");
        println!("    local name");
        println!("    for name in $_VAULTD_EXPORTED; do");
        println!("        unset \"$name\"");
        println!("    done");
        println!("    unset _VAULTD_EXPORTED");
        println!("}}");
    }

    Ok(())
}

fn exported_names(environment: &[(String, String)]) -> String {
    environment
        .iter()
        .map(|(name, _)| name.as_str())
        .collect::<Vec<_>>()
        .join(" ")
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
