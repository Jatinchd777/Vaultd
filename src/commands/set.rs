use anyhow::Result;

use crate::daemon::client;

pub fn run(name: String, value: Option<String>) -> Result<()> {
    let value = match value {
        Some(value) => value,

        None => rpassword::prompt_password("Credential value: ")?,
    };

    client::set(name.clone(), value)?;

    println!("Credential updated: {name}");

    Ok(())
}
