use anyhow::Result;

use crate::daemon::client;

pub fn run(name: String) -> Result<()> {
    client::remove(name.clone())?;

    println!("Credential removed: {name}");

    Ok(())
}
