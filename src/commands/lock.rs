use anyhow::Result;

use crate::daemon::client;

pub fn run() -> Result<()> {
    client::lock()?;

    println!("✓ Vault locked");

    Ok(())
}
