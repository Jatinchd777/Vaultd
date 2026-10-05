use anyhow::Result;

use crate::daemon::client;

pub fn run(name: String) -> Result<()> {
    let value = client::get(name)?;

    println!("{value}");

    Ok(())
}
