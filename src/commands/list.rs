use anyhow::Result;

use crate::daemon::client;

pub fn run() -> Result<()> {
    let names = client::list()?;

    println!();

    let count = names.len();

    if count == 0 {
        println!("No credentials.");
        return Ok(());
    }

    println!(
        "{} {}",
        count,
        if count == 1 {
            "credential"
        } else {
            "credentials"
        }
    );

    println!();

    for name in names {
        println!("  • {name}");
    }

    println!();

    Ok(())
}
