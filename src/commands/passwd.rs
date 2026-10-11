use std::io::{self, Write};

use anyhow::Result;
use zeroize::Zeroizing;

use crate::{crypto::password, daemon::server, vault::store::Vault};

pub fn run() -> Result<()> {
    if server::is_running()? {
        anyhow::bail!("vault is unlocked: run `vaultd lock` first, then `vaultd passwd`");
    }

    let old_password = prompt_password("Current password: ")?;
    let new_password = prompt_password("New master password: ")?;
    let confirmation = prompt_password("Confirm new password: ")?;

    if new_password != confirmation {
        anyhow::bail!("passwords do not match");
    }

    password::check_new_password(&new_password)?;

    let result = Vault::change_password(&old_password, &new_password);

    result?;

    println!("Master password changed");

    Ok(())
}

fn prompt_password(prompt: &str) -> Result<Zeroizing<String>> {
    print!("{prompt}");
    io::stdout().flush()?;

    Ok(Zeroizing::new(rpassword::read_password()?))
}
