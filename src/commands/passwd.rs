use std::io::{self, Write};

use anyhow::Result;
use zeroize::Zeroize;

use crate::{daemon::server, vault::store::Vault};

pub fn run() -> Result<()> {
    if server::is_running()? {
        anyhow::bail!("vault is unlocked: run `vaultd lock` first, then `vaultd passwd`");
    }

    let mut old_password = prompt_password("Current password: ")?;
    let mut new_password = prompt_password("New master password: ")?;
    let mut confirmation = prompt_password("Confirm new password: ")?;

    if new_password != confirmation {
        old_password.zeroize();
        new_password.zeroize();
        confirmation.zeroize();
        anyhow::bail!("passwords do not match");
    }

    if new_password.is_empty() {
        old_password.zeroize();
        new_password.zeroize();
        confirmation.zeroize();
        anyhow::bail!("new password must not be empty");
    }

    let result = Vault::change_password(&old_password, &new_password);

    old_password.zeroize();
    new_password.zeroize();
    confirmation.zeroize();

    result?;

    println!("Master password changed");

    Ok(())
}

fn prompt_password(prompt: &str) -> Result<String> {
    print!("{prompt}");
    io::stdout().flush()?;

    Ok(rpassword::read_password()?)
}
