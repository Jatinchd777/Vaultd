use std::io::{self, Write};

use anyhow::Result;
use zeroize::Zeroizing;

use crate::{
    crypto::{
        cipher,
        kdf::{self, KdfParams},
        password,
    },
    storage::{
        filesystem,
        format::{FORMAT_VERSION, KdfConfig, Manifest},
    },
};

pub fn run() -> Result<()> {
    // Refuse up front so a later failure never leaves a half-made vault
    // behind and the user is not prompted for nothing.
    let cwd = std::env::current_dir()?;
    if filesystem::find_project_root_from(&cwd).is_ok() {
        let existing = filesystem::find_project_root_from(&cwd)?;
        anyhow::bail!("vault already exists at {}", existing.display());
    }

    let password = prompt_password("Create master password: ")?;
    let confirmation = prompt_password("Confirm master password: ")?;

    if password != confirmation {
        anyhow::bail!("passwords do not match");
    }

    password::check_new_password(&password)?;

    filesystem::create_vault_directory()?;

    let params = KdfParams::generate()?;

    let key = kdf::derive_key(password.as_bytes(), &params)?;

    let manifest = Manifest {
        version: FORMAT_VERSION,
        cipher: "AES-256-GCM".to_string(),
        kdf: KdfConfig {
            algorithm: "Argon2id".to_string(),
            salt: base64::Engine::encode(&base64::engine::general_purpose::STANDARD, params.salt),
            memory_cost: params.memory_cost,
            time_cost: params.time_cost,
            parallelism: params.parallelism,
        },
    };

    let manifest_json = serde_json::to_vec_pretty(&manifest)?;

    filesystem::write_manifest(&manifest_json)?;

    let encrypted_vault = cipher::encrypt(&key, b"[]")?;

    filesystem::write_vault(&encrypted_vault)?;

    println!("Vault initialized at ./.vaultd");

    Ok(())
}

fn prompt_password(prompt: &str) -> Result<Zeroizing<String>> {
    print!("{prompt}");
    io::stdout().flush()?;

    Ok(Zeroizing::new(rpassword::read_password()?))
}
