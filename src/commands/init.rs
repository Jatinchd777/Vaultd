use std::io::{self, Write};

use anyhow::Result;

use crate::{
    crypto::{
        cipher,
        kdf::{self, KdfParams},
    },
    storage::{
        filesystem,
        format::{FORMAT_VERSION, KdfConfig, Manifest},
    },
};

pub fn run() -> Result<()> {
    filesystem::create_vault_directory()?;

    let password = prompt_password("Create master password: ")?;
    let confirmation = prompt_password("Confirm master password: ")?;

    if password != confirmation {
        anyhow::bail!("passwords do not match");
    }

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

fn prompt_password(prompt: &str) -> Result<String> {
    print!("{prompt}");
    io::stdout().flush()?;

    Ok(rpassword::read_password()?)
}
