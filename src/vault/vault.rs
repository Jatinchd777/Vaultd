use anyhow::Result;
use base64::Engine;
use zeroize::Zeroize;

use crate::{
    crypto::{cipher, kdf},
    storage::{filesystem, format::Manifest},
};

use super::credential::Credential;

#[derive(Debug)]
pub struct Vault {
    key: [u8; 32],
    credentials: Vec<Credential>,
}

impl Zeroize for Vault {
    fn zeroize(&mut self) {
        self.key.zeroize();

        for credential in &mut self.credentials {
            credential.name.zeroize();
            credential.value.zeroize();
        }

        self.credentials.clear();
    }
}

impl Drop for Vault {
    fn drop(&mut self) {
        self.zeroize();
    }
}

impl Vault {
    pub fn unlock(password: &str) -> Result<Self> {
        let manifest_bytes = filesystem::read_manifest()?;

        let manifest: Manifest = serde_json::from_slice(&manifest_bytes)?;

        let salt = base64::engine::general_purpose::STANDARD.decode(&manifest.kdf.salt)?;

        let salt: [u8; 16] = salt
            .try_into()
            .map_err(|_| anyhow::anyhow!("invalid vault salt length"))?;

        let params = kdf::KdfParams {
            salt,
            memory_cost: manifest.kdf.memory_cost,
            time_cost: manifest.kdf.time_cost,
            parallelism: manifest.kdf.parallelism,
        };

        let key = kdf::derive_key(password.as_bytes(), &params)?;

        let encrypted_vault = filesystem::read_vault()?;

        let plaintext = cipher::decrypt(&key, &encrypted_vault)?;

        let credentials = serde_json::from_slice(&plaintext)?;

        Ok(Self { key, credentials })
    }

    pub fn add(&mut self, name: String, value: String) -> Result<()> {
        if self
            .credentials
            .iter()
            .any(|credential| credential.name == name)
        {
            anyhow::bail!("credential already exists: {name}");
        }

        self.credentials.push(Credential { name, value });

        self.save()
    }

    pub fn get(&self, name: &str) -> Result<&str> {
        self.credentials
            .iter()
            .find(|credential| credential.name == name)
            .map(|credential| credential.value.as_str())
            .ok_or_else(|| anyhow::anyhow!("credential not found: {name}"))
    }

    pub fn set(&mut self, name: String, value: String) -> Result<()> {
        let credential = self
            .credentials
            .iter_mut()
            .find(|credential| credential.name == name)
            .ok_or_else(|| anyhow::anyhow!("credential not found: {name}"))?;

        credential.value = value;

        self.save()
    }

    pub fn remove(&mut self, name: &str) -> Result<()> {
        let original_len = self.credentials.len();

        self.credentials
            .retain(|credential| credential.name != name);

        if self.credentials.len() == original_len {
            anyhow::bail!("credential not found: {name}");
        }

        self.save()
    }

    fn save(&self) -> Result<()> {
        let plaintext = serde_json::to_vec(&self.credentials)?;

        let encrypted = cipher::encrypt(&self.key, &plaintext)?;

        filesystem::write_vault(&encrypted)?;

        Ok(())
    }

    pub fn credentials(&self) -> &[Credential] {
        &self.credentials
    }

    pub fn environment(&self) -> Vec<(String, String)> {
        self.credentials
            .iter()
            .map(|credential| (credential.name.clone(), credential.value.clone()))
            .collect()
    }
}
