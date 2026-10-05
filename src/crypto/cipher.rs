use aes_gcm::{
    Aes256Gcm, Nonce,
    aead::{Aead, KeyInit},
};
use rand::{TryRngCore, rngs::OsRng};

pub const NONCE_LENGTH: usize = 12;

pub fn encrypt(key: &[u8; 32], plaintext: &[u8]) -> anyhow::Result<Vec<u8>> {
    let cipher =
        Aes256Gcm::new_from_slice(key).map_err(|_| anyhow::anyhow!("invalid AES-256 key"))?;

    let mut nonce_bytes = [0u8; NONCE_LENGTH];

    OsRng
        .try_fill_bytes(&mut nonce_bytes)
        .map_err(|e| anyhow::anyhow!("failed to generate nonce: {e}"))?;

    let nonce = Nonce::from_slice(&nonce_bytes);

    let ciphertext = cipher
        .encrypt(nonce, plaintext)
        .map_err(|_| anyhow::anyhow!("vault encryption failed"))?;

    let mut output = Vec::with_capacity(NONCE_LENGTH + ciphertext.len());

    output.extend_from_slice(&nonce_bytes);
    output.extend_from_slice(&ciphertext);

    Ok(output)
}

pub fn decrypt(key: &[u8; 32], encrypted: &[u8]) -> anyhow::Result<Vec<u8>> {
    if encrypted.len() < NONCE_LENGTH {
        anyhow::bail!("encrypted vault is too short");
    }

    let (nonce_bytes, ciphertext) = encrypted.split_at(NONCE_LENGTH);

    let cipher =
        Aes256Gcm::new_from_slice(key).map_err(|_| anyhow::anyhow!("invalid AES-256 key"))?;

    let nonce = Nonce::from_slice(nonce_bytes);

    cipher
        .decrypt(nonce, ciphertext)
        .map_err(|_| anyhow::anyhow!("vault authentication failed"))
}
