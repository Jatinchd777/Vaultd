use argon2::{Algorithm, Argon2, Params, Version};
use rand::TryRngCore;
use rand::rngs::OsRng;

pub const KEY_LENGTH: usize = 32;
pub const SALT_LENGTH: usize = 16;

pub struct KdfParams {
    pub salt: [u8; SALT_LENGTH],
    pub memory_cost: u32,
    pub time_cost: u32,
    pub parallelism: u32,
}

impl KdfParams {
    pub fn generate() -> anyhow::Result<Self> {
        let mut salt = [0u8; SALT_LENGTH];

        OsRng
            .try_fill_bytes(&mut salt)
            .map_err(|e| anyhow::anyhow!("failed to generate salt: {e}"))?;

        Ok(Self {
            salt,
            memory_cost: 19_456,
            time_cost: 2,
            parallelism: 1,
        })
    }
}

pub fn derive_key(password: &[u8], params: &KdfParams) -> anyhow::Result<[u8; KEY_LENGTH]> {
    let argon2 = Argon2::new(
        Algorithm::Argon2id,
        Version::V0x13,
        Params::new(
            params.memory_cost,
            params.time_cost,
            params.parallelism,
            Some(KEY_LENGTH),
        )
        .map_err(|e| anyhow::anyhow!("invalid Argon2 parameters: {e}"))?,
    );

    let mut key = [0u8; KEY_LENGTH];

    argon2
        .hash_password_into(password, &params.salt, &mut key)
        .map_err(|e| anyhow::anyhow!("key derivation failed: {e}"))?;

    Ok(key)
}
