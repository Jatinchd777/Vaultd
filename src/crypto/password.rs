//! New-password policy: a length floor plus a blocklist of the most
//! common real-world passwords (NordPass 2025 global top 10).
//!
//! Applied at `init` and `passwd` time, never at `unlock`: vaults that
//! already exist with weak passwords must still open. The salt and KDF
//! settings ship with the repo, so offline guessing is always possible
//! and the password is the whole defense.

/// Minimum master-password length in characters.
pub const MIN_PASSWORD_LEN: usize = 12;

/// Maximum master-password length in bytes. Only guards against
/// accidental pastes; Argon2id absorbs any input below this.
pub const MAX_PASSWORD_LEN: usize = 512;

/// NordPass 2025 global top 10, lowercased for case-insensitive match.
const BLOCKLIST: [&str; 10] = [
    "123456",
    "admin",
    "12345678",
    "123456789",
    "12345",
    "password",
    "aa123456",
    "1234567890",
    "pass@123",
    "admin123",
];

/// Reject passwords that are empty, on the blocklist, or shorter than
/// [`MIN_PASSWORD_LEN`]. The blocklist is checked before length so the
/// worst passwords get the most specific error.
pub fn check_new_password(password: &str) -> anyhow::Result<()> {
    if password.trim().is_empty() {
        anyhow::bail!("password must not be empty");
    }
    if BLOCKLIST.contains(&password.to_lowercase().as_str()) {
        anyhow::bail!("password is too common: use a generated passphrase");
    }
    if password.chars().count() < MIN_PASSWORD_LEN {
        anyhow::bail!("password must be at least {MIN_PASSWORD_LEN} characters");
    }
    if password.len() > MAX_PASSWORD_LEN {
        anyhow::bail!("password must be at most {MAX_PASSWORD_LEN} bytes");
    }
    Ok(())
}
