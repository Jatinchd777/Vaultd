//! Crypto properties, observed through `init` artifacts: the manifest
//! shape, the opacity of the vault file, fresh randomness per vault, and
//! init-time failure modes.

use crate::common::{Env, TIMEOUT, init_vault, spawn_pty, wait_exit};
use base64::Engine;

const PASSWORD: &str = "correct horse battery staple";

fn manifest(env: &Env) -> serde_json::Value {
    let bytes =
        std::fs::read(env.project.path().join(".vaultd/manifest")).expect("manifest should exist");
    serde_json::from_slice(&bytes).expect("manifest should be JSON")
}

fn vault_bytes(env: &Env) -> Vec<u8> {
    std::fs::read(env.project.path().join(".vaultd/vault")).expect("vault should exist")
}

#[test]
fn init_creates_expected_layout() {
    let env = Env::new("crypto-layout");
    init_vault(&env, PASSWORD);
    assert!(env.project.path().join(".vaultd/manifest").is_file());
    assert!(env.project.path().join(".vaultd/vault").is_file());
}

#[test]
fn manifest_has_expected_shape() {
    let env = Env::new("crypto-manifest");
    init_vault(&env, PASSWORD);
    let m = manifest(&env);
    assert_eq!(m["version"], 1);
    assert_eq!(m["cipher"], "AES-256-GCM");
    assert_eq!(m["kdf"]["algorithm"], "Argon2id");
    let salt = m["kdf"]["salt"].as_str().expect("salt should be a string");
    let raw = base64::engine::general_purpose::STANDARD
        .decode(salt)
        .expect("salt should be valid base64");
    assert_eq!(raw.len(), 16, "salt should be 128 bits");
    for key in ["memory_cost", "time_cost", "parallelism"] {
        assert!(
            m["kdf"][key].as_u64().unwrap_or(0) > 0,
            "{key} should be positive"
        );
    }
}

#[test]
fn vault_file_is_opaque() {
    let env = Env::new("crypto-opaque");
    init_vault(&env, PASSWORD);
    let bytes = vault_bytes(&env);
    // 12-byte nonce plus at least the 16-byte auth tag.
    assert!(bytes.len() >= 12 + 16);
    // Not the plaintext credential list.
    assert!(serde_json::from_slice::<serde_json::Value>(&bytes).is_err());
    assert_ne!(bytes, b"[]".to_vec());
}

#[test]
fn same_password_still_gives_fresh_vaults() {
    let a = Env::new("crypto-fresh-a");
    let b = Env::new("crypto-fresh-b");
    init_vault(&a, PASSWORD);
    init_vault(&b, PASSWORD);
    // Random salt and nonce per vault, even for identical passwords.
    assert_ne!(manifest(&a)["kdf"]["salt"], manifest(&b)["kdf"]["salt"]);
    assert_ne!(vault_bytes(&a), vault_bytes(&b));
}

#[test]
fn mismatched_passwords_abort_init() {
    let env = Env::new("crypto-mismatch");
    let mut session = spawn_pty(&env, &["init"]);
    session.pty.read_until("Create master password:", TIMEOUT);
    session.pty.send("one\n");
    session.pty.read_until("Confirm master password:", TIMEOUT);
    session.pty.send("two\n");
    let transcript = session.pty.read_until("passwords do not match", TIMEOUT);
    assert!(transcript.contains("passwords do not match"));
    let status = wait_exit(&mut session.child, TIMEOUT, "vaultd init");
    assert!(!status.success());
    // Nothing usable was left behind: the directory exists but both files
    // are only written after the passwords match.
    assert!(!env.project.path().join(".vaultd/manifest").exists());
    assert!(!env.project.path().join(".vaultd/vault").exists());
}

#[test]
fn second_init_refuses_to_overwrite() {
    let env = Env::new("crypto-double");
    init_vault(&env, PASSWORD);
    let before = vault_bytes(&env);
    let mut session = spawn_pty(&env, &["init"]);
    session.pty.read_until("already exists", TIMEOUT);
    let status = wait_exit(&mut session.child, TIMEOUT, "vaultd init");
    assert!(!status.success());
    // The existing vault is untouched.
    assert_eq!(vault_bytes(&env), before);
}

// --- Direct unit tests for `src/crypto` (no vault on disk) ---

#[test]
fn cipher_roundtrip() {
    use vaultd::crypto::cipher;
    let key = [0x42u8; 32];
    for plaintext in [b"".as_slice(), b"[]", b"{\"a\":1}", &[0u8; 1024]] {
        let encrypted = cipher::encrypt(&key, plaintext).expect("encrypt");
        // 12-byte nonce + plaintext + 16-byte GCM tag.
        assert_eq!(encrypted.len(), 12 + plaintext.len() + 16);
        assert_eq!(cipher::decrypt(&key, &encrypted).unwrap(), plaintext);
    }
}

#[test]
fn cipher_nonce_is_fresh() {
    use vaultd::crypto::cipher;
    let key = [0x11u8; 32];
    let a = cipher::encrypt(&key, b"same").unwrap();
    let b = cipher::encrypt(&key, b"same").unwrap();
    assert_ne!(a, b, "each encryption must use a fresh random nonce");
    // Nonces themselves differ.
    assert_ne!(&a[..12], &b[..12]);
}

#[test]
fn cipher_tamper_is_detected() {
    use vaultd::crypto::cipher;
    let key = [0x77u8; 32];
    let mut encrypted = cipher::encrypt(&key, b"secret").unwrap();
    let last = encrypted.len() - 1;
    encrypted[last] ^= 0x01;
    let err = cipher::decrypt(&key, &encrypted).unwrap_err();
    assert!(
        err.to_string().contains("authentication failed"),
        "unexpected error: {err}"
    );
}

#[test]
fn cipher_wrong_key_fails() {
    use vaultd::crypto::cipher;
    let encrypted = cipher::encrypt(&[1u8; 32], b"data").unwrap();
    let err = cipher::decrypt(&[2u8; 32], &encrypted).unwrap_err();
    assert!(
        err.to_string().contains("authentication failed"),
        "unexpected error: {err}"
    );
}

#[test]
fn cipher_short_input_fails() {
    use vaultd::crypto::cipher;
    let err = cipher::decrypt(&[0u8; 32], &[0u8; 11]).unwrap_err();
    assert!(
        err.to_string().contains("too short"),
        "unexpected error: {err}"
    );
}

#[test]
fn kdf_generate_gives_fresh_salt_and_defaults() {
    use vaultd::crypto::kdf::KdfParams;
    let a = KdfParams::generate().unwrap();
    let b = KdfParams::generate().unwrap();
    assert_ne!(a.salt, b.salt, "salts must be random");
    for p in [&a, &b] {
        assert_eq!(p.memory_cost, 19_456);
        assert_eq!(p.time_cost, 2);
        assert_eq!(p.parallelism, 1);
    }
}

#[test]
fn kdf_is_deterministic_for_same_inputs() {
    use vaultd::crypto::kdf::{self, KdfParams};
    let params = KdfParams {
        salt: [9u8; 16],
        memory_cost: 19_456,
        time_cost: 2,
        parallelism: 1,
    };
    let k1 = kdf::derive_key(b"password", &params).unwrap();
    let k2 = kdf::derive_key(b"password", &params).unwrap();
    assert_eq!(k1, k2);
    assert_eq!(k1.len(), 32);
    // Different password and different salt change the key.
    assert_ne!(k1, kdf::derive_key(b"other", &params).unwrap());
    let other_salt = params_with_salt([10u8; 16]);
    assert_ne!(k1, kdf::derive_key(b"password", &other_salt).unwrap());
}

fn params_with_salt(salt: [u8; 16]) -> vaultd::crypto::kdf::KdfParams {
    vaultd::crypto::kdf::KdfParams {
        salt,
        memory_cost: 19_456,
        time_cost: 2,
        parallelism: 1,
    }
}
