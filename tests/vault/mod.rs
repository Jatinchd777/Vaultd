//! Vault lifecycle: unlock failure modes plus one full daemon session
//! (add/get/set/list/remove/lock, then the shell exiting).
//!
//! Unlocking and password prompts need a tty, so these run under the pty
//! helper. The session test additionally needs `zsh` for the vault shell
//! and is skipped without it.

use crate::common::{
    have_zsh, init_vault, spawn_pty, stderr, stdout, wait_exit, Env, TIMEOUT,
};
use std::time::Duration;

const PASSWORD: &str = "correct horse battery staple";

#[test]
fn unlock_without_vault_fails() {
    let env = Env::new("vault-novault");
    let mut session = spawn_pty(&env, &["unlock"]);
    session.pty.read_until("Master password:", TIMEOUT);
    session.pty.send(&format!("{PASSWORD}\n"));
    let transcript = session.pty.read_until("No such file", TIMEOUT);
    assert!(transcript.contains("No such file"));
    let status = wait_exit(&mut session.child, TIMEOUT, "vaultd unlock");
    assert!(!status.success());
    assert!(!env.socket().exists());
}

#[test]
fn unlock_wrong_password_fails() {
    let env = Env::new("vault-wrongpw");
    init_vault(&env, PASSWORD);
    let mut session = spawn_pty(&env, &["unlock"]);
    session.pty.read_until("Master password:", TIMEOUT);
    session.pty.send("wrong password\n");
    let transcript = session.pty.read_until("vault authentication failed", TIMEOUT);
    assert!(transcript.contains("vault authentication failed"));
    let status = wait_exit(&mut session.child, TIMEOUT, "vaultd unlock");
    assert!(!status.success());
    assert!(!env.socket().exists());
}

#[test]
fn unlock_corrupt_manifest_fails() {
    let env = Env::new("vault-corrupt");
    init_vault(&env, PASSWORD);
    std::fs::write(env.project.path().join(".vaultd/manifest"), "not json").unwrap();
    let mut session = spawn_pty(&env, &["unlock"]);
    session.pty.read_until("Master password:", TIMEOUT);
    session.pty.send(&format!("{PASSWORD}\n"));
    // Serde error text varies; what matters is no daemon comes up.
    let status = wait_exit(&mut session.child, TIMEOUT, "vaultd unlock");
    assert!(!status.success());
    assert!(!env.socket().exists());
}

#[test]
fn full_session_roundtrip() {
    if !have_zsh() {
        eprintln!("skipping: zsh is required for the vault shell");
        return;
    }
    let env = Env::new("vault-roundtrip");
    init_vault(&env, PASSWORD);

    // Unlock holds the session: the pty stays open so the vault shell
    // stays up for the client commands below.
    let mut shell = spawn_pty(&env, &["unlock"]);
    shell.pty.read_until("Master password:", TIMEOUT);
    shell.pty.send(&format!("{PASSWORD}\n"));
    let banner = shell.pty.read_until("Vault unlocked", TIMEOUT);
    assert!(banner.contains("Vault unlocked"));

    env.wait_for_socket(Duration::from_secs(30));

    // Add, then read back through the daemon.
    let out = env.run(&["add", "API_KEY", "secret-1"], "");
    assert!(out.status.success(), "add failed: {}", stderr(&out));
    assert!(stdout(&out).contains("Credential added: API_KEY"));

    // Prompted values (no inline arg) go through /dev/tty as well.
    let mut add = spawn_pty(&env, &["add", "PROMPTED"]);
    add.pty.read_until("Credential value:", TIMEOUT);
    add.pty.send("prompted-value\n");
    let transcript = add.pty.read_until("Credential added", TIMEOUT);
    assert!(transcript.contains("Credential added: PROMPTED"));
    assert!(wait_exit(&mut add.child, TIMEOUT, "vaultd add").success());

    // Adding the same name twice is an error.
    let out = env.run(&["add", "API_KEY", "other"], "");
    assert!(!out.status.success());
    assert!(stderr(&out).contains("already exists"));

    // Get returns exactly the stored value.
    let out = env.run(&["get", "API_KEY"], "");
    assert!(out.status.success(), "get failed: {}", stderr(&out));
    assert_eq!(stdout(&out).trim_end(), "secret-1");

    // Unknown names fail.
    let out = env.run(&["get", "NOPE"], "");
    assert!(!out.status.success());
    assert!(stderr(&out).contains("not found"));

    // Set updates in place.
    let out = env.run(&["set", "API_KEY", "secret-2"], "");
    assert!(out.status.success(), "set failed: {}", stderr(&out));
    assert!(stdout(&out).contains("Credential updated: API_KEY"));
    let out = env.run(&["get", "API_KEY"], "");
    assert_eq!(stdout(&out).trim_end(), "secret-2");

    // Setting a name that was never added fails.
    let out = env.run(&["set", "NOPE", "x"], "");
    assert!(!out.status.success());
    assert!(stderr(&out).contains("not found"));

    // List shows names but never values.
    let out = env.run(&["list"], "");
    assert!(out.status.success(), "list failed: {}", stderr(&out));
    let text = stdout(&out);
    assert!(text.contains("API_KEY") && text.contains("PROMPTED"));
    assert!(!text.contains("secret-2"));

    // Remove deletes; removing twice fails.
    let out = env.run(&["remove", "PROMPTED"], "");
    assert!(out.status.success(), "remove failed: {}", stderr(&out));
    assert!(stdout(&out).contains("Credential removed: PROMPTED"));
    let out = env.run(&["remove", "PROMPTED"], "");
    assert!(!out.status.success());
    assert!(stderr(&out).contains("not found"));

    // Explicit lock shuts the daemon down and unlinks the socket.
    let out = env.run(&["lock"], "");
    assert!(out.status.success(), "lock failed: {}", stderr(&out));
    assert!(stdout(&out).contains("Vault locked"));
    env.wait_for_gone(&env.socket(), Duration::from_secs(10));

    // With the daemon gone, clients fail again.
    let out = env.run(&["get", "API_KEY"], "");
    assert!(!out.status.success());
    assert!(stderr(&out).contains("vaultd daemon is not running"));

    // Exiting the shell ends the unlock session cleanly.
    shell.pty.send("exit\n");
    let status = wait_exit(&mut shell.child, Duration::from_secs(30), "vaultd unlock");
    assert!(status.success(), "unlock exited with {status}");
}
