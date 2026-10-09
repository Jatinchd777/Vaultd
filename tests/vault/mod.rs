use crate::common::{
    Env, TIMEOUT, TempDir, have_zsh, init_vault, init_vault_in, run_in, socket_for, spawn_pty,
    spawn_pty_in, stderr, stdout, wait_exit, wait_for_gone_path, wait_for_path,
};
use std::time::Duration;

const PASSWORD: &str = "correct horse battery staple";

#[test]
fn unlock_without_vault_fails() {
    let env = Env::new("vault-novault");
    // Fails fast before prompting: no project, so no socket to check.
    let out = env.run(&["unlock"], "");
    assert!(!out.status.success());
    assert!(
        stderr(&out).contains("no vault found"),
        "unexpected stderr: {}",
        stderr(&out)
    );
    assert!(!env.socket().exists());
}

#[test]
fn unlock_wrong_password_fails() {
    let env = Env::new("vault-wrongpw");
    init_vault(&env, PASSWORD);
    let mut session = spawn_pty(&env, &["unlock"]);
    session.pty.read_until("Master password:", TIMEOUT);
    session.pty.send("wrong password\n");
    let transcript = session
        .pty
        .read_until("vault authentication failed", TIMEOUT);
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
    let status = wait_exit(&mut session.child, TIMEOUT, "vaultd unlock");
    assert!(!status.success());
    assert!(!env.socket().exists());
}

#[test]
fn unlock_corrupt_vault_fails() {
    let env = Env::new("vault-corrupt-vault");
    init_vault(&env, PASSWORD);
    let vault_path = env.project.path().join(".vaultd/vault");
    let mut bytes = std::fs::read(&vault_path).unwrap();
    assert!(bytes.len() > 13);
    bytes[13] ^= 0x01;
    std::fs::write(&vault_path, &bytes).unwrap();
    let mut session = spawn_pty(&env, &["unlock"]);
    session.pty.read_until("Master password:", TIMEOUT);
    session.pty.send(&format!("{PASSWORD}\n"));
    let transcript = session
        .pty
        .read_until("vault authentication failed", TIMEOUT);
    assert!(transcript.contains("vault authentication failed"));
    let status = wait_exit(&mut session.child, TIMEOUT, "vaultd unlock");
    assert!(!status.success());
    assert!(!env.socket().exists());
}

#[test]
fn unlock_invalid_salt_fails() {
    let env = Env::new("vault-badsalt");
    init_vault(&env, PASSWORD);
    let manifest_path = env.project.path().join(".vaultd/manifest");
    let mut m: serde_json::Value =
        serde_json::from_slice(&std::fs::read(&manifest_path).unwrap()).unwrap();
    // Truncated salt decodes but has the wrong length.
    m["kdf"]["salt"] = serde_json::Value::String("AAAA".to_string());
    std::fs::write(&manifest_path, serde_json::to_vec(&m).unwrap()).unwrap();
    let mut session = spawn_pty(&env, &["unlock"]);
    session.pty.read_until("Master password:", TIMEOUT);
    session.pty.send(&format!("{PASSWORD}\n"));
    let status = wait_exit(&mut session.child, TIMEOUT, "vaultd unlock");
    assert!(!status.success());
    assert!(!env.socket().exists());
}

#[test]
fn unlock_missing_vault_file_fails() {
    let env = Env::new("vault-missing-file");
    init_vault(&env, PASSWORD);
    std::fs::remove_file(env.project.path().join(".vaultd/vault")).unwrap();
    let mut session = spawn_pty(&env, &["unlock"]);
    session.pty.read_until("Master password:", TIMEOUT);
    session.pty.send(&format!("{PASSWORD}\n"));
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

    let mut shell = spawn_pty(&env, &["unlock"]);
    shell.pty.read_until("Master password:", TIMEOUT);
    shell.pty.send(&format!("{PASSWORD}\n"));
    let banner = shell.pty.read_until("Vault unlocked", TIMEOUT);
    assert!(banner.contains("Vault unlocked"));

    env.wait_for_socket(Duration::from_secs(30));

    let out = env.run(&["add", "API_KEY", "secret-1"], "");
    assert!(out.status.success(), "add failed: {}", stderr(&out));
    assert!(stdout(&out).contains("Credential added: API_KEY"));

    let mut add = spawn_pty(&env, &["add", "PROMPTED"]);
    add.pty.read_until("Credential value:", TIMEOUT);
    add.pty.send("prompted-value\n");
    let transcript = add.pty.read_until("Credential added", TIMEOUT);
    assert!(transcript.contains("Credential added: PROMPTED"));
    assert!(wait_exit(&mut add.child, TIMEOUT, "vaultd add").success());

    let out = env.run(&["add", "API_KEY", "other"], "");
    assert!(!out.status.success());
    assert!(stderr(&out).contains("already exists"));

    let out = env.run(&["get", "API_KEY"], "");
    assert!(out.status.success(), "get failed: {}", stderr(&out));
    assert_eq!(stdout(&out).trim_end(), "secret-1");

    let out = env.run(&["get", "NOPE"], "");
    assert!(!out.status.success());
    assert!(stderr(&out).contains("not found"));

    // Set updates in place.
    let out = env.run(&["set", "API_KEY", "secret-2"], "");
    assert!(out.status.success(), "set failed: {}", stderr(&out));
    assert!(stdout(&out).contains("Credential updated: API_KEY"));
    let out = env.run(&["get", "API_KEY"], "");
    assert_eq!(stdout(&out).trim_end(), "secret-2");

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

    let out = env.run(&["lock"], "");
    assert!(out.status.success(), "lock failed: {}", stderr(&out));
    assert!(stdout(&out).contains("Vault locked"));
    env.wait_for_gone(&env.socket(), Duration::from_secs(10));

    let out = env.run(&["get", "API_KEY"], "");
    assert!(!out.status.success());
    assert!(stderr(&out).contains("vaultd daemon is not running"));

    shell.pty.send("exit\n");
    let status = wait_exit(&mut shell.child, Duration::from_secs(30), "vaultd unlock");
    assert!(status.success(), "unlock exited with {status}");
}

#[test]
fn projects_are_isolated_with_shared_runtime() {
    if !have_zsh() {
        eprintln!("skipping: zsh is required for the vault shell");
        return;
    }

    let runtime = TempDir::new("iso-shared-rt");
    let home = TempDir::new("iso-shared-home");
    std::fs::write(home.path().join(".zshrc"), "").expect("write .zshrc");
    let proj_a = TempDir::new("iso-proj-a");
    let proj_b = TempDir::new("iso-proj-b");

    init_vault_in(proj_a.path(), runtime.path(), home.path(), PASSWORD);
    init_vault_in(proj_b.path(), runtime.path(), home.path(), PASSWORD);

    let sock_a = socket_for(proj_a.path(), runtime.path());
    let sock_b = socket_for(proj_b.path(), runtime.path());
    assert_ne!(
        sock_a, sock_b,
        "different projects must hash to different sockets"
    );

    // Subdirectory resolves to the same project socket (upward search).
    let sub_a = proj_a.path().join("nested/dir");
    std::fs::create_dir_all(&sub_a).unwrap();
    assert_eq!(socket_for(&sub_a, runtime.path()), sock_a);

    let mut shell_a = spawn_pty_in(proj_a.path(), runtime.path(), home.path(), &["unlock"]);
    shell_a.pty.read_until("Master password:", TIMEOUT);
    shell_a.pty.send(&format!("{PASSWORD}\n"));
    shell_a.pty.read_until("Vault unlocked", TIMEOUT);
    wait_for_path(&sock_a, Duration::from_secs(30));

    let mut shell_b = spawn_pty_in(proj_b.path(), runtime.path(), home.path(), &["unlock"]);
    shell_b.pty.read_until("Master password:", TIMEOUT);
    shell_b.pty.send(&format!("{PASSWORD}\n"));
    shell_b.pty.read_until("Vault unlocked", TIMEOUT);
    wait_for_path(&sock_b, Duration::from_secs(30));

    // Distinct daemons are both live.
    assert!(sock_a.exists() && sock_b.exists());

    let out = run_in(
        proj_a.path(),
        runtime.path(),
        home.path(),
        &["add", "ONLY_A", "aaa"],
    );
    assert!(out.status.success(), "add A failed: {}", stderr(&out));
    let out = run_in(
        proj_b.path(),
        runtime.path(),
        home.path(),
        &["add", "ONLY_B", "bbb"],
    );
    assert!(out.status.success(), "add B failed: {}", stderr(&out));

    // A cannot see B and vice versa: no cross-daemon reads.
    let out = run_in(
        proj_a.path(),
        runtime.path(),
        home.path(),
        &["get", "ONLY_A"],
    );
    assert!(out.status.success());
    assert_eq!(stdout(&out).trim_end(), "aaa");
    let out = run_in(
        proj_a.path(),
        runtime.path(),
        home.path(),
        &["get", "ONLY_B"],
    );
    assert!(!out.status.success());
    assert!(stderr(&out).contains("not found"));

    let out = run_in(
        proj_b.path(),
        runtime.path(),
        home.path(),
        &["get", "ONLY_B"],
    );
    assert!(out.status.success());
    assert_eq!(stdout(&out).trim_end(), "bbb");
    let out = run_in(
        proj_b.path(),
        runtime.path(),
        home.path(),
        &["get", "ONLY_A"],
    );
    assert!(!out.status.success());
    assert!(stderr(&out).contains("not found"));

    // Subdir command still hits project A's daemon.
    let out = run_in(&sub_a, runtime.path(), home.path(), &["get", "ONLY_A"]);
    assert!(out.status.success(), "subdir get failed: {}", stderr(&out));
    assert_eq!(stdout(&out).trim_end(), "aaa");

    // Locking A must not disturb B.
    let out = run_in(proj_a.path(), runtime.path(), home.path(), &["lock"]);
    assert!(out.status.success(), "lock A failed: {}", stderr(&out));
    wait_for_gone_path(&sock_a, Duration::from_secs(10));
    assert!(sock_b.exists(), "locking A removed B's socket");

    let out = run_in(
        proj_b.path(),
        runtime.path(),
        home.path(),
        &["get", "ONLY_B"],
    );
    assert!(
        out.status.success(),
        "B broke after A locked: {}",
        stderr(&out)
    );
    assert_eq!(stdout(&out).trim_end(), "bbb");

    let out = run_in(
        proj_a.path(),
        runtime.path(),
        home.path(),
        &["get", "ONLY_A"],
    );
    assert!(!out.status.success());
    assert!(stderr(&out).contains("vaultd daemon is not running"));

    // Cleanup: lock B, then both shells exit cleanly.
    let out = run_in(proj_b.path(), runtime.path(), home.path(), &["lock"]);
    assert!(out.status.success());
    wait_for_gone_path(&sock_b, Duration::from_secs(10));

    shell_a.pty.send("exit\n");
    shell_b.pty.send("exit\n");
    let _ = wait_exit(
        &mut shell_a.child,
        Duration::from_secs(30),
        "unlock A shell",
    );
    let _ = wait_exit(
        &mut shell_b.child,
        Duration::from_secs(30),
        "unlock B shell",
    );
}

#[test]
fn session_persistence_and_empty_list() {
    if !have_zsh() {
        eprintln!("skipping: zsh is required for the vault shell");
        return;
    }
    let env = Env::new("vault-persist");
    init_vault(&env, PASSWORD);

    let mut shell = spawn_pty(&env, &["unlock"]);
    shell.pty.read_until("Master password:", TIMEOUT);
    shell.pty.send(&format!("{PASSWORD}\n"));
    shell.pty.read_until("Vault unlocked", TIMEOUT);
    env.wait_for_socket(Duration::from_secs(30));

    // Fresh vault lists as empty.
    let out = env.run(&["list"], "");
    assert!(out.status.success());
    assert!(
        stdout(&out).contains("No credentials"),
        "unexpected list output: {}",
        stdout(&out)
    );

    // `set` without an inline value prompts, like `add` does.
    let out = env.run(&["add", "PERSIST", "v1"], "");
    assert!(out.status.success(), "add failed: {}", stderr(&out));
    let mut set = spawn_pty(&env, &["set", "PERSIST"]);
    set.pty.read_until("Credential value:", TIMEOUT);
    set.pty.send("v2\n");
    let transcript = set.pty.read_until("Credential updated", TIMEOUT);
    assert!(transcript.contains("Credential updated: PERSIST"));
    assert!(wait_exit(&mut set.child, TIMEOUT, "vaultd set").success());
    assert_eq!(stdout(&env.run(&["get", "PERSIST"], "")).trim_end(), "v2");

    // Lock, unlock again with the same password: secrets persist.
    assert!(env.run(&["lock"], "").status.success());
    env.wait_for_gone(&env.socket(), Duration::from_secs(10));
    shell.pty.send("exit\n");
    let _ = wait_exit(&mut shell.child, Duration::from_secs(30), "vaultd unlock");

    let mut shell2 = spawn_pty(&env, &["unlock"]);
    shell2.pty.read_until("Master password:", TIMEOUT);
    shell2.pty.send(&format!("{PASSWORD}\n"));
    shell2.pty.read_until("Vault unlocked", TIMEOUT);
    env.wait_for_socket(Duration::from_secs(30));
    assert_eq!(stdout(&env.run(&["get", "PERSIST"], "")).trim_end(), "v2");

    // Second lock succeeds; a further lock with no daemon fails.
    assert!(env.run(&["lock"], "").status.success());
    env.wait_for_gone(&env.socket(), Duration::from_secs(10));
    let out = env.run(&["lock"], "");
    assert!(!out.status.success());
    assert!(
        stderr(&out).contains("vaultd daemon is not running"),
        "unexpected stderr: {}",
        stderr(&out)
    );
    shell2.pty.send("exit\n");
    let _ = wait_exit(&mut shell2.child, Duration::from_secs(30), "vaultd unlock");
}

#[test]
fn env_export_format_and_escaping() {
    if !have_zsh() {
        eprintln!("skipping: zsh is required for the vault shell");
        return;
    }
    let env = Env::new("vault-env-fmt");
    init_vault(&env, PASSWORD);
    let mut shell = spawn_pty(&env, &["unlock"]);
    shell.pty.read_until("Master password:", TIMEOUT);
    shell.pty.send(&format!("{PASSWORD}\n"));
    shell.pty.read_until("Vault unlocked", TIMEOUT);
    env.wait_for_socket(Duration::from_secs(30));

    assert!(env.run(&["add", "PLAIN", "secret-1"], "").status.success());
    assert!(
        env.run(&["add", "TRICKY", "a'b \"c\" $d"], "")
            .status
            .success()
    );

    let out = env.run(&["__env"], "");
    assert!(out.status.success(), "__env failed: {}", stderr(&out));
    let text = stdout(&out);
    assert!(text.contains("export VAULTD_SOCKET="), "missing socket:\n{text}");
    assert!(text.contains("export VAULTD_TOKEN="), "missing token:\n{text}");
    assert!(text.contains("export PLAIN='secret-1'"), "missing plain:\n{text}");
    // Single quotes in values must be shell-escaped as '\''.
    assert!(
        text.contains("export TRICKY='a'\\''b \"c\" $d'"),
        "bad escaping:\n{text}"
    );
    assert!(text.contains("_VAULTD_EXPORTED="), "missing export list:\n{text}");
    assert!(text.contains("vaultd-clear()"), "missing clear fn:\n{text}");
    // Token is 64 hex chars.
    let token_line = text
        .lines()
        .find(|l| l.starts_with("export VAULTD_TOKEN="))
        .expect("token line");
    let token_val = token_line
        .split('=')
        .nth(1)
        .unwrap()
        .trim_matches('\'');
    assert_eq!(token_val.len(), 64);
    assert!(token_val.chars().all(|c| c.is_ascii_hexdigit()));

    let _ = env.run(&["lock"], "");
    env.wait_for_gone(&env.socket(), Duration::from_secs(10));
    shell.pty.send("exit\n");
    let _ = wait_exit(&mut shell.child, Duration::from_secs(30), "vaultd unlock");
}

#[test]
fn env_rejects_invalid_name() {
    if !have_zsh() {
        eprintln!("skipping: zsh is required for the vault shell");
        return;
    }
    let env = Env::new("vault-env-badname");
    init_vault(&env, PASSWORD);
    let mut shell = spawn_pty(&env, &["unlock"]);
    shell.pty.read_until("Master password:", TIMEOUT);
    shell.pty.send(&format!("{PASSWORD}\n"));
    shell.pty.read_until("Vault unlocked", TIMEOUT);
    env.wait_for_socket(Duration::from_secs(30));

    // `add` currently accepts any string; `__env` must refuse to emit it
    // as shell code.
    assert!(env.run(&["add", "BAD-NAME", "x"], "").status.success());
    let out = env.run(&["__env"], "");
    assert!(!out.status.success());
    assert!(
        stderr(&out).contains("invalid environment variable name"),
        "unexpected stderr: {}",
        stderr(&out)
    );

    let _ = env.run(&["lock"], "");
    env.wait_for_gone(&env.socket(), Duration::from_secs(10));
    shell.pty.send("exit\n");
    let _ = wait_exit(&mut shell.child, Duration::from_secs(30), "vaultd unlock");
}
