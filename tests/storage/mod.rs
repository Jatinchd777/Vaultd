//! Storage layer: permissions, symlink rejection, and project discovery.
//!
//! Covers `src/storage/filesystem.rs`, which had no direct tests despite
//! guarding ciphertext confidentiality (`0700`/`0600`) and symlink
//! confused-deputy attacks.

use crate::common::{Env, TIMEOUT, init_vault, spawn_pty, stderr, wait_exit};
use std::os::unix::fs::PermissionsExt;

const PASSWORD: &str = "correct horse battery staple";

fn mode(path: &std::path::Path) -> u32 {
    std::fs::metadata(path)
        .unwrap_or_else(|_| panic!("missing {}", path.display()))
        .permissions()
        .mode()
        & 0o777
}

#[test]
fn init_sets_secure_permissions() {
    let env = Env::new("storage-perms");
    init_vault(&env, PASSWORD);
    assert_eq!(
        mode(&env.project.path().join(".vaultd")),
        0o700,
        "vault dir must be owner-only even under umask 022"
    );
    assert_eq!(
        mode(&env.project.path().join(".vaultd/manifest")),
        0o600,
        "manifest must be owner-only"
    );
    assert_eq!(
        mode(&env.project.path().join(".vaultd/vault")),
        0o600,
        "vault file must be owner-only"
    );
}

#[test]
fn read_repairs_clone_permissions() {
    let env = Env::new("storage-repair");
    init_vault(&env, PASSWORD);
    // `git clone` does not preserve 0700/0600: simulate 0755/0644.
    std::fs::set_permissions(
        env.project.path().join(".vaultd"),
        std::fs::Permissions::from_mode(0o755),
    )
    .unwrap();
    for f in ["manifest", "vault"] {
        std::fs::set_permissions(
            env.project.path().join(".vaultd").join(f),
            std::fs::Permissions::from_mode(0o644),
        )
        .unwrap();
    }
    // Any read (here: a failed unlock still reads the manifest first)
    // must tighten permissions back.
    let mut session = spawn_pty(&env, &["unlock"]);
    session.pty.read_until("Master password:", TIMEOUT);
    session.pty.send("wrong password\n");
    let _ = session
        .pty
        .read_until("vault authentication failed", TIMEOUT);
    let _ = wait_exit(&mut session.child, TIMEOUT, "vaultd unlock");
    assert_eq!(mode(&env.project.path().join(".vaultd")), 0o700);
    assert_eq!(
        mode(&env.project.path().join(".vaultd/manifest")),
        0o600
    );
    assert_eq!(mode(&env.project.path().join(".vaultd/vault")), 0o600);
}

#[test]
fn symlink_manifest_is_rejected() {
    let env = Env::new("storage-symlink-manifest");
    init_vault(&env, PASSWORD);
    let manifest = env.project.path().join(".vaultd/manifest");
    let target = env.project.path().join("real-target");
    std::fs::write(&target, "sensitive-target-content").unwrap();
    std::fs::remove_file(&manifest).unwrap();
    std::os::unix::fs::symlink(&target, &manifest).unwrap();

    let mut session = spawn_pty(&env, &["unlock"]);
    session.pty.read_until("Master password:", TIMEOUT);
    session.pty.send(&format!("{PASSWORD}\n"));
    let transcript = session.pty.read_until("symlink", TIMEOUT);
    assert!(
        transcript.to_lowercase().contains("symlink"),
        "expected symlink rejection, saw: {transcript}"
    );
    let status = wait_exit(&mut session.child, TIMEOUT, "vaultd unlock");
    assert!(!status.success());
    // Link target must not have been overwritten with ciphertext.
    assert_eq!(
        std::fs::read_to_string(&target).unwrap(),
        "sensitive-target-content"
    );
}

#[test]
fn symlink_vault_is_rejected() {
    let env = Env::new("storage-symlink-vault");
    init_vault(&env, PASSWORD);
    let vault = env.project.path().join(".vaultd/vault");
    let target = env.project.path().join("vault-target");
    std::fs::write(&target, "do-not-overwrite").unwrap();
    std::fs::remove_file(&vault).unwrap();
    std::os::unix::fs::symlink(&target, &vault).unwrap();

    let mut session = spawn_pty(&env, &["unlock"]);
    session.pty.read_until("Master password:", TIMEOUT);
    session.pty.send(&format!("{PASSWORD}\n"));
    let transcript = session.pty.read_until("symlink", TIMEOUT);
    assert!(
        transcript.to_lowercase().contains("symlink"),
        "expected symlink rejection, saw: {transcript}"
    );
    let status = wait_exit(&mut session.child, TIMEOUT, "vaultd unlock");
    assert!(!status.success());
    assert_eq!(
        std::fs::read_to_string(&target).unwrap(),
        "do-not-overwrite"
    );
}

#[test]
fn symlinked_vault_dir_is_skipped_in_search() {
    use vaultd::storage::filesystem::find_project_root_from;
    let outer = crate::common::TempDir::new("storage-search-outer");
    let inner = outer.path().join("inner");
    std::fs::create_dir_all(&inner).unwrap();
    // Real vault lives at `outer`.
    std::fs::create_dir_all(outer.path().join(".vaultd")).unwrap();
    // Planted symlink in child must not hijack resolution.
    let evil = crate::common::TempDir::new("storage-search-evil");
    std::os::unix::fs::symlink(evil.path(), inner.join(".vaultd")).unwrap();

    let found = find_project_root_from(&inner).expect("should find outer root");
    let canon_outer = std::fs::canonicalize(outer.path()).unwrap();
    assert_eq!(found, canon_outer);
    // A file path inside the project also resolves.
    let file = inner.join("somefile.txt");
    std::fs::write(&file, "x").unwrap();
    assert_eq!(find_project_root_from(&file).unwrap(), canon_outer);
}

#[test]
fn second_init_in_subdir_refuses() {
    let env = Env::new("storage-subdir-init");
    init_vault(&env, PASSWORD);
    let sub = env.project.path().join("nested/dir");
    std::fs::create_dir_all(&sub).unwrap();
    // Run `init` with cwd in the subdirectory: upward search must find the
    // parent vault and refuse, not create a nested one.
    let mut cmd = std::process::Command::new(crate::common::binary());
    cmd.args(["init"])
        .current_dir(&sub)
        .env("XDG_RUNTIME_DIR", env.runtime.path())
        .env("HOME", env.home.path())
        .env("TERM", "dumb")
        .env_remove("VAULTD_SOCKET")
        .env_remove("VAULTD_TOKEN")
        .stdin(std::process::Stdio::piped())
        .stdout(std::process::Stdio::piped())
        .stderr(std::process::Stdio::piped());
    unsafe {
        use std::os::unix::process::CommandExt;
        cmd.pre_exec(|| {
            libc::setsid();
            Ok(())
        });
    }
    let child = cmd.spawn().expect("spawn vaultd");
    let out = {
        use std::io::Read;
        let mut child = child;
        drop(child.stdin.take());
        let start = std::time::Instant::now();
        loop {
            match child.try_wait().expect("try_wait") {
                Some(status) => {
                    let mut so = Vec::new();
                    let mut se = Vec::new();
                    if let Some(mut o) = child.stdout.take() {
                        o.read_to_end(&mut so).unwrap();
                    }
                    if let Some(mut e) = child.stderr.take() {
                        e.read_to_end(&mut se).unwrap();
                    }
                    break std::process::Output {
                        status,
                        stdout: so,
                        stderr: se,
                    };
                }
                None => {
                    assert!(
                        start.elapsed() < TIMEOUT,
                        "timed out waiting for vaultd init"
                    );
                    std::thread::sleep(std::time::Duration::from_millis(50));
                }
            }
        }
    };
    assert!(!out.status.success());
    assert!(
        stderr(&out).contains("already exists"),
        "unexpected stderr: {}",
        stderr(&out)
    );
    assert!(!sub.join(".vaultd").exists());
}
