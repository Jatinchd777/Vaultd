//! Daemon layer: token codec, path derivation, and socket auth.
//!
//! Covers pure helpers in `src/daemon/server.rs` plus black-box socket
//! validation (`$VAULTD_SOCKET` confinement, symlink-socket refusal,
//! double-unlock, wrong-token rejection) in `src/daemon/server.rs` and
//! `src/daemon/client.rs`, none of which had tests.

use crate::common::{Env, TIMEOUT, have_zsh, init_vault, spawn_pty, stderr, stdout, wait_exit};
use std::time::Duration;
use vaultd::daemon::server;

const PASSWORD: &str = "correct horse battery staple";

// --- Pure unit tests (no daemon, no pty) ---

#[test]
fn token_hex_roundtrip() {
    let token = server::generate_session_token().expect("token");
    let hex = server::encode_token_hex(&token);
    assert_eq!(hex.len(), 64);
    assert!(hex.chars().all(|c| c.is_ascii_hexdigit()));
    assert_eq!(server::decode_token_hex(&hex).unwrap(), token);
}

#[test]
fn token_hex_is_unique_per_generation() {
    let a = server::generate_session_token().unwrap();
    let b = server::generate_session_token().unwrap();
    assert_ne!(a, b, "session tokens must be random");
}

#[test]
fn token_hex_rejects_bad_input() {
    assert!(server::decode_token_hex(&"00".repeat(31)).is_err());
    assert!(server::decode_token_hex(&"00".repeat(33)).is_err());
    assert!(server::decode_token_hex(&"zz".repeat(32)).is_err());
    assert!(server::decode_token_hex("").is_err());
}

#[test]
fn token_hex_trims_surrounding_whitespace() {
    let token = server::generate_session_token().unwrap();
    let hex = server::encode_token_hex(&token);
    assert_eq!(
        server::decode_token_hex(&format!("  {hex}\n")).unwrap(),
        token
    );
}

#[test]
fn token_hex_accepts_uppercase() {
    let token = server::generate_session_token().unwrap();
    let hex = server::encode_token_hex(&token).to_uppercase();
    assert_eq!(server::decode_token_hex(&hex).unwrap(), token);
}

#[test]
fn project_hash_is_deterministic_and_sensitive() {
    let a = std::path::Path::new("/tmp/proj-a");
    let b = std::path::Path::new("/tmp/proj-b");
    assert_eq!(server::project_hash(a), server::project_hash(a));
    assert_ne!(server::project_hash(a), server::project_hash(b));
    assert_eq!(server::project_hash(a).len(), 32);
    assert!(
        server::project_hash(a).chars().all(|c| c.is_ascii_hexdigit()),
        "hash must be hex"
    );
}

#[test]
fn socket_and_token_paths_derive() {
    let root = std::path::Path::new("/tmp/some-project");
    let base = std::path::Path::new("/run/user/1000/vaultd");
    let sock = server::socket_path_for_project(root, base);
    let tok = server::token_path_for_project(root, base);
    assert!(sock.to_string_lossy().ends_with(".sock"));
    assert!(tok.to_string_lossy().ends_with(".token"));
    assert_ne!(sock, tok);
    // Socket and token share the project hash stem.
    let sock_stem = sock
        .file_stem()
        .unwrap()
        .to_string_lossy()
        .replace("vaultd-", "");
    let tok_stem = tok
        .file_stem()
        .unwrap()
        .to_string_lossy()
        .replace("vaultd-", "");
    assert_eq!(sock_stem, tok_stem);
}

#[test]
fn token_path_for_socket_mapping() {
    use std::path::Path;
    assert_eq!(
        server::token_path_for_socket(Path::new("/run/vaultd-abc.sock")),
        std::path::PathBuf::from("/run/vaultd-abc.token")
    );
    // No `.sock` suffix: append `.token`.
    assert_eq!(
        server::token_path_for_socket(Path::new("/run/custom")),
        std::path::PathBuf::from("/run/custom.token")
    );
}

#[test]
fn protocol_roundtrip() {
    use vaultd::daemon::protocol::{Request, Response};
    for req in [
        Request::Ping,
        Request::List,
        Request::Get {
            name: "A".to_string(),
        },
        Request::Add {
            name: "A".to_string(),
            value: "v".to_string(),
        },
        Request::Set {
            name: "A".to_string(),
            value: "v".to_string(),
        },
        Request::Remove {
            name: "A".to_string(),
        },
        Request::Environment,
        Request::Lock,
    ] {
        let json = serde_json::to_string(&req).unwrap();
        let back: Request = serde_json::from_str(&json).unwrap();
        assert_eq!(serde_json::to_string(&back).unwrap(), json);
    }
    for resp in [
        Response::Pong,
        Response::CredentialNames(vec!["A".to_string()]),
        Response::Credential {
            name: "A".to_string(),
            value: "v".to_string(),
        },
        Response::Environment(vec![("A".to_string(), "v".to_string())]),
        Response::Success,
        Response::Locked,
        Response::Error("e".to_string()),
    ] {
        let json = serde_json::to_string(&resp).unwrap();
        let back: Response = serde_json::from_str(&json).unwrap();
        assert_eq!(serde_json::to_string(&back).unwrap(), json);
    }
}

// --- Black-box socket auth (drives the real binary) ---

fn run_with_extra_env(
    env: &Env,
    args: &[&str],
    extra: &[(&str, &str)],
) -> std::process::Output {
    use std::io::Read;
    use std::os::unix::process::CommandExt;
    use std::process::Stdio;
    let mut cmd = std::process::Command::new(crate::common::binary());
    cmd.args(args)
        .current_dir(env.project.path())
        .env("XDG_RUNTIME_DIR", env.runtime.path())
        .env("HOME", env.home.path())
        .env("TERM", "dumb");
    cmd.env_remove("VAULTD_SOCKET");
    cmd.env_remove("VAULTD_TOKEN");
    for (k, v) in extra {
        cmd.env(k, v);
    }
    cmd.stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped());
    unsafe {
        cmd.pre_exec(|| {
            libc::setsid();
            Ok(())
        });
    }
    let mut child = cmd.spawn().expect("spawn vaultd");
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
                return std::process::Output {
                    status,
                    stdout: so,
                    stderr: se,
                };
            }
            None => {
                assert!(
                    start.elapsed() < TIMEOUT,
                    "timed out waiting for vaultd {args:?}"
                );
                std::thread::sleep(std::time::Duration::from_millis(50));
            }
        }
    }
}

#[test]
fn untrusted_socket_env_is_rejected() {
    let env = Env::new("daemon-untrusted-sock");
    init_vault(&env, PASSWORD);
    // Point at a socket outside the runtime dir: must be refused before
    // any secret is sent.
    let out = run_with_extra_env(&env, &["list"], &[("VAULTD_SOCKET", "/tmp/evil.sock")]);
    assert!(!out.status.success());
    assert!(
        stderr(&out).contains("untrusted VAULTD_SOCKET"),
        "unexpected stderr: {}",
        stderr(&out)
    );
}

#[test]
fn symlink_socket_is_rejected() {
    let env = Env::new("daemon-symlink-sock");
    init_vault(&env, PASSWORD);
    let sock = env.socket();
    if let Some(parent) = sock.parent() {
        std::fs::create_dir_all(parent).unwrap();
    }
    // `is_running()` gates on `path.exists()` (which follows links), so the
    // link target must exist for the symlink check to be reached. A dangling
    // link would return "not running" before the refusal.
    let target = env.runtime.path().join("link-target");
    std::fs::write(&target, "x").unwrap();
    std::os::unix::fs::symlink(&target, &sock).unwrap();
    // `unlock` checks `is_running()` before prompting, so this fails fast
    // without a pty.
    let out = env.run(&["unlock"], "");
    assert!(!out.status.success());
    assert!(
        stderr(&out).contains("symlink"),
        "expected symlink refusal, saw: {}",
        stderr(&out)
    );
    std::fs::remove_file(&sock).ok();
}

#[test]
fn second_unlock_while_running_fails() {
    if !have_zsh() {
        eprintln!("skipping: zsh is required for the vault shell");
        return;
    }
    let env = Env::new("daemon-double-unlock");
    init_vault(&env, PASSWORD);
    let mut shell = spawn_pty(&env, &["unlock"]);
    shell.pty.read_until("Master password:", TIMEOUT);
    shell.pty.send(&format!("{PASSWORD}\n"));
    shell.pty.read_until("Vault unlocked", TIMEOUT);
    env.wait_for_socket(Duration::from_secs(30));

    let out = env.run(&["unlock"], "");
    assert!(!out.status.success());
    assert!(
        stderr(&out).contains("already running"),
        "unexpected stderr: {}",
        stderr(&out)
    );

    // Cleanup: lock, socket goes away, shell exits.
    let out = env.run(&["lock"], "");
    assert!(out.status.success(), "lock failed: {}", stderr(&out));
    env.wait_for_gone(&env.socket(), Duration::from_secs(10));
    shell.pty.send("exit\n");
    let _ = wait_exit(&mut shell.child, Duration::from_secs(30), "vaultd unlock");
}

#[test]
fn wrong_token_is_rejected() {
    if !have_zsh() {
        eprintln!("skipping: zsh is required for the vault shell");
        return;
    }
    let env = Env::new("daemon-wrong-token");
    init_vault(&env, PASSWORD);
    let mut shell = spawn_pty(&env, &["unlock"]);
    shell.pty.read_until("Master password:", TIMEOUT);
    shell.pty.send(&format!("{PASSWORD}\n"));
    shell.pty.read_until("Vault unlocked", TIMEOUT);
    env.wait_for_socket(Duration::from_secs(30));

    let out = env.run(&["add", "REAL", "value"], "");
    assert!(out.status.success());

    // Correct socket but forged token must not read secrets.
    let sock = env.socket().to_string_lossy().into_owned();
    let out = run_with_extra_env(
        &env,
        &["get", "REAL"],
        &[
            ("VAULTD_SOCKET", sock.as_str()),
            ("VAULTD_TOKEN", &"00".repeat(32)),
        ],
    );
    assert!(!out.status.success());
    assert!(
        stderr(&out).contains("authentication failed"),
        "unexpected stderr: {}",
        stderr(&out)
    );
    // Sanity: without forgery the read works.
    let out = env.run(&["get", "REAL"], "");
    assert!(out.status.success());
    assert_eq!(stdout(&out).trim_end(), "value");

    let _ = env.run(&["lock"], "");
    env.wait_for_gone(&env.socket(), Duration::from_secs(10));
    shell.pty.send("exit\n");
    let _ = wait_exit(&mut shell.child, Duration::from_secs(30), "vaultd unlock");
}
