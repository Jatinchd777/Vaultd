//! Daemon layer: token codec, path derivation, and socket auth.
//!
//! Covers pure helpers in `src/daemon/server.rs` plus black-box socket
//! validation (`$VAULTD_SOCKET` confinement, symlink-socket refusal,
//! double-unlock, wrong-token rejection) in `src/daemon/server.rs` and
//! `src/daemon/client.rs`, none of which had tests.

use crate::common::{
    Env, TIMEOUT, have_bash, have_fish, have_zsh, init_vault, spawn_pty, spawn_pty_with_extra,
    stderr, stdout, wait_exit,
};
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

#[test]
fn shell_parse_accepts_names_and_paths() {
    assert_eq!(
        server::parse_shell_name("bash").unwrap(),
        server::Shell::Bash
    );
    assert_eq!(
        server::parse_shell_name("/bin/bash").unwrap(),
        server::Shell::Bash
    );
    assert_eq!(server::parse_shell_name("zsh").unwrap(), server::Shell::Zsh);
    assert_eq!(
        server::parse_shell_name("/usr/bin/zsh").unwrap(),
        server::Shell::Zsh
    );
    assert_eq!(
        server::parse_shell_name("fish").unwrap(),
        server::Shell::Fish
    );
    assert_eq!(
        server::parse_shell_name("/usr/bin/fish").unwrap(),
        server::Shell::Fish
    );
    assert!(server::parse_shell_name("tcsh").is_err());
    assert!(server::parse_shell_name("").is_err());
}

#[test]
fn shell_select_prefers_override_then_markers() {
    use server::Shell::{Bash, Fish, Zsh};
    // Explicit override wins over everything.
    assert_eq!(
        server::select_shell(
            Some("bash"),
            false,
            true,
            false,
            Some("zsh"),
            Some("/bin/zsh")
        )
        .unwrap(),
        Bash
    );
    // Fish marker beats bash/zsh markers (innermost nested shell wins).
    assert_eq!(
        server::select_shell(None, true, true, true, Some("bash"), Some("/bin/bash")).unwrap(),
        Fish
    );
    // Invoking-shell markers beat parent comm and $SHELL.
    assert_eq!(
        server::select_shell(None, true, false, false, Some("zsh"), Some("/bin/zsh")).unwrap(),
        Bash
    );
    assert_eq!(
        server::select_shell(None, false, true, false, Some("bash"), Some("/bin/bash")).unwrap(),
        Zsh
    );
    // Parent comm beats $SHELL.
    assert_eq!(
        server::select_shell(None, false, false, false, Some("fish"), Some("/bin/zsh")).unwrap(),
        Fish
    );
    assert_eq!(
        server::select_shell(None, false, false, false, Some("bash"), Some("/bin/zsh")).unwrap(),
        Bash
    );
    // $SHELL paths are accepted.
    assert_eq!(
        server::select_shell(None, false, false, false, None, Some("/usr/bin/fish")).unwrap(),
        Fish
    );
    assert_eq!(
        server::select_shell(None, false, false, false, None, Some("/bin/bash")).unwrap(),
        Bash
    );
    // Fallback is zsh for back-compat.
    assert_eq!(
        server::select_shell(None, false, false, false, None, None).unwrap(),
        Zsh
    );
    // Bad override is an error, not a silent fallback.
    assert!(server::select_shell(Some("tcsh"), false, false, false, None, None).is_err());
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

#[test]
fn slow_loris_does_not_block_others() {
    use std::io::Write;
    use std::os::unix::net::UnixStream;

    if !have_zsh() {
        eprintln!("skipping: zsh is required for the vault shell");
        return;
    }
    let env = Env::new("daemon-slow-loris");
    init_vault(&env, PASSWORD);
    let mut shell = spawn_pty(&env, &["unlock"]);
    shell.pty.read_until("Master password:", TIMEOUT);
    shell.pty.send(&format!("{PASSWORD}\n"));
    shell.pty.read_until("Vault unlocked", TIMEOUT);
    env.wait_for_socket(Duration::from_secs(30));

    // Hold a connection open with a partial message and never finish it.
    let mut loris = UnixStream::connect(env.socket()).expect("connect loris");
    loris
        .set_read_timeout(Some(Duration::from_secs(5)))
        .unwrap();
    loris
        .set_write_timeout(Some(Duration::from_secs(5)))
        .unwrap();
    loris.write_all(b"{\"token\":").expect("partial write");

    // A second client must still be served promptly.
    let start = std::time::Instant::now();
    let out = env.run(&["list"], "");
    assert!(out.status.success(), "list blocked: {}", stderr(&out));
    assert!(
        start.elapsed() < Duration::from_secs(30),
        "list stalled behind slow peer ({:?})",
        start.elapsed()
    );
    let out = env.run(&["add", "SLOWPROBE", "v"], "");
    assert!(out.status.success(), "add blocked: {}", stderr(&out));
    drop(loris);

    let _ = env.run(&["lock"], "");
    env.wait_for_gone(&env.socket(), Duration::from_secs(10));
    shell.pty.send("exit\n");
    let _ = wait_exit(&mut shell.child, Duration::from_secs(30), "vaultd unlock");
}

#[test]
fn oversized_request_is_rejected_without_hang() {
    use std::io::{Read, Write};
    use std::os::unix::net::UnixStream;

    if !have_zsh() {
        eprintln!("skipping: zsh is required for the vault shell");
        return;
    }
    let env = Env::new("daemon-oversize");
    init_vault(&env, PASSWORD);
    let mut shell = spawn_pty(&env, &["unlock"]);
    shell.pty.read_until("Master password:", TIMEOUT);
    shell.pty.send(&format!("{PASSWORD}\n"));
    shell.pty.read_until("Vault unlocked", TIMEOUT);
    env.wait_for_socket(Duration::from_secs(30));

    let sock = env.socket();
    let token_path = server::token_path_for_socket(&sock);
    let token = std::fs::read_to_string(&token_path).expect("token file");
    let big_value = "x".repeat(2 * 1024 * 1024);
    let payload = serde_json::json!({
        "token": token.trim(),
        "request": {"Add": {"name": "BIG", "value": big_value}},
    });
    let bytes = serde_json::to_vec(&payload).unwrap();
    assert!(bytes.len() > vaultd::daemon::protocol::MAX_MESSAGE_BYTES);

    let mut stream = UnixStream::connect(&sock).expect("connect");
    stream
        .set_read_timeout(Some(Duration::from_secs(10)))
        .unwrap();
    stream
        .set_write_timeout(Some(Duration::from_secs(10)))
        .unwrap();
    // The daemon closes oversized requests early; either a clean Error
    // frame or a reset/EOF counts as rejection as long as we don't hang.
    let mut response = Vec::new();
    let write_result = stream.write_all(&bytes);
    if write_result.is_ok() {
        let _ = stream.shutdown(std::net::Shutdown::Write);
        let mut buf = [0u8; 8192];
        loop {
            match stream.read(&mut buf) {
                Ok(0) => break,
                Ok(n) => response.extend_from_slice(&buf[..n]),
                Err(e)
                    if e.kind() == std::io::ErrorKind::WouldBlock
                        || e.kind() == std::io::ErrorKind::TimedOut =>
                {
                    break;
                }
                Err(_) => break,
            }
            if response.len() > 8192 {
                break;
            }
        }
        let text = String::from_utf8_lossy(&response);
        assert!(
            response.is_empty() || text.contains("too large") || text.contains("Error"),
            "unexpected oversize response: {text:?}"
        );
    }
    drop(stream);

    // Daemon must still serve legitimate requests afterwards.
    let out = env.run(&["list"], "");
    assert!(out.status.success(), "daemon wedged: {}", stderr(&out));

    let _ = env.run(&["lock"], "");
    env.wait_for_gone(&env.socket(), Duration::from_secs(10));
    shell.pty.send("exit\n");
    let _ = wait_exit(&mut shell.child, Duration::from_secs(30), "vaultd unlock");
}

#[test]
fn concurrent_adds_all_succeed() {
    if !have_zsh() {
        eprintln!("skipping: zsh is required for the vault shell");
        return;
    }
    let env = Env::new("daemon-concurrent");
    init_vault(&env, PASSWORD);
    let mut shell = spawn_pty(&env, &["unlock"]);
    shell.pty.read_until("Master password:", TIMEOUT);
    shell.pty.send(&format!("{PASSWORD}\n"));
    shell.pty.read_until("Vault unlocked", TIMEOUT);
    env.wait_for_socket(Duration::from_secs(30));

    std::thread::scope(|s| {
        let env_ref = &env;
        let mut handles = Vec::new();
        for i in 0..16 {
            handles.push(s.spawn(move || {
                let out = env_ref.run(&["add", &format!("C{i}"), &format!("v{i}")], "");
                assert!(out.status.success(), "add C{i} failed: {}", stderr(&out));
            }));
        }
        for h in handles {
            h.join().expect("worker panicked");
        }
    });

    let out = env.run(&["list"], "");
    assert!(out.status.success(), "list failed: {}", stderr(&out));
    let text = stdout(&out);
    assert!(text.contains("16 credentials"), "missing names:\n{text}");

    let _ = env.run(&["lock"], "");
    env.wait_for_gone(&env.socket(), Duration::from_secs(10));
    shell.pty.send("exit\n");
    let _ = wait_exit(&mut shell.child, Duration::from_secs(30), "vaultd unlock");
}

#[test]
fn bash_shell_roundtrip() {
    if !have_bash() {
        eprintln!("skipping: bash is required for the vault shell");
        return;
    }
    let env = Env::new("daemon-bash-shell");
    init_vault(&env, PASSWORD);
    let mut shell = spawn_pty_with_extra(&env, &["unlock"], &[("VAULTD_SHELL", "bash")]);
    shell.pty.read_until("Master password:", TIMEOUT);
    shell.pty.send(&format!("{PASSWORD}\n"));
    shell.pty.read_until("Vault unlocked", TIMEOUT);
    env.wait_for_socket(Duration::from_secs(30));

    // Prove the spawned shell really is bash.
    shell
        .pty
        .send("echo VAULTD_PROBE_BASH_VERSION=$BASH_VERSION\n");
    shell
        .pty
        .read_until("VAULTD_PROBE_BASH_VERSION=", Duration::from_secs(10));

    // Full CRUD through the daemon while the bash shell owns the session.
    let out = env.run(&["add", "BASH_KEY", "bash-value"], "");
    assert!(out.status.success(), "add failed: {}", stderr(&out));
    let out = env.run(&["get", "BASH_KEY"], "");
    assert!(out.status.success(), "get failed: {}", stderr(&out));
    assert_eq!(stdout(&out).trim_end(), "bash-value");
    let out = env.run(&["list"], "");
    assert!(out.status.success(), "list failed: {}", stderr(&out));
    assert!(stdout(&out).contains("BASH_KEY"));

    let _ = env.run(&["lock"], "");
    env.wait_for_gone(&env.socket(), Duration::from_secs(10));
    shell.pty.send("exit\n");
    let _ = wait_exit(&mut shell.child, Duration::from_secs(30), "vaultd unlock");
}

#[test]
fn unsupported_shell_fails_fast_without_daemon() {
    if !have_bash() && !have_zsh() {
        eprintln!("skipping: no supported shell to compare against");
        return;
    }
    let env = Env::new("daemon-bad-shell");
    init_vault(&env, PASSWORD);
    let mut shell = spawn_pty_with_extra(&env, &["unlock"], &[("VAULTD_SHELL", "tcsh")]);
    shell.pty.read_until("Master password:", TIMEOUT);
    shell.pty.send(&format!("{PASSWORD}\n"));
    let text = shell
        .pty
        .read_until("unsupported shell", Duration::from_secs(30));
    assert!(text.contains("tcsh"), "unexpected error:\n{text}");
    // No daemon may be left behind by the rejected shell.
    assert!(
        !env.socket().exists(),
        "daemon socket should not exist for unsupported shell"
    );
    let _ = wait_exit(&mut shell.child, Duration::from_secs(30), "vaultd unlock");
}

#[test]
fn fish_shell_roundtrip() {
    if !have_fish() {
        eprintln!("skipping: fish is required for the vault shell");
        return;
    }
    let env = Env::new("daemon-fish-shell");
    init_vault(&env, PASSWORD);
    let mut shell = spawn_pty_with_extra(&env, &["unlock"], &[("VAULTD_SHELL", "fish")]);
    shell.pty.read_until("Master password:", TIMEOUT);
    shell.pty.send(&format!("{PASSWORD}\n"));
    shell.pty.read_until("Vault unlocked", TIMEOUT);
    env.wait_for_socket(Duration::from_secs(30));

    // Prove the spawned shell really is fish.
    shell
        .pty
        .send("echo VAULTD_PROBE_FISH_VERSION=$FISH_VERSION\n");
    shell
        .pty
        .read_until("VAULTD_PROBE_FISH_VERSION=", Duration::from_secs(10));

    // Full CRUD through the daemon while the fish shell owns the session.
    let out = env.run(&["add", "FISH_KEY", "fish-value"], "");
    assert!(out.status.success(), "add failed: {}", stderr(&out));
    let out = env.run(&["get", "FISH_KEY"], "");
    assert!(out.status.success(), "get failed: {}", stderr(&out));
    assert_eq!(stdout(&out).trim_end(), "fish-value");
    let out = env.run(&["list"], "");
    assert!(out.status.success(), "list failed: {}", stderr(&out));
    assert!(stdout(&out).contains("FISH_KEY"));

    let _ = env.run(&["lock"], "");
    env.wait_for_gone(&env.socket(), Duration::from_secs(10));
    shell.pty.send("exit\n");
    let _ = wait_exit(&mut shell.child, Duration::from_secs(30), "vaultd unlock");
}

#[test]
fn env_shell_flag_emits_per_shell_syntax() {
    if !have_zsh() && !have_bash() && !have_fish() {
        eprintln!("skipping: no supported shell for the vault session");
        return;
    }
    let env = Env::new("daemon-env-shell-flag");
    init_vault(&env, PASSWORD);
    // Unlock with whatever shell detects; only the daemon matters here.
    let mut shell = spawn_pty(&env, &["unlock"]);
    shell.pty.read_until("Master password:", TIMEOUT);
    shell.pty.send(&format!("{PASSWORD}\n"));
    shell.pty.read_until("Vault unlocked", TIMEOUT);
    env.wait_for_socket(Duration::from_secs(30));

    assert!(env.run(&["add", "PLAIN", "secret-1"], "").status.success());

    let out = env.run(&["__env", "--shell", "fish"], "");
    assert!(
        out.status.success(),
        "__env --shell fish failed: {}",
        stderr(&out)
    );
    let fish_text = stdout(&out);
    assert!(
        fish_text.contains("set -gx VAULTD_SOCKET "),
        "missing fish socket:\n{fish_text}"
    );
    assert!(
        fish_text.contains("set -gx VAULTD_TOKEN "),
        "missing fish token:\n{fish_text}"
    );
    assert!(
        fish_text.contains("set -gx PLAIN 'secret-1'"),
        "missing fish secret:\n{fish_text}"
    );
    assert!(
        !fish_text.contains("export "),
        "fish output must not use export:\n{fish_text}"
    );

    let out = env.run(&["__env", "--shell", "bash"], "");
    assert!(
        out.status.success(),
        "__env --shell bash failed: {}",
        stderr(&out)
    );
    let bash_text = stdout(&out);
    assert!(
        bash_text.contains("export PLAIN='secret-1'"),
        "missing bash secret:\n{bash_text}"
    );
    assert!(
        !bash_text.contains("set -gx"),
        "bash output must not use set -gx:\n{bash_text}"
    );

    let out = env.run(&["__env", "--shell", "tcsh"], "");
    assert!(!out.status.success());
    assert!(
        stderr(&out).contains("unsupported shell"),
        "unexpected stderr: {}",
        stderr(&out)
    );

    let _ = env.run(&["lock"], "");
    env.wait_for_gone(&env.socket(), Duration::from_secs(10));
    shell.pty.send("exit\n");
    let _ = wait_exit(&mut shell.child, Duration::from_secs(30), "vaultd unlock");
}
