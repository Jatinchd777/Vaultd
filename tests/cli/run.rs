use std::time::Duration;

use crate::common::{
    Env, TIMEOUT, have_bash, have_fish, have_zsh, init_vault, run_in_shell, spawn_pty,
    spawn_pty_with_extra, wait_exit,
};

const PASSWORD: &str = "correct horse battery staple";

fn add_credential(env: &Env, name: &str, value: &str) -> bool {
    let shell = if have_bash() {
        "bash"
    } else if have_zsh() {
        "zsh"
    } else if have_fish() {
        "fish"
    } else {
        eprintln!("skipping: one supported shell is needed to set up test credentials");
        return false;
    };

    init_vault(env, PASSWORD);
    let mut shell_session = spawn_pty_with_extra(env, &["unlock"], &[("VAULTD_SHELL", shell)]);
    shell_session.pty.read_until("Master password:", TIMEOUT);
    shell_session.pty.send(&format!("{PASSWORD}\n"));
    shell_session.pty.read_until("Vault unlocked", TIMEOUT);
    env.wait_for_socket(Duration::from_secs(30));

    let out = run_in_shell(&mut shell_session, &["add", name, value]);
    assert!(
        out.status.success(),
        "add failed: {}",
        String::from_utf8_lossy(&out.stderr)
    );

    let out = run_in_shell(&mut shell_session, &["lock"]);
    assert!(
        out.status.success(),
        "lock failed: {}",
        String::from_utf8_lossy(&out.stderr)
    );
    let _ = wait_exit(&mut shell_session.child, TIMEOUT, "vaultd unlock");
    true
}

#[test]
fn run_passes_credentials_to_program_and_keeps_exit_status() {
    let env = Env::new("run-env");
    if !add_credential(&env, "VAULTD_RUN_TEST", "run-secret-value") {
        return;
    }

    let mut session = spawn_pty_with_extra(
        &env,
        &["run", "--", "/usr/bin/printenv", "VAULTD_RUN_TEST"],
        &[("VAULTD_RUN_TEST", "inherited-value")],
    );
    session.pty.read_until("Master password:", TIMEOUT);
    session.pty.send(&format!("{PASSWORD}\n"));
    let output = session.pty.read_until("run-secret-value", TIMEOUT);
    assert!(
        output.contains("run-secret-value"),
        "command did not receive vault environment: {output}"
    );
    let status = wait_exit(&mut session.child, TIMEOUT, "vaultd run");
    assert_eq!(status.code(), Some(0));
}

#[test]
fn run_returns_child_exit_status() {
    let env = Env::new("run-exit-status");
    if !add_credential(&env, "VAULTD_RUN_TEST", "value") {
        return;
    }

    let mut session = spawn_pty(&env, &["run", "--", "/usr/bin/false"]);
    session.pty.read_until("Master password:", TIMEOUT);
    session.pty.send(&format!("{PASSWORD}\n"));

    let status = wait_exit(&mut session.child, TIMEOUT, "vaultd run false");
    assert_eq!(status.code(), Some(1));
}
