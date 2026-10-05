//! CLI surface: help output, argument validation, and behavior when no
//! daemon is running. None of these need a vault on disk.

use crate::common::{stderr, stdout, Env};

#[test]
fn help_lists_subcommands() {
    let env = Env::new("cli-help");
    let out = env.run(&["--help"], "");
    assert!(out.status.success(), "{}", stderr(&out));
    let text = stdout(&out);
    for cmd in [
        "init", "unlock", "lock", "get", "set", "add", "remove", "list",
    ] {
        assert!(text.contains(cmd), "help missing {cmd}:\n{text}");
    }
}

#[test]
fn version_flag() {
    let env = Env::new("cli-version");
    let out = env.run(&["--version"], "");
    assert!(out.status.success(), "{}", stderr(&out));
    assert!(stdout(&out).contains("vaultd"));
}

#[test]
fn unknown_subcommand_fails() {
    let env = Env::new("cli-unknown");
    let out = env.run(&["frobnicate"], "");
    assert!(!out.status.success());
}

#[test]
fn get_without_name_fails() {
    let env = Env::new("cli-get-noname");
    let out = env.run(&["get"], "");
    assert!(!out.status.success());
}

#[test]
fn commands_without_daemon_fail() {
    let env = Env::new("cli-nodaemon");
    let cases: &[&[&str]] = &[
        &["get", "ANYTHING"],
        &["add", "ANYTHING", "value"],
        &["set", "ANYTHING", "value"],
        &["remove", "ANYTHING"],
        &["list"],
        &["lock"],
    ];
    for args in cases {
        let out = env.run(args, "");
        assert!(!out.status.success(), "{args:?} should fail without a daemon");
        assert!(
            stderr(&out).contains("vaultd daemon is not running"),
            "{args:?}: unexpected stderr: {}",
            stderr(&out)
        );
    }
}
