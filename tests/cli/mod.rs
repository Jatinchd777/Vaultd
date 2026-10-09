//! CLI surface: help output, argument validation, and behavior when no
//! daemon is running. None of these need a vault on disk.

use crate::common::{Env, stderr, stdout};

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
fn each_subcommand_validates_its_args() {
    let env = Env::new("cli-args");
    for args in [
        vec!["add"],
        vec!["set"],
        vec!["remove"],
        vec!["set", "ONLY_NAME"],
        // `list` and `lock` take no positional args.
        vec!["list", "EXTRA"],
        vec!["lock", "EXTRA"],
    ] {
        let out = env.run(&args, "");
        assert!(
            !out.status.success(),
            "{args:?} should fail argument validation"
        );
    }
}

#[test]
fn remove_without_name_fails() {
    let env = Env::new("cli-remove-noname");
    let out = env.run(&["remove"], "");
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
    // Outside any vault: fail fast with no-vault, never touching daemons.
    for args in cases {
        let out = env.run(args, "");
        assert!(
            !out.status.success(),
            "{args:?} should fail without a vault"
        );
        assert!(
            stderr(&out).contains("no vault found"),
            "{args:?}: unexpected stderr: {}",
            stderr(&out)
        );
    }

    // Inside a vault but with no daemon: per-project socket missing.
    crate::common::init_vault(&env, "correct horse battery staple");
    for args in cases {
        let out = env.run(args, "");
        assert!(
            !out.status.success(),
            "{args:?} should fail without a daemon"
        );
        assert!(
            stderr(&out).contains("vaultd daemon is not running"),
            "{args:?}: unexpected stderr: {}",
            stderr(&out)
        );
    }
}
