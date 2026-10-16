# Security Policy

This document describes what vaultd protects, what it assumes, and how to report a vulnerability.

## Supported versions

| Version | Supported |
|---|---|
| latest `main` / crates.io release | yes |
| older releases | no; update to the latest release |

## What vaultd stores

- **`.vaultd/vault`:** credential names and values, encrypted together with AES-256-GCM.
- **`.vaultd/manifest`:** format version, cipher, and Argon2id parameters, including the random salt. These settings are public and are required to derive the key.
- **Unlocked session:** the key and decrypted credentials in daemon memory, or temporarily in the `vaultd run` process. In an interactive session, credentials are also present in the vault shell and its child processes' environments.
- **Runtime files:** an owner-only Unix socket and session-token file under `$XDG_RUNTIME_DIR/vaultd` (or the per-user temporary runtime directory when XDG is not configured).

## Threat model

vaultd is designed to protect credentials stored in a project directory and to restrict access to an unlocked daemon. It considers:

- Someone who can read a repository or a copied device and tries offline password guesses against `.vaultd`.
- Another local user attempting to read vault files or connect to the daemon.
- An unrelated process running as the same user attempting to access a project's unlocked daemon from outside its vault shell.
- A modified or corrupted vault or manifest.

vaultd does not treat programs launched inside an unlocked vault shell, or the program launched with `vaultd run`, as trusted boundaries. Those programs receive the credentials and can use or copy them.

## What vaultd does

- **Encryption:** AES-256-GCM encrypts the vault and detects tampering. Each write uses a fresh 12-byte random nonce. A wrong password or modified ciphertext fails to decrypt.
- **Key derivation:** Argon2id derives a 32-byte key using `m=19456, t=2, p=1` and a random 16-byte salt. `init` creates the salt; `passwd` generates a new one when changing the password.
- **Password handling:** the master password is not stored. New passwords must be at least 12 characters and cannot match the top-10 common-password list checked by vaultd. This policy applies to `init` and `passwd`; existing vaults with weaker passwords can still be opened.
- **File permissions:** `.vaultd` is set to `0700`, and its files to `0600`, under `umask 077`. vaultd reapplies these permissions because Git does not preserve them. Symlinked vault directories and files are rejected.
- **Interactive session isolation:** each project uses its own Unix socket. The daemon checks the connecting UID, the session token, and whether the peer process is the vault shell or one of its descendants. Socket paths supplied through `VAULTD_SOCKET` must remain inside vaultd's runtime directory. Requests have timeouts and message-size limits.
- **Locking:** `lock` removes the socket and token, clears the daemon's key and decrypted credentials, and ends the vault shell. Key, plaintext, and password prompt buffers are zeroized when released.
- **One-command execution:** `vaultd run -- <command> [args...]` decrypts the vault in the `vaultd` process and starts the requested program directly with credentials in its process environment. No shell exports or intermediate shell are used; the invoking shell's environment is unchanged. Vault values replace inherited variables with matching names. The child program's exit status is returned.

## What vaultd does not do

- **Prevent offline guessing:** anyone with a copy of `.vaultd` can make password guesses without contacting vaultd. The salt and KDF settings are public; use a strong, unique password.
- **Protect secrets after delivery:** `run` narrows initial delivery to the launched program instead of exporting credentials into the caller's shell, but it is not a secret channel or sandbox. The program can read, log, transmit, or pass credentials to child processes. Environment variables may also be visible through operating-system process inspection, crash dumps, or debugging tools.
- **Sandbox commands:** `vaultd run` limits initial delivery to one program, but is not process isolation. The `vaultd` process keeps the decrypted vault in memory while that program runs and zeroizes it after the program exits. Use a separate user or an isolation tool for untrusted code.
- **Recover lost data:** vaultd has no password reset, escrow, or recovery key. Losing the password or the `.vaultd` files means losing access to the credentials.
- **Provide team access controls or audit logs:** anyone who has both the encrypted files and the master password can open the vault. Access control and recovery for teams are outside the current design.

## Secure use

1. Use a generated, unique master password for each vault. Store a backup of `.vaultd` somewhere safe, separately from the password.
2. Use `vaultd add NAME` or `vaultd set NAME` without a value argument so vaultd prompts without echoing the credential. Avoid putting real values in shell history or command arguments.
3. Commit `.vaultd` only if you intend to share the encrypted vault. Never commit or otherwise store the master password beside it.
4. Exit the vault shell or run `vaultd lock` when you are done. Use `vaultd run` when one command needs credentials, and only run programs you trust with them.
5. If socket behavior is unexpected, check the permissions on `.vaultd` and the runtime directory.

## Reporting a vulnerability

Do not report vulnerabilities in a public GitHub issue. Public issues are for bugs; `blank_issues_enabled` is off for this reason.

Report privately:

1. **GitHub private advisory (preferred):** <https://github.com/Jatinchd777/Vaultd/security/advisories/new>. If private vulnerability reporting is not enabled, a repository administrator must enable it under **Settings → Code security → Private vulnerability reporting**.
2. **Email:** replace `SECURITY_CONTACT_EMAIL` in this file with the project's security contact address. Include the affected version, reproduction steps, impact, and whether the report requires access to ciphertext only or an unlocked session. Do not send real credentials or passwords; use test vaults.

Include a `RUSTSEC` advisory reference if relevant.

We aim to acknowledge reports within 72 hours, fix confirmed issues on `main`, document fixes in `CHANGELOG.md`, and credit reporters unless they prefer not to be named. Vulnerabilities that allow plaintext access across users or projects without access to the relevant session will be treated as high severity. Credential inheritance by programs launched inside a vault shell or with `vaultd run` is intentional behavior, not a vulnerability by itself.
