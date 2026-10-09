# Changelog

All notable changes to vaultd are documented here. Versions follow the
`v0.2.x-beta` tag scheme used for GitHub releases.

## [v0.2.4-beta]

### Added
- `vaultd passwd` — change the master password. Prompt-only (takes no
  arguments, no echo): asks for the current password, then the new one
  twice. Re-encrypts everything under a fresh salt; the old password stops
  working. Must be run while locked (`vaultd lock` first).
- README documents `passwd` (usage table, prompting behavior, salt rotation).

No protocol change, existing sessions stay compatible.

## [v0.2.3-beta]

### Summary
Owner-only vault files: `.vaultd` is now `0700`/`0600` under `umask 077`,
with symlink refusal and permission repair after `git clone`.

### Changes
- Vault dir `0700`, `manifest`/`vault` `0600` (`DirBuilder`/`OpenOptions`
  mode + explicit `chmod`); process `umask 077`
- Reads and writes tighten permissions back, since git checkouts come back
  `0755`/`0644`
- Symlinked `.vaultd`, `manifest`, `vault`, and socket paths refused
  instead of followed; nested `.vaultd` links skipped in project search
- `$VAULTD_SOCKET` confinement and wrong-token rejection covered by tests
- `cargo test` is a single runner (`tests/main.rs`); suite grows 16 → 50
  with `daemon`, `storage`, cipher/KDF, `__env` escaping, and unlock
  failure cases

No protocol change, existing sessions stay compatible.

## [v0.2.2-beta]

### Summary
Authenticated daemons: every request must present the unlock session token,
so only the vault shell session can read or modify secrets.

### Changes
- Per-session token `VAULTD_TOKEN` (32B `OsRng`, hex) alongside
  `vaultd-<hash>.sock` as `vaultd-<hash>.token` (`0600`)
- `AuthenticatedRequest { token, request }` wire format; wrong or missing
  token returns `authentication failed`
- `SO_PEERCRED` UID check on client and daemon
- `VAULTD_SOCKET` must live inside `$XDG_RUNTIME_DIR/vaultd/`
  (`untrusted VAULTD_SOCKET` otherwise)
- `__env` exports `VAULTD_SOCKET` and `VAULTD_TOKEN`
- Stale-socket cleanup never follows symlinks; `lock`/exit removes socket
  and token

Lock and unlock once after updating, old sessions stay on the old protocol.

## [v0.2.1-beta]

### Summary
Per-project daemons: every vault gets its own socket, so two projects can
stay unlocked side by side without commands crossing over.

### Changes
- Per-project socket `SHA-256(project root)` under
  `$XDG_RUNTIME_DIR/vaultd/` (`0700` dir, `0600` socket)
- `.vaultd` found by walking up; `init` refuses nested vaults
- Shell pinned via `VAULTD_SOCKET` exported by `__env`
- `unlock` / stale-socket cleanup per-project; `lock` locks current project
  only
- `clippy -D warnings` and `fmt` clean, 16/16 tests pass

## [v0.1.0-beta.1]

Local-first encrypted secrets for dev projects: a committable `.vaultd/`
directory plus a vault shell where secrets show up as plain environment
variables. Leaving the shell locks everything again.

- `init`, `unlock`, `lock`, `add`, `set`, `get`, `remove`, `list`
- Argon2id key derivation, AES-256-GCM vault, master password never stored
- Background daemon over a Unix socket only your user can reach, auto-lock
  on shell exit
- `install.sh` one-liner plus manual build instructions

No password reset by design — forget it and the vault is gone for good.
