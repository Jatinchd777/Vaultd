# Changelog

All notable changes to vaultd are documented here. Entries mirror the
GitHub releases (`v0.1.0` … `vx.x.x`); the top section tracks work not
yet released.

## [v0.4.3]

### Fixed
- `vaultd lock` now terminates the vault shell it opened instead of
  stopping only the daemon (`src/daemon/server.rs`): the daemon
  signals the shell via its held `pidfd` (`SIGHUP`, wait `1s`, then
  `SIGKILL` fallback — interactive `bash`/`zsh` ignore `SIGTERM`,
  `fish` ignores both). Socket/token removal and vault drop happen
  first, so secrets are unreachable before the shell dies. Locking
  one project kills only its own shell.
- Tests: new `lock_terminates_vault_shell` plus all `lock` cleanups
  now assert auto-exit with no manual `exit`; suite 66 -> 67.

No protocol change, existing sessions stay compatible. Lock and
unlock once after updating.

## [v0.4.2]

### Added
- Fish vault shells: `unlock` detects `fish` (`$FISH_VERSION`, parent
  process, `$SHELL`, or `VAULTD_SHELL=fish`) and spawns `fish -i`,
  loading secrets via `vaultd __env --shell fish | source`.
- Hidden `vaultd __env --shell <bash|zsh|fish>` flag selecting the
  output syntax (`export` vs `set -gx`); defaults to detecting the
  invoking shell. The spawn path passes it explicitly so loading never
  depends on re-detection.

No protocol change, existing sessions stay compatible.

## [v0.4.1]

### Added
- Master-password policy (`src/crypto/password.rs`): `init` and
  `passwd` reject passwords shorter than 12 characters and the
  NordPass 2025 global top 10 most common passwords
  (case-insensitive). `unlock` is unchanged, so existing vaults with
  weak passwords still open.
- `init` checks for an existing vault before prompting, so a rejected
  password never leaves a half-made `.vaultd` behind.
- Password prompt buffers are zeroized on drop (`init`, `unlock`,
  `passwd`).

No protocol change, existing sessions stay compatible.

## [v0.4.0]

### Summary
Bash vault shells: `unlock` now detects the shell you ran it from
and spawns the same shell, `bash` or `zsh`. `VAULTD_SHELL` overrides
detection.

### Changes
- Auto-detects your shell (`VAULTD_SHELL` override, else `bash`/`zsh`
  markers, parent process, `$SHELL`) and spawns `bash -i` or `zsh -i`
- Unsupported shells fail fast with no orphan daemon
- Tests: shell-selection units plus `bash` roundtrip and refusal
  cases; suite 53 -> 57

No protocol change, existing sessions stay compatible.

## [v0.3.1]

### Summary
Concurrent daemon: one slow or huge peer can no longer stall the
vault. Connections are handled on bounded worker threads with
timeouts and size caps.

### Changes
- `serve_loop` (`src/daemon/server.rs`) is now a supervisor:
  `poll(listener,pidfd)` + thread-per-accept, cap 16 with
  `vaultd daemon is busy` reply, `100ms` quantum for `Lock`/reap
- Per-connection `5s` read/write timeouts, `1MiB` cap
  (`MAX_MESSAGE_BYTES` in `src/daemon/protocol.rs`); vault shared
  via `Arc<Mutex>`, locked only while building the response
- `src/daemon/client.rs`: fail-closed peer-cred check, `10s`
  timeouts, response cap
- Removed dead `vaultd-clear()`/`_VAULTD_EXPORTED` from `__env`
  (the function was lost on `exec` and never worked)
- Tests (`tests/daemon/mod.rs`): `slow_loris_does_not_block_others`,
  `oversized_request_is_rejected_without_hang`,
  `concurrent_adds_all_succeed`; suite 50 -> 53

No protocol change, existing sessions stay compatible. Lock and
unlock once after updating.

## [v0.3.0]

### Summary
Password rotation: `vaultd passwd` changes the master password
without ever taking it on the command line, and re-encrypts the
vault under a fresh salt.

### Changes
- New `vaultd passwd` subcommand (`src/commands/passwd.rs`, wired in
  `src/cli.rs` / `src/commands/mod.rs`): takes no arguments, extra
  args are rejected by clap
- Three no-echo prompts via `rpassword`, same as `init`: current
  password, new password, confirmation
- New `Vault::change_password` (`src/vault/store.rs`): verifies the
  current password by unlocking first, derives a fresh key with a new
  random salt, zeroizes the old key in memory, then rewrites
  `manifest` + `vault`
- Empty new passwords and mismatched confirmations are rejected
  before anything is written
- Refuses to run while the daemon is up (`vaultd lock` first), so no
  stale in-memory key survives the rotation
- Prompt buffers zeroized after use; vault (new key + plaintext)
  zeroized on drop
- README usage table, prompting notes, and salt-rotation line updated

No protocol change, existing sessions stay compatible.

## [v0.2.3]

### Summary
Owner-only vault files: `.vaultd` is now `0700`/`0600` under
`umask 077`, with symlink refusal and permission repair after
`git clone`.

### Changes
- Vault dir `0700`, `manifest`/`vault` `0600`
  (`DirBuilder`/`OpenOptions` mode + explicit `chmod`); process
  `umask 077`
- Reads and writes tighten permissions back, since git checkouts come
  back `0755`/`0644`
- Symlinked `.vaultd`, `manifest`, `vault`, and socket paths refused
  instead of followed; nested `.vaultd` links skipped in project
  search
- `$VAULTD_SOCKET` confinement and wrong-token rejection covered by
  tests
- `cargo test` is a single runner (`tests/main.rs`); suite grows
  16 -> 50 with `daemon`, `storage`, cipher/KDF, `__env` escaping,
  and unlock failure cases

No protocol change, existing sessions stay compatible.

## [v0.2.2]

### Summary
Authenticated daemons: every request must present the unlock session
token, so only the vault shell session can read or modify secrets.

### Changes
- Per-session token `VAULTD_TOKEN` (32B `OsRng`, hex) alongside
  `vaultd-<hash>.sock` as `vaultd-<hash>.token` (`0600`)
- `AuthenticatedRequest { token, request }` wire format; wrong or
  missing token returns `authentication failed`
- `SO_PEERCRED` UID check on client and daemon
- `VAULTD_SOCKET` must live inside `$XDG_RUNTIME_DIR/vaultd/`
  (`untrusted VAULTD_SOCKET` otherwise)
- `__env` exports `VAULTD_SOCKET` and `VAULTD_TOKEN`
- Stale-socket cleanup never follows symlinks; `lock`/exit removes
  socket and token

Lock and unlock once after updating, old sessions stay on the old
protocol.

## [v0.2.1]

### Summary
Per-project daemons: every vault gets its own socket, so two
projects can stay unlocked side by side without commands crossing
over.

### Changes
- Per-project socket `SHA-256(project root)` under
  `$XDG_RUNTIME_DIR/vaultd/` (`0700` dir, `0600` socket)
- `.vaultd` found by walking up; `init` refuses nested vaults
- Shell pinned via `VAULTD_SOCKET` exported by `__env`
- `unlock` / stale-socket cleanup per-project; `lock` locks current
  project only
- `clippy -D warnings` and `fmt` clean, 16/16 tests pass

## [v0.1.0]

Local-first encrypted secrets for dev projects: a committable
`.vaultd/` directory plus a vault shell where secrets show up as
plain environment variables. Leaving the shell locks everything
again.

- `init`, `unlock`, `lock`, `add`, `set`, `get`, `remove`, `list`
- Argon2id key derivation, AES-256-GCM vault, master password never
  stored
- Background daemon over a Unix socket only your user can reach,
  auto-lock on shell exit
- `install.sh` one-liner plus manual build instructions

No password reset by design: forget it and the vault is gone for
good.
