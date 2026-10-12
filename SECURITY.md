# Security Policy

## Supported versions

| Version | Supported |
|---|---|
| latest `main` / crates.io release | yes |
| older releases | no, update first |

## Assets

- `vault` file: all names + values, one AES-256-GCM blob.
- `manifest` file: version, cipher, KDF algorithm + salt + settings. Public by design.
- Runtime: daemon memory (key + plaintext), `$XDG_RUNTIME_DIR/vaultd/vaultd-<hash>.sock` (`0600`), `.token` sibling (`0600`), vault-shell env (`VAULTD_SOCKET`, `VAULTD_TOKEN`, secrets).

## Attackers considered

- Git reader / stolen laptop: gets ciphertext + salt, tries offline password guessing.
- Other local UID: tries to read `.vaultd/`, connect to socket, spoof `$VAULTD_SOCKET`.
- Same UID, outside session: other terminal, background job, editor plugin, cron. Tries path guess + token-file read + `/proc/*/environ` read to reach another project's daemon.
- Same UID, inside session: compromised child (dev server dep, `npm install`). Already inherits secrets via env.
- Malicious ciphertext: edited `vault`/`manifest` on disk or in git.

## What vaultd does

- At rest: AES-256-GCM, 12-byte random nonce per write, prepended. Tamper fails closed, never wrong plaintext. Every `add`/`set`/`remove` re-encrypts all with fresh nonce.
- KDF: Argon2id `m=19456, t=2, p=1`, 16-byte salt at `init`, rotated by `passwd`. Same cost for you and guessers. Password only in memory to derive the 32-byte key.
- Files: `.vaultd/` `0700`, files `0600`, `umask 077`. Tightened on every read/write after `git clone`. Symlinked dir/files refused. No nested vaults. `manifest`/`vault` parse errors fail as auth failure.
- IPC: per-project socket `SHA-256(project root)` under `0700` runtime dir. `$VAULTD_SOCKET` outside it rejected. Client + daemon check `SO_PEERCRED` UID, fail closed. 5s timeouts, 1MiB cap, max 16 workers with `busy` reply.
- Session: 32-byte `OsRng` token per `unlock`, hex in env + `0600` file, constant-time compare, removed on `lock`/exit. Daemon pins vault-shell `pid + starttime` (survives `exec`) and walks `/proc` ppid chain per connection. Only shell + descendants pass, even with valid token. Stale sockets cleaned without following symlinks.
- Memory: `zeroize` on key + plaintext + prompt buffers at `lock`/drop. `lock` removes socket/token first, then `SIGKILL`s shell via held `pidfd` after 500ms grace. Shell also self-exits at next prompt when socket is gone.

## What vaultd does not do

- Env leak: `ps e`, `/proc/*/environ`, history, scrollback, core dumps keep copies `lock` cannot pull back.
- Subtree children: everything you run from the vault shell gets secrets + daemon. For untrusted builds use a separate UID (`setpriv`, `sudo -u`, `bwrap`, `systemd-run --uid`) and pass only needed vars.
- Passwords: <12 chars or top-10 common rejected at `init`/`passwd`, but a weak older vault still opens. Salt ships with repo, guesses are unlimited offline. No reset, no escrow, no team ACLs or audit log.
- Availability: daemon dies with shell. No backup; losing `.vaultd/` or password loses secrets.

## Secure use

1. Generated passphrase, unique per project. `lock` before `passwd`.
2. `vaultd add NAME` without value so it prompts with no echo. Never paste secrets in `VALUE`, chat, or tickets.
3. Commit `.vaultd`, never the password. Back it up off-machine.
4. `exit` when done. New terminal needs its own `unlock`.
5. Check `ls -l .vaultd`, `ss -x | grep vaultd` if socket behavior surprises you.

## Reporting a vulnerability

Do not open a public GitHub issue. Public issues are for bugs only, and
`blank_issues_enabled` is off for this reason.

Report privately, in order:

1. GitHub private advisory (preferred, no email needed):
   `https://github.com/Jatinchd777/Vaultd/security/advisories/new`
   — enable this tab first under Settings → Code security →
   `Private vulnerability reporting`.
2. Email: replace `SECURITY_CONTACT_EMAIL` in this file with your address,
   then reporters send: `vaultd`, affected versions, repro, impact, and
   whether ciphertext-only or unlocked-session access is needed. Never send
   real secrets or passwords, only test vaults.

Include `RUSTSEC` if relevant.

We aim to acknowledge in 72h, fix on `main`, note in `CHANGELOG.md`, and credit you unless you opt out. High severity (plaintext exfil across UID or across projects without session access) gets a patch release; env-inheritance inside the subtree is by design, not a bug.
