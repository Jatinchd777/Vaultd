<div align="center">

# vaultd

_Encrypted vault for local dev secrets that exist only while you work._
<br>
<sub>(pronounced: vault-ied)</sub>
<br><br>

<a href="LICENSE"><img alt="license" src="https://custom-icon-badges.demolab.com/crates/l/vaultd?color=1C1917&logo=law&style=for-the-badge&logoColor=1C1917&labelColor=FAFAFA"></a>
<a href="https://crates.io/crates/vaultd"><img alt="version" src="https://custom-icon-badges.demolab.com/crates/v/vaultd?color=1C1917&logo=package&style=for-the-badge&logoColor=1C1917&labelColor=FAFAFA"></a>
<br>
<img alt="Platform: Linux" src="https://img.shields.io/badge/platform-Linux?style=for-the-badge&logo=linux&logoColor=1C1917&labelColor=FAFAFA&color=1C1917">
<img alt="Built with Rust" src="https://img.shields.io/badge/built_with-Rust?style=for-the-badge&logo=rust&logoColor=1C1917&labelColor=FAFAFA&color=1C1917">
<a href="https://github.com/Jatinchd777/Vaultd"><img alt="stars" src="https://custom-icon-badges.demolab.com/github/stars/Jatinchd777/Vaultd?color=1C1917&logo=star&style=for-the-badge&logoColor=1C1917&labelColor=FAFAFA"></a>
<br>

<a href="#installation">Installation</a>
&middot;
<a href="#usage">Usage</a>
&middot;
<a href="#how-it-works">How it works</a>
&middot;
<a href="#security">Security</a>

</div>

---

Most of us have committed a `.env` file at least once. vaultd exists so you can stop worrying about that.

Secrets live on disk encrypted. When you need them, they show up as ordinary environment variables in your shell. When you're done, they go away. The project directory keeps only ciphertext.

<h2>
     <sub>
          <img src="https://cdn.simpleicons.org/git/white"
           height="25"
           width="25">
     </sub>
     Description
</h2>

### Features

> [!TIP]
> Skip `VALUE` and let vaultd prompt for it without echoing. That keeps secrets out of shell history and the process list. More habits in [Usage](#usage).

- **Encrypted at rest, plain in use** - [Read More](#how-it-works)
  - Secrets live in `.vaultd/` as one AES-256-GCM blob, safe to commit to git
  - Master password is never stored anywhere; forget it and the vault is gone
  - Every write re-encrypts everything under a fresh random nonce

- **A vault shell for every session** - [Read More](#quick-start)
  - `vaultd unlock` checks the password and drops you into a shell that has your secrets
  - Apps read them like any other environment variable, no code changes
  - `exit` or `vaultd lock` wipes memory and locks the vault again

- **Per-project daemons that mind their own business** - [Read More](#how-it-works)
  - Each project gets its own Unix socket under `$XDG_RUNTIME_DIR/vaultd`, so two projects stay unlocked side by side without commands crossing over
  - Every request must present the unlock session token (`VAULTD_TOKEN`), and the daemon checks the peer UID
  - `$VAULTD_SOCKET` values pointing outside the runtime dir are rejected

- **Owner-only files, even after `git clone`** - [Read More](#security)
  - `.vaultd` is `0700`, both files `0600`, created under `umask 077`
  - Git doesn't preserve those modes, so vaultd tightens them back on every read and write
  - Symlinked `.vaultd` dirs and `manifest`/`vault` files are refused, never followed

- **`add` creates, `set` updates, neither guesses** - [Read More](#usage)
  - Mixing them up errors out instead of quietly overwriting something or making a duplicate
  - `list` shows names only, values stay hidden
  - `passwd` re-encrypts everything under a fresh salt; the old password stops working

## Quick Start

One-time setup per project:

```sh
vaultd init
# pick a master password when asked
```

Start of every dev session:

```sh
vaultd unlock
# type the master password, you get a vault shell

vaultd add API_KEY
# leave VALUE off, vaultd prompts without echoing

python app.py
# apps read it like any other env var

exit
# leaving the shell locks the vault
```

While unlocked you work in a shell that has your secrets. When you leave, the secrets are wiped from memory and the vault locks itself.

> [!CAUTION]
> Commit `.vaultd` to git. Keep the master password out of it, and out of everywhere else too. Forget the password and the vault is gone. There is no reset flow.

<h2>
     <sub>
          <img src="https://cdn.simpleicons.org/linux/white"
           height="25"
           width="25">
     </sub>
     Supported platforms
</h2>

- Linux

You also need `zsh`, since the vault shell runs on `zsh -i`, and a Rust toolchain if you're building from source.

<h2>
     <sub>
          <img src="https://cdn.simpleicons.org/rust/white"
           height="25"
           width="25">
     </sub>
     Installation
</h2>

<h4>
     <sub>
          <img src="https://cdn.simpleicons.org/rust/white"
           height="20"
           width="20">
     </sub>
     Cargo
     <a href="https://crates.io/crates/vaultd"><img alt="Cargo Version" src="https://img.shields.io/crates/v/vaultd?color=brightgreen&label=" align="right"></a>
</h4>

<details><summary>Click to expand</summary>

```sh
cargo install vaultd
```

That pulls the release from crates.io and puts the binary in `$HOME/.cargo/bin`. Make sure that directory is on your `PATH`.

</details>

<h4>
     <sub>
          <img src="https://cdn.simpleicons.org/linux/white"
           height="20"
           width="20">
     </sub>
     Installer script
</h4>

<details><summary>Click to expand</summary>

```sh
curl -fsSL https://raw.githubusercontent.com/Jatinchd777/Vaultd/main/install.sh | sh
```

That clones the repo, builds with `cargo build --release`, and copies the binary to `$HOME/.local/bin`. If that directory is not on your `PATH`, the script tells you what to add to your shell rc file.

</details>

<h4>
     <sub>
          <img src="https://cdn.simpleicons.org/github/white"
           height="20"
           width="20">
     </sub>
     From source
</h4>

<details><summary>Click to expand</summary>

```sh
git clone https://github.com/Jatinchd777/Vaultd
cd Vaultd
cargo build --release
cp target/release/vaultd $HOME/.local/bin/
```

</details>

## Usage

Run these from anywhere inside the project, vaultd finds `.vaultd` by walking up. Except for `init` and `passwd` (which work while locked), every command needs an unlocked vault, so `unlock` comes first.

| Command | What it does |
|---|---|
| `vaultd init` | Create `.vaultd` and set the master password |
| `vaultd unlock` | Check the password, start the daemon, open the vault shell |
| `vaultd passwd` | Change the master password (prompts, takes no arguments; run while locked) |
| `vaultd add <NAME> [VALUE]` | Store a new credential, errors if the name exists |
| `vaultd set <NAME> [VALUE]` | Update a credential, errors if the name is missing |
| `vaultd get <NAME>` | Print a credential value |
| `vaultd remove <NAME>` | Delete a credential |
| `vaultd list` | Show credential names, never values |
| `vaultd lock` | Lock the current project's vault |

A few things worth knowing:

**`add` creates, `set` updates.** Mixing them up gives you an error instead of quietly overwriting something or creating a duplicate.

**Skip `VALUE` when you can.** Leave it off and vaultd asks for it without echoing:

```sh
$ vaultd add STRIPE_KEY
Credential value: ********
```

That is the better habit. Typed inline, a secret lands in shell history and shows up in the process list while the command runs.

**`passwd` never takes a password on the command line.** It asks for the current password, then the new one twice, with no echo, same as `init`. It re-encrypts everything under a fresh salt, so the old password stops working. If the vault is unlocked, `lock` first:

```sh
$ vaultd lock
✓ Vault locked
$ vaultd passwd
Current password: ********
New master password: ********
Confirm new password: ********
Master password changed
```

**Each project is independent.** Unlocking uses a per-project socket, so two projects can stay unlocked side by side without commands crossing over. `lock` locks the current project only.

<h2>
     <sub>
          <img src="https://cdn.simpleicons.org/rust/white"
           height="25"
           width="25">
     </sub>
     How it works
</h2>

A project carries two files:

```
.vaultd/
├── manifest    # how to open the vault: version, cipher, key derivation settings and salt
└── vault       # the encrypted credentials
```

The manifest is plain JSON. It has to be, since it tells vaultd how to re-derive your key: which algorithm, which settings, which salt. None of that is sensitive. The vault file is the sensitive part. It holds every credential name and value in one encrypted blob.

Unlocking works like this:

1. **Derive the key.** Your password goes through Argon2id with the salt and settings from the manifest. Out comes the key.
2. **Open the vault.** The key decrypts the vault file. The encryption is authenticated, so a wrong password looks exactly like a damaged file. Either way you get an error and nothing else.
3. **Hand it to the daemon.** A background daemon holds the decrypted vault in memory. It listens on a per-project Unix socket under `$XDG_RUNTIME_DIR/vaultd` that only your user can connect to, so one project's commands never reach another project's daemon. Every request must also present the unlock session token (`VAULTD_TOKEN`, stored as `vaultd-<hash>.token` next to the socket), and the daemon checks the peer UID, so only that session can read or modify secrets. Past this point the `vaultd` commands never see keys or ciphertext themselves, they just ask the daemon over that socket.
4. **Work in the vault shell.** Your shell gets the credentials as environment variables. When you exit the shell, or run `vaultd lock`, the daemon clears its memory, removes the socket and token, and stops.

Each `add`, `set`, and `remove` encrypts the full set of credentials again with a new random nonce before writing. The file on disk never holds old plaintext and never repeats encryption randomness.

<details>
<summary>The cryptography, concretely</summary>

- **Cipher:** AES-256-GCM. Nonce is 12 random bytes, prepended to the ciphertext.
- **Key derivation:** Argon2id, 16-byte random salt, `m=19456, t=2, p=1`. Salt is made at `init` time and rotated by `passwd`.
- **Key size:** 32 bytes. The password itself is only in memory for the moment it takes to derive the key.

</details>

The manifest looks like this, salt and settings are public on purpose, the password is the whole defense:

```jsonc
// .vaultd/manifest
{
  "version": 1,
  "cipher": "AES-256-GCM",
  "kdf": {
    "algorithm": "Argon2id",
    "salt": "…base64…",
    "memory_cost": 19456,
    "time_cost": 2,
    "parallelism": 1
  }
}
```

> [!IMPORTANT]
> Back up `.vaultd` somewhere safe, off that machine. Without the password it is unreadable, so losing the files is the same as losing the secrets.

<h2>
     <sub>
          <img src="https://cdn.simpleicons.org/letsencrypt/white"
           height="25"
           width="25">
     </sub>
     Security
</h2>

Since this guards real secrets, here is what it does and where it stops.

**What it does:**

- The blob is sealed with AES-256-GCM, which covers secrecy and tampering in one go. Edited ciphertext does not decrypt to something wrong. It does not decrypt at all.
- The key comes from Argon2id with a random salt made at `init` time (rotated by `passwd`). Deriving it costs real work on every unlock, and the same work per guess for anyone trying passwords offline.
- The password itself is never written anywhere. It is only in memory for the moment it takes to derive the key. That is why forgetting it is final.
- Committing `.vaultd` is safe because all an attacker gets is ciphertext, a salt, and derivation settings. The salt and settings are public on purpose. The password is the whole defense against offline guessing, so it should be a generated passphrase, not a word you picked.
- The vault directory is `0700` and both files are `0600`, created under `umask 077`, so other local users never get the ciphertext in the first place. Git does not preserve those modes, so after a clone the files may come back `0755`/`0644`, vaultd tightens them back on every read and write. Symlinked `.vaultd` directories and `manifest`/`vault` files are refused rather than followed, and `$VAULTD_SOCKET` values pointing outside `$XDG_RUNTIME_DIR/vaultd` are rejected.
- On lock, the daemon zeroes the key and the decrypted secrets. That shrinks how long they sit in RAM. It cannot pull back copies your shell, scrollback, or child processes already hold.
- Once locked, nothing secret remains in memory. The key and plaintext are gone and disk holds ciphertext again.

**What vaultd does not do:**

- Once a secret is in your shell environment, it is out of vaultd's hands. Shell history, process listings, core dumps, a bad dependency phoning home, none of that is something this kind of tool can stop. It protects secrets at rest and on the way to your programs. After that, your programs own them.
- While the vault is unlocked, any process running as you can ask the daemon for secrets. That is how your dev server gets them too. There is no way to allow one and block the other.
- A weak password breaks the whole thing, because the salt and settings ship with the repo and guesses can be tried offline without limits.

<h2>
     <sub>
          <img src="https://cdn.simpleicons.org/stackoverflow/white"
           height="25"
           width="25">
     </sub>
     FAQ
</h2>

**I forgot my master password. How do I reset it?**

You don't. There is no reset flow and no back door, the password is never stored anywhere. If it is gone, the vault is gone. Delete `.vaultd`, run `vaultd init` again, and re-enter your secrets.

**`vaultd unlock` says the daemon is already running. What now?**

You're already inside a vault shell for this project, or a previous shell didn't exit cleanly. Check for the shell, `exit` it or run `vaultd lock`, then unlock again. A stale socket is cleaned up automatically.

**`no vault found`, but I just ran `init`?**

You're outside the project. vaultd looks for `.vaultd` in the current directory and every parent. `cd` back into the project (or a subdirectory of it) and try again. `init` also refuses nested vaults, so you can't init inside an existing one.

**My secrets don't show up in a new terminal.**

That's on purpose. Secrets only exist inside the vault shell that `unlock` opened. Open a new terminal and you get a plain shell with no secrets. Run `vaultd unlock` there if you need them, each project gets its own session.

**Permissions look wrong after `git clone`.**

Normal. Git doesn't keep `0600`/`0700` modes, so files come back `0644`/`0755`. vaultd tightens them back on every read and write. You don't need to `chmod` anything by hand.

**Do I need `zsh`?**

Yes, for now. The vault shell runs on `zsh -i`. If it is missing, unlocking fails when it tries to spawn the shell.

<h2>
     <sub>
          <img src="https://cdn.simpleicons.org/github/white"
           height="25"
           width="25">
     </sub>
     Development
</h2>

```sh
cargo build
cargo run -- --help
cargo run -- <command> --help
cargo test   # one runner, tests/main.rs (50 tests)
```

The code is split the way the system is:

```
src/
├── cli.rs        # command declarations
├── commands/     # carrying them out (init, unlock, add, …)
├── crypto/       # key derivation and encryption
├── storage/      # the .vaultd files
├── vault/        # unlocking and the in-memory secrets
└── daemon/       # IPC protocol and the unlock session
```

Tests mirror that in `tests/`: `cli`, `crypto`, `daemon`, `storage`, `vault`, sharing the `common` harness that drives the real binary in isolated temp projects.

Changes are tracked in [CHANGELOG.md](CHANGELOG.md).

<h2>
     <sub>
          <img src="https://cdn.simpleicons.org/github/white"
           height="25"
           width="25">
     </sub>
     Acknowledgements
</h2>

- [RustCrypto/argon2](https://github.com/RustCrypto/password-hashes) - Argon2id key derivation
- [RustCrypto/aes-gcm](https://github.com/RustCrypto/AEADs) - AES-256-GCM authenticated encryption
- [clap](https://github.com/clap-rs/clap) - command-line parsing
- [rpassword](https://github.com/conradkleinespel/rpassword) - prompt without echoing
- [zeroize](https://github.com/RustCrypto/utils) - wiping keys and secrets from memory

---

This program is free software; you can redistribute it and/or modify it under the terms of the GNU General Public License as published by the Free Software Foundation; either version 3 of the License, or (at your option) any later version. See [LICENSE](LICENSE).
