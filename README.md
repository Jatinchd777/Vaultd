<div align="center">

# vaultd

_Rust CLI and daemon, an AES-256-GCM vault for local dev secrets that exist only while you work._
<br>
<sub>(pronounced: vaultied)</sub>
<br>

<a href="LICENSE"><img alt="license" src="https://custom-icon-badges.demolab.com/crates/l/vaultd?color=1C1917&logo=law&style=for-the-badge&logoColor=1C1917&labelColor=FAFAFA"></a>
<a href="https://crates.io/crates/vaultd"><img alt="version" src="https://img.shields.io/crates/v/vaultd?label=crates.io&color=1C1917&style=for-the-badge&labelColor=FAFAFA"></a>
<img alt="Platform: Linux" src="https://img.shields.io/static/v1?label=platform&message=Linux&style=for-the-badge&labelColor=FAFAFA&color=1C1917">
<br>

<a href="#installation">Installation</a>
&middot;
<a href="#usage">Usage</a>
&middot;
<a href="#how-it-works">How it works</a>
&middot;
<a href="#security">Security</a>
&middot;
<a href="SECURITY.md">Threat model</a>

</div>

---

vaultd stores project credentials in an encrypted vault instead of a plaintext `.env` file. Unlock it to work in a shell with those credentials, or use `vaultd run` to provide them to a single command. Credential values are encrypted on disk; `.vaultd/manifest` contains the public settings needed to open the vault.

<img alt="vaultd demo" src="assets/demo.gif">

See [Threat model](SECURITY.md) for what this stops and what it doesn't.

<h2 id="how-it-works">
     <sub>
          <img src="https://cdn.simpleicons.org/rust/white"
           height="25"
           width="25">
     </sub>
     How it works
</h2>

Each project has a `.vaultd` directory with two files:

```
.vaultd/
├── manifest    # how to open the vault: version, cipher, key derivation settings and salt
└── vault       # the encrypted credentials
```

`manifest` is a plain JSON file containing the format version and settings needed to derive the encryption key. Those settings, including the random salt, are not secret. `vault` contains the credential names and values in an encrypted blob.

When you run `vaultd unlock`, vaultd:

1. **Derives an encryption key.** Argon2id turns your password and the salt in `manifest` into the key. The password is not saved.
2. **Decrypts the vault.** AES-256-GCM checks the ciphertext as it decrypts it. A wrong password or modified vault file produces an error.
3. **Starts a per-project daemon.** The daemon keeps the decrypted credentials in memory and serves commands over a private Unix socket under `$XDG_RUNTIME_DIR/vaultd`. Requests are authenticated with a session token and checked against the UID and process tree of the vault shell. Each project has a separate socket and session.
4. **Opens your vault shell.** Credentials are set as environment variables in this shell and its child processes. When the shell exits or you run `vaultd lock`, vaultd stops the daemon and clears its in-memory vault.

`add`, `set`, and `remove` write the updated encrypted vault using a fresh random nonce. Plaintext credentials are not written to the project directory.

<details>
<summary>The cryptography, concretely</summary>

- **Cipher:** AES-256-GCM. Nonce is 12 random bytes, prepended to the ciphertext.
- **Key derivation:** Argon2id, 16-byte random salt, `m=19456, t=2, p=1`. Salt is made at `init` time and rotated by `passwd`.
- **Key size:** 32 bytes. The password itself is only in memory for the moment it takes to derive the key.

</details>

For example, `manifest` contains the algorithm and key-derivation settings. These values are public; your password protects the vault:

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
> Back up the `.vaultd` directory somewhere safe. You need both the files and the master password to recover your credentials. vaultd has no password reset or recovery key.

<h2 id="description">
     <sub>
          <img src="https://cdn.simpleicons.org/git/white"
           height="25"
           width="25">
     </sub>
     Description
</h2>

### Features

> [!TIP]
> Leave `VALUE` off `add` and `set` commands. vaultd prompts without echoing it, so the value won't appear in shell history or the command's argument list.

- **Encrypted on disk**
  - Credential names and values are stored together in an AES-256-GCM encrypted file
  - The master password is never saved; there is no password reset
  - Each change encrypts the updated vault with a new random nonce

- **A shell with credentials for a work session**
  - `vaultd unlock` verifies the password and opens `bash`, `zsh`, or `fish` with credentials in its environment
  - Programs launched from that shell can read credentials as normal environment variables
  - `exit` or `vaultd lock` ends the session

- **One-command access without a vault shell**
  - `vaultd run -- <command> [args...]` gives credentials directly to the launched program as process environment variables
  - No shell exports, intermediate shell, or background daemon; your current shell's environment is unchanged

- **Separate sessions for separate projects**
  - Each unlocked project has its own daemon and private socket
  - Requests must present the session token and come from the vault shell or one of its child processes

- **Restricted file access**
  - `.vaultd` is created with owner-only permissions; vaultd reapplies them after a clone
  - Symlinked vault directories and files are rejected

- **Explicit credential changes**
  - `add` creates a name and `set` updates one; using the wrong command reports an error
  - `list` shows names, not values
  - `passwd` re-encrypts the vault with a new salt and password

## Quick Start

Initialize the vault once from the project directory:

```sh
vaultd init
# choose a strong master password when prompted
```

To work in a vault shell:

```sh
vaultd unlock
# enter the master password when prompted

vaultd add API_KEY
# enter the value when prompted; it won't be echoed

python app.py
# the program can read API_KEY from its environment

exit
# leaving the vault shell ends the session
```

For a single command, you can instead run:

```sh
vaultd run -- python app.py
```

`run` prompts for the master password, then starts the requested program with the credentials directly in that process's environment. It does not generate shell `export` commands, invoke an intermediate shell, or start the vault daemon. The credentials are not added to your current shell; when the program exits, `vaultd` returns its exit status.

> [!CAUTION]
> You can commit `.vaultd` so another machine or teammate can access the encrypted vault, but anyone with a copy can attempt password guesses offline. Use a strong, unique password and never store it in the repository. Without the password, the vault cannot be recovered.

<h2 id="supported-platforms">
     <sub>
          <img src="https://cdn.simpleicons.org/linux/white"
           height="25"
           width="25">
     </sub>
     Supported platforms
</h2>

- Linux

The interactive vault shell requires `bash`, `zsh`, or `fish`. vaultd detects the shell you launched it from; set `VAULTD_SHELL` to `bash`, `zsh`, or `fish` to choose one explicitly. `vaultd run` starts the requested program directly and does not need an interactive shell. Building from source requires the Rust toolchain.

<h2 id="installation">
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

Run vaultd from anywhere inside a project; it searches the current directory and its parents for `.vaultd`. `init` creates a vault and `passwd` changes its password while it is locked. Credential commands such as `add`, `get`, and `list` require an active vault shell. `run` is different: it prompts for the password and opens the vault just for the command.

| Command | What it does |
|---|---|
| `vaultd init` | Create `.vaultd` and choose a master password |
| `vaultd unlock` | Prompt for the password, start the daemon, and open a vault shell |
| `vaultd passwd` | Change the master password while locked |
| `vaultd add <NAME> [VALUE]` | Add a credential; prompts securely if `VALUE` is omitted |
| `vaultd set <NAME> [VALUE]` | Update a credential; prompts securely if `VALUE` is omitted |
| `vaultd get <NAME>` | Print a credential value |
| `vaultd remove <NAME>` | Delete a credential |
| `vaultd list` | Show credential names without their values |
| `vaultd lock` | End the current project's vault session |
| `vaultd run -- <COMMAND> [ARGS...]` | Prompt for the password and run one program with vault credentials in its environment |

### Managing credentials

Use `add` for a new name and `set` to change an existing one. vaultd returns an error if the name already exists or does not exist, rather than silently creating or replacing a credential.

**Skip `VALUE` when you can.** Leave it off and vaultd asks for it without echoing:

```sh
$ vaultd add STRIPE_KEY
Credential value: ********
```

Entering the value at the prompt keeps it out of shell history and the process argument list. Avoid passing real secrets as `VALUE`.

### Changing the master password

`passwd` takes no password arguments. It prompts for the current password and asks for the new password twice without echoing them. New passwords must be at least 12 characters and cannot be among a short list of common passwords. The vault is re-encrypted with a fresh salt, so the old password no longer works. Lock the vault before changing the password:

```sh
$ vaultd lock
✓ Vault locked
$ vaultd passwd
Current password: ********
New master password: ********
Confirm new password: ********
Master password changed
```

### Running one command

Use `run` when you need secrets for a single process rather than an interactive shell:

```sh
vaultd run -- cargo test
vaultd run -- python app.py --debug
```

After `--`, provide the program and its arguments. vaultd launches that program directly and supplies the credentials in the environment the operating system gives it at startup. No shell parses the command or exports variables, and the credentials are not added to your current shell. Vault credentials replace inherited variables with matching names; `run` returns the child's exit status.

This can reduce exposure compared with opening a shell that has every credential: only the program you launch initially receives them. It is not a secret channel or a sandbox—the program and its child processes can read or copy the environment values. Use `run` only with programs you trust.

### Locking a vault

`unlock` opens a separate session for each project, so multiple projects can remain unlocked at once. `vaultd lock` ends the session for the current project only.

<h2 id="security">
     <sub>
          <img src="https://cdn.simpleicons.org/letsencrypt/white"
           height="25"
           width="25">
     </sub>
     Security
</h2>

vaultd protects the vault file and controls which local processes can use an unlocked session. It cannot protect credentials after a program has received them.

**What it does:**

- **Encryption:** AES-256-GCM encrypts the vault and detects changes to its ciphertext. A modified vault will fail to decrypt.
- **Password protection:** Argon2id derives a 256-bit key from the password and a random 16-byte salt. The salt and settings are stored in `manifest`; they are public. Anyone with a copy of the vault can try password guesses offline, so use a strong, unique password.
- The password itself is never written to disk. It is held in memory while vaultd derives the key; forgetting it means the vault cannot be opened.
- **Sharing the vault:** A copy of `.vaultd` contains ciphertext, not plaintext, but it can be used for offline password guessing. Choose a strong, unique password before sharing or committing it.
- **File permissions:** `.vaultd` is restricted to your user (`0700`) and its files to the owner (`0600`). vaultd reapplies these permissions because Git does not preserve them. Symlinked vault directories and files are rejected.
- **Unlocked sessions:** The daemon uses a private per-project Unix socket, a random session token, and process-tree checks to limit requests to the vault shell and its descendants. `lock` removes the socket and token and zeroizes the daemon's key and decrypted credentials.
- **Memory lifetime:** Locking clears the daemon's copies. It cannot clear copies already inherited by shells or programs, or remove them from scrollback, logs, or crash dumps.

**What vaultd does not do:**

- `vaultd run` passes secrets directly in the launched process's environment; it does not export them into the caller's shell. The receiving program can read them, pass them to child processes, or copy them elsewhere. Environment variables may also be visible through operating-system process inspection, crash dumps, or debugging tools.
- A compromised process inside a vault shell can use the credentials it inherits. For untrusted code, use a separate user or an isolation tool such as `bwrap`.
- A weak or reused password can be guessed offline by someone with a copy of `.vaultd`. vaultd cannot recover a vault if you lose the password or the files.

<h2 id="faq">
     <sub>
          <img src="https://cdn.simpleicons.org/stackoverflow/white"
           height="25"
           width="25">
     </sub>
     FAQ
</h2>

**I forgot my master password. How do I reset it?**

There is no reset or recovery key because vaultd does not store the password. If you cannot remember it, the encrypted vault cannot be opened. You can remove `.vaultd`, run `vaultd init` again, and enter your credentials into a new vault.

**`vaultd unlock` says the daemon is already running. What now?**

This project already has an active vault session, or an earlier session did not exit cleanly. If you are in its vault shell, run `exit` or `vaultd lock`. Then try unlocking again. vaultd cleans up stale sockets.

**`no vault found`, but I just ran `init`?**

vaultd searches the current directory and its parents for `.vaultd`. Change into the project (or one of its subdirectories) and try again. `init` refuses to create a nested vault inside an existing one.

**My secrets don't show up in a new terminal.**

That is expected: `unlock` adds credentials only to the vault shell it opens and programs started from that shell. In another terminal, run `vaultd unlock` for a separate session, or use `vaultd run -- <command>` for one program.

**Permissions look wrong after `git clone`.**

Git does not preserve `0600`/`0700` modes, so a checkout may have broader permissions. vaultd reapplies the required permissions when it reads or writes vault files.

**Which shells are supported?**

The interactive vault shell supports `bash`, `zsh`, and `fish`. vaultd detects the shell you used to run `unlock`; set `VAULTD_SHELL=bash`, `VAULTD_SHELL=zsh`, or `VAULTD_SHELL=fish` to choose one explicitly. The selected shell must be installed. `vaultd run` starts a program directly and does not require one of these shells.

<h2 id="development">
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
cargo test   # one runner, tests/main.rs
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

<h2 id="acknowledgements">
     <sub>
          <img src="https://cdn.simpleicons.org/github/white"
           height="25"
           width="25">
     </sub>
     Acknowledgements
</h2>

- [RustCrypto/argon2](https://github.com/RustCrypto/password-hashes) - Argon2id key derivation
- [RustCrypto/aes-gcm](https://github.com/RustCrypto/AEADs) - AES-256-GCM authenticated encryption
- [rpassword](https://github.com/conradkleinespel/rpassword) - prompt without echoing
- [zeroize](https://github.com/RustCrypto/utils) - wiping keys and secrets from memory

---

This program is free software; you can redistribute it and/or modify it under the terms of the GNU General Public License as published by the Free Software Foundation; either version 3 of the License, or (at your option) any later version. See [LICENSE](LICENSE).
