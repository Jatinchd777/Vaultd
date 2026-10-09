<div align="center">

# vaultd

_Encrypted vault for local dev secrets that exist only while you work._

[![License: GPL-3.0](https://img.shields.io/badge/license-GPL--3.0-blue?style=flat-square)](LICENSE)
![Built with Rust](https://img.shields.io/badge/built_with-Rust-orange?style=flat-square&logo=rust)
![Platform: Linux](https://img.shields.io/badge/platform-Linux-yellow?style=flat-square&logo=linux)

[Quick start](#quick-start) · [Installation](#installation) · [Usage](#usage) · [How it works](#how-it-works) · [Security](#security)

</div>

Most of us have committed a `.env` file at least once. vaultd exists so you can stop worrying about that. Secrets live on disk encrypted, and when you need them they show up as ordinary environment variables in your shell.

## Quick start

```sh
# one-time setup per project
$ vaultd init
# pick a master password when asked

# start of every dev session
$ vaultd unlock
# type the master password, you get a vault shell

# save a secret
$ vaultd add API_KEY your_secret_here
Credential added: API_KEY

# apps read it like any other env var
$ python app.py

$ vaultd list
# names only, values stay hidden

$ exit
# leaving the shell locks the vault
```

While unlocked you work in a shell that has your secrets. When you leave, the secrets are wiped from memory and the vault locks itself. The project directory keeps only ciphertext.

Commit `.vaultd` to git. Keep the master password out of it, and out of everywhere else too. Forget the password and the vault is gone. There is no reset flow.

## Installation

```sh
cargo install vaultd
```

That pulls the release from crates.io and puts the binary in `$HOME/.cargo/bin`. Make sure that directory is on your `PATH`.

Or with the installer script:

```sh
curl -fsSL https://raw.githubusercontent.com/Jatinchd777/Vaultd/main/install.sh | sh
```

That clones the repo, builds with `cargo build --release`, and copies the binary to `$HOME/.local/bin`. If that directory is not on your `PATH`, the script tells you what to add to your shell rc file.

Doing it by hand works too:

```sh
git clone https://github.com/Jatinchd777/Vaultd
cd Vaultd
cargo build --release
cp target/release/vaultd $HOME/.local/bin/
```

You need a Rust toolchain, Linux, and `zsh`, since the vault shell runs on `zsh`.

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

`add` creates and `set` updates. Mixing them up gives you an error instead of quietly overwriting something or creating a duplicate.

Skip `VALUE` and vaultd will ask for it without echoing. That is the better habit. Typed inline, a secret lands in shell history and shows up in the process list while the command runs.

`passwd` never takes a password on the command line. It asks for the current password, then the new one twice, with no echo, same as `init`. It re-encrypts everything under a fresh salt, so the old password stops working. If the vault is unlocked, `lock` first.

## How it works

A project carries two files:

```
.vaultd/
├── manifest    # how to open the vault: version, cipher, key derivation settings and salt
└── vault       # the encrypted credentials
```

The manifest is plain JSON. It has to be, since it tells vaultd how to re-derive your key: which algorithm, which settings, which salt. None of that is sensitive. The vault file is the sensitive part. It holds every credential name and value in one encrypted blob.

Unlocking works like this:

1. Your password goes through Argon2id with the salt and settings from the manifest. Out comes the key.
2. The key decrypts the vault file. The encryption is authenticated, so a wrong password looks exactly like a damaged file. Either way you get an error and nothing else.
3. A background daemon holds the decrypted vault in memory. It listens on a per-project Unix socket under `$XDG_RUNTIME_DIR/vaultd` that only your user can connect to, so one project's commands never reach another project's daemon. Every request must also present the unlock session token (`VAULTD_TOKEN`, stored as `vaultd-<hash>.token` next to the socket), and the daemon checks the peer UID, so only that session can read or modify secrets. Past this point the `vaultd` commands never see keys or ciphertext themselves, they just ask the daemon over that socket.
4. Your shell gets the credentials as environment variables. When you exit the shell, or run `vaultd lock`, the daemon clears its memory, removes the socket and token, and stops.

Each `add`, `set`, and `remove` encrypts the full set of credentials again with a new random nonce before writing. The file on disk never holds old plaintext and never repeats encryption randomness.

## Security

Since this guards real secrets, here is what it does and where it stops.

The blob is sealed with AES-256-GCM, which covers secrecy and tampering in one go. Edited ciphertext does not decrypt to something wrong. It does not decrypt at all.

The key comes from Argon2id with a random salt made at `init` time (rotated by `passwd`). Deriving it costs real work on every unlock, and the same work per guess for anyone trying passwords offline.

The password itself is never written anywhere. It is only in memory for the moment it takes to derive the key. That is why forgetting it is final.

Committing `.vaultd` is safe because all an attacker gets is ciphertext, a salt, and derivation settings. The salt and settings are public on purpose. The password is the whole defense against offline guessing, so it should be a generated passphrase, not a word you picked.

The vault directory is `0700` and both files are `0600`, created under `umask 077`, so other local users never get the ciphertext in the first place. Git does not preserve those modes, so after a clone the files may come back `0755`/`0644`, vaultd tightens them back on every read and write. Symlinked `.vaultd` directories and `manifest`/`vault` files are refused rather than followed, and `$VAULTD_SOCKET` values pointing outside `$XDG_RUNTIME_DIR/vaultd` are rejected.

On lock, the daemon zeroes the key and the decrypted secrets. That shrinks how long they sit in RAM. It cannot pull back copies your shell, scrollback, or child processes already hold.

Once locked, nothing secret remains in memory. The key and plaintext are gone and disk holds ciphertext again.

What vaultd does not do:

Once a secret is in your shell environment, it is out of vaultd's hands. Shell history, process listings, core dumps, a bad dependency phoning home, none of that is something this kind of tool can stop. It protects secrets at rest and on the way to your programs. After that, your programs own them.

While the vault is unlocked, any process running as you can ask the daemon for secrets. That is how your dev server gets them too. There is no way to allow one and block the other.

A weak password breaks the whole thing, because the salt and settings ship with the repo and guesses can be tried offline without limits.

## Storage format

The manifest is JSON: format version, cipher name, key derivation algorithm with salt and cost settings. The vault file is binary: a random nonce up front, then the ciphertext, which decrypts to the JSON list of credentials. Point `xxd` at it and you will see noise.

Back up `.vaultd` somewhere safe, off that machine. Without the password it is unreadable, so losing the files is the same as losing the secrets.

## Development

```sh
cargo build
cargo run -- --help
cargo run -- <command> --help
cargo test   # one runner, tests/main.rs (50 tests)
```

The code is split the way the system is: `cli` declares the commands, `commands` carries them out, `crypto` does key derivation and encryption, `storage` handles the `.vaultd` files, `vault` handles unlocking and the in-memory secrets, `daemon` handles the IPC protocol and the unlock session. Tests mirror that in `tests/`: `cli`, `crypto`, `daemon`, `storage`, `vault`, sharing the `common` harness that drives the real binary in isolated temp projects.

## License

GPL-3.0, see [LICENSE](LICENSE).
