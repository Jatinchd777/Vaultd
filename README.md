# vaultd

Encrypted secrets for local development, with the convenience of `.env`.

`.env` files are convenient and also plaintext. They end up in dotfiles, screenshots, backups, and eventually a git commit. `vaultd` keeps the part you like — secrets showing up as environment variables in your dev shell — while the secrets themselves live on disk encrypted, in files you can commit without a second thought.

## Quick start

```sh
# one-time setup per project
$ vaultd init
# pick a master password when asked

# every dev session starts here
$ vaultd unlock
# enter the master password — you land in a vault shell

# store a secret (value is prompted, never echoed)
$ vaultd add API_KEY
Credential added: API_KEY

# your app changes nothing — it just reads the environment
$ python app.py

$ vaultd list
# ... shows names only, never values

$ exit
# leaving the shell locks the vault
```

That's the whole loop: `unlock` gives you a shell with secrets exported, `exit` (or `vaultd lock`) wipes them from memory and shuts everything down. What stays behind in the project is ciphertext.

Commit `.vaultd`. Never commit — or store anywhere — the master password. There is no recovery if you lose it.

## Installation

```sh
git clone https://github.com/Jatinchd777/Vaultd
cd Vaultd
cargo build --release
```

The binary lands at `target/release/vaultd`; put it somewhere on your `PATH`.

Requirements: a Rust toolchain, Linux, and `zsh` (the vault shell runs on `zsh`).

## Usage

Run everything from the project root, where `.vaultd/` lives. All commands except `init` need an unlocked vault, so `unlock` always comes first.

| Command | What it does |
|---|---|
| `vaultd init` | Create `.vaultd/` and set the master password |
| `vaultd unlock` | Verify the password, start the daemon, enter the vault shell |
| `vaultd add <NAME> [VALUE]` | Store a new credential; fails if the name already exists |
| `vaultd set <NAME> [VALUE]` | Update an existing credential; fails if the name is missing |
| `vaultd get <NAME>` | Print a credential's value |
| `vaultd remove <NAME>` | Delete a credential |
| `vaultd list` | List credential names (never values) |
| `vaultd lock` | Lock the vault from any terminal |

`add` and `set` are intentionally separate: `add` refuses to overwrite, `set` refuses to create. A typo fails loudly instead of silently destroying or duplicating a secret.

Omit `VALUE` and you're prompted for it with echo disabled — prefer this. Passing a secret inline works, but then it sits in your shell history and is visible to other processes while the command runs.

## How it works

Each project carries its vault with it:

```
.vaultd/
├── manifest    # plaintext parameters: format version, cipher, key-derivation settings and salt
└── vault       # the encrypted credentials
```

`manifest` holds everything needed to re-derive the encryption key later — which algorithm, which parameters, which salt. None of that is secret. `vault` holds the actual credentials (names and values together) as one encrypted blob.

Unlocking goes like this:

1. Derive the key from the master password using the parameters and salt in `manifest`.
2. Decrypt `vault`. The encryption is authenticated, so a wrong password and a tampered file fail the same way: no decryption, no partial output, no hints about which it was.
3. A background daemon takes over from there. It keeps the decrypted vault in memory and answers requests from `vaultd` commands over a Unix socket that only your user can reach. The commands themselves never see the key or the ciphertext — they're thin clients talking to the daemon.
4. You get a shell with the credentials exported as environment variables. When you leave the shell — or run `vaultd lock` — the daemon wipes its memory, removes the socket, and exits.

Every change (`add`, `set`, `remove`) re-encrypts the whole credential set with a fresh random nonce before writing it back, so the file on disk never contains stale plaintext and never reuses encryption randomness.

## Security model

The honest version, since this holds real secrets:

- **What's encrypted:** credential names and values, together, in a single blob sealed with AES-256-GCM. GCM provides confidentiality and integrity as one property — modified ciphertext doesn't decrypt to something wrong, it fails to decrypt at all.
- **Key derivation:** the master password is stretched with Argon2id and a random per-vault salt created at `init`. Re-deriving the key takes the same work every time you unlock, and guessing takes the same work per attempt for an attacker.
- **The password is never stored.** Not in the repo, not in a config file, nowhere on disk. It exists briefly at unlock time to derive the key. Forgetting it means losing the vault — that irreversibility is the price of never writing it down.
- **Why the vault is safe to commit:** anyone with the repo gets ciphertext plus the salt and derivation parameters. Those parameters are public by design. The master password is the entire defense against offline guessing, so it needs to be a strong one — a generated passphrase, not a memorable word.
- **Memory hygiene:** the daemon zeroes its key and plaintext when it shuts down, on `lock` and on shell exit. That closes the window secrets spend in RAM; it can't retract copies your shell, terminal scrollback, or child processes already made.
- **Locked means gone:** once the daemon exits, key and plaintext exist nowhere. Disk holds ciphertext again.

And the boundaries, stated plainly:

- Once a secret is exported into a shell environment, `vaultd` can't protect it further. Shell history, process listings, core dumps, a compromised dependency — all outside what a tool like this can cover. It protects secrets **at rest** and **on the way to your processes**, not from your processes.
- While unlocked, anything running as your user can ask the daemon for secrets. That's inherent to the design: your dev server needs that same access.
- A weak master password undermines everything, because the salt and parameters travel with the repo and guessing can happen offline.

## Storage format

`manifest` is JSON describing how to open the vault: a format version, the cipher in use, and the key-derivation algorithm with its salt and cost parameters. `vault` is binary: a fresh random nonce followed by the ciphertext, which decrypts to the JSON list of credentials. Inspecting it with `xxd` shows noise, which is exactly the idea.

Back up `.vaultd` like anything irreplaceable — with the password gone, the ciphertext is permanent noise.

## Development

```sh
cargo build
cargo run -- --help
cargo run -- <command> --help
```

The source mirrors the architecture: `cli` defines the commands, `commands` implements them, `crypto` handles key derivation and encryption, `storage` owns the `.vaultd` file layout, `vault` owns unlocking and in-memory secrets, and `daemon` owns the IPC protocol and the unlock-session lifecycle.

## License

GPL-3.0 — see [LICENSE](LICENSE).
