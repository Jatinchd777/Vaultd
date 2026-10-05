#!/usr/bin/env sh
# Installer for vaultd.
#
# Clones the vaultd repo, builds it with cargo --release,
# and copies the binary to ~/.local/bin.
#
# Run it directly:
#   curl -fsSL https://raw.githubusercontent.com/Jatinchd777/Vaultd/main/install.sh | sh
#
# Requires: git, cargo (Rust toolchain), Linux, zsh.

set -eu

REPO_URL="https://github.com/Jatinchd777/Vaultd"
INSTALL_DIR="$HOME/.local/bin"

command -v git >/dev/null 2>&1 || {
    echo "error: git is required but not installed" >&2
    exit 1
}

command -v cargo >/dev/null 2>&1 || {
    echo "error: cargo (Rust toolchain) is required but not installed" >&2
    exit 1
}

WORK_DIR="$(mktemp -d)"
trap 'rm -rf "$WORK_DIR"' EXIT INT TERM

echo "Cloning $REPO_URL ..."
git clone --depth 1 "$REPO_URL" "$WORK_DIR/vaultd"

echo "Building vaultd (release, this takes a bit) ..."
cargo build --release --manifest-path "$WORK_DIR/vaultd/Cargo.toml"

mkdir -p "$INSTALL_DIR"
cp "$WORK_DIR/vaultd/target/release/vaultd" "$INSTALL_DIR/vaultd"
chmod +x "$INSTALL_DIR/vaultd"

echo "Installed vaultd to $INSTALL_DIR/vaultd"

case ":$PATH:" in
    *":$INSTALL_DIR:"*) ;;
    *)
        echo "Note: $INSTALL_DIR is not on your PATH."
        echo "Add this to your shell rc file:"
        echo "  export PATH=\"\$HOME/.local/bin:\$PATH\""
        ;;
esac
