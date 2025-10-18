#!/bin/sh

set -euo pipefail

# Must be run as root
if [ "$(id -u)" -ne 0 ]; then
  echo "Error: this install script must be run as root." >&2
  exit 1
fi

# Usage: ./install.sh [path/to/binary] [install-name]
# Defaults to target/release/localtunnel-server, falls back to target/debug.
SRC="${1:-target/release/localtunnel}"
NAME="${2:-$(basename "$SRC")}"
CFG_SRC="${3:-config.yml}"

BIN_DEST="/usr/bin/$NAME"
CFG_DIR="/etc/$NAME"
CFG_DEST="$CFG_DIR/config.yml"

# try sensible fallbacks if the provided binary path doesn't exist
if [ ! -f "$SRC" ]; then
  if [ -f "target/release/$NAME" ]; then
    SRC="target/release/$NAME"
  elif [ -f "target/debug/$NAME" ]; then
    SRC="target/debug/$NAME"
  else
    echo "Error: binary not found at '$SRC' and no fallback found."
    exit 1
  fi
fi

echo "Installing binary '$SRC' -> '$BIN_DEST' (owner: root, mode: 755)"
install -o root -g root -m 755 "$SRC" "$BIN_DEST"
echo "Binary installation complete."

# Copy config if provided and exists
if [ -f "$CFG_SRC" ]; then
  # ensure config directory exists
  mkdir -p "$CFG_DIR"
  echo "Found config source: $CFG_SRC"
  if [ -f "$CFG_DEST" ]; then
    # prompt user for overwrite
    printf "Configuration already exists at %s. Overwrite? [y/N]: " "$CFG_DEST"
    read -r answer
    case "$answer" in
      [yY]|[yY][eE][sS])
        echo "Overwriting configuration..."
        install -o root -g root -m 644 "$CFG_SRC" "$CFG_DEST"
        echo "Configuration installed to $CFG_DEST"
        ;;
      *)
        echo "Skipping configuration install."
        ;;
    esac
  else
    install -o root -g root -m 644 "$CFG_SRC" "$CFG_DEST"
    echo "Configuration installed to $CFG_DEST"
  fi
else
  echo "No config file found at '$CFG_SRC' — skipping config install."
fi

echo "Installation finished."