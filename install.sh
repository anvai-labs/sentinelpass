#!/usr/bin/env bash
# SentinelPass one-stop installer for macOS/Linux (user-level)

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
INSTALL_SCRIPT="$SCRIPT_DIR/installation/install.sh"

CHROME_EXTENSION_ID=""
SKIP_BUILD=0
BINARY_DIR=""
NO_LAUNCHD=0

while [[ $# -gt 0 ]]; do
  case "$1" in
    --chrome-extension-id)
      if [[ $# -lt 2 ]]; then
        echo "Missing value for --chrome-extension-id" >&2
        exit 1
      fi
      CHROME_EXTENSION_ID="$2"
      shift 2
      ;;
    --skip-build)
      SKIP_BUILD=1
      shift
      ;;
    --no-launchd)
      NO_LAUNCHD=1
      shift
      ;;
    --binary-dir)
      if [[ $# -lt 2 ]]; then
        echo "Missing value for --binary-dir" >&2
        exit 1
      fi
      BINARY_DIR="$2"
      shift 2
      ;;
    -h|--help)
      cat <<'USAGE'
Usage: ./install.sh [options]

Options:
  --chrome-extension-id <id>   32-char Chrome extension id to write into allowed_origins.
  --skip-build                 Skip cargo build --release.
  --no-launchd                 Do not install the macOS login LaunchAgent for the daemon.
  --binary-dir <path>          Override binary directory (default: ./target/release).
  -h, --help                   Show help.
USAGE
      exit 0
      ;;
    *)
      echo "Unknown option: $1" >&2
      exit 1
      ;;
  esac
done

echo "=== SentinelPass One-Stop Installer (user-level) ==="

if [[ ! -f "$INSTALL_SCRIPT" ]]; then
  echo "Install script not found: $INSTALL_SCRIPT" >&2
  exit 1
fi

if [[ $SKIP_BUILD -eq 0 ]]; then
  echo "[1/2] Building release binaries..."
  cargo build --release
else
  echo "[1/2] Skipping build as requested"
fi

echo "[2/2] Installing user-level binaries + native host manifests..."
if [[ -n "$CHROME_EXTENSION_ID" ]]; then
  SENTINELPASS_CHROME_EXTENSION_ID="$CHROME_EXTENSION_ID" \
    SENTINELPASS_BINARY_DIR="$BINARY_DIR" \
    SENTINELPASS_NO_LAUNCHD="$NO_LAUNCHD" \
    bash "$INSTALL_SCRIPT"
else
  SENTINELPASS_NO_LAUNCHD="$NO_LAUNCHD" \
    SENTINELPASS_BINARY_DIR="$BINARY_DIR" bash "$INSTALL_SCRIPT"
fi

if [[ -n "$CHROME_EXTENSION_ID" && ! "$CHROME_EXTENSION_ID" =~ ^[a-z]{32}$ ]]; then
  echo "WARNING: Chrome extension id format appears invalid (expected 32 lowercase letters)."
fi

echo
echo "Installation completed."
echo "If Chrome prompts still fail, rerun with --chrome-extension-id <32-char-id>."
