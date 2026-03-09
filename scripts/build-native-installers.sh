#!/usr/bin/env bash
set -euo pipefail

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$ROOT_DIR"

if ! command -v cargo >/dev/null 2>&1; then
  echo "cargo not found in PATH" >&2
  exit 1
fi

if ! cargo tauri --help >/dev/null 2>&1; then
  echo "Installing tauri-cli (cargo-tauri)..."
  cargo install tauri-cli --version '^2.0.0' --locked
fi

echo "[1/3] Building runtime binaries (daemon + host)..."
cargo build --release --locked --bin sentinelpass-daemon --bin sentinelpass-host

echo "[2/3] Preparing bundled runtime resources..."
mkdir -p sentinelpass-ui/src-tauri/resources/bin
cp target/release/sentinelpass-daemon sentinelpass-ui/src-tauri/resources/bin/
cp target/release/sentinelpass-host sentinelpass-ui/src-tauri/resources/bin/
chmod +x sentinelpass-ui/src-tauri/resources/bin/sentinelpass-daemon
chmod +x sentinelpass-ui/src-tauri/resources/bin/sentinelpass-host

echo "[3/3] Building native installers via Tauri..."
cargo tauri build --manifest-path sentinelpass-ui/Cargo.toml --ci "$@"

echo
echo "Native installer artifacts:"
find sentinelpass-ui/src-tauri/target/release/bundle -type f \( \
  -name '*.AppImage' -o -name '*.deb' -o -name '*.rpm' -o -name '*.dmg' -o -name '*.pkg' -o -name '*.exe' -o -name '*.msi' \
\) -print | sort
