#!/usr/bin/env bash
set -euo pipefail

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$ROOT_DIR"

# --- Cross-platform binary names (WBS-905) ---------------------------------
# release.yml's native-installer-smoke job runs this script with
# `shell: bash` on every OS — i.e. under Git Bash/MSYS on Windows, where
# cargo emits `sentinelpass-daemon.exe` / `sentinelpass-host.exe`. On Unix
# the suffix stays empty and behavior is unchanged.
case "$(uname -s)" in
  MINGW* | MSYS* | CYGWIN*) EXE_SUFFIX=".exe" ;;
  *) EXE_SUFFIX="" ;;
esac

# Honor CARGO_TARGET_DIR so the copy below always reads what the build above
# wrote (and so sandboxed/local runs can redirect the target dir). Unset —
# the CI default — resolves to the plain `target` directory, unchanged.
TARGET_DIR="${CARGO_TARGET_DIR:-$ROOT_DIR/target}"

# --stage-only: build + stage the daemon/host sidecars, then stop without
# running the (slow) Tauri bundling. Used by release.yml to fail fast before
# the bundle step, and useful for verifying staging in isolation. Any other
# arguments are forwarded to `cargo tauri build` below.
STAGE_ONLY=0
for arg in "$@"; do
  case "$arg" in
    --stage-only) STAGE_ONLY=1 ;;
    *) : ;;
  esac
done

if ! command -v cargo >/dev/null 2>&1; then
  echo "cargo not found in PATH" >&2
  exit 1
fi

if [ "$STAGE_ONLY" -eq 0 ] && ! cargo tauri --help >/dev/null 2>&1; then
  echo "Installing tauri-cli (cargo-tauri)..."
  cargo install tauri-cli --version '^2.0.0' --locked
fi

echo "[1/3] Building runtime binaries (daemon + host)..."
cargo build --release --locked --bin sentinelpass-daemon --bin sentinelpass-host

echo "[2/3] Preparing bundled runtime resources..."
# Stage EXACTLY what this run built: wipe stale sidecars (both suffix
# variants) first — a leftover extensionless binary or a previous version
# must never ride along into a bundle. The tracked README.txt stays.
mkdir -p sentinelpass-ui/src-tauri/resources/bin
rm -f \
  sentinelpass-ui/src-tauri/resources/bin/sentinelpass-daemon \
  sentinelpass-ui/src-tauri/resources/bin/sentinelpass-daemon.exe \
  sentinelpass-ui/src-tauri/resources/bin/sentinelpass-host \
  sentinelpass-ui/src-tauri/resources/bin/sentinelpass-host.exe
cp "$TARGET_DIR/release/sentinelpass-daemon${EXE_SUFFIX}" sentinelpass-ui/src-tauri/resources/bin/
cp "$TARGET_DIR/release/sentinelpass-host${EXE_SUFFIX}" sentinelpass-ui/src-tauri/resources/bin/
chmod +x "sentinelpass-ui/src-tauri/resources/bin/sentinelpass-daemon${EXE_SUFFIX}"
chmod +x "sentinelpass-ui/src-tauri/resources/bin/sentinelpass-host${EXE_SUFFIX}"

# Fail-closed staging gate (WBS-905): tauri.conf.json declares
# `resources: ["src-tauri/resources/bin/*"]` and the bundler SILENTLY
# tolerates an empty glob — which is exactly how installers shipped without
# the daemon/host sidecars. Refuse to proceed unless both sidecars are
# staged and non-empty.
for sidecar in \
  "sentinelpass-ui/src-tauri/resources/bin/sentinelpass-daemon${EXE_SUFFIX}" \
  "sentinelpass-ui/src-tauri/resources/bin/sentinelpass-host${EXE_SUFFIX}"; do
  if [ ! -s "$sidecar" ]; then
    echo "ERROR: staged sidecar '$sidecar' missing or empty — refusing to build sidecar-less installers" >&2
    exit 1
  fi
done
echo "Staged sidecars:"
ls -l sentinelpass-ui/src-tauri/resources/bin/

if [ "$STAGE_ONLY" -eq 1 ]; then
  echo "[3/3] --stage-only: skipping Tauri bundle build"
  exit 0
fi

echo "[3/3] Building native installers via Tauri..."
cargo tauri build --manifest-path sentinelpass-ui/Cargo.toml --ci "$@"

echo
echo "Native installer artifacts:"
find sentinelpass-ui/src-tauri/target/release/bundle -type f \( \
  -name '*.AppImage' -o -name '*.deb' -o -name '*.rpm' -o -name '*.dmg' -o -name '*.pkg' -o -name '*.exe' -o -name '*.msi' \
\) -print | sort
