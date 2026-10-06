#!/usr/bin/env bash
set -euo pipefail

REPO_ROOT="$(git rev-parse --show-toplevel)"
cd "$REPO_ROOT"

MIN_LINES="${RUST_COVERAGE_MIN:-50}"

export CARGO_INCREMENTAL=0
export CARGO_TARGET_DIR="${CARGO_TARGET_DIR:-/tmp/sentinelpass-target}"
mkdir -p "$CARGO_TARGET_DIR"

TMP_ROOT="$CARGO_TARGET_DIR/.tmp"
mkdir -p "$TMP_ROOT"
export TMPDIR="$TMP_ROOT"
export TMP="$TMP_ROOT"
export TEMP="$TMP_ROOT"
export RUSTC_TMPDIR="$CARGO_TARGET_DIR/.rustc-tmp"
mkdir -p "$RUSTC_TMPDIR"

if ! cargo llvm-cov --version >/dev/null 2>&1; then
  echo "[rust] cargo-llvm-cov is required. Install with: cargo install cargo-llvm-cov --locked"
  exit 1
fi

mkdir -p target/llvm-cov

echo "[rust] Running LLVM coverage (line threshold: ${MIN_LINES}%)"
# Build with specific features. The x11 flag is a documented no-op since
# the native-autofill retirement (docs/NATIVE_AUTOFILL_RETIREMENT_2026-10-05.md);
# sync is the only optional feature that links extra code.
if [[ "$(uname)" == "Linux" ]]; then
  # Enable sync; the x11 no-op flag needs no system libraries
  FEATURES="--features sentinelpass-core/sync"
else
  # On macOS/Windows, use default features
  FEATURES=""
fi

cargo llvm-cov \
  --workspace \
  --exclude sentinelpass-ui \
  --exclude sentinelpass-relay \
  $FEATURES \
  --lcov \
  --output-path target/llvm-cov/lcov.info \
  --fail-under-lines "${MIN_LINES}" \
  --ignore-filename-regex '(sentinelpass-cli/src/main\.rs|sentinelpass-daemon/src/main\.rs|sentinelpass-host/src/main\.rs|sentinelpass-relay/|sync/(client|engine)\.rs)' \
  --summary-only

echo "[rust] Coverage report generated at target/llvm-cov/lcov.info"
