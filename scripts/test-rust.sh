#!/usr/bin/env bash
set -euo pipefail

REPO_ROOT="$(git rev-parse --show-toplevel)"
cd "$REPO_ROOT"

export CARGO_INCREMENTAL=0
export CARGO_TARGET_DIR="${CARGO_TARGET_DIR:-/tmp/sentinelpass-target}"
mkdir -p "$CARGO_TARGET_DIR"

# Per-invocation TMPDIR: a single persistent .tmp accumulated weeks of
# fixtures from older branches and deterministically broke
# fixture-lifetime tests (see #212); each run now gets a fresh root.
TMP_ROOT="$CARGO_TARGET_DIR/.tmp/run-$$"
mkdir -p "$TMP_ROOT"
export TMPDIR="$TMP_ROOT"
export TMP="$TMP_ROOT"
export TEMP="$TMP_ROOT"
export RUSTC_TMPDIR="$CARGO_TARGET_DIR/.rustc-tmp"
mkdir -p "$RUSTC_TMPDIR"

echo "[rust] cargo test --workspace --exclude sentinelpass-ui"
cargo test --workspace --exclude sentinelpass-ui --verbose
