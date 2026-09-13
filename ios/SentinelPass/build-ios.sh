#!/bin/bash
# Build the SentinelPass mobile bridge static libraries for iOS and populate
# SentinelPass/Native/libs/ for the SentinelPassApp (app) and
# SentinelPassCredential (credential-provider extension) Xcode targets.
#
# ADR-009 rev 2: no bridge binaries are committed — this script is the
# consumer-side generator. Run it once after cloning, and after any change
# to sentinelpass-mobile-bridge (the C header contract is re-copied too,
# keeping ios/SentinelPass/SentinelPass/Native/include in drift-check sync).
#
# Usage:
#   cd ios/SentinelPass && ./build-ios.sh            # both targets (default)
#   ONLY_SIM=1 ./build-ios.sh                        # simulator only

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REPO_ROOT="$(cd "$SCRIPT_DIR/../.." && pwd)"
BRIDGE_CRATE="$REPO_ROOT/sentinelpass-mobile-bridge"
LIBS_DIR="$SCRIPT_DIR/SentinelPass/Native/libs"
INCLUDE_DIR="$SCRIPT_DIR/SentinelPass/Native/include"

echo "=== SentinelPass iOS bridge build ==="
echo "Repo root:   $REPO_ROOT"
echo "Bridge crate: $BRIDGE_CRATE"

command -v cargo >/dev/null 2>&1 || { echo "ERROR: cargo not found on PATH" >&2; exit 1; }

mkdir -p "$LIBS_DIR" "$INCLUDE_DIR"

copy_lib() { # $1 = rust target triple, $2 = output library suffix
    local triple="$1" suffix="$2"
    local lib_src="$REPO_ROOT/target/$triple/release/libsentinelpass_mobile_bridge.a"
    local lib_dst="$LIBS_DIR/libsentinelpass_mobile_bridge_$suffix.a"
    if [ ! -f "$lib_src" ]; then
        echo "ERROR: expected bridge library not found at $lib_src" >&2
        exit 1
    fi
    cp "$lib_src" "$lib_dst"
    echo "  ✓ $lib_dst"
}

# 1. Simulator (arm64). Fallback list keeps Intel Macs working.
echo ""
echo "1. Building bridge for iOS Simulator (aarch64-apple-ios-sim)..."
rustup target add aarch64-apple-ios-sim >/dev/null
cargo build --package sentinelpass-mobile-bridge \
    --target aarch64-apple-ios-sim --release
copy_lib aarch64-apple-ios-sim ios_sim

# 2. Device (arm64) — optional unless ONLY_SIM=1.
if [ "${ONLY_SIM:-0}" != "1" ]; then
    echo ""
    echo "2. Building bridge for iOS device (aarch64-apple-ios)..."
    rustup target add aarch64-apple-ios >/dev/null
    cargo build --package sentinelpass-mobile-bridge \
        --target aarch64-apple-ios --release
    copy_lib aarch64-apple-ios ios
else
    echo ""
    echo "2. Skipping device build (ONLY_SIM=1)."
    echo "   NOTE: device builds in Xcode will fail until"
    echo "   libsentinelpass_mobile_bridge_ios.a exists."
fi

# 3. Refresh the copied C header from the generated contract.
echo ""
echo "3. Copying generated header contract..."
cp "$BRIDGE_CRATE/include/sentinelpass_bridge.h" "$INCLUDE_DIR/sentinelpass_bridge.h"
echo "  ✓ $INCLUDE_DIR/sentinelpass_bridge.h"

echo ""
echo "=== Done. Open ios/SentinelPass/SentinelPassApp.xcodeproj and build. ==="
