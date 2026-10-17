#!/usr/bin/env bash
# Metadata-only host probes. Never opens a vault or an OS keystore.
set -euo pipefail
if [[ "$(uname -s)" != Darwin ]]; then
  echo "This probe qualifies the macOS host JVM and Swift/C ABI only." >&2
  exit 1
fi
custody_test_dir=$(mktemp -d "${TMPDIR:-/tmp}/sentinelpass-custody.XXXXXX")
trap 'rm -rf "$custody_test_dir"' EXIT
cargo build -p sentinelpass-mobile-bridge --features jni
javac -d "$custody_test_dir/jvm" tests/native/custody/com/sentinelpass/custody/CustodyContract.java
java -cp "$custody_test_dir/jvm" com.sentinelpass.custody.CustodyContract \
  target/debug/libsentinelpass_mobile_bridge.dylib bindings/custody
swiftc -module-cache-path "$custody_test_dir/swift-cache" \
  -import-objc-header sentinelpass-mobile-bridge/include/sentinelpass_bridge.h \
  -L target/debug -lsentinelpass_mobile_bridge \
  -Xlinker -rpath -Xlinker "$PWD/target/debug" \
  bindings/custody/CustodyContract.swift tests/native/custody/main.swift \
  -o "$custody_test_dir/swift-probe"
"$custody_test_dir/swift-probe" bindings/custody
