#!/usr/bin/env bash
# Verify the shipped bundle without executing code or opening a user vault.
set -euo pipefail

if [ "$#" -ne 2 ]; then
  echo "Usage: $0 APP EXPECTED_VERSION" >&2
  exit 2
fi
app="$1"
expected_version="$2"
info="$app/Contents/Info.plist"
test "$(plutil -extract CFBundleIdentifier raw "$info")" = "com.sentinelpass.app"
test "$(plutil -extract CFBundleShortVersionString raw "$info")" = "$expected_version"
test "$(plutil -extract CFBundleExecutable raw "$info")" = "sentinelpass-ui"

for relative in \
  Contents/MacOS/sentinelpass-ui \
  Contents/Resources/src-tauri/resources/bin/sentinelpass-daemon \
  Contents/Resources/src-tauri/resources/bin/sentinelpass-host; do
  binary="$app/$relative"
  test -s "$binary" && test -x "$binary"
  test "$(lipo -archs "$binary")" = "arm64"
  codesign --verify --strict --verbose=2 "$binary"
done

# A linker-signed executable alone is insufficient: the app must also seal
# Info.plist and every bundled resource, even in the ad-hoc release mode.
if [ ! -s "$app/Contents/_CodeSignature/CodeResources" ]; then
  echo "ERROR: app has no sealed resource manifest" >&2
  exit 1
fi
codesign --verify --deep --strict --verbose=2 "$app"
echo "Verified sealed SentinelPass $expected_version app and both arm64 helpers"
