#!/usr/bin/env bash
# Exercise the release verifier against the actual artifact and tampered copies.
set -euo pipefail
test "$#" -eq 2
source_app="$1"
version="$2"
script_dir="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
test_dir=$(mktemp -d)
trap 'rm -rf "$test_dir"' EXIT

bash "$script_dir/verify-macos-app.sh" "$source_app" "$version"
for mutation in info resource helper missing_helper missing_seal; do
  candidate="$test_dir/$mutation/SentinelPass.app"
  mkdir -p "$(dirname "$candidate")"
  ditto "$source_app" "$candidate"
  case "$mutation" in
    info) plutil -replace CFBundleName -string Tampered "$candidate/Contents/Info.plist" ;;
    resource) printf 'unexpected resource\n' > "$candidate/Contents/Resources/injected.txt" ;;
    helper) printf '\ntampered\n' >> "$candidate/Contents/Resources/src-tauri/resources/bin/sentinelpass-host" ;;
    missing_helper) rm "$candidate/Contents/Resources/src-tauri/resources/bin/sentinelpass-host" ;;
    missing_seal) rm "$candidate/Contents/_CodeSignature/CodeResources" ;;
  esac
  if bash "$script_dir/verify-macos-app.sh" "$candidate" "$version" > "$test_dir/$mutation.log" 2>&1; then
    echo "ERROR: verifier accepted $mutation tampering" >&2
    exit 1
  fi
  echo "Rejected $mutation tampering"
done
if bash "$script_dir/verify-macos-app.sh" "$source_app" invalid-version > "$test_dir/version.log" 2>&1; then
  echo "ERROR: verifier accepted the wrong release version" >&2
  exit 1
fi
echo "Rejected wrong release version"
