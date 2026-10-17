#!/usr/bin/env bash
# Exercise published-crate fixtures without access to workspace parent files.
set -euo pipefail
repo_root="$(git rev-parse --show-toplevel)"
cd "$repo_root"
probe_dir="$(mktemp -d "${TMPDIR:-/tmp}/sentinelpass-protocol-package.XXXXXX")"
trap 'rm -rf "$probe_dir"' EXIT
# --no-verify avoids a redundant library build; the extracted tests below
# compile the library and all custody test inputs instead.
cargo package -p sentinelpass-protocol --locked --no-verify --target-dir "$probe_dir/build" "$@"
archive=("$probe_dir"/build/package/sentinelpass-protocol-*.crate)
test "${#archive[@]}" -eq 1
tar -xzf "${archive[0]}" -C "$probe_dir"
manifest=("$probe_dir"/sentinelpass-protocol-*/Cargo.toml)
test "${#manifest[@]}" -eq 1
export CARGO_TARGET_DIR="${CARGO_TARGET_DIR:-$repo_root/target}"
cargo test --manifest-path "${manifest[0]}" --locked --test custody_contract
cargo run --manifest-path "${manifest[0]}" --locked --example check_sandesha_binding
