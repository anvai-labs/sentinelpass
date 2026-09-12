# Fuzz Targets (WBS-903 / TV-003)

Coverage-guided fuzzing for the four hostile-input parsers at SentinelPass's
trust boundaries. The targets are thin `#![no_main]` wrappers over the REAL
production parsers — no re-implementations, no mocks:

| Target | Production surface | Invariant |
| --- | --- | --- |
| `fuzz_envelope_open` | `crypto/envelope.rs` `open_envelope` / `open_envelope_relaxed_epoch` | arbitrary bytes → plaintext or typed error; never panic, never unbounded allocation (magic pre-scan, size/depth/ciphertext caps) |
| `fuzz_sync_mutation` | relay `handlers::sync_v2` decode + `validate_shape`, client `sync::v2::MutationV2` decode + `verify_mutation_mac` | decode/validate may reject, never panic; stateless per-mutation verdicts |
| `fuzz_ipc_frame` | `protocol::session` `parse_hello`/`parse_accept`/`SessionCrypto::open`, `windows_frame::decrypt_windows_ipc_frame` | hostile frames fail auth or are refused on counters; refused frames never mutate counter state; never panic |
| `fuzz_import_parse` | `import_export` `parse_json_import_bytes` / `parse_csv_import_bytes` | user-provided import files parse to entries or typed errors under the bounded line cap |

`corpus/` is seeded from the frozen envelope golden vector (the byte-exact
test vector in `crypto/envelope.rs`), realistic v2 push/mutation JSON, real
handshake frames, and actual export JSON/CSV shapes. Only curated seeds are
committed: libFuzzer writes every coverage-increasing input it finds into
the FIRST corpus directory, so point runs at a scratch corpus to keep the
repo clean —

```sh
cargo fuzz run fuzz_envelope_open -- /tmp/fuzz-corpus/envelope fuzz/corpus/fuzz_envelope_open -max_total_time=60
```

— or expect `fuzz/corpus/**` to accumulate local-only generated inputs that
must not be committed.

## Running

cargo-fuzz needs a NIGHTLY toolchain and the `cargo-fuzz` binary:

```sh
rustup toolchain install nightly
cargo install --locked cargo-fuzz

# from the repository root (fuzz/ is its own workspace, detached on purpose)
cargo fuzz run fuzz_envelope_open   -- -max_total_time=60
cargo fuzz run fuzz_sync_mutation   -- -max_total_time=60
cargo fuzz run fuzz_ipc_frame       -- -max_total_time=60
cargo fuzz run fuzz_import_parse    -- -max_total_time=60
```

A crash writes a reproducer under `fuzz/artifacts/<target>/`; any found
input must be minimized (`cargo fuzz tmin`) and turned into a regression
test in the owning crate's test module before the fix lands.

## Stable toolchain check (no fuzzing)

The targets must always COMPILE on stable (they are ordinary crates; only
the libFuzzer runtime run needs nightly):

```sh
cd fuzz && cargo check
```

## CI policy

Fuzzing is NOT on the required path: it needs nightly, and required jobs
must stay stable/predictable. The scheduled `fuzz.yml` workflow runs each
target for a bounded time (`-max_total_time`) on a weekly schedule and on
manual dispatch; findings land as artifacts, not gate failures.
