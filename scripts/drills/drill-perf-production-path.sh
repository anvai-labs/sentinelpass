#!/usr/bin/env bash
# SP-7 production-path performance drill (ADR-013..017; handoff §7 targets;
# supersedes the FNV-1a provisional methodology flagged in
# docs/SP7_PERFORMANCE_EVIDENCE_2026-10-02.md).
#
# Measures the REAL primitives on the REAL code paths:
#   1. step-up mint + single-use validate (real HMAC-SHA256 commitment);
#   2. service-grant authorize (real SHA-256 token hash + constant-time
#      compare), including the full-work denial path (sampled, N equals
#      the success path);
#   3. canonical enrollment transcript construction (real serde + sha2);
#   4. executable policy over the real /proc/<pid>/exe (Linux, sampled;
#      other platforms verify the fail-closed EvidenceUnavailable denial);
#   5. end-to-end ServiceGetSecret over a REAL Unix socket — note each
#      sample includes reconnect + session handshake (the client API has
#      no long-lived-session mode): a conservative superset of steady
#      state;
#   6. enrollment gpg verification (two real pinned-gpg subprocesses:
#      key import + detached verify) where gpg is available.
#
# Targets (handoff §7): retrieval p95 < 10 ms; enrollment (daemon-side,
# measured incl. gpg) p95 < 1 s. Assertions live in the tests themselves.
#
# Prerequisites: RELEASE build of the workspace tests (a debug build runs
# but its timings are labeled as such by the tests).
#   cargo test --release -p sentinelpass-core --no-run
# The script does NOT build by default.
# Flags: --build              run the release test build first.
#        --skip-gpg           force the gpg timing test to skip.
# Env:   DRILL_REPORT_DIR     (default: the INVOCATION directory, not the
#                             repo root the script cds into),
#        SENTINELPASS_GPG_PATH  pinned gpg binary (e.g. /opt/homebrew/bin/gpg
#                             on macOS hosts without /usr/bin/gpg).
# Usage: bash scripts/drills/drill-perf-production-path.sh [--build]
#
# The tests pin ALL platform dirs (grants/audit/config) into their own
# temp dirs (review B1/S4) and therefore REQUIRE --test-threads=1 (the
# drill enforces it).
# Evidence: perf-production-path-<timestamp>.txt next to the invocation
# dir; exit 0 = all targets met AND the expected tests actually ran.

set -euo pipefail

INVOCATION_DIR="$PWD"
REPO_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
cd "$REPO_ROOT"

BUILD=0
SKIP_GPG=0
for arg in "$@"; do
    case "$arg" in
        --build) BUILD=1 ;;
        --skip-gpg) SKIP_GPG=1 ;;
        *) echo "unknown flag: $arg (supported: --build)" >&2; exit 2 ;;
    esac
done
if [[ "$SKIP_GPG" == 1 ]]; then
    export SENTINELPASS_GPG_PATH="${SENTINELPASS_GPG_PATH:-/nonexistent-gpg}"
fi

if [[ "$BUILD" == 1 ]]; then
    cargo test --release -p sentinelpass-core --no-run
fi

REPORT_DIR="${DRILL_REPORT_DIR:-$INVOCATION_DIR}"
TS="$(date -u +%Y%m%dT%H%M%SZ)"
REPORT="$REPORT_DIR/perf-production-path-$TS.txt"

# pipefail propagates cargo's exit status through tee; --test-threads=1 is
# REQUIRED (process-global platform-dir pinning in the tests).
cargo test --release -p sentinelpass-core perf_evidence -- --ignored --nocapture --test-threads=1 2>&1 | tee "$REPORT"

# Review S5: a filter that matches ZERO tests exits 0 — a silent no-op
# PASS. Require the positive test count (3 perf tests; the gpg one
# self-skips when gpg is absent but still reports "ok").
if ! grep -qE "test result: ok\. 3 passed" "$REPORT"; then
    echo "FAIL: expected exactly 3 perf-evidence tests to run — see $REPORT" >&2
    exit 1
fi
if grep -qE "test result: FAILED|panicked at" "$REPORT"; then
    echo "FAIL: perf drill assertions failed — see $REPORT" >&2
    exit 1
fi
echo "PASS: production-path performance targets met — evidence at $REPORT"
