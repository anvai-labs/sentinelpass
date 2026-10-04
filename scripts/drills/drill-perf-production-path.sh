#!/usr/bin/env bash
# SP-7 production-path performance drill (ADR-013..017; handoff §7 targets;
# supersedes the FNV-1a provisional methodology flagged in
# docs/SP7_PERFORMANCE_EVIDENCE_2026-10-02.md).
#
# Measures the REAL primitives on the REAL code paths, in RELEASE mode:
#   1. step-up mint + single-use validate (real HMAC-SHA256 commitment);
#   2. service-grant authorize (real SHA-256 token hash + constant-time
#      compare), including the full-work denial path;
#   3. canonical enrollment transcript construction (real serde + sha2);
#   4. executable policy over the real /proc/<pid>/exe (Linux; other
#      platforms deny fail-closed with EvidenceUnavailable — verified,
#      not timed);
#   5. warm end-to-end ServiceGetSecret over a REAL Unix socket (session
#      handshake + sealed envelope + authorize + vault lookup).
#
# Targets (handoff §7): warm retrieval p95 < 10 ms; enrollment ceremony
# (excluding the gpg subprocess, which is human/hardware-bound and a
# one-time event) p95 < 1 s. Assertions live in the tests themselves.
#
# Prerequisites: RELEASE build of the workspace tests.
#   cargo test --release -p sentinelpass-core --no-run
# The script does NOT build by default.
# Flags: --build   run the release test build first.
# Env:   DRILL_REPORT_DIR (default: invocation directory).
# Usage: bash scripts/drills/drill-perf-production-path.sh [--build]
#
# Evidence: writes perf-production-path-<timestamp>.txt (the test output
# with the percentile tables) next to this script's invocation dir; exit 0
# = all targets met.

set -euo pipefail

REPO_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
cd "$REPO_ROOT"

if [[ "${1:-}" == "--build" ]]; then
    cargo test --release -p sentinelpass-core --no-run
fi

REPORT_DIR="${DRILL_REPORT_DIR:-$PWD}"
TS="$(date -u +%Y%m%dT%H%M%SZ)"
REPORT="$REPORT_DIR/perf-production-path-$TS.txt"

# --ignored selects the #[ignore] perf-evidence tests (they are evidence,
# not per-PR gates); --test-threads=1 keeps the socket test's runtime
# exclusive for stable timings.
cargo test --release -p sentinelpass-core perf_evidence -- --ignored --nocapture --test-threads=1 2>&1 | tee "$REPORT"

# Fail if the harness reported any failure (tee hides the exit code).
if grep -qE "test result: FAILED|panicked at" "$REPORT"; then
    echo "FAIL: perf drill assertions failed — see $REPORT" >&2
    exit 1
fi
echo "PASS: production-path performance targets met — evidence at $REPORT"
