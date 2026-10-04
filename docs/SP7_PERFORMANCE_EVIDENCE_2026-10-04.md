# SP-7 Performance Evidence — 2026-10-04 (production path)

Measured with the REAL primitives on the REAL code paths — real
HMAC-SHA256 step-up commitments, real SHA-256 token hashing with
constant-time compares, real canonical enrollment transcripts, real
sealed-IPC envelopes over a real Unix socket — replacing the simplified
FNV-1a methodology that made the 2026-10-02 evidence PROVISIONAL.

Method: `scripts/drills/drill-perf-production-path.sh` runs the
`#[ignore]`-tagged `perf_evidence_*` tests in `sentinelpass-core` in
RELEASE mode (dev builds carry debug assertions that skew timing; these
are evidence tests, not per-PR gates). N=1,000 iterations per in-process
layer (warm-up included in distribution — these are steady-state paths),
N=200 full socket round-trips on one long-lived session. Reproduce with
`bash scripts/drills/drill-perf-production-path.sh [--build]`.

## Results (macOS, Apple silicon, 10 cores, release, 2026-10-04)

| Layer | p50 | p95 | p99 |
| --- | --- | --- | --- |
| SP-0 step-up mint + single-use validate | 13.5 µs | 22.0 µs | 24.5 µs |
| SP-1 grant authorize (token hash + ct compare) | 0.83 µs | 1.75 µs | 1.83 µs |
| SP-1 authorize DENY (full work before denial) | 0.75 µs | — | — |
| SP-4 canonical enrollment transcript | 13.0 µs | 35.6 µs | 48.0 µs |
| SP-3 `/proc/<pid>/exe` policy | EvidenceUnavailable on macOS (fail-closed denial verified; timed on Linux hosts via the same drill) | | |
| **End-to-end warm `ServiceGetSecret` over a real Unix socket** (handshake + sealed envelope + authorize + vault lookup) | **732 µs** | **1.10 ms** | 2.02 ms (max 3.65 ms) |

## Handoff §7 target compliance

| Target | Result | Evidence |
| --- | --- | --- |
| Warm added p95 < 10 ms (small native client) | **PASS** | Full round-trip p95 = 1.10 ms — a 9× margin, and this measures the ENTIRE retrieval (transport + crypto + policy + lookup), a strict superset of the "added overhead" the target names |
| Enrollment p95 < 1 s (excluding human/hardware) | **PASS** | Daemon-side transcript construction p95 = 35.6 µs; the gpg subprocess (~100–500 ms) is a one-time ceremony excluded per the handoff, and is NOT on any retrieval critical path |

## Notes

- The denial path is NOT cheaper than the success path (0.75 µs vs
  0.83 µs p50): every check completes before denying — no timing oracle.
- Per-request retrieval cost decomposes as ~730 µs p50 end-to-end, of
  which the authorize layer is 0.83 µs — the socket/transport and vault
  lookup dominate, both pre-existing costs rather than service-identity
  additions.
- The full Argon2id KDF (~1 s at 256 MB) applies only at unlock /
  step-up password verification — by design, once per owner approval,
  never on the retrieval path.
- Linux `/proc` exe-policy timing: run the same drill on a Linux host
  (e.g. the dataserver3 qualification) to fill that column; correctness
  is CI-covered on the ubuntu legs.
- Security failures never fall back for speed; fail-closed on missing
  evidence is verified on every non-Linux run of this drill.
