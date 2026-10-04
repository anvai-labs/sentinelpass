# SP-7 Performance Evidence — 2026-10-02

> **SUPERSEDED (2026-10-04):** the FNV-1a methodology limitation noted
> below is closed by `docs/SP7_PERFORMANCE_EVIDENCE_2026-10-04.md` —
> measured with real primitives on the real code paths (including a full
> real-socket round trip). This document is retained as the honest record
> of the provisional claim and its correction.

Benchmarks run on the development host (macOS, 10 cores) with a standalone
Rust binary (`-O` optimization, warm-cache steady state, 10k–100k iterations,
warm-up discarded). SP-3 (executable hashing) runs on CI's Linux legs where
`/proc/<pid>/exe` exists. Full methodology per the Sandesha handoff §7.

## Results

| Layer | Operation | p50 | p95 | p99 |
| --- | --- | --- | --- | --- |
| SP-2 | Provenance token construction | 0.08 µs | 0.08 µs | 0.12 µs |
| SP-0 | HMAC-SHA256 commitment (~200 B op) | 0.04 µs | 0.04 µs | 0.08 µs |
| SP-4 | Canonical transcript construction (~300 B) | 0.00 µs | 0.04 µs | 0.04 µs |
| SP-1 | Token hash + constant-time compare | 0.00 µs | 0.04 µs | 0.04 µs |
| SP-3 | `/proc/<pid>/exe` SHA-256 (full binary) | I/O-bound by binary size — not per-request logic | | |

## Handoff §7 target assessment (corrected per the adoption handoff P2)

> **Correction (Sandesha adoption handoff):** the original version of this
> document labeled both targets as PASS based on benchmarks that
> substituted FNV-1a for SHA-256/HMAC. Those samples do NOT establish
> production cryptographic-primitive, real executable-hashing, daemon-IPC,
> or gpg-enrollment latency. The corrected assessment is:

| Target | Assessment | Basis |
| --- | --- | --- |
| Warm added p95 < 10 ms (small native client) | **PROVISIONAL** | Sub-µs measurements used simplified hash primitives, not production SHA-256/HMAC/ct_eq. Real primitives on ~200-byte inputs are well-documented as sub-µs on modern hardware, and the Argon2id KDF (~1 s at 256 MB) applies only at unlock/step-up password verification, not on the retrieval path. A production-path benchmark with real primitives remains follow-up work. |
| Enrollment p95 < 1 s (excluding human/hardware) | **PROVISIONAL** | Daemon-side transcript+HMAC is sub-µs; the gpg subprocess (~100–500 ms) dominates. No production-path timing has been recorded; the gpg happy-path test in `enrollment.rs` exercises the full lifecycle but does not measure latency. A timed benchmark remains follow-up work. |

## Notes

- Enrollment signatures are **not** on every retrieval's critical path —
  the per-request cost after enrollment is: token verify (SHA-256 + ct_eq)
  + optional exe-policy check (one file hash). Both are sub-ms.
- **Methodology limitation (P2 correction):** the benchmark used FNV-1a
  as a timing proxy for SHA-256/HMAC. Production implementations use
  the `sha2` and `subtle` crates; for these small payloads the
  production cost is expected to remain sub-millisecond on modern
  hardware, but this has NOT been measured on the production code path.
  A follow-up benchmark using the real primitives and real IPC is
  required before claiming target compliance.
- The full Argon2id KDF cost (~1 s at 256 MB) applies only at
  unlock/step-up password verification, not on the retrieval path.
- Security failures never fall back for speed: every denial path
  (step-up, exe-policy mismatch, token invalid) completes the full
  check before denying.

## Platform support matrix (SP-0–SP-4)

| Feature | Linux | macOS | Windows |
| --- | --- | --- | --- |
| SP-0 master-password step-up | ✅ | ✅ | ✅ |
| SP-1 exact-entry service grants | ✅ | ✅ | ✅ |
| SP-2 trusted peer context (uid+gid+pid) | ✅ full | ✅ uid+gid only | ✅ unknown marker |
| SP-3 executable policy (`/proc/<pid>/exe`) | ✅ full | ❌ (deny: evidence unavailable) | ❌ (deny: evidence unavailable) |
| SP-4 OpenPGP enrollment (pinned gpg) | ✅ (if gpg present) | ✅ (if gpg present) | ✅ (if gpg present) |
