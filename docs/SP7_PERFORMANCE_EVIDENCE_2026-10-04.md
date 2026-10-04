# SP-7 Performance Evidence — 2026-10-04 (production path)

Measured with the REAL primitives on the REAL code paths — real
HMAC-SHA256 step-up commitments, real SHA-256 token hashing with
constant-time compares, real canonical enrollment transcripts, real
sealed-IPC envelopes over a real Unix socket, and the real pinned-gpg
enrollment verification — replacing the simplified FNV-1a methodology
that made the 2026-10-02 evidence PROVISIONAL.

Method: `scripts/drills/drill-perf-production-path.sh` runs the
`#[ignore]`-tagged `perf_evidence_*` tests in `sentinelpass-core`
(release build; the tests label themselves if run in debug) with
`--test-threads=1` — REQUIRED: the tests set the platform base-dir
override (first-write-wins: the first test's temp root serves the whole
process, which is still always a drill temp root — operator state is
never touched under any execution order) and the enrollment ceremony
uses process-global gpg state. N=1,000 per in-process layer, N=200 socket
round-trips, N=3 gpg verifications. Reproduce with
`bash scripts/drills/drill-perf-production-path.sh [--build]`
(`SENTINELPASS_GPG_PATH` pins gpg on hosts without `/usr/bin/gpg`).

## Results (macOS, Apple silicon, 10 cores, release, 2026-10-04)

| Layer | p50 | p95 | p99 |
| --- | --- | --- | --- |
| SP-0 step-up mint + single-use validate | 13.5 µs | 22.0 µs | 24.5 µs |
| SP-1 grant authorize (token hash + ct compare) | 0.83 µs | 1.75 µs | 1.83 µs |
| SP-1 authorize DENY (wrong token, full work) | 0.75 µs | sampled at N=1,000 — distribution overlaps the success path | |
| SP-4 canonical enrollment transcript | 13.0 µs | 35.6 µs | 48.0 µs |
| SP-4 gpg verification (import + detached verify, real subprocess) | — | — | 572–578 ms (N=3, min–max) |
| SP-3 `/proc/<pid>/exe` policy | EvidenceUnavailable on macOS (fail-closed denial verified; sampled timing on Linux hosts via the same drill) | | |
| **End-to-end `ServiceGetSecret` over a real Unix socket** | **732 µs** | **1.10 ms** | 2.02 ms (max 3.65 ms) |

## Handoff §7 target compliance

| Target | Result | Evidence |
| --- | --- | --- |
| Warm retrieval p95 < 10 ms (small native client) | **PASS** | p95 = 1.10 ms — a 9× margin. Honesty note: each sample includes reconnect + full session handshake (HKDF directional keys) because `IpcClient::send` connects per call and this client API has no long-lived-session mode — a CONSERVATIVE SUPERSET of steady-state native-client cost |
| Enrollment p95 < 1 s (daemon-side) | **PASS (measured)** | Transcript 35.6 µs + the real pinned-gpg verification 572–578 ms — the whole daemon-side ceremony is measured, ≈0.6 s against the 1 s budget. The gpg subprocess is daemon-run, not human/hardware-bound (earlier drafts said otherwise — corrected); the human/network parts of the ceremony (key generation, delivering the signature) remain outside the daemon and outside this measurement |

## Notes

- **Denial is not observably cheaper than success**: the wrong-token
  denial performs the same SHA-256 hash and the same-length
  constant-time compare before refusing (verified in code,
  `service_grants.rs` authorize); the sampled distributions overlap
  (deny p50 0.75 µs vs success 0.83 µs — the ~90 ns difference is below
  measurement noise). We rest the no-timing-oracle claim on this
  structure, not on the timing samples. One denial shape does
  short-circuit BEFORE the compare — wrong client_id/entry/field is
  rejected by the pre-filter after the SHA-256 hash but without the
  constant-time compare; that shape reveals only that no grant matches,
  never anything about a token.
- **What the residual is**: the 732 µs p50 round-trip decomposes into
  socket + handshake + sealed-frame crypto + authorize (0.83 µs) + the
  per-request grant-store load from disk (JSON read) + vault entry
  snapshot verification and AES-GCM decrypt + two audit appends. The
  service-identity additions inside that are authorize + the grant-store
  load; the rest is pre-existing retrieval cost.
- **In-process layers are conservative, not steady-state i.i.d.**:
  step-up `mint` and enrollment `begin` retain-scan a map that
  accumulates consumed-but-unexpired entries within the TTL, so
  per-sample cost drifts upward with iteration index at these Ns.
- The full Argon2id KDF (~1 s at 256 MB) applies only at unlock /
  step-up password verification — by design, once per owner approval,
  never on the retrieval path.
- Linux `/proc` exe-policy timing: run the same drill on a Linux host to
  fill that column; correctness is CI-covered on the ubuntu legs.
- **Two product defects found and fixed by this drill** (in
  `daemon/enrollment.rs`): (1) the isolated keyring was created with
  default permissions — gpg ≥ 2.4 refuses a group/other-readable
  `--homedir`, so enrollment verification failed outright on modern
  hosts (CI's older gpg only warned); now pinned 0700. (2) gpg's agent
  socket exceeds the unix `sun_path` budget on macOS `/var/folders`
  temp paths — verification now falls back to a short `/tmp` base when
  the projected socket path is too long.
- The first cut of this drill (before isolation) wrote one synthetic
  grant into the operator's real grant store and appended 600 synthetic
  events to the real audit log on the development Mac (2026-10-04
  ~05:57). The bogus grant was removed; the audit chain is append-only
  and was NOT rewritten — the events remain as the incident record.
  Current tests pin all platform dirs and cannot recur this.
