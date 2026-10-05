# Security Review: SentinelPass v0.16.0

**Scope**: full diff `v0.15.1..v0.16.0` (14 files, ~2,006 lines) plus the pre-existing modules the release builds on (`service_grants.rs`, `stepup.rs`, `exe_policy.rs`, `audit.rs`, transport).
**Reviewer**: Claude Code (agentbrowser session — cross-repo adversarial review).
**Date**: 2026-10-04.
**Verdict**: needs fixes — no blockers; the exact-entry service-grant surface is sound and unusually well-tested. Five MAJOR findings below.

---

## MAJOR findings

### M1 — Strict-profile read containment is overstated

**Location**: `sentinelpass-core/src/daemon/ipc/server.rs:1196-1204` (the strict denial comment and claim) vs `server.rs:2407-2432` (the catch-all dispatch arm that serves `EntryGet` without gate or audit).

**What the code says**: the `GetExternalSecret` strict denial states: "A caller that unsets SENTINELPASS_REQUIRE_STEPUP, or edits external-secret-access.json directly, gains nothing: this daemon refuses to SERVE legacy grants. Exact-entry service grants ... are the **only retrieval surface under strict**."

**What actually happens**: any caller with the same two credentials (daemon IPC auth token + same-UID Unix socket) can invoke `ServiceCall(VaultOp::EntryGet { entry_id })`. `EntryGet` classifies `requires_admin_step_up() == false` (`sentinelpass-protocol/src/service.rs:556`), so the step-up gate at `server.rs:2127` is skipped entirely. `dispatch_service_call` routes it through the catch-all arm to `LiveVaultService::execute_op` → `entry_to_wire` (`service.rs:141-143, 627-639`), which returns the **full plaintext entry including the password**. No daemon-layer audit with peer provenance is emitted (the vault layer logs `CredentialViewed` but without client identity or peer token).

**Impact**: the strict-profile containment is a policy-forcing measure (migrating callers to the audited exact-entry path), not a containment boundary. A compromised same-UID tool reads the entire vault unaudited whether or not strict is on. This is pre-existing surface (ADR-013: "SP-0 is a MUTATION gate, not read containment"), but the release's headline claim and `docs/SERVICE_CREDENTIALS.md` oversell it.

**What IS real and valuable**: the write/capture surfaces (`SaveSecret`, `SaveCredential`, `GrantSitePermission`, `RevokeSitePermission`, bare `SyncNow`) are denied outright under strict, and the service-grant path itself is sound.

**Fix options** (each with tradeoffs):

| Option | What | Pros | Cons |
|---|---|---|---|
| (a) Audit | Add `log_daemon_audit` for sensitive-read ops (`EntryGet`, `SshKeyGet`, `TotpCode`) with `peer.provenance_token()`, mirroring the `ServiceGetSecret` pattern at `server.rs:270-290` | Preserves ADR-013's read model; fixes the forensic gap | Does not close the bypass |
| (b) Step-up | Require step-up for `EntryGet` under strict | Honest enforcement | Contradicts ADR-013's "reads are unattended-safe"; extremely chatty for CLI/UI; prompts from untrusted VPS contexts |
| (c) Deny | Mirror the `GetExternalSecret` denial | Strongest | Can't distinguish owner CLI from attacker (PeerContext = uid/pid only); breaks `credentials.rs` flows |

**Recommended**: option (a) plus correcting the misleading denial copy and `docs/SERVICE_CREDENTIALS.md` to state the actual boundary.

---

### M2 — `ServiceEnrollmentBegin` is unaudited

**Location**: `sentinelpass-core/src/daemon/ipc/server.rs:468-527`.

The handler mints an enrollment challenge — an owner act on the grant-policy lifecycle — with **no `log_daemon_audit` call** on the success path or on either denial path (no-pending-grant at 491, store-unavailable at 477). Every comparable op (create at :423, revoke at :726, enrollment-complete at :654) audits.

**Fix**: un-underscore `_peer` (the handler already receives `PeerContext`) and add audit on the success path (`ExternalSecretAccess { domain: "enrollment", purpose: "enrollment:challenge_minted" }`) and on both denial paths, mirroring the `service_enrollment_complete` pattern at `server.rs:615-625`.

---

### M3 — CLI panic on multi-byte `--expires-in`

**Location**: `sentinelpass-cli/src/commands/service_grant.rs:119`.

`duration.split_at(duration.len() - 1)` takes a byte index and panics when it lands inside a multi-byte character. `--expires-in "5日"` (len 6, split_at(5) inside the 日 char) → `byte index 5 is not a char boundary` panic. Reachable from `handle_create` via a malformed user flag.

**Fix**: use `duration.chars().next_back()` + `strip_suffix(unit)` (the standard char-boundary-safe pair). Drop the byte-length guard — `"m"` alone fails cleanly at `parse()`. Add `"日"` and `"5日"` cases to `expiry_parses_units_and_rejects_garbage`.

---

### M4 — `store_error` reported as "denied"

**Location**: `sentinelpass-cli/src/commands/service_grant.rs:87-109` (`report_error`).

The daemon deliberately distinguishes `store_error` ("NOT published — the grant is still live on disk" for revoke, `server.rs:736-738`) from authz denials. The CLI's `report_error` funnels it into the catch-all: `"daemon denied the operation (status: store_error)"`. An operator told "denied" on a revoke will believe the grant is dead while it is still active. On create, "denied" invites a retry that mints a duplicate pending grant.

**Fix**: add a `"store_error"` arm: `"grant-store write failed — the change was NOT persisted; treat the grant's state as unchanged (a revoked grant is still live; a created grant may not exist — check state before retrying)"`. Extend `report_error_classifies_statuses` (:442-470) with a `store_error` case asserting the message does NOT contain "denied" and DOES mention persistence.

---

### M5 — `SP_KEEP_ENROLL_TMP` silently disables cleanup

**Location**: `sentinelpass-core/src/daemon/enrollment.rs:175-178`.

When set, the enrollment temp dir (containing the transcript: client_id, entry_id, grant_id, nonce, fingerprint in cleartext) persists past the ceremony with no log. `remove_dir_all` failures are also swallowed (`let _ =`). The env var is referenced nowhere else in the repo and appears in no docs.

**Fix**: in the `Drop` guard, when the env var is set emit `tracing::warn!(path = %self.0.display(), "SP_KEEP_ENROLL_TMP set — enrollment temp dir NOT removed")`. Also warn on `remove_dir_all` failure. `tracing` is already a dependency (`sentinelpass-core/Cargo.toml:32`) and the daemon initializes a subscriber.

---

## INFO findings

| # | Observation |
|---|---|
| I1 | Token display goes to stdout (scrollback/shell history); stderr or a `read -s` recipe would be tighter |
| I2 | client_id charset discipline diverges between legacy (validated) and service-grant (raw) surfaces — consistency, not vulnerability |
| I3 | Legacy `verify_client_token` returns `true` for no-token-record clients — legacy grants minted without a token are usable tokenless; strict denies the surface anyway |
| I4 | Temp-dir create-then-chmod window (umask mode, then 0700); directory is empty during the window so no exposure; `OpenOptions`-with-mode would close it |
| I5 | Signing-subkey fingerprint mismatch fails closed (safe direction) — worth a doc line |
| I6 | No `service-grant list` command; inventory requires reading the 0600 store file |
| I7 | Zeroization residuals (String displaced not zeroized; IPC-path copies) — disclosed and accepted, same class as every String-based IPC payload |
| I8 | Perf evidence sound; caveats: authorize measured against one-grant store (real cost O(all grants)); 10ms budget assertions apply in debug too (drill pins release) |

---

## Positive security properties verified

1. **Authoritative daemon-side strict denial** — checked before any allowlist load or unlock state; test stages a valid legacy grant + token and asserts refusal
2. **Entry scoping is real** — exact client_id + entry_id + field; store fails closed on unknown fields, unknown `policy_version`, duplicate grant ids
3. **Token handling** — OsRng 256-bit, `sps_` prefix separating from legacy `spt_`, SHA-256 at rest, `subtle` ct_eq, shown once, `PENDING_TOKEN_HASH` placeholder can never authorize
4. **Step-up** — minted after full Argon2id vault-open; 60s TTL; single-use; connection+operation-bound HMAC-SHA256; escalating throttle; exhaustive per-variant classification (no wildcard)
5. **Enrollment ceremony** — single-use 256-bit nonce consumed before verification; revocation re-checked inside the lock after the gpg window; isolated 0700 keyring with `--no-default-keyring`
6. **Direct-vault compat path rejects all five Service ops** — `SENTINELPASS_ALLOW_DIRECT_VAULT=1` cannot bypass daemon step-up
7. **exe policy fails closed** — digest over the open kernel-referenced procfs fd (exec-race safe); `EvidenceUnavailable` denies on non-Linux
8. **CLI dual-mode confusion blocked fail-fast** — both directions, named remediations, before daemon contact
9. **Audit trail is tamper-evident** — JSONL with per-record HMAC-SHA256 chain, contiguous seq, exact break-location reporting
10. **Grant-store TOCTOU handled** — lock across load+mutate+save with no await points; rename-atomic reads

---

## Recommended fix order

1. M1 (correct the containment claim or enforce it — highest impact on the release's headline)
2. M3 (panic — trivial fix, user-facing crash)
3. M4 (store_error wording — operator safety)
4. M2 (enrollment audit — symmetry)
5. M5 (cleanup logging — hygiene)

All fixes are doc/code edits in the files already touched by 0.16.0. No new dependencies.
