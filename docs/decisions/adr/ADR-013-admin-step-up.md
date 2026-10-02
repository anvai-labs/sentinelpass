# ADR-013: Master-Password Administrative Step-Up (SP-0)

| Field | Value |
|-------|-------|
| Status | Accepted (owner-directed via the Sandesha handoff 2026-10-02; adversarial review rides the PR) |
| Date | 2026-10-02 |
| Owners | Core maintainer, security lead |
| Related | ADR-007 (daemon authority), ADR-011 (service credentials), [#194](https://github.com/anvai-labs/sentinelpass/issues/194), `docs/SANDESHA_SERVICE_IDENTITY_HANDOFF_2026-10-02.md` §3A |

## Summary

Administrative mutations through the daemon require a **fresh master-password
step-up**: a dedicated, single-use, short-lived (60 s), connection-bound,
operation-bound approval minted only after verifying the master password
through the existing reviewed KDF path. Unlocked-vault state, biometric
unlock, IPC/client tokens, or any later PGP factor never authorize a
mutation. Reads run unattended.

## Context

WBS-408/502 made the daemon the sole vault authority: with an unlocked
daemon, any same-UID process holding the IPC token can mutate entries,
policy, and sync configuration through `ServiceCall`/`SaveCredential`/
`SaveSecret` without ever touching the master password. The Sandesha
service-identity handoff (§3A) makes closing this a prerequisite (SP-0)
for any automation/enrollment work: "manual master-password authorization
for setup and ALL administrative mutations; retrieval alone may run
unattended."

## Decision

1. **Centralized operation classification** — `VaultOp::requires_admin_step_up()`
   (exhaustive match, no wildcard: new variants must be classified to
   compile). 28 of 45 ops require step-up (all entry/TOTP/SSH/entity/
   registry mutations, imports, exports — a sensitive read — biometric
   policy, and all sync administrative ops incl. `SyncNow`, conservatively,
   because pull applies remote mutations). Reads (16) and `VaultCreate`
   (bootstrap password-setting, maintenance-mode only) are exempt.
2. **Step-up protocol** (sealed-session IPC, like `UnlockVault`):
   `StepUpAuthorize { master_password, op }` → the daemon verifies the
   password by running the full reviewed open path (`VaultManager::open`)
   and discarding the result — no cheaper verifier, no unlock side effect,
   KDF gated + blocking-pool + lockout-rate-limited exactly like unlock.
   On success it returns `StepUpReceipt { approval_id, expires_at }` where
   the approval binds: the minting **connection**, an HMAC-SHA256
   **commitment over the serialized op** (keyed by a per-daemon-start
   random key; secrets inside the op are only ever inside the keyed
   digest), a 60 s TTL, and single use.
3. **Enforcement at the daemon boundary** — `ServiceCall` gains an optional
   `stepup_approval`; under the strict profile any step-up-classified op
   without a valid, matching, unconsumed approval for THIS connection is
   denied with the typed `step_up_required` error. Approvals are consumed
   on the attempt (a failed mutation burns it — no replay). Server-held
   only: a daemon restart invalidates every pending approval. Browser
   (`SaveCredential`) and external-tool (`SaveSecret`) writes and
   browser-surface site-permission grants are denied outright under the
   strict profile until their clients implement the flow (fail-closed).
4. **Strict profile** — opt-in today via `SENTINELPASS_REQUIRE_STEPUP=1`
   at daemon start (the server-vault posture the Sandesha deployment
   uses). The desktop default stays permissive until the Tauri UI and
   extension implement the step-up prompt; flipping the default is an
   explicit later release gated on that work (see Later).
5. **CLI** — a generic retry wrapper maps `step_up_required` to a hidden
   password prompt, performs `StepUpAuthorize` for the exact op, and
   replays the call with the receipt. No password in argv/env/logs.

## Separation of duties (documented model)

The handoff's five-role model (app admin / sysadmin / key admin / workload
principal / auditor) is a design target for multi-principal vaults; today's
single-owner vault enforces the workload slice of it: the strict profile
makes a service consumer retrieval-only by construction (no mutation
surface without the owner's master password, which never leaves the
trusted owner machine — approvals are minted on the owner's connection).
Two-person rule, quorum recovery, and a key-admin-without-decrypt role
remain future multi-admin work (handoff §3B) and are NOT claimed here.

## Threat Model

Reduces: casual or automated mutation from an unlocked desktop session;
stolen IPC/client tokens being used to alter entries, policy, or sync
config (tokens still read); replayed approvals (single-use, 60 s,
connection- and op-bound); restart replay (in-memory state, per-start key).

Does not defeat: root/kernel compromise (can patch the verifier or read
the password as typed), keylogging on a compromised owner machine,
same-UID process observation of the typed password, or a coerced legitimate
approval. Administrative approval must happen on the trusted owner machine
— never type the master password on the untrusted VPS (the strict profile
exists precisely so the VPS never needs it after provisioning).

## Options Considered

- **Per-op password on the wire for every mutation** — rejected: chatty,
  worse UX, no stronger than a bound single-use approval.
- **Reusing unlock state ("unlocked recently" heuristic)** — rejected by
  the requirement: unlocked state is exactly what must not authorize.
- **A separate lightweight password verifier** — rejected: duplicates
  crypto; the reviewed path is reuse-as-is.
- **Persisted approvals** — rejected: restart must invalidate (replay).

## MVP vs. Later

- **MVP (this change):** classification, step-up protocol + enforcement,
  strict profile flag, CLI retry flow, browser/tool strict denials,
  adversarial bypass suite, runbook/diagnostic corrections from the
  handoff (§8).
- **Later:** UI/extension step-up prompts → strict default on desktop;
  batch manifests (one approval for an immutable multi-op manifest);
  two-person rule and multi-admin custody (handoff §3B); SP-1 exact-entry
  `ServiceGrantV2` + per-principal service socket; SP-3 executable
  binding; SP-4 OpenPGP enrollment — each its own reviewed slice.

## Migration and Rollout

Purely additive protocol messages; `ServiceCall.stepup_approval` is
serde-defaulted so existing clients compile and behave identically. The
strict profile is off by default; enabling it on a service vault denies
browser capture and unattended sync — intended, and stated in the runbook.

## Consequences

Service vaults become retrieval-only for every consumer by construction.
Desktop users who enable strict mode early get password prompts on every
CLI mutation until the UI lands (documented). The 60 s window assumes an
interactive admin; batch manifest work is deliberately deferred.
