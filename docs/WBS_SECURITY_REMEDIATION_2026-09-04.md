# SentinelPass Security Remediation — Work Breakdown Structure

**Version:** 1.0
**Date:** 2026-09-04
**Source plan:** `docs/STRATEGIC_REMEDIATION_PLAN_2026-09-04.md`
**Traceability:** `docs/REQUIREMENTS.md` (FR/SR/TV/OP/CM/RG), `TECHNICAL_DEBT.md` (TD-*),
`docs/SECURITY_STATUS_MATRIX.md`, ADR-003…ADR-010
**Rule:** this document converts the strategic plan into independently testable slices.
Where the plan and this WBS disagree, the strategic plan governs direction and this WBS
governs scope of each change.

## 0. Reading this WBS

Every work package (WP) carries:

- **Outcome** — the observable change, phrased as a testable statement.
- **ADR** — governing decision record (`—` when the strategic plan alone governs).
- **Reqs/TDs** — requirement IDs and TD IDs this WP closes or advances.
- **Deps** — WBS IDs that must exit first.
- **Owner** — SL security lead · CM core maintainer · DE desktop/browser · ME mobile ·
  RE release engineer · PD product · XR external reviewer.
- **Deliverables** — files/modules touched.
- **Tests** — positive (P) and negative (N) evidence required.
- **Migration** — compatibility impact.
- **Docs** — documents that must change in the same commit.
- **Est** — senior-engineer-day estimate (point, not commitment).
- **Status** — `Proposed` → `Ready` (deps met) → `In Progress` → `Done` → `Verified`.
  A WP is `Done` only with its tests merged; `Verified` only after WBS-901/911 evidence.
- **Entry/Exit** — criteria to start / criteria to call it finished.
- **Risk** — accepted residual risk after exit.

Status vocabulary for *controls* (per ADR-003 / SR-DOCS-001): `Planned`, `Experimental`,
`Partial`, `Implemented`, `Verified`. A control moves to `Implemented` only with
positive+negative automated evidence; to `Verified` only via release-gate or independent
review. Evidence rules: every status claim in `docs/SECURITY_STATUS_MATRIX.md` must cite
files/tests; code existence alone never justifies `Implemented`.

## 1. Program governance (WBS-000)

### WBS-001 — Worktree/evidence reconciliation
- **Outcome:** Current docs and code agree on what exists; every stale claim is listed.
- **Reqs/TDs:** SR-DOCS-001, SR-DOCS-002, TV-004 · (feeds all TDs)
- **Deps:** — · **Owner:** SL · **Est:** 1d · **Status:** In Progress (this document)
- **Deliverables:** `docs/SECURITY_STATUS_MATRIX.md` updates; discrepancy list in WP notes.
- **Tests:** P: matrix rows cite file/test paths that exist. N: grep finds no
  `Implemented` row without evidence links.
- **Migration:** none. **Docs:** matrix, README security section.
- **Entry:** repo checkout. **Exit:** zero known doc/runtime mismatches.
- **Risk:** drift re-enters between reviews (mitigate: TV-004 release checklist).

### WBS-002 — Executable WBS + dependency graph
- **Outcome:** This file, validated against every open TD and requirement ID (Appendix A/B).
- **Reqs/TDs:** RG-003 · (all) · **Deps:** WBS-001 · **Owner:** SL · **Est:** 1d
- **Status:** In Progress
- **Deliverables:** this file.
- **Tests:** P: Appendix A lists every TD-*; Appendix B every FR/SR/TV/OP ID.
  N: no TD/requirement ID appears in zero packages.
- **Entry:** WBS-001. **Exit:** appendices complete; critical path stated.
- **Risk:** WBS rot (mitigate: update in same change as scope-affecting decisions).

### WBS-003 — Traceability assignment
- **Outcome:** Every WP maps to ≥1 requirement/TD (Appendices A, B).
- **Reqs/TDs:** RG-003 · **Deps:** WBS-002 · **Owner:** SL · **Est:** 0.5d · **Status:** In Progress
- **Tests:** P: each WP block lists IDs. N: an ID with no owning WP fails review.
- **Entry/Exit:** with WBS-002. **Risk:** mappings go stale on requirement edits.

### WBS-004 — Release-status vocabulary + evidence rules
- **Outcome:** Single vocabulary (`Planned/Experimental/Partial/Implemented/Verified`)
  with machine-checkable evidence rules adopted across all docs and the matrix.
- **Reqs:** SR-DOCS-001, SR-DOCS-002, TV-004 · **Deps:** WBS-001 · **Owner:** SL+CM
- **Est:** 0.5d · **Status:** Ready
- **Deliverables:** matrix header, ADR-003 cross-ref, docs/README.md conventions note.
- **Tests:** P: all matrix rows use only the five states. N: unknown state strings fail
  a docs lint/check script.
- **Entry/Exit:** WBS-001 exit. **Risk:** vocabulary applied inconsistently in prose.

### WBS-005 — Release-blocker register (P0/P1)
- **Outcome:** A tracked register of all P0/P1 trust-boundary findings with owner,
  target release, evidence links, and status — the machine-checkable critical-gate list
  ADR-003 requires.
- **Reqs/TDs:** SR-DOCS-002, TV-004 · TD-SEC-01…08, TD-ROB-01…16, TD-NET-01…07,
  TD-CLIENT-01…09, TD-MOB-01…10, TD-REL-01…07
- **Deps:** WBS-002 · **Owner:** SL · **Est:** 0.5d · **Status:** Ready
- **Deliverables:** `docs/RELEASE_BLOCKER_REGISTER.md` (new) generated from TD tables.
- **Tests:** P: every P0/P1 TD row appears. N: a closed blocker without evidence link
  fails the register check.
- **Entry/Exit:** WBS-002 exit / register merged and linked from matrix.
- **Risk:** register drifts from TD tables (mitigate: generate, don't hand-edit).

## 2. Phase 0 — containment and truthful defaults (WBS-100, release 0.8.x)

Gate: ADR-003 direction accepted *as working assumption*; full ADR-003 acceptance not
required for defaults that only *remove* unsafe reachability.

### WBS-101 — Deny originless browser-surface IPC by default
- **Outcome:** `GetCredential/GetTotpCode/ListDomainCredentials/SaveCredential` from a
  client presenting no origin marker are rejected by default; legacy ≤0.7 hosts keep a
  documented explicit opt-in.
- **Reqs/TDs:** SR-IPC-003 (containment half), TV-001 · TD-SEC-06 (first half), TD
  deferred-#4 (accelerated from 0.9)
- **ADR:** ADR-007 (direction; full capability model is WBS-504/505)
- **Deps:** — · **Owner:** CM · **Est:** 1d · **Status:** Ready
- **Deliverables:** `sentinelpass-core/src/daemon/ipc/server.rs` (`browser_surface_allowed`),
  native-host version note, `docs/IPC_PROTOCOL.md` (if present) or CLAUDE.md IPC section.
- **Tests:** P: `NativeHost`-originated requests still pass. N: originless request is
  denied; `SENTINELPASS_ALLOW_LEGACY_ORIGINLESS=1` restores old behavior (documented
  compatibility path); `Cli` origin still denied.
- **Migration:** users running host ≤0.7 with autofill must upgrade the host or set the
  opt-in env var. Documented in release notes.
- **Docs:** matrix row "Native-host/browser IPC authorization"; CLAUDE.md IPC section.
- **Entry:** none. **Exit:** tests merged; default flipped; compatibility path documented.
- **Risk:** transient breakage for stale hosts (accepted; opt-in exists).

### WBS-102 — Sync disabled by default; label v1 experimental
- **Outcome:** Code keeps `sync_enabled=false` default (already true); every user-facing
  surface (CLI `sync init`, docs, README, relay README) states sync is experimental and
  not for production credentials.
- **Reqs/TDs:** strategic Phase 0 · TD-SEC-02/05 (labels), TD-NET-02 (0.8.x half)
- **Deps:** — · **Owner:** CM+PD · **Est:** 0.5d · **Status:** Ready
- **Deliverables:** `sentinelpass-cli/src/commands/sync.rs` (warning banner), README,
  docs/SYNC.md header, matrix row.
- **Tests:** P: `sync init` output includes experimental warning. N: docs grep finds no
  unqualified production-readiness claim for sync.
- **Migration:** none. **Docs:** SYNC.md, README, matrix.
- **Entry/Exit:** — / labels merged. **Risk:** users ignore labels.

### WBS-103 — TLS required for non-loopback relays
- **Outcome:** Relay URL configuration rejects non-HTTPS schemes except explicit
  loopback-development (`http` + loopback host + opt-in allowance). Userinfo in relay
  URLs rejected.
- **Reqs/TDs:** SR-SYNC-007 (config half; redirect handling remains WBS-617) · TD-NET-02
  (0.8.x half)
- **Deps:** — · **Owner:** CM · **Est:** 1.5d · **Status:** Ready
- **Deliverables:** `sentinelpass-core/src/sync/config.rs` (`validate_relay_url`),
  call sites `init_sync` (`vault/sync_ops.rs`) and `SyncClient::new` (feature-gated).
- **Tests:** P: `https://…` accepted; `http://127.0.0.1:8743` + allowance accepted.
  N: plain `http://relay.example.com` rejected; loopback without allowance rejected;
  `ftp://`, `file://`, userinfo URLs rejected; stored config with disallowed URL fails
  closed at sync start.
- **Migration:** existing dev setups pointing at LAN HTTP relays must move to loopback
  profile or TLS. Documented.
- **Docs:** docs/SYNC.md self-host section; matrix "Relay transport policy".
- **Entry/Exit:** — / validation + tests merged. **Risk:** none material.

### WBS-104 — Label mobile prototypes; no placeholder-as-control
- **Outcome:** Android/iOS docs, READMEs, and app strings label clients prototype;
  placeholder biometric/sync/autofill paths are explicitly not security controls.
- **Reqs/TDs:** SR-DOCS-001 · TD-SEC-08, TD-MOB-03 (labeling half)
- **Deps:** — · **Owner:** ME+PD · **Est:** 0.5d · **Status:** Ready
- **Deliverables:** `android/README.md`, `ios/README.md` (or docs/MOBILE_*), README
  badges/wording, matrix rows.
- **Tests:** P: docs contain prototype labels. N: no doc claims working mobile
  biometric/sync/autofill.
- **Migration:** none. **Docs:** README, mobile docs, matrix.
- **Entry/Exit:** — / labels merged. **Risk:** APKs in the wild (accepted; not shipped).

### WBS-105 — Correct public security claims
- **Outcome:** README, SECURITY_ARCHITECTURE.md §2 threat table, CLAUDE.md state
  accurate control status: recovery unavailable, per-field (not full-DB) encryption,
  no AAD binding, memsec/mlock removed, sync padding unused, rollback protection
  partial, biometric parity partial, mobile prototype.
- **Reqs/TDs:** SR-DOCS-001, SR-DOCS-002, TV-004 · (matrix-wide)
- **Deps:** WBS-004 · **Owner:** SL · **Est:** 1d · **Status:** Ready
- **Deliverables:** README.md, SECURITY_ARCHITECTURE.md §2 statuses, CLAUDE.md
  limitations section.
- **Tests:** P: each corrected claim cites matrix. N: grep for previously-false
  "✅ full database encryption"/"mlock"/"padding" claims returns nothing unqualified.
- **Migration:** none. **Docs:** in scope itself.
- **Entry:** WBS-004. **Exit:** claims match matrix. **Risk:** prose drift.

### WBS-106 — Regression tests for changed defaults
- **Outcome:** Every Phase 0 default change has an automated negative test that fails
  if someone reverts the default.
- **Reqs/TDs:** TV-001 · covers WBS-101..104 · **Deps:** WBS-101..104
- **Owner:** CM · **Est:** 0.5d · **Status:** Ready
- **Deliverables:** tests inside the touched modules (IPC server tests, sync config
  tests) — no separate harness.
- **Tests:** the tests are the deliverable. **Migration:** none. **Docs:** none.
- **Entry/Exit:** with 101–104 / all merged green. **Risk:** none.

## 3. Architecture decisions (WBS-200)

All WPs: **Owner** SL+CM (+ME for 009, +RE for 010, +PD where UX-visible);
**Deliverables** = decision sections updated in the ADR + decision-question appendix
answered; **Tests** = acceptance criteria written as testable statements; **Docs** =
ADR itself + matrix "Target" columns. **Entry:** WBS-002. **Exit:** ADR marked
`Accepted` after review per repository rule 6 (request review; no self-acceptance
without the required decision/evidence). **Risk (all):** acceptance delayed blocks
dependent phases — hence question lists first.

### WBS-201 — ADR-003 threat model & release gates
- **Outcome:** Accepted baseline: adversaries, non-goals, status vocabulary, 1.0 gates.
- **Reqs/TDs:** SR-DOCS-001/002, SR-SUPPLY-004 · feeds all. **Deps:** WBS-004/005.
- **Est:** 1d · **Status:** Done (ADR-003 Accepted rev 3, 2026-09-04).

### WBS-202 — ADR-004 recovery/key-slots/epoch
- **Outcome:** Accepted slot model, epoch/revocation semantics, recovery flow, DEK
  rotation policy.
- **Reqs/TDs:** SR-RECOVERY-001…004 · TD-SEC-03, TD-SEC-04, TD-SEC-05.
- **Deps:** WBS-201. **Est:** 2d · **Status:** Done (ADR-004 Accepted rev 4, 2026-09-04).

### WBS-203 — ADR-005 envelope v2/AAD/serialization/migration
- **Outcome:** Accepted AAD builder inputs, envelope types, serialization choice,
  version/fail-closed rules, migration contract.
- **Reqs/TDs:** SR-CRYPTO-001/002/003/005 · TD-SEC-01, TD-ROB-07/08/10.
- **Deps:** WBS-202 (epoch semantics). **Est:** 2d · **Status:** Done (ADR-005 Accepted rev 4, 2026-09-04).

### WBS-204 — ADR-008 backup & verified restore
- **Outcome:** Accepted backup format, snapshot method, restore/verification contract.
- **Reqs/TDs:** SR-DATA-005, TV-005 · TD-ROB-12. **Deps:** WBS-202/203. **Est:** 1.5d.

### WBS-205 — ADR-007 daemon authority & IPC capabilities
- **Outcome:** Accepted capability model, peer controls, session crypto, deadlines.
- **Reqs/TDs:** SR-IPC-003/004/005 · TD-SEC-06, TD-ROB-13/14/15/16. **Deps:** WBS-201.
  May run parallel with WBS-300; implementation consumes accepted contracts. **Est:** 2d.

### WBS-206 — ADR-006 sync v2/conflict/pairing/rollback
- **Outcome:** Accepted v2 mutation schema, ack/idempotency, conflict preservation,
  pairing replacement, v1 retirement.
- **Reqs/TDs:** SR-SYNC-001…007, TV-002/006 · TD-SEC-02/05/07, TD-ROB-01…06,
  TD-NET-01…07. **Deps:** WBS-202/203 (epoch/envelope first). **Est:** 2.5d.

### WBS-207 — ADR-009 mobile ABI/platform-keystore
- **Outcome:** Accepted generated-ABI approach, JNI contract, panic/ownership rules,
  Keystore/Keychain slot binding.
- **Reqs/TDs:** SR-MOBILE-001/002 · TD-MOB-01…10. **Deps:** WBS-202/203 (slot model).
  **Est:** 1.5d.

### WBS-208 — ADR-010 signing/provenance/audit gates
- **Outcome:** Accepted signing/notarization/SBOM/provenance/updater-trust design and
  release-gate enforcement.
- **Reqs/TDs:** SR-SUPPLY-001/002/003 · TD-REL-01…07. **Deps:** WBS-201. **Est:** 1.5d.

## 4. Phase 1 — recovery, key slots, envelope v2 (WBS-300, release 0.9)

Gate: ADR-004 + ADR-005 Accepted. **Owner** CM unless noted. Serialization, slot, and
AAD decisions come from the ADRs; WPs below assume the ADR-004/005 direction.

### WBS-301 — Vault UUID, format version, crypto epoch, high-water sidecar
- **Outcome:** Durable vault identity + monotonic epoch + explicit format version,
  plus the out-of-DB **epoch high-water sidecar** (ADR-004 rev 4): owner-only file
  beside the vault, minted/updated on epoch change, checked at every open;
  absent-file = trust-on-first-use WITH a visible user warning; restore override =
  reauthentication + acknowledgment + audit event (tested with WBS-417).
- **Reqs/TDs:** SR-RECOVERY-001 · TD-SEC-03/05 · **Deps:** 202/203 accepted.
- **Deliverables:** `crypto/keyring.rs`, `database/schema.rs`, migrations.
- **Tests:** P: epoch increments survive reopen. N: epoch regression fails closed;
  cross-vault slot rejected (with 302).
- **Migration:** legacy unlock mints UUID/password slot (ADR-004 rollout).
- **Docs:** SECURITY_ARCHITECTURE §3, matrix. **Est:** 3d · **Status:** Proposed
- **Entry:** ADRs accepted. **Exit:** tests green; migration path exists (with 401).
- **Risk:** epoch misuse bugs (mitigated by typed epoch, tests).
- **Status:** Done (2026-09-04, first Phase 1 slice) — `vault/epoch_guard.rs` (7 unit
  tests) + schema v6 migration (vault_uuid, format_version; idempotent column adds)
  + create/open/biometric-open/rotation integration (5 tests incl. end-to-end
  rollback refusal and TOFU); hardened after adversarial review (NULL-uuid fails
  closed; +1-only forward jumps; atomic sidecar writes; create() rebases stale
  sidecars). Round 3 + architecture review drove the v2 material-bound sidecar
  (digest over stored key-material columns; surgical-rewind refusal), the
  authenticated-adoption redesign (check is read-only pre-auth; heals adopted
  only after epoch-AAD-verified password unlock; biometric defers; legacy
  refuses), the honest scope recast + placement/coverage/multi-device rules
  (ADR-004 rev 5), and round 4's consistency fixes (VaultSnapshot single-read —
  kills the guard/unlock/heal TOCTOU and the 4-5 redundant reads; idempotent
  concurrent adopt; create/pair-join compensation paths; guarded+loud rollback
  restore; shared outcome auditing on all three unlock surfaces; temp-file
  cleanup). Remaining in later slices: UI surfacing of TOFU/heal warnings;
  restore override (WBS-417); biometric-only heal deferral (documented ADR
  residual, platform slots may close it); digest of the future slot-registry
  MAC by composition (302).

### WBS-302 — Key-slot registry (password/recovery/platform/trusted-device)
- **Reqs/TDs:** SR-RECOVERY-001/004 · TD-SEC-03 · **Deps:** 301.
- **Deliverables:** `vault/slot_ops.rs` (new), `key_slots` table (schema v7),
  `slot_registry_mac` column, `list_key_slots`/`revoke_key_slot` public API.
- **Tests:** P: slot CRUD + password-slot unlock; MAC order-independence +
  input-sensitivity (edit/resurrect/add/remove/epoch/key all change it);
  rotation keeps registry+MAC+sidecar consistent; legacy vault bootstraps the
  MAC at first open. N: slot-row tamper fails closed at open; row removal
  fails closed; final-usable-slot revocation refused (313 guard, enforced in
  the registry so no caller bypasses it); pair-join sidecar failure leaves a
  consistent (not bricked) vault — regression test for the partial-revert
  desync bug found and fixed during implementation.
- **Migration:** v6→v7 mints the password slot from the existing wrap; the
  registry MAC (key derives from the DEK) bootstraps at the first
  post-unlock open, guarded by a pre-bootstrap invariant that refuses to
  bless anything but the exact migrated state.
- **Docs:** ADR-004 rev 5 (composition rule consumed), matrix rows.
- **Est:** 4d · **Status:** Done (2026-09-05, after adversarial review round 1 —
  10 findings, all addressed): revoke is ONE BEGIN IMMEDIATE transaction (guard +
  UPDATE + fresh-read MAC; crash window and cross-process lost-update closed) with
  the idempotent retry re-following the sidecar; the NULL-MAC bootstrap invariant
  byte-compares the slot against db_metadata's RAW blobs and requires exactly one
  row total (row-swap/rogue-revoked-row blessing refused — regression tested);
  create() commits metadata+slot+MAC in one transaction with a best-effort
  post-commit sidecar (both crash windows closed, no compensation dance);
  open_with_biometric AND retrieve_dek_via_biometric now run the registry
  check (the biometric surface is no longer the MAC-less laundering path);
  pair-join adopts the hierarchy and clears sync tables before any
  post-commit error can surface, with a remediation-naming error; disable-
  biometric tolerates the platform-unsupported clear while still failing loud
  on real keychain errors; user-facing refusal strings repaired (`\\\` bugs).
  Verified: workspace 478 passed / 0 failed, fmt/clippy/TS clean · **Risk:**
  slot-metadata corruption → fail closed (explicit error), never silent.

### WBS-303 — AAD builder (typed inputs)
- **Reqs/TDs:** SR-CRYPTO-001 · TD-SEC-01 · **Deps:** 301. Includes the
  canonical-JSON profile conformance test (duplicate-key rejection, integer-only,
  depth cap; decode never through untyped Value — ADR-005 rev 3).
- **Deliverables:** `crypto/aad.rs` (new): typed builder vault/object/purpose/type/
  epoch/version.
- **Tests:** P: deterministic encoding golden vectors. N: each input perturbation
  changes AAD (property test).
- **Migration:** none until 304 adopts. **Est:** 2d · **Status:** Proposed.

### WBS-304 — Versioned summary + secret envelopes
- **Reqs/TDs:** SR-CRYPTO-001/002 · TD-SEC-01 · **Deps:** 303.
- **Deliverables:** `crypto/envelope.rs` (new) + vault encrypt/decrypt paths.
- **Tests:** P: roundtrip; golden vectors. N: cross-field/record/vault/type/purpose/
  tombstone/version/epoch substitution all fail authentication.
- **Migration:** v1 records re-encrypted only via 404. **Est:** 5d · **Status:** Proposed.

### WBS-305 — Replace bincode-only durable contracts
- **Outcome:** Documented, language-neutral, bounded serialization for all durable
  envelopes (per ADR-005 choice).
- **Reqs/TDs:** SR-CRYPTO-002 · (bincode debt) · **Deps:** 304. **Est:** 3d.
- **Tests:** P: cross-language shape doc + golden files. N: oversized/truncated/
  unknown-version decode rejected before allocation.

### WBS-306 — Encrypt identity metadata / keyed lookup tags
- **Reqs/TDs:** SR-CRYPTO-001, SR-DATA-004 (privacy) · TD-ROB-10 · **Deps:** 304.
  **ADR:** ADR-005 rev 3 (tag contract).
- **Deliverables:** domain-mapping tables, SSH/TOTP metadata, keyed FULL
  LABEL-CHAIN tag sets (host + every dot-suffix, label-count-capped; no PSL —
  ADR-005 rev 4); mapping write-path moves into the application service (local
  CRUD writes none today — verified: the repository.rs INSERT is test-only).
- **Tests:** P: lookup by domain works via tags (mutual full-host containment per
  ADR-005 rev 4); bare-parent↔dotted-child PRESERVED (`gitlab` ↔ `sub.gitlab`
  matches, as `domains_match` does today). N: DB dump reveals no plaintext
  domain/identity columns; SIBLING subdomains do NOT match; chain-only tags (e.g.
  `com`) never match alone; canonicalization fixture (IDNA, case, bare hosts).
- **Migration:** tag + mapping backfill in 404 (derives mappings for ~all local
  entries). **Est:** 4d.

### WBS-307 — KDF hard maximums + platform profiles
- **Reqs/TDs:** SR-CRYPTO-003 · TD-ROB-08 · **Deps:** — (independent).
- **Deliverables:** `crypto/kdf.rs` bounds + profiles.
- **Tests:** P: calibration evidence recorded. N: hostile m/t/p/output values fail
  before expensive work.
- **Est:** 2d · **Status:** Proposed.

### WBS-308 — Zeroize intermediate KDF/envelope buffers
- **Reqs/TDs:** SR-CRYPTO-004 · TD-ROB-08 · **Deps:** 304/305. **Est:** 2d.
- **Tests:** P: audit table of secret-bearing types. N: no owned secret without
  zeroizing type in new paths.

### WBS-309 — Password rotation stage→verify→commit→adopt
- **Reqs/TDs:** SR-RECOVERY-004 · TD-SEC-04 · **Deps:** — (implemented ahead of 302;
  depends only on the accepted ADR-002/004 contracts). **Est:** 2d.
- **Tests:** P: rotation succeeds end to end. N: interrupted rotation at each stage
  leaves old password usable; new password not half-adopted.
- **Status:** Done (2026-09-04, post adversarial review) — `rotate_master_password`
  stages + verifies (round-trip unwrap, ct-compared DEK) WITHOUT adopting; caller
  commits (UPDATE guarded `WHERE key_epoch = ?expected` + rows==1 against concurrent
  rotation clobber), then adopts, then follows the sidecar best-effort; `checked_add`
  on the epoch. Tests: staging-without-adopting, commit-failure via BEGIN EXCLUSIVE
  injector (old password intact, epoch unchanged), stale-epoch UPDATE no-op. Review
  hardening in the same slice: NULL-uuid fails closed, sidecar writes atomic
  (temp+rename), epoch jumps > +1 refused (anti-ratchet), biometric DEK-retrieval
  path guarded, TOFU/advance audit-logged (`EpochHighWaterRebased`).

### WBS-310 — Recovery key generation (128–256-bit + checksum)
- **Reqs/TDs:** SR-RECOVERY-002 · TD-SEC-03 · **Deps:** 302.
- **Status:** Done (2026-09-05, after adversarial review round 1 — crypto core
  verified against independent models: CRC-10/ATM confirmed via the standard
  check value 0x199; base32 bit-plumbing verified over 2,264 patterns).
- **Status (implementation detail):** `vault/recovery.rs`: 256-bit
  machine-generated entropy; Crockford base32 display (52 body symbols + 2
  CRC-10 checksum symbols, 9 groups of 6); parse validates length,
  alphabet, padding, and checksum — EXHAUSTIVELY tested that every
  single-character substitution at every position is rejected (3 keys × 54
  positions × 31 alternatives); case-insensitive + grouping-tolerant +
  O/I/L homoglyph-lenient decode; round-trip, determinism, distinct-entropy
  tests. Zeroizing key material; the display string IS the secret.
### WBS-311 — Verified recovery onboarding
- **Reqs/TDs:** SR-RECOVERY-002 · TD-UX-01 · **Deps:** 310.
- **Status:** Done (2026-09-05, after adversarial review round 1).
- **Status (implementation detail):** `create_recovery_slot` (one
  transaction: revoke-previous + insert + MAC; sidecar follows at constant
  epoch); raw AES-256-GCM wrap of the DEK under the 256-bit key (machine
  origin ⇒ no KDF, ADR-004 rev 4 wrap-policy-by-origin) with structured AAD
  binding vault uuid + slot uuid + type + epoch (WBS-303 generalizes);
  unwrap seam refuses non-epoch-bound wraps and any context transplant
  (wrong slot uuid / wrong epoch — tested); CLI `sentinelpass recovery
  setup` enforces verified re-entry (checksum-valid AND byte-identical)
  before persisting — SR-RECOVERY-002's unverified-key prohibition.
### WBS-312 — Recovery creates new password slot + epoch advance
- **Reqs/TDs:** SR-RECOVERY-002/003 · TD-SEC-03/05 · **Deps:** 302, 309, 311.
- **Status:** Done (2026-09-05, after adversarial review rounds 1 AND 2 —
  round 1 fixed 9 findings incl. 2 critical (rollback laundering via
  missing epoch-guard; TOCTOU on verify-before-write); round 2 verified
  those fixes sound (crypto core independently re-derived: CRC-10/ATM
  confirmed against the standard check value 0x199, base32 bit-plumbing
  over 2,264 patterns) and found the verify-before-write discipline was
  incomplete — extended to revoke_key_slot, create_recovery_slot, and
  rotation (the last required moving the check to its call site: it must
  run BEFORE the epoch-bumping UPDATE in the same transaction, not after,
  or it spuriously fails every legitimate rotation — caught by the full
  workspace test run, not the review itself). Also from round 2: durable
  audit events extended (`SlotRevoked`, guard-refusal-before-unwrap on
  recovery, both biometric surfaces); `SlotRegistryTampered` typed error
  variant replaces string-matched refusals (a future reword can no longer
  silently misfile the audit event); recovery's biometric-keychain clear
  moved to a post-commit best-effort step (was inside the transaction —
  an external side effect that couldn't be rolled back by a later SQL
  failure); disable_biometric_unlock's tolerant-clear now matches the
  UNSUPPORTED_PLATFORM_MSG const instead of a diverged hardcoded string;
  three garbled error-string literals (lost newlines from an earlier
  edit-script bug) repaired; CLAUDE.md's vault-path claim corrected
  (platform data dir, not ~/.sentinelpass — now load-bearing since guard
  refusals point users at the sidecar file next to it); stale TD.md
  deferred item closed.
- **Status (implementation detail):** `recover_access` (static: no old
  password): unwrap DEK via the NEWEST usable recovery slot; VERIFY the
  registry MAC with the recovered DEK before any write (tampered registry
  refuses, never minted into a fresh epoch); stage+verify the new password
  wrap outside the transaction (Argon2 cost); ONE transaction revokes ALL
  usable slots (lost password included), mints the new password slot,
  rewraps db_metadata under an epoch-guarded UPDATE (concurrent-change
  refusal), and recomputes the registry MAC; sidecar bumps to the new epoch
  (best-effort, +1-lag self-heal). Tests: forgot-password → new password
  works and the old one NEVER does (epoch 2, exactly 1 usable slot,
  history kept); wrong key changes NOTHING (pre-write refusal); tampered
  registry refuses; used recovery slot revoked (a stolen key cannot
  re-recover over a newer password); no-slot refusal is actionable. CLI
  `recovery recover` + `status`. Local revocation only (ADR-004 rev 4 —
  online authority revoked at sync v2 / WBS-614).
### WBS-313 — Final-usable-slot deletion guard
- **Reqs/TDs:** SR-RECOVERY-004 · **Deps:** 302. **Est:** 1d.
- **Tests:** N: deleting last usable slot rejected; force path requires explicit
  acknowledgment of lockout risk.

### WBS-314 — Optional full-DEK rotation (compromise response)
- **Reqs/TDs:** SR-RECOVERY-003 · TD-SEC-05 · **Deps:** 312, 304; relay
  re-baselining depends on WBS-624 (sync v2) — until then rotation is local-only
  and must disable sync + require re-pairing (ADR-004 rev 2). **Est:** 3d + 2d
  (re-baseline lands with 624).
- **Tests:** P: all records re-encrypted under new DEK; old wrapped keys useless.
  N: interrupted re-encryption resumable; no window with zero usable slots;
  rotation-with-v1-sync-active is refused (no wedged re-pair path — ADR-004 rev 3).
- **Docs:** UI states the offline-copy limit and the v1-sync rotation limits.

### WBS-315 — Fail closed on unsupported newer versions
- **Reqs/TDs:** SR-CRYPTO-005 · TD-ROB-07 · **Deps:** 301/304. **Est:** 1d.
- **Tests:** N: synthetic newer schema/envelope/crypto version returns specific
  compatibility error; no entry read or mutated.

**Phase 1 required negative suite (gate):** field/record/vault/type/purpose/tombstone/
version/epoch substitution; wrong recovery key; corrupt slot metadata; last-slot
deletion; interrupted rotation; hostile KDF parameters; oversized/truncated/unknown
envelopes. **Exit:** matrix rows for recovery/envelope → `Implemented`.

## 5. Phase 2 — schema migration, persistence, backup (WBS-400, release 0.9–0.10)

Gate: WBS-300 core types + ADR-008 accepted. **Owner** CM.

- **WBS-401 — Verified pre-migration backup.** Reqs SR-DATA-005 · TD-ROB-12.
  Deps 416 (format) — sequenced early via minimal snapshot-only bundle if 416 lags.
  Tests: P restore-before-migration works. N migration refuses without backup. Est 2d.
- **WBS-402 — v2 schema beside legacy.** SR-CRYPTO-002, ADR-005 rev 3. Tests: P
  legacy tables untouched until activation; activation renames db_metadata + drops
  legacy tables in one transaction; migration runner's post-commit data phase
  eliminated (version bump + backfill in one transaction). N: old-binary-opens-v2
  fails at the version probe; `create()` refuses to initialize over an existing
  file with ANY content (byte-size > 0 or any table — "non-empty" defined), and
  `create()` itself becomes atomic (schema + metadata in one transaction) so a
  crash cannot leave a leftover file that then bricks creation; the guard's error
  names the manual reset path (verified: no shipped flow legitimately creates over
  an existing file — CLI/UI/pair-join all check exists first). Est 3d.
- **WBS-403 — Stable IDs + slot migration.** SR-RECOVERY-001. Tests: P deterministic
  UUIDs; N ID collisions rejected. Est 2d.
- **WBS-404 — Re-encrypt all records with v2 AAD.** TD-SEC-01. Tests: P count parity;
  N any record failing verification aborts whole migration (atomic). Est 4d.
- **WBS-405 — Verify before activation.** TV-005. Tests: P every envelope + relation
  decrypt/verify. N corrupted target aborts without touching legacy. Est 2d.
- **WBS-406 — Atomic activation; block downgrade.** SR-CRYPTO-005, TD-ROB-07. Tests:
  N older client refuses v2 vault. Est 2d.
- **WBS-407 — Fixtures for every released schema (v1→current).** TV-005.
  Regenerated from actual released schema dumps, not the drifted
  `migrations/v1_initial.sql` labels (ADR-005 rev 3). Est 2d.
- **WBS-408 — Application services / unit-of-work boundary.** SR-DATA-001, TD-ROB-02.
  Deps — may start after ADR-007 direction. Est 4d.
- **WBS-409 — Explicit local vs remote write paths (remove trigger echo).** TD-ROB-02.
  Tests: N remote apply cannot re-mark pending. Est 3d.
- **WBS-410 — NULL preserved end to end.** SR-DATA-002, TD-ROB-03. Tests: P NULL
  roundtrip through encrypt/sync/restore. Est 1.5d.
- **WBS-411 — Transactional entry/mapping/registry/audit/sync-state.** SR-DATA-001.
  Est 3d.
- **WBS-412 — Explicit Unix modes + Windows ACLs for sensitive files.** SR-DATA-003,
  TD-ROB-09. Est 2d.
- **WBS-413 — Owner/type/symlink validation.** TD-ROB-09. Tests: N symlink swap
  rejected. Est 1.5d.
- **WBS-414 — Opaque audit identifiers.** SR-DATA-004, TD-ROB-10/11. Est 1.5d.
- **WBS-415 — Audit chaining/rotation/retention/verification.** SR-DATA-004,
  TD-ROB-11. Tests: N tamper detection. Est 3d.
- **WBS-416 — Portable authenticated backup (SQLite snapshot API).** SR-DATA-005,
  TD-ROB-12, ADR-008. Bundle carries vault UUID + epoch but NOT the high-water
  sidecar (ADR-004 rev 4: restore re-baselines via TOFU-warning or override).
  Tests: N live-file copy rejected; bundle tamper fails. Est 4d.
- **WBS-417 — Dry-run validation + atomic verified restore.** SR-DATA-005.
  Restoring an older-epoch bundle on a machine with a newer high-water requires
  reauthentication + acknowledgment, re-baselines the sidecar, and audit-logs
  (ADR-004 rev 4). Tests: N interrupted restore leaves prior state complete;
  restore-older-epoch override flow + abuse negative. Est 3d.
- **WBS-418 — Crash/fault injection harness (migration/CRUD/backup/restore).**
  SR-DATA-001, TV-005. Est 4d. Gate for the phase: fault at any step → complete-old or
  complete-new, never partial.

## 6. Phase 3 — daemon authority & IPC (WBS-500, release 0.10)

Gate: ADR-007 accepted + WBS-408 contracts. **Owner** CM.

- **WBS-501 — Daemon sole DEK owner/writer.** SR-IPC-004, TD-ROB-13. Est 4d.
- **WBS-502 — Desktop+CLI CRUD via daemon services.** SR-IPC-004, TD-ROB-13, deferred
  TD-#10. Est 4d.
- **WBS-503 — Exclusive offline maintenance mode.** SR-IPC-004. Est 2d.
- **WBS-504 — Scoped capabilities (audience/op/resource/expiry/nonce).** SR-IPC-003,
  TD-SEC-06. Est 4d.
- **WBS-505 — Native-host installation capability.** SR-IPC-003. Tests: N general
  client claiming NativeHost denied. Est 2d.
- **WBS-506 — Retain least-privilege external grants.** (extends existing
  `external_secret_access.rs`). Est 1d.
- **WBS-507 — Unix peer UID + owner-only socket.** SR-IPC-005. Est 1.5d.
- **WBS-508 — Windows SID ACL + remote rejection.** TD-ROB-15, SR-IPC-005. Est 2d.
- **WBS-509 — HKDF directional session keys.** TD-ROB-16. Est 2.5d.
- **WBS-510 — AAD-bound session context (proto/direction/type/counter).** TD-ROB-16.
  Est 2d.
- **WBS-511 — Replay protection, frame bounds, deadlines.** TD-ROB-14, SR-IPC-005.
  Est 3d.
- **WBS-512 — Bounded concurrent clients.** TD-ROB-14. Est 2d.
- **WBS-513 — Blocking pool for Argon2/IO.** TD-ROB-14. Est 1.5d.
- **WBS-514 — Remove lock-poisoning unwraps.** deferred TD-#9. Est 1.5d.
- **WBS-515 — Protocol upgrade/credential rotation path.** Est 2d.
- **Phase negative suite (gate):** general-client-claims-NativeHost; originless;
  wrong audience/op/resource; expired/revoked capability; cross-direction/reflected/
  replayed frame; wrong peer/ACL; oversized/truncated/stalled/concurrent clients.

## 7. Phase 4 — sync v2 & relay (WBS-600, release 0.11 beta)

Gate: ADR-006 + WBS-300/400. **Owner** CM (client) + SL (relay). May overlap WBS-500
after 408/409 stabilize.

- **WBS-601 — v2 mutation schema.** SR-SYNC-004. Est 3d.
- **WBS-602 — Distinct sequence/version/cursor types.** SR-SYNC-002, TD-ROB-01. Est 2d.
- **WBS-603 — Idempotency + original-result replay.** SR-SYNC-001, TD-ROB-05. Est 3d.
- **WBS-604 — Per-object acknowledgements.** SR-SYNC-001. Est 2d.
- **WBS-605 — Outbox removal only on specific ack.** TD-ROB-01. Est 1.5d.
- **WBS-606 — Relay atomic mutation/entry/sequence/ack.** SR-SYNC-003, TD-ROB-04. Est 2d.
- **WBS-607 — Client atomic page/inbox/object/index/cursor.** TD-ROB-04. Est 3d.
- **WBS-608 — Remove remote-apply trigger echo.** TD-ROB-02 (sync half). Est 1.5d.
- **WBS-609 — Nullable encrypted fields preserved.** TD-ROB-03 (sync half). Est 1d.
- **WBS-610 — One bounded paginated path (normal+full).** TD-ROB-06. Est 3d.
- **WBS-611 — Preserve concurrent alternatives; expose conflicts.** SR-SYNC-005,
  TD-UX-02. Est 3d.
- **WBS-612 — Authenticate identity/type/origin/version/epoch/tombstone.** SR-SYNC-004,
  TD-SEC-02. Apply-side rule: pull never applies epoch/registry state below the
  local high-water sidecar — rejected as suspected rollback (ADR-004 rev 4). Est 4d.
- **WBS-613 — Version/hash lineage + trusted high-water.** SR-SYNC-004. Est 3d.
- **WBS-614 — Device/epoch revocation everywhere.** TD-SEC-05. Est 2d.
- **WBS-615 — High-entropy QR bootstrap / reviewed PAKE.** SR-SYNC-006, TD-SEC-07,
  SR-RELAY-002. Est 5d.
- **WBS-616 — Pairing material in bodies; one-use; transcript-bound.** TD-NET-01. Est 2d.
- **WBS-617 — TLS-only, safe redirects, no userinfo (full client rules).** SR-SYNC-007,
  TD-NET-02. Est 2d.
- **WBS-618 — Proxy-trust config for forwarded IPs.** TD-NET-03. Est 1.5d.
- **WBS-619 — Per-vault/device quotas + bounded limiter state.** TD-NET-04,
  SR-RELAY-001, FR-SYNC-001/003. Est 3d.
- **WBS-620 — Non-blocking relay storage.** TD-NET-05. Est 3d.
- **WBS-621 — One consistent limit set.** TD-NET-06. Est 1.5d.
- **WBS-622 — Padding: integrate authenticated profile or remove claim.** TD-NET-07.
  Est 1d.
- **WBS-623 — Production self-host profile docs.** FR-SYNC-004, OP-001/002. Est 1.5d.
- **WBS-624 — v1 retirement + authoritative-device re-bootstrap.** Est 2d.
- **Phase gate (tests):** loss/retry, duplicate/reorder, partial acceptance, concurrent
  edits, stale versions/devices/epochs, malicious relay metadata/tombstone/identity,
  crash between every persistence step, pagination boundaries, rate-limit/proxy/size/TLS
  negatives, randomized model-based convergence (TV-006).

## 8. Phase 5 — desktop & browser hardening (WBS-700, release 0.10–0.11)

Gate: WBS-500 (sync UI also needs 600). **Owner** DE.

- **WBS-701 — Summary-only desktop state; scoped reveal/copy.** TD-CLIENT-01.
  **ADR:** ADR-005 rev 3 (daemon-owned summary index; UI re-requests rather than
  caching — supersedes the plan's "store summaries in UI state" line on acceptance).
  Est 3d.
- **WBS-702 — Scrub DOM/JS/TOTP/timers on lock.** SR-CLIENT-001, TD-CLIENT-01/02. Est 3d.
- **WBS-703 — Lock on inactivity/background/session/suspend/logout.** SR-CLIENT-001,
  TD-CLIENT-02. Est 3d.
- **WBS-704 — Privacy cover before visibility loss.** TD-CLIENT-02. Est 2d.
- **WBS-705 — Reauthentication for sensitive ops.** TD-UX-01 (op half). Est 2d.
- **WBS-706 — Structured URL parsing; HTTP warn/refuse.** TD-CLIENT-06 (URL half). Est 1.5d.
- **WBS-707 — Minimize Tauri capabilities + CSP.** SR-CLIENT-002, TD-CLIENT-03. Est 2d.
- **WBS-708 — Remove production debug-unlock artifacts.** Est 1d.
- **WBS-709 — Native expiring/sensitive clipboard.** Est 1.5d.
- **WBS-710 — Windows Hello-bound key release.** TD-CLIENT-04, SR-CLIENT (biometric
  parity). Est 3d.
- **WBS-711 — Default-deny HTTP autofill.** SR-CLIENT-003, SR-EXT-002, TD-CLIENT-05.
  Est 2d.
- **WBS-712 — Optional/requested site permissions.** TD-CLIENT-05. Est 2d.
- **WBS-713 — Validated site/frame/form/field binding.** SR-CLIENT-003, SR-EXT-002,
  TD-CLIENT-06. Est 3d.
- **WBS-714 — autocomplete semantics + password-change handling.** TD-CLIENT-06. Est 2d.
- **WBS-715 — Ambiguity chooser.** TD-CLIENT-06. Est 2d.
- **WBS-716 — Minimize/scrub extension session secrets.** TD-CLIENT-07. Est 2d.
- **WBS-717 — Shared Chrome/Firefox security source.** SR-CLIENT-004, TD-CLIENT-08. Est 3d.
- **WBS-718 — Manifest/native-host parity CI.** SR-CLIENT-004, TD-CLIENT-08. Est 1.5d.
- **WBS-719 — Chromium/Firefox/daemon E2E suite.** TD-CLIENT-09, SR-CLIENT-003, TV-001.
  Est 4d.

## 9. Phase 6 — mobile (WBS-800, release 0.12 beta)

Gate: ADR-009 + WBS-300/400 stable ABI/envelope. **Owner** ME.

Shared (801–807): **WBS-801** generated C ABI (TD-MOB-09, SR-MOBILE-001) 4d;
**802** JNI contract (TD-MOB-02) 2d; **803** ABI/feature negotiation 2d; **804**
ownership + zeroizing destroy (TD-MOB-09) 2d; **805** FFI panic containment 1.5d;
**806** lifecycle/invalid-handle tests 2d; **807** atomic update + placeholder removal
(TD-MOB-03/04) 3d.

Android: **810** JNI compile/type fixes (TD-MOB-01/02, TV-007) 2d; **811** all-ABI JNI
CI (TD-MOB-01, TV-007) 2d; **812** Keystore-bound platform slot (TD-MOB-03,
SR-MOBILE-002) 4d; **813** AutofillService save/retrieve (TD-MOB-03, SR-MOBILE-003,
FR-MOBILE-001) 5d; **814** lifecycle/lock/cover (TD-MOB-05, SR-MOBILE-004) 3d; **815**
cleartext deny 1d; **816** backup policy (TD-MOB-05) 2d; **817** permission trim 0.5d;
**818** instrumentation matrix (TD-MOB-10, FR-MOBILE-002) 4d.

iOS: **820** consolidate Swift bridges (TD-MOB-09) 3d; **821** Keychain
SecAccessControl slot (TD-MOB-06, SR-MOBILE-002) 4d; **822** file protection + backup
policy (SR-MOBILE-004) 2d; **823** scene lock + cover (TD-MOB-07) 2d; **824** local
expiring pasteboard 1d; **825** Credential Provider (TD-MOB-08, SR-MOBILE-003,
FR-MOBILE-001) 5d; **826** remove plaintext persistence models 1d; **827**
authenticated backup/export (TD-MOB-08) 3d; **828** XCTest matrix (TD-MOB-10) 4d.

## 10. Phase 7 — release assurance & 1.0 (WBS-900)

Gate: WBS-300..800 + ADR-010 accepted. **Owner** RE+SL.

- **901** security workflows as tag-release prerequisites (TD-REL-01, SR-SUPPLY-001) 2d;
  **902** security feature/platform matrix builds (TV-007, SR-SUPPLY-001) 3d; **903**
  fuzz targets envelopes/migrations/IPC/sync/import/FFI (TV-003) 4d; **904** historical
  fixtures (TV-005) — merges with 407; **905** installed-artifact smoke + recovery/restore and compromise-rotation drills
  (TD-REL-05; the ADR-003 rev 3 blocking 1.0 drill gates) 4d;
  **906** signed checksums/updater metadata (TD-REL-02, SR-SUPPLY-002) 3d; **907**
  Windows + macOS signing/notarization (TD-REL-02) 5d; **908** SBOM + provenance
  (TD-REL-03, SR-SUPPLY-002) 3d; **909** dependency-exception lifecycle (TD-REL-04,
  SR-SUPPLY-003) 2d; **910** fix+enable ignored relay timing tests (TD-REL-06) 2d;
  **911** independent trust-boundary review commissioned (TD-REL-07, SR-SUPPLY-004,
  XR) 3d+external; **912** close critical/high findings 5d; **913** final docs/claims
  reconciliation (SR-DOCS-001, TV-004) 2d.

## 11. Post-foundation UX & features (WBS-1000, not on security critical path)

Governed by §7–8 of the strategic plan; enters only after the relevant gates close.
- **WBS-1001** recovery/reverification/reauth UX (TD-UX-01; with 311/705).
- **WBS-1002** device/epoch/conflict Security Center (TD-UX-02, TD-UX-04; with 600).
- **WBS-1003** password-policy guidance update (TD-UX-03). Est 1d; safe anytime.
- **WBS-1004** baseline features: history/trash, custom fields, notes, device mgmt,
  KeePass/Bitwarden imports (TD-FEAT-01, FR-IMPORT-001/002).
- **WBS-1005** personal expansion (TD-FEAT-02). **WBS-1006** emergency/social
  recovery + sharing (TD-FEAT-03; separate ADR). **WBS-1007** enterprise (TD-FEAT-04).
  **WBS-1008** passkey custody (TD-FEAT-05; separate architecture, stays reference-only).

## 12. Critical path

WBS-000 → 201/202/203 → 300 → 400 → 206+600 → 207+801–807 → 810–818 & 820–828 → 900 → 1.0.
Supporting: 400 → 205+500 → 700 → 900; 200 → 208 → 900; 300+400 → 204+416/417.
Parallelization per strategic plan §Critical path (ADR-004/005 together; ADR-007 design
parallel to envelope work; relay ops cleanup early; mobile after ABI+envelope stability;
release automation advisory-early/mandatory-late).

## Appendix A — TD coverage

Every open TD maps to ≥1 WP: TD-SEC-01→303/304/404 · SEC-02→612 · SEC-03→302/310/311/312 ·
SEC-04→309 · SEC-05→312/314/614 · SEC-06→101/504/505 · SEC-07→615 · SEC-08→104 ·
ROB-01→602/605 · ROB-02→408/409/608 · ROB-03→410/609 · ROB-04→606/607 · ROB-05→603 ·
ROB-06→610 · ROB-07→315/406 · ROB-08→307/308 · ROB-09→412/413 · ROB-10→306/414 ·
ROB-11→415 · ROB-12→416/417/401 · ROB-13→501/502 · ROB-14→511/512/513 · ROB-15→508 ·
ROB-16→509/510 · NET-01→616 · NET-02→103/617 · NET-03→618 · NET-04→619 · NET-05→620 ·
NET-06→621 · NET-07→622 · CLIENT-01→701/702 · CLIENT-02→702/703/704 · CLIENT-03→707 ·
CLIENT-04→710 · CLIENT-05→711/712 · CLIENT-06→706/713/714/715 · CLIENT-07→716 ·
CLIENT-08→717/718 · CLIENT-09→719 · MOB-01→810/811 · MOB-02→802/810 · MOB-03→807/812/813 ·
MOB-04→807 · MOB-05→814/815/816/817/822 · MOB-06→821 · MOB-07→823/824 · MOB-08→825/826/827 ·
MOB-09→801/804/820 · MOB-10→818/828 · REL-01→901 · REL-02→906/907 · REL-03→908 ·
REL-04→909 · REL-05→905 · REL-06→910 · REL-07→911/912 · UX-01→1001 · UX-02→1002 ·
UX-03→1003 · UX-04→1002 · FEAT-01..05→1004..1008. Deferred-TD list (v0.8.0 session
log): #1→schema-v5/601 · #2→308/701/716 (partial) · #3→dependency majors (ops) ·
#4→101 (done here) · #5→ops · #6→408 · #7→ops+911 · #8→ops · #9→514 · #10→502.

## Appendix B — Requirement coverage

FR-CORE-001→400/402 regression guarantee · FR-CORE-002→402/406/407 · FR-BROWSER-001→
(architecture invariant; 719 verifies) · FR-BROWSER-002→713/719 · FR-BROWSER-003→done
(v0.3.0; maintained) · FR-BROWSER-004→ops (release logging; 913 verifies) ·
FR-SYNC-001→619 · FR-SYNC-002→(implemented; 619/623 maintain) · FR-SYNC-003→619 ·
FR-SYNC-004→623 · FR-SYNC-005→611/1002 · FR-MOBILE-001→813/825 · FR-MOBILE-002→818/828 ·
FR-IMPORT-001/002→1004 · SR-IPC-001→(named pipes implemented; 508/509 complete) ·
SR-IPC-002→105 (docs) + ongoing · SR-IPC-003→101/504/505 · SR-IPC-004→501/502/503 ·
SR-IPC-005→507..512 · SR-EXT-001→(implemented; 719 maintains) · SR-EXT-002→711/713 ·
SR-RELAY-001→619 · SR-RELAY-002→615/616 · SR-RELAY-003→(implemented; 619/910 maintain) ·
SR-RELAY-004→(implemented; maintained) · SR-DOCS-001/002→004/005/105/913 ·
SR-CRYPTO-001→303/304 · SR-CRYPTO-002→304/305/402 · SR-CRYPTO-003→307 ·
SR-CRYPTO-004→308 (+701/716 client sweep) · SR-CRYPTO-005→315/406 · SR-RECOVERY-001→302 ·
SR-RECOVERY-002→310/311/312 · SR-RECOVERY-003→312/314/614 · SR-RECOVERY-004→309/313 ·
SR-DATA-001→408/411/418 · SR-DATA-002→410 · SR-DATA-003→412/413 · SR-DATA-004→414/415 ·
SR-DATA-005→416/417 · SR-SYNC-001→603/604/605 · SR-SYNC-002→602 · SR-SYNC-003→606/607 ·
SR-SYNC-004→612/613/614 · SR-SYNC-005→611 · SR-SYNC-006→615/616 · SR-SYNC-007→103/617 ·
SR-CLIENT-001→702/703 · SR-CLIENT-002→707 · SR-CLIENT-003→711/713/719 ·
SR-CLIENT-004→717/718 · SR-MOBILE-001→801..806/811 · SR-MOBILE-002→812/821 ·
SR-MOBILE-003→813/825 · SR-MOBILE-004→814/822/818/828 · SR-SUPPLY-001→901/902 ·
SR-SUPPLY-002→906/907/908 · SR-SUPPLY-003→909 · SR-SUPPLY-004→911/912 · TV-001→106/
per-phase suites · TV-002→619+relay tests · TV-003→903 · TV-004→004/005/105/913 ·
TV-005→405/407/417/418/904 · TV-006→600 gate · TV-007→811/902 · OP-001/002→623 ·
OP-003→ops/913 · CM/RG→governance (1000-series + register).

## Appendix C — Decision answers and convergence record (post round-3 review)

ADR-003 is at **rev 3**, ADR-004 at **rev 4**, ADR-005 at **rev 4** (three adversarial
rounds; round 3 verified ADR-005's code claims sound and drove the rev-4 completions
below). These answers supersede every earlier revision's text — where any earlier
note disagrees, the ADR bodies govern. Acceptance is the owner's decision.

**ADR-003 (rev 3):** same-UID malicious code is an explicit public non-goal
(capabilities = damage limitation); `Verified` without external review only for
release-gate-reviewed local controls; 1.0 holds on ALL gates; compromise-rotation
drill is a named blocking 1.0 gate; status downgrades flip the matrix row before the
next release cut via register regeneration.

**ADR-004 (rev 4):** slot validity = whole-registry MAC under HKDF(DEK) (canonical
slot-UUID order; stray rows fail closed; repair = verified restore only); epoch
equality is NOT the unlock rule; platform slots survive rotation; recovery commit =
one SQLite transaction (no zero-slot window); epoch advance re-pairs all devices;
recovery entropy = machine-generated 256-bit (raw-wrap ≥128 bits) / Argon2id
MANDATORY for human-typed keys; attempt counters are PER SLOT, capped backoff,
stored beside the high-water sidecar (not in the vault DB); 0.9 revocation is
LOCAL-ONLY (v1 sync carries no epoch; revoke_device has no production caller —
verified); DEK rotation until v2 is sync-disabled-vaults-only, the old relay history
is abandoned (the relay has no purge capability — verified); the epoch high-water
sidecar is fully specified (TOFU on absent file with visible warning; restore
override = reauth + ack + audit; apply-side rejection of below-high-water sync
state; defense-in-depth, not tamper-proof); trusted-device slot post-1.0; recovery
unlock not IPC-exposed until WBS-504.

**ADR-005 (rev 4):** canonical JSON profile (duplicate-key rejection, integers-only,
strict UTF-8, depth cap, base64+byte-cap binary; AAD byte-encoding frozen in golden
vectors; decode never through untyped Value); summaries daemon-owned, lazy,
zeroize-on-lock, UI re-requests (supersedes the plan's "store summaries in UI
state"); domain lookup = FULL LABEL-CHAIN tag sets with mutual full-host containment
(exactly today's semantics incl. bare↔dotted hosts; NO Public Suffix List — the
rev-3 eTLD+1 design was replaced as simpler and drift-proof); local CRUD writes no
domain_mappings today (verified — repository.rs INSERT is test-only), so tag
backfill derives mappings for ~all local entries; migration single-step v1→v2 with
db_metadata rename + legacy-table drop in one transaction (old binaries fail at the
version probe — the rev-2 "initialize_schema-before-check on open" rationale was
code-falsified and retracted), `create()` core-API guard + atomicity, migration
runner's post-commit phase eliminated; fixtures from actual released dumps; padding
claim dropped in v2; mixed-fleet v1 sync disabled before migration.

**Remaining open item (owner input):** relay re-baseline mechanics for DEK rotation
are v2 scope (WBS-624); today's pull-aborts-before-cursor-advance is the recorded
hazard it must eliminate.

**Review note:** ADR-003/004/005 were Accepted by the owner on 2026-09-04 after
three adversarial review rounds. WBS-300 is unblocked. ADR-006..010 remain
Proposed and gate their phases.
