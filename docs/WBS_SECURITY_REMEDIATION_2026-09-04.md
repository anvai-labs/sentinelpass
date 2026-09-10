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
- **Deliverables:** `crypto/aad.rs` (new): `AadContext` typed builder binding
  vault/object/purpose/type/schema_version/crypto_version/epoch/tombstone, plus
  its own `aad_version`. Canonical JSON via `#[derive(Serialize)]` on a flat
  struct (deterministic field order, no HashMap); duplicate-key rejection via
  typed-struct decode (never through `serde_json::Value`); a pre-parse byte-level
  depth guard (own contract, not serde_json's internal recursion limit).
- **Tests (10, all pass):** P: two golden vectors (with/without tombstone) pinning
  exact bytes; determinism across repeated calls; encode/decode round-trip.
  N: every-field-perturbation property test (9 fields, all pairwise-distinct
  output — proves each field is actually GCM-bound); duplicate-key decode
  rejection; float-in-integer-field decode rejection; excessive-nesting decode
  rejection (with a brace-inside-string false-positive guard); snake_case tag
  serialization for the purpose/type enums.
- **Migration:** none until 304 adopts. **Est:** 2d · **Status:** Done
  (2026-09-05, after adversarial review round 1 — genuinely clean on the
  security-critical claims: field-order determinism, duplicate-key
  rejection, float-in-integer rejection, and the depth guard's UTF-8/escape
  handling were all independently verified against the pinned serde_json
  version, not just read-through. Five findings, none critical, addressed:
  the 8-positional-argument constructor (two adjacent same-typed i32 fields,
  a transposition trap for WBS-304's future call sites) replaced with
  `AadContextBuilder` — named setters, so swapping call ORDER is harmless
  and swapping the wrong METHOD is a visible mistake, not a silent one; the
  `tombstone: Option<bool>` ambiguity (unset-because-not-applicable vs.
  unset-because-forgotten) is now a written contract on the builder's
  `tombstone()` doc, not an implicit convention; `from_bytes` gained an
  explicit pre-parse size cap (4096 bytes) — ADR-005's "hard decode limits"
  applies to AAD, not just the durable envelope; dead test-code cleanup;
  the `.expect()` in `to_bytes` kept deliberately (provably infallible for
  this struct's field types — documented why) rather than pushing a
  never-taken error path onto every future caller) · workspace 514 passed
  / 0 failed, fmt/clippy/TS clean.

### WBS-304 — Versioned summary + secret envelopes
- **Reqs/TDs:** SR-CRYPTO-001/002 · TD-SEC-01 · **Deps:** 303.
- **Deliverables:** `crypto/envelope.rs` (new) + vault encrypt/decrypt paths.
- **Tests:** P: roundtrip; golden vectors. N: cross-field/record/vault/type/purpose/
  tombstone/version/epoch substitution all fail authentication.
- **Migration:** v1 records re-encrypted only via 404. **Est:** 5d ·
  **Status:** In Progress (2026-09-05) — format module DONE: `crypto/envelope.rs`
  self-describing bounded JSON document (magic pre-scan before parsing, 4 MiB
  doc cap, depth cap, exact-length base64 nonce/tag, 1 MiB ct cap, typed-struct
  decode); the embedded `AadContext`'s canonical bytes are the GCM AAD, so
  every identity substitution breaks the tag (tested: vault/object/purpose/
  type/schema/epoch/tombstone/ct/DEK all fail authentication; version+alg fail
  closed with typed errors; duplicate keys rejected; top-level crypto_version
  must agree with the authenticated context copy — drift refuses). Per-field
  plaintext maximums enforced at seal (policy bound under the global cap).
  Round-1 adversarial review of the format module: core binding property
  verified EMPIRICALLY (parse→re-encode injective on identity — integer
  respellings rejected by serde_json, enums exact-tag, base64 strict-
  canonical; no panic path; nonce freshness per seal). 10 findings
  addressed: (1) authenticated context.crypto_version now gated against
  SUPPORTED_CRYPTO_VERSION on BOTH seal and open (ADR-005 fail-closed for
  future scheme bumps, not just envelope_version); (2) THE structural fix —
  open_envelope now takes the EXPECTED context (from the trusted DB row),
  derives the GCM AAD from it, and cross-checks the parsed document context
  against it BEFORE GCM: whole-envelope relocation between rows is refused
  by the SIGNATURE, not by adopter diligence (regression-tested); (3)
  UnsupportedCryptoVersion Display reworded direction-neutral ("found X,
  supports exactly Y" — the old text claimed "newer version, upgrade" even
  for downgrades/tamper); (4) WBS-313 citation corrected (see that entry);
  (5) substitution needles are full key:value patterns; (6) true byte-exact
  golden vector via seal_envelope_with_nonce (fixed DEK+nonce; also the
  WBS-305 seal-parity hook, documented as test/golden-only); (7) ct cap now
  declared-length BEFORE decode, and the 4 KiB AAD size contract enforced
  on the envelope path; (8) deny_unknown_fields on the document + unknown-
  key rejection test; module docs state the SEMANTIC (not byte-level)
  binding guarantee; (9) depth scanner deduplicated into aad::
  json_depth_exceeds (one copy of the escape-tracking logic); (10) magic
  field enforced post-parse, derived from one spelling.
  ADOPTION (entry fields) DONE (2026-09-05): `vault/envelope_ops.rs` routes
  every entry field (title/username = summary purpose; password/url/notes =
  secret purpose) through the envelope. New rows seal v2 bound to
  (vault_uuid, sync_id, purpose, type, schema/crypto versions, epoch) —
  `sync_id` (generated on every add) is the stable object identity, so no
  schema change was needed. Reads are dual (SPENV magic → v2 against row
  identity, else v1 bincode); v1 rows never mix formats on update (row-level
  policy; bulk conversion is WBS-404). Registry equality/sweep/posture paths
  route through the same dual-read (entity fields remain v1 until adopted).
  CROSS-EPOCH policy: entry envelopes use `open_envelope_relaxed_epoch` —
  the DEK is rotation-invariant, so pre-rotation entries must open
  post-rotation; the epoch stays tag-bound (authenticated from the
  document), only not required to equal the reader's current epoch.
  Rotation-variant classes (key slots) use strict open. Adoption tests (4):
  v2 magic on all five columns + roundtrip, legacy v1 row read + update
  stays v1, CROSS-ENTRY blob swap refused (the relocation property, proven
  end-to-end at the vault API), rotation survival. Found+fixed during
  adoption: the epoch-override in open_envelope_impl ran AFTER the AAD
  derivation (every rotated-vault read failed auth — caught by the
  rotation test, ordering fixed + commented); the registry sweep/overview
  deadlocked re-locking key_epoch under the held DB Mutex (epoch now
  fetched once from the held guard and threaded through `*_with_epoch`
  variants).
  ADOPTION ROUND-1 ADVERSARIAL REVIEW addressed (2026-09-05, 10 findings —
  the relaxed-epoch policy, sync_id stability, zero-fill safety, no-half-v2
  reachability, dual-read fail-closedness, deadlock-fix completeness,
  update TOCTOU convergence, and registry_on_add/update plaintext flow all
  verified SOUND against the actual code): (1) CRITICAL — the sync push
  collector still decrypted v1-only, so every new v2 entry permanently
  aborted the whole push; the collector now dual-reads against
  (vault_uuid from db_metadata, row sync_id); (2) CRITICAL — the AAD bound
  the DB CURRENT_SCHEMA_VERSION, so the next routine schema bump would
  auto-migrate forward and then refuse every v2 entry as tampered; entry
  envelopes now bind a dedicated ENTRY_ENVELOPE_SCHEMA constant that moves
  only with the entry-identity contract; (3) CRITICAL — sync pull-apply
  wrote v1 blobs over synced rows (silent downgrade, re-propagated to all
  peers by the sync trigger); apply now seals v2 under the local identity;
  (4) get_entry's audit hint logged the raw title column — harmless v1
  mojibake, but v2 made it the full envelope JSON (vault/entry UUIDs,
  epoch, ciphertext) in the plaintext audit log; now logs the decrypted
  title; (5) seal caps raised to 64 KiB summary / 2 MiB secret (the
  original 4 KiB/256 KiB would abort imports of legacy vaults mid-file);
  (6) field opens return Zeroizing<String>; (7)+(8) per-field key_epoch()
  re-derivation (a full metadata SELECT + two bincode deserializes per
  field, and the deadlock source) replaced by a session-epoch cache on
  VaultManager (AtomicI64; set at create/open, updated at rotation and
  pair-join commit points; seal-staleness is self-healing under relaxed
  reads) — the *_with_epoch threading and its dead seal variant deleted;
  (9) sweep refusal rows now skip-and-warn with entry_id + a failed count
  on SweepReport instead of aborting the backfill anonymously; (10) the
  v2-blob-on-NULL-sync_id refusal branch is now pinned by a test. Known
  residuals: sync_id ownership is by convention (dedicated object_uuid
  column at WBS-404); imports commit per-entry (partial state on abort is
  pre-existing); seal_envelope_with_nonce remains crate-visible for
  golden vectors.
  ALL OBJECT CLASSES ADOPTED (2026-09-05): registry entities (name/notes
  seal v2 against the entity_id PRIMARY KEY; load_entities dual-reads;
  membership labels remain v1 pending entity-schema work), SSH private
  keys (add decrypts the incoming v1 components and re-seals v2 under a
  fresh sync_id; export dual-reads), and TOTP secrets (add/upsert seals v2
  against the row's OWN stable sync_id; code generation dual-reads and
  re-normalizes). Sync SSH/TOTP payloads now carry PLAINTEXT (the whole
  payload is DEK-encrypted for transport) with each device sealing under
  its OWN identity on apply — passing local envelopes through would
  transplant them with the wrong identity; sync fixtures now hold real
  DEK-encrypted material. KEY SLOTS: deliberately NOT converted to SPENV —
  they are already identity-bound through the ADR-004 slot scheme
  (recovery slots carry full vault/slot/type/epoch AAD; password slots
  bind the epoch as wrap AAD), and conversion would churn recovery
  cryptography for zero security gain.
  FINAL REVIEW PASS COMPLETE (2026-09-06, 8 parallel angles over the
  whole adoption; lead aggregator lost to API rate limits — angle reports
  were each self-verified against the working tree and fixed directly).
  SYNC CORRECTNESS: push collectors are per-row skip-and-warn (one
  corrupt pending row no longer permanently wedges push AND pull);
  pull-apply is per-blob skip-and-warn with the cursor advancing (no
  more poison-pill pages); SSH/TOTP wire payloads carry PLAINTEXT with
  TRUE v0.8.x wire backward compatibility (old field names
  private_key_encrypted/nonce/auth_tag deserialize via serde defaults +
  aliases, resolve_sync_secret decrypts with the shared DEK, and both
  apply arms seal the RESOLVED plaintext — an empty-string-sealing
  wrong-variable drift in the SSH UPDATE branch was caught and fixed);
  TOTP apply warns-and-skips when the parent credential hasn't landed;
  TOTP upsert now writes sync_id = excluded.sync_id (a legacy
  NULL-sync_id row re-added can no longer strand a v2 envelope with no
  stored identity) and SELECT errors propagate (no silent masking);
  TOTP v2 seals the NORMALIZED secret (add-time base32 validation
  restored). LOCAL: add_ssh_key refuses already-v2 input with guidance
  (get→add round-trip regression closed); get_entry audits FAILED views
  (tamper probing leaves a trace); registry overview matches the sweep's
  skip-and-warn containment; MAX_CIPHERTEXT_BYTES raised to 3 MiB so the
  2 MiB secret-class policy is genuinely reachable; pair-join validates
  bootstrap.key_epoch >= 1. CONSOLIDATION: read_local_identity (one
  fail-closed SELECT for all six identity sites; per-row fetches hoisted),
  zeroed_legacy_v1_columns (nine sites), SealedEntryFields + a single
  field→purpose owner (add/update/sync no longer restate the mapping),
  session_epoch fallback branch removed (dead complexity; recover_access
  documented as the accepted out-of-session exception), Zeroizing<String>
  + hand-written redacting Debug on the secret-bearing wire payloads.
  Test-honesty residuals (documented, accepted): entity/ssh/totp lack
  class-parity negatives for swap/NULL-identity (the shared core path is
  pinned by the entry tests); the legacy sync-apply resolution path has
  no engine-level test (engine has no test module; resolve_sync_secret is
  pure and the wiring was angle-verified line-by-line after a
  wrong-variable bug was caught and fixed mid-review).
  STATUS: **Done.** Membership-label sealing remains the WP's only open
  minor item (tracked with entity-schema work, WBS-404).

### WBS-305 — Replace bincode-only durable contracts
- **Outcome:** Documented, language-neutral, bounded serialization for all durable
  envelopes (per ADR-005 choice).
- **Reqs/TDs:** SR-CRYPTO-002 · (bincode debt) · **Deps:** 304. **Est:** 3d.
- **Tests:** P: cross-language shape doc + golden files. N: oversized/truncated/
  unknown-version decode rejected before allocation.
- **Status:** Done (2026-09-06, scoped to the `db_metadata` key-material columns —
  the entry/entity/SSH/TOTP blob classes were adopted by WBS-304's envelope work;
  entry/blob re-encryption is WBS-404). `crypto/dbwire.rs` (new): the three
  columns move to versioned SPKDF/SPWRAP/SPNONCE JSON documents — magic +
  version + alg fail-closed, integers only, standard padded base64 with
  exact/declared-length checks, `deny_unknown_fields`, typed-struct decode
  (never `serde_json::Value`). DUAL-READ dispatches on the FULL magic byte
  prefix (never a bare `{`: a legacy bincode KdfParams/nonce blob starts with
  random bytes that are `{` with p≈1/256 — a first-byte sniff would misroute
  ~0.4% of legacy vaults), and the document branch has NO bincode fallback (a
  magic-bearing blob that fails to parse fails closed — no format confusion).
  Ordered pre-parse gates: 4 KiB raw cap BEFORE any parse, shared byte-level
  depth scan, magic pre-scan. Legacy bincode path decoded under
  limit(4096)+fixint+reject_trailing — also closing pair-join's previously
  unbounded `bincode::deserialize` of a PEER-supplied kdf blob. All four
  db_metadata writers (create, rotation, pair-join, recovery) encode through
  `dbwire::encode_metadata_blobs`; pair-join now re-encodes canonically
  instead of storing peer bytes verbatim. Scope boundaries held: `key_slots`
  keeps the frozen bincode slot format (slot recovery depends on it;
  conversion documented as follow-up), pairing-bootstrap transport stays
  bincode (cross-version compat; joiners dual-read), no schema bump, in-memory
  types unchanged. The pre-bootstrap byte-mirror invariant stays intact: real
  NULL-MAC vaults predate the switch (bincode both sides); a document-format
  vault with a NULLed MAC is writer tampering and is REFUSED (pinned by test),
  with the epoch guard refusing the sidecar-bearing variant. Deliverables:
  `docs/DURABLE_WIRE_FORMATS.md` (byte-level field tables for the three
  documents + SPENV v2 summary + frozen legacy bincode layouts). Tests: 21
  codec tests (3 byte-exact golden vectors, dual-read legacy/3-field wrap,
  14 negatives: oversized/truncated/empty/unknown-version/wrong-class/
  unknown-key/duplicate-key/float/short-b64/invalid-b64+utf8/depth-bomb/
  hostile-bincode-prefix/alg/magic-field) + 6 adoption tests (new-vault docs;
  legacy bincode load via both readers; rotation, pair-join, and recovery all
  write documents while the password slot stays bincode and reopens work;
  NULL-MAC document-format tamper refused). Adversarial pre-check resolved:
  dispatch confusion (full-magic + no-fallback), cap bypass (gates ordered
  before allocation), cross-language drift (writer output golden-pinned,
  reader contract structural — the doc states the split normatively).

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
- **Deliverables:** `crypto/kdf.rs`: hard MIN and MAX bounds on mem_cost (64
  MB–1 GiB), time_cost (1–20), parallelism (1–16), output_length (32–1024
  bytes), all enforced in `validate()` (pure integer comparison, no
  allocation) which already runs before every `derive_master_key` call.
  `KdfParams::mobile_profile()`: a lighter RFC 9106-aligned profile pinned
  at the hard memory minimum — explicitly documented as published-guidance,
  NOT on-device-calibrated (no physical mobile hardware available in this
  environment; on-device wall-clock verification remains open follow-up).
- **Tests (8):** P: `test_kdf_params_default`; calibration evidence — both
  profiles' wall-clock time measured and bounded (15s ceiling, sized for
  unoptimized debug-build Argon2id, ~10-20x slower than release: measured
  locally ~0.2-0.3s release / ~5-6s debug for the desktop profile), with the
  mobile profile asserted to never exceed desktop's resource cost on any
  axis; maximum-inclusive (not off-by-one) boundary check. N: 8 hostile
  cases (each field just-over-max and at u32::MAX) all rejected by BOTH
  `validate()` directly and through `derive_master_key`, each measured to
  return in under 50ms — proves rejection happens before any Argon2
  allocation is attempted, not just that it eventually fails.
- **Est:** 2d · **Status:** Done (2026-09-05, after adversarial review
  round 1 — attack-path verification sound: `KdfParams` is fixed-size
  bincode (no prealloc risk), `validate()` is the first line of
  `derive_master_key`, no bypassing call sites, no writer of non-default
  values exists so no brick risk). Findings addressed: (1) the adjacent
  untrusted field — `WrappedKey::from_bincode_bytes`'s bincode `Vec`
  length prefix — could abort the process via `Vec::with_capacity(2^40)`
  BEFORE KDF validation; now decoded under a 4 KiB `bincode::SizeLimit`
  (byte-compatible: fixint + reject-trailing restored explicitly — the
  legacy-blob test caught that `bincode::options()` defaults to varint),
  with a hostile-length-prefix regression test; (2) citations corrected —
  RFC 9106's constrained option is 65,536 KiB t=3 p=4 (ours: same t/p,
  64,000 KiB memory) and OWASP's floor is 19 MiB t=2 p=1 (ours is
  stricter); "RFC-aligned" wording replaced with exact numbers; (3)
  timing-test flake margins widened (calibration 15s→60s — the old value
  held only ~2.1x headroom under workspace-parallel Argon2 contention;
  hostile-rejection 50ms→1s — CI thread-preemption tolerance that still
  proves no Argon2 work began); (4) MAX-mem doc no longer overstates —
  it bounds the REQUEST, not platform executability; pair-join's
  wholesale adoption of peer params + constrained-device ceilings are
  documented as open follow-up with ADR-009 calibration; (5) calibration
  test now asserts mobile ≤ desktop on ALL FOUR axes. · workspace 518
  passed / 0 failed, fmt/clippy/TS clean.

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
- **Status:** Done (2026-09-05) — the guard is enforced INSIDE the registry
  (`slot_ops.rs::revoke_key_slot` refuses when zero usable slots would remain,
  under the BEGIN IMMEDIATE write lock; no caller can bypass it) and tested
  (`final_usable_slot_revocation_is_refused`). There is no public slot-DELETION
  API at all — only revocation, which keeps history. The "force path" this
  entry anticipated is REJECTED AS A DESIGN DECISION RECORDED HERE (this WP's
  own record; review round 2 of WBS-304 flagged that the earlier wording
  misattributed it to ADR-004, whose "no in-place repair path" clause at
  lines 45-46 is scoped to REGISTRY-CORRUPTION repair, not slot force-revoke):
  an explicit-acknowledgment force-revoke would be new lockout surface with
  no legitimate flow — every multi-slot path (onboarding replacement,
  pair-join adoption, recovery) revokes-and-replaces within one transaction
  where the guard's invariant holds at commit. Deleting the last usable slot
  is impossible; deleting any slot is impossible; the guard's negative
  evidence covers the revocation path.

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
  **Status:** Done (2026-09-07) — post-unlock sweep per the v5-registry
  precedent (DEK unavailable at migration time). DOCUMENTED SPEC DEVIATION
  (gate review, finding 5): the atomic-abort semantics above are implemented
  as per-row skip-and-continue — abort-on-first-bad-row would let one corrupt
  row wedge the migration forever. Safety preserved: failing rows are skipped
  byte-untouched with a warning naming the row; seal+open-back+constant-time
  compare verification runs BEFORE any write; deterministic failures
  dead-letter via a residual completion marker (clear the registry key to
  retry). Sync-trigger suppression neutralizes both trigger shapes
  (OF-list and legacy no-list, captured/recreated in-transaction).
  TD-ROB-02 trigger ratchet remains tracked separately.
- **WBS-405 — Verify before activation.** TV-005. Tests: P every envelope + relation
  decrypt/verify. N corrupted target aborts without touching legacy. Est 2d.
  **Status:** Done (2026-09-07, PR #107) — `vault/activation_ops.rs` full-vault
  verification pass (every envelope + domain-mapping relation opens under the v2
  path) before the activation marker is written; corrupted-target abort leaves the
  legacy state untouched.
- **WBS-406 — Atomic activation; block downgrade.** SR-CRYPTO-005, TD-ROB-07. Tests:
  N older client refuses v2 vault. Est 2d.
  **Status:** Done (2026-09-07, PR #107) — `db_metadata.format_version` = 2
  activation marker written via atomic replace; open refuses `format_version`
  greater than `CURRENT_VAULT_FORMAT_VERSION` (fail-closed downgrade/upgrade gate,
  `database/schema.rs`).
- **WBS-407 — Fixtures for every released schema (v1→current).** TV-005.
  Regenerated from actual released schema dumps, not the drifted
  `migrations/v1_initial.sql` labels (ADR-005 rev 3). Est 2d.
  **Status:** Done (2026-09-07, PR #107) — per-version schema fixture ladder
  (v1→v8) regenerated from actual migration shapes; the ladder drives the
  migration/compat tests incl. the Windows directory-refusal regression.
- **WBS-408 — Application services / unit-of-work boundary.** SR-DATA-001, TD-ROB-02.
  Deps — may start after ADR-007 direction. Est 4d.
  **Status:** Done (2026-09-09) — `sentinelpass-protocol/src/service.rs`: `VaultOp`/
  `VaultOpResult`/`ServiceError` (stable codes) + serde-defaulted wire DTOs;
  `IpcMessage::ServiceCall`/`ServiceResult` + `IpcClient::call_service`;
  `sentinelpass-core/src/daemon/service.rs`: `VaultApplicationService` trait +
  `LiveVaultService` executor + wire-core conversions; redacting Debug on
  secret-bearing wire types; review round 1 findings fixed.
- **WBS-409 — Explicit local vs remote write paths (remove trigger echo).** TD-ROB-02.
  Tests: N remote apply cannot re-mark pending. Est 3d.
  **Status:** Done (2026-09-08, write-path PR) — schema v9: `create_triggers` no
  longer installs the echo trigger and `migrate_v8_to_v9` drops both historical
  shapes (OF-list and legacy no-list) in one transaction with the version bump;
  every production write to `entries` carries explicit sync bookkeeping
  (integration-review enumeration found no missed path). Negative:
  `remote_apply_does_not_remark_pending` (synced state + stable
  version/modified_at); migrated-vault e2e test proves first-edit single bump.
- **WBS-410 — NULL preserved end to end.** SR-DATA-002, TD-ROB-03. Tests: P NULL
  roundtrip through encrypt/sync/restore. Est 1.5d.
  **Status:** Done (2026-09-08, write-path PR) — None url/notes stay NULL through
  encrypt/collect/apply/restore; apply-side empty-blob coercion removed; url/notes
  are unconditional full-replace SETs (local None clears to NULL); legacy `X''`
  optional blobs decode as absence on read and convert (not dead-letter) in the
  sweep; `Some("")` never collapses — pinned by
  `empty_string_url_roundtrip_not_coerced_to_null`.
- **WBS-411 — Transactional entry/mapping/registry/audit/sync-state.** SR-DATA-001.
  Est 3d.
  **Status:** Done (2026-09-08, write-path PR) — add/update/delete (entry +
  registry + rotation in one tx), per-blob sync apply tx (entry + domain
  mappings required; derived registry index best-effort inside the tx with
  `mark_backfill_needed` re-arming the repair sweep — the apply asymmetry is
  deliberate: skipped blobs are never re-served), push checkpoint (batch
  mark-synced + cursor in one tx). Acceptance via the SQLite-authorizer
  fault-injection harness (`database/fault_injection.rs`): denial at every write
  action → complete-old or complete-new, with non-vacuity guards. Audit records
  remain file-appends outside vault.db by design (documented boundary).
  Known limitation carried to WBS-605: interrupted push after a committed
  checkpoint wedges on the relay's monotonic `device_sequence` (ADR-006).
- **WBS-412 — Explicit Unix modes + Windows ACLs for sensitive files.** SR-DATA-003,
  TD-ROB-09. Est 2d.
  **Status:** Done (2026-09-07, PR #107) — born-0600 creation for vault db (+WAL/SHM
  via private-umask window), epoch sidecar, IPC token (0700 dir), grants, exports;
  Refuse policy at open for loose existing vault modes with typed
  `SensitivePathError` + remediation hint; Windows ACL coverage documented as
  profile-inheritance (matrix residual). Evidence: `SECURITY_STATUS_MATRIX.md`
  SR-DATA-003 row.
- **WBS-413 — Owner/type/symlink validation.** TD-ROB-09. Tests: N symlink swap
  rejected. Est 1.5d.
  **Status:** Done (2026-09-07, PR #107) — symlink/regular-file/owner (uid) checks
  at every sensitive open with typed refusals; negative tests incl. symlink swap
  (Unix-gated where uid checks require it); TOCTOU residual documented.
- **WBS-414 — Opaque audit identifiers.** SR-DATA-004, TD-ROB-10/11. Est 1.5d.
  **Status:** Done (2026-09-07, PR #107) — credential/registry identifier fields
  opaqued at record time under DEK-derived keys (`opaque_value`/`opaque_event_type`,
  `audit.rs`); negative: raw identifiers never appear (`recorded_entry_contains_opaque_token_not_raw_entry_id`,
  `recorded_entries_contain_opaque_domain_and_entity_tokens`).
- **WBS-415 — Audit chaining/rotation/retention/verification.** SR-DATA-004,
  TD-ROB-11. Tests: N tamper detection. Est 3d.
  **Status:** Done (2026-09-07, PR #107) — HMAC-SHA256 chain under DEK-derived
  key (keyless SHA-256 for locked-period records), size-bounded rotation with
  retention pruning, public `verify_audit_chain` + `AuditVerifyReport`
  (key-bound); negatives detect byte-flip/deletion/reordering/forged-tail and
  locked-period tampering at exact position, plus stripped-chain splice
  suspicion counting; `AuditKeyLease` scope guard bounds key lifetime.
  CLI/UI surface for the verifier remains open (library-level today).
- **WBS-416 — Portable authenticated backup (SQLite snapshot API).** SR-DATA-005,
  TD-ROB-12, ADR-008. Bundle carries vault UUID + epoch but NOT the high-water
  sidecar (ADR-004 rev 4: restore re-baselines via TOFU-warning or override).
  Tests: N live-file copy rejected; bundle tamper fails. Est 4d.
  **Status:** Done (2026-09-08) — `vault/backup_ops.rs`: `VACUUM INTO` snapshot
  under the db lock, SPBACKUP bundle (format registered in
  docs/DURABLE_WIRE_FORMATS.md §6) with HKDF-over-DEK manifest MAC (registry
  precedent), digest+identity+slot-inventory binding, usable-slot-only manifest
  inventory (bounded), no-plaintext-entry-content, atomic 0600 bundle write,
  CLI `backup create`. Negatives: locked/in-memory refusal, overwrite+symlink
  output refusal, snapshot-byte/manifest-field/cross-bundle-splice tamper,
  truncation, trailing bytes, hostile lengths pre-allocation, unknown/dup
  keys, unknown version (typed), wrong password, raw live-file copy rejected,
  depth bomb.
- **WBS-417 — Dry-run validation + atomic verified restore.** SR-DATA-005.
  Restoring an older-epoch bundle on a machine with a newer high-water requires
  reauthentication + acknowledgment, re-baselines the sidecar, and audit-logs
  (ADR-004 rev 4). Tests: N interrupted restore leaves prior state complete;
  restore-older-epoch override flow + abuse negative. Est 3d.
  **Status:** Done (2026-09-08) — `backup_ops::restore_bundle` (static,
  path-based): MAC-first authenticity → target classification + gates
  (allow_replace / allow_epoch_rewind / disable_sync flags; live-sync
  refusal per ADR-008) → full staged validation (identity, slot inventory,
  schema-migration path, registry MAC, WBS-405 full decrypt) → sync-lineage
  neutralization + biometric-ref clearing on the staged copy → single-rename
  swap with checkpoint-then-remove `-wal`/`-shm` → epoch sidecar re-baseline
  as the sequenced second step (TOFU / forward / acknowledged supervised
  override, all audited) → final functional `open()` → only then is the
  retained `<vault>.pre-restore` snapshot replaced (exactly one, replaced
  on the next restore; preserved untouched on any post-swap failure).
  CLI `backup verify --deep` exposes the dry-run; `backup restore` carries
  the three acknowledgment flags. Negatives: older-epoch + equal-epoch-
  different-material restores refused without the ack; live-sync restore
  refused without disable-sync; replace refusal leaves live state complete;
  tampered bundle + wrong password refuse pre-mutation with live state
  complete; pre-restore snapshot retention/replacement verified.
- **WBS-418 — Crash/fault injection harness (migration/CRUD/backup/restore).**
  SR-DATA-001, TV-005. Est 4d. Gate for the phase: fault at any step → complete-old or
  complete-new, never partial.
  **Status:** Done for the backup/restore scope (2026-09-08; migration/CRUD sweeps
  already landed with #121). Restore: staged-write authorizer sweep (fail_at =
  0..N over the staged connection's validation + sync-neutralization statements —
  every denial leaves the live vault complete-old, clean run proves complete-new,
  with a non-vacuity guard) plus swap-phase interruption tests (abort after the
  pre-restore snapshot / sidecar removal / swap / re-baseline: pre-swap aborts
  leave the prior state complete with no litter; a post-swap abort leaves the
  documented refused-open rollback state with the safety net preserved and a
  re-run completing it). Backup: failure injections prove no partial output and
  no staging litter. SR-DATA-005 fixture acceptance: hand-sealed bundles of the
  v6/v7/v8 released schemas restore through the migration ladder and fully
  decrypt (v1–v5 have no durable vault identity, so no manifest can bind them —
  inherent, not a gap).

## 6. Phase 3 — daemon authority & IPC (WBS-500, release 0.10)

Gate: ADR-007 accepted + WBS-408 contracts. **Owner** CM.

- **WBS-501 — Daemon sole DEK owner/writer.** SR-IPC-004, TD-ROB-13. Est 4d.
  **Status:** Done (2026-09-09) — lifetime advisory lock `<vault>.maint-lock`
  (0600/0700, File::try_lock, never unlinked) with coexistence refusal
  (MaintenanceLockHeld, non-zero exit); no-vault startup is a maintenance
  mode serving only status/bootstrap (`VaultCreate` on the blocking pool,
  audited, transitions to live); full `ServiceCall` dispatch. Tests: lock
  mutual exclusion, bootstrap e2e, live refusal negatives.
- **WBS-502 — Desktop+CLI CRUD via daemon services.** SR-IPC-004, TD-ROB-13, deferred
  TD-#10. Est 4d.
  **Status:** Done (2026-09-09) — every UI/CLI vault command routes through
  `VaultOp` (CLI backend: daemon default, FLAGGED
  `SENTINELPASS_ALLOW_DIRECT_VAULT=1` compat lock-guarded + announced; custom
  `--vault` never daemon-served; UI `service_call` same ops, Tauri command
  signatures unchanged). Dual-writer ratchet test pins the direct-open
  allowlist to the offline-maintenance set. Residual: compat env removed at
  1.0 (TD-ROB-13 Partial until then).
- **WBS-503 — Exclusive offline maintenance mode.** SR-IPC-004. Est 2d.
  **Status:** Done (2026-09-09) — `with_maintenance_lock` wired into init,
  passwd, backup create/restore, recovery setup/recover, sync
  pair-start/pair-join; refuses while held (typed error names owner+lock);
  audit ownership during maintenance rides the multi-process-append-safe
  WBS-415 chain.
- **WBS-504 — Scoped capabilities (audience/op/resource/expiry/nonce).** SR-IPC-003,
  TD-SEC-06. Est 4d.
  **Status:** Done for the browser/native-host audience (2026-09-09) —
  hashed-at-rest store (0600), constant-time verify, expiry + revocation
  (restart does not resurrect), fail-closed on unreadable store; negative
  suite (wrong audience/secret/expired/revoked) unit + e2e. General-purpose
  grant-minting CLI surface deferred with the 1.0 protocol hardening.
- **WBS-505 — Native-host installation capability.** SR-IPC-003. Tests: N general
  client claiming NativeHost denied. Est 2d.
  **Status:** Done (2026-09-09) — daemon provisions `native_host.capability`
  (0600) on start; host presents it on every envelope; browser-surface gate
  verifies audience `native-host`; e2e negative (claim without material
  denied, with material served, wrong material denied); legacy windows are
  explicit announced env opt-outs removed in 1.0. Honest scope sentence per
  ADR-003 rev 2 in `capabilities.rs` + SECURITY_ARCHITECTURE §10.
- **WBS-506 — Retain least-privilege external grants.** (extends existing
  `external_secret_access.rs`). Est 1d.
  **Status:** Done (2026-09-09) — external-secret grants (audience-bound,
  token-enforced, write-gated, expiry) retained unchanged beside the
  capability store; existing daemon tests cover grant/token
  enforcement/rotation/revocation; documented in SECURITY_ARCHITECTURE
  §10/§11.
- **WBS-507 — Unix peer UID + owner-only socket.** SR-IPC-005. Est 1.5d.
  **Status:** Done (2026-09-09) — default socket `$XDG_RUNTIME_DIR/SentinelPass/`
  (config runtime fallback), /tmp fallback removed; bind creates 0700 or
  refuses non-private/symlinked/not-owned dirs; clients refuse before
  connect; SO_PEERCRED/getpeereid peer-UID check rejects foreign or
  unverifiable peers; legacy tcp:// branch removed from server and client.
- **WBS-508 — Windows SID ACL + remote rejection.** TD-ROB-15, SR-IPC-005. Est 2d.
  **Status:** Done (2026-09-09) — raw CreateNamedPipeW with explicit
  current-user SID DACL (GENERIC_READ|WRITE), FILE_FLAG_FIRST_PIPE_INSTANCE
  on the first instance (squatting refusal), PIPE_REJECT_REMOTE_CLIENTS;
  FFI type-checked against windows 0.61 for x86_64-pc-windows-msvc; runtime
  verification rides the Windows CI matrix.
- **WBS-509 — HKDF directional session keys.** TD-ROB-16. Est 2.5d.
  **Status:** Done (2026-09-09) — `protocol::session`: HKDF-SHA256 over the
  token with session-random salt derives directional c2s/s2c keys; clients
  negotiate SessionHello/SessionAccept; `IpcConnection` negotiates on both
  endpoints (legacy plaintext accepted only server-side, announced,
  removed 1.0).
- **WBS-510 — AAD-bound session context (proto/direction/type/counter).** TD-ROB-16.
  Est 2d.
  **Status:** Done (2026-09-09) — AAD binds SPIS magic + protocol version +
  sender direction + counter; reflection and cross-direction replay fail
  authentication (tested).
- **WBS-511 — Replay protection, frame bounds, deadlines.** TD-ROB-14, SR-IPC-005.
  Est 3d.
  **Status:** Done (2026-09-09) — strictly-increasing per-direction counters
  (duplicates/reorder refused pre-delivery); 64KiB frame bounds unchanged +
  sealed-frame bound check; 30s deadline bounds every frame read/write
  (negotiation and per-frame).
- **WBS-512 — Bounded concurrent clients.** TD-ROB-14. Est 2d.
  **Status:** Done (2026-09-09) — one bounded task per connection gated by a
  16-client semaphore; a stalled client no longer wedges others (negative
  test proves a second client completes during a stall).
- **WBS-513 — Blocking pool for Argon2/IO.** TD-ROB-14. Est 1.5d.
  **Status:** Done (2026-09-09) — all service ops execute on
  `spawn_blocking`; KDF-heavy paths (unlock, bootstrap VaultCreate) hold a
  per-vault 1-permit gate (ADR-004 rev 5: one Argon2id per vault).
- **WBS-514 — Remove lock-poisoning unwraps.** deferred TD-#9. Est 1.5d.
- **WBS-515 — Protocol upgrade/credential rotation path.** Est 2d.
- **Phase negative suite (gate):** general-client-claims-NativeHost; originless;
  wrong audience/op/resource; expired/revoked capability; cross-direction/reflected/
  replayed frame; wrong peer/ACL; oversized/truncated/stalled/concurrent clients.

## 7. Phase 4 — sync v2 & relay (WBS-600, release 0.11 beta)

Gate: ADR-006 + WBS-300/400. **Owner** CM (client) + SL (relay). May overlap WBS-500
after 408/409 stabilize.

- **WBS-601 — v2 mutation schema.** SR-SYNC-004. Est 3d.
  **Status:** Done (2026-09-10, sync v2 stage 1) — `core/src/sync/v2.rs`:
  `MutationV2` (vault/epoch, object UUID/type, expected+resulting versions,
  origin device, idempotency key, authenticated tombstone state, payload,
  DEK-derived metadata MAC over canonical shared metadata — distinct from
  the ADR-005 per-device storage envelope, identity-domain split
  documented; stage-1 computes/transports/stores the MAC, ENFORCEMENT is
  WBS-612/613); per-field MAC-tamper negatives.
- **WBS-602 — Distinct sequence/version/cursor types.** SR-SYNC-002,
  TD-ROB-01. Est 2d.
  **Status:** Done (2026-09-10, sync v2 stage 1) — `DeviceSequence` /
  `ObjectVersion` / `ServerCursor` newtypes with checked arithmetic, no
  cross-`From`, distinct serde fields; cursor lineage comparisons.
- **WBS-603 — Idempotency + original-result replay.** SR-SYNC-001,
  TD-ROB-05. Est 3d.
  **Status:** Done (2026-09-10, sync v2 stage 1) — relay `mutation_results`
  (TTL `mutation_result_ttl_secs` + per-device cap
  `max_mutation_results_per_device` in cleanup); duplicates replay the
  ORIGINAL durable result (applied AND rejected); post-expiry duplicates
  re-evaluated by CAS and REJECTED, never replayed; deterministic
  content-derived mutation ids survive re-collection with fresh GCM
  nonces; one SQLite transaction per push (results + object state + log +
  counters). Negatives: `duplicate_push_returns_original_rejection`,
  `expired_duplicate_is_re_evaluated_by_cas_and_rejected`,
  `same_version_overwrite_is_rejected_regardless_of_content`.
- **WBS-604 — Per-object acknowledgements.** SR-SYNC-001. Est 2d.
  **Status:** Done (2026-09-10, sync v2 stage 1) — schema v10
  `sync_acked_version` on entries/ssh_keys/totp_secrets (migration seeds
  synced=version, pending=0; fixtures extended); engine records each
  object's own ack in the checkpoint transaction; relay per-mutation
  results are the server-side durable ack.
- **WBS-605 — Outbox removal only on specific ack.** TD-ROB-01. Est 1.5d.
  **Status:** Done (2026-09-10, sync v2 stage 1, after adversarial review
  round 1) — `outbox::apply_push_acks` honors ONLY an Applied ack matching
  the version the client actually sent (mismatched acks are ignored —
  hostile-relay hardening); Applied marks synced+acked in ONE transaction
  with the cursor diagnostic. Conflicts reconcile without wedging: at-or-
  beyond the attempt adopts the relay baseline (pull reconciles content),
  behind it re-bases the row for a FRESH mutation id (review findings:
  lost-response-then-edit and TTL-expiry wedges closed by
  `conflict_behind_our_attempt_rebases_for_a_fresh_mutation`);
  remote-apply arms record `sync_acked_version` so peer-sourced objects
  are editable (`pull_then_edit_push_succeeds`). End-to-end over an
  in-memory relay model serving its log:
  `lost_push_response_retry_completes_without_wedge`,
  `lost_response_then_edit_recovers`,
  `conflict_rejection_converges_without_wedge`; fault-injection sweep
  `apply_push_acks_fault_injection_is_all_or_nothing`. The #121
  device_sequence wedge note in engine.rs is resolved (v2 framing counter
  recorded, never gated). Two-alternative conflict PRESERVATION remains
  WBS-611 (stage 1 adopts the relay state on superseding conflicts).
- **WBS-606 — Relay atomic mutation/entry/sequence/ack.** SR-SYNC-003, TD-ROB-04. Est 2d.
  **Status:** Done (2026-09-10, sync v2 stage 2) — `handlers/sync_v2.rs`:
  one SQLite transaction per push request covers per-mutation result rows,
  object state, the append-only log, the vault sequence counter, the epoch
  high-water, and the device framing counter. Authorizer fault-injection
  sweep (`push_v2_fault_injection_is_all_or_nothing`): denial at every
  write → complete-old across ALL five stores; clean run proves
  complete-new. (The handler was born transactional in stage 1; stage 2
  added the evidence.)
- **WBS-607 — Client atomic page/inbox/object/index/cursor.** TD-ROB-04. Est 3d.
  **Status:** Done (2026-09-10, sync v2 stage 2) — schema v11
  `sync_dead_letter` (hard-capped at 1,000, fail-closed at overflow); the
  pull page folds applies, dispositions, and the cursor advance into ONE
  transaction (`pull_page_fault_injection_is_all_or_nothing`); order-
  dependent applies (TOTP parent later in the page) get one bounded
  requeue pass (`deferred_totp_parent_resolves_within_one_run` — the
  pre-v2 permanent silent loss is gone); unappliable mutations are
  dead-lettered with their server_sequence as the disposition key and the
  cursor passes them only with a disposition recorded
  (`unappliable_mutation_is_dead_lettered_and_page_advances`); cap
  overflow rolls the page back and errors until purged
  (`dead_letter_cap_fails_closed_until_purged`). Skip-and-advance is
  removed from the pull path.
- **WBS-608 — Remove remote-apply trigger echo.** TD-ROB-02 (sync half). Est 1.5d.
- **WBS-609 — Nullable encrypted fields preserved.** TD-ROB-03 (sync half). Est 1d.
- **WBS-610 — One bounded paginated path (normal+full).** TD-ROB-06. Est 3d.
- **WBS-611 — Preserve concurrent alternatives; expose conflicts.** SR-SYNC-005,
  TD-UX-02. Est 3d.
  **Status:** Done (2026-09-10, sync v2 stage 3) — schema v12
  `sync_conflicts` (one durable alternative per object, DEK ciphertext
  stored relay-shaped, re-sealed under the LOCAL identity at resolution);
  pull-side guard records any mutation (tombstones included) hitting an
  object with an UNSYNCED local edit (equal-or-greater version; stale
  blobs keep the lineage skip) and marks `sync_state = 'conflict'`;
  push-side conflicts mark conflicted instead of adopting; resolvers
  keep-local (re-version above the peer + CAS re-base) and take-remote
  (apply the alternative through the normal seal-under-local path); CLI
  `sync conflict-list` / `conflict-resolve --object-id [--take-remote]`;
  conflict count surfaced through `SyncStatus` and the daemon service
  contract (`ServiceSyncStatus.conflicts`, serde default). Evidence:
  `conflict_preserves_alternatives_and_resolves_keep_local`,
  `conflict_take_remote_applies_the_alternative`,
  `tombstone_vs_edit_conflict_is_preserved_and_resolvable`,
  `take_remote_resurrects_a_locally_deleted_row`. After adversarial
  review round 1: content applies are RESURRECTION-SAFE (clear the local
  tombstone — delete-vs-edit races and take-remote resolution can no
  longer silently no-op into an invisible row); resolutions are atomic
  (pre-adjust + apply + record removal in ONE transaction — a failed
  take-remote leaves the row conflicted with the record intact);
  stale alternatives are purged when the row applies past them; the
  conflict surface counts stored records OR conflicted rows (whichever
  is larger) so transient record-less windows stay visible. The relay
  same-version-rejection half landed with WBS-603 (stage 1).
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
  **Status:** Done (2026-09-08, PR #126) — extension save paths use WHATWG
  structured parsing (IDN→punycode, ports/userinfo/IPv6; unparseable values
  refused, not stored raw); plain-HTTP saves warn with explicit consent on
  all three save surfaces (25 test cases; ~60 adversarial inputs, zero
  wrong-host results). Hard default-deny autofill remains WBS-711.
- **WBS-707 — Minimize Tauri capabilities + CSP.** SR-CLIENT-002, TD-CLIENT-03. Est 2d.
  **Status:** Done (2026-09-08, PR #126) — grep-evidence capability audit:
  tauri-plugin-shell removed entirely (dependency, registration, config),
  unused dialog/clipboard grants dropped, capabilities single-sourced in
  default.json, CSP script-src 'self' with Tauri IPC origins; 18-case
  negative gate test tripwires capability/CSP regressions in CI.
- **WBS-708 — Remove production debug-unlock artifacts.** Est 1d.
  **Status:** Done (2026-09-07, PR #107) — debug-unlock paths removed from
  production wiring; no plaintext unlock shortcut remains (stream C verification
  + gate review).
- **WBS-709 — Native expiring/sensitive clipboard.** Est 1.5d.
  **Status:** Done (2026-09-08, PR #126) — secrets copy Rust-side (arboard)
  with native sensitive markers (macOS ConcealedType, Windows
  exclude-from-monitoring); expiry (30s, re-armed) clears only if the
  clipboard still hashes the registered secret; vault-lock and app-exit
  clear hooks; the clipboard-manager plugin and its IPC surface are
  removed entirely. Known residual (documented): frontend-timed expiry is
  throttled in hidden webviews — backend timer is the tracked follow-up.
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
