# Independent Security Review — Commissioning Brief (WBS-911)

**Status:** Draft for the owner (commissioning package; not yet sent).
**Scope owner:** Core maintainer (CM). **Gate:** ADR-003 §1.0 — *zero unresolved
critical/high trust-boundary findings* (TD-REL-07, WBS-911 commissioning,
WBS-912 remediation closure).
**Related:** `docs/WBS_SECURITY_REMEDIATION_2026-09-04.md` §Phase 7 (WBS-911/912);
`docs/RELEASE_BLOCKER_REGISTER.md` (P0 table + 1.0 gate section);
`SECURITY_ARCHITECTURE.md`; `docs/SECURITY_STATUS_MATRIX.md`.

This brief is what the owner hands to a candidate review firm. Component names,
paths, and acceptance criteria below are taken from the actual workspace so the
engagement can be quoted and staffed without discovery.

## 1. Objective

An independent trust-boundary review of SentinelPass, a local-first password
manager (Rust workspace + Tauri desktop UI + browser extensions + native
messaging + optional E2E-encrypted sync relay + mobile bridges), sufficient to
discharge the ADR-003 1.0 gate: **zero unresolved critical/high findings on any
trust boundary**. The review is a precondition of the 1.0 release, not a
post-release audit.

## 2. Design baseline (what the reviewers receive as ground truth)

Accepted architecture decisions (all owner-accepted after adversarial review;
see `docs/decisions/adr/`):

| ADR | Subject |
| --- | --- |
| ADR-001 | Credential registry by logical entity |
| ADR-002 | Master-password rotation (DEK re-wrap, epoch advance) |
| ADR-003 | Security baseline and release gates (rev 3) |
| ADR-004 | Recovery key slots and revocation (rev 5) |
| ADR-005 | Authenticated vault envelope v2 (rev 4) |
| ADR-006 | Sync protocol v2 (rev 2) |
| ADR-007 | Daemon authority and IPC capabilities (rev 2) |
| ADR-008 | Authenticated backup and verified restore (rev 2) |
| ADR-009 | Mobile ABI and platform keystore (rev 2) |
| ADR-010 | Release assurance and provenance (rev 2) |

Plus: `SECURITY_ARCHITECTURE.md` (threat model §2, cryptographic design §3,
daemon authority and exclusive maintenance §11, sync protocol v2 §12, desktop
hardening §13), `docs/SYNC.md`, `docs/DURABLE_WIRE_FORMATS.md` (canonical JSON
profile for durable formats), `docs/DEPENDENCY_EXCEPTIONS.md`, and
`docs/SECURITY_STATUS_MATRIX.md` (per-control evidence and residual-risk
statements — reviewers are asked to treat the matrix's residual-risk column as
the vendor's own claim inventory to attack).

## 3. In scope (surfaces and entry points)

| Surface | Components | Trust boundary exercised |
| --- | --- | --- |
| Core crypto and vault | `sentinelpass-core/src/crypto/` (`kdf.rs` Argon2id profiles, `cipher.rs` AES-256-GCM, `envelope.rs` SPENV v2, `aad.rs` typed AAD, `keyring.rs` key hierarchy/wrapping, `password.rs` generation) and `sentinelpass-core/src/vault/` (`mod.rs` CRUD, `envelope_ops.rs`, `activation_ops.rs`, `slot_ops.rs` key-slot registry + MAC, `recovery.rs`, `backup_ops.rs` `.spbackup`, `epoch_guard.rs`, `registry_ops.rs`) | Envelope/AAD binding, slot-registry MAC, epoch rollback refusal, recovery single-use, bundle MAC-first restore |
| Daemon IPC and capabilities | `sentinelpass-daemon/`, `sentinelpass-core/src/daemon/` (`ipc.rs`, `service.rs` `LiveVaultService`, `vault_state.rs`, `native_messaging.rs`), `sentinelpass-protocol/` (envelope, `service.rs` `VaultOp` contract) | Unix socket (owner-only runtime dir, peer-UID check, session crypto, deadlines) and Windows named pipe (explicit DACL, squatting refusal, `PIPE_REJECT_REMOTE_CLIENTS`); `native-host` installation-capability gate; external-tool grants (`GetExternalSecret`/`SaveSecret`) |
| Native messaging host | `sentinelpass-host/` | Length-prefixed stdio JSON protocol between browser and daemon; request/response validation |
| Browser extensions | `browser-extension/chrome/` (MV3), `browser-extension/firefox/` (MV2, shared source via `scripts/build-extension.mjs`) | Content-script field targeting, save-prompt capture pipeline, background TTL secret store, sender validation, per-site grants |
| Sync protocol v2 and relay | `sentinelpass-core/src/sync/` (`v2.rs`, `outbox.rs`, `crypto.rs`, `auth.rs` Ed25519 canonical signing, `pairing.rs`, `engine.rs`, `client.rs`), `sentinelpass-relay/` (Axum server: Ed25519 auth middleware, nonce dedup, device revocation, epoch high-water gate, rate limiting, v1 retirement/410) | Mutation authentication (DEK-derived HMAC), pairing-secret bootstrap, replay/rollback, dead-lettering, relay storage of ciphertext + opaque MAC only |
| Mobile bridge FFI | `sentinelpass-mobile-bridge/` (generated C ABI + `catch_unwind` exports), Kotlin `VaultBridge`, Swift bridge, platform keystore slots (Android Keystore auth-bound key; iOS Keychain `kSecAccessControl`), Credential Provider extensions | FFI ownership/zeroization contract, ABI handshake, DEK sealing/unsealing via platform keystores |
| Desktop app | `sentinelpass-ui/` (`src-tauri/` commands, `capabilities/default.json` ACL, CSP) | Tauri command surface, least-privilege capabilities, secret state lifetime |
| Recovery/backup/rotation UX contract | CLI offline-exclusive ops: `recovery setup/recover/status`, `backup create/verify/restore`, `passwd`, and their exclusive maintenance lock (`<vault>.maint-lock`) | Fail-closed semantics; drill evidence in `scripts/drills/` and `.github/workflows/drills.yml` |

## 4. Review methodology expectations

The engagement should combine, at the firm's discretion but covering all of:

1. **Design review** — the ADR set (§2) against the implementation, with
   explicit attention to gaps between accepted design and shipped code.
2. **Targeted code audit** — per surface in §3, prioritized by trust-boundary
   exposure: crypto/vault first, daemon IPC + native messaging second, relay +
   sync third, extensions/mobile fourth.
3. **Protocol analysis** — the three wire protocols: daemon IPC (Unix/Windows
   transports + capability envelope), browser native messaging, and sync v2
   (client↔relay), including replay, rollback (epoch), downgrade, and
   cross-version behavior against `docs/DURABLE_WIRE_FORMATS.md`.
4. **Cryptographic implementation review** — Argon2id parameter handling,
   AES-256-GCM nonce discipline, HKDF domain separation (envelope vs slot
   registry vs pairing vs session keys), Ed25519 canonical signing string,
   constant-time comparisons, and CSPRNG usage (the TD-SEC-09
   `thread_rng` hardening item was closed 2026-09-13 — all production
   secret/key generation now draws from `rand::rngs::OsRng`; independently
   re-verify that claim, which an earlier adversarial review round caught
   being made prematurely).
5. **Verification work** — the vendor's automated evidence is reproducible:
   `cargo test --workspace`, the `fuzz/` crate (envelope open, sync v2 parse
   both ends, IPC frame decode, import/export byte parse), `cargo audit` under
   the governed `.cargo/audit.toml` policy, the Chromium E2E suite
   (`browser-extension/e2e/`), and the recovery/backup/rotation drills
   (`scripts/drills/`). Reviewers are encouraged to build fuzzing/PoC work on
   these harnesses.

**Severity scheme** (findings must use it verbatim, so the register can absorb
them):

| Severity | Definition |
| --- | --- |
| Critical | Breaks a core security property (confidentiality/integrity/authenticity of vault data, or auth of a trust boundary) exploitable within the documented threat model, without privileged local access |
| High | Same impact class with meaningful preconditions (a specific configuration, a sibling vulnerability, or limited local access); or a trust-boundary bypass with non-secret impact |
| Medium | Material weakness in defense-in-depth or fail-closed behavior; exploitation requires conditions outside the primary threat model |
| Low | Hardening opportunity with a concrete (if unlikely) path |
| Informational | Correctness/documentation/claim mismatch without direct exploitability (e.g., a residual-risk statement that understates reality) |

Each finding must state: severity, affected component and file path(s),
preconditions, impact within the threat model, a proof-of-concept or concrete
exploitation sketch (fuzz input, protocol transcript, or unit test is
preferred), and remediation guidance.

## 5. Environment and access needs

- **Code:** the full repository at the 1.0 RC tag (`v*` tag on `main`); git
  history access for context. The 2026-09-04 remediation program history
  (`docs/STRATEGIC_REMEDIATION_PLAN_2026-09-04.md`,
  `docs/WBS_SECURITY_REMEDIATION_2026-09-04.md`, `TECHNICAL_DEBT.md`) explains
  why each control looks the way it does.
- **Build:** per `CLAUDE.md` / `BUILD.md` — Rust 1.89+ workspace
  (`cargo build --workspace`), Node 24 + npm 10 for web assets
  (`npm run web:build`), platform dependencies listed there. Linux reviewers
  need the GTK/WebKit dev packages only for the Tauri UI; all headless surfaces
  (core/CLI/daemon/host/relay) build without them.
- **Test evidence and vectors:** in-repo — golden vectors for the typed AAD
  builder and byte-exact envelope sealing (`sentinelpass-core/src/crypto/`
  tests), fixture ladders for historical schema/envelope versions
  (`vault/activation_ops.rs`, backup restore fixtures), the `fuzz/` corpus,
  and the drill evidence transcripts produced by `scripts/drills/` (see the
  `drills` workflow artifacts).
- **Platform coverage:** Linux and macOS are build-and-test-first platforms;
  Windows-specific behavior (named-pipe DACL, Hello-bound biometric slot) and
  mobile (Android emulator matrix, iOS simulator) ride the project CI
  (`android.yml`, `ios.yml`, `extension-e2e.yml`) — reviewers should request
  runner access or artifacts rather than re-provisioning devices.
- **Kickoff:** a 2-hour threat-model briefing with the core maintainer; a
  named contact for questions with a 72-hour response target (matching
  `SECURITY.md` response norms); no access to any real user vault data — all
  review work uses synthetic vaults (the drill scripts demonstrate the
  isolated-environment pattern).

## 6. Deliverables

1. **Findings report** — every finding in the §4 severity scheme with PoC and
   remediation guidance; an executive summary mapping findings to the trust
   boundaries in §3; explicit statements where a documented control was **not**
   verifiable (absence of evidence is a reportable result).
2. **Claim audit** — a pass over `docs/SECURITY_STATUS_MATRIX.md` and
   `README.md`/`SECURITY_ARCHITECTURE.md` security claims, flagging any public
   claim the evidence does not support (the project treats falsified claims as
   P0; see the TD-SEC-09 precedent in `TECHNICAL_DEBT.md`).
3. **Remediation consultation** — a working session per critical/high finding
   with the maintainer during the fix window (WBS-912, estimated 5d of
   maintainer time).
4. **Re-review** — written confirmation, per critical/high finding, that the
   shipped remediation closes it (or a documented accepted-risk decision via
   ADR, per the register's status vocabulary). This confirmation is the
   evidence the register's 1.0 gate points at.

## 7. Acceptance criteria (tie-back to the register)

- Every finding triaged into the `docs/RELEASE_BLOCKER_REGISTER.md` vocabulary
  (`Open` / `In progress` / `Closed (evidence)` / `Accepted-risk` with an ADR).
- **Gate:** zero unresolved critical/high trust-boundary findings at re-review
  (ADR-003 1.0 gate; TD-REL-07 closure).
- Remediations merged with tests (the project's own WBS standard: a work
  package is `Done` only with its tests merged; `Verified` only after
  WBS-901/911 evidence).
- Matrix rows updated in the same change as any claim affected by a finding
  (per `docs/SECURITY_STATUS_MATRIX.md` "Release Interpretation" rules).

## 8. Out of scope

- Social engineering, phishing, or any testing against the maintainer or users.
- Any access to, or analysis of, the maintainer's or any real user's actual
  vault data; all engagement work uses synthetic vaults.
- Denial-of-service against, or load testing of, any production relay
  infrastructure; relay DoS resilience is reviewed as code + local-instance
  behavior only.
- Store review processes (Chrome Web Store, Mozilla Add-ons, Apple App Store,
  Google Play) and the mobile platforms' own sandbox guarantees beyond what the
  bridge code assumes.
- Physical attacks, hardware fault injection, and side-channel measurement
  attacks (cache/power/EM) — noted as future work, not 1.0 gating.
- Attacks by malicious code running as the same OS user (the documented
  non-goal of the 0.9–1.0 line, ADR-003 rev 3 and `SECURITY_STATUS_MATRIX.md`
  "Release Interpretation"): capability scoping is damage limitation against
  this adversary, not a defense. Findings that reframe this boundary are in
  scope as design feedback, not gate findings.
- Dependency CVE volume per se (covered by the governed audit/exception
  lifecycle: `.cargo/audit.toml`, `docs/DEPENDENCY_EXCEPTIONS.md`,
  tag-time audit gates in `release.yml`) — except where a dependency
  vulnerability is reachable through an in-scope trust boundary.

## 9. Logistics (for the owner to complete before sending)

- Firm selection, contracting, and pricing (placeholders: effort estimate in
  `docs/WBS_SECURITY_REMEDIATION_2026-09-04.md` §Phase 7 is "3d+external" for
  commissioning plus firm-specified review duration).
- Target review window: immediately after the 1.0 RC tag exists, so reviewers
  get the exact shipped artifact set; WBS-912 remediation window follows.
- Contact roster and secure channel for the findings draft (per `SECURITY.md`
  reporting norms; do not use public issue trackers for pre-publication
  findings).
