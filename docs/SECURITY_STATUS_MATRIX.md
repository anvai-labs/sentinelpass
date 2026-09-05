# Security Status Matrix

**Last reviewed:** 2026-09-04

**Workspace baseline:** 0.8.0

**Plan:** `docs/STRATEGIC_REMEDIATION_PLAN_2026-09-04.md`

This matrix records current implementation evidence. ADRs and the strategic plan
describe target state and do not change a control's status by themselves.

Status definitions:

- `Implemented`: code exists and has relevant positive and negative automated evidence.
- `Partial`: useful implementation exists, but material hardening/evidence is missing.
- `Experimental`: reachable implementation is not approved for production secrets.
- `Planned`: design/backlog exists but the control is not implemented.

| Control | Status | Current evidence | Residual risk / missing evidence | Target |
|---------|--------|------------------|----------------------------------|--------|
| Local Argon2id password KDF and random salt | Partial | `sentinelpass-core/src/crypto/kdf.rs` (WBS-307, Done after adversarial review): hard MIN+MAX bounds on all four parameters enforced in `validate()` before any Argon2 call (8 hostile-value tests, rejection proven to precede allocation); untrusted wrapped-DEK blobs decoded under a hard size limit; `mobile_profile()` shaped after RFC 9106's constrained option (same t/p, 64,000 KiB memory floor; exact numbers cited in code) | Intermediate buffers still need a zeroization sweep (WBS-308); mobile profile is published-guidance, not on-device-calibrated (on-device wall-clock verification remains open, incl. adopted-parameter ceilings for constrained devices under pair-join) | 0.9 |
| AES-256-GCM encrypted entry fields | Partial | `sentinelpass-core/src/crypto/cipher.rs`; vault crypto tests; typed AAD builder (`crypto/aad.rs`, WBS-303, Done after adversarial review) binds vault/object/purpose/type/schema/crypto version/epoch/tombstone via `AadContextBuilder` (named setters — no positional-argument transposition risk), golden-vector-pinned deterministic encoding, canonical-JSON-profile conformance tests, and a pre-parse size cap | Builder exists but is not yet consumed by any encrypt/decrypt call site — envelope adoption is WBS-304 | 0.9 / ADR-005 |
| Durable encrypted format/versioning | Planned | Schema versioning and legacy `bincode` blobs | Needs self-describing bounded envelope v2, algorithm IDs, golden vectors, and fail-closed compatibility | 0.9 / ADR-005 |
| Key hierarchy and password rotation | Partial | `crypto/keyring.rs`; `vault/mod.rs`; ADR-002; rotation tests; epoch high-water sidecar (`vault/epoch_guard.rs`, WBS-301/ADR-004 rev 4) with rollback-refusal, TOFU, anti-ratchet and atomic-write tests; stable vault UUID + format_version (schema v6); rotation stage→verify→commit→adopt with stale-epoch guard and commit-failure test (WBS-309) | Sync does not enforce epoch revocation (0.11); TOFU warning audit-logged but not yet surfaced in UI | 0.9-0.11 |
| Forgotten-password recovery | Partial | `vault/recovery.rs` + `recover_access` + CLI `recovery setup/recover/status` (WBS-310–312): 256-bit key, CRC-10 checksum (every single-char error rejected, exhaustively tested), verified onboarding (raw AES-256-GCM wrap with vault/slot/type/epoch AAD), recovery without the old password (registry verified with the recovered DEK before any write; all prior slots revoked; epoch advance; new password staged+verified then committed in one transaction; used slot single-use) | Desktop-UI flows not built (CLI-only); no recovery drill yet (WBS-905); local revocation only until sync v2 (WBS-614) | 0.9 / ADR-004 |
| Recovery/device/platform key slots | Partial | `vault/slot_ops.rs` (WBS-302): `key_slots` table (schema v7), whole-registry HMAC-SHA256 MAC under an HKDF(DEK) key (canonical slot-UUID order; fail-closed on any row tamper/removal/resurrection), sidecar digest composition (ADR-004 rev 5), final-usable-slot revocation guard, rotation/pair-join/revoke/create keep wrap+registry atomic (all one-transaction; review round 1 hardened); unit + integration tests incl. tamper negatives | Recovery/platform/trusted-device slot CREATION flows are WBS-310–312 (only the password slot exists today); no recovery drill yet | 0.9 / ADR-004 |
| File permissions and owner validation | Partial | Unix socket/export hardening exists in selected paths | Database/WAL/SHM, directories, tokens, grants, audit, debug artifacts, and Windows ACLs are not consistently explicit/proven | 0.10 |
| Metadata confidentiality | Partial | Secret fields encrypted; credential registry uses keyed equality concepts | Domain mappings, SSH/TOTP metadata, and audit contexts still expose identity metadata | 0.9-0.10 |
| Secret memory lifetime | Partial | `Zeroizing` used for selected key/password types | IPC, sync, native messaging, export, FFI, Swift/Kotlin, UI/DOM, and intermediate buffers remain incompletely covered | 0.10 |
| Audit trail | Partial | Structured audit events exist | Plaintext identity context, no integrity chain, rotation, retention, or verification contract | 0.10 |
| Authenticated portable backup and restore | Planned | Import/export and platform backup scaffolding | No atomic authenticated bundle, historical restore matrix, or routine recovery drill | 0.10 / ADR-008 |
| Database migrations | Partial | Schema v7 migrations and tests exist (v6 identity, v7 slot registry; idempotent column adds, BEGIN IMMEDIATE race tolerance) | Envelope-v2 migration, complete historical fixtures, interruption tests, and fail-closed newer-schema behavior are missing | 0.9-0.10 |
| Transactional multi-table persistence | Partial | SQLite transactions used in selected paths | Sync apply, mappings, registry, cursor/outbox, and relay mutations are not one proven unit of work | 0.10-0.11 |
| Local external-tool grants | Implemented | `external_secret_access.rs`; daemon/CLI/audit tests | Scoped read/write grant model exists; richer approval UX and IPC peer/capability hardening remain | 0.10 UX |
| Native-host/browser IPC authorization | Partial | General token, origin label, constant-time comparison; originless browser-surface requests denied by default since 0.8.x containment (`ipc/server.rs::browser_surface_allowed` + unit tests; `SENTINELPASS_ALLOW_LEGACY_ORIGINLESS` legacy escape hatch) | Origin remains a self-asserted label — a native-host installation capability and scoped capabilities land with ADR-007 / WBS-504-505 | 0.10 / ADR-007 |
| Unix IPC availability isolation | Partial | Owner-scoped socket transport | Serial accept/read path lacks comprehensive deadlines and a stalled client can block service; blocking KDF work needs isolation | 0.10 |
| Windows named-pipe boundary | Partial | Named-pipe transport and encrypted frame support | Explicit current-user SID ACL, remote-client rejection, derived directional sessions, and platform negative tests are missing | 0.10 |
| Single desktop key/database authority | Planned | Daemon and UI vault paths both exist | Duplicate unlocked DEKs/write owners create lifecycle and consistency risk | 0.10 / ADR-007 |
| Sync content confidentiality | Partial | DEK-encrypted payloads; relay stores ciphertext | Routing/version/tombstone/origin metadata is not authenticated with payload; production padding claim is unsupported | 0.11 / ADR-006 |
| Sync delivery correctness | Experimental | Push/pull engine and relay tests | Aggregate acknowledgements, counter-domain mix-up, non-idempotent lost-response retry, trigger echo, NULL corruption, and non-atomic pages risk loss/divergence | 0.11 / ADR-006 |
| Sync conflict and rollback handling | Experimental | Per-entry versions and LWW conflict code | Timestamp-only decisions, no authenticated version lineage/high-water state, and no safe preservation of concurrent secret values | 0.11 / ADR-006 |
| Sync device epoch/revocation | Partial | Device keys/revocation and bootstrap key epoch exist | Epoch is not enforced on every normal request/object; password rotation cannot revoke ongoing stale-key sync | 0.11 |
| Device pairing | Experimental | One-use relay records, expiry, proof, Argon2-hashed tokens | Six-digit HKDF bootstrap remains offline-guessable and pairing token is fetched in a URL | 0.11 / ADR-006 |
| Relay request authentication/replay controls | Partial | Ed25519 request auth, timestamp/nonce checks, rate limiting, cleanup, tests | Forwarded IP trust, target-aware quotas, bounded shared limiter state, storage concurrency, and consistent limits need hardening | 0.11 |
| Relay transport policy | Partial | Rustls client support; config-level transport policy since 0.8.x containment — `sync/config.rs::validate_relay_url` rejects non-loopback HTTP, userinfo URLs, and non-HTTP(S) schemes at `init_sync` and in `SyncClient::new` (loopback HTTP only with `SENTINELPASS_ALLOW_LOOPBACK_RELAY=1`; unit tests cover all negatives) | Client redirect following and token-in-URL behavior still need bounded rules with sync v2 (WBS-617) | 0.11 / ADR-006 |
| Desktop biometric unlock: macOS | Partial | Keychain access control with current-biometry/passcode policy | Needs slot integration, lifecycle/recovery behavior, and enrollment-change end-to-end tests | 0.10 |
| Desktop biometric unlock: Windows | Partial | UserConsentVerifier plus generic keyring retrieval | Consent is not cryptographically bound to key release; needs Windows Hello/protection-bound slot and tests | 0.10 |
| Desktop lifecycle and secret-state handling | Partial | Explicit lock and timed clipboard clearing exist | Background/session/suspend lock, privacy cover, DOM/state scrubbing, and native sensitive clipboard behavior are incomplete | 0.10 |
| Tauri least-privilege policy | Partial | Capability file and CSP exist | Shell/clipboard permissions and localhost WebSocket CSP are broader than demonstrated need | 0.10 |
| Extension sender validation | Implemented | Chrome/Firefox background validation; URL utility tests | Sender/domain/frame validation is present; field targeting, HTTP policy, and browser parity remain separate risks | Maintain |
| Extension field/form safety | Partial | Explicit user-triggered fill | Requested target is ignored by fill path, first password field may be selected, HTTP is permitted, and ambiguous password-change forms need a chooser | 0.10 |
| Extension secret lifetime and permissions | Partial | Session-scoped pending state and explicit clear paths | Plaintext credentials remain temporarily in extension session storage and manifests request broad hosts | 0.10 |
| Passkey support | Partial | `passkey_reference` metadata type and export/lookup guards | SentinelPass is not an authenticator/provider and does not hold recoverable passkey private keys; claims must remain reference-only | Deferred design |
| Android native bridge | Experimental | Kotlin app and Rust bridge scaffold | CI omits JNI feature, enabled build fails, class/export names differ, handle/FFI lifecycle needs work | 0.12 / ADR-009 |
| Android biometric, sync, and autofill | Experimental | UI/service/native method scaffolds | Biometric setter/unlock, sync apply, and AutofillService contain placeholders | 0.12 |
| Android lifecycle/storage/backup | Experimental | Process lifecycle timer and backup XML exist | Privacy cover, screen-lock policy, cleartext deny, explicit file protection, and coherent WAL/device-transfer backup need evidence | 0.12 |
| iOS native bridge and biometric | Experimental | Swift/Rust bridge scaffolds | Biometric data is process-local/unusable after restart; duplicate bridges and FFI ownership remain | 0.12 / ADR-009 |
| iOS lifecycle, Credential Provider, and backup | Experimental | SwiftUI app scaffolding | No scene privacy/lock policy, Credential Provider, protected backup contract, or complete exports | 0.12 |
| Mobile automated assurance | Planned | Core/default-feature builds and lightweight integration tests | No release-grade JNI, simulator/device unlock/CRUD/process-death/biometric/autofill/restore matrix | 0.12 |
| Dependency and source scanning | Partial | Cargo audit, npm audit, Trivy, Dependabot workflows | Security exception lifecycle and release-job dependency need tightening | 0.10-1.0 RC |
| Artifact signing, updater trust, SBOM, provenance | Planned | Release packaging and SHA-256 output | Full platform signing/notarization, signed updater metadata/checksums, SBOM, and provenance are missing | 1.0 RC / ADR-010 |
| Independent security assessment | Planned | Internal gap reviews | Full trust-boundary external review and critical/high remediation required | 1.0 RC |

## Release Interpretation

- `Experimental` surfaces are not approved for production credentials.
- SentinelPass does **not** defend against malicious code running as the local user
  (same-UID processes can read the IPC token and any credential the user can); this
  is a documented non-goal of the 0.9–1.0 line (ADR-003 rev 3). Capability scoping
  (ADR-007) is damage limitation against this adversary, not a defense.
- `Partial` does not mean unsafe in every threat model; it means the public claim must
  name the residual risk and the release cannot rely on the missing control.
- The current detailed execution source is the 2026-09-04 strategic remediation plan.
- Update this matrix in the same change as any security-relevant implementation or
  public claim.
