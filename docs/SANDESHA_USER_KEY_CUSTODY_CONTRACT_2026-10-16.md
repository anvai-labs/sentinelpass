# User-owned key custody: portable provider contract and Sandesha integration

Date: 2026-10-16. Status: **proposed contract / implementation handoff**, not a
shipped capability, release approval or security certification. Owner requested
this design for the SentinelPass session; implementation starts with the gates
below. No credentials, keys, grants, runtime configuration or dependencies changed.

## 1. Decision and scope

Keep one logical OpenPGP mailbox identity per owner/key epoch across approved
devices for the first release. Devices recover the same public certificate and
private mail-key material, but protect access with distinct local protection keys
and have separate device identities, enrollment and revocation records. Signing
and encryption keys remain distinct components of the mailbox identity. Old epochs
are retained only under an explicit historical-decryption policy.

SentinelPass is an **optional, user-owned custody provider**, alongside qualified OS
keystores and the existing user recovery kit. It is not a mandatory account service.
The operator's VPS/service-credential vault must never receive users' private mail
keys, mail/storage recovery secrets, or a grant that releases them. The operator's
master password is not a recovery route for a user's mailbox. A user's personal
vault master password can unlock their chosen custody provider; disclose that trust.

Use a small Rust core contract with generated TypeScript and native ABI bindings.
Swift/Kotlin implement platform lifecycle and keystore adapters, not OpenPGP or a
second envelope algorithm. Do not introduce Go or Python into the runtime. Reuse
Anvai OpenPGP for mail operations and preserve Sandesha's existing profile-aware
recovery envelopes. A generic `get_password(service, account)` keyring API can be
an internal software adapter; it is not the application contract because it drops
scope, epoch, authorization, lifecycle and assurance information.

Default: Sandesha continues to work with its qualified recovery path without
SentinelPass. Offer an explicit "Remember on this device" choice only for qualified
platform protection; offer "Use my SentinelPass vault" as an opt-in provider that
may be remembered as that user's default. Installation alone never selects it.
Unsupported or locked providers return an actionable error; never silently fall
back to a weaker store or create replacement mail keys.

## 2. Evidence reviewed and honest capability map

Reviewed SentinelPass local and remote develop at
`84c7f58d012b428a4f8635d87ae988e0f1ebfc31`; latest release queried was v0.17.0.
Recheck before implementation. Read SECURITY_ARCHITECTURE.md with its status warning,
SECURITY_STATUS_MATRIX.md, ADR-003/004/005/006/007/009/013/014/015/016/017.

| Existing surface | Reuse / limit |
| --- | --- |
| `sentinelpass-mobile-bridge/src/abi.rs` | ABI v2, BASE + PLATFORM_KEYSTORE advertised. RELAY_SYNC_V2 is explicitly NOT advertised. An iOS/Android UI does not establish cross-device custody sync. |
| `sentinelpass-core/src/biometric.rs`, `biometric_hello.rs` | Existing keyring/biometric slot mechanisms; do not equate storing a secret with hardware nonextractability. Review exact per-platform path. |
| `ios/.../Services/KeychainSlot.swift` | Existing auth-bound slot adapter; status matrix still records enrollment/device-evidence gaps. Revalidate rather than claiming complete support. |
| `android/.../slot/BiometricKeystore.kt` | Existing auth-bound signing-slot adapter. Source comments alone do not prove TEE/StrongBox; inspected creation path did not establish a runtime security-tier assertion. Qualify actual key properties. |
| SERVICE_CREDENTIALS.md exact-entry grants | Reuse policy/step-up patterns, not server service tokens or generic password retrieval for user mail. Same-UID/IPC-token and root limitations are documented. |
| ADR-006 sync v2 | Reuse reviewed transactional/epoch/conflict model only after applicable endpoints/platforms are qualified. Never revive v1 or CloudKit/Drive file-sync as a shortcut. |
| Sandesha `lib/encryption/recovery/contract.ts` | Existing provider-neutral OpenPGP handle, explicit v4/v6 profile, seal/open/lock and optional sealMany. Custody must feed this boundary, not replace it. |
| Sandesha recovery-kit/reference/storage/session modules | Existing independent mail and storage secrets, owner/reference checks, opaque runtime custody, cancellation and recovery proof. Preserve bytes and authority checks. |

This document adds a requirement, not proof of any missing capability. Existing
OpenPGP *service-client enrollment* proves possession for service authorization;
it is not a user-mail-key synchronization protocol.

## 3. Key hierarchy and device model

```text
Owner's mailbox identity, epoch E (same on approved devices)
  public certificate --------------------> authenticated public directory
  private mail material Kmail
          |
          +-- existing envelope encrypted under Rmail (random 32 bytes)

Owner's separate local-journal key
          +-- existing storage envelope under Rstorage (independent random secret)

                      User-selected custody
                /               |                 \
       offline recovery kit   personal vault     device-local slot
          user holds it       protects Rmail/     protects Rmail/
                              Rstorage as         Rstorage under
                              distinct objects    local OS protection
                                   |
                           approved E2E vault sync
                           (separate qualification)

Mac device protection != iPhone protection != Android protection
Rmail -> Kmail recovery happens only inside trusted client crypto runtime
```

Initial integration stores/protects existing bounded recovery-secret objects, not
raw OpenPGP secret packets, the whole vault DEK, or the combined recovery file in a
password field. A custody secret grants effective access to its corresponding
encrypted private material; label it as sensitive key material, not harmless metadata.
Preserve separate mail/storage purposes and existing envelope/reference digests.
Do not derive these secrets from an OIDC password, access token, PIN or public key.

This minimizes format churn: the cryptographic envelope stays portable when the
user changes custody providers. Moving provider requires proving recovery on the
destination before retiring the source. A provider-specific encrypted wrapper is
not itself a portable recovery format. Device-only wrappers must not be copied to
another device or placed into ordinary cloud backups as if they were recoverable.

For native paths a device's auth-bound OS key protects the local slot or vault
unlock. For browser-only paths a website cannot assume direct access to Keychain,
Android Keystore or a native Rust daemon. Recovery-kit entry is the baseline;
an extension/native bridge or qualified WebAuthn PRF adapter is optional. Login
passkeys do not automatically supply mail decryption keys.

## 4. Ownership, central coordination and lifecycle

Scope is immutable issuer + subject + mailbox ID (Sandesha translates its existing
owner type); email addresses and aliases are display/routing values, never ownership
keys. Include application namespace and purpose to prevent cross-product reuse.

The central application can coordinate authenticated public certificates, epochs,
device enrollment/revocation metadata and optional opaque encrypted objects. It
cannot recover private keys from OIDC login. Sandesha's current reference API accepts
references/hashes, NOT encrypted private bundles; server-side encrypted bundle sync
would be a new explicitly reviewed endpoint, not a widening of that route.

| Event | Required behavior |
| --- | --- |
| First enrollment | Generate in trusted crypto runtime; verify independent recovery; atomically bind owner/profile/epoch/reference; explicitly enroll selected custody provider; publish public certificate separately. |
| Additional device | Authenticate account AND prove existing-key custody using an approved device or recovery kit; bind new local device identity/protector; verify exact certificate/reference and signed-encrypted round trip before usable state. Login alone cannot enroll or replace keys. |
| Routine unlock | Exact-owner, exact-object read lease; platform authentication according to consent/policy; no mutation authority. Unlocked vault alone is not app authorization. |
| New browser profile / private browsing | No assumption of persistent local keystore; explicit recovery/pairing; no secret cookie/localStorage. Ephemeral sessions offer no remembered-device claim. |
| Logout / background / account change | Revoke local leases, cancel operations, terminate Worker custody, clear owned secret buffers best-effort. Platform lifecycle overrides timers when the OS suspends a process. |
| Lost device | Revoke server/session/vault-device authority, deny future sync, remove local slot where possible. Offline devices may retain keys and old ciphertext; remote wipe is not guaranteed. |
| Suspected device/key compromise | Shared-mail-key model requires rotation to a NEW mail identity/epoch for future mail and distribution only to remaining approved devices, plus compromised wrapping/sync-secret rotation. Rewrapping the same private key is insufficient. |
| New key epoch | Preserve old reference bindings as historical state; no mixed-profile reinterpretation. Current one-subkey provider cannot silently accumulate subkeys. Versioned identities and separately gated archive access avoid inventing multi-subkey support. |
| Historical decryption | Old keys may decrypt old mail only through explicit archive policy, never regain current signing/send authority. This API remains a separate gate; do not weaken current expiry/revocation checks. |
| OIDC reset | Restores login only; no key reset/recovery. If all keys/recovery sources are lost, old mail may be unrecoverable; explain before enrollment. |
| Provider migration | Stage destination under fresh mutation approval, recover/compare current references and prove possession, record confirmation, then separately authorize source retirement. Failure leaves source usable. |
| Stale backup / conflicting sync | Quarantine; never last-writer-wins key identity/epoch. Reconcile against independently current authority and retained device pins. Restoring all trust state together cannot prove freshness. |

No forward secrecy or WhatsApp-style ratchet claim follows from ordinary OpenPGP
archives. Disabling a device cannot revoke plaintext, a secret or a recovery kit it
already copied. Public-key directory authentication does not alone defeat a malicious
operator replacing both a directory and its web client; retain independent recipient
fingerprint confirmation and treat transparency/signed distribution as separate work.

## 5. Provider contract v1 (semantic sketch, not an implemented SDK)

Separate storage, local protection, authorization and synchronization capabilities.
One provider may implement multiple ports, but no caller assumes all of them.
Keep the neutral contract free of email rendering, OIDC token formats and vault-wide
CRUD. Sandesha's adapter selects exact objects after verified owner/reference lookup.

```ts
type Assurance = 'software' | 'os-protected' | 'hardware-backed' | 'unknown';
type Purpose = 'mail-recovery' | 'storage-recovery';
interface ScopeV1 {
  readonly version: 1;
  readonly namespace: string;
  readonly issuer: string;
  readonly subject: string;
  readonly mailboxId: string;
  readonly purpose: Purpose;
}
interface ObjectRefV1 {
  readonly objectId: string;        // opaque, not a secret or bearer capability
  readonly revision: string;        // canonical bounded decimal CAS version
  readonly keyEpoch: string;
  readonly bindingSha256: string;   // existing envelope/reference binding
}
interface ProviderInfoV1 {
  readonly protocol: 1;
  readonly providerId: string;
  readonly assurance: Assurance;
  readonly userVerification: 'per-use' | 'session' | 'none';
  readonly scopeEnforcement: 'app' | 'os' | 'hardware';
  readonly canSync: boolean;         // false until platform/transport qualified
  readonly canTransferToRuntime: boolean;
  readonly canPortableExport: boolean;
  readonly maxSecretBytes: number;
}
// Opaque unforgeable runtime/transport capabilities, NOT caller-created strings.
interface RuntimeReceiver { readonly kind: 'registered-runtime-receiver' }
interface RuntimeSource { readonly kind: 'registered-runtime-source' }
interface StepUpApproval { readonly kind: 'operation-bound-step-up' }
interface CustodyLease {
  // Deliver into a registered native crypto context or Worker endpoint only.
  // No bytes/string/getSecret result to the application page.
  deliverTo(receiver: RuntimeReceiver, signal?: AbortSignal): Promise<void>;
  close(): void;
}
interface CustodyProviderV1 {
  describe(): Promise<ProviderInfoV1>;
  acquire(scope: ScopeV1, ref: ObjectRefV1,
    signal?: AbortSignal): Promise<CustodyLease>;
}
// Separate privilege surface. Omit entirely from routine consumer handles.
interface CustodyAdminV1 {
  put(scope: ScopeV1, expected: ObjectRefV1 | null, source: RuntimeSource,
    approval: StepUpApproval, signal?: AbortSignal): Promise<ObjectRefV1>;
  remove(scope: ScopeV1, expected: ObjectRefV1,
    approval: StepUpApproval, signal?: AbortSignal): Promise<void>;
}
```

The shown TypeScript brands describe intent, not security. JS runtime-private
registries/closures and native daemon-held capability tables must enforce identity;
serializing or forging `{kind: ...}` never produces authority. Across IPC use random
unguessable handle IDs bound to authenticated peer/channel, object, purpose, scope,
reference, operation and expiry; no transferable raw pointer or caller-provided PID
as proof. Schema validation occurs again in Rust, not just TypeScript.

Rust owns `CustodyScope`, `ObjectRef`, `ProviderCapabilities`, `CustodyError` and
traits corresponding to the ports above. Native-only secret buffers use zeroizing
ownership types without Debug/Display/Serialize/Clone. A runtime source/receiver is
an opaque registered endpoint, not a generic callback that can print/export secrets.
Generated TS/C headers/JNI bindings share golden wire vectors and compatibility tests.
Use the existing ABI version/feature negotiation; advertise a new optional custody
feature only when implemented. A breaking ABI change follows ADR-009, not copy/pasted
Swift/Kotlin struct layouts. Small platform shims remain necessary.

Administrative operations include create/replace/delete, provider/device enrollment,
grant changes, sync-policy changes, migration and portable export. They require
fresh trusted-UI master-password step-up in SentinelPass, bound to exact request,
connection, one use and expiry (reuse ADR-013). A provider without that ceremony
must expose its real equivalent user-verification policy and be separately approved;
never label OS biometric approval as SentinelPass master-password step-up. Native
OS adapter enrollment must still require explicit owner intent and auth-bound action.
Routine authorized reads may be automated only inside an existing bounded lease.

Public API errors: unavailable, unsupported, locked, interaction_required, denied,
not_found, stale_reference, conflict, cancelled, expired, capacity, invalidated,
integrity_failed. Use fixed messages and opaque correlation IDs; do not include
secret values, filenames, certificate bodies or vendor error dumps. Retry only on
explicit user action where safe; never rotate/generate/export on read failure.

## 6. Read leases, transfer and mutation semantics

V1 secret values are exactly 32 bytes for each of the two existing purposes. Keep
mail and storage objects separate. Per-user object namespace is exact; no wildcard
entries/fields, vault enumeration, generic owner CLI token or broad service grant.
No secrets in JS React state, clipboard, URLs, logs, command arguments or normal
IPC JSON. Neither vault DEK nor master password is an application credential.

Lease ceiling 120 s, one delivery, one in-flight operation per lease, at most eight
live leases per application-owner session. Authority is checked before AND after
asynchronous delivery; detected lock/revoke/account change wipes/disposes late output.
Use monotonic expiry plus lifecycle events; timer suspension cannot prolong authority.
Acquisition including user interaction has a 120 s deadline; delivery after user
authentication has 5 s. No hidden interactive prompt during background refresh.
Cross-process revocation has a race window; document it, minimize it and test ordering.
Already released bytes cannot be recalled. Returned mail custody needs its own bounded
lifetime/invalidation fencing; expiration of a lease alone cannot erase copied keys.

Mutation uses compare-and-swap and a single-use operation-bound approval. Persist
object + binding atomically; reject stale expected revision, duplicate object identity,
wrong purpose/owner, unknown schema and unauthenticated metadata. Mutation retries
must not replay consumed approvals: inspect authenticated outcome and request fresh
approval if needed. Use existing transactional/idempotent sync semantics; do not invent
a second mutation log. Restart closes leases and invalidates pending approvals.

Native same-process: deliver a zeroizing bounded buffer directly to the approved Rust
crypto context, not through Tauri page JSON or Kotlin/Swift strings. Native IPC needs
the reviewed authenticated transport plus exact peer/channel binding.

Browser: no web page can simply open an OS keyring. Optional extension/native-host
transport must bind actual browser-supplied top-level HTTPS origin, document/frame,
navigation lifetime and explicit user consent. Never accept an origin asserted only
by page JSON. No raw secret in a content script/DOM/autofill path. Require an
authenticated binding of an ephemeral Worker receiver key and an encrypted transfer
to that receiver; consumed once, bound to request/scope/reference/channel and expiry.
The page may relay ciphertext only. Evaluate an existing reviewed transport first;
if HPKE is needed, use a reviewed RFC9180 implementation with a separate suite,
dependency/license review and protocol workcard. HPKE base mode alone does not
authenticate the sender. **No custom key exchange or browser bridge is authorized
by this sketch**; this adapter stays unavailable until that transport is specified
and adversarially qualified. A malicious same-origin application can substitute its
own receiver or misuse plaintext after unlock; this is not code attestation.

Neither the generic lease nor a program-name/argv fingerprint defeats root, same-UID
malware with privileged IPC access or an injected approved process. Linux executable
digest pinning is a separately attested peer feature; it is not automatically portable
to browsers/iOS/Android. OS package/signing/access-group identity and actual transport
peer evidence belong to platform adapters. Unknown assurance must stay unknown.

## 7. Platform policy and interoperability

| Target | Qualified route to pursue | Boundary / default |
| --- | --- | --- |
| Browser/PWA | Existing kit + dedicated Rust/WASM Worker; optional reviewed native bridge or WebAuthn PRF | A nonextractable WebCrypto key is not a general hardware or anti-XSS guarantee. PRF availability, user verification, credential/RP binding and recovery must be feature-tested. No silent provider switch. |
| macOS desktop | Rust custody + Keychain access-controlled local protection; optional user's SentinelPass | Keychain storage is not identical to Secure Enclave execution. Do not claim imported X25519/Ed25519 mail keys run inside Apple's documented P-256 Secure Enclave API. |
| iPhone/iPad | Same Rust core via generated ABI; Swift Keychain/auth/lifecycle shim | Device-only access policy and backup exclusion; Keychain app-group entitlement does not allow unrelated apps to share arbitrary keys. Sandesha↔SentinelPass transfer needs explicit reviewed inter-app authorization. |
| Android | Rust/JNI + Kotlin Keystore CryptoObject/lifecycle shim | Query key security level and invalidate on relevant auth changes; TEE/StrongBox/software distinctions are real. Keystore objects do not automatically sync between phones/apps. |
| Windows | Rust + CNG/DPAPI/Hello as independently qualified adapters | DPAPI software storage is not TPM-backed execution. Distinguish software vs Platform Crypto Provider capabilities; do not assume a prompt authorizes the subsequent key use. |
| Linux | Rust + Secret Service/keyring software adapter; optional qualified TPM | Session-service protection is not hardware-backed. Headless fallback to files is never implicit. |
| Other vaults | Implement scoped storage/protection/lease adapter and conformance suite | A vendor's password autofill or passkey login API does not automatically implement mail-key custody. Mark unsupported operations explicitly. |

Device wrappers, sync keys, mailbox keys and OIDC/passkey signing credentials are
different keys. Do not use a signature-derived wrap design generically across
platforms: randomized signature algorithms will not reproduce the same wrapping
key. Reuse an already reviewed per-platform slot only after its assumptions pass.

## 8. Sync, recovery and alternatives

V1 manual recovery enrollment remains usable without background sync or any vault.
SentinelPass sync is an optional separate capability: end-to-end encrypted values,
authenticated object identity/version/tombstones, bounded outbox, conflict handling,
epoch/device revocation and new-device possession proof. Scope an app to the exact
objects; do not hand Sandesha the personal vault's shared DEK to make sync convenient.

Do not bypass ADR-013's step-up classification for sync operations to make onboarding
seamless. The sibling session must resolve/test how current SyncNow and remote-applied
mutations obtain required authorization. Automatic ciphertext transport is not approval
to change grants, device membership or key epochs. Until resolved, sync remains manual
and unavailable to Sandesha's automatic custody adapter.

Keep a verified offline recovery source independent of the sync provider. If vault and
kit contain the same recovery secret they provide independent availability locations,
not two-factor protection; compromise of either can unlock its encrypted material.
Provider/OS backup cannot promise revocation of exported old snapshots. Adding a
device must not re-encrypt all stored messages; it provisions existing key epochs.

Alternatives considered:

- Unique mailbox private keys per device: stronger future key-isolation potential,
  but per-message fanout, historical access, offline devices and external OpenPGP
  discovery become harder. Current single-encryption-subkey profile cannot represent
  this automatically. Defer to an explicit device-key-set protocol/benchmark project.
- Shared household/tenant vault: rejected; one user must not unlock another's mail.
- Central administrator escrow/HSM: rejected for consumer user-only mail custody.
  Enterprise escrow, if ever offered, is separate conspicuous policy, not a fallback.
- Require SentinelPass: rejected for lock-in, adoption and mobile-readiness reasons.
- Plain keyring get/set everywhere: insufficient lifecycle and authority contract;
  useful only behind an honest software adapter with scoped access and explicit consent.
- Reimplement OpenPGP in each UI or add Go/Python: rejected; reuse Rust and TS boundary.

## 9. Ordered work and acceptance (no gates waived)

| Slice | Deliverable | Acceptance before moving on |
| --- | --- | --- |
| KC-01 | Frozen schema/traits, TS/native generation, capability negotiation, fake/synthetic adapter | Red-first conformance tests; wrong owner/purpose/reference/epoch/peer, forged handles, close/replay/cancel/late completion and capacity denied; ABI mismatch fails closed. No platform success claim. |
| KC-02 | Personal SentinelPass exact-object storage and lease delivery to a native Rust test receiver | Fresh admin step-up on every mutation; read-only handle cannot mutate/enumerate/export; lock/revoke races, restart, zeroizing ownership, no secret output; audit/IPC review. No real vault data. |
| KC-03 | Sandesha recovery adapter + native macOS pilot | Existing envelope/profile bytes unchanged; two purposes remain separate; real recovery proof and certificate match; verified destination before migration cleanup; browser bridge still unavailable. |
| KC-04 | Cross-device bootstrap and optional sync | Two independent device contexts, fresh local wrappers, same mailbox fingerprint, tamper/conflict/rollback/lost-device drills, required sync step-up; never call emulator-only evidence physical-device proof. |
| KC-05 | Browser extension/Worker or PRF adapter (separate transport workcard) | Actual browser origin/navigation/frame binding, ciphertext-only page transfer, trusted prompt, abort/revoke/late work, CSP/notices; no implicit localhost daemon access. |
| KC-06 | iOS/iPadOS/Android/Windows/Linux adapters + release matrix | Real platform key-release, biometric change, reinstall, OS backup/restore, background/process-death, absent hardware and offline tests; physical iPhone/iPad/Android required for their claims. |
| KC-07 | Sandesha opt-in settings/product integration | Accessible recovery/provider choice, honest assurance labels, logout/account isolation, send/read/old-mail/rotation tests and independent review before any enablement. |

For KC-01/02 freeze before implementation: two 32-byte secrets per owner, 1/8 parallel
owner sessions, 100 sequential unlock/deliver/close cycles and 100 denied requests;
three warmups plus 30 timed trials per valid cohort. Local warm dispatch+delivery p95
<=100 ms excluding human/KDF/OS prompt time (report those separately), <=8 live
leases/session, zero live handles after close, no unbounded retry/queue. Record cold
startup and RSS high-water; ≤16 MiB incremental RSS over already-loaded provider for
this secret-only synthetic workload, excluding separately reported existing KDF/crypto
runtime allocation. Measure each platform/transport before claiming parity. Do not
relax failed limits after seeing results; record a revised workcard first if needed.

Native crypto ownership tests, TS contract tests, real IPC/browser/FFI negative tests,
wire-format fuzzing, golden cross-language vectors and fresh adversarial review are
required. Redaction scans use synthetic canaries only. Preserve failures/evidence,
exact source/artifact hashes and platform versions. No production-secret experiments.
Hardware claims require inspected capabilities plus actual cryptographic operation,
not a biometric dialog screenshot. Reviewer must examine same-UID/root limitations,
recovery-loss UX, hidden fallback, archive authority and sync enrollment carefully.

## 10. Handback and source references

Hand back reviewed merged commit/tag, generated contract/package versions, supported
capabilities per platform, evidence paths/raw timings, remaining gaps, dependency/SBOM
delta and an isolated synthetic Sandesha integration recipe. No crates publication,
new service deployment, live grants or mail-encryption activation follows from this
request. Private Sandesha adapter stays private; neutral SentinelPass SDK follows that
repository's existing license/provenance policy.

Official references consulted 2026-10-16 (retrieve again before implementation):

- [Apple Secure Enclave](https://developer.apple.com/documentation/security/protecting-keys-with-the-secure-enclave): platform algorithms and key provenance constraints.
- [Android Keystore](https://developer.android.com/privacy-and-security/keystore): extraction resistance, auth-bound use and hardware security levels.
- [Microsoft CNG providers](https://learn.microsoft.com/en-us/windows/win32/seccertenroll/cng-key-storage-providers): storage/provider abstraction and TPM provider.
- [WebAuthn PRF](https://www.w3.org/TR/webauthn-3/#prf-extension): optional credential-bound PRF, not automatic mail-key sync.
- [RFC9180](https://www.rfc-editor.org/rfc/rfc9180.html): candidate standardized encrypted transfer primitive, not a selected/implemented new transport.

Read Sandesha `MAIL_KEY_LIFECYCLE.md`, `MAIL_KEY_CUSTODY_2026-10-13.md`,
`MAIL_STORAGE_CUSTODY_2026-10-13.md`, `MAIL_KEY_REFERENCE_AUTHORITY_2026-10-13.md`,
`MODERN_OPENPGP_PROFILE_WORKCARD.md`, `SPEC.md`, `PLAN.md` and
`lib/encryption/recovery/contract.ts` alongside this contract. Older evidence has Go
qualification history; current target is the reviewed Anvai Rust/WASM provider.
