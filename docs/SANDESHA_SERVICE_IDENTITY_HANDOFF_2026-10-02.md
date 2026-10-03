# Service identity, executable binding and OpenPGP enrollment

Status: reviewed design / implementation handoff, NOT a shipped capability.
Owner request: finish SentinelPass #194 with the strongest practical service
authorization posture, including OpenPGP registration, then qualify Sandesha adoption.
Date: 2026-10-02. Receiving project: SentinelPass. Producing project: AnvaiOps/Sandesha.

## 1. Verified baseline and scope

Local `main` was fast-forwarded to `636b56f32fc50d131dbef1a1eed55731f1727b18`
(v0.14.2). Installed Mac CLI is 0.14.2. Issue
[194](https://github.com/anvai-labs/sentinelpass/issues/194) is OPEN.
This handoff changes documentation only. No new authorization code, dependency,
grant, enrollment, listener, production vault migration or release is implied.
Recheck repository status and issue state before implementation; another session
may have advanced them. Feature/fix PRs target `develop`; promotion to `main` is
the repository's reviewed, CI-gated release process. Do not patch `main` directly.

Read `AGENTS.md`, `SECURITY_ARCHITECTURE.md`, `docs/SECURITY_STATUS_MATRIX.md`,
`docs/SERVICE_CREDENTIALS.md`, and ADR-007/ADR-011. Historical architecture prose
contains unimplemented target state; use code and evidence for capability claims.

Source review anchors (relative to SentinelPass):

| File | Observed behavior / implementation seam |
| --- | --- |
| `sentinelpass-core/src/daemon/transport/unix.rs` | Private 0700 socket directory, 0600 socket; peer UID must equal daemon UID. Linux obtains ucred but retains only UID. |
| `sentinelpass-protocol/src/transport/unix.rs` | Connection holds stream; client expects private socket directory. No trusted peer executable context. |
| `sentinelpass-core/src/daemon/ipc/server.rs` | Accept -> connection -> frame -> message; no executable context reaches policy. Global daemon token checked before dispatch. |
| `sentinelpass-protocol/src/envelope.rs` | Global token plus optional client token/capability; origin is provenance, not authority. |
| `sentinelpass-core/src/external_secret_access.rs` | Grants use client/domain/field/expiry/write; no entry ID or executable pin. Legacy tokenless grants exist. Atomic file replacement is not serialized read/modify/write. |
| `sentinelpass-cli/src/commands/secret.rs` | Scoped retrieval, token enforcement when configured, optional interactive biometric unlock. |
| `sentinelpass-cli/src/commands/service_client.rs` | Owner CLI uses broad application-service IPC; direct-vault compatibility is separately gated. |
| `sentinelpass-cli/src/commands/service_credential.rs` | Existing Linux restart-safe systemd credential delivery; extend instead of duplicating. |

Important review finding: `ServiceCall { op }` dispatches to the broad vault
application service after the daemon-token gate. A service deployment must not
give consumers the owner's daemon token or access to its private configuration.
Adding a check ONLY to `GetExternalSecret` does not create a least-privilege
boundary for a client that can use the owner administration path. This is a design
blocker for a new multi-principal broker, not a claim of a demonstrated remote exploit.

## 2. Security contract and non-goals

Automation means no repeated human password prompt after explicit enrollment and
provisioning. It does not mean an encrypted vault unlocks itself without a key.
Keep the owner/master vault off the ordinary VPS when possible; provision only
the minimum workload secrets needed there.

| Threat | Required boundary / honest limit |
| --- | --- |
| Another unprivileged Unix user | Private custody, kernel peer identity, dedicated service UID and restricted credentials directory. |
| Stolen client token used by an unapproved executable | Token AND local executable policy; deny on unknown identity. |
| Another process under the same UID | UID and digest alone do not isolate it; it may run the approved binary, read same-UID material or modify policy. Separate UIDs and administrator-owned policy are required for service isolation. |
| Root, kernel or hypervisor compromise | Not excluded by ordinary VPS encryption, process fingerprints or OpenPGP. Runtime plaintext is accessible to sufficiently privileged code. |
| Copied encrypted credential alone | Encryption helps; host-key mode does not protect a full image containing both ciphertext and host key. |
| Network MITM / enrollment replay | Authenticated TLS, pinned enrollment authority, signed single-use challenge, key possession and scope binding. |
| Authorized consumer intentionally leaking its secret | Outside secret delivery's protection; constrain provider permissions and avoid disclosure by using operation-specific APIs where practical. |

Do not market argv, cwd, process name, PID, client ID, email address, OpenPGP User
ID, or a self-reported fingerprint as authentication. An executable digest is an
additional constraint, not remote attestation and not a same-UID security sandbox.
Scripts pin their interpreter if only `/proc/PID/exe` is measured. Python, shells,
Node and the general-purpose SentinelPass CLI must not be advertised as uniquely
identifying the calling application. Shared libraries, plugins, environment and
injected code remain relevant even for a pinned ELF executable.

## 3. Chosen architecture

Keep three explicit layers with separate threat models:

1. Owner administration: existing local, private, unlocked-vault interface.
2. Service authorization: versioned grants bound to an exact vault entry and
   authenticated principal, with optional mandatory executable policy.
3. Delivery: existing systemd encrypted credentials for restart independence;
   optional remote broker only after enrollment and transport qualification.

Preserve the private owner socket. For cross-UID service retrieval, introduce a
separate opt-in service-only Unix socket with explicit group/ACL access and kernel
UID checks, and a service protocol containing only allowed retrieval operations.
It must not reuse/disclose the global owner token, allow grant creation, list all
entries, export the vault, unlock it, or reach `VaultOp` administration. Do not
weaken the owner socket's directory rules to make service access work. If this
new endpoint is not implemented in the first slice, retain the existing trusted
installer -> systemd credential path and label direct cross-UID retrieval unsupported.

Proposed logical policy (final Rust/schema details belong in an ADR):

```
ServiceGrantV2 {
  grant_id, policy_version, client_id, principal_id,
  vault_id, entry_id, fields, operations, expires_at, revoked_at,
  required_local_identity: { uid, executable_sha256_set, executable_policy_version },
  enrollment_id, registration_key_fingerprint, authorization_epoch
}
```

Required properties: no wildcards by default; read-only; reject ambiguous domain
lookup; exact immutable entry ID within a vault, never a mutable display name;
unknown versions/mandatory fields fail closed; distinguish legacy grants without
silently converting them to stronger grants. New service grants cannot be tokenless.
Policy is writable only by the owner/admin principal, outside consumer UID custody.
Serialize grant/rotation/revocation updates with crash-safe publication and generation
checks. Existing atomic rename alone cannot prevent lost revocations during concurrent updates.

Every request binds authentication, entry, field, operation, scope version and
current revocation state before decrypting. Resolve locked/denied/not-found into
stable typed errors without leaking unauthorized entry existence. The current
locked reply's `authorized: true` is not evidence of an authorization decision.

## 3A. Mandatory owner update: master-password-gated administration

The owner explicitly requires manual master-password authorization for setup and
ALL administrative mutations. Retrieval alone may run unattended. This supersedes
any implication above that an already-unlocked vault or a registration key alone
is sufficient to change policy. This is a new requirement, not a v0.14.2 claim.

Implement a strict service-vault/profile policy with a centralized operation
classification and exhaustive routing tests. Fail unknown operations closed:

| Operation | Required authority |
| --- | --- |
| Retrieve an enrolled entry/field within its current scope | Authenticated service principal, current grant, required executable/registration policy; no human prompt. |
| Create/edit/delete/import/restore entries; change values, URLs or metadata used in lookup | Owner administrator + fresh master-password step-up bound to the exact mutation. |
| Add/change/remove grants, approve/renew/revoke enrollments, change executable pins, trust roots, scopes, TTLs, client keys/tokens or delivery targets | Owner administrator + fresh master-password step-up; additional independent approval for high-risk policy if configured. |
| Install/replace/remove a deployed credential, rotate its provider value, change vault/master keys, recovery or unlock policy | Explicit master-password-authorized plan; no unattended policy expansion or credential mutation. |
| Export plaintext secrets, export vault keys, view recovery material | Sensitive owner operation; fresh master-password step-up even though this is technically a read. Never exposed to services. |
| Audit append, nonce consumption, counters, expiry enforcement, replay cache, crash recovery of an approved transaction | Internal system state only; automatic, not permission to mutate entries or authorization policy. |
| Start/restart with the already-approved installed credential | Allowed under the approved unit/UID/path; must not opportunistically fetch and install a replacement. |

Fresh means a dedicated password verification action, not ordinary vault-unlocked
state, biometric unlock, possession of client/daemon tokens, a PGP signature or an
environment flag. Never persist the master password for automation. Verify it using
the existing reviewed master-password/KDF path with rate limits, bounded concurrency,
zeroized buffers and no logs. Do not add a cheaper independent password verifier.

The result is a short-lived, single-use, server-held authorization bound to the
authenticated admin session, exact typed operation/parameters (including secret
replacement value via a keyed commitment, never a public password hash), vault ID,
expected policy/data version and nonce. Initial maximum age: 60 seconds. Prefer
server-held pending payloads, with tightly bounded encrypted/zeroized custody; no
secret in CLI argv or approval URLs. A reviewed batch may bind a complete immutable
manifest instead of prompting for every item; it cannot grant open-ended write
authority. Consume approval atomically with commit; do not reuse after failure.
Lock/logout, version conflict, timeout, master-key change or revocation invalidates
pending approvals. Audit outcome without retaining password or raw secret payload.

Enforce this at the common application-service mutation boundary, not CLI/UI only.
Cover browser SaveCredential/SaveSecret, import, sync, restore, recovery, direct
compatibility mode, CLI, UI and service IPC. In strict service mode remote sync or
autofill must not silently overwrite service credentials. Disallow legacy/direct
bypasses or require the same gate; client-controlled origin labels never suffice.
Inventory every VaultOp and message before implementing. An enrolled service must
not invoke step-up/unlock itself or trick the user into approving an opaque action.
Show precise redacted target, fields, scope and privilege changes before approval.

Enrollment has two distinct transitions: authenticated candidate registration and
master-password-authorized activation. Receiving a valid signature can update
bounded pending state but must not create usable grants. Require fresh approval
for activation/renewal/scope changes; expiry/revocation checks remain automatic.
With this strict policy, future automatic certificate or provider-secret renewal
must not be quietly added. Design an explicitly approved bounded exception later
only if the owner changes this requirement.

Even restrictive administrative revocation uses step-up under the owner's current
rule; emergency operators may stop the service or block its network externally.
Define an independent emergency deny-only role only with a subsequent explicit
policy decision, not an undocumented master-password bypass.

Master-password step-up protects against an unlocked session being casually used
to mutate secrets. It does not protect against root patching a same-host verifier
or keylogging a password typed into a compromised machine. Administrative approval
must happen on the trusted owner/key-admin machine, never by typing the master
password on the untrusted VPS. Send narrowly scoped authenticated provisioning
instructions to the workload; keep the approval root/key material off that host.

## 3B. Separation of duties and the cloud administrator boundary

Target role model (application-enforced roles need matching OS/account boundaries):

| Role | Can do | Cannot do |
| --- | --- | --- |
| Application administrator | Deploy approved artifacts, manage app configuration and request secret references | Approve own secret grants, export master keys or inherit key-admin credentials |
| System/cloud administrator | Patch/restart hosts, capacity/network operations, recover ciphertext | Administer the independent key authority or issue approved secret scopes through its API |
| Key administrator | Enroll/rotate/disable keys and approve narrow policy under step-up | Automatically receive application data-decryption/use rights merely from key-management role |
| Workload principal | Retrieve only exact approved secrets or invoke a limited remote cryptographic operation | List the vault, change credentials/policy, enroll others or unlock the master vault |
| Independent reviewer/auditor | Approve designated high-risk changes / inspect redacted audit evidence | Self-approve own changes or read secret values by default |

Today this is a single-owner personal vault. The master-password holder may have
broad vault access; that is NOT already a multi-admin key-manager-without-decrypt
implementation. Genuine separation needs independent authenticated identities,
separate administrative custody and, for critical grant/export/recovery changes,
two distinct approvers. Do not share one master password among several people and
call it separation of duties. Model future multi-admin enrollment separately from
the current owner bootstrap, with recovery/quorum policy that cannot grant one
operator unilateral access. A threshold scheme must use a reviewed implementation.

Industry examples: Google Cloud KMS distinguishes key administration from key
usage and recommends separating their principals; HashiCorp Vault policies split
read from create/update/delete and Enterprise control groups add joint approval.
These are design references, not a proposal to enable paid hyperscaler resources
or import another product's code/licensing assumptions.

Practical Sandesha baseline: key authority/master vault on the trusted owner side,
dedicated workload identities on OVH, least-privilege bucket/provider credentials,
separate offsite audit/backup administration, signed approved builds and manually
approved rotations. Existing host-key systemd credentials provide restart safety,
not secrecy from the OVH host's root administrator.

Critical limitation: a host administrator able to change application code can
usually make the legitimate workload exfiltrate plaintext or use its permissions.
An external HSM protects key extraction, but does not by itself stop authorized
decryption/signing requests or protect returned plaintext. Reduce exposure with
operation-specific remote APIs and short-lived scoped credentials where providers
support them. If excluding malicious cloud/root operators is a hard requirement,
evaluate attested confidential execution with external release tied to measured,
approved code and protected I/O, or end-user-held encryption keys. These require
separate qualification; standard OVH VPS plus PGP cannot meet that claim. User-held
mail encryption also changes search, recovery and external-recipient behavior.

## 4. Linux executable identity implementation

Add server-owned `PeerIdentity` / `RequestSecurityContext`, never deserialized from
the caller. Thread it through accept, connection, frame and authorization dispatch.
Keep OS adapters separate; Linux support does not imply Mac or Windows support.

- Obtain UID/GID/PID from kernel socket credentials and validate returned length.
- Examine current kernel facilities such as `SO_PEERPIDFD` where available;
  `pidfd_open` after a PID lookup alone is not a race-free connection identity proof.
  Pin process lifetime and reconcile proc handles/start identity. Document minimum
  kernels and reject enforced policy if required evidence cannot be obtained.
- Open the kernel-referenced executable through validated proc handles and hash
  the open file, never a caller path or a `readlink` pathname reopened later.
  Bound size/time, use a blocking worker pool and limit concurrency.
- Check trusted executable custody and writable ancestors; reject unexpected
  deleted/memfd/interpreter cases in the strict initial profile. Define container,
  PID/user namespace and proc visibility support explicitly; don't compare an
  unqualified container UID with a host UID.
- Revalidate for each privileged request. Handle exec-after-connect, process exit,
  PID recycling and descriptors passed to a different process. `SO_PEERCRED`
  describes connection-time identity; it does not prove the sender of every later
  message. If per-message credentials/framing are required, implement and test
  them or restrict the supported profile; do not hide this with a pre/post stat.
- pidfds pin lifetime, not code execution state. Arbitrary exec/FD transfer races
  cannot be eliminated by hashing alone. State residual limits and rely on the
  dedicated UID/unit sandbox; no strong continuous-code-attestation claim.
- No digest caching until correctness is proven. Later caching must cover inode,
  mutation, process exec and policy/revocation invalidation; pathname/mtime alone
  is insufficient. Upgrades require explicit new digest approval, bounded overlap,
  rollback evidence, then removal of the old digest; never auto-trust the new binary.

argv contracts remain optional usability guardrails. Avoid generic flag sorting:
repeated flags, positional arguments, `--`, shell parsing and ordering can change
meaning. Use a typed command-specific schema if necessary. Never log raw argv or
environment (they often contain secrets); log static reason codes and policy IDs.

## 5. OpenPGP registration profile (requested additional factor)

Use OpenPGP for enrollment signatures and pinned key possession, not a bespoke
encrypted socket protocol. RFC 9580 is the format reference. GnuPG is an
implementation, not a different protocol. Keep enrollment offline-capable/local
initially; do not enable a public listener just to demonstrate it.

Proposed enrollment sequence:

1. Owner approves an exact client, service UID, entry/fields, executable policy and
   full registration-key fingerprint through the existing administrative channel.
   No automatic trust based on a name, short key ID, email or keyserver result.
2. Broker creates a cryptographically random 256-bit nonce and short-lived pending
   enrollment (initial target five minutes). Persist bounded single-use state.
3. Produce exact canonical bytes (versioned schema, no duplicate keys, deterministic
   encoding): domain separator `sentinelpass/service-enrollment/v1`, nonce,
   broker/vault IDs, client ID, requested-scope digest, executable-policy digest,
   registration-key fingerprint, client transport public-key digest and expiration.
4. Client signs those bytes using its dedicated OpenPGP signing key. For remote
   enrollment, prove possession of the separately generated TLS key too; signing
   someone else's public key is not proof of possession of that key.
5. Broker verifies trusted full primary-key fingerprint, signing subkey binding,
   key usage, validity/revocation, signature algorithms and exact transcript. Verify
   approved scopes server-side and atomically consume the nonce with enrollment
   publication; concurrent replay and restart replay must fail.
6. Return an enrollment receipt bound to the transcript/policy generation. Issue
   only a scoped principal credential, never a vault master key or owner IPC token.
   Reenrollment, rotation and recovery require owner authority; key possession
   alone must not expand scopes. Revoke active sessions and pending enrollments.

This profile can require BOTH OpenPGP enrollment and executable policy. If either
is configured mandatory, unavailable evidence must deny, not degrade to token-only.
Registration proves key possession at enrollment; future sessions need independent
proof (e.g. mTLS). The registration signature cannot be replayed as a session token.
The two controls are not independent against compromise if both keys/tokens are
stored under the same compromised UID. Prefer hardware-backed/offline owner keys
where operationally appropriate; don't require human key touch at every service boot.

Use a maintained library with a verified compatible license, audit/advisory review,
strict parsing and interoperability tests; do not implement OpenPGP primitives.
Evaluate the Rust `pgp` crate first, without declaring it approved based on license
alone. Check current version, advisory history, packet limits and supported RFC
profile. Compare alternatives' licenses before embedding them. GnuPG may be an
optional external interoperability signer; if invoked, pin the executable, avoid
shells, use an isolated keyring, disable network key retrieval and parse machine
status rather than human output. No new production dependency is selected here.
Reject weak/unknown algorithms, invalid critical subpackets and unbounded packet
graphs; disable compression for the registration profile and bound input size.
Record the exact accepted key/signature versions and algorithms in the ADR.

For a future remote broker use a maintained TLS implementation with TLS 1.3 and
mutual client authentication, certificate validation, short-lived credentials,
server-side revocation, request deadlines/rate limits and no 0-RTT on enrollment or
secret operations. Bind enrollment to the intended broker and TLS key. OpenPGP
does not replace TLS, authorize executable identity on a remote machine, or give
forward secrecy to a custom long-lived encrypted-message protocol.

## 6. Restart-safe delivery and audit

Reuse `service-credential install/verify/rotate/remove`. Encrypt before atomic
publish; strict owner-only custody from file creation; failed rotations preserve
the prior credential; serialized writer; no plaintext files, argv, logs or exports
to a shared environment. Prefer credential FDs / `$CREDENTIALS_DIRECTORY`.
One Unix identity and narrowly scoped provider credential per service. Avoid a
container claiming host-level isolation merely because its internal UID is 2000.

Revoke broker grants promptly; also remove/update installed systemd ciphertext
and rotate at the provider when access must end. Broker revocation cannot erase
a secret already disclosed or already loaded by a running service. Document this
and qualify revoke -> rotate -> restart -> old-value-denied.

Audit grant approval/change, enrollment, retrieval decisions, digest mismatch,
rotation and revocation with stable reason codes and authorization generation.
Never audit secret values, token hashes that enable attacks, raw argv or signatures
containing sensitive application metadata. Define audit durability explicitly;
strict service mode must fail closed if the required audit event cannot be recorded.
Local logs are not tamper-proof against root; optionally export to a separately
administered receiver. Don't label local append-only files immutable evidence.

## 7. Implementation tracker and release gates

All implementation boxes below are pending. Document-only preparation is complete.

- [ ] SP-0: Implement fresh master-password administrative step-up, exhaustive
  operation classification, single-use mutation approval, role/custody model and
  bypass tests. Complete before enabling enrollment or broader automation.
- [ ] SP-1: ADR and threat model, exact-entry grants, policy migration, per-principal
  service endpoint and owner/admin isolation; typed lookup/locked/denied errors.
- [ ] SP-2: Trusted peer context and redacted provenance; preserve browser/mobile
  protocol behavior. Never trust serialized peer context.
- [ ] SP-3: Linux executable policy, race/namespace support matrix and upgrade path.
- [ ] SP-4: OpenPGP adapter, canonical enrollment transcript, persisted single-use
  state, owner approval, key rotation/revocation and strict profile toggles.
- [ ] SP-5: Optional remote mTLS adapter only after local profile passes; no public
  exposure or live secrets in development. Local and remote claims remain distinct.
- [ ] SP-6: systemd delivery integration, least-privilege examples, CLI diagnostics,
  restart/rollback qualification and operator runbook.
- [ ] SP-7: Adversarial tests, performance evidence, required CI/review, release
  notes/status matrix reflecting exact platform support, then tagged promotion.
- [ ] SP-8: Sandesha synthetic qualification against released artifacts, concrete
  consuming-unit plan, provider rotation and production cutover with rollback.

Required test matrix:

| Area | Evidence required |
| --- | --- |
| Privilege boundaries | Service credential cannot call owner operations, list/export entries, mint grants or unlock vault; wrong UID/token/entry/field denied; same-domain duplicate entries never choose an arbitrary account. |
| Master-password gate | Already-unlocked/biometric/token/PGP-only clients cannot mutate; wrong password, expired/reused approval, swapped target/value, concurrent version changes, restart replay, direct/sync/browser/import bypass all denied. Approved mutation succeeds once. Automated audit/nonce recording and unchanged restarts still work. |
| Separation of duties | App/sysadmin cannot self-grant key authority; key-manager role does not implicitly have data-use rights; two-person policy rejects same-person dual approval; compromised-host limitation documented. |
| Executable policy | Correct binary allowed; replaced/symlinked/untrusted/deleted executable denied per profile; forged argv/client PID irrelevant; unsupported OS fails closed. |
| Process races | PID exit/reuse, exec-after-connect, FD passing/fork, proc hidden, namespace mismatch, executable mutation; document residual limits instead of flaky happy-path assertions. |
| Enrollment | Wrong key/broker/vault/scope/TLS key, stale nonce, concurrent/restart replay, revoked/expired subkey, malformed/oversized packets and downgrade denied. |
| Custody/concurrency | Loose umask, symlink/hardlink/path races, interrupted write, disk full, concurrent revoke/allow/rotate; no lost revocations or plaintext persistence. |
| Delivery | Locked vault + stopped daemon, three service restarts; foreign UID denied; failed replacement preserves prior ciphertext; provider rotation invalidates old value. |
| Audit | Every decision has redacted reason and policy version; audit outage behavior and root-tampering limits explicit. |
| Interoperability | Supported OpenPGP signatures cross-checked with independent implementation; Mac/Windows absence of Linux feature is visible, not silently bypassed. |

Use synthetic secrets generated at runtime, no real vaults or new paid compute.
Test on existing aiserver1/ds3 Linux, local Mac for IPC regression, existing Windows
test environment if affected. Repository-required `cargo test --workspace`, fmt,
clippy and affected TS checks must pass before PR; use focused tests while iterating.
Fuzz enrollment/parser boundaries and policy deserialization; bounded resource tests.

Performance experiments: compare 0.14.2 baseline, provenance-only, token+digest,
and token+digest+enrollment-enabled steady state on the same machine/build. Report
p50/p95/p99, CPU, peak memory, bytes hashed, cold/warm starts and concurrent-client
denials. Enrollment signatures are not on every retrieval's critical path. Initial
engineering targets (not measured promises): warm added p95 <10 ms for a small
native client and enrollment p95 <1 s excluding human/hardware interaction; document
hardware and adjust with evidence. Security failures cannot fall back for speed.

## 8. Sandesha integration state and hand-back contract

Existing OVH VPS: 40.160.36.82, Ubuntu, engine/web colocated; mail blobs now on
OVH S3, RocksDB metadata local, independent encrypted backups on ds3. Postfix
still owns public SMTP. Do not alter mail routing as part of this feature.
Current Docker launchers are root-owned and engine runs as container UID 2000;
a real per-service host boundary still needs design before production adoption.

Synthetic 0.14.2 qualification PASSED on Oct 2 at 05:46 UTC: scoped denial tests,
0600 custody, systemd host-key encrypted install, rotation failure preservation,
three restarts while vault locked/daemon stopped, cleanup. This proves existing
delivery only, not executable binding/OpenPGP. Authoritative evidence lives in
`../anvaiops/docs/operations/SENTINELPASS_QUALIFICATION_2026-10-02.md` and
`../anvaiops/docs/operations/evidence/sentinelpass-20261002/`.
The harness later gained preflight-refusal safety tests; retain provenance of the
actually executed harness rather than substituting a new source hash silently.

Runbook corrections: `secret allow CLIENT_ID` / `revoke CLIENT_ID` use a positional
client ID. Domain lookup currently requires an entry URL, not merely its title.
Server denial guidance still suggests `--client-id` for `allow`; fix diagnostics.
Authorized no-match currently becomes an unhelpful CLI unexpected-response error.

Owner SSO password import remains pending (vault was locked); don't claim it was
saved. Credential source is on ds3, not in this document. This is the owner's real
account used for smoke testing, NOT a low-privilege synthetic identity. Keep that
human credential on the Mac vault; don't provision it to VPS service automation.
Use a descriptively named entry and never include values in issue/PR/evidence.

Hand back release tag + source/asset digests, platform capability matrix, ADR,
schema/CLI examples, threat limits, test/performance evidence, rotation/revocation
runbook and a synthetic Sandesha qualification recipe. Do not claim production
adoption or provider-admin immunity. Keep this document status updated as slices
land, so the Sandesha session can consume shipped facts without re-research.

## 9. Primary references reviewed

- [Issue #194](https://github.com/anvai-labs/sentinelpass/issues/194)
- [OpenPGP RFC 9580](https://www.rfc-editor.org/rfc/rfc9580.html): format/signature reference, not an application authorization protocol.
- [Linux unix(7)](https://man7.org/linux/man-pages/man7/unix.7.html): connection credentials and descriptor passing.
- [Linux pidfd_open(2)](https://man7.org/linux/man-pages/man2/pidfd_open.2.html): process handles, not executable attestation.
- [Rust pgp library documentation](https://docs.rs/pgp/latest/pgp/): evaluation candidate, not approval.
- [systemd credential design](https://github.com/systemd/systemd/blob/main/docs/CREDENTIALS.md): delivery and storage threat model.
- [Cloud KMS separation of duties](https://docs.cloud.google.com/kms/docs/separation-of-duties): key administration versus use; reference only, no cloud provisioning.
- [Vault joint controller authorization](https://developer.hashicorp.com/vault/tutorials/enterprise/control-groups): approval at operation level; Enterprise feature, not claimed for all editions.

No production code was changed for this handoff. Source inspection is a scoped
design review, not a completed penetration test or formal security proof.
