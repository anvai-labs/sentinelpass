# ADR-004: Recovery Key Slots and Revocation

| Field | Value |
|-------|-------|
| Status | Accepted (rev 5, 2026-09-04 — owner decision after three adversarial rounds; rev 5 folds the architecture review (lag-adoption bypass fix, scope recast, placement decision, coverage/multi-device rules) before any release of the feature) |
| Date | 2026-09-04 |
| Owners | Security lead, core maintainer, product lead |
| Related | ADR-002; ADR-005; ADR-006; ADR-008 |

## Summary

Recover vault access through independently wrapped DEK key slots. Never store or
recover the old master password.

## Context

The current password-wrapped DEK permits cheap password rotation but provides no
forgotten-password recovery. Pairing still depends on password-wrapped bootstrap
material, and the current epoch does not revoke normal sync authority.

## Decision

Each vault has a stable UUID, monotonic crypto epoch, and key-slot registry. Initial
slot types are password, recovery key, platform device/biometric, and trusted device.

Every slot records a stable UUID, type, algorithm/KDF parameters, wrapped DEK, epoch,
creation time, revocation time, and format version. Its authenticated context binds
the vault, slot identity/type, epoch, and version.

### Slot-registry authentication and validity (rev 2, from adversarial review)

Individual slot wraps bind their creation epoch as AAD (the shipped ADR-002
mechanism), but epoch equality is **not** the unlock-time validity rule — that
trilemma cannot be satisfied by wrap AAD alone (equality breaks ADR-002 D4
platform-slot survival across rotation; `<=` lets a resurrected revoked row
re-authenticate). Instead:

- The **entire slot registry is authenticated as an ordered set** under an
  HKDF(DEK)-derived registry MAC key with its own `info` label (extending the
  `derive_equality_key` precedent in `crypto/keyring.rs`). Revocation state lives in
  the MACed rows; an attacker cannot resurrect, add, or edit a slot without the DEK.
  The MAC input is normative: rows serialized in **canonical slot-UUID lexicographic
  order** (never insertion/rowid order), with row count and vault epoch bound in. A
  row present in the table but absent from the MACed set — or vice versa — rejects
  the whole registry (fail closed); there is no in-place repair path; recovery from
  registry corruption is ADR-008 verified restore only.
**Honest scope (rev 5, architecture review):** with the declared non-goals
excluded (same-UID, root, offline-copy-with-old-password, both-files-rolled-back),
the sidecar's *adversarial* coverage is thin — the realistic DB-only writer on a
single-user desktop IS a same-UID process. The control is graded as an
**accident/consistency control and substrate**: it catches single-file accidental
restores, surgical rewinds on legacy non-epoch-bound material, and provides the
anchor WBS-417 (restore override), WBS-612/614 (epoch enforcement), and the
per-slot attempt counters consume. Public docs must not present it as an
attacker-defeating control.

**Adoption rule (rev 5, closes the lag-adoption bypass):** the sidecar is NEVER
moved by unauthenticated evidence. The open-time check is read-only (plus the
protection-neutral TOFU mint of current state); a pending one-step heal is adopted
only AFTER an epoch-AAD-verified password unlock of the new state. Biometric
unlocks defer pending heals to the next password unlock (no password proof
exists there). Legacy (non-epoch-bound) wraps cannot authenticate a transition
and refuse the heal. `epoch_bound` itself is unauthenticated today; folding it
into the authenticated domain is part of the slot-registry wrap redesign (302).

**Placement (rev 5, decision + upgrade path):** beside the vault
(`<vault>.epoch`) for 0.9. Trade-off recorded: a folder-level restore carries
the anchor with the vault, and copying an old DB to a new path gets a clean TOFU.
The upgrade path — config-dir sidecar keyed by `vault_uuid`, which survives both
— is deferred until a release justifies its migration cost (note: on macOS the
config and data dirs coincide, so the gain there is nil; Linux/Windows gain the
separation). Not both: two anchors double the TOFU confusion for no added
protection against the conceded residuals.

**Coverage rule (rev 5):** the epoch is a generation counter over ALL anchored
authority state — no legitimate mutation changes anchored state at a constant
epoch. The material digest covers the unlock-authority columns (`kdf_params`,
`wrapped_dek`, `dek_nonce`) and, when WBS-302 lands, the slot-registry MAC
**by composition** (never raw rows, so registry internals stay free to evolve).
`biometric_ref` is deliberately excluded: the keychain entry is the authority
for that path — with fail-loud disable (the keychain is cleared before the
column is NULLed), a restored ref gates an empty slot — and anchoring a column
that legitimately toggles at constant epoch would false-refuse every biometric
toggle at the next open. WBS-613's sync-lineage high-water is a SEPARATE
mark with a separate home (sync state, not the epoch sidecar) — different
monoid, different reset rules after relay re-baselining; implementations must
not conflate them.

**Multi-device adoption (rev 5, consumed by WBS-612/614):** sync apply adopts
remote epochs ≥ the local high-water by explicit rebase (the pair-join pattern),
never through the one-step-lag window — multi-rotation catch-up would otherwise
brick offline devices. The relay enforces an epoch floor rejecting stale-epoch
pushes; after relay re-baselining (WBS-624) the LOCAL sidecar keeps its epoch and
the relay restarts from the current authoritative state.

**Known deferral (rev 5, round-4 finding):** a vault used *exclusively*
through biometric unlock never adopts a pending one-step heal (no password
proof exists on that surface). After a rotation whose sidecar follow failed,
such a vault's rollback detection stays stale until the next password
unlock. Mitigation: the deferral is audit-logged, and the desktop TOFU/heal
warning (below) will tell the user a password unlock is required. Platform
slots (WBS-302/812/821) may later authenticate heals via the keychain-held
DEK. Accepted residual for 0.9.

**TOFU contract (rev 5):** the mint warning must be a blocking/modal user
acknowledgment in the UI (log/audit-only is insufficient — warning fatigue
defeats the one visible barrier to sidecar deletion), and repeated mints are
flagged. A future narrowing (with WBS-415's tamper-evident audit trail): TOFU
mints cross-checked against the highest recorded audit epoch (requires vault
attribution in audit entries; attacker-writable until 415).

- **Boundary, stated honestly (rev 3/4):** the registry MAC stops *partial* tampering.
  Restoring an entire older self-consistent database (rows + MAC + epoch together)
  re-verifies — this is the whole-file-rollback boundary ADR-002 F3 already
  documents. Mitigation: a monotonic **epoch high-water mark stored outside the
  vault database** (owner-only sidecar file beside the vault), checked at every
  open; a vault whose on-disk epoch is below the high-water mark refuses to open
  with an explicit rollback error. The sidecar's semantics are fully specified
  (rev 4): **absent file → trust-on-first-use** — mint from the current DB epoch
  and warn the user visibly ("vault rollback-protection sidecar missing — it has
  been reset; revocations from before this point are not enforced"); this is also
  the new-machine/ADR-008 bundle-restore path. **Restore override:** restoring an
  older ADR-008 bundle on a machine whose high-water is newer requires explicit
  reauthentication plus user acknowledgment that older revocations are being undone;
  the override re-baselines the high-water and is audit-logged. Because the sidecar
  is not DEK-bound, an attacker with vault-directory write access can delete it and
  trigger the same TOFU path — the sidecar is **defense-in-depth that raises the bar
  (a rollback now requires knowing to remove two artifacts and surviving a visible
  warning), not a tamper-proof control**; rolling back both files together remains
  equivalent to restoring any pre-incident backup (accepted residual). **Multi-device
  rule (rev 4):** sync apply never writes an epoch or slot-registry state below the
  local high-water mark — a lower-epoch pull result is rejected as a suspected
  rollback, not applied (the wedge-free behavior WBS-612/614 must test).
- A slot unlocks the vault iff (a) its row is part of the MAC-verified registry,
  (b) it is not revoked, and (c) its own wrap authenticates under its creation-time
  AAD. Rotation advances the epoch without re-wrapping platform slots (D4 preserved);
  revocation is carried by the registry MAC, not by epoch comparison.
- Recovery commit is **one SQLite transaction**: new password slot insert, epoch
  bump, slot revocations, and registry MAC rewrite commit atomically; the unlocking
  process adopts the post-commit state. A crash before commit leaves the pre-recovery
  state complete and recoverable — there is no window with zero usable slots.

### Recovery-key wrap policy (rev 2)

The wrap mode is tied to key origin, not key length: **Argon2id is mandatory for any
human-typed recovery key** (length floors are checkable, entropy is not — a 20-char
memorized phrase carries far less than 128 bits); raw AES key-wrap is permitted only
for machine-generated keys of at least 128 recorded entropy bits. Attempt accounting
is **per slot** (rev 4, sharpened from per-slot-type): wrong attempts against one
slot never consume or share another slot's budget — independent recovery slots stay
independently usable. Each slot gets its own counter with **capped** exponential
backoff (hard maximum lockout duration), and attempts refused during backoff extend
it only up to that cap, so transient wrong-key access cannot indefinitely pin the
recovery budget high. Counter storage must NOT be inside the vault database alone
(the whole-file-rollback adversary resets it — the failed_attempts table today):
counters live beside the epoch high-water sidecar. Concurrent Argon2id derivations
are serialized/bounded (one in flight per vault — the Phase 3 blocking pool owns the
mechanism), so parallel wrong-key attempts cannot multiply 256 MB allocations into
daemon OOM.

### Scope of revocation in the MVP release (rev 2)

Sync v1 carries no epoch on any request, path, or stored object, and device
revocation has no production caller today (verified 2026-09-04). **0.9 recovery
therefore revokes local authority only**: epoch advance and slot revocation take
effect on the recovering device, and the ADR does not claim online revocation until
sync v2 (WBS-614) enforces epoch and device revocation on every relay request. Full
DEK rotation (compromise response) similarly re-encrypts local records and requires
relay re-baselining that only v2 defines (WBS-624). **Until v2, DEK rotation with
sync enabled is not supported at all**: v1 re-pairing after rotation would hand a
device the new wrapped DEK while the relay still stores old-DEK blobs, and the v1
pull loop aborts before advancing its cursor — permanently wedging the new device.
The interim rule is therefore (rev 4): **DEK rotation is available only to
sync-disabled vaults until v2** — a rotated vault never re-pairs to its old relay
history; the relay's existing history is abandoned (the shipped relay has no
vault-purge endpoint or admin procedure, verified against its routes, so no
"delete the relay history" step is claimed). A vault that must rotate while sync
matters waits for v2, or the operator starts a fresh relay vault and re-onboards.
The UI must state both limits.

Setup generates 128-256 bits of recovery entropy with checksum, printable form, QR
form, and mandatory verification. Plaintext recovery material is never sent to the
relay. Recovery unwraps the DEK, creates a new password slot, increments the epoch,
revokes prior local authority, and notifies remaining devices (notification channel
lands with sync v2).

Forgotten-password recovery normally retains the DEK. A suspected compromise offers
full DEK rotation and record re-encryption (relay re-baselining per sync v2). The UI
states that previously copied offline snapshots cannot be remotely revoked.

## Options Considered

- Vendor password reset or escrow: rejected; violates zero-knowledge/local-first goals.
- Security questions or email-only recovery: rejected as insufficient assurance.
- Recovery key plus optional trusted/social recovery slots: proposed.
- Always rotate the DEK: deferred because it increases failure and backup complexity.

## Threat Model

Protects against forgotten passwords and loss of one device. It must resist relay
compromise, recovery-database theft, slot substitution, stale-device access, and
accidental removal of the final usable slot. It does not protect a leaked recovery
secret or an already copied unlocked/offline vault.

## MVP vs. Later

- MVP: password, recovery, and platform slots; device revocation; recovery drill.
- Later: mutually authenticated trusted-device recovery and optional threshold/social
  recovery. No administrative recovery by default.

## Migration and Rollout

On legacy unlock, create a vault UUID and password slot around the existing DEK.
Prompt the user to create and verify a recovery slot before enabling sync or biometric
convenience unlock. Existing paired devices re-pair under the new epoch.

## Consequences

Recovery becomes possible without weakening the master password. The schema, sync,
backup, mobile keystore, and UX must all understand slot and epoch lifecycle.
