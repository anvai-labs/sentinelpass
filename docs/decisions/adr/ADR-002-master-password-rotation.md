# ADR-002: Master Password Rotation via DEK Re-Wrap with Zero-Trust Stale-Credential Invalidation

| | |
|---|---|
| **Status** | Accepted (rev 2, after adversarial review — see git history). Shipped in v0.8.1 |
| **Date** | 2026-09-02 |
| **Area** | `sentinelpass-core` (crypto/keyring, crypto/kdf, vault metadata, daemon), `sentinelpass-cli`, `sentinelpass-ui` |
| **Related** | [ADR-001](ADR-001-credential-registry-by-logical-entity.md) (rotation-recommendation surfacing); [TECHNICAL_DEBT.md](../../../../TECHNICAL_DEBT.md) roadmap; `crypto/keyring.rs` (`KeyHierarchy`), `crypto/kdf.rs` (`KdfParams`), `database/schema.rs` (`db_metadata`), `daemon/vault_state.rs`, `sync/` (pairing bootstrap) |

## Summary

Add master-password rotation to SentinelPass. The vault's data encryption key (DEK) is a
random 32-byte key that is **independent of the master password**; the password only wraps
it. Rotation therefore **re-wraps a single blob and never re-encrypts vault entries**. What
rotation *does* change is who can unwrap that blob — so under zero-trust assumptions the
hard part is not the crypto, it is **invalidating every stale copy of the old wrapped DEK**:
other sync devices, the biometric wrapper, the running daemon's in-memory hierarchy, and any
backup taken mid-rotation. This ADR specifies a rotation that is explicitly re-authenticated,
atomic (verified-then-commit), epoch-stamped for stale-credential rejection, and audited.

## Context

Verified against `sentinelpass-core` at v0.8.0:

- **No rotation capability exists.** Zero occurrences of password-change/rewrap paths across
  core, CLI, UI (`KeyHierarchy` in `crypto/keyring.rs` offers `initialize_vault`,
  `unlock_vault`, `unlock_vault_with_dek`, `lock_vault`, `dek()` — nothing else).

### Verified wrapping mechanism (code audit)

The exact chain, read from source:

```
master password ──Argon2id(salt)──▶ Master Key ──AES-256-GCM wrap──▶ Wrapped DEK ──▶ db_metadata
                                                                                        │
entry fields ◀──AES-256-GCM (per-field nonce)── Data Encryption Key (random, ONE per vault)
```

- **One DEK per vault, not per entry.** `DataEncryptionKey::new()` (`cipher.rs:28-32`)
  generates a random 32-byte key from `OsRng`. It is *never* derived from the master
  password. All entry fields across the vault are encrypted under this single DEK
  (`vault/mod.rs` fetches `key_hierarchy.dek()` at `:201, :223, :278, :569` and calls
  `encrypt_string`).
- **The password never encrypts anything directly.** It only deterministically reproduces
  the `MasterKey` (Argon2id, fresh 16-byte salt, `kdf.rs:43-46`), whose sole purpose is the
  AES-256-GCM wrap/unwrap of the DEK (`keyring.rs` module doc, `wrap_dek`/`unwrap_dek`).
  `initialize_vault` (`keyring.rs:71-90`) generates the DEK and stores only the wrapped form
  (`WrappedKey` in `db_metadata`, alongside `kdf_params` and `dek_nonce`).
- **Consequence:** rotation is a *metadata* operation — derive a new Master Key under a new
  salt, re-wrap the same DEK, commit — and **no entry is read, written, or re-encrypted**.
  For a 28-entry vault or a 28,000-entry vault the cost is identical: one Argon2id
  derivation plus one AES-GCM wrap. Individual passwords decrypt identically afterward
  because the unwrapped DEK is byte-identical.
- **Biometric-unlock nuance (verified):** `unlock_vault_with_dek` (`keyring.rs:114-118`)
  calls `master_key.take()` — after a biometric unlock the Master Key is *not* in memory.
  Rotation must therefore always re-derive the old Master Key from the supplied current
  password (never rely on in-memory state), which also makes the operation independent of
  how the vault was unlocked.
- **Stale wrapped-DEK copies exist by design today** and are the actual risk surface:
  (1) the biometric wrapper stores a DEK-equivalent unwrap path in the OS keychain
  (`vault/biometric_ops.rs`); (2) sync pairing distributes `{kdf_params, wrapped_dek}` in the
  `VaultBootstrap` blob to paired devices (`sync/pairing.rs`); (3) a running daemon holds the
  unlocked `KeyHierarchy` in memory; (4) any export/backup predating rotation.
- The daemon cannot be handed a new password over its CLI (rpassword requires a TTY) and has
  no IPC message to rotate; after rotation a running daemon must be treated as stale.

## Decision drivers

1. **Zero-trust posture.** No component may rely on *process identity* or *same-user*
   assumptions: rotation requires proof of the current password (re-authentication), every
   stale credential derived from the old password must be *explicitly invalidated*, and
   failure at any step must leave the vault in the old, still-openable state (fail-safe, not
   fail-open).
2. **Immutability of vault ciphertext.** Entry ciphertexts, nonces, and tags are untouched —
   the DEK does not change, so there is no re-encryption window, no backup/recrypt risk, and
   rotation cost is O(1).
3. **Rollback protection** (consistent with the sync `sync_version` monotonicity rule): an
   attacker who re-introduces an *older* `db_metadata` row must not silently downgrade the
   vault to a password they know.
4. **Least privilege of surfaces:** rotation is a vault-owner operation exposed on the CLI
   (interactive, TTY) and later the UI; the daemon accepts it only over authenticated local
   IPC, and only for an already-unlocked vault.
5. **Hygiene:** old password, old master key, and intermediate material are zeroized; the new
   password is never logged, never at rest, and strength-assessed.

## Decision

**D1 — Rotation = re-wrap, never re-encryption. Epoch-bound wrapping.** With the vault
unlocked, derive `new_master_key = Argon2id(new_password, new_salt)` with fresh `KdfParams`,
unwrap the DEK under the current in-memory `KeyHierarchy`, wrap the *same* DEK under
`new_master_key`, and persist `{kdf_params(new), wrapped_dek(new), key_epoch(n+1)}` to
`db_metadata` in one transaction. Entry rows are not read or written by rotation.

**Rev 2 (F1):** the new `key_epoch` is bound as **AEAD associated data** in the DEK wrap.
A `db_metadata` row whose epoch column disagrees with the epoch baked into the wrap fails
GCM authentication at open time — a file-level rollback that swaps an older `wrapped_dek`
in alongside a matching epoch column is therefore *cryptographically* rejected, not merely
advisory. (F5: cross-vault `wrapped_dek` swaps fail the tag independently, since the DEKs
differ.)

**D2 — Explicit re-authentication under the existing lockout regime.** The operation begins
by verifying the *current* password via the existing `verify_master_password` path, and
re-derives the old Master Key from it — so rotation never depends on how the vault was
unlocked (password or biometric; a biometric-unlocked vault deliberately holds no Master
Key, and the supplied current password reconstructs everything rotation needs). Failed
verification increments the brute-force `failed_attempts` counter and is subject to the same
exponential lockout as unlock attempts; successful rotation writes an
`AuditEventType::MasterPasswordChanged { success }` event.

**D3 — Verified-then-commit atomicity.** The new wrapped DEK is persisted only after a
round-trip proof: construct a *candidate* `KeyHierarchy` from `(new_password, new_params)`,
unwrap the candidate `WrappedKey`, and require it to equal the in-memory DEK (constant-time
compare). Only then commit the transaction. A crash before commit leaves the old
`db_metadata` valid; a crash after commit leaves the vault openable with the new password.
There is no intermediate state in which either password fails.

**D4 — Monotonic `key_epoch` for stale-credential rejection.** `db_metadata` gains a
`key_epoch INTEGER NOT NULL` column, incremented on every rotation and bound as AEAD
associated data per D1. Rev 2 corrects and sharpens the invalidation scope:

- **Biometric wrapper (F2 — corrected):** rotation does **not** invalidate the biometric
  path, and that is deliberate. The wrapper stores the DEK itself under the OS keychain;
  the DEK is byte-identical after a re-wrap, so biometric unlock keeps working across
  rotation. Password rotation's threat model is *password* compromise — a thief holding the
  old password never had the device-bound keychain path, so deleting the reference would
  force re-enrollment for zero security gain. Device *compromise* is a different threat that
  re-wrap rotation cannot address by construction; its escape hatch is full DEK rotation
  (option A), available as a follow-up ADR if that threat model becomes primary.
- **Sync peers (the hard enforcement point):** the pairing bootstrap's `wrapped_dek` is
  stamped with the epoch that produced it. Peers reject bootstrap blobs and signed payloads
  referencing `key_epoch < current`, forcing re-pairing at the current epoch. The relay plus
  per-device Ed25519 signing provide the external trust anchor that makes this rejection
  meaningful (F3).
- **Local-file rollback (F3 — honest caveat):** without an external anchor, detection of a
  rolled-back live vault file is best-effort; D1's AEAD binding makes epoch/column
  inconsistency fail hard, but an attacker who rewrites *both* consistently is outside what
  file-local state can detect. Documented as a boundary, not hidden.
- **In-memory daemon state (F4 — corrected rationale):** a stale daemon's *entry crypto*
  remains correct after rotation (the DEK is unchanged); v1 still refuses rotation while a
  daemon holds the vault, but as key-material hygiene (no unepoched hierarchy copies),
  not as a correctness requirement. `ChangeMasterPassword` IPC for in-place rotation is the
  v2 slice.
- **Exports/backups:** carry their own snapshot of `wrapped_dek`; they remain openable with
  the password *at time of export* (documented property, not an invalidation target).

**D5 — Surfaces and policy.** v1 ships `sentinelpass passwd` (TTY; prompts current password,
new password, confirmation; enforces the existing lockout; strength-checks the new password
with the `crypto/health.rs` analyzer — advisory verdict plus a hard minimum-length gate of
12 characters). **Rev 2 (F6):** rotation with `new == current` is rejected (zero-entropy
rotation). The UI gains a Settings surface in a later slice behind the same core call.
Broker surfaces (`secret get`/`exec`/`env`) are unaffected: they consume daemon IPC and hold
no key material.

**D6 — Rotation is never silent.** `--force`-style overrides, bypasses of the old-password
check, or "admin reset" paths are explicitly out of scope: under zero-trust there is no
recovery path that does not require the current password (or a restored backup).
**Rev 2 (F7):** the audit event carries the epoch transition —
`AuditEventType::MasterPasswordChanged { success, from_epoch, to_epoch }` — with no secret
material.

## Options considered

- **A. Re-encrypt all entries under a new DEK on rotation.** Rejected: massive ciphertext
  churn, a crash window with mixed generations, O(n) cost for a problem that is O(1), and no
  security gain — the DEK never leaves the vault except wrapped.
- **B. No rotation ("password is forever").** Rejected: violates credential-hygiene zero-trust
  posture; a leaked password would force rebuilding the vault from export.
- **C. Key-versioned double-wrap (keep old + new wrapped DEKs concurrently).** Deferred: useful
  for zero-downtime daemon re-key, but v1's verified-then-commit makes the concurrency
  unnecessary; ADR-002's epoch model extends cleanly to it later.

## Threat model (zero-trust specific)

| Threat | Mitigation |
|---|---|
| Caller without current password attempts rotation | D2 re-authentication; failures feed the existing lockout; audit-logged |
| Stale-credential resurrection: replay old `wrapped_dek` / old biometric unwrap / old pairing bootstrap | D4 monotonic `key_epoch` rejection on all unwrap paths |
| Rollback to an older `db_metadata` (attacker knows the old password) | D4 epoch comparison at open time; older epoch refused with explicit error |
| Crash mid-rotation | D3 verified-then-commit; vault remains openable with exactly one password |
| Weak replacement password | D5 policy gate + health advisory |
| Rotation as a lockout/burn-down vector | D2: rotation shares unlock lockout; unattended daemons reject rotation while locked |
| Secret leakage via logs or swap | Passwords as `Zeroizing` inputs only; old master key zeroized post-commit; audit events carry no material |

## MVP vs. later

**MVP (this ADR's implementation slice):** `KeyHierarchy::rotate_master_password` with
epoch-bound AEAD wrapping, `key_epoch` column + additive migration (v4 → v5; **F8:** the
migration number is merge-order dependent — if ADR-001's registry migration lands first,
this one renumbers to v6 and ADR-001's schema expectations are unaffected, since both are
additive), `sentinelpass passwd` CLI, audit events with epoch transition, daemon-stale
detection (refuse while daemon holds vault), integration tests (rotation round-trip with
old-password rejection + new-password success, epoch-AAD tamper rejection, same-password
rejection, crash-before-commit equivalence, lockout interaction).

**Later slices:** `ChangeMasterPassword` daemon IPC for in-place rotation; UI Settings surface;
sync peer epoch propagation with automatic re-bootstrap on re-pair; key-versioned double-wrap
if zero-downtime re-key is ever required.

## Migration / rollout

1. Additive migration to `key_epoch` (default epoch 1 for existing vaults; no behavioral
   change until first rotation).
2. Land core + CLI slice behind no flag (rotation is opt-in per user action anyway).
3. Ship UI surface; then daemon IPC slice.
4. Document in README/SECURITY_ARCHITECTURE: rotation invalidates biometric unlock and
   requires re-pairing of sync devices (by design, per D4).

## Consequences

- Password rotation becomes a cheap, safe, frequent operation — no re-encryption, no backup
  recursion, O(1) crypto.
- Stale unwrap credentials are rejected cryptographically where possible (AEAD-bound epoch
  locally; relay-anchored epoch on the sync path) and by documented boundary elsewhere
  (file-local rollback without an external anchor).
- Biometric unlock deliberately survives rotation (same user, same device, same DEK);
  device-compromise containment is out of scope for re-wrap rotation and requires the
  option-A follow-up if ever needed.
- A new schema migration (v4 → v5, or next available per merge order with ADR-001) is
  required; the schema-compat forward-compat warning applies to older binaries opening
  rotated vaults (documented).
- Paired devices must re-pair after rotation (accepted friction; deliberate under D4).
- The daemon must not hold an unlocked vault during v1 rotation (restart friction until the
  v2 IPC slice).

## Adversarial review (rev 2)

Findings incorporated from a dedicated adversarial pass; each is labeled in place above:
- **F1** epoch not authenticated → AEAD associated-data binding (D1)
- **F2** biometric invalidation was wrong (no gain, user-hostile) → corrected: biometric survives rotation deliberately (D4)
- **F3** overclaimed local rollback detection → honest boundary split: relay-anchored enforcement hard, file-local best-effort (D4)
- **F4** daemon refusal rationale corrected: hygiene, not correctness (D4)
- **F5** cross-vault swap → covered by GCM tag; stated (D1)
- **F6** same-password rotation → rejected (D5)
- **F7** audit event lacked epoch transition → added (D6)
- **F8** migration numbering collision with ADR-001 → coordination rule (MVP)
