//! Key-slot registry (WBS-302 / ADR-004 rev 4-5).
//!
//! Vault access is represented by independently revocable slots around one
//! DEK — password, recovery, platform device/biometric, trusted device. The
//! registry is the set of those slots, and its integrity is the security
//! core: an attacker with vault-file write access must not be able to add,
//! edit, resurrect, or remove a slot.
//!
//! Integrity model (three layers, each catching what the previous cannot):
//! 1. **Registry MAC** — HMAC-SHA256 under an HKDF(DEK)-derived key over the
//!    canonical serialization of ALL slots in slot-UUID order. Catches any
//!    in-registry tampering, including whole-row resurrection (a restored
//!    pre-revocation row changes the serialized set).
//! 2. **Sidecar digest composition** — the epoch high-water sidecar's
//!    material digest includes the registry MAC bytes (ADR-004 rev 5
//!    "by composition"), so rolling back the DB *and* its MAC together is
//!    still caught at the pre-auth open check.
//! 3. **Slot wrap AAD** — each slot's own wrap binds its creation epoch, so
//!    a slot valid under one epoch cannot be replayed under another.
//!
//! Locked-while-tampered: the MAC key derives from the DEK, so full registry
//! verification happens post-unlock; the pre-auth sidecar check already
//! anchors the MAC bytes (a tampered registry changes the digest at equal
//! epoch → refusal before KDF work).
//!
//! Fail-closed rule: a stray row (present in the table but altering the
//! serialized set), a missing MAC, or a MAC mismatch refuses the vault.
//! Repair is ADR-008 verified restore only — there is no in-place fix, ever.

use crate::audit::{AuditEventType, AuditLogger};
use crate::crypto::cipher::DataEncryptionKey;
use crate::crypto::KdfParams;
use crate::crypto::WrappedKey;
use crate::{DatabaseError, PasswordManagerError, Result};
use hkdf::Hkdf;
use hmac::{Hmac, Mac};
use sha2::Sha256;
use std::sync::Arc;
use uuid::Uuid;
use zeroize::Zeroizing;

use super::{epoch_guard, VaultManager};

/// HKDF `info` label binding the slot-registry MAC key to its purpose
/// (key-separated from the DEK and from the registry equality key).
pub const SLOT_REGISTRY_MAC_INFO: &[u8] = b"sentinelpass-slot-registry-mac-v1";

/// Slot types (ADR-004). `TrustedDevice` is created but unused until the
/// post-1.0 trusted-device work.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SlotType {
    Password,
    Recovery,
    Platform,
    TrustedDevice,
}

impl SlotType {
    pub fn as_str(self) -> &'static str {
        match self {
            SlotType::Password => "password",
            SlotType::Recovery => "recovery",
            SlotType::Platform => "platform",
            SlotType::TrustedDevice => "trusted_device",
        }
    }

    fn from_db(s: &str) -> Result<Self> {
        match s {
            "password" => Ok(SlotType::Password),
            "recovery" => Ok(SlotType::Recovery),
            "platform" => Ok(SlotType::Platform),
            "trusted_device" => Ok(SlotType::TrustedDevice),
            other => Err(PasswordManagerError::InvalidInput(format!(
                "unknown slot type '{other}'"
            ))),
        }
    }
}

/// A registry row. `kdf_params` is the Argon2id profile for human-typed
/// slot credentials; machine-key slots (platform) store an empty profile
/// marker and use raw key-wrap (ADR-004 rev 4 wrap-policy-by-origin).
#[derive(Debug, Clone)]
pub struct KeySlot {
    pub slot_uuid: String,
    pub slot_type: SlotType,
    pub kdf_params: Vec<u8>,
    pub wrapped_dek: Vec<u8>,
    pub dek_nonce: Vec<u8>,
    pub key_epoch: i64,
    pub created_at: i64,
    pub revoked_at: Option<i64>,
    pub format_version: i64,
}

/// Public view of a slot (no key material).
#[derive(Debug, Clone)]
pub struct SlotSummary {
    pub slot_uuid: String,
    pub slot_type: SlotType,
    pub key_epoch: i64,
    pub created_at: i64,
    pub revoked_at: Option<i64>,
    pub usable: bool,
}

/// Derive the registry MAC key from the DEK (HKDF-SHA256, 32 bytes,
/// purpose-bound info label — same discipline as `derive_equality_key`).
pub fn derive_registry_mac_key(dek: &DataEncryptionKey) -> Result<Zeroizing<Vec<u8>>> {
    let hk = Hkdf::<Sha256>::new(None, dek.as_bytes());
    let mut okm = Zeroizing::new(vec![0u8; 32]);
    hk.expand(SLOT_REGISTRY_MAC_INFO, okm.as_mut_slice())
        .map_err(|e| {
            PasswordManagerError::InvalidInput(format!("registry MAC key derivation failed: {e}"))
        })?;
    Ok(okm)
}

fn feed_len_prefixed(mac: &mut Hmac<Sha256>, bytes: &[u8]) {
    mac.update(&(bytes.len() as u64).to_le_bytes());
    mac.update(bytes);
}

/// Canonical registry MAC: HMAC over every slot's full row content in
/// slot-UUID lexicographic order, plus the row count. Deterministic across
/// implementations; any addition, removal, edit, or resurrection of a row
/// changes the MAC.
pub fn compute_registry_mac(
    mac_key: &[u8],
    slots: &[KeySlot],
    vault_epoch: i64,
) -> Result<[u8; 32]> {
    let mut ordered: Vec<&KeySlot> = slots.iter().collect();
    ordered.sort_by(|a, b| a.slot_uuid.cmp(&b.slot_uuid));

    let mut mac = <Hmac<Sha256> as Mac>::new_from_slice(mac_key)
        .map_err(|e| DatabaseError::Other(format!("registry MAC init failed: {e}")))?;
    feed_len_prefixed(&mut mac, &(ordered.len() as u64).to_le_bytes());
    feed_len_prefixed(&mut mac, &vault_epoch.to_le_bytes());
    for slot in ordered {
        feed_len_prefixed(&mut mac, slot.slot_uuid.as_bytes());
        feed_len_prefixed(&mut mac, slot.slot_type.as_str().as_bytes());
        feed_len_prefixed(&mut mac, &slot.kdf_params);
        feed_len_prefixed(&mut mac, &slot.wrapped_dek);
        feed_len_prefixed(&mut mac, &slot.dek_nonce);
        feed_len_prefixed(&mut mac, &slot.key_epoch.to_le_bytes());
        feed_len_prefixed(&mut mac, &slot.created_at.to_le_bytes());
        match slot.revoked_at {
            Some(ts) => feed_len_prefixed(&mut mac, &ts.to_le_bytes()),
            None => feed_len_prefixed(&mut mac, &[]),
        }
        feed_len_prefixed(&mut mac, &slot.format_version.to_le_bytes());
    }
    Ok(mac.finalize().into_bytes().into())
}

impl VaultManager {
    /// Load all registry rows (unordered; MAC computation sorts).
    pub(super) fn load_key_slots(conn: &rusqlite::Connection) -> Result<Vec<KeySlot>> {
        let mut stmt = conn
            .prepare(
                "SELECT slot_uuid, slot_type, kdf_params, wrapped_dek, dek_nonce,
                        key_epoch, created_at, revoked_at, format_version
                 FROM key_slots",
            )
            .map_err(DatabaseError::Sqlite)?;
        let rows = stmt
            .query_map([], |row| {
                Ok((
                    row.get::<_, String>(0)?,
                    row.get::<_, String>(1)?,
                    row.get::<_, Vec<u8>>(2)?,
                    row.get::<_, Vec<u8>>(3)?,
                    row.get::<_, Vec<u8>>(4)?,
                    row.get::<_, i64>(5)?,
                    row.get::<_, i64>(6)?,
                    row.get::<_, Option<i64>>(7)?,
                    row.get::<_, i64>(8)?,
                ))
            })
            .map_err(DatabaseError::Sqlite)?;

        let mut slots = Vec::new();
        for row in rows {
            let (slot_uuid, type_str, kdf, wrapped, nonce, epoch, created, revoked, fv) =
                row.map_err(DatabaseError::Sqlite)?;
            // Type parsed here so tampered type strings fail closed.
            let slot_type = SlotType::from_db(&type_str)?;
            slots.push(KeySlot {
                slot_uuid,
                slot_type,
                kdf_params: kdf,
                wrapped_dek: wrapped,
                dek_nonce: nonce,
                key_epoch: epoch,
                created_at: created,
                revoked_at: revoked,
                format_version: fv,
            });
        }
        Ok(slots)
    }

    /// Public slot listing (no key material).
    pub fn list_key_slots(&self) -> Result<Vec<SlotSummary>> {
        let db = self.lock_db()?;
        let slots = Self::load_key_slots(db.conn())?;
        Ok(slots
            .into_iter()
            .map(|s| SlotSummary {
                usable: s.revoked_at.is_none(),
                slot_uuid: s.slot_uuid,
                slot_type: s.slot_type,
                key_epoch: s.key_epoch,
                created_at: s.created_at,
                revoked_at: s.revoked_at,
            })
            .collect())
    }

    /// Verify the registry MAC against the stored value. Fail closed on
    /// mismatch, missing MAC, or any unparseable row.
    pub(super) fn verify_slot_registry(
        hierarchy: &crate::crypto::KeyHierarchy,
        conn: &rusqlite::Connection,
    ) -> Result<()> {
        let dek = hierarchy.dek()?.clone();

        let stored: Option<Vec<u8>> = conn
            .query_row(
                "SELECT slot_registry_mac FROM db_metadata WHERE id = 1",
                [],
                |r| r.get(0),
            )
            .map_err(DatabaseError::Sqlite)?;
        let stored = stored.ok_or_else(|| {
            PasswordManagerError::InvalidInput(
                "slot registry MAC is missing from the vault; refusing to open".to_string(),
            )
        })?;

        let slots = Self::load_key_slots(conn)?;
        let epoch = conn
            .query_row(
                "SELECT COALESCE(key_epoch, 1) FROM db_metadata WHERE id = 1",
                [],
                |r| r.get::<_, i64>(0),
            )
            .map_err(DatabaseError::Sqlite)?;
        let key = derive_registry_mac_key(&dek)?;
        let computed = compute_registry_mac(key.as_slice(), &slots, epoch)?;

        use subtle::ConstantTimeEq;
        if !bool::from(computed.as_slice().ct_eq(&stored)) {
            return Err(PasswordManagerError::SlotRegistryTampered);
        }
        Ok(())
    }

    /// Recompute the registry MAC over the given slot set and store it.
    /// Callers hold the DB lock (inside their transaction) and pass the
    /// rows to cover; the MAC write is the commit point. Does NOT touch the
    /// epoch sidecar — callers must follow it themselves when the MAC
    /// changes (at constant epoch: `rebase`; across epochs: `bump`).
    pub(super) fn commit_slot_registry(
        hierarchy: &crate::crypto::KeyHierarchy,
        conn: &rusqlite::Connection,
        slots: &[KeySlot],
    ) -> Result<()> {
        let dek = hierarchy.dek()?.clone();
        let epoch = conn
            .query_row(
                "SELECT COALESCE(key_epoch, 1) FROM db_metadata WHERE id = 1",
                [],
                |r| r.get::<_, i64>(0),
            )
            .map_err(DatabaseError::Sqlite)?;
        let key = derive_registry_mac_key(&dek)?;
        let mac = compute_registry_mac(key.as_slice(), slots, epoch)?;

        conn.execute(
            "UPDATE db_metadata SET slot_registry_mac = ?1 WHERE id = 1",
            [&mac[..]],
        )
        .map_err(DatabaseError::Sqlite)?;
        Ok(())
    }

    /// Mint the initial password slot from the vault's existing password
    /// wrap (migration v6→v7 and fresh `create()`). Idempotent: a registry
    /// that already has rows is left untouched.
    pub(super) fn ensure_password_slot(
        conn: &rusqlite::Connection,
        kdf_params_blob: &[u8],
        wrapped_dek_blob: &[u8],
        dek_nonce_blob: &[u8],
        key_epoch: i64,
    ) -> Result<()> {
        let existing: i64 = conn
            .query_row("SELECT COUNT(*) FROM key_slots", [], |r| r.get(0))
            .map_err(DatabaseError::Sqlite)?;
        if existing > 0 {
            return Ok(());
        }

        let now = chrono::Utc::now().timestamp();
        let slot_uuid = Uuid::new_v4().to_string();
        conn.execute(
            "INSERT INTO key_slots
                (slot_uuid, slot_type, kdf_params, wrapped_dek, dek_nonce,
                 key_epoch, created_at, revoked_at, format_version)
             VALUES (?1, 'password', ?2, ?3, ?4, ?5, ?6, NULL, 1)",
            rusqlite::params![
                slot_uuid,
                kdf_params_blob,
                wrapped_dek_blob,
                dek_nonce_blob,
                key_epoch,
                now
            ],
        )
        .map_err(DatabaseError::Sqlite)?;
        Ok(())
    }

    /// Post-unlock registry step: bootstrap (one-time, migration v7 or a
    /// pre-registry vault) or verify (fail closed). Bootstrap mints the
    /// password slot if missing, computes and stores the MAC, and rebases
    /// the sidecar digest so the newly-anchored MAC does not false-refuse
    /// the next open.
    pub(super) fn ensure_or_verify_slot_registry(
        hierarchy: &crate::crypto::KeyHierarchy,
        db: &crate::database::Database,
        snapshot: &super::VaultSnapshot,
        sidecar: &Option<std::path::PathBuf>,
        vault_uuid: &Option<String>,
        allow_bootstrap: bool,
    ) -> Result<()> {
        let conn = db.conn();
        let needs_bootstrap: Option<Option<Vec<u8>>> = conn
            .query_row(
                "SELECT slot_registry_mac FROM db_metadata WHERE id = 1",
                [],
                |r| r.get(0),
            )
            .map_err(DatabaseError::Sqlite)?;

        match needs_bootstrap {
            Some(_stored) => Self::verify_slot_registry(hierarchy, conn),
            None if !allow_bootstrap => {
                // Biometric surfaces must NOT bootstrap (review round 1):
                // the MAC key derives from the keychain-released DEK, which
                // is never proven equal to db_metadata's wrapped DEK on
                // those paths — blessing it can permanently brick the vault
                // (a stale keychain DEK yields a MAC no password open can
                // ever verify). Bootstrap requires the password surface.
                Err(PasswordManagerError::InvalidInput(
                    "slot registry is not yet initialized; unlock once with your \
                     master password to complete the one-time initialization \
                     (biometric unlock cannot initialize it)"
                        .to_string(),
                ))
            }
            None => {
                let conn = db.conn();
                // Bootstrap may only bless the exact state migration/create
                // produce: EXACTLY ONE row in total (no rogue revoked rows
                // hiding behind the usable filter), of password type, at the
                // snapshot's epoch, BYTE-MIRRORING db_metadata's raw wrap
                // blobs. Comparing raw stored bytes — not re-serialized
                // structs, which diverge for legacy 3-field wraps — closes
                // the NULL-MAC-window row-swap attack (review round 1,
                // finding 3). Anything else is tampering: blessing it would
                // launder rogue rows permanently.
                {
                    let slots = Self::load_key_slots(conn)?;
                    let invariant = slots.len() == 1
                        && slots[0].slot_type == SlotType::Password
                        && slots[0].revoked_at.is_none()
                        && slots[0].key_epoch == snapshot.key_epoch
                        && slots[0].kdf_params == snapshot.raw_kdf_params
                        && slots[0].wrapped_dek == snapshot.raw_wrapped_dek
                        && slots[0].dek_nonce == snapshot.raw_dek_nonce;
                    if !invariant {
                        return Err(PasswordManagerError::InvalidInput(
                            "slot registry is not in the expected pre-bootstrap state \
                             (exactly one usable password slot byte-mirroring the vault \
                             wrap); refusing to bless it — repair is verified restore only"
                                .to_string(),
                        ));
                    }
                }
                // No mint here: the invariant guarantees the row exists
                // (migration and create() both mint inside their own
                // transactions); a missing row is tampering, refused above.
                let slots = Self::load_key_slots(conn)?;
                Self::commit_slot_registry(hierarchy, conn, &slots)?;

                // The digest now anchors the freshly-written MAC: follow the
                // sidecar at the SAME epoch with the new digest (rebase, not
                // bump — nothing about the epoch changed).
                if let (Some(path), Some(uuid)) = (sidecar, vault_uuid) {
                    let digest = epoch_guard::material_digest(conn)?;
                    epoch_guard::rebase(path, uuid, snapshot.key_epoch, &digest)?;
                }
                tracing::warn!(
                    "slot registry bootstrapped (one-time): password slot minted and \
                     registry MAC stored; sidecar digest re-anchored"
                );
                Ok(())
            }
        }
    }

    /// Mirror a committed password-wrap change into the password slot and
    /// recompute the registry MAC. Called inside the same DB scope as the
    /// `db_metadata` UPDATE it mirrors (rotation). `replace_registry`
    /// additionally DELETES all rows first — used by pair-join, whose
    /// target's pre-existing slots (including any rogue row planted during
    /// the NULL-MAC window) are throwaway and must not be MAC-blessed into
    /// the adopted vault (adversarial-review finding).
    pub(super) fn sync_password_slot_after_material_change(
        hierarchy: &crate::crypto::KeyHierarchy,
        conn: &rusqlite::Connection,
        kdf_params_blob: &[u8],
        wrapped_dek_blob: &[u8],
        dek_nonce_blob: &[u8],
        key_epoch: i64,
        replace_registry: bool,
    ) -> Result<()> {
        // NOTE (review round 2, finding 1): rotation's verify-before-write
        // runs at its CALL SITE (mod.rs), before this function is invoked —
        // NOT here. `verify_slot_registry` reads the vault epoch live, and
        // the rotation caller has already bumped `db_metadata.key_epoch` in
        // this same transaction by the time this function runs; verifying
        // here would compare the POST-bump epoch against the PRE-bump
        // stored MAC and spuriously fail every legitimate rotation. Pair-
        // join (replace_registry=true) deliberately discards the pre-join
        // registry (its rows are throwaway and must not be blessed) — no
        // verify on that path by design either.
        if replace_registry {
            conn.execute("DELETE FROM key_slots", [])
                .map_err(DatabaseError::Sqlite)?;
            let now = chrono::Utc::now().timestamp();
            let slot_uuid = Uuid::new_v4().to_string();
            conn.execute(
                "INSERT INTO key_slots
                    (slot_uuid, slot_type, kdf_params, wrapped_dek, dek_nonce,
                     key_epoch, created_at, revoked_at, format_version)
                 VALUES (?1, 'password', ?2, ?3, ?4, ?5, ?6, NULL, 1)",
                rusqlite::params![
                    slot_uuid,
                    kdf_params_blob,
                    wrapped_dek_blob,
                    dek_nonce_blob,
                    key_epoch,
                    now
                ],
            )
            .map_err(DatabaseError::Sqlite)?;
        } else {
            conn.execute(
                "UPDATE key_slots SET kdf_params = ?1, wrapped_dek = ?2, dek_nonce = ?3,
                        key_epoch = ?4
                 WHERE slot_type = 'password' AND revoked_at IS NULL",
                rusqlite::params![kdf_params_blob, wrapped_dek_blob, dek_nonce_blob, key_epoch],
            )
            .map_err(DatabaseError::Sqlite)?;
        }
        let slots = Self::load_key_slots(conn)?;
        Self::commit_slot_registry(hierarchy, conn, &slots)
    }

    /// WBS-312: recover access WITHOUT the old master password. The recovery
    /// key unwraps the DEK (any usable recovery slot, newest first); the
    /// registry MAC is verified with the recovered DEK BEFORE anything is
    /// written (a tampered registry must not be minted into a new epoch);
    /// then ONE transaction: revoke every usable slot (the lost password
    /// slot included — presumed compromised), mint the new password slot,
    /// advance the epoch, rewrap db_metadata under the new password, and
    /// recompute the registry MAC. The sidecar bumps to the new epoch.
    ///
    /// Per ADR-004 rev 4 this is LOCAL revocation only: prior online sync
    /// authority is revoked when sync v2 enforces the epoch (WBS-614).
    pub fn recover_access(
        path: &std::path::Path,
        recovery_key: &super::recovery::RecoveryKey,
        new_password: &[u8],
    ) -> Result<()> {
        const MIN_LENGTH: usize = 12;
        if new_password.len() < MIN_LENGTH {
            return Err(PasswordManagerError::InvalidInput(format!(
                "New master password must be at least {MIN_LENGTH} characters"
            )));
        }

        let db = crate::database::Database::open(path)?;
        // Fail closed on unsupported newer schemas before touching anything.
        db.validate_schema_version()?;

        let conn = db.conn();
        let snapshot = Self::load_vault_snapshot(&db)?;
        let vault_uuid = snapshot.vault_uuid.clone().ok_or_else(|| {
            PasswordManagerError::InvalidInput(
                "vault identity (vault_uuid) is missing; refusing recovery".to_string(),
            )
        })?;

        // Audit logger BEFORE the guard (review round 2, finding 2): the
        // highest-severity attack signal on this feature — an epoch-guard
        // refusal on the recovery path — must leave a durable trace.
        let audit_logger = AuditLogger::new(crate::get_audit_log_dir())
            .map(Arc::new)
            .ok();

        // Epoch high-water enforcement BEFORE anything else (review round 1,
        // critical finding): recovery is a vault-opening path and must refuse
        // exactly the rollback / material-rewind states open() refuses.
        // Without this, an attacker holding a REVOKED recovery key plus an
        // old vault-file copy launders the rollback through recovery — the
        // revocation is defeated with zero refusals fired. HealPending is
        // acceptable to proceed from: the registry MAC (verified below with
        // the recovered DEK) authenticates the on-disk state, and recovery's
        // own epoch advance supersedes the pending transition. TOFU-minting
        // an absent sidecar is protection-neutral.
        if let Some(sidecar_path) = Self::sidecar_for(path) {
            if let Err(guard_err) = epoch_guard::check(
                &sidecar_path,
                &vault_uuid,
                snapshot.key_epoch,
                &snapshot.digest,
            ) {
                if let Some(ref logger) = audit_logger {
                    let _ = logger.log(
                        AuditEventType::EpochHighWaterRebased { refused: true },
                        &format!("recovery refused by epoch guard: {guard_err}"),
                    );
                }
                return Err(guard_err);
            }
        }

        // Unwrap the DEK via the NEWEST usable recovery slot (onboarding
        // replacement keeps old rows revoked; a stale row must not win).
        let (slot_uuid, wrapped_blob, epoch_at_wrap, nonce) = {
            let slots = Self::load_key_slots(conn)?;
            let mut candidates: Vec<&KeySlot> = slots
                .iter()
                .filter(|s| s.slot_type == SlotType::Recovery && s.revoked_at.is_none())
                .collect();
            candidates.sort_by_key(|s| std::cmp::Reverse(s.created_at));

            let recovery_slot = candidates.first().ok_or_else(|| {
                PasswordManagerError::NotFound(
                    "no usable recovery slot on this vault; recovery was never set up \
                     or the slot was revoked"
                        .to_string(),
                )
            })?;

            let nonce: [u8; 12] = bincode::deserialize(&recovery_slot.dek_nonce)
                .map_err(|e| DatabaseError::Serialization(e.to_string()))?;
            (
                recovery_slot.slot_uuid.clone(),
                recovery_slot.wrapped_dek.clone(),
                recovery_slot.key_epoch,
                nonce,
            )
        };

        let dek = Self::unwrap_dek_via_recovery_slot(
            &wrapped_blob,
            &nonce,
            recovery_key,
            &vault_uuid,
            &slot_uuid,
            epoch_at_wrap,
        )
        .map_err(|e| {
            // No lockout budget here: the recovery key is 256-bit generated
            // entropy with a checksum, not a guessable password — and the
            // GCM tag IS the attempt limiter.
            PasswordManagerError::InvalidInput(format!(
                "recovery key did not open this vault's recovery slot: {e}"
            ))
        })?;

        // Build the new password wrap OUTSIDE the transaction (Argon2id is
        // expensive): derive the new master key, wrap the recovered DEK
        // with the new epoch as AAD, and verify the staged wrap round-trips
        // before it can be committed (WBS-309 discipline).
        let new_epoch = snapshot.key_epoch.checked_add(1).ok_or_else(|| {
            PasswordManagerError::InvalidInput("vault epoch exhausted".to_string())
        })?;
        let new_kdf = KdfParams::new();
        let new_master = crate::crypto::MasterKey::from_bytes(
            crate::crypto::kdf::derive_master_key(new_password, &new_kdf)?,
        );
        let new_wrapped = crate::crypto::KeyHierarchy::wrap_dek_under_key(
            &new_master,
            &dek,
            Some(&new_epoch.to_le_bytes()),
            true,
        )?;
        let verify = crate::crypto::KeyHierarchy::unwrap_dek_under_key(
            &new_master,
            &new_wrapped,
            Some(&new_epoch.to_le_bytes()),
        )?;
        use subtle::ConstantTimeEq;
        if !bool::from(verify.as_bytes().ct_eq(dek.as_bytes())) {
            return Err(PasswordManagerError::InvalidInput(
                "staged password wrap failed verification; recovery aborted".to_string(),
            ));
        }

        // A transient hierarchy carrying the recovered DEK for the MAC key
        // derivation inside the transaction below.
        let mut recovered_hierarchy = crate::crypto::KeyHierarchy::new();
        recovered_hierarchy.unlock_vault_with_dek(dek.clone());

        // A NULL registry MAC means the vault has not been opened with a
        // password since the v7 migration: recovery refuses and asks for one
        // such unlock first (review round 1). Reason: the pre-bootstrap
        // window carries no registry integrity guarantee, and recovery's
        // verify-before-write rule needs a stored MAC to verify against.
        {
            let existing_mac: Option<Vec<u8>> = conn
                .query_row(
                    "SELECT slot_registry_mac FROM db_metadata WHERE id = 1",
                    [],
                    |r| r.get(0),
                )
                .map_err(DatabaseError::Sqlite)?;
            if existing_mac.is_none() {
                return Err(PasswordManagerError::InvalidInput(
                    "the slot registry is not initialized on this vault; unlock once \
                     with your current master password (any password open completes the \
                     one-time initialization), then re-run recovery"
                        .to_string(),
                ));
            }
        }

        // ONE transaction: revoke all usable slots, mint the new password
        // slot, rewrap db_metadata, advance the epoch, recompute the MAC.
        conn.execute_batch("BEGIN IMMEDIATE;")
            .map_err(DatabaseError::Sqlite)?;

        let new_slot_uuid = Uuid::new_v4().to_string();
        let inner = || -> Result<()> {
            // Re-verify INSIDE the write lock (review round 1, TOCTOU
            // finding): a racing DB-writer between the outer verify and
            // BEGIN IMMEDIATE would otherwise have its tampered rows
            // MAC-blessed into the new epoch by the commit below.
            Self::verify_slot_registry(&recovered_hierarchy, conn)?;

            let now = chrono::Utc::now().timestamp();
            conn.execute(
                "UPDATE key_slots SET revoked_at = ?1 WHERE revoked_at IS NULL",
                [now],
            )
            .map_err(DatabaseError::Sqlite)?;

            let kdf_blob = bincode::serialize(&new_kdf)
                .map_err(|e| DatabaseError::Serialization(e.to_string()))?;
            let wrapped_blob = bincode::serialize(&new_wrapped)
                .map_err(|e| DatabaseError::Serialization(e.to_string()))?;
            let nonce_blob = bincode::serialize(&new_wrapped.nonce)
                .map_err(|e| DatabaseError::Serialization(e.to_string()))?;
            conn.execute(
                "INSERT INTO key_slots
                    (slot_uuid, slot_type, kdf_params, wrapped_dek, dek_nonce,
                     key_epoch, created_at, revoked_at, format_version)
                 VALUES (?1, 'password', ?2, ?3, ?4, ?5, ?6, NULL, 1)",
                rusqlite::params![
                    new_slot_uuid,
                    kdf_blob,
                    wrapped_blob,
                    nonce_blob,
                    new_epoch,
                    now
                ],
            )
            .map_err(DatabaseError::Sqlite)?;

            conn.execute(
                "UPDATE db_metadata
                 SET kdf_params = ?1, wrapped_dek = ?2, dek_nonce = ?3,
                     key_epoch = ?4, last_modified = ?5
                 WHERE id = 1 AND key_epoch = ?6",
                rusqlite::params![
                    &kdf_blob,
                    &wrapped_blob,
                    &nonce_blob,
                    new_epoch,
                    now,
                    snapshot.key_epoch
                ],
            )
            .map_err(DatabaseError::Sqlite)?;
            let rows_changed = conn
                .query_row("SELECT changes()", [], |r| r.get::<_, i64>(0))
                .map_err(DatabaseError::Sqlite)?;
            if rows_changed != 1 {
                return Err(PasswordManagerError::InvalidInput(
                    "vault changed concurrently during recovery; aborted — retry".to_string(),
                ));
            }

            let fresh = Self::load_key_slots(conn)?;
            Self::commit_slot_registry(&recovered_hierarchy, conn, &fresh)
        };

        match inner() {
            Ok(()) => {
                conn.execute_batch("COMMIT;")
                    .map_err(DatabaseError::Sqlite)
                    .map_err(PasswordManagerError::from)?;
                if let Some(ref logger) = audit_logger {
                    let _ = logger.log(
                        AuditEventType::RecoveryPerformed {
                            from_epoch: snapshot.key_epoch,
                            to_epoch: new_epoch,
                        },
                        "vault access regained via recovery key: all prior slots revoked, \
                         new password minted (local revocation; online authority revoked \
                         at sync v2)",
                    );
                }
            }
            Err(e) => {
                let _ = conn.execute_batch("ROLLBACK;");
                if let (Some(ref logger), PasswordManagerError::SlotRegistryTampered) =
                    (&audit_logger, &e)
                {
                    let _ = logger.log(
                        AuditEventType::SlotRegistryIntegrityRefused,
                        "recovery refused: slot registry failed integrity verification",
                    );
                }
                return Err(e);
            }
        }

        // Clear the biometric slot POST-commit, best-effort (review round 2,
        // finding 7): the keychain deletion is an irreversible external side
        // effect that cannot be rolled back by SQL — performing it mid-
        // transaction meant a LATER in-tx failure (e.g. the MAC commit)
        // would ROLLBACK the DB's biometric_ref column while the keychain
        // entry was already gone, leaving the two permanently disagreeing.
        // The recovery itself (all slots revoked, new password minted) is
        // already durable at this point; a failure here is surfaced but
        // does not unwind it — same tolerance the sidecar bump below gets.
        if let Ok(Some(bio_ref)) = Self::load_biometric_ref(&db) {
            match crate::biometric::BiometricManager::clear_vault_dek(&bio_ref) {
                Ok(()) => {
                    if let Err(e) = conn.execute(
                        "UPDATE db_metadata SET biometric_ref = NULL WHERE id = 1",
                        [],
                    ) {
                        tracing::warn!(
                            "clearing biometric_ref after recovery failed: {e} (keychain \
                             entry already cleared; disable biometric unlock manually)"
                        );
                    }
                }
                Err(e) => {
                    let unsupported = matches!(
                        &e,
                        PasswordManagerError::NotFound(msg)
                            if msg.contains(crate::biometric::UNSUPPORTED_PLATFORM_MSG)
                    );
                    if unsupported {
                        let _ = conn.execute(
                            "UPDATE db_metadata SET biometric_ref = NULL WHERE id = 1",
                            [],
                        );
                    } else {
                        tracing::warn!(
                            "clearing biometric keychain entry after recovery failed: {e} \
                             (disable biometric unlock manually)"
                        );
                    }
                }
            }
        }

        // Follow the sidecar to the new epoch (best-effort by design, same
        // as rotation: a missed bump heals via the authenticated +1 lag).
        let sidecar = Self::sidecar_for(path);
        if let Some(ref sidecar_path) = sidecar {
            let digest = epoch_guard::material_digest(conn)?;
            if let Err(e) = epoch_guard::bump(sidecar_path, &vault_uuid, new_epoch, &digest) {
                tracing::warn!(
                    "epoch sidecar bump failed after committed recovery: {} \
                     (self-heals at next authenticated open)",
                    e
                );
            }
        }

        tracing::warn!(
            "vault access recovered: all prior slots revoked, new password slot              minted at epoch {new_epoch} (local revocation only; online sync              authority is revoked when sync v2 enforces epochs)"
        );
        Ok(())
    }

    /// Follow the sidecar digest after a CONSTANT-epoch registry change
    /// (revoke / recovery-slot create). Compares EPOCHS only — never
    /// `check()`, whose equal-epoch digest-mismatch refusal is exactly the
    /// legitimate change this follow exists to apply. Never adopts a pending
    /// heal: a lagging sidecar (rotation whose follow crashed) is left for
    /// the next AUTHENTICATED password unlock to adopt (ADR-004 rev 5;
    /// review round 1 finding: the old unconditional rebase laundered
    /// unauthenticated adoption).
    fn follow_sidecar_at_constant_epoch(&self, conn: &rusqlite::Connection) -> Result<()> {
        let (Some(sidecar), Some(uuid)) = (&self.epoch_sidecar, &self.vault_uuid) else {
            return Ok(());
        };
        let epoch = conn
            .query_row(
                "SELECT COALESCE(key_epoch, 1) FROM db_metadata WHERE id = 1",
                [],
                |r| r.get::<_, i64>(0),
            )
            .map_err(DatabaseError::Sqlite)?;
        match epoch_guard::peek(sidecar) {
            None => {
                // Absent sidecar (crash between DB write and a previous
                // follow, or pre-sidecar vault): mint from current state —
                // protection-neutral TOFU.
                let digest = epoch_guard::material_digest(conn)?;
                epoch_guard::rebase(sidecar, uuid, epoch, &digest)
            }
            Some((sidecar_uuid, sidecar_epoch)) => {
                if sidecar_uuid != *uuid {
                    return Err(PasswordManagerError::InvalidInput(
                        "epoch sidecar belongs to a different vault; refusing to follow"
                            .to_string(),
                    ));
                }
                if sidecar_epoch == epoch {
                    let digest = epoch_guard::material_digest(conn)?;
                    epoch_guard::rebase(sidecar, uuid, epoch, &digest)
                } else if sidecar_epoch < epoch {
                    tracing::warn!(
                        "sidecar lags the DB epoch (pending heal); constant-epoch digest \
                         follow deferred — the heal is adopted at the next authenticated \
                         password unlock"
                    );
                    Ok(())
                } else {
                    Err(PasswordManagerError::EpochRollback {
                        on_disk: epoch,
                        high_water: sidecar_epoch,
                    })
                }
            }
        }
    }

    /// The recovery-slot AAD byte encoding — ONE implementation shared by
    /// wrap and unwrap (review finding: the duplicated loops were a
    /// divergence trap — a future edit applied to one side only would
    /// silently break every recovery slot at the exact moment a user needs
    /// it). WBS-303's AAD builder generalizes this.
    fn recovery_slot_aad(vault_uuid: &str, slot_uuid: &str, key_epoch: i64) -> Vec<u8> {
        let mut aad = Vec::with_capacity(96);
        for part in [
            b"sp-recovery-slot-v1".as_slice(),
            vault_uuid.as_bytes(),
            slot_uuid.as_bytes(),
            b"recovery".as_slice(),
        ] {
            aad.extend_from_slice(&(part.len() as u32).to_le_bytes());
            aad.extend_from_slice(part);
        }
        aad.extend_from_slice(&key_epoch.to_le_bytes());
        aad
    }

    /// Wrap the DEK under a machine-generated recovery key: raw AES-256-GCM
    /// (no KDF — the wrap policy is by key ORIGIN; the key is 256 recorded
    /// bits of generated entropy, ADR-004 rev 4). The AAD binds the slot's
    /// full semantic identity — vault, slot uuid, type, epoch — so a wrapped
    /// DEK cannot be transplanted between vaults, slots, or epochs.
    fn wrap_dek_for_recovery_slot(
        dek: &DataEncryptionKey,
        recovery_key: &super::recovery::RecoveryKey,
        vault_uuid: &str,
        slot_uuid: &str,
        key_epoch: i64,
    ) -> Result<(WrappedKey, Vec<u8>)> {
        use aes_gcm::{
            aead::{Aead, AeadCore, KeyInit, OsRng},
            Aes256Gcm, Nonce,
        };

        let cipher = Aes256Gcm::new_from_slice(recovery_key.as_bytes())
            .map_err(|e| DatabaseError::Other(format!("recovery wrap key init: {e}")))?;
        let nonce_bytes: [u8; 12] = Aes256Gcm::generate_nonce(&mut OsRng).into();
        let nonce_blob = bincode::serialize(&nonce_bytes)
            .map_err(|e| DatabaseError::Serialization(e.to_string()))?;

        let aad = Self::recovery_slot_aad(vault_uuid, slot_uuid, key_epoch);

        let ciphertext = cipher
            .encrypt(
                &Nonce::from(nonce_bytes),
                aes_gcm::aead::Payload {
                    msg: dek.as_bytes(),
                    aad: &aad,
                },
            )
            .map_err(|e| DatabaseError::Other(format!("recovery wrap failed: {e}")))?;

        // Store as the same durable WrappedKey shape the password slot uses,
        // with epoch_bound=true (the AAD above binds the epoch).
        let auth_tag: [u8; 16] = ciphertext[ciphertext.len() - 16..]
            .try_into()
            .map_err(|_| DatabaseError::Other("recovery wrap tag".to_string()))?;
        Ok((
            WrappedKey {
                wrapped_dek: ciphertext[..ciphertext.len() - 16].to_vec(),
                nonce: nonce_bytes,
                auth_tag,
                epoch_bound: true,
            },
            nonce_blob,
        ))
    }

    /// Unwrap the DEK from a recovery slot (the seam WBS-312's recovery
    /// flow consumes). Fails closed on any AAD/context mismatch.
    pub(super) fn unwrap_dek_via_recovery_slot(
        dek_wrapped: &[u8],
        nonce: &[u8; 12],
        recovery_key: &super::recovery::RecoveryKey,
        vault_uuid: &str,
        slot_uuid: &str,
        key_epoch: i64,
    ) -> Result<DataEncryptionKey> {
        use aes_gcm::{aead::Aead, Aes256Gcm, KeyInit, Nonce};
        use subtle::ConstantTimeEq;

        let wrapped: WrappedKey = bincode::deserialize(dek_wrapped)
            .map_err(|e| DatabaseError::Serialization(e.to_string()))?;
        if !wrapped.epoch_bound {
            return Err(PasswordManagerError::InvalidInput(
                "recovery slot wrap is not epoch-bound; refusing".to_string(),
            ));
        }
        let aad = Self::recovery_slot_aad(vault_uuid, slot_uuid, key_epoch);

        let cipher = Aes256Gcm::new_from_slice(recovery_key.as_bytes())
            .map_err(|e| DatabaseError::Other(format!("recovery unwrap key init: {e}")))?;
        let mut ct = wrapped.wrapped_dek.clone();
        ct.extend_from_slice(&wrapped.auth_tag);
        if !bool::from(nonce.ct_eq(&wrapped.nonce)) {
            return Err(PasswordManagerError::InvalidInput(
                "recovery slot nonce mismatch".to_string(),
            ));
        }
        let dek_bytes = cipher
            .decrypt(
                &Nonce::from(*nonce),
                aes_gcm::aead::Payload {
                    msg: &ct,
                    aad: &aad,
                },
            )
            .map_err(|_| {
                PasswordManagerError::Crypto(crate::crypto::CryptoError::AuthenticationFailed)
            })?;
        let mut dek_arr: [u8; 32] = dek_bytes
            .try_into()
            .map_err(|_| DatabaseError::Other("recovered DEK length".to_string()))?;
        Ok(DataEncryptionKey::from_bytes(&mut dek_arr))
    }

    /// WBS-311: create (or replace) the vault's recovery slot from a
    /// VERIFIED recovery key — the caller generated the key, showed it, and
    /// the user re-entered it successfully (`parse_recovery_key` validated
    /// the checksum; SR-RECOVERY-002 forbids persisting an unverified key).
    /// One transaction: revoke any previous recovery slot, insert the new
    /// one (raw wrap of the current DEK, full AAD binding), recompute the
    /// registry MAC; the sidecar follows at the constant epoch.
    pub fn create_recovery_slot(&self, verified_key: &super::recovery::RecoveryKey) -> Result<()> {
        let dek = self.key_hierarchy.dek()?.clone();
        let db = self.lock_db()?;
        let conn = db.conn();

        conn.execute_batch("BEGIN IMMEDIATE;")
            .map_err(DatabaseError::Sqlite)?;

        let inner = || -> Result<()> {
            // Verify-before-write (review round 2, finding 1).
            Self::verify_slot_registry(&self.key_hierarchy, conn)?;

            let (epoch, vault_uuid) = conn
                .query_row(
                    "SELECT COALESCE(key_epoch, 1), COALESCE(vault_uuid, '') \
                     FROM db_metadata WHERE id = 1",
                    [],
                    |r| Ok((r.get::<_, i64>(0)?, r.get::<_, String>(1)?)),
                )
                .map_err(DatabaseError::Sqlite)?;

            let now = chrono::Utc::now().timestamp();
            // Replace semantics with history: revoke the previous recovery
            // slot (if any) and mint a fresh one — the registry keeps the
            // revocation, so a rolled-back row cannot silently resurrect.
            conn.execute(
                "UPDATE key_slots SET revoked_at = ?1
                 WHERE slot_type = 'recovery' AND revoked_at IS NULL",
                [now],
            )
            .map_err(DatabaseError::Sqlite)?;

            let slot_uuid = Uuid::new_v4().to_string();
            let (wrapped, nonce_blob) = Self::wrap_dek_for_recovery_slot(
                &dek,
                verified_key,
                &vault_uuid,
                &slot_uuid,
                epoch,
            )?;
            let wrapped_blob = bincode::serialize(&wrapped)
                .map_err(|e| DatabaseError::Serialization(e.to_string()))?;

            conn.execute(
                "INSERT INTO key_slots
                    (slot_uuid, slot_type, kdf_params, wrapped_dek, dek_nonce,
                     key_epoch, created_at, revoked_at, format_version)
                 VALUES (?1, 'recovery', X'7261772D7631', ?2, ?3, ?4, ?5, NULL, 1)",
                rusqlite::params![slot_uuid, wrapped_blob, nonce_blob, epoch, now],
            )
            .map_err(DatabaseError::Sqlite)?;

            let fresh = Self::load_key_slots(conn)?;
            Self::commit_slot_registry(&self.key_hierarchy, conn, &fresh)
        };

        match inner() {
            Ok(()) => {
                conn.execute_batch("COMMIT;")
                    .map_err(DatabaseError::Sqlite)
                    .map_err(PasswordManagerError::from)?;
            }
            Err(e) => {
                let _ = conn.execute_batch("ROLLBACK;");
                return Err(e);
            }
        }

        // Audit AFTER commit, BEFORE the anchor follow (review round 2,
        // finding 4): the slot EXISTS from the commit above; a follow
        // failure must not make the creation invisible in the audit trail.
        if let Some(ref logger) = self.audit_logger {
            let _ = logger.log(
                AuditEventType::RecoverySlotCreated,
                "recovery slot created (or replaced) after verified re-entry",
            );
        }

        // Constant-epoch MAC change: the sidecar digest MUST follow (same
        // rule as revoke; propagation is hard).
        self.follow_sidecar_at_constant_epoch(conn)?;
        Ok(())
    }

    /// Revoke a slot. Refuses to remove the final usable slot (WBS-313's
    /// guard, enforced here so no caller can bypass it).
    pub fn revoke_key_slot(&self, slot_uuid: &str) -> Result<()> {
        let db = self.lock_db()?;
        let conn = db.conn();

        // BEGIN IMMEDIATE takes the write lock up front: the final-slot
        // guard, the revoked_at UPDATE, and the registry-MAC recompute run
        // as ONE serialized unit. The prior shape (read outside, two
        // autocommit writes) had both a crash window — revoked_at durable
        // with a stale MAC is a permanent verified-restore-only brick with
        // no remediation — and a cross-process lost-update (adversarial
        // review, round 1).
        conn.execute_batch("BEGIN IMMEDIATE;")
            .map_err(DatabaseError::Sqlite)?;

        let inner = || -> Result<bool> {
            // Verify-before-write (review round 2, finding 1): mid-session
            // tampering (e.g. a resurrected row flipped after open()'s
            // verify) must refuse here — NOT be MAC-blessed by this
            // revoke's recompute.
            Self::verify_slot_registry(&self.key_hierarchy, conn)?;

            let slots = Self::load_key_slots(conn)?;
            let target = slots
                .iter()
                .find(|s| s.slot_uuid == slot_uuid)
                .ok_or_else(|| PasswordManagerError::NotFound(format!("slot {slot_uuid}")))?;

            if target.revoked_at.is_some() {
                // Already revoked: nothing to write, but the sidecar follow
                // below still MUST run — a prior attempt may have committed
                // the revoke and then failed its rebase (review finding).
                return Ok(false);
            }

            // Guard under the write lock (fresh read above).
            let usable_after: usize = slots
                .iter()
                .filter(|s| s.revoked_at.is_none() && s.slot_uuid != slot_uuid)
                .count();
            if usable_after == 0 {
                return Err(PasswordManagerError::InvalidInput(
                    "refusing to revoke the final usable key slot — the vault would have \
                     no unlock method; add another slot first (WBS-313)"
                        .to_string(),
                ));
            }

            let now = chrono::Utc::now().timestamp();
            conn.execute(
                "UPDATE key_slots SET revoked_at = ?1 WHERE slot_uuid = ?2",
                rusqlite::params![now, slot_uuid],
            )
            .map_err(DatabaseError::Sqlite)?;
            // Recompute over a FRESH in-transaction read — never a stale
            // in-memory set (a stale set MACs a world that no longer
            // exists; review finding).
            let fresh = Self::load_key_slots(conn)?;
            Self::commit_slot_registry(&self.key_hierarchy, conn, &fresh)?;
            Ok(true)
        };

        match inner() {
            Ok(_wrote) => {
                conn.execute_batch("COMMIT;")
                    .map_err(DatabaseError::Sqlite)
                    .map_err(PasswordManagerError::from)?;
            }
            Err(e) => {
                let _ = conn.execute_batch("ROLLBACK;");
                return Err(e);
            }
        }

        // Audit AFTER commit, BEFORE the anchor follow (review round 2:
        // committed privileged changes must leave a durable trace even if
        // the follow fails) — revocation is the core security control.
        if let Some(ref logger) = self.audit_logger {
            let _ = logger.log(
                AuditEventType::SlotRevoked,
                &format!("key slot revoked: {slot_uuid}"),
            );
        }

        // The registry MAC changed at a CONSTANT epoch — the sidecar digest
        // includes it, so the anchor MUST be followed here or the next open
        // false-refuses as 'material rollback' and coaches deleting the
        // sidecar for a benign revoke. Runs on BOTH the fresh-revoke and
        // the already-revoked (retry) paths. Propagation is hard: a revoke
        // that cannot update its anchor has not durably revoked.
        self.follow_sidecar_at_constant_epoch(conn)?;
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn demo_slots(vault_epoch: i64) -> Vec<KeySlot> {
        vec![
            KeySlot {
                slot_uuid: "00000000-0000-0000-0000-00000000000b".into(),
                slot_type: SlotType::Password,
                kdf_params: vec![1, 2],
                wrapped_dek: vec![9, 9, 9],
                dek_nonce: vec![1; 12],
                key_epoch: vault_epoch,
                created_at: 100,
                revoked_at: None,
                format_version: 1,
            },
            KeySlot {
                slot_uuid: "00000000-0000-0000-0000-00000000000a".into(),
                slot_type: SlotType::Recovery,
                kdf_params: vec![3, 4],
                wrapped_dek: vec![7, 7],
                dek_nonce: vec![2; 12],
                key_epoch: 1,
                created_at: 101,
                revoked_at: Some(999),
                format_version: 1,
            },
        ]
    }

    #[test]
    fn mac_is_order_independent_and_input_sensitive() {
        let key = [5u8; 32];
        let a = compute_registry_mac(&key, &demo_slots(3), 3).unwrap();
        // Insertion order must not matter (canonical UUID order).
        let mut reordered = demo_slots(3);
        reordered.reverse();
        let b = compute_registry_mac(&key, &reordered, 3).unwrap();
        assert_eq!(a, b);

        // Every mutation class changes the MAC:
        // edit
        let mut edited = demo_slots(3);
        edited[0].wrapped_dek[0] ^= 1;
        assert_ne!(a, compute_registry_mac(&key, &edited, 3).unwrap());
        // resurrect (un-revoke)
        let mut resurrected = demo_slots(3);
        resurrected[1].revoked_at = None;
        assert_ne!(a, compute_registry_mac(&key, &resurrected, 3).unwrap());
        // add
        let mut added = demo_slots(3);
        added.push(demo_slots(3)[0].clone());
        assert_ne!(a, compute_registry_mac(&key, &added, 3).unwrap());
        // remove
        let removed: Vec<KeySlot> = demo_slots(3)[..1].to_vec();
        assert_ne!(a, compute_registry_mac(&key, &removed, 3).unwrap());
        // epoch bump
        assert_ne!(a, compute_registry_mac(&key, &demo_slots(3), 4).unwrap());
        // different key
        assert_ne!(
            a,
            compute_registry_mac(&[6u8; 32], &demo_slots(3), 3).unwrap()
        );
    }

    #[test]
    fn registry_mac_key_is_dek_bound_and_purpose_separated() {
        let dek_a = DataEncryptionKey::new().unwrap();
        let dek_b = DataEncryptionKey::new().unwrap();
        let key_a = derive_registry_mac_key(&dek_a).unwrap();
        let key_b = derive_registry_mac_key(&dek_b).unwrap();
        assert_ne!(key_a.to_vec(), key_b.to_vec());

        // Purpose separation from the equality key (same DEK, different info).
        let equality = crate::crypto::derive_equality_key(&dek_a).unwrap();
        assert_ne!(key_a.to_vec(), equality.to_vec());
    }
}

#[cfg(test)]
mod roundtrip_determinism {
    use crate::crypto::{KdfParams, WrappedKey};

    /// Bincode round-trip determinism: re-serializing what db_metadata
    /// stores must be byte-identical for CURRENT shapes. (Legacy 3-field
    /// wraps deliberately DIVERGE on re-serialization — which is exactly
    /// why the bootstrap invariant compares the slot's blobs against the
    /// raw stored bytes rather than re-serialized ones.)
    #[test]
    fn snapshot_blobs_round_trip_byte_identically() {
        let params = KdfParams::new();
        let mut hierarchy = crate::crypto::KeyHierarchy::new();
        let (_, wrapped) = hierarchy.initialize_vault(b"round-trip-probe").unwrap();

        let p1 = bincode::serialize(&params).unwrap();
        let p2 = bincode::serialize(&bincode::deserialize::<KdfParams>(&p1).unwrap()).unwrap();
        assert_eq!(p1, p2, "KdfParams round-trip must be byte-stable");

        let w1 = bincode::serialize(&wrapped).unwrap();
        let w2 = bincode::serialize(&WrappedKey::from_bincode_bytes(&w1).unwrap()).unwrap();
        assert_eq!(w1, w2, "WrappedKey round-trip must be byte-stable");

        let n1 = bincode::serialize(&wrapped.nonce).unwrap();
        let n2 = bincode::serialize(&bincode::deserialize::<[u8; 12]>(&n1).unwrap()).unwrap();
        assert_eq!(n1, n2, "nonce round-trip must be byte-stable");
    }
}
