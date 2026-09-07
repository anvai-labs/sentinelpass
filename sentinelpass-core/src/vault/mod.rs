//! Vault management - coordinates crypto and database layers

mod biometric_ops;
pub(crate) mod domain_ops;
pub(crate) mod envelope_ops;
pub(crate) mod epoch_guard;
mod health_ops;
pub(crate) mod migration_ops;
pub mod recovery;
mod registry_ops;
pub(crate) mod slot_ops;

pub use domain_ops::DomainSweepReport;
pub use migration_ops::V2BlobSweepReport;
pub use slot_ops::{SlotSummary, SlotType};
mod ssh_ops;
mod sync_ops;
#[cfg(test)]
mod tests;
mod totp_ops;

use crate::{
    audit::{get_audit_log_dir, AuditEventType, AuditLogger},
    crypto::cipher::encrypt_string,
    crypto::{KdfParams, KeyHierarchy, WrappedKey},
    database::{
        schema::CURRENT_SCHEMA_VERSION, Database, EntryFilter, EntryRepository, NewEntryParams,
        RawEntryRow, SqliteEntryRepository, UpdateEntryParams,
    },
    lockout::DEFAULT_MAX_ATTEMPTS,
    platform::{ensure_data_dir, get_default_vault_path},
    DatabaseError, PasswordManagerError, Result,
};
use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use std::path::{Path, PathBuf};
use std::sync::{Arc, Mutex};
use zeroize::Zeroizing;

/// Credential category stored with a vault entry.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, Default)]
#[serde(rename_all = "snake_case")]
pub enum CredentialType {
    #[default]
    Password,
    ApiKey,
    PasskeyReference,
}

impl CredentialType {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Password => "password",
            Self::ApiKey => "api_key",
            Self::PasskeyReference => "passkey_reference",
        }
    }

    pub fn parse(value: &str) -> Result<Self> {
        match value {
            "password" => Ok(Self::Password),
            "api_key" => Ok(Self::ApiKey),
            "passkey_reference" => Ok(Self::PasskeyReference),
            other => Err(PasswordManagerError::InvalidInput(format!(
                "Unsupported credential type: {}",
                other
            ))),
        }
    }

    pub fn is_retrievable_secret(self) -> bool {
        matches!(self, Self::Password | Self::ApiKey)
    }

    pub fn is_generic_password_exportable(self) -> bool {
        self.is_retrievable_secret()
    }
}

/// Single consistent view of the durable authority row (see
/// [`VaultManager::load_vault_snapshot`]).
pub(crate) struct VaultSnapshot {
    pub kdf_params: KdfParams,
    pub wrapped_dek: WrappedKey,
    pub key_epoch: i64,
    pub vault_uuid: Option<String>,
    pub digest: [u8; 32],
    /// The RAW durable blobs exactly as stored in `db_metadata` — used by
    /// the slot-registry bootstrap invariant, which must byte-compare the
    /// minted slot against the stored wrap (re-serialized structs diverge
    /// for legacy 3-field blobs; review round 1, finding 3).
    pub raw_kdf_params: Vec<u8>,
    pub raw_wrapped_dek: Vec<u8>,
    pub raw_dek_nonce: Vec<u8>,
}

/// Vault manager handles all vault operations
pub struct VaultManager {
    pub(super) key_hierarchy: KeyHierarchy,
    pub(super) db: Arc<Mutex<Database>>,
    pub(super) vault_path: PathBuf,
    pub(super) audit_logger: Option<Arc<AuditLogger>>,
    /// Epoch high-water sidecar path (ADR-004 rev 4). `None` for in-memory
    /// vaults, which have no durable state to protect.
    pub(super) epoch_sidecar: Option<PathBuf>,
    /// Stable vault identity (WBS-301). `None` only for in-memory vaults that
    /// never went through `create()`/`open()` identity provisioning.
    pub(super) vault_uuid: Option<String>,
    /// Session-cached key epoch for envelope sealing (WBS-304 adoption
    /// review, findings 7+8): the epoch is session-constant between
    /// rotation commits, and reading it from db_metadata per field would
    /// both re-lock the non-reentrant Mutex under guard-holding callers
    /// (the registry sweep deadlock) and burn a full metadata SELECT per
    /// field. Set at create/open; updated at every rotation commit point
    /// (password rotation, pair-join adoption). Envelope reads don't need
    /// it at all (relaxed-epoch takes the epoch from the authenticated
    /// document); a stale cache value on seal is self-healing — the seal
    /// simply records the older epoch, which relaxed reads accept.
    pub(super) session_epoch: std::sync::atomic::AtomicI64,
}

impl VaultManager {
    /// Create a new vault with a master password
    pub fn create<P: AsRef<Path>>(path: P, master_password: &[u8]) -> Result<Self> {
        let vault_path = path.as_ref().to_path_buf();

        // Ensure data directory exists
        ensure_data_dir()?;

        // Refuse to initialize over ANY existing non-empty database file
        // (WBS-402 / ADR-005 rev 3). The db_metadata probe below only
        // recognizes SentinelPass-shaped vaults; a legacy/foreign database
        // (no db_metadata table) or an empty-schema one (db_metadata table
        // present but zero rows) would otherwise be silently resurrected —
        // `initialize_schema` merges our tables into the foreign file with
        // IF NOT EXISTS and the probe passes. A zero-byte file is allowed:
        // there is no data to destroy and SQLite treats it as a fresh
        // database. `:memory:` is skipped explicitly: on Unix its stat
        // simply returns NotFound, but Windows rejects the reserved colon
        // with ERROR_INVALID_NAME (code 123), which is NOT NotFound — the
        // generic error arm would have refused every in-memory/dev vault
        // (found by the Windows CI run of the WBS-306/308/315 cycle). A
        // stat error on a real path is allowed through: we cannot confirm
        // a file exists there, and Database::open below surfaces any
        // genuine problem; the db_metadata probe inside the open still
        // refuses resurrection of an existing SentinelPass vault.
        if vault_path != std::path::Path::new(":memory:") {
            match std::fs::metadata(&vault_path) {
                Ok(meta) if meta.is_file() && meta.len() > 0 => {
                    return Err(PasswordManagerError::InvalidInput(format!(
                        "a database file already exists at {} ({} bytes); refusing to \
                         initialize a new vault over it — remove the file explicitly or \
                         choose a different path",
                        vault_path.display(),
                        meta.len()
                    )));
                }
                Ok(_) => {}
                Err(_) => {}
            }
        }

        // Create and initialize database
        let db = Database::open(&vault_path)?;
        db.initialize_schema()?;

        // Initialize key hierarchy
        let mut key_hierarchy = KeyHierarchy::new();
        let (kdf_params, wrapped_dek) = key_hierarchy.initialize_vault(master_password)?;

        // Durable vault identity (WBS-301 / ADR-004 rev 4)
        let vault_uuid = uuid::Uuid::new_v4().to_string();

        // Second create-guard layer (the file check above ran before the
        // database existed): refuse if a db_metadata row appeared in the
        // race window between the file check and this probe — TOCTOU (a
        // restore/copy racing init) or a direct embedder call would
        // otherwise overwrite the old vault's rollback protection and then
        // fail the INSERT — bricking the pre-existing vault
        // (adversarial-review finding).
        {
            let existing: bool = db
                .conn()
                .query_row("SELECT EXISTS(SELECT 1 FROM db_metadata)", [], |r| r.get(0))
                .map_err(DatabaseError::Sqlite)?;
            if existing {
                return Err(PasswordManagerError::InvalidInput(format!(
                    "a vault already exists at {}; refusing to initialize over it",
                    vault_path.display()
                )));
            }
        }

        // ONE transaction covers the metadata INSERT, the password-slot
        // mint, and the registry MAC (review round 1, findings 4+5): the
        // prior shape had both an uncompensated crash window between the
        // INSERT and the mint (a vault that can be neither re-created — the
        // probe refuses — nor opened — bootstrap invariant fails), and a
        // sidecar-failure compensation that deleted only the metadata row,
        // leaking the minted slot so a retried create silently MAC-blessed
        // the aborted attempt's slot as the new vault's mirror.
        {
            let conn = db.conn();
            conn.execute_batch("BEGIN IMMEDIATE;")
                .map_err(DatabaseError::Sqlite)?;

            let inner = || -> Result<()> {
                Self::store_vault_metadata(&db, &kdf_params, &wrapped_dek, &vault_uuid)?;
                let kdf_blob = bincode::serialize(&kdf_params)
                    .map_err(|e| DatabaseError::Serialization(e.to_string()))?;
                let wrapped_blob = bincode::serialize(&wrapped_dek)
                    .map_err(|e| DatabaseError::Serialization(e.to_string()))?;
                let nonce_blob = bincode::serialize(&wrapped_dek.nonce)
                    .map_err(|e| DatabaseError::Serialization(e.to_string()))?;
                Self::ensure_password_slot(conn, &kdf_blob, &wrapped_blob, &nonce_blob, 1)?;
                let slots = Self::load_key_slots(conn)?;
                Self::commit_slot_registry(&key_hierarchy, conn, &slots)
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
        }

        // Base the epoch sidecar AFTER the durable row exists, binding the
        // stored material digest: a fresh identity has no rollback history,
        // and a stale sidecar from a previous vault at this path is replaced
        // unconditionally (adversarial-review finding). Best-effort by
        // design (review round 1): the vault is already complete and
        // consistent — a sidecar write failure (read-only dir, ENOSPC)
        // must not wedge the path. The next open trust-on-first-use mints
        // the sidecar from current state with a visible warning.
        let epoch_sidecar = Self::sidecar_for(&vault_path);
        if let Some(ref sidecar_path) = epoch_sidecar {
            let rebase_result = epoch_guard::material_digest(db.conn())
                .and_then(|digest| epoch_guard::rebase(sidecar_path, &vault_uuid, 1, &digest));
            if let Err(e) = rebase_result {
                tracing::warn!(
                    "epoch sidecar write failed at vault creation: {} — the vault is \
                     complete; rollback protection anchors at the next open (TOFU)",
                    e
                );
            }
        }

        // Initialize audit logger
        let audit_logger = AuditLogger::new(get_audit_log_dir()).map(Arc::new).ok();

        let vault_manager = Self {
            key_hierarchy,
            db: Arc::new(Mutex::new(db)),
            vault_path,
            audit_logger,
            epoch_sidecar,
            vault_uuid: Some(vault_uuid),
            session_epoch: std::sync::atomic::AtomicI64::new(1),
        };

        // Log vault creation
        if let Some(ref logger) = vault_manager.audit_logger {
            let _ = logger.log(AuditEventType::VaultCreated, "Vault created successfully");
        }

        Ok(vault_manager)
    }

    /// Open an existing vault
    pub fn open<P: AsRef<Path>>(path: P, master_password: &[u8]) -> Result<Self> {
        let vault_path = path.as_ref().to_path_buf();
        let db = Database::open(&vault_path)?;
        db.validate_schema_version()?;

        if let Some(remaining) = Self::get_remaining_lockout_seconds(&db)? {
            return Err(PasswordManagerError::LockedOut(remaining));
        }

        // One consistent snapshot of the authority row: guard, unlock, and
        // any heal all consume THESE bytes (round-4 TOCTOU fix).
        let snapshot = Self::load_vault_snapshot(&db)?;
        let (kdf_params, wrapped_dek, key_epoch) = (
            snapshot.kdf_params.clone(),
            snapshot.wrapped_dek.clone(),
            snapshot.key_epoch,
        );

        // Initialize the audit logger BEFORE the epoch guard: refusals are
        // security-relevant events and must leave a durable trace even though
        // the vault never opens (adversarial-review finding).
        let early_logger = AuditLogger::new(get_audit_log_dir()).map(Arc::new).ok();

        // Epoch high-water enforcement (WBS-301 / ADR-004 rev 4): refuse a
        // vault whose on-disk epoch or key material disagrees with the
        // out-of-DB high-water record, BEFORE spending KDF time. A
        // pre-rotation vault has a non-epoch-bound wrap, so rewound state
        // would otherwise unlock silently — this guard is the only detection.
        let (epoch_sidecar, vault_uuid, epoch_check) =
            match Self::enforce_epoch_guard(&snapshot, &vault_path) {
                Ok(triple) => triple,
                Err(guard_err) => {
                    if let Some(ref logger) = early_logger {
                        let _ = logger.log(
                            AuditEventType::EpochHighWaterRebased { refused: true },
                            &format!("vault open refused by epoch guard: {guard_err}"),
                        );
                    }
                    return Err(guard_err);
                }
            };

        // Unlock vault (epoch-bound wraps verify the key_epoch as AEAD)
        let mut key_hierarchy = KeyHierarchy::new();
        if let Err(e) = key_hierarchy.unlock_vault_with_epoch(
            master_password,
            &kdf_params,
            &wrapped_dek,
            key_epoch,
        ) {
            let _ = Self::record_failed_attempt(&db);

            if let Some(remaining) = Self::get_remaining_lockout_seconds(&db)? {
                return Err(PasswordManagerError::LockedOut(remaining));
            }

            return Err(PasswordManagerError::Crypto(e));
        }

        // A pending one-step heal is adopted ONLY now: the unlock above just
        // proved the on-disk wrap under this epoch (epoch-bound wraps verify
        // the epoch as AEAD associated data), so the new state is
        // authenticated. Legacy (non-epoch-bound) wraps cannot authenticate
        // an epoch transition at all — adopting on them would re-open the
        // unauthenticated-adoption bypass — so they refuse instead.
        if let Some(epoch_guard::EpochCheck::HealPending { from, to }) = epoch_check {
            if wrapped_dek.epoch_bound {
                // The snapshot digest is the material the password just
                // authenticated — blessing anything else (a fresh re-read)
                // would re-open the TOCTOU laundering window.
                epoch_guard::adopt_heal(
                    epoch_sidecar.as_ref().unwrap(),
                    vault_uuid.as_ref().unwrap(),
                    from,
                    to,
                    &snapshot.digest,
                )?;
            } else {
                if let Some(ref logger) = early_logger {
                    let _ = logger.log(
                        AuditEventType::EpochHighWaterRebased { refused: true },
                        "legacy (non-epoch-bound) wrap cannot authenticate a pending \
                         epoch transition; refusing to adopt",
                    );
                }
                return Err(PasswordManagerError::InvalidInput(
                    "vault is one epoch ahead on legacy (non-epoch-bound) key material; \
                     rotate the master password once to re-establish authenticated \
                     epoch binding"
                        .to_string(),
                ));
            }
        }

        Self::clear_failed_attempts(&db)?;

        // Key-slot registry (WBS-302): verify fail-closed, or bootstrap
        // one-time for a pre-registry vault (migration mints the row; the
        // MAC needs the DEK, so it lands here).
        Self::ensure_or_verify_slot_registry(
            &key_hierarchy,
            &db,
            &snapshot,
            &epoch_sidecar,
            &vault_uuid,
            true, // password surface authenticated the DEK: bootstrap allowed
        )?;

        let audit_logger = early_logger;

        let vault_manager = Self {
            key_hierarchy,
            db: Arc::new(Mutex::new(db)),
            vault_path,
            audit_logger,
            epoch_sidecar,
            vault_uuid,
            session_epoch: std::sync::atomic::AtomicI64::new(key_epoch),
        };

        // Surface epoch-guard outcomes in the audit trail (ADR-004 rev 4:
        // TOFU re-basing must be visible, not silent) via the shared helper.
        if let (Some(check), Some(logger)) = (epoch_check, vault_manager.audit_logger.as_deref()) {
            Self::log_epoch_outcome(logger, &check, "vault open");
        }

        // Log vault unlock
        if let Some(ref logger) = vault_manager.audit_logger {
            let _ = logger.log(
                AuditEventType::VaultUnlocked { success: true },
                "Vault unlocked successfully",
            );
        }

        // Registry index backfill (ADR-001): repair the equality index when
        // it is incomplete (post-migration, post-restore). Bounded full
        // decrypt — runs only when the sweep bookkeeping says so, never on
        // every unlock. Best-effort: a failed backfill retries on the next
        // open or registry read.
        if vault_manager.registry_backfill_needed().unwrap_or(false) {
            if let Err(e) = vault_manager.sweep_registry_index() {
                tracing::warn!(
                    error = %e,
                    "registry index backfill failed; will retry on next open"
                );
            }
        }

        // Domain-mapping index backfill (WBS-306): seal legacy plaintext
        // mappings + write their lookup tags post-unlock (the migration is
        // pure DDL — no DEK exists at migration time). Count-triggered and
        // idempotent; a failed sweep retries on the next open. Best-effort:
        // unbackfilled rows stay findable via the legacy plaintext fallback.
        if vault_manager.domain_backfill_needed().unwrap_or(false) {
            if let Err(e) = vault_manager.sweep_domain_mappings() {
                tracing::warn!(
                    error = %e,
                    "domain-mapping index backfill failed; will retry on next open"
                );
            }
        }

        // Bulk v1→v2 blob re-encryption (WBS-404): every remaining v1 blob
        // (entry fields, SSH private keys, TOTP secrets) is re-sealed as a
        // v2 envelope bound to the row's identity. Flag-gated (a completed
        // zero-v1 pass records `v2_blob_sweep_complete`) and idempotent
        // (per-row SPENV-magic skip). Best-effort like the backfills above:
        // a failed pass retries on the next open and NEVER fails the
        // unlock — dual reads keep unconverted rows readable meanwhile.
        if vault_manager.v2_blob_sweep_needed().unwrap_or(false) {
            if let Err(e) = vault_manager.sweep_v1_blobs_to_v2() {
                tracing::warn!(
                    error = %e,
                    "v1→v2 blob sweep failed; will retry on next open"
                );
            }
        }

        Ok(vault_manager)
    }

    /// Create a new vault at the default path
    pub fn create_default(master_password: &[u8]) -> Result<Self> {
        Self::create(get_default_vault_path(), master_password)
    }

    /// Open the vault at the default path
    pub fn open_default(master_password: &[u8]) -> Result<Self> {
        Self::open(get_default_vault_path(), master_password)
    }

    /// Get the filesystem path for this vault instance.
    pub fn vault_path(&self) -> &Path {
        &self.vault_path
    }

    /// Current master-password key epoch (ADR-002). Vault metadata, not key
    /// material — readable while the vault is locked.
    pub fn key_epoch(&self) -> Result<i64> {
        let db = self.lock_db()?;
        let (_, _, key_epoch) = Self::load_vault_metadata(&db)?;
        Ok(key_epoch)
    }

    /// Stable vault identity (WBS-301 / ADR-004 rev 4).
    pub fn vault_uuid(&self) -> Option<&str> {
        self.vault_uuid.as_deref()
    }

    /// Epoch high-water sidecar path for a vault database. `None` for
    /// in-memory vaults (no durable state to protect).
    fn sidecar_for(vault_path: &Path) -> Option<PathBuf> {
        if vault_path.as_os_str() == ":memory:" {
            return None;
        }
        Some(epoch_guard::sidecar_path(vault_path))
    }

    /// Enforce the epoch high-water guard for any vault-opening path
    /// (password, biometric, DEK-retrieval). One implementation so a future
    /// open path cannot silently forget the fail-closed identity rule
    /// (adversarial-review finding).
    /// Shared epoch-guard outcome auditing so every surface (password,
    /// biometric, DEK-retrieval) logs identical semantics (round-4 finding:
    /// per-path copies had already drifted).
    pub(super) fn log_epoch_outcome(
        logger: &AuditLogger,
        check: &epoch_guard::EpochCheck,
        surface: &str,
    ) {
        let event = match check {
            epoch_guard::EpochCheck::MintedFromAbsent { epoch } => Some((
                false,
                format!("{surface}: epoch sidecar minted (TOFU) at epoch {epoch}; revocations before this point are unenforced"),
            )),
            epoch_guard::EpochCheck::HealPending { from, to } => Some((
                false,
                format!("{surface}: one-step heal {from} -> {to} pending"),
            )),
            epoch_guard::EpochCheck::Current => None,
        };
        if let Some((refused, context)) = event {
            let _ = logger.log(AuditEventType::EpochHighWaterRebased { refused }, &context);
        }
    }

    fn enforce_epoch_guard(
        snapshot: &VaultSnapshot,
        vault_path: &Path,
    ) -> Result<(
        Option<PathBuf>,
        Option<String>,
        Option<epoch_guard::EpochCheck>,
    )> {
        let key_epoch = snapshot.key_epoch;
        let vault_uuid = snapshot.vault_uuid.clone();
        let epoch_sidecar = Self::sidecar_for(vault_path);
        if epoch_sidecar.is_some() && vault_uuid.is_none() {
            return Err(PasswordManagerError::InvalidInput(
                "vault identity (vault_uuid) is missing from the database; refusing to \
                 open without epoch-rollback protection"
                    .to_string(),
            ));
        }
        match (&epoch_sidecar, &vault_uuid) {
            (Some(sidecar_path), Some(uuid)) => {
                let check = epoch_guard::check(sidecar_path, uuid, key_epoch, &snapshot.digest)?;
                Ok((epoch_sidecar, vault_uuid, Some(check)))
            }
            _ => Ok((epoch_sidecar, vault_uuid, None)),
        }
    }

    /// Read-only vault metadata inspection that requires **no master
    /// password**: `db_metadata.version`/`key_epoch` are plaintext columns,
    /// never the DEK or master key. Backs `sentinelpass status` and any
    /// embedder that needs to know a vault's rotation generation without
    /// first authenticating.
    pub fn inspect_metadata<P: AsRef<Path>>(path: P) -> Result<VaultMetadataInfo> {
        let path = path.as_ref();
        if !path.exists() {
            return Err(PasswordManagerError::NotFound(format!(
                "Vault at {}",
                path.display()
            )));
        }
        let db = Database::open(path)?;
        let (schema_version, key_epoch): (i32, i64) = db
            .conn()
            .query_row(
                "SELECT version, COALESCE(key_epoch, 1) FROM db_metadata WHERE id = 1",
                [],
                |row| Ok((row.get(0)?, row.get(1)?)),
            )
            .map_err(DatabaseError::Sqlite)?;
        Ok(VaultMetadataInfo {
            schema_version,
            key_epoch,
        })
    }

    /// Lock the vault (clear keys from memory)
    pub fn lock(&mut self) {
        self.key_hierarchy.lock_vault();

        // Log vault lock event
        if let Some(ref logger) = self.audit_logger {
            let _ = logger.log(AuditEventType::VaultLocked, "Vault locked");
        }
    }

    /// Check if vault is unlocked
    pub fn is_unlocked(&self) -> bool {
        self.key_hierarchy.is_unlocked()
    }

    /// Acquire the database lock, mapping a poison error to a structured error.
    /// The session-cached key epoch (see the `session_epoch` field docs).
    pub(super) fn session_epoch(&self) -> i64 {
        // No fallback read exists: every constructor initializes the
        // atomic (create=1; open/biometric=COALESCE(key_epoch,1) >= 1),
        // and a `key_epoch()` call here could re-lock the non-reentrant
        // Mutex under guard-holding callers. KNOWN EXCEPTION (documented,
        // accepted): `recover_access` is a static path-based operation
        // and cannot update a concurrently-live manager's cache — a
        // manager held open across an external recovery seals with the
        // pre-recovery epoch, which relaxed-epoch reads accept by design.
        self.session_epoch
            .load(std::sync::atomic::Ordering::Relaxed)
    }

    fn lock_db(&self) -> Result<std::sync::MutexGuard<'_, Database>> {
        self.db
            .lock()
            .map_err(|_| DatabaseError::LockPoisoned("db lock poisoned".to_string()).into())
    }

    /// Convert raw entry row to summary (decrypt only title and username)
    fn row_to_summary(&self, row: &RawEntryRow) -> Result<EntrySummary> {
        let cred = CredentialType::parse(&row.credential_type)?;
        let title = self
            .open_entry_field(
                row.sync_id.as_deref(),
                cred,
                crate::crypto::aad::EnvelopePurpose::Summary,
                &row.title,
            )?
            .to_string();
        let username = self
            .open_entry_field(
                row.sync_id.as_deref(),
                cred,
                crate::crypto::aad::EnvelopePurpose::Summary,
                &row.username,
            )?
            .to_string();

        Ok(EntrySummary {
            entry_id: row.entry_id,
            title,
            username,
            credential_type: cred,
            favorite: row.favorite,
        })
    }

    /// Decrypt a raw entry row from the database
    fn decrypt_entry_row(&self, row: &RawEntryRow) -> Result<Entry> {
        let cred = CredentialType::parse(&row.credential_type)?;
        let sid = row.sync_id.as_deref();
        let title = self
            .open_entry_field(
                sid,
                cred,
                crate::crypto::aad::EnvelopePurpose::Summary,
                &row.title,
            )?
            .to_string();
        let username = self
            .open_entry_field(
                sid,
                cred,
                crate::crypto::aad::EnvelopePurpose::Summary,
                &row.username,
            )?
            .to_string();
        let password = self.open_entry_field(
            sid,
            cred,
            crate::crypto::aad::EnvelopePurpose::Secret,
            &row.password,
        )?;

        let url = row
            .url
            .as_ref()
            .map(|blob| {
                self.open_entry_field(sid, cred, crate::crypto::aad::EnvelopePurpose::Secret, blob)
                    .map(|z| z.to_string())
            })
            .transpose()?;

        let notes = row
            .notes
            .as_ref()
            .map(|blob| {
                self.open_entry_field(sid, cred, crate::crypto::aad::EnvelopePurpose::Secret, blob)
                    .map(|z| z.to_string())
            })
            .transpose()?;

        Ok(Entry {
            entry_id: Some(row.entry_id),
            title,
            username,
            password,
            url,
            notes,
            credential_type: cred,
            created_at: DateTime::from_timestamp(row.created_at, 0).unwrap_or_else(Utc::now),
            modified_at: DateTime::from_timestamp(row.modified_at, 0).unwrap_or_else(Utc::now),
            favorite: row.favorite,
        })
    }

    /// Add a new entry to the vault
    pub fn add_entry(&self, entry: &Entry) -> Result<i64> {
        if !self.is_unlocked() {
            return Err(PasswordManagerError::VaultLocked);
        }

        // Stable object identity FIRST (WBS-304): the v2 envelope's AAD
        // binds it, so it must exist before sealing.
        let sync_id = uuid::Uuid::new_v4().to_string();
        let cred = entry.credential_type;

        // Seal sensitive fields as v2 envelopes bound to
        // (vault_uuid, sync_id, purpose, type, schema/crypto versions,
        // epoch). New rows are always v2 — dual-read keeps older rows on
        // the v1 path until the WBS-404 migration re-encrypts them.
        let sealed = crate::vault::envelope_ops::seal_entry_fields(
            self.key_hierarchy.dek()?,
            self.vault_uuid_str()?,
            &sync_id,
            cred,
            entry,
            self.session_epoch(),
        )?;
        let title_blob = sealed.title;
        let username_blob = sealed.username;
        let password_blob = sealed.password;
        let url_blob = sealed.url;
        let notes_blob = sealed.notes;

        // Legacy v1 columns (`entry_nonce`/`auth_tag` mirrored the TITLE
        // field's v1 nonce/tag for pre-envelope readers). v2 envelopes
        // carry their own nonce/tag inside the document — the columns are
        // zero-filled to satisfy NOT NULL and are read by nothing on v2
        // rows (deprecated; dropped by the eventual v2 schema migration).
        let (nonce_blob, auth_tag_blob) = crate::vault::envelope_ops::zeroed_legacy_v1_columns();

        let now = Utc::now().timestamp();

        // Use repository to insert the entry
        let db = self.lock_db()?;
        let repo = SqliteEntryRepository::new(&db);
        let params = NewEntryParams {
            title: title_blob,
            username: username_blob,
            password: password_blob,
            url: url_blob,
            notes: notes_blob,
            credential_type: entry.credential_type.as_str().to_string(),
            entry_nonce: nonce_blob,
            auth_tag: auth_tag_blob,
            created_at: now,
            modified_at: now,
            favorite: entry.favorite,
            sync_id: Some(sync_id),
        };

        let entry_id = repo.create(params)?;

        // Release the db lock before the registry hook: registry_on_add
        // re-acquires it, and Mutex is not reentrant (a nested lock_db()
        // here deadlocks the vault).
        drop(db);

        // Log credential creation
        if let Some(ref logger) = self.audit_logger {
            let _ = logger.log(
                AuditEventType::CredentialCreated { entry_id },
                &format!("Created credential: {}", entry.title),
            );
        }

        // Registry equality index (ADR-001). Best-effort: a failed index
        // write is repaired by the next sweep; the entry write stands.
        if let Err(e) = self.registry_on_add(entry_id, entry) {
            tracing::warn!(entry_id, error = %e, "registry index update failed");
        }

        Ok(entry_id)
    }

    /// Get an entry by ID
    pub fn get_entry(&self, entry_id: i64) -> Result<Entry> {
        if !self.is_unlocked() {
            return Err(PasswordManagerError::VaultLocked);
        }

        let db = self.lock_db()?;
        let repo = SqliteEntryRepository::new(&db);
        let raw_row = repo
            .get_raw(entry_id)?
            .ok_or_else(|| PasswordManagerError::NotFound(format!("Entry {}", entry_id)))?;

        // Drop the database lock before decrypting (decrypt doesn't need the DB)
        drop(db);

        // Decrypt FIRST, then audit with the real title. The former
        // shape (from_utf8_lossy of the raw column) was harmless when
        // columns held v1 bincode mojibake, but a v2 envelope document is
        // readable JSON — logging it would leak vault UUID, entry
        // sync_id, purpose/type, epoch, and ciphertext into the long-lived
        // plaintext audit log on every credential view (adoption review,
        // finding 4).
        let entry = match self.decrypt_entry_row(&raw_row) {
            Ok(entry) => entry,
            // A FAILED view is the security-interesting case (tamper
            // probing, corruption) — it must leave an audit trace too,
            // not just the success path (adoption review).
            Err(e) => {
                if let Some(ref logger) = self.audit_logger {
                    let _ = logger.log(
                        AuditEventType::CredentialViewed { entry_id },
                        &format!("Credential view FAILED (decrypt refused): {e}"),
                    );
                }
                return Err(e);
            }
        };

        if let Some(ref logger) = self.audit_logger {
            let _ = logger.log(
                AuditEventType::CredentialViewed { entry_id },
                &format!("Viewed credential: {}", entry.title),
            );
        }

        Ok(entry)
    }

    /// List all entries
    pub fn list_entries(&self) -> Result<Vec<EntrySummary>> {
        if !self.is_unlocked() {
            return Err(PasswordManagerError::VaultLocked);
        }

        let db = self.lock_db()?;
        let repo = SqliteEntryRepository::new(&db);
        let raw_rows = repo.list_raw(EntryFilter::default())?;

        // Drop the database lock before decrypting
        drop(db);

        // Convert raw rows to summaries
        let mut entries = raw_rows
            .iter()
            .map(|row| self.row_to_summary(row))
            .collect::<Result<Vec<_>>>()?;

        // Sort entries alphabetically by title
        entries.sort_by(|a, b| a.title.cmp(&b.title));

        // Log credentials list operation
        if let Some(ref logger) = self.audit_logger {
            let _ = logger.log(
                AuditEventType::CredentialsListed {
                    count: entries.len(),
                },
                &format!("Listed {} credentials", entries.len()),
            );
        }

        Ok(entries)
    }

    /// Find entries matching a domain via the encrypted `domain_mappings`
    /// index (WBS-306). Implemented in `domain_ops`: tag-set intersection
    /// pre-filter, sealed-domain envelope verification, and a legacy
    /// plaintext fallback for rows not yet backfilled.
    pub fn find_entries_by_domain(&self, domain: &str) -> Result<Vec<Entry>> {
        self.domain_lookup(domain)
    }

    /// List entries with pagination to prevent performance issues with large vaults.
    /// Returns entries for the specified page, along with total count and whether more results exist.
    pub fn list_entries_paginated(
        &self,
        pagination: PaginationParams,
    ) -> Result<PaginatedResult<EntrySummary>> {
        if !self.is_unlocked() {
            return Err(PasswordManagerError::VaultLocked);
        }

        let db = self.lock_db()?;
        let repo = SqliteEntryRepository::new(&db);

        // Get total count
        let total_count = repo.count()?;

        // Get paginated entries
        let filter = EntryFilter {
            limit: Some(pagination.limit()),
            offset: Some(pagination.offset()),
            favorite_only: false,
        };
        let raw_rows = repo.list_raw(filter)?;

        // Drop the database lock before decrypting
        drop(db);

        // Convert raw rows to summaries
        let items = raw_rows
            .iter()
            .map(|row| self.row_to_summary(row))
            .collect::<Result<Vec<_>>>()?;

        // Calculate if there are more results
        let has_more = (pagination.offset() as i64 + items.len() as i64) < total_count;

        // Log credentials list operation
        if let Some(ref logger) = self.audit_logger {
            let _ = logger.log(
                AuditEventType::CredentialsListed { count: items.len() },
                &format!(
                    "Listed {} credentials (page {}, total {})",
                    items.len(),
                    pagination.page,
                    total_count
                ),
            );
        }

        Ok(PaginatedResult {
            items,
            total_count,
            has_more,
        })
    }

    /// Delete an entry (soft-delete with tombstone for sync).
    pub fn delete_entry(&self, entry_id: i64) -> Result<()> {
        if !self.is_unlocked() {
            return Err(PasswordManagerError::VaultLocked);
        }

        let db = self.lock_db()?;

        let now = chrono::Utc::now().timestamp();

        let tx = db
            .conn()
            .unchecked_transaction()
            .map_err(DatabaseError::Sqlite)?;

        // Get sync_id and sync_version before soft-deleting
        let sync_info: Option<(String, i64)> = tx
            .query_row(
                "SELECT sync_id, sync_version FROM entries WHERE entry_id = ?1",
                [entry_id],
                |row| Ok((row.get(0)?, row.get(1)?)),
            )
            .ok();

        // Soft-delete: mark as deleted, bump sync_version
        let rows_affected = tx
            .execute(
                "UPDATE entries SET is_deleted = 1, deleted_at = ?1,
                 sync_version = sync_version + 1, sync_state = 'pending'
                 WHERE entry_id = ?2 AND is_deleted = 0",
                rusqlite::params![now, entry_id],
            )
            .map_err(DatabaseError::Sqlite)?;

        if rows_affected == 0 {
            return Err(PasswordManagerError::NotFound(format!(
                "Entry {}",
                entry_id
            )));
        }

        // Record tombstone for sync
        if let Some((sync_id, sync_version)) = sync_info {
            tx.execute(
                "INSERT OR IGNORE INTO sync_tombstones (sync_id, entry_type, sync_version, deleted_at, origin_device_id)
                 VALUES (?1, 'credential', ?2, ?3, '')",
                rusqlite::params![sync_id, sync_version + 1, now],
            )
            .map_err(DatabaseError::Sqlite)?;
        }

        // Delete associated domain mappings (these are inside the credential blob for sync)
        tx.execute(
            "DELETE FROM domain_mappings WHERE entry_id = ?1",
            [entry_id],
        )
        .map_err(DatabaseError::Sqlite)?;

        // Purge registry rows (ADR-001): soft delete never fires FK CASCADE,
        // so the equality index, lifecycle, and membership rows are removed
        // here, mirroring the domain_mappings cleanup above.
        Self::registry_purge_in_tx(&tx, entry_id)?;

        tx.commit().map_err(DatabaseError::Sqlite)?;

        // Log credential deletion
        if let Some(ref logger) = self.audit_logger {
            let _ = logger.log(
                AuditEventType::CredentialDeleted { entry_id },
                &format!("Deleted credential: {}", entry_id),
            );
        }

        Ok(())
    }

    /// Update an existing entry
    pub fn update_entry(&self, entry_id: i64, entry: &Entry) -> Result<()> {
        if !self.is_unlocked() {
            return Err(PasswordManagerError::VaultLocked);
        }

        // Row-level format policy (WBS-304): the row's stable sync_id is
        // required to seal v2 (it is the AAD's object identity); v1 rows —
        // anything pre-adoption, sync-backed or not — stay on the v1 write
        // path so a row is never mixed-format. Bulk v1→v2 conversion is
        // WBS-404. Format is classified across ALL five blob columns, not
        // just password: a "mixed" row (v2 columns alongside v1) is not a
        // legacy row — it is tamper (e.g. a v1 blob planted into a v2
        // row's password column to launder a downgrade through this very
        // update path) and refuses (gate review, finding 4).
        let (sync_id, row_is_v2) = {
            let db = self.lock_db()?;
            // (sync_id, password, title, username, url, notes)
            #[allow(clippy::type_complexity)]
            let row: (Option<String>, Vec<u8>, Vec<u8>, Vec<u8>, Option<Vec<u8>>, Option<Vec<u8>>) = db
                .conn()
                .query_row(
                    "SELECT sync_id, password, title, username, url, notes FROM entries WHERE entry_id = ?1",
                    rusqlite::params![entry_id],
                    |r| {
                        Ok((
                            r.get(0)?,
                            r.get(1)?,
                            r.get(2)?,
                            r.get(3)?,
                            r.get(4)?,
                            r.get(5)?,
                        ))
                    },
                )
                .map_err(DatabaseError::Sqlite)?;
            let is_v2 = |blob: &Vec<u8>| crate::vault::envelope_ops::is_envelope_blob(blob);
            let password_v2 = is_v2(&row.1);
            // Format agreement across all PRESENT blob columns. A NULL
            // optional column is format-NEUTRAL (absence is NULL — never
            // a v1 blob), so only Some columns are compared; counting
            // NULL as "v1" would flag every legitimate v2 row that has no
            // url/notes (found by the registry rotation test).
            let mismatch = |blob: Option<&Vec<u8>>| -> bool {
                match blob {
                    Some(b) => is_v2(b) != password_v2,
                    None => false,
                }
            };
            let mixed = mismatch(Some(&row.2))
                || mismatch(Some(&row.3))
                || mismatch(row.4.as_ref())
                || mismatch(row.5.as_ref());
            if mixed {
                return Err(PasswordManagerError::InvalidInput(
                    "entry row has mixed v1/v2 field formats — refusing to update; \
                     restore this entry from a verified backup"
                        .to_string(),
                ));
            }
            (row.0, password_v2)
        };

        let (
            title_blob,
            username_blob,
            password_blob,
            url_blob,
            notes_blob,
            nonce_blob,
            auth_tag_blob,
        ) = if row_is_v2 {
            let (zero_nonce, zero_tag) = crate::vault::envelope_ops::zeroed_legacy_v1_columns();
            let sid = sync_id.as_deref().ok_or_else(|| {
                PasswordManagerError::InvalidInput(
                    "v2 entry row has no sync_id — refusing update (identity cannot \
                         be established)"
                        .to_string(),
                )
            })?;
            let cred = entry.credential_type;
            let seal =
                |purpose, plaintext: &str| self.seal_entry_field(sid, cred, purpose, plaintext);
            (
                seal(crate::crypto::aad::EnvelopePurpose::Summary, &entry.title)?,
                seal(
                    crate::crypto::aad::EnvelopePurpose::Summary,
                    &entry.username,
                )?,
                seal(
                    crate::crypto::aad::EnvelopePurpose::Secret,
                    entry.password.as_str(),
                )?,
                entry
                    .url
                    .as_ref()
                    .map(|u| seal(crate::crypto::aad::EnvelopePurpose::Secret, u))
                    .transpose()?,
                entry
                    .notes
                    .as_ref()
                    .map(|n| seal(crate::crypto::aad::EnvelopePurpose::Secret, n))
                    .transpose()?,
                // Deprecated v1 columns — zero-filled on v2 rows.
                zero_nonce,
                zero_tag,
            )
        } else {
            let dek = self.key_hierarchy.dek()?;
            let title_encrypted = encrypt_string(dek, &entry.title)?;
            let username_encrypted = encrypt_string(dek, &entry.username)?;
            let password_encrypted = encrypt_string(dek, &entry.password)?;
            let url_encrypted = entry
                .url
                .as_ref()
                .map(|u| encrypt_string(dek, u))
                .transpose()?;
            let notes_encrypted = entry
                .notes
                .as_ref()
                .map(|n| encrypt_string(dek, n))
                .transpose()?;
            (
                bincode::serialize(&title_encrypted)
                    .map_err(|e| DatabaseError::Serialization(e.to_string()))?,
                bincode::serialize(&username_encrypted)
                    .map_err(|e| DatabaseError::Serialization(e.to_string()))?,
                bincode::serialize(&password_encrypted)
                    .map_err(|e| DatabaseError::Serialization(e.to_string()))?,
                url_encrypted
                    .as_ref()
                    .map(|e| {
                        bincode::serialize(e)
                            .map_err(|e| DatabaseError::Serialization(e.to_string()))
                    })
                    .transpose()?,
                notes_encrypted
                    .as_ref()
                    .map(|e| {
                        bincode::serialize(e)
                            .map_err(|e| DatabaseError::Serialization(e.to_string()))
                    })
                    .transpose()?,
                bincode::serialize(&title_encrypted.nonce)
                    .map_err(|e| DatabaseError::Serialization(e.to_string()))?,
                bincode::serialize(&title_encrypted.auth_tag)
                    .map_err(|e| DatabaseError::Serialization(e.to_string()))?,
            )
        };

        let now = Utc::now().timestamp();

        // Use repository pattern to update
        let db = self.lock_db()?;
        let repo = SqliteEntryRepository::new(&db);

        let params = UpdateEntryParams {
            title: Some(title_blob),
            username: Some(username_blob),
            password: Some(password_blob),
            url: url_blob,
            notes: notes_blob,
            credential_type: Some(entry.credential_type.as_str().to_string()),
            entry_nonce: Some(nonce_blob),
            auth_tag: Some(auth_tag_blob),
            modified_at: now,
            favorite: Some(entry.favorite),
        };

        repo.update(entry_id, params)
            .map_err(PasswordManagerError::from)?;

        // Release the db lock before the registry hook (non-reentrant Mutex
        // — see add_entry).
        drop(db);

        // Log credential modification
        if let Some(ref logger) = self.audit_logger {
            let _ = logger.log(
                AuditEventType::CredentialModified { entry_id },
                &format!("Modified credential: {}", entry.title),
            );
        }

        // Registry equality index (ADR-001): a changed tag against a prior
        // row is a password rotation — stamped in entry_lifecycle and
        // audited. Title-only edits leave the tag unchanged and stamp
        // nothing. Best-effort on failure; the sweep repairs.
        if let Err(e) = self.registry_on_update(entry_id, entry) {
            tracing::warn!(entry_id, error = %e, "registry index update failed");
        }

        Ok(())
    }

    /// Store vault metadata in database
    pub(super) fn store_vault_metadata(
        db: &Database,
        kdf_params: &KdfParams,
        wrapped_dek: &WrappedKey,
        vault_uuid: &str,
    ) -> Result<()> {
        let kdf_params_blob = bincode::serialize(kdf_params)
            .map_err(|e| DatabaseError::Serialization(e.to_string()))?;
        let wrapped_dek_blob = bincode::serialize(wrapped_dek)
            .map_err(|e| DatabaseError::Serialization(e.to_string()))?;
        let nonce_blob = bincode::serialize(&wrapped_dek.nonce)
            .map_err(|e| DatabaseError::Serialization(e.to_string()))?;

        let now = Utc::now().timestamp();

        db.conn().execute(
            "INSERT INTO db_metadata (id, version, kdf_params, wrapped_dek, dek_nonce, created_at, last_modified, vault_uuid, format_version)
             VALUES (1, ?1, ?2, ?3, ?4, ?5, ?6, ?7, 1)",
            rusqlite::params![
                CURRENT_SCHEMA_VERSION,
                &kdf_params_blob,
                &wrapped_dek_blob,
                &nonce_blob,
                now,
                now,
                vault_uuid
            ],
        ).map_err(DatabaseError::Sqlite)?;

        Ok(())
    }

    fn record_failed_attempt(db: &Database) -> Result<()> {
        let now = Utc::now().timestamp();
        db.conn()
            .execute(
                "INSERT INTO failed_attempts (attempt_time, ip_address) VALUES (?1, NULL)",
                [now],
            )
            .map_err(DatabaseError::Sqlite)?;
        Ok(())
    }

    pub(super) fn clear_failed_attempts(db: &Database) -> Result<()> {
        db.conn()
            .execute("DELETE FROM failed_attempts", [])
            .map_err(DatabaseError::Sqlite)?;
        Ok(())
    }

    fn lockout_duration_seconds(total_failed_attempts: u32) -> Option<i64> {
        if total_failed_attempts < DEFAULT_MAX_ATTEMPTS {
            return None;
        }

        // Exponential backoff, capped to avoid extreme values.
        let excess_attempts = total_failed_attempts - DEFAULT_MAX_ATTEMPTS;
        let multiplier = 2_i64.pow(excess_attempts.min(10));
        Some(60 * multiplier)
    }

    fn get_remaining_lockout_seconds(db: &Database) -> Result<Option<i64>> {
        let total_failed_attempts: u32 = db
            .conn()
            .query_row("SELECT COUNT(*) FROM failed_attempts", [], |row| row.get(0))
            .map_err(DatabaseError::Sqlite)?;

        let Some(lockout_duration_seconds) = Self::lockout_duration_seconds(total_failed_attempts)
        else {
            return Ok(None);
        };

        let last_failed_attempt: Option<i64> = db
            .conn()
            .query_row("SELECT MAX(attempt_time) FROM failed_attempts", [], |row| {
                row.get(0)
            })
            .map_err(DatabaseError::Sqlite)?;

        let Some(last_failed_attempt) = last_failed_attempt else {
            return Ok(None);
        };

        let elapsed = Utc::now().timestamp() - last_failed_attempt;
        let remaining = lockout_duration_seconds - elapsed;

        if remaining > 0 {
            Ok(Some(remaining))
        } else {
            Ok(None)
        }
    }

    /// Rotate the master password (ADR-002): re-wraps the DEK under a new
    /// master key derived from `new_password` with a fresh salt. Entry
    /// ciphertexts are untouched. The current password is proven by unwrapping
    /// the stored key material; failures count toward the brute-force lockout.
    ///
    /// Returns the new key epoch.
    pub fn change_master_password(
        &mut self,
        current_password: &[u8],
        new_password: &[u8],
    ) -> Result<i64> {
        use subtle::ConstantTimeEq;

        const MIN_LENGTH: usize = 12;
        if new_password.len() < MIN_LENGTH {
            return Err(PasswordManagerError::InvalidInput(format!(
                "New master password must be at least {MIN_LENGTH} characters"
            )));
        }
        if bool::from(new_password.ct_eq(current_password)) {
            return Err(PasswordManagerError::InvalidInput(
                "New master password must differ from the current password".to_string(),
            ));
        }

        let (kdf_params, wrapped_dek, key_epoch) = {
            let db = self.lock_db()?;
            if let Some(remaining) = Self::get_remaining_lockout_seconds(&db)? {
                return Err(PasswordManagerError::LockedOut(remaining));
            }
            Self::load_vault_metadata(&db)?
        };
        let new_epoch = key_epoch.checked_add(1).ok_or_else(|| {
            PasswordManagerError::InvalidInput("vault epoch exhausted".to_string())
        })?;
        let rotation = crate::crypto::keyring::rotate_master_password(
            &mut self.key_hierarchy,
            current_password,
            &kdf_params,
            &wrapped_dek,
            key_epoch,
            new_password,
        );

        match rotation {
            // WBS-309 ordering: the staged material is verified inside
            // `rotate_master_password`; here we COMMIT (durable UPDATE), then
            // ADOPT the new key in memory, then follow the sidecar forward.
            // A failure before the UPDATE leaves the old password fully
            // intact in memory and on disk; a failure after it cannot leave
            // in-memory state stale because adoption follows immediately.
            Ok((new_kdf_params, new_wrapped, new_master)) => {
                {
                    let db = self.lock_db()?;
                    let kdf_params_blob = bincode::serialize(&new_kdf_params)
                        .map_err(|e| DatabaseError::Serialization(e.to_string()))?;
                    let wrapped_blob = bincode::serialize(&new_wrapped)
                        .map_err(|e| DatabaseError::Serialization(e.to_string()))?;
                    let nonce_blob = bincode::serialize(&new_wrapped.nonce)
                        .map_err(|e| DatabaseError::Serialization(e.to_string()))?;
                    let now = chrono::Utc::now().timestamp();
                    // ONE transaction covers the wrap UPDATE, the password-
                    // slot mirror, and the registry-MAC recompute (WBS-302):
                    // separate autocommit statements strand new-wrap with a
                    // stale MAC on a mid-crash, which the one-step-lag heal
                    // would then adopt while the MAC check refuses forever —
                    // a legitimate-user brick (pre-derived, review angle d).
                    let tx = db
                        .conn()
                        .unchecked_transaction()
                        .map_err(DatabaseError::Sqlite)?;
                    // Verify-before-write (review round 2, finding 1): the
                    // stored registry MAC must verify BEFORE anything in
                    // this transaction mutates db_metadata's epoch — a
                    // mid-session tamper (e.g. a resurrected revoked slot)
                    // must refuse here, not be MAC-blessed by rotation's
                    // recompute. Must run before the epoch-bumping UPDATE
                    // below: `verify_slot_registry` reads the vault epoch
                    // LIVE, so verifying after the bump would compare the
                    // new epoch against the still-old stored MAC and
                    // spuriously fail every legitimate rotation.
                    if let Err(e) = Self::verify_slot_registry(&self.key_hierarchy, &tx) {
                        let _ = tx.rollback();
                        return Err(e);
                    }
                    // Optimistic concurrency: this rotation staged against
                    // `key_epoch`; if another writer already moved the epoch
                    // (concurrent CLI + UI rotation), the WHERE matches zero
                    // rows and we refuse instead of silently clobbering the
                    // committed rotation (adversarial-review finding).
                    let rows = tx.execute(
                        "UPDATE db_metadata SET kdf_params = ?1, wrapped_dek = ?2, \
                             dek_nonce = ?3, key_epoch = ?4, last_modified = ?5 \
                             WHERE id = 1 AND key_epoch = ?6",
                        rusqlite::params![
                            &kdf_params_blob,
                            &wrapped_blob,
                            &nonce_blob,
                            new_epoch,
                            now,
                            key_epoch
                        ],
                    );
                    let rows = match rows {
                        Ok(n) => n,
                        Err(e) => {
                            let _ = tx.rollback();
                            return Err(DatabaseError::Sqlite(e).into());
                        }
                    };
                    // Lost-race check BEFORE the slot sync (review finding):
                    // the loser's slot mirror must never commit over the
                    // winner's registry.
                    if rows != 1 {
                        let _ = tx.rollback();
                        if let Some(ref logger) = self.audit_logger {
                            let _ = logger.log(
                                AuditEventType::MasterPasswordChanged {
                                    success: false,
                                    from_epoch: key_epoch,
                                    to_epoch: key_epoch,
                                },
                                "rotation refused: vault changed concurrently (epoch moved)",
                            );
                        }
                        return Err(PasswordManagerError::InvalidInput(
                            "vault changed concurrently (epoch moved); rotation refused — \
                             retry with the current password"
                                .to_string(),
                        ));
                    }
                    // Mirror the committed wrap into the password slot and
                    // recompute the registry MAC in the SAME transaction:
                    // db_metadata and the registry must never disagree on
                    // disk.
                    if let Err(e) = Self::sync_password_slot_after_material_change(
                        &self.key_hierarchy,
                        &tx,
                        &kdf_params_blob,
                        &wrapped_blob,
                        &nonce_blob,
                        new_epoch,
                        false,
                    ) {
                        let _ = tx.rollback();
                        if let Some(ref logger) = self.audit_logger {
                            let _ = logger.log(
                                AuditEventType::MasterPasswordChanged {
                                    success: false,
                                    from_epoch: key_epoch,
                                    to_epoch: key_epoch,
                                },
                                "rotation commit failed while syncing the slot registry",
                            );
                        }
                        return Err(e);
                    }
                    tx.commit().map_err(DatabaseError::Sqlite)?;
                }

                // Adopt the new master key only now — after durable commit.
                self.key_hierarchy.adopt_master_key(new_master);
                // Session epoch cache follows the committed rotation
                // (envelope seals record the new epoch from here on).
                self.session_epoch
                    .store(new_epoch, std::sync::atomic::Ordering::Relaxed);

                // Durable epoch advance: follow the out-of-DB high-water mark
                // forward (WBS-301 / ADR-004 rev 4). The DB row above is the
                // authority; the sidecar self-heals at next open (Advanced
                // path) if this write fails, so a sidecar error must not
                // report a committed rotation as failed.
                if let (Some(ref sidecar), Some(ref uuid)) = (&self.epoch_sidecar, &self.vault_uuid)
                {
                    // Post-commit sidecar work is best-effort BY DESIGN: a
                    // committed rotation must never be reported as failed
                    // (the user would retry with the old password and burn
                    // lockout budget). A missed bump heals at next open via
                    // the authenticated one-step-lag path.
                    let follow = (|| -> Result<()> {
                        let db = self.lock_db()?;
                        let digest = epoch_guard::material_digest(db.conn())?;
                        epoch_guard::bump(sidecar, uuid, new_epoch, &digest)
                    })();
                    if let Err(e) = follow {
                        tracing::warn!(
                            "epoch sidecar follow failed after committed rotation: {} \
                             (self-heals at next authenticated open)",
                            e
                        );
                    }
                }
                if let Some(ref logger) = self.audit_logger {
                    let _ = logger.log(
                        AuditEventType::MasterPasswordChanged {
                            success: true,
                            from_epoch: key_epoch,
                            to_epoch: new_epoch,
                        },
                        "Master password rotated",
                    );
                }
            }
            Err(rotation_err) => {
                // Only genuine authentication failures (wrong current
                // password) feed the brute-force lockout; transient crypto
                // or DB errors must neither burn lockout budget nor
                // masquerade as a wrong password.
                let auth_failure = matches!(
                    rotation_err,
                    crate::crypto::CryptoError::AuthenticationFailed
                );
                {
                    let db = self.lock_db()?;
                    if auth_failure {
                        Self::record_failed_attempt(&db)?;
                    }
                    if let Some(ref logger) = self.audit_logger {
                        let _ = logger.log(
                            AuditEventType::MasterPasswordChanged {
                                success: false,
                                from_epoch: key_epoch,
                                to_epoch: key_epoch,
                            },
                            if auth_failure {
                                "Master password rotation failed verification"
                            } else {
                                "Master password rotation failed"
                            },
                        );
                    }
                    if auth_failure {
                        if let Some(remaining) = Self::get_remaining_lockout_seconds(&db)? {
                            return Err(PasswordManagerError::LockedOut(remaining));
                        }
                    }
                }
                if auth_failure {
                    return Err(PasswordManagerError::Crypto(
                        crate::crypto::CryptoError::AuthenticationFailed,
                    ));
                }
                return Err(PasswordManagerError::Crypto(rotation_err));
            }
        }

        Ok(key_epoch + 1)
    }

    /// Load vault metadata from database
    pub(super) fn load_vault_metadata(
        db: &crate::database::Database,
    ) -> Result<(KdfParams, WrappedKey, i64)> {
        let mut stmt = db
            .conn()
            .prepare("SELECT kdf_params, wrapped_dek, COALESCE(key_epoch, 1) FROM db_metadata WHERE id = 1")
            .map_err(DatabaseError::Sqlite)?;

        let result = stmt.query_row([], |row| {
            let kdf_params_blob: Vec<u8> = row.get(0)?;
            let wrapped_dek_blob: Vec<u8> = row.get(1)?;
            let key_epoch: i64 = row.get(2)?;
            Ok((kdf_params_blob, wrapped_dek_blob, key_epoch))
        });

        match result {
            Ok((kdf_params_blob, wrapped_dek_blob, key_epoch)) => {
                let kdf_params: KdfParams = bincode::deserialize(&kdf_params_blob)
                    .map_err(|e| DatabaseError::Serialization(e.to_string()))?;
                let wrapped_dek = WrappedKey::from_bincode_bytes(&wrapped_dek_blob)
                    .map_err(|e| DatabaseError::Serialization(e.to_string()))?;
                Ok((kdf_params, wrapped_dek, key_epoch))
            }
            Err(_) => Err(PasswordManagerError::NotFound("Vault metadata".to_string())),
        }
    }

    /// One consistent snapshot of the vault's durable authority row — a
    /// SINGLE SELECT shared by the epoch guard, the unlock, and any heal, so
    /// an interleaved writer cannot make them disagree (round-4 TOCTOU fix;
    /// also collapses the 4-5 redundant re-reads per open into one).
    ///
    /// Load the single-snapshot view (see [`VaultSnapshot`]).
    pub(super) fn load_vault_snapshot(db: &crate::database::Database) -> Result<VaultSnapshot> {
        /// Raw authority row + identity: blobs, registry MAC, vault UUID, epoch.
        type SnapshotRow = (
            Vec<u8>,
            Vec<u8>,
            Vec<u8>,
            Option<Vec<u8>>,
            Option<String>,
            i64,
        );
        let row: SnapshotRow = db
            .conn()
            .query_row(
                "SELECT kdf_params, wrapped_dek, dek_nonce, slot_registry_mac, vault_uuid,
                        COALESCE(key_epoch, 1)
                 FROM db_metadata WHERE id = 1",
                [],
                |r| {
                    Ok((
                        r.get(0)?,
                        r.get(1)?,
                        r.get(2)?,
                        r.get(3)?,
                        r.get(4)?,
                        r.get(5)?,
                    ))
                },
            )
            .map_err(DatabaseError::Sqlite)?;
        let kdf_params: KdfParams = bincode::deserialize(&row.0)
            .map_err(|e| DatabaseError::Serialization(e.to_string()))?;
        let wrapped_dek = WrappedKey::from_bincode_bytes(&row.1)
            .map_err(|e| DatabaseError::Serialization(e.to_string()))?;
        Ok(VaultSnapshot {
            kdf_params,
            wrapped_dek,
            key_epoch: row.5,
            vault_uuid: row.4,
            digest: epoch_guard::digest_of(
                &row.0,
                &row.1,
                &row.2,
                row.3.as_deref().unwrap_or(&[]),
                row.5,
            ),
            raw_kdf_params: row.0,
            raw_wrapped_dek: row.1,
            raw_dek_nonce: row.2,
        })
    }

    /// Load biometric key reference from database metadata.
    pub(super) fn load_biometric_ref(db: &crate::database::Database) -> Result<Option<String>> {
        db.conn()
            .query_row(
                "SELECT biometric_ref FROM db_metadata WHERE id = 1",
                [],
                |row| row.get(0),
            )
            .map_err(DatabaseError::Sqlite)
            .map_err(PasswordManagerError::from)
    }

    /// Update biometric key reference in database metadata.
    pub(super) fn set_biometric_ref(
        db: &crate::database::Database,
        biometric_ref: Option<&str>,
    ) -> Result<()> {
        db.conn()
            .execute(
                "UPDATE db_metadata SET biometric_ref = ?1 WHERE id = 1",
                [biometric_ref],
            )
            .map_err(DatabaseError::Sqlite)?;
        Ok(())
    }
}

/// A password entry
///
/// Debug is HAND-WRITTEN to redact the password (CLAUDE.md NEVER 1: log
/// secrets). `Zeroizing`'s own `Debug` impl is transparent — it prints the
/// INNER string — so the derived `Debug` this struct previously had would
/// emit the plaintext password on the first accidental `{:?}` (WBS-308 /
/// SR-CRYPTO-004).
#[derive(Clone, Serialize, Deserialize)]
pub struct Entry {
    pub entry_id: Option<i64>,
    pub title: String,
    pub username: String,
    pub password: Zeroizing<String>,
    pub url: Option<String>,
    pub notes: Option<String>,
    #[serde(default)]
    pub credential_type: CredentialType,
    pub created_at: DateTime<Utc>,
    pub modified_at: DateTime<Utc>,
    pub favorite: bool,
}

impl std::fmt::Debug for Entry {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Entry")
            .field("entry_id", &self.entry_id)
            .field("title", &self.title)
            .field("username", &self.username)
            .field("password", &"[REDACTED]")
            .field("url", &self.url)
            .field("notes", &self.notes)
            .field("credential_type", &self.credential_type)
            .field("created_at", &self.created_at)
            .field("modified_at", &self.modified_at)
            .field("favorite", &self.favorite)
            .finish()
    }
}

/// Read-only vault metadata (schema version, key epoch) obtainable
/// without a master password — see [`VaultManager::inspect_metadata`].
#[derive(Debug, Clone, Copy, Serialize, Deserialize)]
pub struct VaultMetadataInfo {
    pub schema_version: i32,
    pub key_epoch: i64,
}

/// Summary of an entry (without password)
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct EntrySummary {
    pub entry_id: i64,
    pub title: String,
    pub username: String,
    pub credential_type: CredentialType,
    pub favorite: bool,
}

/// Result of a paginated query
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PaginatedResult<T> {
    pub items: Vec<T>,
    pub total_count: i64,
    pub has_more: bool,
}

/// Pagination parameters
#[derive(Debug, Clone, Copy, Serialize, Deserialize)]
pub struct PaginationParams {
    pub page: u32,
    pub page_size: u32,
}

impl Default for PaginationParams {
    fn default() -> Self {
        Self {
            page: 0,
            page_size: 50,
        }
    }
}

impl PaginationParams {
    pub fn new(page: u32, page_size: u32) -> Self {
        Self { page, page_size }
    }

    pub fn offset(&self) -> u32 {
        self.page.saturating_mul(self.page_size)
    }

    pub fn limit(&self) -> u32 {
        self.page_size.min(1000) // Cap at 1000 items per page
    }
}
