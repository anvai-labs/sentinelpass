//! Vault management - coordinates crypto and database layers

mod biometric_ops;
mod health_ops;
mod registry_ops;
mod ssh_ops;
mod sync_ops;
#[cfg(test)]
mod tests;
mod totp_ops;

use crate::{
    audit::{get_audit_log_dir, AuditEventType, AuditLogger},
    crypto::cipher::{decrypt_to_string, encrypt_string},
    crypto::{EncryptedEntry, KdfParams, KeyHierarchy, WrappedKey},
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

/// Vault manager handles all vault operations
pub struct VaultManager {
    pub(super) key_hierarchy: KeyHierarchy,
    pub(super) db: Arc<Mutex<Database>>,
    pub(super) vault_path: PathBuf,
    pub(super) audit_logger: Option<Arc<AuditLogger>>,
}

impl VaultManager {
    /// Create a new vault with a master password
    pub fn create<P: AsRef<Path>>(path: P, master_password: &[u8]) -> Result<Self> {
        let vault_path = path.as_ref().to_path_buf();

        // Ensure data directory exists
        ensure_data_dir()?;

        // Create and initialize database
        let db = Database::open(&vault_path)?;
        db.initialize_schema()?;

        // Initialize key hierarchy
        let mut key_hierarchy = KeyHierarchy::new();
        let (kdf_params, wrapped_dek) = key_hierarchy.initialize_vault(master_password)?;

        // Store vault metadata
        Self::store_vault_metadata(&db, &kdf_params, &wrapped_dek)?;

        // Initialize audit logger
        let audit_logger = AuditLogger::new(get_audit_log_dir()).map(Arc::new).ok();

        let vault_manager = Self {
            key_hierarchy,
            db: Arc::new(Mutex::new(db)),
            vault_path,
            audit_logger,
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

        // Load vault metadata
        let (kdf_params, wrapped_dek, key_epoch) = Self::load_vault_metadata(&db)?;

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

        Self::clear_failed_attempts(&db)?;

        // Initialize audit logger
        let audit_logger = AuditLogger::new(get_audit_log_dir()).map(Arc::new).ok();

        let vault_manager = Self {
            key_hierarchy,
            db: Arc::new(Mutex::new(db)),
            vault_path,
            audit_logger,
        };

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
    fn lock_db(&self) -> Result<std::sync::MutexGuard<'_, Database>> {
        self.db
            .lock()
            .map_err(|_| DatabaseError::LockPoisoned("db lock poisoned".to_string()).into())
    }

    /// Convert raw entry row to summary (decrypt only title and username)
    fn row_to_summary(&self, row: &RawEntryRow) -> Result<EntrySummary> {
        let dek = self.key_hierarchy.dek()?;

        let title_encrypted: EncryptedEntry = bincode::deserialize(&row.title)
            .map_err(|e| PasswordManagerError::from(DatabaseError::Serialization(e.to_string())))?;
        let username_encrypted: EncryptedEntry = bincode::deserialize(&row.username)
            .map_err(|e| PasswordManagerError::from(DatabaseError::Serialization(e.to_string())))?;

        let title = decrypt_to_string(dek, &title_encrypted).map_err(PasswordManagerError::from)?;
        let username =
            decrypt_to_string(dek, &username_encrypted).map_err(PasswordManagerError::from)?;

        Ok(EntrySummary {
            entry_id: row.entry_id,
            title,
            username,
            credential_type: CredentialType::parse(&row.credential_type)?,
            favorite: row.favorite,
        })
    }

    /// Decrypt a raw entry row from the database
    fn decrypt_entry_row(&self, row: &RawEntryRow) -> Result<Entry> {
        let dek = self.key_hierarchy.dek()?;

        // Deserialize encrypted entries
        let title_encrypted: EncryptedEntry = bincode::deserialize(&row.title)
            .map_err(|e| PasswordManagerError::from(DatabaseError::Serialization(e.to_string())))?;
        let username_encrypted: EncryptedEntry = bincode::deserialize(&row.username)
            .map_err(|e| PasswordManagerError::from(DatabaseError::Serialization(e.to_string())))?;
        let password_encrypted: EncryptedEntry = bincode::deserialize(&row.password)
            .map_err(|e| PasswordManagerError::from(DatabaseError::Serialization(e.to_string())))?;

        let url = row
            .url
            .as_ref()
            .map(|blob| {
                let encrypted: EncryptedEntry = bincode::deserialize(blob).map_err(|e| {
                    PasswordManagerError::from(DatabaseError::Serialization(e.to_string()))
                })?;
                decrypt_to_string(dek, &encrypted).map_err(PasswordManagerError::from)
            })
            .transpose()?;

        let notes = row
            .notes
            .as_ref()
            .map(|blob| {
                let encrypted: EncryptedEntry = bincode::deserialize(blob).map_err(|e| {
                    PasswordManagerError::from(DatabaseError::Serialization(e.to_string()))
                })?;
                decrypt_to_string(dek, &encrypted).map_err(PasswordManagerError::from)
            })
            .transpose()?;

        Ok(Entry {
            entry_id: Some(row.entry_id),
            title: decrypt_to_string(dek, &title_encrypted).map_err(PasswordManagerError::from)?,
            username: decrypt_to_string(dek, &username_encrypted)
                .map_err(PasswordManagerError::from)?,
            password: decrypt_to_string(dek, &password_encrypted)
                .map_err(PasswordManagerError::from)?
                .into(),
            url,
            notes,
            credential_type: CredentialType::parse(&row.credential_type)?,
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

        let dek = self.key_hierarchy.dek()?;

        // Encrypt sensitive fields
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

        // Serialize encrypted entries
        let title_blob = bincode::serialize(&title_encrypted)
            .map_err(|e| DatabaseError::Serialization(e.to_string()))?;
        let username_blob = bincode::serialize(&username_encrypted)
            .map_err(|e| DatabaseError::Serialization(e.to_string()))?;
        let password_blob = bincode::serialize(&password_encrypted)
            .map_err(|e| DatabaseError::Serialization(e.to_string()))?;
        let url_blob = url_encrypted
            .as_ref()
            .map(|e| bincode::serialize(e).map_err(|e| DatabaseError::Serialization(e.to_string())))
            .transpose()?;
        let notes_blob = notes_encrypted
            .as_ref()
            .map(|e| bincode::serialize(e).map_err(|e| DatabaseError::Serialization(e.to_string())))
            .transpose()?;

        let nonce_blob = bincode::serialize(&title_encrypted.nonce)
            .map_err(|e| DatabaseError::Serialization(e.to_string()))?;
        let auth_tag_blob = bincode::serialize(&title_encrypted.auth_tag)
            .map_err(|e| DatabaseError::Serialization(e.to_string()))?;

        let now = Utc::now().timestamp();
        let sync_id = uuid::Uuid::new_v4().to_string();

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

        // Log credential viewing
        let title_hint = String::from_utf8_lossy(&raw_row.title).to_string();
        if let Some(ref logger) = self.audit_logger {
            let _ = logger.log(
                AuditEventType::CredentialViewed { entry_id },
                &format!("Viewed credential: {}", title_hint),
            );
        }

        self.decrypt_entry_row(&raw_row)
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

    /// Find entries matching a domain via the `domain_mappings` index.
    ///
    /// Returns only entries that have a domain mapping for the given domain.
    /// Falls back to an empty list when no mappings exist (callers should
    /// fall back to a full scan when domain_mappings are not yet populated).
    pub fn find_entries_by_domain(&self, domain: &str) -> Result<Vec<Entry>> {
        if !self.is_unlocked() {
            return Err(PasswordManagerError::VaultLocked);
        }

        let db = self.lock_db()?;
        let repo = SqliteEntryRepository::new(&db);
        let raw_rows = repo.find_by_domain(domain)?;

        drop(db);

        raw_rows
            .iter()
            .map(|row| self.decrypt_entry_row(row))
            .collect::<Result<Vec<_>>>()
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

        let dek = self.key_hierarchy.dek()?;

        // Encrypt the entry data
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

        // Serialize encrypted entries
        let title_blob = bincode::serialize(&title_encrypted)
            .map_err(|e| DatabaseError::Serialization(e.to_string()))?;
        let username_blob = bincode::serialize(&username_encrypted)
            .map_err(|e| DatabaseError::Serialization(e.to_string()))?;
        let password_blob = bincode::serialize(&password_encrypted)
            .map_err(|e| DatabaseError::Serialization(e.to_string()))?;
        let url_blob = url_encrypted
            .as_ref()
            .map(|e| bincode::serialize(e).map_err(|e| DatabaseError::Serialization(e.to_string())))
            .transpose()?;
        let notes_blob = notes_encrypted
            .as_ref()
            .map(|e| bincode::serialize(e).map_err(|e| DatabaseError::Serialization(e.to_string())))
            .transpose()?;

        let nonce_blob = bincode::serialize(&title_encrypted.nonce)
            .map_err(|e| DatabaseError::Serialization(e.to_string()))?;
        let auth_tag_blob = bincode::serialize(&title_encrypted.auth_tag)
            .map_err(|e| DatabaseError::Serialization(e.to_string()))?;

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
    ) -> Result<()> {
        let kdf_params_blob = bincode::serialize(kdf_params)
            .map_err(|e| DatabaseError::Serialization(e.to_string()))?;
        let wrapped_dek_blob = bincode::serialize(wrapped_dek)
            .map_err(|e| DatabaseError::Serialization(e.to_string()))?;
        let nonce_blob = bincode::serialize(&wrapped_dek.nonce)
            .map_err(|e| DatabaseError::Serialization(e.to_string()))?;

        let now = Utc::now().timestamp();

        db.conn().execute(
            "INSERT INTO db_metadata (id, version, kdf_params, wrapped_dek, dek_nonce, created_at, last_modified)
             VALUES (1, ?1, ?2, ?3, ?4, ?5, ?6)",
            (CURRENT_SCHEMA_VERSION, &kdf_params_blob, &wrapped_dek_blob, &nonce_blob, now, now),
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
        let new_epoch = key_epoch + 1;
        let rotation = crate::crypto::keyring::rotate_master_password(
            &mut self.key_hierarchy,
            current_password,
            &kdf_params,
            &wrapped_dek,
            key_epoch,
            new_password,
        );

        match rotation {
            Ok((new_kdf_params, new_wrapped)) => {
                let db = self.lock_db()?;
                let kdf_params_blob = bincode::serialize(&new_kdf_params)
                    .map_err(|e| DatabaseError::Serialization(e.to_string()))?;
                let wrapped_blob = bincode::serialize(&new_wrapped)
                    .map_err(|e| DatabaseError::Serialization(e.to_string()))?;
                let nonce_blob = bincode::serialize(&new_wrapped.nonce)
                    .map_err(|e| DatabaseError::Serialization(e.to_string()))?;
                let now = chrono::Utc::now().timestamp();
                db.conn()
                    .execute(
                        "UPDATE db_metadata SET kdf_params = ?1, wrapped_dek = ?2, \
                         dek_nonce = ?3, key_epoch = ?4, last_modified = ?5 WHERE id = 1",
                        rusqlite::params![
                            &kdf_params_blob,
                            &wrapped_blob,
                            &nonce_blob,
                            new_epoch,
                            now
                        ],
                    )
                    .map_err(DatabaseError::Sqlite)?;
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
#[derive(Debug, Clone, Serialize, Deserialize)]
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
