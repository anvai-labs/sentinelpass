//! Vault management - coordinates crypto and database layers

mod biometric_ops;
mod health_ops;
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
        let (kdf_params, wrapped_dek) = Self::load_vault_metadata(&db)?;

        // Unlock vault
        let mut key_hierarchy = KeyHierarchy::new();
        if let Err(e) = key_hierarchy.unlock_vault(master_password, &kdf_params, &wrapped_dek) {
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

        // Log credential creation
        if let Some(ref logger) = self.audit_logger {
            let _ = logger.log(
                AuditEventType::CredentialCreated { entry_id },
                &format!("Created credential: {}", entry.title),
            );
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

        // Log credential modification
        if let Some(ref logger) = self.audit_logger {
            let _ = logger.log(
                AuditEventType::CredentialModified { entry_id },
                &format!("Modified credential: {}", entry.title),
            );
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

    /// Load vault metadata from database
    pub(super) fn load_vault_metadata(
        db: &crate::database::Database,
    ) -> Result<(KdfParams, WrappedKey)> {
        let mut stmt = db
            .conn()
            .prepare("SELECT kdf_params, wrapped_dek FROM db_metadata WHERE id = 1")
            .map_err(DatabaseError::Sqlite)?;

        let result = stmt.query_row([], |row| {
            let kdf_params_blob: Vec<u8> = row.get(0)?;
            let wrapped_dek_blob: Vec<u8> = row.get(1)?;
            Ok((kdf_params_blob, wrapped_dek_blob))
        });

        match result {
            Ok((kdf_params_blob, wrapped_dek_blob)) => {
                let kdf_params: KdfParams = bincode::deserialize(&kdf_params_blob)
                    .map_err(|e| DatabaseError::Serialization(e.to_string()))?;
                let wrapped_dek: WrappedKey = bincode::deserialize(&wrapped_dek_blob)
                    .map_err(|e| DatabaseError::Serialization(e.to_string()))?;
                Ok((kdf_params, wrapped_dek))
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
