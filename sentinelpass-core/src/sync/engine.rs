//! Sync engine: orchestrates push/pull/resolve/apply cycle.

use crate::crypto::cipher::DataEncryptionKey;
use crate::database::Database;
use crate::sync::change_tracker::{
    collect_pending_credential_blobs, collect_pending_ssh_key_blobs, collect_pending_totp_blobs,
    count_pending_changes, mark_entries_synced,
};
use crate::sync::client::SyncClient;
use crate::sync::config::SyncConfig;
use crate::sync::conflict::{ConflictResolver, Resolution};
use crate::sync::crypto::decrypt_from_sync;
use crate::sync::models::{
    CredentialPayload, PullRequest, PushRequest, SshKeyPayload, SyncEntryBlob, SyncEntryType,
    SyncStatus, TotpPayload,
};
use crate::{DatabaseError, PasswordManagerError, Result};
use std::sync::{Arc, Mutex};
use uuid::Uuid;

/// Orchestrates the full sync lifecycle: push local changes, pull remote changes, resolve conflicts.
pub struct SyncEngine {
    client: SyncClient,
    db: Arc<Mutex<Database>>,
    device_id: Uuid,
}

impl SyncEngine {
    /// Create a new sync engine with the given client, database, and device identity.
    pub fn new(client: SyncClient, db: Arc<Mutex<Database>>, device_id: Uuid) -> Self {
        Self {
            client,
            db,
            device_id,
        }
    }

    /// Perform a full sync cycle: push local changes, then pull remote changes.
    pub async fn sync(&self, dek: &DataEncryptionKey) -> Result<SyncStatus> {
        // 1. Collect and push pending changes
        let _push_count = self.push_changes(dek).await?;

        // 2. Pull and apply remote changes
        let _pull_count = self.pull_changes(dek).await?;

        // 3. Update sync metadata
        let db = self
            .db
            .lock()
            .map_err(|_| DatabaseError::LockPoisoned("sync engine".to_string()))?;
        let mut config = SyncConfig::load(db.conn())?;
        config.last_sync_at = Some(chrono::Utc::now().timestamp());
        config.save(db.conn())?;

        let pending = count_pending_changes(db.conn())?;

        Ok(SyncStatus {
            enabled: config.sync_enabled,
            device_id: config.device_id,
            device_name: config.device_name.clone(),
            relay_url: config.relay_url.clone(),
            last_sync_at: config.last_sync_at,
            pending_changes: pending,
        })
    }

    /// Push all pending local changes to the relay.
    async fn push_changes(&self, dek: &DataEncryptionKey) -> Result<u64> {
        let blobs = {
            let db = self
                .db
                .lock()
                .map_err(|_| DatabaseError::LockPoisoned("push".to_string()))?;
            let conn = db.conn();

            let mut all_blobs = collect_pending_credential_blobs(conn, dek, self.device_id)?;
            all_blobs.extend(collect_pending_ssh_key_blobs(conn, dek, self.device_id)?);
            all_blobs.extend(collect_pending_totp_blobs(conn, dek, self.device_id)?);
            all_blobs
        };

        if blobs.is_empty() {
            return Ok(0);
        }

        let sync_ids: Vec<Uuid> = blobs.iter().map(|b| b.sync_id).collect();
        let count = blobs.len() as u64;

        let config = {
            let db = self
                .db
                .lock()
                .map_err(|_| DatabaseError::LockPoisoned("push seq".to_string()))?;
            SyncConfig::load(db.conn())?
        };

        let request = PushRequest {
            device_sequence: config.last_push_sequence + 1,
            entries: blobs,
        };

        let response = self.client.push(&request).await?;

        // Mark synced
        let db = self
            .db
            .lock()
            .map_err(|_| DatabaseError::LockPoisoned("mark synced".to_string()))?;
        mark_entries_synced(db.conn(), &sync_ids)?;

        let mut config = SyncConfig::load(db.conn())?;
        config.last_push_sequence = response.server_sequence;
        config.save(db.conn())?;

        Ok(count)
    }

    /// Pull remote changes from the relay and apply them locally.
    async fn pull_changes(&self, dek: &DataEncryptionKey) -> Result<u64> {
        let mut cursor = {
            let db = self
                .db
                .lock()
                .map_err(|_| DatabaseError::LockPoisoned("pull seq".to_string()))?;
            let config = SyncConfig::load(db.conn())?;
            config.last_pull_sequence
        };

        let mut total_count = 0u64;

        loop {
            let request = PullRequest {
                since_sequence: cursor,
                limit: Some(1000),
            };

            let response = self.client.pull(&request).await?;

            if response.entries.is_empty() {
                break;
            }

            total_count += response.entries.len() as u64;

            let db = self
                .db
                .lock()
                .map_err(|_| DatabaseError::LockPoisoned("apply pull".to_string()))?;

            for blob in &response.entries {
                // Skip our own changes
                if blob.origin_device_id == self.device_id {
                    continue;
                }
                self.apply_remote_entry(db.conn(), dek, blob)?;
            }

            if response.server_sequence <= cursor {
                return Err(PasswordManagerError::InvalidInput(
                    "Relay pull cursor did not advance".to_string(),
                ));
            }

            cursor = response.server_sequence;

            let mut config = SyncConfig::load(db.conn())?;
            config.last_pull_sequence = cursor;
            config.save(db.conn())?;

            if !response.has_more {
                break;
            }
        }

        Ok(total_count)
    }

    /// Apply a single remote entry to the local database.
    fn apply_remote_entry(
        &self,
        conn: &rusqlite::Connection,
        dek: &DataEncryptionKey,
        blob: &SyncEntryBlob,
    ) -> Result<()> {
        match blob.entry_type {
            SyncEntryType::Credential => self.apply_credential(conn, dek, blob),
            SyncEntryType::SshKey => self.apply_ssh_key(conn, dek, blob),
            SyncEntryType::TotpSecret => self.apply_totp(conn, dek, blob),
        }
    }

    fn apply_credential(
        &self,
        conn: &rusqlite::Connection,
        dek: &DataEncryptionKey,
        blob: &SyncEntryBlob,
    ) -> Result<()> {
        let sync_id_str = blob.sync_id.to_string();

        // Check if we have this entry locally
        let local: Option<(i64, i64, i64)> = conn
            .query_row(
                "SELECT entry_id, sync_version, modified_at FROM entries WHERE sync_id = ?1",
                [&sync_id_str],
                |row| Ok((row.get(0)?, row.get(1)?, row.get(2)?)),
            )
            .ok();

        if let Some((entry_id, local_version, local_modified)) = local {
            // Existing entry: resolve conflict
            let resolution = ConflictResolver::resolve(local_version as u64, local_modified, blob);

            if resolution == Resolution::KeepLocal {
                return Ok(());
            }

            if blob.is_tombstone {
                // Soft-delete locally
                conn.execute(
                    "UPDATE entries SET is_deleted = 1, deleted_at = ?1,
                     sync_version = ?2, sync_state = 'synced', last_synced_at = ?1
                     WHERE entry_id = ?3",
                    rusqlite::params![
                        chrono::Utc::now().timestamp(),
                        blob.sync_version as i64,
                        entry_id,
                    ],
                )
                .map_err(DatabaseError::Sqlite)?;
                return Ok(());
            }

            // Decrypt and apply the remote payload
            let payload_json = decrypt_from_sync(dek, &blob.encrypted_payload)
                .map_err(PasswordManagerError::Crypto)?;
            let payload: CredentialPayload = serde_json::from_slice(&payload_json)
                .map_err(|e| DatabaseError::Serialization(e.to_string()))?;

            // Re-encrypt fields for local storage
            let title_enc = crate::encrypt_string(dek, &payload.title)?;
            let username_enc = crate::encrypt_string(dek, &payload.username)?;
            let password_enc = crate::encrypt_string(dek, &payload.password)?;
            let url_enc = payload
                .url
                .as_ref()
                .map(|u| crate::encrypt_string(dek, u))
                .transpose()?;
            let notes_enc = payload
                .notes
                .as_ref()
                .map(|n| crate::encrypt_string(dek, n))
                .transpose()?;

            let title_blob = bincode::serialize(&title_enc)
                .map_err(|e| DatabaseError::Serialization(e.to_string()))?;
            let username_blob = bincode::serialize(&username_enc)
                .map_err(|e| DatabaseError::Serialization(e.to_string()))?;
            let password_blob = bincode::serialize(&password_enc)
                .map_err(|e| DatabaseError::Serialization(e.to_string()))?;
            let url_blob = url_enc
                .as_ref()
                .map(|e| {
                    bincode::serialize(e).map_err(|e| DatabaseError::Serialization(e.to_string()))
                })
                .transpose()?;
            let notes_blob = notes_enc
                .as_ref()
                .map(|e| {
                    bincode::serialize(e).map_err(|e| DatabaseError::Serialization(e.to_string()))
                })
                .transpose()?;
            let nonce_blob = bincode::serialize(&title_enc.nonce)
                .map_err(|e| DatabaseError::Serialization(e.to_string()))?;
            let auth_tag_blob = bincode::serialize(&title_enc.auth_tag)
                .map_err(|e| DatabaseError::Serialization(e.to_string()))?;

            let now = chrono::Utc::now().timestamp();

            conn.execute(
                "UPDATE entries SET
                    title = ?1, username = ?2, password = ?3, url = ?4, notes = ?5,
                    credential_type = ?6, entry_nonce = ?7, auth_tag = ?8,
                    modified_at = ?9, favorite = ?10, sync_version = ?11,
                    sync_state = 'synced', last_synced_at = ?12
                 WHERE entry_id = ?13",
                rusqlite::params![
                    title_blob,
                    username_blob,
                    password_blob,
                    url_blob.as_deref().unwrap_or(&[]),
                    notes_blob.as_deref().unwrap_or(&[]),
                    payload.credential_type.as_str(),
                    nonce_blob,
                    auth_tag_blob,
                    payload.modified_at,
                    payload.favorite as i32,
                    blob.sync_version as i64,
                    now,
                    entry_id,
                ],
            )
            .map_err(DatabaseError::Sqlite)?;

            // Update domain mappings
            conn.execute(
                "DELETE FROM domain_mappings WHERE entry_id = ?1",
                [entry_id],
            )
            .map_err(DatabaseError::Sqlite)?;
            for dm in &payload.domains {
                conn.execute(
                    "INSERT INTO domain_mappings (entry_id, domain, is_primary) VALUES (?1, ?2, ?3)",
                    rusqlite::params![entry_id, dm.domain, dm.is_primary],
                )
                .map_err(DatabaseError::Sqlite)?;
            }
        } else {
            // New entry
            if blob.is_tombstone {
                return Ok(()); // Nothing to delete
            }

            if !ConflictResolver::accept_new(blob) {
                return Ok(());
            }

            let payload_json = decrypt_from_sync(dek, &blob.encrypted_payload)
                .map_err(PasswordManagerError::Crypto)?;
            let payload: CredentialPayload = serde_json::from_slice(&payload_json)
                .map_err(|e| DatabaseError::Serialization(e.to_string()))?;

            let title_enc = crate::encrypt_string(dek, &payload.title)?;
            let username_enc = crate::encrypt_string(dek, &payload.username)?;
            let password_enc = crate::encrypt_string(dek, &payload.password)?;
            let url_enc = payload
                .url
                .as_ref()
                .map(|u| crate::encrypt_string(dek, u))
                .transpose()?;
            let notes_enc = payload
                .notes
                .as_ref()
                .map(|n| crate::encrypt_string(dek, n))
                .transpose()?;

            let title_blob = bincode::serialize(&title_enc)
                .map_err(|e| DatabaseError::Serialization(e.to_string()))?;
            let username_blob = bincode::serialize(&username_enc)
                .map_err(|e| DatabaseError::Serialization(e.to_string()))?;
            let password_blob = bincode::serialize(&password_enc)
                .map_err(|e| DatabaseError::Serialization(e.to_string()))?;
            let url_blob = url_enc
                .as_ref()
                .map(|e| {
                    bincode::serialize(e).map_err(|e| DatabaseError::Serialization(e.to_string()))
                })
                .transpose()?;
            let notes_blob = notes_enc
                .as_ref()
                .map(|e| {
                    bincode::serialize(e).map_err(|e| DatabaseError::Serialization(e.to_string()))
                })
                .transpose()?;
            let nonce_blob = bincode::serialize(&title_enc.nonce)
                .map_err(|e| DatabaseError::Serialization(e.to_string()))?;
            let auth_tag_blob = bincode::serialize(&title_enc.auth_tag)
                .map_err(|e| DatabaseError::Serialization(e.to_string()))?;

            let now = chrono::Utc::now().timestamp();

            conn.execute(
                "INSERT INTO entries (
                    vault_id, title, username, password, url, notes, credential_type,
                    entry_nonce, auth_tag, created_at, modified_at, favorite,
                    sync_id, sync_version, sync_state, last_synced_at, is_deleted
                ) VALUES (1, ?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9, ?10, ?11, ?12, ?13, 'synced', ?14, 0)",
                rusqlite::params![
                    title_blob,
                    username_blob,
                    password_blob,
                    url_blob.as_deref().unwrap_or(&[]),
                    notes_blob.as_deref().unwrap_or(&[]),
                    payload.credential_type.as_str(),
                    nonce_blob,
                    auth_tag_blob,
                    payload.created_at,
                    payload.modified_at,
                    payload.favorite as i32,
                    sync_id_str,
                    blob.sync_version as i64,
                    now,
                ],
            )
            .map_err(DatabaseError::Sqlite)?;

            let entry_id = conn.last_insert_rowid();
            for dm in &payload.domains {
                conn.execute(
                    "INSERT INTO domain_mappings (entry_id, domain, is_primary) VALUES (?1, ?2, ?3)",
                    rusqlite::params![entry_id, dm.domain, dm.is_primary],
                )
                .map_err(DatabaseError::Sqlite)?;
            }
        }

        Ok(())
    }

    fn apply_ssh_key(
        &self,
        conn: &rusqlite::Connection,
        dek: &DataEncryptionKey,
        blob: &SyncEntryBlob,
    ) -> Result<()> {
        let sync_id_str = blob.sync_id.to_string();

        let local: Option<(i64, i64, i64)> = conn
            .query_row(
                "SELECT key_id, sync_version, modified_at FROM ssh_keys WHERE sync_id = ?1",
                [&sync_id_str],
                |row| Ok((row.get(0)?, row.get(1)?, row.get(2)?)),
            )
            .ok();

        if let Some((key_id, local_version, local_modified)) = local {
            let resolution = ConflictResolver::resolve(local_version as u64, local_modified, blob);
            if resolution == Resolution::KeepLocal {
                return Ok(());
            }

            if blob.is_tombstone {
                conn.execute(
                    "UPDATE ssh_keys SET is_deleted = 1, deleted_at = ?1,
                     sync_version = ?2, sync_state = 'synced', last_synced_at = ?1
                     WHERE key_id = ?3",
                    rusqlite::params![
                        chrono::Utc::now().timestamp(),
                        blob.sync_version as i64,
                        key_id
                    ],
                )
                .map_err(DatabaseError::Sqlite)?;
                return Ok(());
            }

            let payload_json = decrypt_from_sync(dek, &blob.encrypted_payload)
                .map_err(PasswordManagerError::Crypto)?;
            let payload: SshKeyPayload = serde_json::from_slice(&payload_json)
                .map_err(|e| DatabaseError::Serialization(e.to_string()))?;

            let now = chrono::Utc::now().timestamp();
            conn.execute(
                "UPDATE ssh_keys SET
                    name = ?1, comment = ?2, key_type = ?3, key_size = ?4,
                    public_key = ?5, private_key_encrypted = ?6, nonce = ?7, auth_tag = ?8,
                    fingerprint = ?9, modified_at = ?10,
                    sync_version = ?11, sync_state = 'synced', last_synced_at = ?12
                 WHERE key_id = ?13",
                rusqlite::params![
                    payload.name,
                    payload.comment,
                    payload.key_type,
                    payload.key_size,
                    payload.public_key,
                    payload.private_key_encrypted,
                    payload.nonce,
                    payload.auth_tag,
                    payload.fingerprint,
                    payload.modified_at,
                    blob.sync_version as i64,
                    now,
                    key_id,
                ],
            )
            .map_err(DatabaseError::Sqlite)?;
        } else {
            if blob.is_tombstone {
                return Ok(());
            }
            if !ConflictResolver::accept_new(blob) {
                return Ok(());
            }

            let payload_json = decrypt_from_sync(dek, &blob.encrypted_payload)
                .map_err(PasswordManagerError::Crypto)?;
            let payload: SshKeyPayload = serde_json::from_slice(&payload_json)
                .map_err(|e| DatabaseError::Serialization(e.to_string()))?;

            let now = chrono::Utc::now().timestamp();
            conn.execute(
                "INSERT INTO ssh_keys (
                    name, comment, key_type, key_size, public_key,
                    private_key_encrypted, nonce, auth_tag, fingerprint,
                    created_at, modified_at,
                    sync_id, sync_version, sync_state, last_synced_at, is_deleted
                ) VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9, ?10, ?11, ?12, ?13, 'synced', ?14, 0)",
                rusqlite::params![
                    payload.name,
                    payload.comment,
                    payload.key_type,
                    payload.key_size,
                    payload.public_key,
                    payload.private_key_encrypted,
                    payload.nonce,
                    payload.auth_tag,
                    payload.fingerprint,
                    payload.created_at,
                    payload.modified_at,
                    sync_id_str,
                    blob.sync_version as i64,
                    now,
                ],
            )
            .map_err(DatabaseError::Sqlite)?;
        }

        Ok(())
    }

    fn apply_totp(
        &self,
        conn: &rusqlite::Connection,
        dek: &DataEncryptionKey,
        blob: &SyncEntryBlob,
    ) -> Result<()> {
        let sync_id_str = blob.sync_id.to_string();

        let local: Option<(i64, i64, i64)> = conn
            .query_row(
                "SELECT totp_id, sync_version, created_at FROM totp_secrets WHERE sync_id = ?1",
                [&sync_id_str],
                |row| Ok((row.get(0)?, row.get(1)?, row.get(2)?)),
            )
            .ok();

        if let Some((totp_id, local_version, local_created)) = local {
            let resolution = ConflictResolver::resolve(local_version as u64, local_created, blob);
            if resolution == Resolution::KeepLocal {
                return Ok(());
            }

            if blob.is_tombstone {
                conn.execute(
                    "UPDATE totp_secrets SET is_deleted = 1, deleted_at = ?1,
                     sync_version = ?2, sync_state = 'synced', last_synced_at = ?1
                     WHERE totp_id = ?3",
                    rusqlite::params![
                        chrono::Utc::now().timestamp(),
                        blob.sync_version as i64,
                        totp_id
                    ],
                )
                .map_err(DatabaseError::Sqlite)?;
                return Ok(());
            }

            let payload_json = decrypt_from_sync(dek, &blob.encrypted_payload)
                .map_err(PasswordManagerError::Crypto)?;
            let payload: TotpPayload = serde_json::from_slice(&payload_json)
                .map_err(|e| DatabaseError::Serialization(e.to_string()))?;

            // Re-link entry_id from parent_credential_sync_id
            let entry_id = payload.parent_credential_sync_id.and_then(|pid| {
                conn.query_row(
                    "SELECT entry_id FROM entries WHERE sync_id = ?1",
                    [pid.to_string()],
                    |row| row.get::<_, i64>(0),
                )
                .ok()
            });

            let now = chrono::Utc::now().timestamp();
            if let Some(eid) = entry_id {
                conn.execute(
                    "UPDATE totp_secrets SET
                        entry_id = ?1, secret_encrypted = ?2, nonce = ?3, auth_tag = ?4,
                        algorithm = ?5, digits = ?6, period = ?7, issuer = ?8, account_name = ?9,
                        sync_version = ?10, sync_state = 'synced', last_synced_at = ?11
                     WHERE totp_id = ?12",
                    rusqlite::params![
                        eid,
                        payload.secret_encrypted,
                        payload.nonce,
                        payload.auth_tag,
                        payload.algorithm,
                        payload.digits as i32,
                        payload.period as i32,
                        payload.issuer,
                        payload.account_name,
                        blob.sync_version as i64,
                        now,
                        totp_id,
                    ],
                )
                .map_err(DatabaseError::Sqlite)?;
            }
        } else {
            if blob.is_tombstone {
                return Ok(());
            }
            if !ConflictResolver::accept_new(blob) {
                return Ok(());
            }

            let payload_json = decrypt_from_sync(dek, &blob.encrypted_payload)
                .map_err(PasswordManagerError::Crypto)?;
            let payload: TotpPayload = serde_json::from_slice(&payload_json)
                .map_err(|e| DatabaseError::Serialization(e.to_string()))?;

            let entry_id = payload.parent_credential_sync_id.and_then(|pid| {
                conn.query_row(
                    "SELECT entry_id FROM entries WHERE sync_id = ?1",
                    [pid.to_string()],
                    |row| row.get::<_, i64>(0),
                )
                .ok()
            });

            if let Some(eid) = entry_id {
                let now = chrono::Utc::now().timestamp();
                conn.execute(
                    "INSERT INTO totp_secrets (
                        entry_id, secret_encrypted, nonce, auth_tag,
                        algorithm, digits, period, issuer, account_name, created_at,
                        sync_id, sync_version, sync_state, last_synced_at, is_deleted
                    ) VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9, ?10, ?11, ?12, 'synced', ?13, 0)",
                    rusqlite::params![
                        eid,
                        payload.secret_encrypted,
                        payload.nonce,
                        payload.auth_tag,
                        payload.algorithm,
                        payload.digits as i32,
                        payload.period as i32,
                        payload.issuer,
                        payload.account_name,
                        payload.created_at,
                        sync_id_str,
                        blob.sync_version as i64,
                        now,
                    ],
                )
                .map_err(DatabaseError::Sqlite)?;
            }
        }

        Ok(())
    }
}
