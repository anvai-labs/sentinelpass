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
use zeroize::Zeroizing;

/// Decrypt a sync blob's payload and deserialize it into `T`.
fn decrypt_sync_payload<T: serde::de::DeserializeOwned>(
    dek: &DataEncryptionKey,
    blob: &SyncEntryBlob,
) -> Result<T> {
    let json =
        decrypt_from_sync(dek, &blob.encrypted_payload).map_err(PasswordManagerError::Crypto)?;
    serde_json::from_slice(&json).map_err(|e| DatabaseError::Serialization(e.to_string()).into())
}

/// Conflict + tombstone preamble for the "existing local row" path.
///
/// Returns `true` when the caller should return `Ok(())` immediately (row kept locally
/// or tombstone has been applied). Returns `false` when the caller should proceed with
/// the update. `tombstone_sql` must be a parameterized UPDATE with bindings
/// `(?1 = now_timestamp, ?2 = sync_version, ?3 = local_id)`.
fn apply_existing_preamble(
    conn: &rusqlite::Connection,
    local_id: i64,
    local_version: i64,
    local_modified: i64,
    blob: &SyncEntryBlob,
    tombstone_sql: &str,
) -> Result<bool> {
    if ConflictResolver::resolve(local_version as u64, local_modified, blob)
        == Resolution::KeepLocal
    {
        return Ok(true);
    }
    if blob.is_tombstone {
        conn.execute(
            tombstone_sql,
            rusqlite::params![
                chrono::Utc::now().timestamp(),
                blob.sync_version as i64,
                local_id
            ],
        )
        .map_err(DatabaseError::Sqlite)?;
        return Ok(true);
    }
    Ok(false)
}

/// Returns `true` when a new-entry insert should be skipped (tombstone or stale blob).
#[inline]
fn skip_new_entry(blob: &SyncEntryBlob) -> bool {
    blob.is_tombstone || !ConflictResolver::accept_new(blob)
}

/// Resolve a sync payload's secret to plaintext: the current-build field
/// (plaintext) when present, else the v0.8.x legacy three-part shape
/// (old wire field names) decrypted with the shared DEK — wire backward
/// compatibility: old-peer payloads must apply, not wedge the pull.
/// (Note: the legacy path recovers the plaintext the SENDER stored under
/// the shared DEK; the receiver then re-seals under its OWN identity.)
fn resolve_sync_secret(
    plaintext: &str,
    legacy_ct: Option<&[u8]>,
    legacy_nonce: Option<&[u8]>,
    legacy_auth_tag: Option<&[u8]>,
    // WBS-308: v1 decryptors return zeroizing secrets, matching the v2
    // envelope path.
    decrypt_v1: impl Fn(&[u8], &[u8], &[u8]) -> Result<Zeroizing<String>>,
) -> Result<Zeroizing<String>> {
    if !plaintext.is_empty() {
        return Ok(plaintext.to_string().into());
    }
    match (legacy_ct, legacy_nonce, legacy_auth_tag) {
        (Some(ct), Some(nonce), Some(tag)) => decrypt_v1(ct, nonce, tag),
        _ => Err(PasswordManagerError::InvalidInput(
            "sync payload carries neither the current plaintext field nor the complete \
             legacy secret shape"
                .to_string(),
        )),
    }
}

struct CredentialBlobs {
    title: Vec<u8>,
    username: Vec<u8>,
    password: Vec<u8>,
    url: Option<Vec<u8>>,
    notes: Option<Vec<u8>>,
    nonce: Vec<u8>,
    auth_tag: Vec<u8>,
}

fn prepare_credential_blobs(
    conn: &rusqlite::Connection,
    dek: &DataEncryptionKey,
    payload: &CredentialPayload,
    sync_id: &str,
) -> Result<CredentialBlobs> {
    // Seal v2 under the LOCAL identity (adoption review, finding 3): the
    // old shape wrote context-free v1 blobs, silently stripping the
    // identity binding from synced rows (and the sync trigger re-marked
    // them pending, propagating the downgrade to every peer). The vault
    // UUID comes from db_metadata on this connection; the entry's stable
    // sync_id is the object identity.
    let (vault_uuid, epoch) = crate::vault::envelope_ops::read_local_identity(conn)?;
    let seal = |purpose, plaintext: &str| {
        crate::vault::envelope_ops::seal_object_field(
            dek,
            &vault_uuid,
            sync_id,
            crate::vault::envelope_ops::envelope_object_type(payload.credential_type),
            purpose,
            plaintext,
            epoch,
        )
    };
    let title = seal(crate::crypto::aad::EnvelopePurpose::Summary, &payload.title)?;
    let username = seal(
        crate::crypto::aad::EnvelopePurpose::Summary,
        &payload.username,
    )?;
    let password = seal(
        crate::crypto::aad::EnvelopePurpose::Secret,
        &payload.password,
    )?;
    let url = payload
        .url
        .as_ref()
        .map(|u| seal(crate::crypto::aad::EnvelopePurpose::Secret, u))
        .transpose()?;
    let notes = payload
        .notes
        .as_ref()
        .map(|n| seal(crate::crypto::aad::EnvelopePurpose::Secret, n))
        .transpose()?;
    // Deprecated v1 columns — zero-filled on v2 rows (see envelope_ops).
    let (nonce, auth_tag) = crate::vault::envelope_ops::zeroed_legacy_v1_columns();
    Ok(CredentialBlobs {
        nonce,
        auth_tag,
        title,
        username,
        password,
        url,
        notes,
    })
}

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

        // 3. Update sync metadata and checkpoint the WAL.
        let db = self
            .db
            .lock()
            .map_err(|_| DatabaseError::LockPoisoned("sync engine".to_string()))?;
        let mut config = SyncConfig::load(db.conn())?;
        config.last_sync_at = Some(chrono::Utc::now().timestamp());
        config.save(db.conn())?;

        let pending = count_pending_changes(db.conn())?;

        // Passive checkpoint: flush WAL pages written during push/pull back to the
        // main database file without blocking readers.
        let _ = db.wal_checkpoint();

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

            let mut apply_failures: u64 = 0;
            for blob in &response.entries {
                // Skip our own changes
                if blob.origin_device_id == self.device_id {
                    continue;
                }
                // Per-blob resilience (adoption review): one unreadable
                // blob — an old-peer payload shape, a decode failure —
                // must NOT abort the page before the cursor advances,
                // wedging every future sync on the same blob forever.
                // Skip-and-warn names the blob; the experimental-sync
                // data-loss tradeoff is spelled out in docs/SYNC.md.
                if let Err(e) = self.apply_remote_entry(db.conn(), dek, blob) {
                    apply_failures += 1;
                    tracing::warn!(
                        sync_id = %blob.sync_id,
                        entry_type = ?blob.entry_type,
                        error = %e,
                        "sync pull: skipping unappliable blob (cursor advances; \
                         the change is NOT applied)"
                    );
                }
            }
            if apply_failures > 0 {
                tracing::warn!(
                    failures = apply_failures,
                    "sync pull completed with skipped blobs — inspect the warnings \
                     above; affected entries were not applied"
                );
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

        // Local identity + domain-tag key for v2 sealing (WBS-304/WBS-306):
        // entry fields AND domain mappings seal under the LOCAL identity.
        let (vault_uuid, epoch) = crate::vault::envelope_ops::read_local_identity(conn)?;
        let domain_tag_key = crate::crypto::keyring::derive_domain_tag_key(dek)?;
        let mapping_ctx = crate::vault::domain_ops::MappingSealCtx {
            dek,
            vault_uuid: &vault_uuid,
            epoch,
            tag_key: &domain_tag_key,
        };

        // Check if we have this entry locally
        let local: Option<(i64, i64, i64)> = conn
            .query_row(
                "SELECT entry_id, sync_version, modified_at FROM entries WHERE sync_id = ?1",
                [&sync_id_str],
                |row| Ok((row.get(0)?, row.get(1)?, row.get(2)?)),
            )
            .ok();

        if let Some((entry_id, local_version, local_modified)) = local {
            if apply_existing_preamble(
                conn,
                entry_id,
                local_version,
                local_modified,
                blob,
                "UPDATE entries SET is_deleted = 1, deleted_at = ?1,
                 sync_version = ?2, sync_state = 'synced', last_synced_at = ?1
                 WHERE entry_id = ?3",
            )? {
                // Tombstoned remotely: purge registry rows (soft delete never
                // fires FK CASCADE). The preamble also returns early on
                // conflict resolution (local row kept), so gate the purge on
                // the row actually being soft-deleted.
                let is_deleted: i64 = conn
                    .query_row(
                        "SELECT is_deleted FROM entries WHERE entry_id = ?1",
                        [entry_id],
                        |row| row.get(0),
                    )
                    .unwrap_or(0);
                if is_deleted == 1 {
                    if let Err(e) = crate::registry::purge_registry_rows(conn, entry_id) {
                        tracing::warn!(entry_id, error = %e, "registry purge failed");
                    }
                }
                return Ok(());
            }

            let payload: CredentialPayload = decrypt_sync_payload(dek, blob)?;
            let blobs = prepare_credential_blobs(conn, dek, &payload, &sync_id_str)?;
            let now = chrono::Utc::now().timestamp();

            conn.execute(
                "UPDATE entries SET
                    title = ?1, username = ?2, password = ?3, url = ?4, notes = ?5,
                    credential_type = ?6, entry_nonce = ?7, auth_tag = ?8,
                    modified_at = ?9, favorite = ?10, sync_version = ?11,
                    sync_state = 'synced', last_synced_at = ?12
                 WHERE entry_id = ?13",
                rusqlite::params![
                    blobs.title,
                    blobs.username,
                    blobs.password,
                    blobs.url.as_deref().filter(|b| !b.is_empty()),
                    blobs.notes.as_deref().filter(|b| !b.is_empty()),
                    payload.credential_type.as_str(),
                    blobs.nonce,
                    blobs.auth_tag,
                    payload.modified_at,
                    payload.favorite as i32,
                    blob.sync_version as i64,
                    now,
                    entry_id,
                ],
            )
            .map_err(DatabaseError::Sqlite)?;

            // Update domain mappings (sealed + tagged, WBS-306 — the
            // mapping delete cascades its tag rows).
            conn.execute(
                "DELETE FROM domain_mappings WHERE entry_id = ?1",
                [entry_id],
            )
            .map_err(DatabaseError::Sqlite)?;
            for dm in &payload.domains {
                crate::vault::domain_ops::insert_sealed_domain_mapping(
                    conn,
                    &mapping_ctx,
                    entry_id,
                    &dm.domain,
                    dm.is_primary,
                )?;
            }

            // Registry equality index (ADR-001): sync apply is a first-class
            // write site — this entry never passes through VaultManager, so
            // without this hook remote-origin rotations would never stamp.
            // Best-effort; the next sweep repairs.
            if let Err(e) = crate::registry::upsert_equality_tag(
                conn,
                dek,
                entry_id,
                payload.credential_type,
                &payload.password,
                now,
            ) {
                tracing::warn!(entry_id, error = %e, "registry index update failed");
            }
        } else {
            if skip_new_entry(blob) {
                return Ok(());
            }
            let payload: CredentialPayload = decrypt_sync_payload(dek, blob)?;
            let blobs = prepare_credential_blobs(conn, dek, &payload, &sync_id_str)?;
            let now = chrono::Utc::now().timestamp();

            conn.execute(
                "INSERT INTO entries (
                    vault_id, title, username, password, url, notes, credential_type,
                    entry_nonce, auth_tag, created_at, modified_at, favorite,
                    sync_id, sync_version, sync_state, last_synced_at, is_deleted
                ) VALUES (1, ?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9, ?10, ?11, ?12, ?13, 'synced', ?14, 0)",
                rusqlite::params![
                    blobs.title,
                    blobs.username,
                    blobs.password,
                    blobs.url.as_deref().filter(|b| !b.is_empty()),
                    blobs.notes.as_deref().filter(|b| !b.is_empty()),
                    payload.credential_type.as_str(),
                    blobs.nonce,
                    blobs.auth_tag,
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
                crate::vault::domain_ops::insert_sealed_domain_mapping(
                    conn,
                    &mapping_ctx,
                    entry_id,
                    &dm.domain,
                    dm.is_primary,
                )?;
            }

            // Registry equality index for pulled-in entries (same rationale
            // as the update branch above).
            if let Err(e) = crate::registry::upsert_equality_tag(
                conn,
                dek,
                entry_id,
                payload.credential_type,
                &payload.password,
                now,
            ) {
                tracing::warn!(entry_id, error = %e, "registry index update failed");
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
        // Local identity for v2 sealing (WBS-304): fetched from this
        // connection's db_metadata, never assumed from config.
        // Local identity for v2 sealing (WBS-304) — see read_local_identity.
        let (vault_uuid, epoch) = crate::vault::envelope_ops::read_local_identity(conn)?;

        let local: Option<(i64, i64, i64)> = conn
            .query_row(
                "SELECT key_id, sync_version, modified_at FROM ssh_keys WHERE sync_id = ?1",
                [&sync_id_str],
                |row| Ok((row.get(0)?, row.get(1)?, row.get(2)?)),
            )
            .ok();

        if let Some((key_id, local_version, local_modified)) = local {
            if apply_existing_preamble(
                conn,
                key_id,
                local_version,
                local_modified,
                blob,
                "UPDATE ssh_keys SET is_deleted = 1, deleted_at = ?1,
                 sync_version = ?2, sync_state = 'synced', last_synced_at = ?1
                 WHERE key_id = ?3",
            )? {
                return Ok(());
            }
            let payload: SshKeyPayload = decrypt_sync_payload(dek, blob)?;
            let private_key = resolve_sync_secret(
                &payload.private_key,
                payload.private_key_encrypted.as_deref(),
                payload.legacy_nonce.as_deref(),
                payload.legacy_auth_tag.as_deref(),
                |ct, nonce, tag| crate::ssh::SshKey::decrypt_private_key(dek, ct, nonce, tag),
            )?;
            // Seal v2 under the LOCAL identity (WBS-304 — never store the
            // peer's envelope; see prepare_credential_blobs). Seals the
            // RESOLVED plaintext (a legacy-shape peer's payload.private_key
            // is empty; the plaintext came from its v1 triplet).
            let private_key_blob = crate::vault::envelope_ops::seal_object_field(
                dek,
                &vault_uuid,
                &sync_id_str,
                crate::crypto::aad::ObjectType::SshKey,
                crate::crypto::aad::EnvelopePurpose::Secret,
                &private_key,
                epoch,
            )?;
            let (nonce_blob, auth_tag_blob) =
                crate::vault::envelope_ops::zeroed_legacy_v1_columns();
            // Identity metadata sealed in place (WBS-306): the comment
            // column carries a Summary envelope under the row's identity.
            let comment_blob = payload
                .comment
                .as_deref()
                .map(|c| {
                    crate::vault::envelope_ops::seal_object_field(
                        dek,
                        &vault_uuid,
                        &sync_id_str,
                        crate::crypto::aad::ObjectType::SshKey,
                        crate::crypto::aad::EnvelopePurpose::Summary,
                        c,
                        epoch,
                    )
                })
                .transpose()?;

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
                    comment_blob,
                    payload.key_type,
                    payload.key_size,
                    payload.public_key,
                    &private_key_blob,
                    &nonce_blob,
                    &auth_tag_blob,
                    payload.fingerprint,
                    payload.modified_at,
                    blob.sync_version as i64,
                    now,
                    key_id,
                ],
            )
            .map_err(DatabaseError::Sqlite)?;
        } else {
            if skip_new_entry(blob) {
                return Ok(());
            }
            let payload: SshKeyPayload = decrypt_sync_payload(dek, blob)?;
            let private_key = resolve_sync_secret(
                &payload.private_key,
                payload.private_key_encrypted.as_deref(),
                payload.legacy_nonce.as_deref(),
                payload.legacy_auth_tag.as_deref(),
                |ct, nonce, tag| crate::ssh::SshKey::decrypt_private_key(dek, ct, nonce, tag),
            )?;
            let private_key_blob = crate::vault::envelope_ops::seal_object_field(
                dek,
                &vault_uuid,
                &sync_id_str,
                crate::crypto::aad::ObjectType::SshKey,
                crate::crypto::aad::EnvelopePurpose::Secret,
                &private_key,
                epoch,
            )?;
            let (nonce_blob, auth_tag_blob) =
                crate::vault::envelope_ops::zeroed_legacy_v1_columns();
            // Identity metadata sealed in place (WBS-306 — see UPDATE arm).
            let comment_blob = payload
                .comment
                .as_deref()
                .map(|c| {
                    crate::vault::envelope_ops::seal_object_field(
                        dek,
                        &vault_uuid,
                        &sync_id_str,
                        crate::crypto::aad::ObjectType::SshKey,
                        crate::crypto::aad::EnvelopePurpose::Summary,
                        c,
                        epoch,
                    )
                })
                .transpose()?;
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
                    comment_blob,
                    payload.key_type,
                    payload.key_size,
                    payload.public_key,
                    &private_key_blob,
                    &nonce_blob,
                    &auth_tag_blob,
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
        // Local identity for v2 sealing (WBS-304 — see apply_ssh_key).
        // Local identity for v2 sealing (WBS-304) — see read_local_identity.
        let (vault_uuid, epoch) = crate::vault::envelope_ops::read_local_identity(conn)?;

        let local: Option<(i64, i64, i64)> = conn
            .query_row(
                "SELECT totp_id, sync_version, created_at FROM totp_secrets WHERE sync_id = ?1",
                [&sync_id_str],
                |row| Ok((row.get(0)?, row.get(1)?, row.get(2)?)),
            )
            .ok();

        if let Some((totp_id, local_version, local_created)) = local {
            if apply_existing_preamble(
                conn,
                totp_id,
                local_version,
                local_created,
                blob,
                "UPDATE totp_secrets SET is_deleted = 1, deleted_at = ?1,
                 sync_version = ?2, sync_state = 'synced', last_synced_at = ?1
                 WHERE totp_id = ?3",
            )? {
                return Ok(());
            }
            let payload: TotpPayload = decrypt_sync_payload(dek, blob)?;
            let secret = resolve_sync_secret(
                &payload.secret,
                payload.secret_encrypted.as_deref(),
                payload.legacy_nonce.as_deref(),
                payload.legacy_auth_tag.as_deref(),
                |ct, nonce, tag| crate::totp::decrypt_totp_secret(dek, ct, nonce, tag),
            )?;

            // Re-link entry_id from parent_credential_sync_id
            let entry_id = payload.parent_credential_sync_id.and_then(|pid| {
                conn.query_row(
                    "SELECT entry_id FROM entries WHERE sync_id = ?1",
                    [pid.to_string()],
                    |row| row.get::<_, i64>(0),
                )
                .ok()
            });

            // Seal v2 under the LOCAL identity (WBS-304 — never store
            // the peer's envelope; see prepare_credential_blobs). The
            // totp row keeps its OWN sync_id (sync_id_str), which the
            // envelope binds.
            let secret_blob = crate::vault::envelope_ops::seal_object_field(
                dek,
                &vault_uuid,
                &sync_id_str,
                crate::crypto::aad::ObjectType::TotpSecret,
                crate::crypto::aad::EnvelopePurpose::Secret,
                &secret,
                epoch,
            )?;
            let (nonce_blob, auth_tag_blob) =
                crate::vault::envelope_ops::zeroed_legacy_v1_columns();
            // Identity metadata sealed in place (WBS-306): issuer/
            // account_name carry Summary envelopes under the row's identity.
            let issuer_blob = payload
                .issuer
                .as_deref()
                .map(|c| {
                    crate::vault::envelope_ops::seal_object_field(
                        dek,
                        &vault_uuid,
                        &sync_id_str,
                        crate::crypto::aad::ObjectType::TotpSecret,
                        crate::crypto::aad::EnvelopePurpose::Summary,
                        c,
                        epoch,
                    )
                })
                .transpose()?;
            let account_name_blob = payload
                .account_name
                .as_deref()
                .map(|c| {
                    crate::vault::envelope_ops::seal_object_field(
                        dek,
                        &vault_uuid,
                        &sync_id_str,
                        crate::crypto::aad::ObjectType::TotpSecret,
                        crate::crypto::aad::EnvelopePurpose::Summary,
                        c,
                        epoch,
                    )
                })
                .transpose()?;

            let Some(eid) = entry_id else {
                // The parent credential has not landed locally (relay
                // ordering or a conflicting local version). Dropping the
                // blob silently loses the TOTP forever — warn loudly
                // (re-sync after the credential lands re-delivers only if
                // the peer re-pushes; sync v2's requeue is WBS-605).
                tracing::warn!(
                    sync_id = %sync_id_str,
                    "sync pull: TOTP blob skipped — parent credential is not \
                     present locally; the secret was NOT applied"
                );
                return Ok(());
            };

            let now = chrono::Utc::now().timestamp();
            {
                conn.execute(
                    "UPDATE totp_secrets SET
                        entry_id = ?1, secret_encrypted = ?2, nonce = ?3, auth_tag = ?4,
                        algorithm = ?5, digits = ?6, period = ?7, issuer = ?8, account_name = ?9,
                        sync_version = ?10, sync_state = 'synced', last_synced_at = ?11
                     WHERE totp_id = ?12",
                    rusqlite::params![
                        eid,
                        &secret_blob,
                        &nonce_blob,
                        &auth_tag_blob,
                        payload.algorithm,
                        payload.digits as i32,
                        payload.period as i32,
                        issuer_blob,
                        account_name_blob,
                        blob.sync_version as i64,
                        now,
                        totp_id,
                    ],
                )
                .map_err(DatabaseError::Sqlite)?;
            }
        } else {
            if skip_new_entry(blob) {
                return Ok(());
            }
            let payload: TotpPayload = decrypt_sync_payload(dek, blob)?;
            let secret = resolve_sync_secret(
                &payload.secret,
                payload.secret_encrypted.as_deref(),
                payload.legacy_nonce.as_deref(),
                payload.legacy_auth_tag.as_deref(),
                |ct, nonce, tag| crate::totp::decrypt_totp_secret(dek, ct, nonce, tag),
            )?;
            let entry_id = payload.parent_credential_sync_id.and_then(|pid| {
                conn.query_row(
                    "SELECT entry_id FROM entries WHERE sync_id = ?1",
                    [pid.to_string()],
                    |row| row.get::<_, i64>(0),
                )
                .ok()
            });

            // Seal v2 under the LOCAL identity (WBS-304 — see above).
            let secret_blob = crate::vault::envelope_ops::seal_object_field(
                dek,
                &vault_uuid,
                &sync_id_str,
                crate::crypto::aad::ObjectType::TotpSecret,
                crate::crypto::aad::EnvelopePurpose::Secret,
                &secret,
                epoch,
            )?;
            let (nonce_blob, auth_tag_blob) =
                crate::vault::envelope_ops::zeroed_legacy_v1_columns();
            // Identity metadata sealed in place (WBS-306 — see UPDATE arm).
            let issuer_blob = payload
                .issuer
                .as_deref()
                .map(|c| {
                    crate::vault::envelope_ops::seal_object_field(
                        dek,
                        &vault_uuid,
                        &sync_id_str,
                        crate::crypto::aad::ObjectType::TotpSecret,
                        crate::crypto::aad::EnvelopePurpose::Summary,
                        c,
                        epoch,
                    )
                })
                .transpose()?;
            let account_name_blob = payload
                .account_name
                .as_deref()
                .map(|c| {
                    crate::vault::envelope_ops::seal_object_field(
                        dek,
                        &vault_uuid,
                        &sync_id_str,
                        crate::crypto::aad::ObjectType::TotpSecret,
                        crate::crypto::aad::EnvelopePurpose::Summary,
                        c,
                        epoch,
                    )
                })
                .transpose()?;

            if entry_id.is_none() {
                tracing::warn!(
                    sync_id = %sync_id_str,
                    "sync pull: TOTP blob skipped — parent credential is not \
                     present locally; the secret was NOT applied"
                );
                return Ok(());
            }
            let eid = entry_id.unwrap();
            {
                let now = chrono::Utc::now().timestamp();
                conn.execute(
                    "INSERT INTO totp_secrets (
                        entry_id, secret_encrypted, nonce, auth_tag,
                        algorithm, digits, period, issuer, account_name, created_at,
                        sync_id, sync_version, sync_state, last_synced_at, is_deleted
                    ) VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9, ?10, ?11, ?12, 'synced', ?13, 0)",
                    rusqlite::params![
                        eid,
                        &secret_blob,
                        &nonce_blob,
                        &auth_tag_blob,
                        payload.algorithm,
                        payload.digits as i32,
                        payload.period as i32,
                        issuer_blob,
                        account_name_blob,
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
