//! Sync engine: orchestrates push/pull/resolve/apply cycle.

use crate::crypto::cipher::DataEncryptionKey;
use crate::database::Database;
use crate::sync::change_tracker::{
    collect_pending_credential_blobs, collect_pending_ssh_key_blobs, collect_pending_totp_blobs,
    count_pending_changes, mark_entries_synced_in,
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

/// Mark the pushed blobs synced and advance the push cursor as ONE
/// transaction (SR-DATA-001 / WBS-411): an interruption leaves either both
/// untouched (everything re-pushes next cycle — LWW makes that idempotent)
/// or both applied — never a partially-marked batch against a moved cursor.
/// Free function so tests can fault-inject every statement without an HTTP
/// client.
pub(crate) fn complete_push_checkpoint(
    conn: &rusqlite::Connection,
    sync_ids: &[Uuid],
    server_sequence: u64,
) -> Result<()> {
    let tx = conn
        .unchecked_transaction()
        .map_err(DatabaseError::Sqlite)?;
    mark_entries_synced_in(&tx, sync_ids)?;

    let mut config = SyncConfig::load(&tx)?;
    config.last_push_sequence = server_sequence;
    config.save(&tx)?;

    tx.commit().map_err(DatabaseError::Sqlite)?;
    Ok(())
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

        // Mark synced + advance the push cursor as ONE unit (see
        // [`Self::complete_push_checkpoint`]).
        let db = self
            .db
            .lock()
            .map_err(|_| DatabaseError::LockPoisoned("mark synced".to_string()))?;
        complete_push_checkpoint(db.conn(), &sync_ids, response.server_sequence)?;

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
                //
                // Each blob applies inside its OWN transaction — see
                // [`Self::apply_remote_entry`] (SR-DATA-001 / WBS-411):
                // a failure at any statement rolls that blob back entirely
                // (complete-old for this entry) while the rest of the page
                // proceeds.
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
    ///
    /// UNIT OF WORK (SR-DATA-001 / WBS-411): the entry write, the
    /// domain-mapping rewrite, and the registry index write for this blob
    /// run inside ONE transaction created here — a failure at any statement
    /// rolls the whole blob back (complete-old state), and the caller's
    /// per-blob resilience can never strand a partially-applied entry.
    ///
    /// `pub(crate)` (not private) so tests can drive the apply logic
    /// directly against a real vault database — the engine's HTTP client
    /// is never involved in an apply.
    pub(crate) fn apply_remote_entry(
        &self,
        conn: &rusqlite::Connection,
        dek: &DataEncryptionKey,
        blob: &SyncEntryBlob,
    ) -> Result<()> {
        let tx = conn
            .unchecked_transaction()
            .map_err(DatabaseError::Sqlite)?;
        let result = match blob.entry_type {
            SyncEntryType::Credential => self.apply_credential(&tx, dek, blob),
            SyncEntryType::SshKey => self.apply_ssh_key(&tx, dek, blob),
            SyncEntryType::TotpSecret => self.apply_totp(&tx, dek, blob),
        };
        if let Err(e) = result {
            // tx drops on return: the whole blob rolls back.
            let _ = tx.rollback();
            return Err(e);
        }
        Ok(tx.commit().map_err(DatabaseError::Sqlite)?)
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

            // Typed NULL preservation (WBS-410 / TD-ROB-03 / SR-DATA-002):
            // payload None stores NULL; payload Some stores its envelope —
            // including Some("") — with NO empty-blob coercion at either
            // end. (The former `.filter(|b| !b.is_empty())` here was the
            // TD-ROB-03 band-aid, silently losing Some("").)
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
                    blobs.url.as_deref(),
                    blobs.notes.as_deref(),
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
            // REQUIRED, not best-effort (SR-DATA-001 / WBS-411): the blob
            // apply is one transaction, so an index failure rolls the whole
            // blob back — the pull cursor advances past it (skip-and-warn)
            // and the blob re-delivers on a later sync (LWW idempotent).
            crate::registry::upsert_equality_tag(
                conn,
                dek,
                entry_id,
                payload.credential_type,
                &payload.password,
                now,
            )?;
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
                    // Typed NULL preservation — see the UPDATE arm above.
                    blobs.url.as_deref(),
                    blobs.notes.as_deref(),
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
            // and same REQUIRED semantics as the update branch above —
            // SR-DATA-001 / WBS-411).
            crate::registry::upsert_equality_tag(
                conn,
                dek,
                entry_id,
                payload.credential_type,
                &payload.password,
                now,
            )?;
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

#[cfg(test)]
mod tests {
    use super::*;
    use crate::sync::crypto::encrypt_for_sync;
    use crate::sync::models::CredentialPayload;

    /// A vault-shaped in-memory database: current schema + the
    /// db_metadata identity (vault_uuid, key_epoch) that `read_local_identity`
    /// requires on every apply path.
    fn apply_test_db() -> Database {
        fn seed_identity(db: &Database) {
            let sql = format!(
                "INSERT INTO db_metadata (id, version, kdf_params, wrapped_dek, dek_nonce, created_at, last_modified, vault_uuid, format_version, key_epoch)
                 VALUES (1, {}, X'00', X'00', X'00', strftime('%s','now'), strftime('%s','now'), '11111111-1111-1111-1111-111111111111', 1, 1)",
                crate::database::schema::CURRENT_SCHEMA_VERSION
            );
            db.conn().execute(&sql, []).unwrap();
        }

        let db = Database::in_memory().unwrap();
        db.initialize_schema().unwrap();
        seed_identity(&db);
        db
    }

    fn apply_engine(db: Database) -> (SyncEngine, Arc<Mutex<Database>>) {
        let db = Arc::new(Mutex::new(db));
        let signing_key = ed25519_dalek::SigningKey::from_bytes(&[7u8; 32]);
        // The client is never used by an apply; the URL only has to pass
        // transport validation.
        let client = SyncClient::new("https://relay.invalid", Uuid::new_v4(), signing_key).unwrap();
        let engine = SyncEngine::new(client, db.clone(), Uuid::new_v4());
        (engine, db)
    }

    fn credential_blob(dek: &DataEncryptionKey, sync_id: Uuid, version: u64) -> SyncEntryBlob {
        let payload = CredentialPayload {
            title: "Remote Title".to_string(),
            username: "remote-user".to_string(),
            password: Zeroizing::new("remote-pass".to_string()),
            credential_type: crate::CredentialType::Password,
            url: Some("https://remote.example".to_string()),
            notes: None,
            favorite: false,
            domains: vec![],
            created_at: 1_700_000_000,
            modified_at: 1_700_000_100,
        };
        let plaintext = Zeroizing::new(serde_json::to_vec(&payload).unwrap());
        let encrypted = encrypt_for_sync(dek, &plaintext).unwrap();
        SyncEntryBlob {
            sync_id,
            entry_type: SyncEntryType::Credential,
            sync_version: version,
            modified_at: payload.modified_at,
            encrypted_payload: encrypted,
            is_tombstone: false,
            origin_device_id: Uuid::new_v4(),
        }
    }

    /// THE WBS-409 / TD-ROB-02 negative: a remote apply writes
    /// `sync_state = 'synced'` (and its explicit sync_version) and it
    /// STAYS that way — the echo trigger that rewrote applies back to
    /// `'pending'` (re-push loop) is gone from the schema and must never
    /// come back (the schema test asserts its absence; migrate_v8_to_v9
    /// drops it on legacy vaults).
    #[tokio::test]
    async fn remote_apply_does_not_remark_pending() {
        let dek = DataEncryptionKey::new().unwrap();
        let sync_id = Uuid::new_v4();

        let (engine, db) = apply_engine(apply_test_db());
        {
            let conn = db.lock().unwrap();
            // An existing local row, already synced at version 3.
            conn.conn()
                .execute(
                    "INSERT INTO entries (vault_id, title, username, password, credential_type,
                        entry_nonce, auth_tag, created_at, modified_at, favorite,
                        sync_id, sync_version, sync_state, is_deleted)
                     VALUES (1, X'01', X'02', X'03', 'password', X'04', X'05', 100, 100, 0,
                             ?1, 3, 'synced', 0)",
                    [&sync_id.to_string()],
                )
                .unwrap();
        }

        let blob = credential_blob(&dek, sync_id, 4);
        {
            let conn = db.lock().unwrap();
            engine.apply_remote_entry(conn.conn(), &dek, &blob).unwrap();
        }

        let (state, version, modified, last_synced): (String, i64, i64, Option<i64>) = {
            let conn = db.lock().unwrap();
            conn.conn()
                .query_row(
                    "SELECT sync_state, sync_version, modified_at, last_synced_at \
                     FROM entries WHERE sync_id = ?1",
                    [&sync_id.to_string()],
                    |r| Ok((r.get(0)?, r.get(1)?, r.get(2)?, r.get(3)?)),
                )
                .unwrap()
        };
        assert_eq!(
            state, "synced",
            "remote apply must not be re-marked pending"
        );
        assert_eq!(version, 4, "the applied version must survive");
        // The echo trigger clobbered modified_at to apply-time, which then
        // won the peer's LWW tie-break (see-saw). It must survive untouched.
        assert_eq!(modified, 1_700_000_100, "the wire modified_at must survive");
        assert!(last_synced.is_some());
    }

    /// A remote apply of an UNKNOWN sync_id inserts the row directly as
    /// `'synced'` (INSERTs never fired the old trigger, but this pins the
    /// full explicit-bookkeeping contract of the apply path).
    #[tokio::test]
    async fn remote_apply_insert_lands_synced() {
        let dek = DataEncryptionKey::new().unwrap();
        let sync_id = Uuid::new_v4();

        let (engine, db) = apply_engine(apply_test_db());
        let blob = credential_blob(&dek, sync_id, 1);
        {
            let conn = db.lock().unwrap();
            engine.apply_remote_entry(conn.conn(), &dek, &blob).unwrap();
        }

        let (state, version, url_is_null): (String, i64, bool) = {
            let conn = db.lock().unwrap();
            conn.conn()
                .query_row(
                    "SELECT sync_state, sync_version, url IS NULL FROM entries \
                     WHERE sync_id = ?1",
                    [&sync_id.to_string()],
                    |r| Ok((r.get(0)?, r.get(1)?, r.get(2)?)),
                )
                .unwrap()
        };
        assert_eq!(state, "synced");
        assert_eq!(version, 1);
        assert!(!url_is_null, "Some(url) payload must store a url blob");
    }

    /// A stale remote blob (older sync_version) must NOT clobber the local
    /// row's bookkeeping (rollback protection — the LWW gate refuses
    /// before any write happens).
    #[tokio::test]
    async fn remote_apply_stale_version_keeps_local_row() {
        let dek = DataEncryptionKey::new().unwrap();
        let sync_id = Uuid::new_v4();

        let (engine, db) = apply_engine(apply_test_db());
        {
            let conn = db.lock().unwrap();
            conn.conn()
                .execute(
                    "INSERT INTO entries (vault_id, title, username, password, credential_type,
                        entry_nonce, auth_tag, created_at, modified_at, favorite,
                        sync_id, sync_version, sync_state, is_deleted)
                     VALUES (1, X'01', X'02', X'03', 'password', X'04', X'05', 100, 100, 0,
                             ?1, 5, 'pending', 0)",
                    [&sync_id.to_string()],
                )
                .unwrap();
        }

        let blob = credential_blob(&dek, sync_id, 4);
        {
            let conn = db.lock().unwrap();
            engine.apply_remote_entry(conn.conn(), &dek, &blob).unwrap();
        }

        let (state, version): (String, i64) = {
            let conn = db.lock().unwrap();
            conn.conn()
                .query_row(
                    "SELECT sync_state, sync_version FROM entries WHERE sync_id = ?1",
                    [&sync_id.to_string()],
                    |r| Ok((r.get(0)?, r.get(1)?)),
                )
                .unwrap()
        };
        assert_eq!(state, "pending", "local pending state must be untouched");
        assert_eq!(version, 5, "the local (newer) version must be untouched");
    }

    // --- WBS-411 / SR-DATA-001: the apply paths are units of work ----------

    fn install_fault(db: &Database, fail_at: usize) {
        crate::database::fault_injection::install_write_fault(db.conn(), fail_at);
    }

    fn clear_fault(db: &Database) {
        crate::database::fault_injection::clear_write_fault(db.conn());
    }

    /// THE apply-update negative (SR-DATA-001): one blob = entry UPDATE +
    /// mapping rewrite + registry index, all inside ONE transaction.
    /// Failing any statement leaves the entry, its mappings, and the index
    /// in the complete-OLD state; success applies all of it.
    #[tokio::test]
    async fn remote_apply_update_arm_fault_injection_is_all_or_nothing() {
        let dek = DataEncryptionKey::new().unwrap();
        let sync_id = Uuid::new_v4();

        let (engine, db) = apply_engine(apply_test_db());
        {
            let conn = db.lock().unwrap();
            conn.conn()
                .execute(
                    "INSERT INTO entries (vault_id, title, username, password, credential_type,
                        entry_nonce, auth_tag, created_at, modified_at, favorite,
                        sync_id, sync_version, sync_state, is_deleted)
                     VALUES (1, X'01', X'02', X'03', 'password', X'04', X'05', 100, 100, 0,
                             ?1, 3, 'synced', 0)",
                    [&sync_id.to_string()],
                )
                .unwrap();
            let entry_id: i64 = conn
                .conn()
                .query_row(
                    "SELECT entry_id FROM entries WHERE sync_id = ?1",
                    [&sync_id.to_string()],
                    |r| r.get(0),
                )
                .unwrap();
            conn.conn()
                .execute(
                    "INSERT INTO domain_mappings (entry_id, domain, is_primary) VALUES (?1, 'old.example', 1)",
                    [entry_id],
                )
                .unwrap();
        }

        // A blob carrying one NEW domain.
        let payload = CredentialPayload {
            title: "Remote Title".to_string(),
            username: "remote-user".to_string(),
            password: Zeroizing::new("remote-pass".to_string()),
            credential_type: crate::CredentialType::Password,
            url: None,
            notes: None,
            favorite: false,
            domains: vec![crate::sync::models::DomainPayload {
                domain: "applied.example".to_string(),
                is_primary: true,
            }],
            created_at: 1_700_000_000,
            modified_at: 1_700_000_100,
        };
        let plaintext = Zeroizing::new(serde_json::to_vec(&payload).unwrap());
        let mut blob = credential_blob(&dek, sync_id, 4);
        blob.encrypted_payload = encrypt_for_sync(&dek, &plaintext).unwrap();

        let old_title: Vec<u8> = {
            let conn = db.lock().unwrap();
            conn.conn()
                .query_row(
                    "SELECT title FROM entries WHERE sync_id = ?1",
                    [&sync_id.to_string()],
                    |r| r.get(0),
                )
                .unwrap()
        };

        let mut fail_at = 0usize;
        let mut injected_failures = 0usize;
        loop {
            {
                let conn = db.lock().unwrap();
                install_fault(&conn, fail_at);
            }
            let result = {
                let conn = db.lock().unwrap();
                engine.apply_remote_entry(conn.conn(), &dek, &blob)
            };
            {
                let conn = db.lock().unwrap();
                clear_fault(&conn);
            }

            let (state, version, entry_id): (String, i64, i64) = {
                let conn = db.lock().unwrap();
                conn.conn()
                    .query_row(
                        "SELECT sync_state, sync_version, entry_id FROM entries WHERE sync_id = ?1",
                        [&sync_id.to_string()],
                        |r| Ok((r.get(0)?, r.get(1)?, r.get(2)?)),
                    )
                    .unwrap()
            };
            let mappings: Vec<String> = {
                let conn = db.lock().unwrap();
                let mut stmt = conn
                    .conn()
                    .prepare("SELECT domain FROM domain_mappings WHERE entry_id = ?1")
                    .unwrap();
                let rows = stmt
                    .query_map([entry_id], |r| r.get::<_, String>(0))
                    .unwrap()
                    .collect::<std::result::Result<Vec<_>, _>>()
                    .unwrap();
                rows
            };
            let index: i64 = {
                let conn = db.lock().unwrap();
                conn.conn()
                    .query_row(
                        "SELECT COUNT(*) FROM secret_equality_index WHERE entry_id = ?1",
                        [entry_id],
                        |r| r.get(0),
                    )
                    .unwrap()
            };

            match result {
                Err(_) => {
                    injected_failures += 1;
                    assert_eq!(state, "synced", "complete-old at write {fail_at}");
                    assert_eq!(version, 3, "complete-old at write {fail_at}");
                    let title: Vec<u8> = {
                        let conn = db.lock().unwrap();
                        conn.conn()
                            .query_row(
                                "SELECT title FROM entries WHERE sync_id = ?1",
                                [&sync_id.to_string()],
                                |r| r.get(0),
                            )
                            .unwrap()
                    };
                    assert_eq!(title, old_title, "complete-old at write {fail_at}");
                    assert_eq!(
                        mappings,
                        vec!["old.example".to_string()],
                        "complete-old: old mapping survives at write {fail_at}"
                    );
                    assert_eq!(index, 0, "complete-old: no index row at write {fail_at}");
                }
                Ok(()) => {
                    assert_eq!(version, 4, "complete-new at write {fail_at}");
                    assert_eq!(state, "synced", "complete-new at write {fail_at}");
                    assert_eq!(
                        mappings,
                        vec!["applied.example".to_string()],
                        "complete-new: mapping rewrite committed WITH the row"
                    );
                    assert_eq!(
                        index, 1,
                        "complete-new: registry index committed WITH the row"
                    );
                    break;
                }
            }
            fail_at += 1;
            assert!(fail_at < 96, "apply never succeeded within the sweep bound");
        }
        assert!(
            injected_failures >= 1,
            "the sweep must inject at least one real failure to be meaningful"
        );
    }

    /// The push checkpoint: mark-synced for the whole batch + the cursor
    /// advance commit together — an injected failure leaves every row
    /// pending and the cursor untouched.
    #[test]
    fn complete_push_checkpoint_fault_injection_is_all_or_nothing() {
        let db = apply_test_db();
        let ids: Vec<Uuid> = (0..2).map(|_| Uuid::new_v4()).collect();
        {
            let conn = db.conn();
            for id in &ids {
                conn.execute(
                    "INSERT INTO entries (vault_id, title, username, password, credential_type,
                        entry_nonce, auth_tag, created_at, modified_at, favorite,
                        sync_id, sync_version, sync_state, is_deleted)
                     VALUES (1, X'01', X'02', X'03', 'password', X'04', X'05', 100, 100, 0,
                             ?1, 1, 'pending', 0)",
                    [&id.to_string()],
                )
                .unwrap();
            }
        }

        let mut fail_at = 0usize;
        let mut injected_failures = 0usize;
        loop {
            install_fault(&db, fail_at);
            let result = complete_push_checkpoint(db.conn(), &ids, 42);
            clear_fault(&db);

            let (pending, synced): (i64, i64) = {
                let conn = db.conn();
                conn.query_row(
                    "SELECT \
                         (SELECT COUNT(*) FROM entries WHERE sync_state = 'pending'), \
                         (SELECT COUNT(*) FROM entries WHERE sync_state = 'synced')",
                    [],
                    |r| Ok((r.get(0)?, r.get(1)?)),
                )
                .unwrap()
            };
            let cursor: i64 = crate::sync::config::SyncConfig::load(db.conn())
                .unwrap()
                .last_push_sequence as i64;

            match result {
                Err(_) => {
                    injected_failures += 1;
                    assert_eq!(pending, 2, "complete-old at write {fail_at}");
                    assert_eq!(synced, 0, "complete-old at write {fail_at}");
                    assert_eq!(cursor, 0, "complete-old: cursor unmoved at write {fail_at}");
                }
                Ok(()) => {
                    assert_eq!(pending, 0, "complete-new at write {fail_at}");
                    assert_eq!(synced, 2, "complete-new at write {fail_at}");
                    assert_eq!(cursor, 42, "complete-new: cursor advanced WITH the marks");
                    break;
                }
            }
            fail_at += 1;
            assert!(
                fail_at < 64,
                "checkpoint never succeeded within the sweep bound"
            );
        }
        assert!(
            injected_failures >= 1,
            "the sweep must inject at least one real failure to be meaningful"
        );
    }

    // --- WBS-410 / TD-ROB-03 / SR-DATA-002: typed NULL end to end ----------

    /// A pending v1-shape credential row with configurable optional fields
    /// (None -> NULL column; Some -> v1 bincode blob under `dek`).
    fn insert_pending_with_optionals(
        conn: &rusqlite::Connection,
        dek: &DataEncryptionKey,
        url: Option<&str>,
        notes: Option<&str>,
    ) -> Uuid {
        use crate::crypto::cipher::encrypt_string;
        let sync_id = Uuid::new_v4();
        let now = chrono::Utc::now().timestamp();
        let t = encrypt_string(dek, "Opt Title").unwrap();
        let u = encrypt_string(dek, "opt-user").unwrap();
        let p = encrypt_string(dek, "opt-pass").unwrap();
        let url_blob = url.map(|s| bincode::serialize(&encrypt_string(dek, s).unwrap()).unwrap());
        let notes_blob =
            notes.map(|s| bincode::serialize(&encrypt_string(dek, s).unwrap()).unwrap());
        conn.execute(
            "INSERT INTO entries (vault_id, title, username, password, url, notes, credential_type,
                entry_nonce, auth_tag, created_at, modified_at, favorite,
                sync_id, sync_version, sync_state, is_deleted)
             VALUES (1, ?1, ?2, ?3, ?4, ?5, 'password', ?6, ?7, ?8, ?9, 0, ?10, 1, 'pending', 0)",
            rusqlite::params![
                bincode::serialize(&t).unwrap(),
                bincode::serialize(&u).unwrap(),
                bincode::serialize(&p).unwrap(),
                url_blob,
                notes_blob,
                bincode::serialize(&t.nonce).unwrap(),
                bincode::serialize(&t.auth_tag).unwrap(),
                now,
                now,
                sync_id.to_string(),
            ],
        )
        .unwrap();
        sync_id
    }

    fn decrypt_payload(dek: &DataEncryptionKey, blob: &SyncEntryBlob) -> CredentialPayload {
        let json = decrypt_from_sync(dek, &blob.encrypted_payload).unwrap();
        serde_json::from_slice(&json).unwrap()
    }

    /// THE positive NULL roundtrip: local NULL -> wire absence -> remote
    /// NULL. The applied column IS NULL (never an empty blob, never a
    /// sealed empty string).
    #[test]
    fn none_url_notes_roundtrip_stays_null_end_to_end() {
        let dek = DataEncryptionKey::new().unwrap();
        let source = apply_test_db();
        let target_db = apply_test_db();
        {
            let conn = source.conn();
            insert_pending_with_optionals(conn, &dek, None, None);
        }
        let blobs = collect_pending_credential_blobs(source.conn(), &dek, Uuid::new_v4()).unwrap();
        assert_eq!(blobs.len(), 1);
        let payload = decrypt_payload(&dek, &blobs[0]);
        assert_eq!(payload.url, None, "wire must carry absence");
        assert_eq!(payload.notes, None, "wire must carry absence");

        let (engine2, target) = apply_engine(target_db);
        {
            let conn = target.lock().unwrap();
            engine2
                .apply_remote_entry(conn.conn(), &dek, &blobs[0])
                .unwrap();
        }
        let (url_null, notes_null): (bool, bool) = {
            let conn = target.lock().unwrap();
            conn.conn()
                .query_row(
                    "SELECT url IS NULL, notes IS NULL FROM entries WHERE sync_id = ?1",
                    [&blobs[0].sync_id.to_string()],
                    |r| Ok((r.get(0)?, r.get(1)?)),
                )
                .unwrap()
        };
        assert!(
            url_null && notes_null,
            "remote columns must be NULL, not empty blobs"
        );
    }

    /// THE positive Some roundtrip: local Some -> wire Some -> remote Some,
    /// decrypted back byte-faithful under the TARGET identity.
    #[test]
    fn some_url_notes_roundtrip_preserved() {
        let dek = DataEncryptionKey::new().unwrap();
        let source = apply_test_db();
        let target_db = apply_test_db();
        {
            let conn = source.conn();
            insert_pending_with_optionals(
                conn,
                &dek,
                Some("https://roundtrip.example"),
                Some("round the trip"),
            );
        }
        let blobs = collect_pending_credential_blobs(source.conn(), &dek, Uuid::new_v4()).unwrap();
        assert_eq!(blobs.len(), 1);
        let payload = decrypt_payload(&dek, &blobs[0]);
        assert_eq!(payload.url.as_deref(), Some("https://roundtrip.example"));
        assert_eq!(payload.notes.as_deref(), Some("round the trip"));

        let (engine2, target) = apply_engine(target_db);
        {
            let conn = target.lock().unwrap();
            engine2
                .apply_remote_entry(conn.conn(), &dek, &blobs[0])
                .unwrap();
        }
        let (url_blob, notes_blob, vault_uuid): (Option<Vec<u8>>, Option<Vec<u8>>, String) = {
            let conn = target.lock().unwrap();
            let (u, n, v): (Option<Vec<u8>>, Option<Vec<u8>>, String) = conn
                .conn()
                .query_row(
                    "SELECT url, notes, (SELECT vault_uuid FROM db_metadata WHERE id = 1) \
                     FROM entries WHERE sync_id = ?1",
                    [&blobs[0].sync_id.to_string()],
                    |r| Ok((r.get(0)?, r.get(1)?, r.get(2)?)),
                )
                .unwrap();
            (u, n, v)
        };
        assert!(
            url_blob.is_some() && notes_blob.is_some(),
            "Some must store blobs, not NULL"
        );
        let opened_url = crate::vault::envelope_ops::open_object_field(
            &dek,
            Some(vault_uuid.as_str()),
            Some(blobs[0].sync_id.to_string().as_str()),
            crate::crypto::aad::ObjectType::Password,
            crate::crypto::aad::EnvelopePurpose::Secret,
            url_blob.as_deref().unwrap(),
        )
        .unwrap();
        assert_eq!(opened_url.as_str(), "https://roundtrip.example");
        let opened_notes = crate::vault::envelope_ops::open_object_field(
            &dek,
            Some(vault_uuid.as_str()),
            Some(blobs[0].sync_id.to_string().as_str()),
            crate::crypto::aad::ObjectType::Password,
            crate::crypto::aad::EnvelopePurpose::Secret,
            notes_blob.as_deref().unwrap(),
        )
        .unwrap();
        assert_eq!(opened_notes.as_str(), "round the trip");
    }

    /// THE negative for the old band-aid: Some("") must NOT be coerced to
    /// NULL/absence anywhere in the chain (no Some->None loss). The former
    /// apply-side `.filter(|b| !b.is_empty())` fabricated exactly that loss.
    #[test]
    fn empty_string_url_roundtrip_not_coerced_to_null() {
        let dek = DataEncryptionKey::new().unwrap();
        let source = apply_test_db();
        let target_db = apply_test_db();
        {
            let conn = source.conn();
            insert_pending_with_optionals(conn, &dek, Some(""), Some(""));
        }
        let blobs = collect_pending_credential_blobs(source.conn(), &dek, Uuid::new_v4()).unwrap();
        assert_eq!(blobs.len(), 1);
        let payload = decrypt_payload(&dek, &blobs[0]);
        assert_eq!(
            payload.url,
            Some(String::new()),
            "wire must keep Some(\"\")"
        );
        assert_eq!(payload.notes, Some(String::new()));

        let (engine2, target) = apply_engine(target_db);
        {
            let conn = target.lock().unwrap();
            engine2
                .apply_remote_entry(conn.conn(), &dek, &blobs[0])
                .unwrap();
        }
        let (url_null, notes_null): (bool, bool) = {
            let conn = target.lock().unwrap();
            conn.conn()
                .query_row(
                    "SELECT url IS NULL, notes IS NULL FROM entries WHERE sync_id = ?1",
                    [&blobs[0].sync_id.to_string()],
                    |r| Ok((r.get(0)?, r.get(1)?)),
                )
                .unwrap()
        };
        assert!(
            !url_null && !notes_null,
            "Some(\"\") must survive as a stored value"
        );
    }

    /// Legacy EMPTY blobs (X'', the pre-0.9 absence marker) decode to
    /// absence on push — the collector never fabricates Some("") from them.
    #[test]
    fn legacy_empty_blob_url_collects_as_absent() {
        let dek = DataEncryptionKey::new().unwrap();
        let source = apply_test_db();
        {
            let conn = source.conn();
            insert_pending_with_optionals(conn, &dek, None, None);
            conn.execute("UPDATE entries SET url = X'', notes = X''", [])
                .unwrap();
        }
        let blobs = collect_pending_credential_blobs(source.conn(), &dek, Uuid::new_v4()).unwrap();
        assert_eq!(blobs.len(), 1);
        let payload = decrypt_payload(&dek, &blobs[0]);
        assert_eq!(payload.url, None);
        assert_eq!(payload.notes, None);
    }
}
