//! Sync engine: orchestrates the v2 push/pull/resolve/apply cycle (ADR-006).
//!
//! Push collects pending rows as deterministic v2 mutations
//! ([`crate::sync::outbox`]); the outbox entry leaves ONLY on its own
//! `Applied` acknowledgement, and a rejected object's retry re-derives the
//! same mutation id so the relay replays the original durable result — the
//! v1 lost-checkpoint wedge (strictly-increasing `device_sequence` versus a
//! locally lost cursor) is structurally impossible in v2.
//! Pull walks the relay's append-only vault log with a distinct
//! [`ServerCursor`].

use crate::crypto::cipher::DataEncryptionKey;
use crate::database::Database;
use crate::sync::change_tracker::count_pending_changes;
use crate::sync::client::{SyncClient, SyncTransport};
use crate::sync::config::SyncConfig;
use crate::sync::conflict::{ConflictResolver, Resolution};
use crate::sync::crypto::decrypt_from_sync;
use crate::sync::models::{
    CredentialPayload, SshKeyPayload, SyncEntryBlob, SyncEntryType, SyncStatus, TotpPayload,
};
use crate::sync::outbox;
use crate::sync::v2::{DeviceSequence, MutationV2, PullRequestV2, PushRequestV2, ServerCursor};
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
/// The synced-bookkeeping columns of an existing local row, for the
/// conflict guard and LWW preamble.
struct ExistingLocalRow<'a> {
    id: i64,
    version: i64,
    modified: i64,
    state: &'a str,
}

fn apply_existing_preamble(
    conn: &rusqlite::Connection,
    local: ExistingLocalRow<'_>,
    blob: &SyncEntryBlob,
    table: &str,
    tombstone_sql: &str,
) -> Result<bool> {
    // SR-SYNC-005 (WBS-611): an UNSYNCED local edit must never be silently
    // overwritten (or silently deleted by a tombstone). Record the incoming
    // mutation as the durable alternative and mark the row conflicted —
    // the local side stays in its own row until user resolution
    // (`resolve_sync_conflict`); the recorded mutation is the page
    // disposition.
    if (local.state == "pending" || local.state == "conflict")
        && blob.sync_version >= local.version as u64
    {
        // Equal version = divergent content under the same lineage point;
        // greater = the peer progressed past our base. A STALE blob
        // (version below the local row) is not an alternative worth
        // preserving — it cannot have applied anywhere current (relay CAS)
        // and would only pollute resolution.
        record_conflict(conn, blob)?;
        conn.execute(
            &format!("UPDATE {table} SET sync_state = 'conflict' WHERE sync_id = ?1"),
            rusqlite::params![blob.sync_id.to_string()],
        )
        .map_err(DatabaseError::Sqlite)?;
        return Ok(true);
    }
    if ConflictResolver::resolve(local.version as u64, local.modified, blob)
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
                local.id
            ],
        )
        .map_err(DatabaseError::Sqlite)?;
        return Ok(true);
    }
    Ok(false)
}

/// Record a pulled mutation as a durable conflict alternative (WBS-611):
/// latest alternative wins; the payload is stored relay-shaped (DEK
/// ciphertext) and re-sealed under the LOCAL identity at resolution.
fn record_conflict(conn: &rusqlite::Connection, blob: &SyncEntryBlob) -> Result<()> {
    tracing::warn!(
        sync_id = %blob.sync_id,
        incoming_version = blob.sync_version,
        tombstone = blob.is_tombstone,
        "sync pull: concurrent edit preserved as a conflict alternative \
         (local edit kept; resolve with 'sync conflict-resolve')"
    );
    conn.execute(
        "INSERT INTO sync_conflicts (
            object_id, object_type, remote_version, remote_payload,
            origin_device_id, is_tombstone, received_at
         ) VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7)
         ON CONFLICT(object_id) DO UPDATE SET
            object_type = excluded.object_type,
            remote_version = excluded.remote_version,
            remote_payload = excluded.remote_payload,
            origin_device_id = excluded.origin_device_id,
            is_tombstone = excluded.is_tombstone,
            received_at = excluded.received_at",
        rusqlite::params![
            blob.sync_id.to_string(),
            format!("{:?}", blob.entry_type),
            blob.sync_version as i64,
            blob.encrypted_payload,
            blob.origin_device_id.to_string(),
            blob.is_tombstone,
            chrono::Utc::now().timestamp(),
        ],
    )
    .map_err(DatabaseError::Sqlite)?;
    Ok(())
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
///
/// Generic over the v2 transport ([`SyncTransport`]): production runs over
/// HTTP ([`SyncClient`]); tests drive the same engine against an in-memory
/// relay model, which is how loss/retry/duplicate acceptance evidence is
/// produced without a network.
pub struct SyncEngine<T: SyncTransport + 'static = SyncClient> {
    client: T,
    db: Arc<Mutex<Database>>,
    device_id: Uuid,
}

/// Convert a pulled v2 log mutation into the blob shape the apply paths
/// consume. v2 carries no LWW timestamp: `modified_at` is 0 so the
/// version-lineage compare decides (a strictly greater version applies; an
/// equal-or-lower version keeps local — conflict preservation hardens this
/// in WBS-611).
fn blob_from_log_mutation(m: &MutationV2) -> SyncEntryBlob {
    SyncEntryBlob {
        sync_id: m.object_id,
        entry_type: m.object_type,
        sync_version: m.resulting_version.as_u64(),
        modified_at: 0,
        encrypted_payload: m.encrypted_payload.clone(),
        is_tombstone: m.is_tombstone,
        origin_device_id: m.origin_device_id,
    }
}

/// One stored concurrent-edit alternative (the peer's side of a conflict).
#[derive(Debug, Clone)]
pub struct ConflictAlternative {
    pub entry_type: SyncEntryType,
    pub remote_version: u64,
    pub payload: Vec<u8>,
    pub origin: Uuid,
    pub is_tombstone: bool,
}

/// Parse the Debug-form object type tag stored in conflict/dead-letter rows.
pub fn parse_object_type(type_str: &str) -> Result<SyncEntryType> {
    match type_str {
        "Credential" => Ok(SyncEntryType::Credential),
        "SshKey" => Ok(SyncEntryType::SshKey),
        "TotpSecret" => Ok(SyncEntryType::TotpSecret),
        other => Err(PasswordManagerError::InvalidInput(format!(
            "unknown sync object type {other}"
        ))),
    }
}

fn table_for(entry_type: SyncEntryType) -> &'static str {
    match entry_type {
        SyncEntryType::Credential => "entries",
        SyncEntryType::SshKey => "ssh_keys",
        SyncEntryType::TotpSecret => "totp_secrets",
    }
}

/// KEEP-LOCAL resolution (WBS-611): re-version the local content above the
/// peer and re-base its CAS expectation onto the peer's version — the next
/// push applies it cleanly (CAS current == expected), and the stored
/// alternative is discarded. The caller deletes the `sync_conflicts` row.
pub fn resolve_conflict_keep_local(
    conn: &rusqlite::Connection,
    object_id: &Uuid,
    entry_type: SyncEntryType,
    remote_version: u64,
) -> Result<()> {
    let table = table_for(entry_type);
    conn.execute(
        &format!(
            "UPDATE {table} SET sync_state = 'pending',
             sync_acked_version = MAX(sync_acked_version, ?1),
             sync_version = MAX(sync_version, ?2)
             WHERE sync_id = ?3"
        ),
        rusqlite::params![
            remote_version as i64,
            remote_version.saturating_add(1) as i64,
            object_id.to_string()
        ],
    )
    .map_err(DatabaseError::Sqlite)?;
    conn.execute(
        "DELETE FROM sync_conflicts WHERE object_id = ?1",
        [object_id.to_string()],
    )
    .map_err(DatabaseError::Sqlite)?;
    Ok(())
}

/// TAKE-REMOTE resolution (WBS-611): re-base the local row below the stored
/// alternative and apply it through the normal path (sealing under the
/// LOCAL identity); the alternative record is then deleted. A tombstone
/// alternative deletes the local row.
pub fn resolve_conflict_take_remote<T: SyncTransport + 'static>(
    engine: &SyncEngine<T>,
    conn: &rusqlite::Connection,
    dek: &DataEncryptionKey,
    object_id: &Uuid,
    alternative: &ConflictAlternative,
) -> Result<()> {
    let ConflictAlternative {
        entry_type,
        remote_version,
        ref payload,
        ref origin,
        ref is_tombstone,
    } = *alternative;
    let table = table_for(entry_type);
    conn.execute(
        &format!(
            "UPDATE {table} SET sync_state = 'synced',
             sync_version = MIN(sync_version, ?1)
             WHERE sync_id = ?2"
        ),
        rusqlite::params![
            remote_version.saturating_sub(1) as i64,
            object_id.to_string()
        ],
    )
    .map_err(DatabaseError::Sqlite)?;
    let blob = SyncEntryBlob {
        sync_id: *object_id,
        entry_type,
        sync_version: remote_version,
        modified_at: 0,
        encrypted_payload: payload.clone(),
        is_tombstone: *is_tombstone,
        origin_device_id: *origin,
    };
    engine.apply_remote_entry(conn, dek, &blob)?;
    conn.execute(
        "DELETE FROM sync_conflicts WHERE object_id = ?1",
        [object_id.to_string()],
    )
    .map_err(DatabaseError::Sqlite)?;
    Ok(())
}

/// Hard cap on dead-letter rows — bounded disposition state (ADR-006). At
/// the cap the pull fails closed (page + cursor roll back) until the user
/// inspects and purges.
pub const MAX_DEAD_LETTER: usize = 1_000;

/// The outcome of one savepoint-wrapped apply inside a page.
enum ApplyDisposition {
    Applied,
    Deferred(String),
    Failed(String),
}

/// Record the durable disposition for an unappliable mutation, inside the
/// caller's page transaction.
fn dead_letter_entry(
    tx: &rusqlite::Transaction<'_>,
    entry: &crate::sync::v2::MutationLogEntry,
    reason: &str,
) -> Result<()> {
    tracing::warn!(
        sync_id = %entry.mutation.object_id,
        entry_type = ?entry.mutation.object_type,
        server_sequence = entry.server_sequence.as_u64(),
        reason = %reason,
        "sync pull: mutation dead-lettered (durable disposition; the cursor \
         passes it, the change is NOT applied)"
    );
    tx.execute(
        "INSERT INTO sync_dead_letter (
            server_sequence, mutation_id, object_id, object_type, reason, received_at
         ) VALUES (?1, ?2, ?3, ?4, ?5, ?6)",
        rusqlite::params![
            entry.server_sequence.as_u64() as i64,
            entry.mutation.mutation_id.to_string(),
            entry.mutation.object_id.to_string(),
            format!("{:?}", entry.mutation.object_type),
            reason,
            chrono::Utc::now().timestamp(),
        ],
    )
    .map_err(DatabaseError::Sqlite)?;
    Ok(())
}

impl<T: SyncTransport + 'static> SyncEngine<T> {
    /// Create a new sync engine with the given client, database, and device identity.
    pub fn new(client: T, db: Arc<Mutex<Database>>, device_id: Uuid) -> Self {
        Self {
            client,
            db,
            device_id,
        }
    }

    /// Perform a full sync cycle: push local changes, then pull remote changes.
    pub async fn sync(&self, dek: &DataEncryptionKey) -> Result<SyncStatus> {
        // Fail-closed mixed-protocol gate (ADR-006): a v1-era configuration
        // (protocol_version != 2) must never speak v2 against relay state
        // that was established under v1 — the v2 tables for that vault are
        // a parallel universe the v1 peers never see. Migration is the
        // authoritative-device re-baseline (WBS-624) or a fresh v2
        // init/re-pair.
        {
            let db = self
                .db
                .lock()
                .map_err(|_| DatabaseError::LockPoisoned("protocol gate".to_string()))?;
            let config = SyncConfig::load(db.conn())?;
            if config.sync_enabled
                && config.protocol_version != crate::sync::config::SYNC_PROTOCOL_VERSION
            {
                return Err(PasswordManagerError::InvalidInput(format!(
                    "this vault's sync configuration predates sync protocol v2 \
                     (configured protocol version: {}). Mixed-protocol operation is \
                     forbidden (ADR-006): run the authoritative-device migration on \
                     this device (re-init sync as the migration authority) or re-pair \
                     under v2 before syncing again.",
                    config.protocol_version
                )));
            }
        }

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

        let conflict_count = crate::sync::outbox::count_sync_conflicts(db.conn())?;
        Ok(SyncStatus {
            enabled: config.sync_enabled,
            device_id: config.device_id,
            device_name: config.device_name.clone(),
            relay_url: config.relay_url.clone(),
            last_sync_at: config.last_sync_at,
            pending_changes: pending,
            conflict_count,
        })
    }

    /// Push all pending local changes as v2 mutations (WBS-603/604/605).
    ///
    /// Mutations go out in bounded pages (the relay caps a request at
    /// [`outbox::MAX_PUSH_MUTATIONS`]); every page is independently
    /// idempotent, so a failure mid-batch costs a retry of the unacked
    /// remainder only.
    async fn push_changes(&self, dek: &DataEncryptionKey) -> Result<u64> {
        let (mutations, device_sequence) = {
            let db = self
                .db
                .lock()
                .map_err(|_| DatabaseError::LockPoisoned("push".to_string()))?;
            let conn = db.conn();

            let config = SyncConfig::load(conn)?;
            let relay_vault_id = config.vault_id.ok_or_else(|| {
                PasswordManagerError::InvalidInput("Sync vault ID missing".to_string())
            })?;
            let (_, epoch) = crate::vault::envelope_ops::read_local_identity(conn)?;

            let mutations = outbox::collect_pending_mutations(
                conn,
                dek,
                self.device_id,
                relay_vault_id,
                epoch,
            )?;
            // Framing counter: diagnostic only in v2 (idempotency keys carry
            // correctness). A retry deliberately re-sends the same value.
            let device_sequence = DeviceSequence(config.last_push_sequence + 1);
            (mutations, device_sequence)
        };

        let total = mutations.len();
        if total == 0 {
            return Ok(0);
        }

        for chunk in mutations.chunks(outbox::MAX_PUSH_MUTATIONS) {
            let request = PushRequestV2 {
                device_sequence,
                mutations: chunk.iter().map(|m| m.mutation.clone()).collect(),
            };
            let response = self.client.push_v2(&request).await?;

            // Per-object durable checkpoint (WBS-604/605): only Applied
            // objects leave the outbox; rejections stay pending with their
            // acked version untouched. One transaction with the relay-cursor
            // diagnostic.
            {
                let db = self
                    .db
                    .lock()
                    .map_err(|_| DatabaseError::LockPoisoned("mark acked".to_string()))?;
                outbox::apply_push_acks(
                    db.conn(),
                    chunk,
                    &response.results,
                    response.server_cursor.as_u64(),
                )?;
            }
        }

        Ok(total as u64)
    }

    /// Pull remote changes from the relay's vault log and apply them
    /// locally (WBS-607 / SR-SYNC-003).
    ///
    /// UNIT OF WORK: each page applies, dispositions, and the cursor
    /// advance inside ONE transaction — a mutation that cannot be applied
    /// receives a DURABLE disposition (bounded dead-letter) rather than a
    /// silent skip, and the cursor only ever passes a mutation that has
    /// one. Order-dependent applies (a TOTP whose parent credential arrives
    /// later in the page) get ONE bounded retry pass within the same
    /// transaction before being dead-lettered.
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
            let request = PullRequestV2 {
                since: ServerCursor(cursor),
                limit: Some(500),
            };

            let response = self.client.pull_v2(&request).await?;

            if response.entries.is_empty() {
                break;
            }

            if response.cursor.as_u64() <= cursor {
                return Err(PasswordManagerError::InvalidInput(
                    "Relay pull cursor did not advance".to_string(),
                ));
            }

            total_count += response.entries.len() as u64;

            {
                let db = self
                    .db
                    .lock()
                    .map_err(|_| DatabaseError::LockPoisoned("apply pull".to_string()))?;
                let mut tx = db
                    .conn()
                    .unchecked_transaction()
                    .map_err(DatabaseError::Sqlite)?;

                let mut deferred: Vec<(usize, String)> = Vec::new();
                let mut applied = 0usize;
                for (index, entry) in response.entries.iter().enumerate() {
                    let mutation = &entry.mutation;
                    // Skip our own changes: their acks already governed the
                    // outbox, and the cursor passes them with this page.
                    if mutation.origin_device_id == self.device_id {
                        continue;
                    }
                    let blob = blob_from_log_mutation(mutation);
                    // Per-blob SAVEPOINT: a mid-apply failure must not leave
                    // the object's earlier writes (entry rewrite, mapping
                    // deletes, ...) committed under a "not applied"
                    // disposition — the page rolls the blob back to its
                    // pre-apply state before dead-lettering.
                    let outcome = {
                        let mut sp = tx.savepoint().map_err(DatabaseError::Sqlite)?;
                        let r = self.apply_remote_entry_in_tx(&sp, dek, &blob);
                        match r {
                            Ok(()) => {
                                sp.commit().map_err(DatabaseError::Sqlite)?;
                                ApplyDisposition::Applied
                            }
                            Err(PasswordManagerError::SyncDeferred(reason)) => {
                                sp.rollback().map_err(DatabaseError::Sqlite)?;
                                ApplyDisposition::Deferred(reason)
                            }
                            Err(e) => {
                                sp.rollback().map_err(DatabaseError::Sqlite)?;
                                ApplyDisposition::Failed(e.to_string())
                            }
                        }
                    };
                    match outcome {
                        ApplyDisposition::Applied => applied += 1,
                        ApplyDisposition::Deferred(reason) => deferred.push((index, reason)),
                        ApplyDisposition::Failed(reason) => dead_letter_entry(&tx, entry, &reason)?,
                    }
                }

                // ONE bounded requeue pass: a parent credential later in the
                // page satisfies an earlier deferred TOTP.
                let mut still_deferred = 0usize;
                for (index, reason) in &deferred {
                    let entry = &response.entries[*index];
                    let blob = blob_from_log_mutation(&entry.mutation);
                    let outcome = {
                        let mut sp = tx.savepoint().map_err(DatabaseError::Sqlite)?;
                        let r = self.apply_remote_entry_in_tx(&sp, dek, &blob);
                        match r {
                            Ok(()) => {
                                sp.commit().map_err(DatabaseError::Sqlite)?;
                                ApplyDisposition::Applied
                            }
                            Err(other) => {
                                sp.rollback().map_err(DatabaseError::Sqlite)?;
                                ApplyDisposition::Failed(format!(
                                    "unresolved after one requeue pass: {reason} ({other})"
                                ))
                            }
                        }
                    };
                    match outcome {
                        ApplyDisposition::Applied => applied += 1,
                        ApplyDisposition::Failed(reason) => {
                            still_deferred += 1;
                            dead_letter_entry(&tx, entry, &reason)?;
                        }
                        ApplyDisposition::Deferred(_) => unreachable!("retry defers no more"),
                    }
                }

                // Bounded state (ADR-006): the dead-letter table is hard-
                // capped. Overflow is FAIL-CLOSED — the whole page, cursor
                // included, rolls back and the error surfaces to the user.
                let dead_lettered: i64 = tx
                    .query_row("SELECT COUNT(*) FROM sync_dead_letter", [], |r| r.get(0))
                    .map_err(DatabaseError::Sqlite)?;
                if dead_lettered as usize > MAX_DEAD_LETTER {
                    return Err(PasswordManagerError::InvalidInput(format!(
                        "sync dead-letter exceeded its bound ({MAX_DEAD_LETTER}); \
                         the pull page was rolled back and the cursor did NOT advance. \
                         Inspect the sync_dead_letter table and purge resolved rows"
                    )));
                }

                let mut config = SyncConfig::load(&tx)?;
                config.last_pull_sequence = response.cursor.as_u64();
                config.save(&tx)?;

                tx.commit().map_err(DatabaseError::Sqlite)?;

                if still_deferred > 0 {
                    tracing::warn!(
                        unresolved = still_deferred,
                        applied,
                        "sync pull page committed with dead-lettered mutations"
                    );
                }
            }

            cursor = response.cursor.as_u64();

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
    /// Per-blob unit of work — production pull folds applies into the PAGE
    /// transaction ([`Self::apply_remote_entry_in_tx`]); this one-blob
    /// wrapper serves the conflict-resolution path (take-remote applies one
    /// stored alternative) and the apply-path test fixtures.
    pub fn apply_remote_entry(
        &self,
        conn: &rusqlite::Connection,
        dek: &DataEncryptionKey,
        blob: &SyncEntryBlob,
    ) -> Result<()> {
        let tx = conn
            .unchecked_transaction()
            .map_err(DatabaseError::Sqlite)?;
        let result = self.apply_remote_entry_in_tx(&tx, dek, blob);
        if let Err(e) = result {
            // tx drops on return: the whole blob rolls back.
            let _ = tx.rollback();
            return Err(e);
        }
        Ok(tx.commit().map_err(DatabaseError::Sqlite)?)
    }

    /// The apply core WITHOUT its own transaction — the caller's transaction
    /// is the unit of work. The pull page folds applies, dead-letter
    /// dispositions, and the cursor advance into ONE transaction (WBS-607)
    /// and therefore calls this variant.
    fn apply_remote_entry_in_tx(
        &self,
        tx: &rusqlite::Connection,
        dek: &DataEncryptionKey,
        blob: &SyncEntryBlob,
    ) -> Result<()> {
        match blob.entry_type {
            SyncEntryType::Credential => self.apply_credential(tx, dek, blob),
            SyncEntryType::SshKey => self.apply_ssh_key(tx, dek, blob),
            SyncEntryType::TotpSecret => self.apply_totp(tx, dek, blob),
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
        let local: Option<(i64, i64, i64, String)> = conn
            .query_row(
                "SELECT entry_id, sync_version, modified_at, sync_state FROM entries WHERE sync_id = ?1",
                [&sync_id_str],
                |row| Ok((row.get(0)?, row.get(1)?, row.get(2)?, row.get(3)?)),
            )
            .ok();

        if let Some((entry_id, local_version, local_modified, local_state)) = local {
            let local = ExistingLocalRow {
                id: entry_id,
                version: local_version,
                modified: local_modified,
                state: &local_state,
            };
            if apply_existing_preamble(
                conn,
                local,
                blob,
                "entries",
                "UPDATE entries SET is_deleted = 1, deleted_at = ?1,
                 sync_version = ?2, sync_acked_version = ?2, sync_state = 'synced', \
                 last_synced_at = ?1
                 WHERE entry_id = ?3",
            )? {
                // Tombstoned remotely: purge registry rows (soft delete never
                // fires FK CASCADE). The preamble also returns early on
                // conflict resolution (local row kept), so gate the purge on
                // the row actually being soft-deleted. Best-effort per the
                // REGISTRY-BOUNDARY note below: a failed purge degrades to
                // sweep repair (the deletion itself is durable either way).
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
                        if let Err(flag_err) = crate::registry::mark_backfill_needed(conn) {
                            tracing::warn!(entry_id, error = %flag_err, "could not re-arm the registry sweep");
                        }
                    }
                }
                return Ok(());
            }

            let payload: CredentialPayload = decrypt_sync_payload(dek, blob)?;
            let blobs = prepare_credential_blobs(conn, dek, &payload, &sync_id_str)?;
            let now = chrono::Utc::now().timestamp();

            // Typed NULL preservation (WBS-410 / TD-ROB-03 / SR-DATA-002):
            // payload None stores NULL; payload Some stores its envelope —
            // including Some("") — with NO empty-blob coercion. (The former
            // `.filter(|b| !b.is_empty())` here has been INERT since v2
            // envelope sealing — sealed blobs are never empty; it is
            // removed as the explicit typed contract. The historical
            // TD-ROB-03 fabrication was the 0.8.x era's
            // `unwrap_or(&[])`, which turned None into an empty blob.)
            conn.execute(
                "UPDATE entries SET
                    title = ?1, username = ?2, password = ?3, url = ?4, notes = ?5,
                    credential_type = ?6, entry_nonce = ?7, auth_tag = ?8,
                    modified_at = ?9, favorite = ?10, sync_version = ?11,
                    sync_acked_version = ?11, sync_state = 'synced', last_synced_at = ?12
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
            //
            // REGISTRY-BOUNDARY NOTE (WBS-411 review): this write is
            // BEST-EFFORT inside the blob transaction, deliberately. The
            // atomic unit of an apply is entry + domain mappings; the
            // equality index is DERIVED data with its own repair loop.
            // Making it required would widen the documented permanent-loss
            // class: a skipped blob's cursor moves past it and the relay
            // never re-serves that sequence (docs/SYNC.md), so a
            // repairable index failure would drop the peer's whole change.
            // A degraded index, by contrast, is repairable — the branch
            // below RE-ARMS the sweep's completion flag, because the sweep
            // is flag-gated and would otherwise never revisit a completed
            // vault (and on local add/update/delete, where the USER can
            // retry, the registry write IS required).
            if let Err(e) = crate::registry::upsert_equality_tag(
                conn,
                dek,
                entry_id,
                payload.credential_type,
                &payload.password,
                now,
            ) {
                tracing::warn!(entry_id, error = %e, "registry index update failed");
                if let Err(flag_err) = crate::registry::mark_backfill_needed(conn) {
                    tracing::warn!(entry_id, error = %flag_err, "could not re-arm the registry sweep");
                }
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
                    sync_id, sync_version, sync_acked_version, sync_state, last_synced_at, is_deleted
                ) VALUES (1, ?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9, ?10, ?11, ?12, ?13, ?13, 'synced', ?14, 0)",
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
            // and same best-effort REGISTRY-BOUNDARY semantics as the
            // update branch above — WBS-411 review).
            if let Err(e) = crate::registry::upsert_equality_tag(
                conn,
                dek,
                entry_id,
                payload.credential_type,
                &payload.password,
                now,
            ) {
                tracing::warn!(entry_id, error = %e, "registry index update failed");
                if let Err(flag_err) = crate::registry::mark_backfill_needed(conn) {
                    tracing::warn!(entry_id, error = %flag_err, "could not re-arm the registry sweep");
                }
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

        let local: Option<(i64, i64, i64, String)> = conn
            .query_row(
                "SELECT key_id, sync_version, modified_at, sync_state FROM ssh_keys WHERE sync_id = ?1",
                [&sync_id_str],
                |row| Ok((row.get(0)?, row.get(1)?, row.get(2)?, row.get(3)?)),
            )
            .ok();

        if let Some((key_id, local_version, local_modified, local_state)) = local {
            let local = ExistingLocalRow {
                id: key_id,
                version: local_version,
                modified: local_modified,
                state: &local_state,
            };
            if apply_existing_preamble(
                conn,
                local,
                blob,
                "ssh_keys",
                "UPDATE ssh_keys SET is_deleted = 1, deleted_at = ?1,
                 sync_version = ?2, sync_acked_version = ?2, sync_state = 'synced', \
                 last_synced_at = ?1
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
                    sync_version = ?11, sync_acked_version = ?11, sync_state = 'synced', last_synced_at = ?12
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
                    sync_id, sync_version, sync_acked_version, sync_state, last_synced_at, is_deleted
                ) VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9, ?10, ?11, ?12, ?13, ?13, 'synced', ?14, 0)",
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

        let local: Option<(i64, i64, i64, String)> = conn
            .query_row(
                "SELECT totp_id, sync_version, created_at, sync_state FROM totp_secrets WHERE sync_id = ?1",
                [&sync_id_str],
                |row| Ok((row.get(0)?, row.get(1)?, row.get(2)?, row.get(3)?)),
            )
            .ok();

        if let Some((totp_id, local_version, local_created, local_state)) = local {
            let local = ExistingLocalRow {
                id: totp_id,
                version: local_version,
                modified: local_created,
                state: &local_state,
            };
            if apply_existing_preamble(
                conn,
                local,
                blob,
                "totp_secrets",
                "UPDATE totp_secrets SET is_deleted = 1, deleted_at = ?1,
                 sync_version = ?2, sync_acked_version = ?2, sync_state = 'synced', \
                 last_synced_at = ?1
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
                // ordering). WBS-607: this is a DEFERRED apply — the pull
                // retries after the rest of the page and dead-letters the
                // mutation only if still unresolved. It is never a silent
                // skip (the pre-v2 behavior permanently lost the TOTP).
                return Err(PasswordManagerError::SyncDeferred(format!(
                    "TOTP {sync_id_str}: parent credential not present locally yet"
                )));
            };

            let now = chrono::Utc::now().timestamp();
            {
                conn.execute(
                    "UPDATE totp_secrets SET
                        entry_id = ?1, secret_encrypted = ?2, nonce = ?3, auth_tag = ?4,
                        algorithm = ?5, digits = ?6, period = ?7, issuer = ?8, account_name = ?9,
                        sync_version = ?10, sync_acked_version = ?10, sync_state = 'synced', last_synced_at = ?11
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

            let Some(eid) = entry_id else {
                // Deferred, not dropped — see the UPDATE arm above.
                return Err(PasswordManagerError::SyncDeferred(format!(
                    "TOTP {sync_id_str}: parent credential not present locally yet"
                )));
            };
            {
                let now = chrono::Utc::now().timestamp();
                conn.execute(
                    "INSERT INTO totp_secrets (
                        entry_id, secret_encrypted, nonce, auth_tag,
                        algorithm, digits, period, issuer, account_name, created_at,
                        sync_id, sync_version, sync_acked_version, sync_state, last_synced_at, is_deleted
                    ) VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9, ?10, ?11, ?12, ?12, 'synced', ?13, 0)",
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
    use crate::sync::change_tracker::collect_pending_credential_blobs;
    use crate::sync::crypto::encrypt_for_sync;
    use crate::sync::models::CredentialPayload;

    /// A vault-shaped in-memory database: current schema + the
    /// db_metadata identity (vault_uuid, key_epoch) that `read_local_identity`
    /// requires on every apply path.
    pub(crate) fn apply_test_db() -> Database {
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

    pub(crate) fn apply_engine(db: Database) -> (SyncEngine, Arc<Mutex<Database>>) {
        let db = Arc::new(Mutex::new(db));
        let signing_key = ed25519_dalek::SigningKey::from_bytes(&[7u8; 32]);
        // The client is never used by an apply; the URL only has to pass
        // transport validation.
        let client = SyncClient::new("https://relay.invalid", Uuid::new_v4(), signing_key).unwrap();
        let engine = SyncEngine::new(client, db.clone(), Uuid::new_v4());
        (engine, db)
    }

    pub(crate) fn credential_blob(
        dek: &DataEncryptionKey,
        sync_id: Uuid,
        version: u64,
    ) -> SyncEntryBlob {
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

    fn install_fault(
        db: &Database,
        fail_at: usize,
    ) -> crate::database::fault_injection::WriteFaultGuard {
        crate::database::fault_injection::install_write_fault(db.conn(), fail_at)
    }

    fn clear_fault(db: &Database) {
        crate::database::fault_injection::clear_write_fault(db.conn());
    }

    /// THE apply-update fault sweep (SR-DATA-001): one blob = entry UPDATE
    /// + mapping rewrite REQUIRED inside one tx; the registry index write
    /// is best-effort by the REGISTRY-BOUNDARY contract. Phase 1 injects a
    /// denial at every write action: each failure must leave complete-old,
    /// and the first Ok — which, with this fixture's single index INSERT as
    /// the trailing registry write, is the degraded outcome — must have the
    /// change fully applied with a stale index. Phase 2 runs clean and
    /// proves complete-new including the index. (The degraded contract
    /// itself is pinned deterministically by
    /// `remote_apply_registry_failure_degrades_not_skips`, which is the
    /// test that fails if someone re-requires the upsert.)
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

        // --- Phase 1: injected denials -----------------------------------
        let mut fail_at = 0usize;
        let mut injected_failures = 0usize;
        loop {
            let guard = {
                let conn = db.lock().unwrap();
                install_fault(&conn, fail_at)
            };
            let result = {
                let conn = db.lock().unwrap();
                engine.apply_remote_entry(conn.conn(), &dek, &blob)
            };
            {
                let conn = db.lock().unwrap();
                clear_fault(&conn);
            }
            let denied = guard.seen() > fail_at;

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
            let mappings: Vec<String> = {
                let conn = db.lock().unwrap();
                let mut stmt = conn
                    .conn()
                    .prepare("SELECT domain FROM domain_mappings ORDER BY mapping_id")
                    .unwrap();
                let rows = stmt
                    .query_map([], |r| r.get::<_, String>(0))
                    .unwrap()
                    .collect::<std::result::Result<Vec<_>, _>>()
                    .unwrap();
                rows
            };
            let index: i64 = {
                let conn = db.lock().unwrap();
                conn.conn()
                    .query_row("SELECT COUNT(*) FROM secret_equality_index", [], |r| {
                        r.get(0)
                    })
                    .unwrap()
            };

            match result {
                Err(_) => {
                    injected_failures += 1;
                    assert!(
                        denied,
                        "an Err without a denial is a harness bug at write {fail_at}"
                    );
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
                    // First success. Either the denial hit the best-effort
                    // registry write (documented degraded outcome) or it is
                    // a clean run.
                    assert_eq!(version, 4, "applied change is complete at write {fail_at}");
                    assert_eq!(
                        state, "synced",
                        "applied change is complete at write {fail_at}"
                    );
                    assert_eq!(
                        mappings,
                        vec!["applied.example".to_string()],
                        "mapping rewrite committed WITH the row at write {fail_at}"
                    );
                    if denied {
                        assert_eq!(
                            index, 0,
                            "degraded outcome: the denied index write is the ONLY loss"
                        );
                    } else {
                        assert_eq!(index, 1, "clean run: complete-new incl. the index");
                    }
                    if denied {
                        injected_failures += 1;
                    }
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

        // --- Phase 2: the clean run proves complete-new ------------------
        {
            let conn = db.lock().unwrap();
            let entry_id: i64 = conn
                .conn()
                .query_row(
                    "SELECT entry_id FROM entries WHERE sync_id = ?1",
                    [&sync_id.to_string()],
                    |r| r.get(0),
                )
                .unwrap();
            conn.conn()
                .execute("DELETE FROM domain_mappings", [])
                .unwrap();
            conn.conn()
                .execute("DELETE FROM secret_equality_index", [])
                .unwrap();
            conn.conn()
                .execute(
                    "UPDATE entries SET title = X'01', sync_version = 3, sync_state = 'synced' \
                     WHERE entry_id = ?1",
                    [entry_id],
                )
                .unwrap();
            conn.conn()
                .execute(
                    "INSERT INTO domain_mappings (entry_id, domain, is_primary) VALUES (?1, 'old.example', 1)",
                    [entry_id],
                )
                .unwrap();
        }
        {
            let conn = db.lock().unwrap();
            engine.apply_remote_entry(conn.conn(), &dek, &blob).unwrap();
        }
        let (state, version, index): (String, i64, i64) = {
            let conn = db.lock().unwrap();
            let (s, v, e): (String, i64, i64) = conn
                .conn()
                .query_row(
                    "SELECT sync_state, sync_version, entry_id FROM entries WHERE sync_id = ?1",
                    [&sync_id.to_string()],
                    |r| Ok((r.get(0)?, r.get(1)?, r.get(2)?)),
                )
                .unwrap();
            let index: i64 = conn
                .conn()
                .query_row(
                    "SELECT COUNT(*) FROM secret_equality_index WHERE entry_id = ?1",
                    [e],
                    |r| r.get(0),
                )
                .unwrap();
            (s, v, index)
        };
        assert_eq!(version, 4);
        assert_eq!(state, "synced");
        assert_eq!(index, 1, "clean run: complete-new including the index");
    }

    /// The v2 push checkpoint ([`outbox::apply_push_acks`]): the per-object
    /// acked marks + the cursor diagnostic commit together — an injected
    /// failure leaves every row pending with unmoved acked versions.
    #[test]
    fn apply_push_acks_fault_injection_is_all_or_nothing() {
        use crate::sync::v2::{MutationOutcome, ObjectVersion, ServerCursor};

        let db = apply_test_db();
        let ids: Vec<Uuid> = (0..2).map(|_| Uuid::new_v4()).collect();
        {
            let conn = db.conn();
            for id in &ids {
                conn.execute(
                    "INSERT INTO entries (vault_id, title, username, password, credential_type,
                        entry_nonce, auth_tag, created_at, modified_at, favorite,
                        sync_id, sync_version, sync_acked_version, sync_state, is_deleted)
                     VALUES (1, X'01', X'02', X'03', 'password', X'04', X'05', 100, 100, 0,
                             ?1, 1, 0, 'pending', 0)",
                    [&id.to_string()],
                )
                .unwrap();
            }
        }

        let mutations: Vec<outbox::OutboxMutation> = ids
            .iter()
            .map(|id| outbox::OutboxMutation {
                mutation: crate::sync::v2::MutationV2 {
                    mutation_id: Uuid::new_v4(),
                    vault_id: Uuid::new_v4(),
                    object_id: *id,
                    object_type: SyncEntryType::Credential,
                    expected_version: ObjectVersion(0),
                    resulting_version: ObjectVersion(1),
                    key_epoch: 1,
                    origin_device_id: Uuid::new_v4(),
                    is_tombstone: false,
                    encrypted_payload: vec![1, 2, 3],
                    metadata_mac: [0u8; 32],
                },
                object_id: *id,
                object_type: SyncEntryType::Credential,
            })
            .collect();
        let results: Vec<crate::sync::v2::MutationResult> = mutations
            .iter()
            .map(|m| crate::sync::v2::MutationResult {
                mutation_id: m.mutation.mutation_id,
                object_id: m.object_id,
                outcome: MutationOutcome::Applied {
                    resulting_version: ObjectVersion(1),
                    server_sequence: ServerCursor(42),
                },
            })
            .collect();

        let mut fail_at = 0usize;
        let mut injected_failures = 0usize;
        loop {
            install_fault(&db, fail_at);
            let result = outbox::apply_push_acks(db.conn(), &mutations, &results, 42);
            clear_fault(&db);

            let (pending, acked): (i64, i64) = {
                let conn = db.conn();
                conn.query_row(
                    "SELECT \
                         (SELECT COUNT(*) FROM entries WHERE sync_state = 'pending'), \
                         (SELECT COUNT(*) FROM entries WHERE sync_acked_version = 1)",
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
                    assert_eq!(acked, 0, "complete-old at write {fail_at}");
                    assert_eq!(cursor, 0, "complete-old: cursor unmoved at write {fail_at}");
                }
                Ok(summary) => {
                    assert_eq!(summary.applied, 2);
                    assert_eq!(pending, 0, "complete-new at write {fail_at}");
                    assert_eq!(acked, 2, "complete-new at write {fail_at}");
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
    pub(crate) fn insert_pending_with_optionals(
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

    /// The typed-contract pin: Some("") must NOT be coerced to NULL or
    /// absence anywhere in the chain (no Some->None loss). The removed
    /// apply-side `.filter` was inert against today's sealed blobs, but
    /// this test keeps the contract honest if coercion ever returns.
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

#[cfg(test)]
mod registry_boundary_tests {
    use super::tests::{apply_engine, apply_test_db, credential_blob};
    use crate::crypto::cipher::DataEncryptionKey;
    use crate::database::fault_injection;
    use uuid::Uuid;

    /// THE degraded-contract pin (WBS-411 review): a registry-index failure
    /// during a remote apply must NOT skip the delivered change. The entry
    /// and its mappings are applied (the atomic unit), the index degrades,
    /// and the sweep repairs it — the pre-existing alternative (skipping
    /// the blob) is permanent loss, because the relay never re-serves a
    /// consumed sequence (docs/SYNC.md).
    #[test]
    fn remote_apply_registry_failure_degrades_not_skips() {
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
        }

        let blob = credential_blob(&dek, sync_id, 4);
        let guard = {
            let conn = db.lock().unwrap();
            fault_injection::install_write_fault_on_table(conn.conn(), 0, "secret_equality_index")
        };
        let result = {
            let conn = db.lock().unwrap();
            engine.apply_remote_entry(conn.conn(), &dek, &blob)
        };
        {
            let conn = db.lock().unwrap();
            fault_injection::clear_write_fault(conn.conn());
        }

        // The apply SUCCEEDS despite the denied index write.
        assert!(
            result.is_ok(),
            "a registry failure must not drop the change"
        );
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
        assert_eq!(version, 4, "the delivered change is applied");
        assert_eq!(state, "synced");
        // The index is degraded (denied), pending sweep repair.
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
        assert_eq!(index, 0, "the denied index write is the degradation");
        assert!(
            guard.seen() >= 1,
            "the index write must have been attempted"
        );
    }
}

/// Engine-level v2 acceptance tests against an in-memory relay MODEL that
/// mirrors the shipped relay's semantics (CAS guard + durable idempotent
/// results + append-only log) — SR-SYNC-001/003 acceptance evidence with no
/// HTTP in the loop.
#[cfg(all(test, feature = "sync"))]
mod v2_cycle_tests {
    use super::tests::{apply_test_db, credential_blob};
    use super::*;
    use crate::sync::crypto::encrypt_for_sync;
    use crate::sync::v2::{
        MutationOutcome, ObjectVersion, PullRequestV2, PullResponseV2, RejectionReason,
    };
    use std::collections::HashMap;
    use std::future::Future;
    use std::pin::Pin;

    // --- in-memory relay model ----------------------------------------------

    #[derive(Clone)]
    struct ObjectState {
        version: u64,
    }

    #[derive(Clone, Default)]
    struct Model {
        vault: Option<Uuid>,
        objects: HashMap<(Uuid, Uuid), ObjectState>,
        results: HashMap<(Uuid, Uuid), crate::sync::v2::MutationResult>,
        /// (server_sequence, mutation) — the append-only vault log the pull
        /// serves by cursor.
        log: Vec<(i64, crate::sync::v2::MutationV2)>,
        counter: u64,
    }

    /// Shareable fake relay implementing the v2 semantics the shipped relay
    /// enforces: idempotency (duplicates replay the ORIGINAL durable
    /// result), CAS acceptance, append-only log.
    #[derive(Clone, Default)]
    struct FakeRelay {
        model: Arc<Mutex<Model>>,
        /// Drop the NEXT push response AFTER committing (lost-response fault).
        drop_next_push_response: Arc<std::sync::atomic::AtomicBool>,
        seen_pushes: Arc<Mutex<Vec<Vec<Uuid>>>>,
    }

    impl FakeRelay {
        fn new() -> Self {
            Self::default()
        }

        fn set_vault(&self, vault: Uuid) {
            self.model.lock().unwrap().vault = Some(vault);
        }

        /// Simulate a PEER's applied mutation: object state AND a log entry
        /// pull can serve (so pull-apply is exercised end to end).
        fn seed_peer_mutation(&self, mutation: crate::sync::v2::MutationV2) {
            let mut model = self.model.lock().unwrap();
            model.counter += 1;
            let seq = model.counter as i64;
            model.objects.insert(
                (mutation.vault_id, mutation.object_id),
                ObjectState {
                    version: mutation.resulting_version.as_u64(),
                },
            );
            model.log.push((seq, mutation));
        }

        fn log_len(&self) -> usize {
            self.model.lock().unwrap().log.len()
        }
    }

    impl SyncTransport for FakeRelay {
        fn push_v2<'a>(
            &'a self,
            request: &'a crate::sync::v2::PushRequestV2,
        ) -> Pin<Box<dyn Future<Output = Result<crate::sync::v2::PushResponseV2>> + Send + 'a>>
        {
            Box::pin(async move {
                let mut model = self.model.lock().unwrap();
                self.seen_pushes
                    .lock()
                    .unwrap()
                    .push(request.mutations.iter().map(|m| m.mutation_id).collect());

                let mut results = Vec::with_capacity(request.mutations.len());
                for m in &request.mutations {
                    if Some(m.vault_id) != model.vault {
                        return Err(PasswordManagerError::InvalidInput(
                            "vault mismatch".to_string(),
                        ));
                    }
                    // Idempotency: duplicates return the ORIGINAL result
                    // (scoped per device, as on the shipped relay).
                    let result_key = (m.origin_device_id, m.mutation_id);
                    if let Some(stored) = model.results.get(&result_key) {
                        results.push(stored.clone());
                        continue;
                    }
                    let key = (m.vault_id, m.object_id);
                    let outcome = match model.objects.get(&key) {
                        Some(state) => {
                            if state.version == m.expected_version.as_u64() {
                                MutationOutcome::Applied {
                                    resulting_version: m.resulting_version,
                                    server_sequence: ServerCursor(model.counter),
                                }
                            } else {
                                MutationOutcome::Rejected {
                                    reason: RejectionReason::VersionConflict {
                                        current_version: ObjectVersion(state.version),
                                    },
                                }
                            }
                        }
                        None => {
                            if m.expected_version.as_u64() == 0 {
                                MutationOutcome::Applied {
                                    resulting_version: m.resulting_version,
                                    server_sequence: ServerCursor(model.counter),
                                }
                            } else {
                                MutationOutcome::Rejected {
                                    reason: RejectionReason::VersionConflict {
                                        current_version: ObjectVersion(0),
                                    },
                                }
                            }
                        }
                    };
                    if matches!(outcome, MutationOutcome::Applied { .. }) {
                        model.counter += 1;
                        let seq = model.counter as i64;
                        model.log.push((seq, m.clone()));
                        model.objects.insert(
                            key,
                            ObjectState {
                                version: m.resulting_version.as_u64(),
                            },
                        );
                    }
                    model.results.insert(
                        result_key,
                        crate::sync::v2::MutationResult {
                            mutation_id: m.mutation_id,
                            object_id: m.object_id,
                            outcome: outcome.clone(),
                        },
                    );
                    results.push(crate::sync::v2::MutationResult {
                        mutation_id: m.mutation_id,
                        object_id: m.object_id,
                        outcome,
                    });
                }
                let server_cursor = ServerCursor(model.counter);

                if self
                    .drop_next_push_response
                    .swap(false, std::sync::atomic::Ordering::SeqCst)
                {
                    // The relay COMMITTED (the model mutated above) but the
                    // client never sees the response.
                    return Err(PasswordManagerError::Io(std::io::Error::other(
                        "simulated lost response",
                    )));
                }

                Ok(crate::sync::v2::PushResponseV2 {
                    server_cursor,
                    results,
                })
            })
        }

        fn pull_v2<'a>(
            &'a self,
            request: &'a PullRequestV2,
        ) -> Pin<Box<dyn Future<Output = Result<PullResponseV2>> + Send + 'a>> {
            Box::pin(async move {
                let model = self.model.lock().unwrap();
                let limit = request.limit.unwrap_or(500) as usize;
                let entries: Vec<crate::sync::v2::MutationLogEntry> = model
                    .log
                    .iter()
                    .filter(|(seq, _)| (*seq as u64) > request.since.as_u64())
                    .take(limit + 1)
                    .map(|(seq, m)| crate::sync::v2::MutationLogEntry {
                        server_sequence: ServerCursor(*seq as u64),
                        mutation: m.clone(),
                    })
                    .collect();
                let has_more = entries.len() > limit;
                let entries: Vec<crate::sync::v2::MutationLogEntry> =
                    entries.into_iter().take(limit).collect();
                let cursor = entries
                    .last()
                    .map(|e| e.server_sequence)
                    .unwrap_or(request.since);
                Ok(PullResponseV2 {
                    entries,
                    cursor,
                    has_more,
                })
            })
        }
    }

    // --- fixtures -------------------------------------------------------------

    /// A pending credential row the COLLECTOR can actually read (legacy
    /// v1-shape field blobs — the collector's dual-read opens them), with
    /// explicit sync bookkeeping: `version` = the local (resulting) version,
    /// `acked` = the last version the relay acknowledged.
    fn insert_collectable_pending(
        dek: &DataEncryptionKey,
        conn: &rusqlite::Connection,
        sync_id: &Uuid,
        version: i64,
        acked: i64,
    ) {
        use super::tests::insert_pending_with_optionals;
        insert_pending_with_optionals(conn, dek, Some("https://pending.example"), None);
        conn.execute(
            "UPDATE entries SET sync_id = ?1, sync_version = ?2, sync_acked_version = ?3",
            rusqlite::params![sync_id.to_string(), version, acked],
        )
        .unwrap();
    }

    fn row_bookkeeping(db: &Mutex<Database>, sync_id: &Uuid) -> (String, i64) {
        let (state, acked, _) = row_bookkeeping_full(db, sync_id);
        (state, acked)
    }

    fn row_bookkeeping_full(db: &Mutex<Database>, sync_id: &Uuid) -> (String, i64, i64) {
        let conn = db.lock().unwrap();
        conn.conn()
            .query_row(
                "SELECT sync_state, sync_acked_version, sync_version FROM entries \
                 WHERE sync_id = ?1",
                [sync_id.to_string()],
                |r| Ok((r.get(0)?, r.get(1)?, r.get(2)?)),
            )
            .unwrap()
    }

    // --- acceptance -----------------------------------------------------------

    /// THE lost-response acceptance (SR-SYNC-001): the relay committed the
    /// push but the response was lost. The retry re-derives the SAME
    /// mutation ids, the relay replays the ORIGINAL results, the outbox
    /// completes, and the relay log holds exactly ONE copy of the mutation —
    /// the v1 device_sequence wedge is structurally impossible.
    #[tokio::test]
    async fn lost_push_response_retry_completes_without_wedge() {
        let dek = DataEncryptionKey::new().unwrap();
        let relay_vault = Uuid::new_v4();
        let device = Uuid::new_v4();
        let sync_id = Uuid::new_v4();

        let db = apply_test_db();
        vault_config(&db, relay_vault, device);
        // A never-synced row: local v2, never acked (expected 0 → create).
        insert_collectable_pending(&dek, db.conn(), &sync_id, 2, 0);

        let relay = FakeRelay::new();
        relay.set_vault(relay_vault);
        let db = Arc::new(Mutex::new(db));
        let engine = SyncEngine::new(relay.clone(), db.clone(), device);

        // First cycle: the push COMMITS relay-side, the response is lost.
        relay
            .drop_next_push_response
            .store(true, std::sync::atomic::Ordering::SeqCst);
        let outcome = engine.sync(&dek).await;
        assert!(outcome.is_err(), "the lost response surfaces as an error");
        assert_eq!(relay.log_len(), 1, "the relay committed the mutation");
        let (state, acked) = row_bookkeeping(&db, &sync_id);
        assert_eq!(state, "pending", "no ack was seen — the row stays pending");
        assert_eq!(acked, 0);

        // Retry cycle: same mutation id, original result replayed, outbox
        // completes.
        engine.sync(&dek).await.unwrap();
        assert_eq!(relay.log_len(), 1, "no duplicate data in the log");
        let (state, acked) = row_bookkeeping(&db, &sync_id);
        assert_eq!(
            state, "synced",
            "the retried mutation completed the outbox entry"
        );
        assert_eq!(acked, 2, "acked version advanced to the resulting version");

        let pushes = relay.seen_pushes.lock().unwrap();
        assert_eq!(pushes.len(), 2);
        assert_eq!(
            pushes[0], pushes[1],
            "the retry must reuse the identical mutation ids"
        );
    }

    /// SR-SYNC-005 (WBS-611): a push conflict where the relay is AT OR
    /// BEYOND our attempt NEVER silently adopts the relay state — the row is
    /// marked conflicted, the same-run pull stores the peer's content as the
    /// durable alternative, and keep-local resolution re-versions the local
    /// content above the peer so the next push lands cleanly. Both
    /// alternatives were preserved and user resolution drives convergence.
    #[tokio::test]
    async fn conflict_preserves_alternatives_and_resolves_keep_local() {
        let dek = DataEncryptionKey::new().unwrap();
        let relay_vault = Uuid::new_v4();
        let device = Uuid::new_v4();
        let sync_id = Uuid::new_v4();

        let db = apply_test_db();
        vault_config(&db, relay_vault, device);
        insert_collectable_pending(&dek, db.conn(), &sync_id, 3, 1);

        let relay = FakeRelay::new();
        relay.set_vault(relay_vault);
        // A peer's edit won: object at v4, WITH a log entry pull can serve.
        let peer_mutation = crate::sync::v2::build_mutation(
            &crate::sync::v2::derive_metadata_mac_key(&dek).unwrap(),
            &crate::sync::v2::MutationInput {
                vault_id: relay_vault,
                object_id: sync_id,
                object_type: SyncEntryType::Credential,
                expected_version: ObjectVersion(2),
                resulting_version: ObjectVersion(4),
                key_epoch: 1,
                origin_device_id: Uuid::new_v4(),
                is_tombstone: false,
                encrypted_payload: {
                    let payload = CredentialPayload {
                        title: "Peer Title".to_string(),
                        username: "peer-user".to_string(),
                        password: Zeroizing::new("peer-pass".to_string()),
                        credential_type: crate::CredentialType::Password,
                        url: None,
                        notes: None,
                        favorite: false,
                        domains: vec![],
                        created_at: 1_700_000_000,
                        modified_at: 1_700_000_200,
                    };
                    encrypt_for_sync(&dek, &Zeroizing::new(serde_json::to_vec(&payload).unwrap()))
                        .unwrap()
                },
            },
        )
        .unwrap();
        relay.seed_peer_mutation(peer_mutation);

        let db = Arc::new(Mutex::new(db));
        let engine = SyncEngine::new(relay.clone(), db.clone(), device);

        engine.sync(&dek).await.unwrap();
        let (state, acked, version) = row_bookkeeping_full(&db, &sync_id);
        assert_eq!(state, "conflict", "the row is conflicted, never adopted");
        assert_eq!(acked, 1, "acked untouched — the local edit is preserved");
        assert_eq!(version, 3, "the LOCAL content stays in the row");
        let conflicts: Vec<(i64, String)> = {
            let conn = db.lock().unwrap();
            let mut stmt = conn
                .conn()
                .prepare("SELECT remote_version, object_id FROM sync_conflicts")
                .unwrap();
            stmt.query_map([], |r| Ok((r.get(0)?, r.get(1)?)))
                .unwrap()
                .collect::<std::result::Result<Vec<_>, _>>()
                .unwrap()
        };
        assert_eq!(conflicts.len(), 1, "the alternative is durably stored");
        assert_eq!(conflicts[0].0, 4, "the alternative is the peer's v4");

        // KEEP-LOCAL resolution: re-version above the peer, re-base CAS.
        {
            let conn = db.lock().unwrap();
            resolve_conflict_keep_local(conn.conn(), &sync_id, SyncEntryType::Credential, 4)
                .unwrap();
        }
        let (state, acked, version) = row_bookkeeping_full(&db, &sync_id);
        assert_eq!(state, "pending");
        assert_eq!(acked, 4, "CAS expectation re-based onto the peer's version");
        assert_eq!(version, 5, "local content re-versioned above the peer");

        // The next push applies the LOCAL content (CAS 4 == 4).
        engine.sync(&dek).await.unwrap();
        let (state, acked) = row_bookkeeping(&db, &sync_id);
        assert_eq!(state, "synced");
        assert_eq!(acked, 5);
        assert_eq!(relay.log_len(), 2, "peer v4 + our resolved v5");
        let our_v4_overwrites = relay.model.lock().unwrap().log.iter().any(|(_, m)| {
            m.object_id == sync_id
                && m.resulting_version.as_u64() == 4
                && m.origin_device_id == device
        });
        assert!(
            !our_v4_overwrites,
            "the peer's v4 was not overwritten by a fabricated v4 — ours is v5"
        );
    }

    /// TAKE-REMOTE resolution: the stored alternative is applied through the
    /// normal path (sealing under the LOCAL identity), the local edit is
    /// discarded per the user's choice, and the record is removed.
    #[tokio::test]
    async fn conflict_take_remote_applies_the_alternative() {
        let dek = DataEncryptionKey::new().unwrap();
        let relay_vault = Uuid::new_v4();
        let device = Uuid::new_v4();
        let sync_id = Uuid::new_v4();

        let db = apply_test_db();
        vault_config(&db, relay_vault, device);
        insert_collectable_pending(&dek, db.conn(), &sync_id, 3, 1);

        let relay = FakeRelay::new();
        relay.set_vault(relay_vault);
        let peer_payload = {
            let payload = CredentialPayload {
                title: "Peer Title".to_string(),
                username: "peer-user".to_string(),
                password: Zeroizing::new("peer-pass".to_string()),
                credential_type: crate::CredentialType::Password,
                url: None,
                notes: None,
                favorite: false,
                domains: vec![],
                created_at: 1_700_000_000,
                modified_at: 1_700_000_200,
            };
            encrypt_for_sync(&dek, &Zeroizing::new(serde_json::to_vec(&payload).unwrap())).unwrap()
        };
        let peer_mutation = crate::sync::v2::build_mutation(
            &crate::sync::v2::derive_metadata_mac_key(&dek).unwrap(),
            &crate::sync::v2::MutationInput {
                vault_id: relay_vault,
                object_id: sync_id,
                object_type: SyncEntryType::Credential,
                expected_version: ObjectVersion(2),
                resulting_version: ObjectVersion(4),
                key_epoch: 1,
                origin_device_id: Uuid::new_v4(),
                is_tombstone: false,
                encrypted_payload: peer_payload.clone(),
            },
        )
        .unwrap();
        relay.seed_peer_mutation(peer_mutation);

        let db = Arc::new(Mutex::new(db));
        let engine = SyncEngine::new(relay.clone(), db.clone(), device);
        engine.sync(&dek).await.unwrap();
        assert_eq!(row_bookkeeping_full(&db, &sync_id).0, "conflict");

        // TAKE REMOTE.
        {
            let conn = db.lock().unwrap();
            let (remote_version, payload, origin): (i64, Vec<u8>, String) = conn
                .conn()
                .query_row(
                    "SELECT remote_version, remote_payload, origin_device_id FROM sync_conflicts \
                     WHERE object_id = ?1",
                    [&sync_id.to_string()],
                    |r| Ok((r.get(0)?, r.get(1)?, r.get(2)?)),
                )
                .unwrap();
            resolve_conflict_take_remote(
                &engine,
                conn.conn(),
                &dek,
                &sync_id,
                &ConflictAlternative {
                    entry_type: SyncEntryType::Credential,
                    remote_version: remote_version as u64,
                    payload,
                    origin: Uuid::parse_str(&origin).unwrap(),
                    is_tombstone: false,
                },
            )
            .unwrap();
        }

        let (state, acked, version) = row_bookkeeping_full(&db, &sync_id);
        assert_eq!(state, "synced", "the alternative applied");
        assert_eq!(acked, 4);
        assert_eq!(version, 4);
        let conflicts: i64 = db
            .lock()
            .unwrap()
            .conn()
            .query_row("SELECT COUNT(*) FROM sync_conflicts", [], |r| r.get(0))
            .unwrap();
        assert_eq!(conflicts, 0, "the record is consumed by resolution");
    }

    /// THE pull-then-edit acceptance (reviewer finding 1): a peer's mutation
    /// applies locally (recording the relay's acked version), the local row
    /// is edited, and the NEXT push CASes against the pull-learned version —
    /// not 0 — so peer-sourced objects are editable without wedging.
    #[tokio::test]
    async fn pull_then_edit_push_succeeds() {
        let dek = DataEncryptionKey::new().unwrap();
        let relay_vault = Uuid::new_v4();
        let device_a = Uuid::new_v4();
        let device_b = Uuid::new_v4();
        let sync_id = Uuid::new_v4();

        let relay = FakeRelay::new();
        relay.set_vault(relay_vault);

        // Device A owns the row and pushes it.
        let db_a = apply_test_db();
        vault_config(&db_a, relay_vault, device_a);
        insert_collectable_pending(&dek, db_a.conn(), &sync_id, 1, 0);
        let db_a = Arc::new(Mutex::new(db_a));
        let engine_a = SyncEngine::new(relay.clone(), db_a.clone(), device_a);
        engine_a.sync(&dek).await.unwrap();

        // Device B pulls A's mutation, then edits the row locally.
        let db_b = apply_test_db();
        vault_config(&db_b, relay_vault, device_b);
        let db_b = Arc::new(Mutex::new(db_b));
        let engine_b = SyncEngine::new(relay.clone(), db_b.clone(), device_b);
        engine_b.sync(&dek).await.unwrap();
        let (b_state, b_acked) = row_bookkeeping(&db_b, &sync_id);
        assert_eq!(b_state, "synced", "B applied A's mutation");
        assert_eq!(b_acked, 1, "the apply recorded the relay's acked version");
        {
            let conn = db_b.lock().unwrap();
            // Repository-edit shape: content bump + version bump + pending.
            conn.conn()
                .execute(
                    "UPDATE entries SET sync_version = sync_version + 1, \
                     sync_state = 'pending' WHERE sync_id = ?1",
                    [&sync_id.to_string()],
                )
                .unwrap();
        }

        // B pushes its edit: CAS must expect the PULLED version (1), not 0.
        engine_b.sync(&dek).await.unwrap();
        let (b_state, b_acked) = row_bookkeeping(&db_b, &sync_id);
        assert_eq!(b_state, "synced", "B's edit applied on top of A's version");
        assert_eq!(b_acked, 2);
        assert_eq!(relay.log_len(), 2, "both devices' mutations are in the log");
    }

    /// THE lost-response-then-edit acceptance (reviewer finding 2, attack A):
    /// the relay committed v2 but the response was lost, and the user edited
    /// (v3) before the retry. The rejected M(3) re-bases the row onto the
    /// relay's current version with a FRESH id; the next cycle applies —
    /// no permanent wedge.
    #[tokio::test]
    async fn lost_response_then_edit_recovers() {
        let dek = DataEncryptionKey::new().unwrap();
        let relay_vault = Uuid::new_v4();
        let device = Uuid::new_v4();
        let sync_id = Uuid::new_v4();

        let db = apply_test_db();
        vault_config(&db, relay_vault, device);
        insert_collectable_pending(&dek, db.conn(), &sync_id, 2, 0);

        let relay = FakeRelay::new();
        relay.set_vault(relay_vault);
        let db = Arc::new(Mutex::new(db));
        let engine = SyncEngine::new(relay.clone(), db.clone(), device);

        // Cycle 1: relay commits v2; the response is lost.
        relay
            .drop_next_push_response
            .store(true, std::sync::atomic::Ordering::SeqCst);
        assert!(engine.sync(&dek).await.is_err());

        // The user edits before the retry: row moves to v3 (repository bump).
        {
            let conn = db.lock().unwrap();
            conn.conn()
                .execute(
                    "UPDATE entries SET sync_version = sync_version + 1, \
                     sync_state = 'pending' WHERE sync_id = ?1",
                    [&sync_id.to_string()],
                )
                .unwrap();
        }

        // Cycle 2: M(3) expects 0, relay holds 2 → conflict BEHIND our
        // attempt → the row re-bases (acked 2, version 4).
        engine.sync(&dek).await.unwrap();
        let (state, acked, version) = row_bookkeeping_full(&db, &sync_id);
        assert_eq!(state, "pending");
        assert_eq!(acked, 2, "learned the relay's current version");
        assert_eq!(version, 4, "re-versioned past the attempted 3");

        // Cycle 3: fresh mutation M(4), expected 2 → applies.
        engine.sync(&dek).await.unwrap();
        let (state, acked, version) = row_bookkeeping_full(&db, &sync_id);
        assert_eq!(state, "synced", "the fresh mutation completed");
        assert_eq!(acked, 4);
        assert_eq!(version, 4);
        assert_eq!(relay.log_len(), 2, "v2 (lost response) + v4 (recovered)");
    }

    fn vault_config(db: &Database, relay_vault: Uuid, device: Uuid) {
        vault_config_with_protocol(
            db,
            relay_vault,
            device,
            crate::sync::config::SYNC_PROTOCOL_VERSION,
        );
    }

    fn vault_config_with_protocol(db: &Database, relay_vault: Uuid, device: Uuid, protocol: u32) {
        let config = SyncConfig {
            sync_enabled: true,
            vault_id: Some(relay_vault),
            device_id: Some(device),
            device_name: Some("test".to_string()),
            relay_url: Some("https://relay.invalid".to_string()),
            last_push_sequence: 0,
            last_pull_sequence: 0,
            last_sync_at: None,
            protocol_version: protocol,
        };
        config.save(db.conn()).unwrap();
    }

    /// THE mixed-protocol fail-closed duty (ADR-006), applied early: a
    /// v1-era configuration (protocol_version != 2) refuses to sync at all.
    /// Without this gate an upgraded client would push v2 mutations into
    /// the old vault's EMPTY v2 tables — a parallel universe the v1 peers
    /// never see (silent split-brain).
    #[tokio::test]
    async fn legacy_protocol_configuration_refuses_to_sync() {
        let dek = DataEncryptionKey::new().unwrap();
        let relay_vault = Uuid::new_v4();
        let device = Uuid::new_v4();
        let sync_id = Uuid::new_v4();

        let db = apply_test_db();
        vault_config_with_protocol(&db, relay_vault, device, 0);
        insert_collectable_pending(&dek, db.conn(), &sync_id, 2, 0);

        let relay = FakeRelay::new();
        relay.set_vault(relay_vault);
        let db = Arc::new(Mutex::new(db));
        let engine = SyncEngine::new(relay.clone(), db.clone(), device);

        let outcome = engine.sync(&dek).await;
        assert!(outcome.is_err(), "a v1-era config must refuse to sync");
        let message = outcome.unwrap_err().to_string();
        assert!(
            message.contains("protocol"),
            "the refusal must name the protocol gate: {message}"
        );
        assert_eq!(
            relay.log_len(),
            0,
            "no v2 mutation may reach the relay from a legacy configuration"
        );
        let (state, _) = row_bookkeeping(&db, &sync_id);
        assert_eq!(state, "pending", "the row is untouched");
    }

    // --- WBS-607: bounded dead-letter + atomic pull pages -------------------

    /// A peer mutation whose payload cannot be decrypted is DEAD-LETTERED
    /// (durable disposition) while the rest of the page applies; the cursor
    /// advances past it with the disposition recorded, so the poison never
    /// wedges a later sync.
    #[tokio::test]
    async fn unappliable_mutation_is_dead_lettered_and_page_advances() {
        let dek = DataEncryptionKey::new().unwrap();
        let relay_vault = Uuid::new_v4();
        let device = Uuid::new_v4();
        let good_id = Uuid::new_v4();

        let db = apply_test_db();
        vault_config(&db, relay_vault, device);

        let relay = FakeRelay::new();
        relay.set_vault(relay_vault);
        // Poison first (undecryptable payload), good mutation after it.
        relay.seed_peer_mutation(
            crate::sync::v2::build_mutation(
                &crate::sync::v2::derive_metadata_mac_key(&dek).unwrap(),
                &crate::sync::v2::MutationInput {
                    vault_id: relay_vault,
                    object_id: Uuid::new_v4(),
                    object_type: SyncEntryType::Credential,
                    expected_version: ObjectVersion(0),
                    resulting_version: ObjectVersion(1),
                    key_epoch: 1,
                    origin_device_id: Uuid::new_v4(),
                    is_tombstone: false,
                    encrypted_payload: vec![0xFF; 64],
                },
            )
            .unwrap(),
        );
        relay.seed_peer_mutation(
            crate::sync::v2::build_mutation(
                &crate::sync::v2::derive_metadata_mac_key(&dek).unwrap(),
                &crate::sync::v2::MutationInput {
                    vault_id: relay_vault,
                    object_id: good_id,
                    object_type: SyncEntryType::Credential,
                    expected_version: ObjectVersion(0),
                    resulting_version: ObjectVersion(1),
                    key_epoch: 1,
                    origin_device_id: Uuid::new_v4(),
                    is_tombstone: false,
                    encrypted_payload: {
                        let payload = CredentialPayload {
                            title: "Good".to_string(),
                            username: "u".to_string(),
                            password: Zeroizing::new("p".to_string()),
                            credential_type: crate::CredentialType::Password,
                            url: None,
                            notes: None,
                            favorite: false,
                            domains: vec![],
                            created_at: 1,
                            modified_at: 1,
                        };
                        encrypt_for_sync(
                            &dek,
                            &Zeroizing::new(serde_json::to_vec(&payload).unwrap()),
                        )
                        .unwrap()
                    },
                },
            )
            .unwrap(),
        );

        let db = Arc::new(Mutex::new(db));
        let engine = SyncEngine::new(relay.clone(), db.clone(), device);
        engine.sync(&dek).await.unwrap();

        // The poison has a durable disposition; the good row applied.
        let (dead_lettered, seq): (i64, i64) = {
            let conn = db.lock().unwrap();
            conn.conn()
                .query_row(
                    "SELECT COUNT(*), COALESCE(MIN(server_sequence), 0) FROM sync_dead_letter",
                    [],
                    |r| Ok((r.get(0)?, r.get(1)?)),
                )
                .unwrap()
        };
        assert_eq!(dead_lettered, 1);
        assert_eq!(
            seq, 1,
            "the poison's server_sequence is the disposition key"
        );
        let (state, _) = row_bookkeeping(&db, &good_id);
        assert_eq!(
            state, "synced",
            "the good mutation applied in the same page"
        );
        let cursor = SyncConfig::load(db.lock().unwrap().conn())
            .unwrap()
            .last_pull_sequence;
        assert_eq!(
            cursor, 2,
            "the cursor advanced past the dispositioned poison"
        );

        // A follow-up sync is not wedged: nothing new, nothing re-fetched.
        engine.sync(&dek).await.unwrap();
        assert_eq!(relay.log_len(), 2);
    }

    /// The order-dependent case: a TOTP whose parent credential arrives
    /// LATER in the page. Pass 1 defers it; the bounded requeue pass (after
    /// the credential applied) resolves it — both land in ONE run, and
    /// nothing is dead-lettered. (Pre-v2 this was a permanent silent loss.)
    #[tokio::test]
    async fn deferred_totp_parent_resolves_within_one_run() {
        use crate::sync::models::TotpPayload;
        let dek = DataEncryptionKey::new().unwrap();
        let relay_vault = Uuid::new_v4();
        let device = Uuid::new_v4();
        let parent_id = Uuid::new_v4();
        let totp_id = Uuid::new_v4();

        let db = apply_test_db();
        vault_config(&db, relay_vault, device);

        let relay = FakeRelay::new();
        relay.set_vault(relay_vault);

        let totp_mutation = crate::sync::v2::build_mutation(
            &crate::sync::v2::derive_metadata_mac_key(&dek).unwrap(),
            &crate::sync::v2::MutationInput {
                vault_id: relay_vault,
                object_id: totp_id,
                object_type: SyncEntryType::TotpSecret,
                expected_version: ObjectVersion(0),
                resulting_version: ObjectVersion(1),
                key_epoch: 1,
                origin_device_id: Uuid::new_v4(),
                is_tombstone: false,
                encrypted_payload: {
                    let payload = TotpPayload {
                        secret: Zeroizing::new("JBSWY3DPEHPK3PXP".to_string()),
                        secret_encrypted: None,
                        legacy_nonce: None,
                        legacy_auth_tag: None,
                        algorithm: "SHA1".to_string(),
                        digits: 6,
                        period: 30,
                        issuer: None,
                        account_name: None,
                        created_at: 1,
                        parent_credential_sync_id: Some(parent_id),
                    };
                    encrypt_for_sync(&dek, &Zeroizing::new(serde_json::to_vec(&payload).unwrap()))
                        .unwrap()
                },
            },
        )
        .unwrap();
        let parent_mutation = crate::sync::v2::build_mutation(
            &crate::sync::v2::derive_metadata_mac_key(&dek).unwrap(),
            &crate::sync::v2::MutationInput {
                vault_id: relay_vault,
                object_id: parent_id,
                object_type: SyncEntryType::Credential,
                expected_version: ObjectVersion(0),
                resulting_version: ObjectVersion(1),
                key_epoch: 1,
                origin_device_id: Uuid::new_v4(),
                is_tombstone: false,
                encrypted_payload: {
                    let payload = CredentialPayload {
                        title: "Parent".to_string(),
                        username: "u".to_string(),
                        password: Zeroizing::new("p".to_string()),
                        credential_type: crate::CredentialType::Password,
                        url: None,
                        notes: None,
                        favorite: false,
                        domains: vec![],
                        created_at: 1,
                        modified_at: 1,
                    };
                    encrypt_for_sync(&dek, &Zeroizing::new(serde_json::to_vec(&payload).unwrap()))
                        .unwrap()
                },
            },
        )
        .unwrap();
        // TOTP FIRST (deferred in pass 1), parent SECOND.
        relay.seed_peer_mutation(totp_mutation);
        relay.seed_peer_mutation(parent_mutation);

        let db = Arc::new(Mutex::new(db));
        let engine = SyncEngine::new(relay.clone(), db.clone(), device);
        engine.sync(&dek).await.unwrap();

        let conn = db.lock().unwrap();
        let (parent_state, totp_count, dead_lettered): (String, i64, i64) = conn
            .conn()
            .query_row(
                "SELECT (SELECT sync_state FROM entries WHERE sync_id = ?1), \
                        (SELECT COUNT(*) FROM totp_secrets WHERE sync_id = ?2), \
                        (SELECT COUNT(*) FROM sync_dead_letter)",
                rusqlite::params![parent_id.to_string(), totp_id.to_string()],
                |r| Ok((r.get(0)?, r.get(1)?, r.get(2)?)),
            )
            .unwrap();
        assert_eq!(parent_state, "synced");
        assert_eq!(
            totp_count, 1,
            "the deferred TOTP resolved in the requeue pass"
        );
        assert_eq!(dead_lettered, 0, "nothing needed a dead-letter disposition");
    }

    /// THE dead-letter bound is fail-closed (ADR-006: bounded disposition
    /// state): at the cap, the page — cursor included — rolls back and sync
    /// errors; after the user purges a row, the same page applies cleanly.
    #[tokio::test]
    async fn dead_letter_cap_fails_closed_until_purged() {
        let dek = DataEncryptionKey::new().unwrap();
        let relay_vault = Uuid::new_v4();
        let device = Uuid::new_v4();
        let good_id = Uuid::new_v4();

        let db = apply_test_db();
        vault_config(&db, relay_vault, device);
        {
            let conn = db.conn();
            // Pre-fill the dead-letter to exactly the cap (distinct PK space
            // from the fake's sequences).
            for i in 0..MAX_DEAD_LETTER {
                conn.execute(
                    "INSERT INTO sync_dead_letter (server_sequence, mutation_id, object_id, \
                        object_type, reason, received_at) \
                     VALUES (?1, 'm', 'o', 'Credential', 'seeded', 1)",
                    [MAX_DEAD_LETTER as i64 + 10_000 + i as i64],
                )
                .unwrap();
            }
        }

        let relay = FakeRelay::new();
        relay.set_vault(relay_vault);
        relay.seed_peer_mutation(
            crate::sync::v2::build_mutation(
                &crate::sync::v2::derive_metadata_mac_key(&dek).unwrap(),
                &crate::sync::v2::MutationInput {
                    vault_id: relay_vault,
                    object_id: Uuid::new_v4(),
                    object_type: SyncEntryType::Credential,
                    expected_version: ObjectVersion(0),
                    resulting_version: ObjectVersion(1),
                    key_epoch: 1,
                    origin_device_id: Uuid::new_v4(),
                    is_tombstone: false,
                    encrypted_payload: vec![0xEE; 64],
                },
            )
            .unwrap(),
        );

        let db = Arc::new(Mutex::new(db));
        let engine = SyncEngine::new(relay.clone(), db.clone(), device);

        let outcome = engine.sync(&dek).await;
        assert!(outcome.is_err(), "the cap must fail closed");
        assert!(outcome.unwrap_err().to_string().contains("dead-letter"));
        let cursor = SyncConfig::load(db.lock().unwrap().conn())
            .unwrap()
            .last_pull_sequence;
        assert_eq!(cursor, 0, "the cursor did NOT advance past the cap");

        // Purge ONE row; the same page now applies (fail-open after action).
        {
            let conn = db.lock().unwrap();
            conn.conn()
                .execute(
                    "DELETE FROM sync_dead_letter WHERE server_sequence = ?1",
                    [MAX_DEAD_LETTER as i64 + 10_000],
                )
                .unwrap();
        }
        engine.sync(&dek).await.unwrap();
        let cursor = SyncConfig::load(db.lock().unwrap().conn())
            .unwrap()
            .last_pull_sequence;
        assert_eq!(cursor, 1, "the page committed after the purge");
        let _ = good_id;
    }

    /// The page transaction is all-or-nothing (SR-SYNC-003): a fault at any
    /// write of the page rolls the applies, dispositions, AND the cursor
    /// back together; the clean run proves complete-new AND that no denial
    /// was silently swallowed (a best-effort site swallowing an authorizer
    /// denial would inflate the clean run's write count past the baseline).
    /// The page mixes an APPLICABLE mutation with an unappliable one, so the
    /// apply-path writes are themselves fault-swept.
    #[tokio::test]
    async fn pull_page_fault_injection_is_all_or_nothing() {
        use crate::database::fault_injection::{clear_write_fault, install_write_fault};
        let dek = DataEncryptionKey::new().unwrap();
        let relay_vault = Uuid::new_v4();
        let device = Uuid::new_v4();

        let build_state = || -> (FakeRelay, Database) {
            let db = apply_test_db();
            vault_config(&db, relay_vault, device);
            let relay = FakeRelay::new();
            relay.set_vault(relay_vault);
            // Applicable first, poison second — the apply-path writes AND
            // the dead-letter disposition writes are both in the sweep.
            relay.seed_peer_mutation(
                crate::sync::v2::build_mutation(
                    &crate::sync::v2::derive_metadata_mac_key(&dek).unwrap(),
                    &crate::sync::v2::MutationInput {
                        vault_id: relay_vault,
                        object_id: Uuid::new_v4(),
                        object_type: SyncEntryType::Credential,
                        expected_version: ObjectVersion(0),
                        resulting_version: ObjectVersion(1),
                        key_epoch: 1,
                        origin_device_id: Uuid::new_v4(),
                        is_tombstone: false,
                        encrypted_payload: {
                            let payload = CredentialPayload {
                                title: "Applicable".to_string(),
                                username: "u".to_string(),
                                password: Zeroizing::new("p".to_string()),
                                credential_type: crate::CredentialType::Password,
                                url: None,
                                notes: None,
                                favorite: false,
                                domains: vec![],
                                created_at: 1,
                                modified_at: 1,
                            };
                            encrypt_for_sync(
                                &dek,
                                &Zeroizing::new(serde_json::to_vec(&payload).unwrap()),
                            )
                            .unwrap()
                        },
                    },
                )
                .unwrap(),
            );
            relay.seed_peer_mutation(
                crate::sync::v2::build_mutation(
                    &crate::sync::v2::derive_metadata_mac_key(&dek).unwrap(),
                    &crate::sync::v2::MutationInput {
                        vault_id: relay_vault,
                        object_id: Uuid::new_v4(),
                        object_type: SyncEntryType::Credential,
                        expected_version: ObjectVersion(0),
                        resulting_version: ObjectVersion(1),
                        key_epoch: 1,
                        origin_device_id: Uuid::new_v4(),
                        is_tombstone: false,
                        encrypted_payload: vec![0xDD; 64], // poison
                    },
                )
                .unwrap(),
            );
            (relay, db)
        };

        let (relay, db) = build_state();
        let db = Arc::new(Mutex::new(db));
        let engine = SyncEngine::new(relay.clone(), db.clone(), device);

        let reset_state = |db: &Arc<Mutex<Database>>| {
            let conn = db.lock().unwrap();
            conn.conn().execute("DELETE FROM entries", []).unwrap();
            conn.conn()
                .execute("DELETE FROM secret_equality_index", [])
                .unwrap();
            conn.conn()
                .execute("DELETE FROM sync_dead_letter", [])
                .unwrap();
            drop(conn);
            let config = SyncConfig {
                sync_enabled: true,
                vault_id: Some(relay_vault),
                device_id: Some(device),
                device_name: Some("test".to_string()),
                relay_url: Some("https://relay.invalid".to_string()),
                last_push_sequence: 0,
                last_pull_sequence: 0,
                last_sync_at: None,
                protocol_version: crate::sync::config::SYNC_PROTOCOL_VERSION,
            };
            config.save(db.lock().unwrap().conn()).unwrap();
        };

        // Sweep: reset the client state to pristine after every attempt so
        // each run processes the IDENTICAL page (deterministic write order).

        let mut fail_at = 0usize;
        let mut injected_failures = 0usize;
        loop {
            reset_state(&db);
            let guard = {
                let conn = db.lock().unwrap();
                install_write_fault(conn.conn(), fail_at)
            };
            let result = engine.sync(&dek).await;
            {
                let conn = db.lock().unwrap();
                clear_write_fault(conn.conn());
            }

            let denied = guard.seen() > fail_at;
            let cursor = SyncConfig::load(db.lock().unwrap().conn())
                .unwrap()
                .last_pull_sequence;
            let diag: (i64, i64) = db
                .lock()
                .unwrap()
                .conn()
                .query_row(
                    "SELECT (SELECT COUNT(*) FROM entries), \
                            (SELECT COUNT(*) FROM sync_dead_letter)",
                    [],
                    |r| Ok((r.get(0)?, r.get(1)?)),
                )
                .unwrap();
            // The PAGE transaction is the unit under test; sync() has writes
            // AFTER it (the last_sync_at checkpoint), so a denial that hits
            // those surfaces as Err with the page already complete-new.
            match (result, cursor) {
                (Err(_), 0) => {
                    assert!(denied, "harness bug at write {fail_at}");
                    injected_failures += 1;
                    let (entries, dead): (i64, i64) = db
                        .lock()
                        .unwrap()
                        .conn()
                        .query_row(
                            "SELECT (SELECT COUNT(*) FROM entries), \
                                    (SELECT COUNT(*) FROM sync_dead_letter)",
                            [],
                            |r| Ok((r.get(0)?, r.get(1)?)),
                        )
                        .unwrap();
                    assert_eq!(
                        (entries, dead),
                        (0, 0),
                        "complete-old: no partial page state at write {fail_at}"
                    );
                }
                (Err(_), 2) => {
                    assert!(denied, "harness bug at write {fail_at}");
                    injected_failures += 1;
                }
                (Ok(_), 2) if diag != (1, 1) => {
                    // A denial was absorbed by a per-blob savepoint (the
                    // apply failed → dead-lettered → page committed): the
                    // savepoint must have left NO partial rows behind.
                    injected_failures += 1;
                    let orphans: i64 = db
                        .lock()
                        .unwrap()
                        .conn()
                        .query_row(
                            "SELECT COUNT(*) FROM entries WHERE sync_id IN \
                             (SELECT object_id FROM sync_dead_letter)",
                            [],
                            |r| r.get(0),
                        )
                        .unwrap();
                    assert_eq!(
                        orphans, 0,
                        "savepoint rollback: a dead-lettered object left partial rows"
                    );
                }
                (Ok(_), 2) => {
                    // TRUE complete-new: the applicable row applied and
                    // exactly one disposition recorded.
                    break;
                }
                other => panic!("unexpected outcome at write {fail_at}: {other:?}"),
            }
            fail_at += 1;
            assert!(fail_at < 64, "page never succeeded within the sweep bound");
        }
        assert!(
            injected_failures >= 1,
            "the sweep must inject at least one real failure to be meaningful"
        );
    }

    /// The credential blob helper stays referenced (parity with the apply
    /// fixtures above; pull-apply reuse is covered by the shared tests).
    #[test]
    fn blob_helper_roundtrip_shape() {
        let dek = DataEncryptionKey::new().unwrap();
        let blob = credential_blob(&dek, Uuid::new_v4(), 1);
        assert!(matches!(blob.entry_type, SyncEntryType::Credential));
    }
}
