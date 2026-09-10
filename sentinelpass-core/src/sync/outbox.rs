//! Sync v2 outbox: pending-change collection as mutations and per-object
//! acknowledgement bookkeeping (WBS-604/605, ADR-006).
//!
//! Collection wraps the v1 blob collectors (their payload-building logic is
//! shared verbatim) and pairs each blob with the object's durable
//! `sync_acked_version` — the CAS `expected_version` of the mutation.
//! Mutation ids are DETERMINISTIC (v2::mutation_id_for), so a retry after a
//! lost response re-derives the same id and the relay replays the original
//! durable result — the outbox entry is removed only by ITS OWN `Applied`
//! acknowledgement (WBS-605).

use crate::crypto::cipher::DataEncryptionKey;
use crate::sync::change_tracker::{
    collect_pending_credential_blobs, collect_pending_ssh_key_blobs, collect_pending_totp_blobs,
};
use crate::sync::models::{SyncEntryBlob, SyncEntryType};
use crate::sync::v2::{
    build_mutation, derive_metadata_mac_key, MutationInput, MutationResult, MutationV2,
    ObjectVersion,
};
use crate::DatabaseError;
use crate::Result;
use rusqlite::Connection;
use uuid::Uuid;

/// One collected pending change as a ready-to-push mutation.
#[derive(Debug, Clone)]
pub struct OutboxMutation {
    pub mutation: MutationV2,
    /// Stable object identity (echoed from the mutation for ack routing).
    pub object_id: Uuid,
    pub object_type: SyncEntryType,
}

/// Client-side push page size — matches the relay's per-request cap
/// (`relay::handlers::sync_v2::MAX_MUTATIONS_PER_PUSH`).
pub const MAX_PUSH_MUTATIONS: usize = 500;

/// Collect every pending local change as v2 mutations.
///
/// `relay_vault_id` is the shared RELAY vault identity (routing + MAC
/// domain — every paired device knows it from the bootstrap); `key_epoch`
/// is the local vault's key epoch (`read_local_identity`). A pending row
/// whose current version has not advanced past its acked version yields NO
/// mutation (nothing new to push).
pub fn collect_pending_mutations(
    conn: &Connection,
    dek: &DataEncryptionKey,
    device_id: Uuid,
    relay_vault_id: Uuid,
    key_epoch: i64,
) -> Result<Vec<OutboxMutation>> {
    let mac_key = derive_metadata_mac_key(dek)?;

    let blobs = {
        let mut all: Vec<SyncEntryBlob> = collect_pending_credential_blobs(conn, dek, device_id)?;
        all.extend(collect_pending_ssh_key_blobs(conn, dek, device_id)?);
        all.extend(collect_pending_totp_blobs(conn, dek, device_id)?);
        all
    };

    let mut out = Vec::with_capacity(blobs.len());
    for blob in blobs {
        let acked = acked_version_for(conn, blob.sync_id, blob.entry_type)?;
        if blob.sync_version <= acked {
            // Nothing new since the last ack — no mutation for this object.
            continue;
        }
        let input = MutationInput {
            vault_id: relay_vault_id,
            object_id: blob.sync_id,
            object_type: blob.entry_type,
            expected_version: ObjectVersion(acked),
            resulting_version: ObjectVersion(blob.sync_version),
            key_epoch,
            origin_device_id: device_id,
            is_tombstone: blob.is_tombstone,
            encrypted_payload: blob.encrypted_payload.clone(),
        };
        let mutation =
            build_mutation(&mac_key, &input).map_err(crate::PasswordManagerError::Crypto)?;
        out.push(OutboxMutation {
            mutation,
            object_id: blob.sync_id,
            object_type: blob.entry_type,
        });
    }
    Ok(out)
}

/// The durable acked version of one object (0 = never acked).
fn acked_version_for(
    conn: &Connection,
    object_id: Uuid,
    object_type: SyncEntryType,
) -> Result<u64> {
    let table = match object_type {
        SyncEntryType::Credential => "entries",
        SyncEntryType::SshKey => "ssh_keys",
        SyncEntryType::TotpSecret => "totp_secrets",
    };
    let acked: Option<i64> = conn
        .query_row(
            &format!("SELECT sync_acked_version FROM {table} WHERE sync_id = ?1"),
            [object_id.to_string()],
            |row| row.get(0),
        )
        .map_err(DatabaseError::Sqlite)
        .ok();
    Ok(acked.unwrap_or(0).max(0) as u64)
}

/// Summary of one push response's per-object acks (WBS-604/605).
#[derive(Debug, Default, Clone, PartialEq, Eq)]
pub struct AckSummary {
    /// Objects acknowledged Applied — removed from the outbox.
    pub applied: u64,
    /// Objects rejected with VersionConflict — kept pending (they carry an
    /// unresolved concurrent edit; conflict preservation is WBS-611).
    pub conflicts: u64,
    /// Objects rejected for any other reason (stale epoch, …) — kept
    /// pending; the next sync retries the same deterministic mutation.
    pub rejected: u64,
}

/// Record a push response's durable results and move the push checkpoint as
/// ONE transaction (SR-SYNC-003 groundwork / WBS-605).
///
/// Per object, ONLY its own `Applied` ack marks the row synced and advances
/// its `sync_acked_version` — a rejected object stays pending with its acked
/// version untouched, so the retry re-derives the same mutation id. The
/// relay's vault cursor is recorded as a diagnostic (v2 correctness never
/// gates on it).
pub fn apply_push_acks(
    conn: &Connection,
    mutations: &[OutboxMutation],
    results: &[MutationResult],
    server_cursor: u64,
) -> Result<AckSummary> {
    let now = chrono::Utc::now().timestamp();
    let tx = conn
        .unchecked_transaction()
        .map_err(DatabaseError::Sqlite)?;

    let mut summary = AckSummary::default();
    for result in results {
        let Some(outbox) = mutations
            .iter()
            .find(|m| m.mutation.mutation_id == result.mutation_id)
        else {
            // A result for a mutation we did not send: ignore (cannot route).
            continue;
        };
        match &result.outcome {
            crate::sync::v2::MutationOutcome::Applied {
                resulting_version, ..
            } => {
                let table = match outbox.object_type {
                    SyncEntryType::Credential => "entries",
                    SyncEntryType::SshKey => "ssh_keys",
                    SyncEntryType::TotpSecret => "totp_secrets",
                };
                tx.execute(
                    &format!(
                        "UPDATE {table} SET sync_state = 'synced', sync_acked_version = ?1,
                         last_synced_at = ?2 WHERE sync_id = ?3"
                    ),
                    rusqlite::params![
                        resulting_version.as_u64() as i64,
                        now,
                        outbox.object_id.to_string()
                    ],
                )
                .map_err(DatabaseError::Sqlite)?;
                summary.applied += 1;
            }
            crate::sync::v2::MutationOutcome::Rejected { reason } => match reason {
                crate::sync::v2::RejectionReason::VersionConflict { .. } => {
                    summary.conflicts += 1;
                    tracing::warn!(
                        object_id = %outbox.object_id,
                        "sync push: concurrent edit on another device won — the local \
                         alternative is preserved and the entry stays pending"
                    );
                }
                other => {
                    summary.rejected += 1;
                    tracing::warn!(
                        object_id = %outbox.object_id,
                        reason = %other,
                        "sync push: mutation rejected — the entry stays pending and \
                         retries next sync"
                    );
                }
            },
        }
    }

    let mut config = crate::sync::config::SyncConfig::load(&tx)?;
    config.last_push_sequence = server_cursor;
    config.save(&tx)?;

    tx.commit().map_err(DatabaseError::Sqlite)?;
    Ok(summary)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::crypto::cipher::DataEncryptionKey;
    use crate::database::Database;
    use crate::sync::v2::{MutationOutcome, RejectionReason, ServerCursor};

    /// A vault-shaped in-memory database (same fixture contract as the
    /// engine tests).
    fn outbox_db() -> Database {
        let db = Database::in_memory().unwrap();
        db.initialize_schema().unwrap();
        let sql = format!(
            "INSERT INTO db_metadata (id, version, kdf_params, wrapped_dek, dek_nonce, created_at, last_modified, vault_uuid, format_version, key_epoch)
             VALUES (1, {}, X'00', X'00', X'00', strftime('%s','now'), strftime('%s','now'), '11111111-1111-1111-1111-111111111111', 1, 1)",
            crate::database::schema::CURRENT_SCHEMA_VERSION
        );
        db.conn().execute(&sql, []).unwrap();
        db
    }

    fn insert_pending(
        conn: &Connection,
        dek: &DataEncryptionKey,
        sync_id: &Uuid,
        version: i64,
        acked: i64,
        state: &str,
    ) {
        use crate::crypto::cipher::encrypt_string;
        let t = encrypt_string(dek, "T").unwrap();
        conn.execute(
            "INSERT INTO entries (vault_id, title, username, password, credential_type,
                entry_nonce, auth_tag, created_at, modified_at, favorite,
                sync_id, sync_version, sync_acked_version, sync_state, is_deleted)
             VALUES (1, ?1, ?1, ?1, 'password', ?2, ?3, 1, 1, 0, ?4, ?5, ?6, ?7, 0)",
            rusqlite::params![
                bincode::serialize(&t).unwrap(),
                bincode::serialize(&t.nonce).unwrap(),
                bincode::serialize(&t.auth_tag).unwrap(),
                sync_id.to_string(),
                version,
                acked,
                state,
            ],
        )
        .unwrap();
    }

    fn relay_vault() -> Uuid {
        Uuid::from_u128(0xABCD)
    }

    #[test]
    fn collection_pairs_pending_rows_with_acked_versions() {
        let dek = DataEncryptionKey::new().unwrap();
        let db = outbox_db();
        let device = Uuid::new_v4();
        let a = Uuid::new_v4();
        let b = Uuid::new_v4();
        {
            let conn = db.conn();
            // a: edited twice since sync (acked 1, now 3). b: never acked.
            insert_pending(conn, &dek, &a, 3, 1, "pending");
            insert_pending(conn, &dek, &b, 1, 0, "pending");
        }

        let out = collect_pending_mutations(db.conn(), &dek, device, relay_vault(), 1).unwrap();
        assert_eq!(out.len(), 2);
        let a_m = out.iter().find(|m| m.object_id == a).unwrap();
        let b_m = out.iter().find(|m| m.object_id == b).unwrap();
        assert_eq!(a_m.mutation.expected_version, ObjectVersion(1));
        assert_eq!(a_m.mutation.resulting_version, ObjectVersion(3));
        assert_eq!(a_m.mutation.vault_id, relay_vault());
        assert_eq!(a_m.mutation.key_epoch, 1);
        assert_eq!(b_m.mutation.expected_version, ObjectVersion(0));
        assert_eq!(b_m.mutation.resulting_version, ObjectVersion(1));
    }

    /// THE WBS-605 pin: only Applied objects are marked synced+acked; a
    /// rejected object stays pending with its acked version untouched, so
    /// the retry re-derives the SAME mutation id.
    #[test]
    fn ack_marks_only_applied_objects() {
        let dek = DataEncryptionKey::new().unwrap();
        let db = outbox_db();
        let device = Uuid::new_v4();
        let a = Uuid::new_v4();
        let b = Uuid::new_v4();
        let c = Uuid::new_v4();
        {
            let conn = db.conn();
            insert_pending(conn, &dek, &a, 3, 1, "pending");
            insert_pending(conn, &dek, &b, 2, 1, "pending");
            insert_pending(conn, &dek, &c, 2, 1, "pending");
        }
        let mutations =
            collect_pending_mutations(db.conn(), &dek, device, relay_vault(), 1).unwrap();
        assert_eq!(mutations.len(), 3);

        let results: Vec<MutationResult> = mutations
            .iter()
            .map(|m| {
                let outcome = if m.object_id == a {
                    MutationOutcome::Applied {
                        resulting_version: ObjectVersion(3),
                        server_sequence: ServerCursor(9),
                    }
                } else if m.object_id == b {
                    MutationOutcome::Rejected {
                        reason: RejectionReason::VersionConflict {
                            current_version: ObjectVersion(4),
                        },
                    }
                } else {
                    MutationOutcome::Rejected {
                        reason: RejectionReason::StaleEpoch { vault_epoch: 5 },
                    }
                };
                MutationResult {
                    mutation_id: m.mutation.mutation_id,
                    object_id: m.object_id,
                    outcome,
                }
            })
            .collect();

        let summary = apply_push_acks(db.conn(), &mutations, &results, 9).unwrap();
        assert_eq!(
            summary,
            AckSummary {
                applied: 1,
                conflicts: 1,
                rejected: 1
            }
        );

        let (a_state, a_acked): (String, i64) = db
            .conn()
            .query_row(
                "SELECT sync_state, sync_acked_version FROM entries WHERE sync_id = ?1",
                [a.to_string()],
                |r| Ok((r.get(0)?, r.get(1)?)),
            )
            .unwrap();
        assert_eq!(a_state, "synced");
        assert_eq!(a_acked, 3, "acked version advanced WITH the mark");

        for (id, expected_version) in [(b, 1), (c, 1)] {
            let (state, acked): (String, i64) = db
                .conn()
                .query_row(
                    "SELECT sync_state, sync_acked_version FROM entries WHERE sync_id = ?1",
                    [id.to_string()],
                    |r| Ok((r.get(0)?, r.get(1)?)),
                )
                .unwrap();
            assert_eq!(state, "pending", "rejected rows must stay pending");
            assert_eq!(
                acked, expected_version,
                "rejected rows keep their acked version"
            );
        }

        // The checkpoint records the relay cursor diagnostic.
        let config = crate::sync::config::SyncConfig::load(db.conn()).unwrap();
        assert_eq!(config.last_push_sequence, 9);
    }

    /// The retry story end to end at the outbox layer: a rejected object's
    /// NEXT collection re-derives the identical mutation id (deterministic)
    /// and identical CAS expectation — idempotent against the relay.
    #[test]
    fn retry_of_rejected_object_rederives_the_same_mutation() {
        let dek = DataEncryptionKey::new().unwrap();
        let db = outbox_db();
        let device = Uuid::new_v4();
        let a = Uuid::new_v4();
        {
            let conn = db.conn();
            insert_pending(conn, &dek, &a, 2, 1, "pending");
        }
        let first = collect_pending_mutations(db.conn(), &dek, device, relay_vault(), 1)
            .unwrap()
            .pop()
            .unwrap();

        // No state change (the rejection was durable) → same mutation again.
        let retry = collect_pending_mutations(db.conn(), &dek, device, relay_vault(), 1)
            .unwrap()
            .pop()
            .unwrap();
        assert_eq!(first.mutation.mutation_id, retry.mutation.mutation_id);
        assert_eq!(
            first.mutation.expected_version,
            retry.mutation.expected_version
        );
        assert_eq!(
            first.mutation.resulting_version, retry.mutation.resulting_version,
            "idempotency-relevant metadata is identical"
        );
        // The payload differs byte-wise (fresh GCM nonce per encryption) —
        // deliberately NOT part of the idempotency key.
    }
}
