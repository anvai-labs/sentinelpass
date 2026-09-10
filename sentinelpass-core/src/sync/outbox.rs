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
    /// Objects rejected with VersionConflict — reconciled per the conflict
    /// rules on [`apply_push_acks`] (adopted in place, or re-based for a
    /// fresh-mutation retry; two-alternative preservation is WBS-611).
    pub conflicts: u64,
    /// Objects rejected for any other reason (stale epoch, …) — kept
    /// pending; the next sync retries the same deterministic mutation.
    pub rejected: u64,
    /// Acks whose `resulting_version` did not match the mutation we sent —
    /// ignored (a relay must never move our bookkeeping to a version we did
    /// not produce).
    pub suspicious_acks: u64,
}

/// Record a push response's durable results and move the push checkpoint as
/// ONE transaction (SR-SYNC-003 groundwork / WBS-605).
///
/// Per-object rules:
/// - `Applied{R}` — honored ONLY when `R` equals the resulting version WE
///   sent (anything else is a relay misreport and is ignored): the row
///   leaves the outbox (`sync_state = 'synced'`, `sync_acked_version = R`).
/// - `Rejected{VersionConflict{C}}` — the relay's current version is C:
///   - `C >= R` (our attempted resulting version): the relay is at or
///     beyond our attempt — the relay state supersedes this row; record
///     `sync_acked_version = C` and mark it synced. The next PULL brings
///     the relay's content down (v1-equivalent adoption; full
///     two-alternative conflict preservation lands with WBS-611).
///   - `C < R` — our attempt was genuinely rejected while we moved on (a
///     local edit, or a lost-response mutation committed and a later edit
///     advanced the row): learn `C` into `sync_acked_version` and
///     re-version the row PAST the attempted `R` so the next cycle pushes
///     a FRESH mutation (a retry of the rejected id would only replay the
///     stored rejection).
/// - Other rejections — the row stays pending untouched; the same
///   deterministic mutation retries next sync.
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
        let table = match outbox.object_type {
            SyncEntryType::Credential => "entries",
            SyncEntryType::SshKey => "ssh_keys",
            SyncEntryType::TotpSecret => "totp_secrets",
        };
        let sent_resulting = outbox.mutation.resulting_version;
        match &result.outcome {
            crate::sync::v2::MutationOutcome::Applied {
                resulting_version, ..
            } => {
                if resulting_version != &sent_resulting {
                    // Never let a relay move our bookkeeping to a version we
                    // did not produce (malicious or buggy relay): the acked
                    // column is trusted local state.
                    summary.suspicious_acks += 1;
                    tracing::warn!(
                        object_id = %outbox.object_id,
                        sent = sent_resulting.as_u64(),
                        reported = resulting_version.as_u64(),
                        "sync push: ack resulting_version does not match the sent \
                         mutation — ack ignored, the entry stays pending"
                    );
                    continue;
                }
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
                crate::sync::v2::RejectionReason::VersionConflict { current_version } => {
                    summary.conflicts += 1;
                    let current = current_version.as_u64() as i64;
                    let sent = sent_resulting.as_u64() as i64;
                    if current >= sent {
                        // The relay is at or beyond our attempt: adopt the
                        // relay state as the new baseline (the next pull
                        // reconciles content).
                        tx.execute(
                            &format!(
                                "UPDATE {table} SET sync_state = 'synced',
                                 sync_acked_version = MAX(sync_acked_version, ?1),
                                 last_synced_at = ?2 WHERE sync_id = ?3"
                            ),
                            rusqlite::params![current, now, outbox.object_id.to_string()],
                        )
                        .map_err(DatabaseError::Sqlite)?;
                    } else {
                        // Superseded mid-flight: learn the relay's current
                        // version and re-version the row past our attempted
                        // resulting version — the next cycle pushes a fresh
                        // mutation (new id, correct CAS expectation).
                        tx.execute(
                            &format!(
                                "UPDATE {table} SET sync_state = 'pending',
                                 sync_acked_version = MAX(sync_acked_version, ?1),
                                 sync_version = MAX(sync_version, ?2)
                                 WHERE sync_id = ?3"
                            ),
                            rusqlite::params![current, sent + 1, outbox.object_id.to_string()],
                        )
                        .map_err(DatabaseError::Sqlite)?;
                    }
                    tracing::warn!(
                        object_id = %outbox.object_id,
                        current,
                        "sync push: version conflict — row re-based onto the relay's \
                         current version (two-alternative conflict preservation \
                         lands with WBS-611)"
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

    /// THE WBS-605 ack bookkeeping: Applied marks synced+acked; a conflict
    /// whose relay current is AT OR BEYOND our attempt adopts that baseline
    /// (synced, acked = current — the next pull reconciles content); a
    /// stale-epoch rejection leaves the row fully untouched.
    #[test]
    fn ack_outcomes_drive_row_bookkeeping() {
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
                rejected: 1,
                suspicious_acks: 0,
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

        // b: conflict with relay current 4 >= attempted 2 → adopted baseline
        // (the next pull reconciles content; WBS-611 adds preservation).
        let (b_state, b_acked): (String, i64) = db
            .conn()
            .query_row(
                "SELECT sync_state, sync_acked_version FROM entries WHERE sync_id = ?1",
                [b.to_string()],
                |r| Ok((r.get(0)?, r.get(1)?)),
            )
            .unwrap();
        assert_eq!(
            b_state, "synced",
            "a superseding conflict adopts the relay state"
        );
        assert_eq!(b_acked, 4, "acked learns the relay's current version");

        // c: stale-epoch rejection — fully untouched, retries same mutation.
        let (c_state, c_acked): (String, i64) = db
            .conn()
            .query_row(
                "SELECT sync_state, sync_acked_version FROM entries WHERE sync_id = ?1",
                [c.to_string()],
                |r| Ok((r.get(0)?, r.get(1)?)),
            )
            .unwrap();
        assert_eq!(c_state, "pending", "non-conflict rejections stay pending");
        assert_eq!(c_acked, 1, "their acked version is untouched");

        // The checkpoint records the relay cursor diagnostic.
        let config = crate::sync::config::SyncConfig::load(db.conn()).unwrap();
        assert_eq!(config.last_push_sequence, 9);
    }

    /// A conflict BEHIND our attempt (we edited mid-flight, or a lost
    /// response committed and a later edit moved on) learns the relay's
    /// current version and re-versions the row PAST our attempted resulting
    /// version — the next collection produces a FRESH mutation (new id,
    /// correct CAS expectation) instead of replaying the stored rejection
    /// forever (the reviewer's lost-response-then-edit wedge).
    #[test]
    fn conflict_behind_our_attempt_rebases_for_a_fresh_mutation() {
        let dek = DataEncryptionKey::new().unwrap();
        let db = outbox_db();
        let device = Uuid::new_v4();
        let a = Uuid::new_v4();
        {
            let conn = db.conn();
            insert_pending(conn, &dek, &a, 3, 1, "pending");
        }
        let mutations =
            collect_pending_mutations(db.conn(), &dek, device, relay_vault(), 1).unwrap();
        let first = &mutations[0];
        assert_eq!(first.mutation.resulting_version, ObjectVersion(3));

        // Relay rejected: it holds version 2 (behind our attempted 3).
        let results = vec![MutationResult {
            mutation_id: first.mutation.mutation_id,
            object_id: a,
            outcome: MutationOutcome::Rejected {
                reason: RejectionReason::VersionConflict {
                    current_version: ObjectVersion(2),
                },
            },
        }];
        let summary = apply_push_acks(db.conn(), &mutations, &results, 5).unwrap();
        assert_eq!(summary.conflicts, 1);

        let (state, acked, version): (String, i64, i64) = db
            .conn()
            .query_row(
                "SELECT sync_state, sync_acked_version, sync_version FROM entries \
                 WHERE sync_id = ?1",
                [a.to_string()],
                |r| Ok((r.get(0)?, r.get(1)?, r.get(2)?)),
            )
            .unwrap();
        assert_eq!(state, "pending", "still has an unsynced local edit");
        assert_eq!(acked, 2, "acked learned the relay's current version");
        assert_eq!(version, 4, "re-versioned past the attempted 3");

        // Next collection: fresh id (v4), CAS expectation 2 — the retry is a
        // NEW mutation, not a replay of the stored rejection.
        let retry = collect_pending_mutations(db.conn(), &dek, device, relay_vault(), 1)
            .unwrap()
            .pop()
            .unwrap();
        assert_ne!(retry.mutation.mutation_id, first.mutation.mutation_id);
        assert_eq!(retry.mutation.resulting_version, ObjectVersion(4));
        assert_eq!(retry.mutation.expected_version, ObjectVersion(2));
    }

    /// A relay reporting an Applied ack for a version we did not produce is
    /// IGNORED — bookkeeping never moves off our own mutations (malicious /
    /// buggy relay hardening).
    #[test]
    fn mismatched_ack_version_is_ignored() {
        let dek = DataEncryptionKey::new().unwrap();
        let db = outbox_db();
        let device = Uuid::new_v4();
        let a = Uuid::new_v4();
        {
            let conn = db.conn();
            insert_pending(conn, &dek, &a, 3, 1, "pending");
        }
        let mutations =
            collect_pending_mutations(db.conn(), &dek, device, relay_vault(), 1).unwrap();
        let first = &mutations[0];

        let results = vec![MutationResult {
            mutation_id: first.mutation.mutation_id,
            object_id: a,
            outcome: MutationOutcome::Applied {
                resulting_version: ObjectVersion(99),
                server_sequence: ServerCursor(9),
            },
        }];
        let summary = apply_push_acks(db.conn(), &mutations, &results, 9).unwrap();
        assert_eq!(summary.suspicious_acks, 1);
        assert_eq!(summary.applied, 0);

        let (state, acked): (String, i64) = db
            .conn()
            .query_row(
                "SELECT sync_state, sync_acked_version FROM entries WHERE sync_id = ?1",
                [a.to_string()],
                |r| Ok((r.get(0)?, r.get(1)?)),
            )
            .unwrap();
        assert_eq!(
            state, "pending",
            "the forged ack must not complete the outbox entry"
        );
        assert_eq!(acked, 1, "bookkeeping untouched");
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
