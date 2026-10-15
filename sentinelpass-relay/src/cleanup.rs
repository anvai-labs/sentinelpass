//! Incremental maintenance of expired metadata and legacy tombstones.
//! V2 object state and mutation history are never pruned here.

use crate::storage::RelayStorage;
use rusqlite::{Connection, OptionalExtension};
use std::time::Duration;

const ROWS_PER_BATCH: usize = 256;
const DEVICES_PER_PASS: usize = 32;
const IDLE_INTERVAL: Duration = Duration::from_secs(3600);
const BACKLOG_INTERVAL: Duration = Duration::from_secs(1);

pub(crate) const PRUNE_NONCES: &str = "DELETE FROM seen_nonces WHERE rowid IN (
         SELECT rowid FROM seen_nonces WHERE seen_at < ?1
         ORDER BY seen_at LIMIT ?2)";
const PRUNE_RESULTS: &str = "DELETE FROM mutation_results WHERE rowid IN (
         SELECT rowid FROM mutation_results WHERE created_at < ?1
         ORDER BY created_at LIMIT ?2)";
const PRUNE_DEVICE_RESULTS: &str = "DELETE FROM mutation_results WHERE rowid IN (
         SELECT rowid FROM mutation_results WHERE device_id = ?1
         ORDER BY created_at DESC, rowid DESC LIMIT ?2 OFFSET ?3)";
const NEXT_DEVICE: &str = "SELECT device_id FROM mutation_results WHERE device_id > ?1
     ORDER BY device_id LIMIT 1";
const FIRST_DEVICE: &str = "SELECT device_id FROM mutation_results ORDER BY device_id LIMIT 1";
const PRUNE_FETCH_ATTEMPTS: &str = "DELETE FROM pairing_fetch_attempts WHERE rowid IN (
         SELECT rowid FROM pairing_fetch_attempts
         WHERE MAX(last_attempt_at, blocked_until) < ?1
         ORDER BY MAX(last_attempt_at, blocked_until) LIMIT ?2)";
const PRUNE_LEGACY_TOMBSTONES: &str = "DELETE FROM sync_entries WHERE rowid IN (
         SELECT rowid FROM sync_entries WHERE is_tombstone = 1 AND received_at < ?1
         ORDER BY received_at LIMIT ?2)";

#[derive(Clone, Copy)]
pub(crate) struct CleanupPolicy {
    pub tombstone_retention_days: u64,
    pub nonce_window_secs: i64,
    pub pairing_fetch_attempt_retention_secs: i64,
    pub mutation_result_ttl_secs: i64,
    pub max_mutation_results_per_device: usize,
}

/// A disposable traversal cursor, not a replication checkpoint. Restarting a
/// sweep repeats only idempotent maintenance; it cannot lose sync history.
#[derive(Default)]
pub(crate) struct CleanupCursor {
    after_device: Option<String>,
    device_backlog: bool,
}

#[derive(Debug, Default)]
pub(crate) struct CleanupReport {
    deleted_rows: usize,
    devices_visited: usize,
    more_work: bool,
}

impl CleanupReport {
    fn record_batch(&mut self, deleted: usize) {
        self.deleted_rows += deleted;
        // A full batch may have more work. One extra empty pass is harmless.
        self.more_work |= deleted == ROWS_PER_BATCH;
    }
}

/// One blocking worker at a time, with a delay between bounded passes. Backlog
/// is revisited promptly; an idle sweep sleeps for the original hourly interval.
#[allow(dead_code)]
pub fn spawn_cleanup_task(
    storage: RelayStorage,
    tombstone_retention_days: u64,
    nonce_window_secs: i64,
    pairing_fetch_attempt_retention_secs: i64,
    mutation_result_ttl_secs: i64,
    max_mutation_results_per_device: usize,
) {
    let policy = CleanupPolicy {
        tombstone_retention_days,
        nonce_window_secs,
        pairing_fetch_attempt_retention_secs,
        mutation_result_ttl_secs,
        max_mutation_results_per_device,
    };
    tokio::spawn(async move {
        let mut cursor = CleanupCursor::default();
        loop {
            let cleanup_storage = storage.clone();
            let result = tokio::task::spawn_blocking(move || {
                let result = run_cleanup(
                    &cleanup_storage,
                    &policy,
                    &mut cursor,
                    chrono::Utc::now().timestamp(),
                );
                (cursor, result)
            })
            .await;
            let delay = match result {
                Ok((next_cursor, result)) => {
                    cursor = next_cursor;
                    match result {
                        Ok(report) => {
                            tracing::debug!(
                                deleted_rows = report.deleted_rows,
                                devices_visited = report.devices_visited,
                                more_work = report.more_work,
                                "Cleanup pass completed"
                            );
                            if report.more_work {
                                BACKLOG_INTERVAL
                            } else {
                                IDLE_INTERVAL
                            }
                        }
                        Err(error) => {
                            tracing::error!(%error, "Cleanup error");
                            IDLE_INTERVAL
                        }
                    }
                }
                Err(error) => {
                    cursor = CleanupCursor::default();
                    tracing::error!(%error, "Cleanup worker failed");
                    IDLE_INTERVAL
                }
            };
            tokio::time::sleep(delay).await;
        }
    });
}

/// Also used by authentication, so request-triggered nonce housekeeping cannot
/// delete an arbitrarily large accumulated backlog in one statement.
pub(crate) fn prune_expired_nonces(conn: &Connection, cutoff: i64) -> rusqlite::Result<usize> {
    conn.execute(
        PRUNE_NONCES,
        rusqlite::params![cutoff, ROWS_PER_BATCH as i64],
    )
}

fn delete_batch(storage: &RelayStorage, sql: &str, cutoff: i64) -> Result<usize, String> {
    // Release the shared connection after each statement. A pass is deliberately
    // not one transaction: each deletion is independently safe to repeat.
    storage
        .conn()
        .map_err(|e| e.to_string())?
        .execute(sql, rusqlite::params![cutoff, ROWS_PER_BATCH as i64])
        .map_err(|e| e.to_string())
}

pub(crate) fn run_cleanup(
    storage: &RelayStorage,
    policy: &CleanupPolicy,
    cursor: &mut CleanupCursor,
    now: i64,
) -> Result<CleanupReport, String> {
    let mut report = CleanupReport::default();
    let retention = i64::try_from(policy.tombstone_retention_days)
        .unwrap_or(i64::MAX)
        .saturating_mul(86400);
    // Expiry and consumption use separate indexed ranges instead of an OR scan.
    // Keep attempt history until after BOTH the last attempt and backoff expiry;
    // maintenance must never clear a still-active lockout.
    for (sql, cutoff) in [
        (
            PRUNE_NONCES,
            now.saturating_sub(policy.nonce_window_secs.max(1)),
        ),
        (
            PRUNE_RESULTS,
            now.saturating_sub(policy.mutation_result_ttl_secs.max(1)),
        ),
        (
            "DELETE FROM pairing_bootstraps WHERE rowid IN (
            SELECT rowid FROM pairing_bootstraps WHERE expires_at < ?1
            ORDER BY expires_at LIMIT ?2)",
            now,
        ),
        (
            "DELETE FROM pairing_bootstraps WHERE rowid IN (
            SELECT rowid FROM pairing_bootstraps WHERE consumed = ?1
            ORDER BY expires_at LIMIT ?2)",
            1,
        ),
        (
            "DELETE FROM pairing_bootstraps_v2 WHERE rowid IN (
            SELECT rowid FROM pairing_bootstraps_v2 WHERE expires_at < ?1
            ORDER BY expires_at LIMIT ?2)",
            now,
        ),
        (
            "DELETE FROM pairing_bootstraps_v2 WHERE rowid IN (
            SELECT rowid FROM pairing_bootstraps_v2 WHERE consumed = ?1
            ORDER BY expires_at LIMIT ?2)",
            1,
        ),
        (
            "DELETE FROM pairing_registration_proofs WHERE rowid IN (
            SELECT rowid FROM pairing_registration_proofs WHERE expires_at < ?1
            ORDER BY expires_at LIMIT ?2)",
            now,
        ),
        (
            "DELETE FROM pairing_registration_proofs WHERE rowid IN (
            SELECT rowid FROM pairing_registration_proofs WHERE consumed = ?1
            ORDER BY expires_at LIMIT ?2)",
            1,
        ),
        (
            PRUNE_FETCH_ATTEMPTS,
            now.saturating_sub(policy.pairing_fetch_attempt_retention_secs.max(60)),
        ),
        (PRUNE_LEGACY_TOMBSTONES, now.saturating_sub(retention)),
    ] {
        report.record_batch(delete_batch(storage, sql, cutoff)?);
    }

    // Seek directly to the next device, including orphaned result rows. Do not
    // GROUP BY or window-sort the entire result table. The SQL offset examines
    // up to the configured retained count plus one batch per device.
    let cap = i64::try_from(policy.max_mutation_results_per_device).unwrap_or(i64::MAX);
    for _ in 0..DEVICES_PER_PASS {
        let conn = storage.conn().map_err(|e| e.to_string())?;
        let device: Option<String> = match &cursor.after_device {
            Some(after) => conn.query_row(NEXT_DEVICE, [after], |row| row.get(0)),
            None => conn.query_row(FIRST_DEVICE, [], |row| row.get(0)),
        }
        .optional()
        .map_err(|e| e.to_string())?;
        let Some(device) = device else {
            cursor.after_device = None;
            // A full batch earlier in this multi-pass sweep must trigger the
            // next sweep even when its final devices had no excess rows.
            report.more_work |= std::mem::take(&mut cursor.device_backlog);
            return Ok(report);
        };
        let deleted = conn
            .execute(
                PRUNE_DEVICE_RESULTS,
                rusqlite::params![&device, ROWS_PER_BATCH as i64, cap],
            )
            .map_err(|e| e.to_string())?;
        report.record_batch(deleted);
        cursor.device_backlog |= deleted == ROWS_PER_BATCH;
        report.devices_visited += 1;
        cursor.after_device = Some(device);
    }
    // Resume this traversal before beginning another sweep, so a hot early
    // device cannot monopolize the cap-enforcement budget.
    report.more_work = true;
    Ok(report)
}

#[cfg(test)]
pub(crate) fn test_policy() -> CleanupPolicy {
    CleanupPolicy {
        tombstone_retention_days: 90,
        nonce_window_secs: 60,
        pairing_fetch_attempt_retention_secs: 300,
        mutation_result_ttl_secs: 7 * 24 * 3600,
        max_mutation_results_per_device: 4_096,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::storage::RelayStorage;
    use chrono::Utc;

    #[test]
    fn cleanup_uses_configured_nonce_window_and_prunes_consumed_pairings() {
        let storage = RelayStorage::in_memory().expect("in-memory storage");
        let conn = storage.conn().expect("storage conn");
        let now = Utc::now().timestamp();

        conn.execute(
            "INSERT INTO seen_nonces (nonce, device_id, seen_at) VALUES (?1, ?2, ?3)",
            rusqlite::params!["old", "d1", now - 61],
        )
        .unwrap();
        conn.execute(
            "INSERT INTO seen_nonces (nonce, device_id, seen_at) VALUES (?1, ?2, ?3)",
            rusqlite::params!["new", "d1", now - 10],
        )
        .unwrap();

        conn.execute(
            "INSERT INTO pairing_bootstraps (pairing_token, vault_id, encrypted_bootstrap, pairing_salt, expires_at, consumed)
             VALUES (?1, ?2, ?3, ?4, ?5, ?6)",
            rusqlite::params!["consumed", "v1", vec![1u8], vec![2u8], now + 100, 1],
        )
        .unwrap();
        conn.execute(
            "INSERT INTO pairing_bootstraps (pairing_token, vault_id, encrypted_bootstrap, pairing_salt, expires_at, consumed)
             VALUES (?1, ?2, ?3, ?4, ?5, ?6)",
            rusqlite::params!["active", "v1", vec![1u8], vec![2u8], now + 100, 0],
        )
        .unwrap();
        conn.execute(
            "INSERT INTO pairing_registration_proofs (proof_hash, pairing_token_hash, vault_id, expires_at, consumed)
             VALUES (?1, ?2, ?3, ?4, ?5)",
            rusqlite::params!["proof-consumed", "token-a", "v1", now + 100, 1],
        )
        .unwrap();
        conn.execute(
            "INSERT INTO pairing_registration_proofs (proof_hash, pairing_token_hash, vault_id, expires_at, consumed)
             VALUES (?1, ?2, ?3, ?4, ?5)",
            rusqlite::params!["proof-active", "token-b", "v1", now + 100, 0],
        )
        .unwrap();

        conn.execute(
            "INSERT INTO sync_entries (
                sync_id, vault_id, entry_type, sync_version, modified_at, encrypted_payload,
                is_tombstone, origin_device_id, server_sequence, received_at
             ) VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9, ?10)",
            rusqlite::params![
                "t_old",
                "v1",
                "credential",
                1,
                now - 1000,
                vec![0u8],
                1,
                "d1",
                1,
                now - 200 * 86400,
            ],
        )
        .unwrap();
        conn.execute(
            "INSERT INTO sync_entries (
                sync_id, vault_id, entry_type, sync_version, modified_at, encrypted_payload,
                is_tombstone, origin_device_id, server_sequence, received_at
             ) VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9, ?10)",
            rusqlite::params![
                "t_new",
                "v1",
                "credential",
                1,
                now - 1000,
                vec![0u8],
                1,
                "d1",
                2,
                now - 10,
            ],
        )
        .unwrap();

        conn.execute(
            "INSERT INTO pairing_fetch_attempts (token_hash, attempts, first_attempt_at, last_attempt_at, blocked_until)
             VALUES (?1, ?2, ?3, ?4, ?5)",
            rusqlite::params!["token-old", 8, now - 500, now - 500, now - 400],
        )
        .unwrap();
        conn.execute(
            "INSERT INTO pairing_fetch_attempts (token_hash, attempts, first_attempt_at, last_attempt_at, blocked_until)
             VALUES (?1, ?2, ?3, ?4, ?5)",
            rusqlite::params!["token-new", 2, now - 10, now - 10, 0],
        )
        .unwrap();
        drop(conn);

        run_cleanup(&storage, &test_policy(), &mut CleanupCursor::default(), now).unwrap();

        let conn = storage.conn().unwrap();
        let has_old_nonce: bool = conn
            .query_row(
                "SELECT EXISTS(SELECT 1 FROM seen_nonces WHERE nonce = 'old')",
                [],
                |row| row.get(0),
            )
            .unwrap();
        let has_new_nonce: bool = conn
            .query_row(
                "SELECT EXISTS(SELECT 1 FROM seen_nonces WHERE nonce = 'new')",
                [],
                |row| row.get(0),
            )
            .unwrap();
        let has_consumed_pairing: bool = conn
            .query_row(
                "SELECT EXISTS(SELECT 1 FROM pairing_bootstraps WHERE pairing_token = 'consumed')",
                [],
                |row| row.get(0),
            )
            .unwrap();
        let has_active_pairing: bool = conn
            .query_row(
                "SELECT EXISTS(SELECT 1 FROM pairing_bootstraps WHERE pairing_token = 'active')",
                [],
                |row| row.get(0),
            )
            .unwrap();
        let has_consumed_proof: bool = conn
            .query_row(
                "SELECT EXISTS(SELECT 1 FROM pairing_registration_proofs WHERE proof_hash = 'proof-consumed')",
                [],
                |row| row.get(0),
            )
            .unwrap();
        let has_active_proof: bool = conn
            .query_row(
                "SELECT EXISTS(SELECT 1 FROM pairing_registration_proofs WHERE proof_hash = 'proof-active')",
                [],
                |row| row.get(0),
            )
            .unwrap();
        let has_old_fetch_attempt: bool = conn
            .query_row(
                "SELECT EXISTS(SELECT 1 FROM pairing_fetch_attempts WHERE token_hash = 'token-old')",
                [],
                |row| row.get(0),
            )
            .unwrap();
        let has_new_fetch_attempt: bool = conn
            .query_row(
                "SELECT EXISTS(SELECT 1 FROM pairing_fetch_attempts WHERE token_hash = 'token-new')",
                [],
                |row| row.get(0),
            )
            .unwrap();
        let has_old_tombstone: bool = conn
            .query_row(
                "SELECT EXISTS(SELECT 1 FROM sync_entries WHERE sync_id = 't_old')",
                [],
                |row| row.get(0),
            )
            .unwrap();
        let has_new_tombstone: bool = conn
            .query_row(
                "SELECT EXISTS(SELECT 1 FROM sync_entries WHERE sync_id = 't_new')",
                [],
                |row| row.get(0),
            )
            .unwrap();

        assert!(!has_old_nonce);
        assert!(has_new_nonce);
        assert!(!has_consumed_pairing);
        assert!(has_active_pairing);
        assert!(!has_consumed_proof);
        assert!(has_active_proof);
        assert!(!has_old_fetch_attempt);
        assert!(has_new_fetch_attempt);
        assert!(!has_old_tombstone);
        assert!(has_new_tombstone);
    }
    #[test]
    fn nonce_backlog_is_bounded_and_expiry_boundary_is_preserved() {
        let storage = RelayStorage::in_memory().unwrap();
        let now = 10_000;
        {
            let mut conn = storage.conn().unwrap();
            let tx = conn.transaction().unwrap();
            for n in 0..(ROWS_PER_BATCH * 2 + 1) {
                tx.execute(
                    "INSERT INTO seen_nonces VALUES (?1, 'd', ?2)",
                    rusqlite::params![format!("old-{n}"), now - 61],
                )
                .unwrap();
            }
            tx.execute(
                "INSERT INTO seen_nonces VALUES ('boundary', 'd', ?1)",
                [now - 60],
            )
            .unwrap();
            tx.commit().unwrap();
        }
        // Request-path housekeeping uses the same limit as background cleanup.
        assert_eq!(
            prune_expired_nonces(&storage.conn().unwrap(), now - 60).unwrap(),
            ROWS_PER_BATCH
        );
        let mut cursor = CleanupCursor::default();
        let first = run_cleanup(&storage, &test_policy(), &mut cursor, now).unwrap();
        assert_eq!(first.deleted_rows, ROWS_PER_BATCH);
        assert!(first.more_work);
        let second = run_cleanup(&storage, &test_policy(), &mut cursor, now).unwrap();
        assert_eq!(second.deleted_rows, 1);
        assert!(!second.more_work);
        assert_eq!(
            storage
                .conn()
                .unwrap()
                .query_row("SELECT nonce FROM seen_nonces", [], |r| r
                    .get::<_, String>(0))
                .unwrap(),
            "boundary"
        );
    }

    #[test]
    fn result_cap_rotates_devices_keeps_newest_ties_and_converges_after_restart() {
        let storage = RelayStorage::in_memory().unwrap();
        let now = 10_000;
        let rows_per_device = ROWS_PER_BATCH + 3;
        {
            let mut conn = storage.conn().unwrap();
            let tx = conn.transaction().unwrap();
            for d in 0..(DEVICES_PER_PASS + 1) {
                for n in 0..rows_per_device {
                    // Deliberately no device-table rows: orphan metadata also expires.
                    tx.execute(
                        "INSERT INTO mutation_results
                        (mutation_id, vault_id, device_id, object_id, outcome, created_at)
                        VALUES (?1, 'v', ?2, 'o', 'applied', ?3)",
                        rusqlite::params![format!("m{n}"), format!("d{d:03}"), now],
                    )
                    .unwrap();
                }
            }
            tx.commit().unwrap();
        }
        let policy = CleanupPolicy {
            max_mutation_results_per_device: 2,
            ..test_policy()
        };
        let mut cursor = CleanupCursor::default();
        let first = run_cleanup(&storage, &policy, &mut cursor, now).unwrap();
        assert_eq!(first.devices_visited, DEVICES_PER_PASS);
        assert_eq!(first.deleted_rows, DEVICES_PER_PASS * ROWS_PER_BATCH);
        assert!(first.more_work);
        let second = run_cleanup(&storage, &policy, &mut cursor, now).unwrap();
        assert_eq!(
            second.devices_visited, 1,
            "resume after the first 32 devices"
        );
        assert_eq!(second.deleted_rows, ROWS_PER_BATCH);
        assert!(second.more_work);
        // Dropping the traversal cursor is safe: deletion is independently durable.
        cursor = CleanupCursor::default();
        let third = run_cleanup(&storage, &policy, &mut cursor, now).unwrap();
        assert_eq!(third.deleted_rows, DEVICES_PER_PASS);
        let fourth = run_cleanup(&storage, &policy, &mut cursor, now).unwrap();
        assert_eq!(fourth.deleted_rows, 1);
        assert!(!fourth.more_work);
        let conn = storage.conn().unwrap();
        let mut stmt = conn
            .prepare(
                "SELECT mutation_id, COUNT(*) FROM mutation_results
            GROUP BY mutation_id ORDER BY mutation_id",
            )
            .unwrap();
        let kept: Vec<(String, i64)> = stmt
            .query_map([], |r| Ok((r.get(0)?, r.get(1)?)))
            .unwrap()
            .collect::<Result<_, _>>()
            .unwrap();
        assert_eq!(
            kept,
            vec![
                (
                    format!("m{}", rows_per_device - 2),
                    (DEVICES_PER_PASS + 1) as i64
                ),
                (
                    format!("m{}", rows_per_device - 1),
                    (DEVICES_PER_PASS + 1) as i64
                )
            ]
        );
        drop(stmt);
        drop(conn);
        // An extreme configured cap must not wrap into a negative SQL offset.
        let report = run_cleanup(
            &storage,
            &CleanupPolicy {
                max_mutation_results_per_device: usize::MAX,
                ..policy
            },
            &mut cursor,
            now,
        )
        .unwrap();
        assert_eq!(report.deleted_rows, 0);
    }

    #[test]
    fn maintenance_preserves_active_pairing_backoff_and_retention_boundary() {
        let storage = RelayStorage::in_memory().unwrap();
        let now = 10_000;
        let conn = storage.conn().unwrap();
        for (id, blocked_until) in [
            ("expired", now - 301),
            ("boundary", now - 300),
            ("active", now + 10_000),
        ] {
            conn.execute(
                "INSERT INTO pairing_fetch_attempts VALUES (?1, 8, ?2, ?2, ?3)",
                rusqlite::params![id, now - 1_000, blocked_until],
            )
            .unwrap();
        }
        drop(conn);
        run_cleanup(&storage, &test_policy(), &mut CleanupCursor::default(), now).unwrap();
        let conn = storage.conn().unwrap();
        let mut stmt = conn
            .prepare("SELECT token_hash FROM pairing_fetch_attempts ORDER BY token_hash")
            .unwrap();
        let remaining: Vec<String> = stmt
            .query_map([], |r| r.get(0))
            .unwrap()
            .collect::<Result<_, _>>()
            .unwrap();
        assert_eq!(remaining, ["active", "boundary"]);
    }

    #[test]
    fn cleanup_queries_use_indexed_ranges_without_global_sorting() {
        let storage = RelayStorage::in_memory().unwrap();
        let conn = storage.conn().unwrap();
        let queries: &[(&str, &[&dyn rusqlite::ToSql], &str)] = &[
            (
                PRUNE_NONCES,
                &[&100_i64, &256_i64],
                "idx_seen_nonces_seen_at",
            ),
            (
                PRUNE_RESULTS,
                &[&100_i64, &256_i64],
                "idx_mutation_results_age",
            ),
            (
                PRUNE_DEVICE_RESULTS,
                &[&"d", &256_i64, &4096_i64],
                "idx_mutation_results_device",
            ),
            (NEXT_DEVICE, &[&"d"], "idx_mutation_results_device"),
            (
                PRUNE_FETCH_ATTEMPTS,
                &[&100_i64, &256_i64],
                "idx_pairing_fetch_attempts_cleanup",
            ),
            (
                PRUNE_LEGACY_TOMBSTONES,
                &[&100_i64, &256_i64],
                "idx_sync_entries_tombstone_age",
            ),
        ];
        for (sql, params, index) in queries {
            assert_index_plan(&conn, sql, params, index);
        }
        for (table, index) in [
            ("pairing_bootstraps", "idx_pairing_consumed"),
            ("pairing_bootstraps_v2", "idx_pairing_v2_consumed"),
            ("pairing_registration_proofs", "idx_pairing_proofs_consumed"),
        ] {
            let sql = format!(
                "DELETE FROM {table} WHERE rowid IN (
                SELECT rowid FROM {table} WHERE consumed = ?1 ORDER BY expires_at LIMIT ?2)"
            );
            assert_index_plan(&conn, &sql, &[&1_i64, &256_i64], index);
        }
    }

    fn assert_index_plan(
        conn: &Connection,
        sql: &str,
        params: &[&dyn rusqlite::ToSql],
        index: &str,
    ) {
        let mut stmt = conn.prepare(&format!("EXPLAIN QUERY PLAN {sql}")).unwrap();
        let plan = stmt
            .query_map(params, |r| r.get::<_, String>(3))
            .unwrap()
            .collect::<Result<Vec<_>, _>>()
            .unwrap()
            .join("\n");
        assert!(plan.contains(index), "expected {index}: {plan}");
        assert!(!plan.contains("USE TEMP B-TREE"), "unbounded sort: {plan}");
    }
    #[test]
    fn file_backed_cleanup_coexists_with_writer_reader_and_checkpoint() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("relay.db");
        let storage = RelayStorage::open(&path).unwrap();
        let writer = RelayStorage::open(&path).unwrap();
        let now = 10_000;
        let expired = ROWS_PER_BATCH * 3 + 1;
        {
            let mut conn = storage.conn().unwrap();
            let tx = conn.transaction().unwrap();
            for n in 0..expired {
                tx.execute(
                    "INSERT INTO seen_nonces VALUES (?1, 'd', ?2)",
                    rusqlite::params![format!("old-{n}"), now - 61],
                )
                .unwrap();
            }
            tx.commit().unwrap();
        }
        let mut reader = Connection::open(&path).unwrap();
        let snapshot = reader.transaction().unwrap();
        let count = |conn: &Connection| {
            conn.query_row("SELECT COUNT(*) FROM seen_nonces", [], |r| {
                r.get::<_, i64>(0)
            })
            .unwrap()
        };
        assert_eq!(count(&snapshot), expired as i64);
        let checkpoint = Connection::open(&path).unwrap();
        checkpoint.busy_timeout(Duration::from_secs(5)).unwrap();
        let start = std::sync::Arc::new(std::sync::Barrier::new(3));
        let cleaner_start = start.clone();
        let cleaner_storage = storage.clone();
        let cleaner = std::thread::spawn(move || {
            cleaner_start.wait();
            let mut cursor = CleanupCursor::default();
            for _ in 0..4 {
                run_cleanup(&cleaner_storage, &test_policy(), &mut cursor, now).unwrap();
            }
        });
        let writer_start = start.clone();
        let writer = std::thread::spawn(move || {
            writer_start.wait();
            for n in 0..100 {
                writer
                    .conn()
                    .unwrap()
                    .execute(
                        "INSERT INTO seen_nonces VALUES (?1, 'd', ?2)",
                        rusqlite::params![format!("new-{n}"), now],
                    )
                    .unwrap();
            }
        });
        start.wait();
        for _ in 0..4 {
            let _: (i64, i64, i64) = checkpoint
                .query_row("PRAGMA wal_checkpoint(PASSIVE)", [], |r| {
                    Ok((r.get(0)?, r.get(1)?, r.get(2)?))
                })
                .unwrap();
        }
        cleaner.join().unwrap();
        writer.join().unwrap();
        assert_eq!(
            count(&snapshot),
            expired as i64,
            "the reader retains its original snapshot"
        );
        snapshot.commit().unwrap();
        let (busy, frames, checkpointed): (i64, i64, i64) = checkpoint
            .query_row("PRAGMA wal_checkpoint(TRUNCATE)", [], |r| {
                Ok((r.get(0)?, r.get(1)?, r.get(2)?))
            })
            .unwrap();
        assert_eq!((busy, frames, checkpointed), (0, 0, 0));
        assert_eq!(
            checkpoint
                .query_row("PRAGMA integrity_check", [], |r| r.get::<_, String>(0))
                .unwrap(),
            "ok"
        );
        drop(checkpoint);
        drop(reader);
        drop(storage);
        let reopened = RelayStorage::open(&path).unwrap();
        assert_eq!(count(&reopened.conn().unwrap()), 100);
    }
    #[test]
    fn hot_early_device_backlog_survives_a_quiet_final_pass() {
        let storage = RelayStorage::in_memory().unwrap();
        let now = 10_000;
        {
            let mut conn = storage.conn().unwrap();
            let tx = conn.transaction().unwrap();
            for d in 0..(DEVICES_PER_PASS + 1) {
                let count = if d == 0 { ROWS_PER_BATCH + 3 } else { 2 };
                for n in 0..count {
                    tx.execute(
                        "INSERT INTO mutation_results
                        (mutation_id, vault_id, device_id, object_id, outcome, created_at)
                        VALUES (?1, 'v', ?2, 'o', 'applied', ?3)",
                        rusqlite::params![format!("m{n}"), format!("d{d:03}"), now],
                    )
                    .unwrap();
                }
            }
            tx.commit().unwrap();
        }
        let policy = CleanupPolicy {
            max_mutation_results_per_device: 2,
            ..test_policy()
        };
        let mut cursor = CleanupCursor::default();
        assert_eq!(
            run_cleanup(&storage, &policy, &mut cursor, now)
                .unwrap()
                .deleted_rows,
            ROWS_PER_BATCH
        );
        let quiet = run_cleanup(&storage, &policy, &mut cursor, now).unwrap();
        assert_eq!(quiet.deleted_rows, 0);
        assert_eq!(quiet.devices_visited, 1);
        assert!(quiet.more_work, "remember backlog from the earlier pass");
        assert_eq!(
            run_cleanup(&storage, &policy, &mut cursor, now)
                .unwrap()
                .deleted_rows,
            1
        );
        assert!(
            !run_cleanup(&storage, &policy, &mut cursor, now)
                .unwrap()
                .more_work
        );
    }
}
