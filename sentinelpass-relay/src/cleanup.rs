//! Background cleanup tasks: prune nonces, tombstones, expired pairings.

use crate::storage::RelayStorage;
use std::time::Duration;
use tokio::time;

/// Spawn a background task that periodically prunes expired nonces, tombstones, and pairing blobs.
#[allow(dead_code)]
pub fn spawn_cleanup_task(
    storage: RelayStorage,
    tombstone_retention_days: u64,
    nonce_window_secs: i64,
    pairing_fetch_attempt_retention_secs: i64,
    mutation_result_ttl_secs: i64,
    max_mutation_results_per_device: usize,
) {
    tokio::spawn(async move {
        let mut interval = time::interval(Duration::from_secs(3600)); // hourly
        loop {
            interval.tick().await;
            if let Err(e) = run_cleanup(
                &storage,
                tombstone_retention_days,
                nonce_window_secs,
                pairing_fetch_attempt_retention_secs,
                mutation_result_ttl_secs,
                max_mutation_results_per_device,
            ) {
                tracing::error!("Cleanup error: {}", e);
            }
        }
    });
}

pub(crate) fn run_cleanup(
    storage: &RelayStorage,
    tombstone_retention_days: u64,
    nonce_window_secs: i64,
    pairing_fetch_attempt_retention_secs: i64,
    mutation_result_ttl_secs: i64,
    max_mutation_results_per_device: usize,
) -> Result<(), String> {
    let conn = storage.conn().map_err(|e| e.to_string())?;
    let now = chrono::Utc::now().timestamp();

    // Prune nonces older than the configured freshness window (minimum 1 second)
    let nonce_cutoff = now - nonce_window_secs.max(1);
    conn.execute("DELETE FROM seen_nonces WHERE seen_at < ?1", [nonce_cutoff])
        .map_err(|e| e.to_string())?;

    // Prune aged-out v2 mutation results (bounded idempotency state,
    // WBS-603): after expiry a duplicate is re-evaluated by the CAS guard,
    // which rejects it rather than replaying it.
    let result_cutoff = now - mutation_result_ttl_secs.max(1);
    conn.execute(
        "DELETE FROM mutation_results WHERE created_at < ?1",
        [result_cutoff],
    )
    .map_err(|e| e.to_string())?;
    // Per-device cap: keep the newest N records per device, evict the rest.
    conn.execute(
        "DELETE FROM mutation_results
         WHERE rowid IN (
             SELECT rowid FROM (
                 SELECT rowid, ROW_NUMBER() OVER (
                     PARTITION BY device_id ORDER BY created_at DESC, rowid DESC
                 ) AS rn
                 FROM mutation_results
             ) WHERE rn > ?1
         )",
        [max_mutation_results_per_device as i64],
    )
    .map_err(|e| e.to_string())?;

    // Prune expired pairing bootstraps
    conn.execute(
        "DELETE FROM pairing_bootstraps WHERE expires_at < ?1 OR consumed = 1",
        [now],
    )
    .map_err(|e| e.to_string())?;
    conn.execute(
        "DELETE FROM pairing_bootstraps_v2 WHERE expires_at < ?1 OR consumed = 1",
        [now],
    )
    .map_err(|e| e.to_string())?;
    conn.execute(
        "DELETE FROM pairing_registration_proofs WHERE expires_at < ?1 OR consumed = 1",
        [now],
    )
    .map_err(|e| e.to_string())?;
    let pairing_fetch_cutoff = now - pairing_fetch_attempt_retention_secs.max(60);
    conn.execute(
        "DELETE FROM pairing_fetch_attempts
         WHERE (blocked_until <= ?1 AND last_attempt_at < ?2) OR last_attempt_at < ?2",
        rusqlite::params![now, pairing_fetch_cutoff],
    )
    .map_err(|e| e.to_string())?;

    // Prune old tombstones
    let tombstone_cutoff = now - (tombstone_retention_days as i64 * 86400);
    conn.execute(
        "DELETE FROM sync_entries WHERE is_tombstone = 1 AND received_at < ?1",
        [tombstone_cutoff],
    )
    .map_err(|e| e.to_string())?;

    tracing::debug!("Cleanup completed");
    Ok(())
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
            rusqlite::params!["token-old", 8, now - 500, now - 500, now - 100],
        )
        .unwrap();
        conn.execute(
            "INSERT INTO pairing_fetch_attempts (token_hash, attempts, first_attempt_at, last_attempt_at, blocked_until)
             VALUES (?1, ?2, ?3, ?4, ?5)",
            rusqlite::params!["token-new", 2, now - 10, now - 10, 0],
        )
        .unwrap();
        drop(conn);

        run_cleanup(&storage, 90, 60, 300, 7 * 24 * 3600, 4_096).unwrap();

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
}
