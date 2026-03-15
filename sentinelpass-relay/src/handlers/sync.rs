//! Sync push/pull handlers.

use crate::app_state::RelayAppState;
use crate::error::RelayError;
use axum::extract::State;
use axum::http::Extensions;
use axum::Json;
use base64::Engine;
use chrono::Utc;
use serde::{Deserialize, Serialize};
use uuid::Uuid;

/// Wire format for an encrypted sync entry received by the relay.
#[derive(Deserialize)]
pub struct SyncEntryBlob {
    pub sync_id: Uuid,
    pub entry_type: String,
    pub sync_version: u64,
    pub modified_at: i64,
    pub encrypted_payload: String, // base64
    pub is_tombstone: bool,
    pub origin_device_id: Uuid,
}

/// Request body for pushing sync entries to the relay.
#[derive(Deserialize)]
pub struct PushRequest {
    pub device_sequence: u64,
    pub entries: Vec<SyncEntryBlob>,
}

/// Response after a push operation with acceptance counts.
#[derive(Debug, Serialize)]
pub struct PushResponse {
    pub accepted: u64,
    pub rejected: u64,
    pub server_sequence: u64,
}

/// Request body for pulling sync entries since a given sequence.
#[derive(Deserialize)]
pub struct PullRequest {
    pub since_sequence: u64,
    pub limit: Option<u64>,
}

/// A single entry in a pull response.
#[derive(Serialize)]
pub struct PullEntry {
    pub sync_id: String,
    pub entry_type: String,
    pub sync_version: u64,
    pub modified_at: i64,
    pub encrypted_payload: String, // base64
    pub is_tombstone: bool,
    pub origin_device_id: String,
}

/// Response containing pulled entries and pagination state.
#[derive(Serialize)]
pub struct PullResponse {
    pub entries: Vec<PullEntry>,
    /// Pagination cursor: the last returned server sequence in this page.
    pub server_sequence: u64,
    pub has_more: bool,
}

/// POST /api/v1/sync/push -- Accept incremental entry pushes, validating versions and sequences.
pub async fn push(
    State(state): State<RelayAppState>,
    extensions: Extensions,
    Json(req): Json<PushRequest>,
) -> Result<Json<PushResponse>, RelayError> {
    let device_id = extensions
        .get::<Uuid>()
        .ok_or_else(|| RelayError::Auth("No device ID".to_string()))?;

    let conn = state.storage.conn()?;

    // Get vault_id for this device
    let vault_id: String = conn
        .query_row(
            "SELECT vault_id FROM devices WHERE device_id = ?1",
            [device_id.to_string()],
            |row| row.get(0),
        )
        .map_err(|_| RelayError::NotFound("Device not found".to_string()))?;

    // Check device sequence (monotonic)
    let last_seq: i64 = conn
        .query_row(
            "SELECT last_sequence FROM device_sequences WHERE device_id = ?1",
            [device_id.to_string()],
            |row| row.get(0),
        )
        .unwrap_or(0);

    if (req.device_sequence as i64) <= last_seq {
        return Err(RelayError::Conflict(
            "Device sequence not increasing".to_string(),
        ));
    }

    let now = Utc::now().timestamp();
    let mut accepted = 0u64;
    let mut rejected = 0u64;

    /// Maximum size of a single encrypted payload (1 MB).
    const MAX_ENTRY_PAYLOAD_SIZE: usize = 1_048_576;

    for entry in &req.entries {
        let payload = base64::engine::general_purpose::STANDARD
            .decode(&entry.encrypted_payload)
            .map_err(|e| RelayError::BadRequest(format!("Invalid payload: {}", e)))?;

        if payload.len() > MAX_ENTRY_PAYLOAD_SIZE {
            return Err(RelayError::BadRequest(format!(
                "Entry payload exceeds maximum size of {} bytes",
                MAX_ENTRY_PAYLOAD_SIZE
            )));
        }

        let sync_id_str = entry.sync_id.to_string();

        // Check if we already have this sync_id with a higher version
        let existing_version: Option<i64> = conn
            .query_row(
                "SELECT sync_version FROM sync_entries WHERE sync_id = ?1 AND vault_id = ?2",
                rusqlite::params![sync_id_str, vault_id],
                |row| row.get(0),
            )
            .ok();

        if let Some(existing) = existing_version {
            if entry.sync_version as i64 <= existing {
                // Same or lower version, check modified_at for tie-break
                let existing_modified: i64 = conn
                    .query_row(
                        "SELECT modified_at FROM sync_entries WHERE sync_id = ?1 AND vault_id = ?2",
                        rusqlite::params![sync_id_str, vault_id],
                        |row| row.get(0),
                    )
                    .unwrap_or(0);

                if entry.sync_version as i64 == existing && entry.modified_at <= existing_modified {
                    rejected += 1;
                    continue;
                }
                if (entry.sync_version as i64) < existing {
                    rejected += 1;
                    continue;
                }
            }
        }

        // Increment server sequence
        conn.execute(
            "UPDATE sequence_counters SET current_sequence = current_sequence + 1 WHERE vault_id = ?1",
            [&vault_id],
        )
        .map_err(|e| RelayError::Database(e.to_string()))?;

        let server_seq: i64 = conn
            .query_row(
                "SELECT current_sequence FROM sequence_counters WHERE vault_id = ?1",
                [&vault_id],
                |row| row.get(0),
            )
            .map_err(|e| RelayError::Database(e.to_string()))?;

        // Upsert the entry
        conn.execute(
            "INSERT INTO sync_entries (sync_id, vault_id, entry_type, sync_version, modified_at,
                                       encrypted_payload, is_tombstone, origin_device_id,
                                       server_sequence, received_at)
             VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9, ?10)
             ON CONFLICT(sync_id, vault_id) DO UPDATE SET
                entry_type = excluded.entry_type,
                sync_version = excluded.sync_version,
                modified_at = excluded.modified_at,
                encrypted_payload = excluded.encrypted_payload,
                is_tombstone = excluded.is_tombstone,
                origin_device_id = excluded.origin_device_id,
                server_sequence = excluded.server_sequence,
                received_at = excluded.received_at",
            rusqlite::params![
                sync_id_str,
                vault_id,
                entry.entry_type,
                entry.sync_version as i64,
                entry.modified_at,
                payload,
                entry.is_tombstone,
                entry.origin_device_id.to_string(),
                server_seq,
                now,
            ],
        )
        .map_err(|e| RelayError::Database(e.to_string()))?;

        accepted += 1;
    }

    // Update device sequence
    conn.execute(
        "UPDATE device_sequences SET last_sequence = ?1 WHERE device_id = ?2",
        rusqlite::params![req.device_sequence as i64, device_id.to_string()],
    )
    .map_err(|e| RelayError::Database(e.to_string()))?;

    let server_seq: i64 = conn
        .query_row(
            "SELECT current_sequence FROM sequence_counters WHERE vault_id = ?1",
            [&vault_id],
            |row| row.get(0),
        )
        .map_err(|e| RelayError::Database(e.to_string()))?;

    Ok(Json(PushResponse {
        accepted,
        rejected,
        server_sequence: server_seq as u64,
    }))
}

/// POST /api/v1/sync/pull -- Return entries newer than the requested sequence.
pub async fn pull(
    State(state): State<RelayAppState>,
    extensions: Extensions,
    Json(req): Json<PullRequest>,
) -> Result<Json<PullResponse>, RelayError> {
    let device_id = extensions
        .get::<Uuid>()
        .ok_or_else(|| RelayError::Auth("No device ID".to_string()))?;

    let conn = state.storage.conn()?;

    let vault_id: String = conn
        .query_row(
            "SELECT vault_id FROM devices WHERE device_id = ?1",
            [device_id.to_string()],
            |row| row.get(0),
        )
        .map_err(|_| RelayError::NotFound("Device not found".to_string()))?;

    let limit = req.limit.unwrap_or(1000).min(10_000) as i64;

    let mut stmt = conn
        .prepare(
            "SELECT sync_id, entry_type, sync_version, modified_at,
                    encrypted_payload, is_tombstone, origin_device_id, server_sequence
             FROM sync_entries
             WHERE vault_id = ?1 AND server_sequence > ?2
             ORDER BY server_sequence ASC
             LIMIT ?3",
        )
        .map_err(|e| RelayError::Database(e.to_string()))?;

    let entries_with_seq: Vec<(PullEntry, i64)> = stmt
        .query_map(
            rusqlite::params![vault_id, req.since_sequence as i64, limit + 1],
            |row| {
                let payload: Vec<u8> = row.get(4)?;
                let server_sequence: i64 = row.get(7)?;
                Ok((
                    PullEntry {
                        sync_id: row.get(0)?,
                        entry_type: row.get(1)?,
                        sync_version: row.get::<_, i64>(2)? as u64,
                        modified_at: row.get(3)?,
                        encrypted_payload: base64::engine::general_purpose::STANDARD
                            .encode(&payload),
                        is_tombstone: row.get(5)?,
                        origin_device_id: row.get(6)?,
                    },
                    server_sequence,
                ))
            },
        )
        .map_err(|e| RelayError::Database(e.to_string()))?
        .collect::<Result<Vec<_>, _>>()
        .map_err(|e| RelayError::Database(e.to_string()))?;

    let has_more = entries_with_seq.len() > limit as usize;
    let entries_with_seq: Vec<(PullEntry, i64)> =
        entries_with_seq.into_iter().take(limit as usize).collect();
    let page_cursor = entries_with_seq
        .last()
        .map(|(_, seq)| *seq as u64)
        .unwrap_or(req.since_sequence);
    let entries: Vec<PullEntry> = entries_with_seq
        .into_iter()
        .map(|(entry, _)| entry)
        .collect();

    Ok(Json(PullResponse {
        entries,
        // `server_sequence` acts as a pagination cursor (last returned sequence) so clients can
        // safely page without skipping unseen entries when `has_more = true`.
        server_sequence: page_cursor,
        has_more,
    }))
}

/// POST /api/v1/sync/full-push -- Accept a full vault upload (initial sync).
pub async fn full_push(
    State(state): State<RelayAppState>,
    extensions: Extensions,
    Json(entries): Json<Vec<SyncEntryBlob>>,
) -> Result<Json<PushResponse>, RelayError> {
    // Delegate to regular push with sequence 1
    let req = PushRequest {
        device_sequence: 1,
        entries,
    };
    push(State(state), extensions, Json(req)).await
}

/// POST /api/v1/sync/full-pull -- Return all entries in the vault.
pub async fn full_pull(
    State(state): State<RelayAppState>,
    extensions: Extensions,
) -> Result<Json<Vec<PullEntry>>, RelayError> {
    let req = PullRequest {
        since_sequence: 0,
        limit: Some(100_000),
    };
    let response = pull(State(state), extensions, Json(req)).await?;
    Ok(Json(response.0.entries))
}

/// GET /api/v1/sync/status -- Return sync status for the authenticated device.
pub async fn status(
    State(state): State<RelayAppState>,
    extensions: Extensions,
) -> Result<Json<serde_json::Value>, RelayError> {
    let device_id = extensions
        .get::<Uuid>()
        .ok_or_else(|| RelayError::Auth("No device ID".to_string()))?;

    let conn = state.storage.conn()?;

    let vault_id: String = conn
        .query_row(
            "SELECT vault_id FROM devices WHERE device_id = ?1",
            [device_id.to_string()],
            |row| row.get(0),
        )
        .map_err(|_| RelayError::NotFound("Device not found".to_string()))?;

    let entry_count: i64 = conn
        .query_row(
            "SELECT COUNT(*) FROM sync_entries WHERE vault_id = ?1 AND is_tombstone = 0",
            [&vault_id],
            |row| row.get(0),
        )
        .map_err(|e| RelayError::Database(e.to_string()))?;

    let current_seq: i64 = conn
        .query_row(
            "SELECT current_sequence FROM sequence_counters WHERE vault_id = ?1",
            [&vault_id],
            |row| row.get(0),
        )
        .unwrap_or(0);

    Ok(Json(serde_json::json!({
        "vault_id": vault_id,
        "entry_count": entry_count,
        "server_sequence": current_seq,
    })))
}

#[cfg(test)]
#[allow(clippy::await_holding_lock)] // Test code uses sync DB connections across await points
mod tests {
    use super::*;
    use crate::app_state::RelayAppState;
    use crate::config::RelayConfig;
    use crate::storage::RelayStorage;
    use axum::extract::State;
    use axum::http::Extensions;
    use base64::engine::general_purpose::STANDARD;
    use chrono::Utc;
    use uuid::Uuid;

    fn setup_test_vault(state: &RelayAppState) -> (Uuid, String, Uuid) {
        let device_id = Uuid::new_v4();
        let vault_id = Uuid::new_v4().to_string();
        let now = Utc::now().timestamp();
        let conn = state.storage.conn().unwrap();

        // Create vault
        conn.execute(
            "INSERT INTO vaults (vault_id, created_at) VALUES (?1, ?2)",
            rusqlite::params![&vault_id, now],
        )
        .unwrap();

        // Initialize sequence counter
        conn.execute(
            "INSERT INTO sequence_counters (vault_id, current_sequence) VALUES (?1, 0)",
            [&vault_id],
        )
        .unwrap();

        // Register device
        conn.execute(
            "INSERT INTO devices (device_id, vault_id, device_name, device_type, public_key, registered_at)
             VALUES (?1, ?2, ?3, ?4, ?5, ?6)",
            rusqlite::params![
                device_id.to_string(),
                &vault_id,
                "Test Device",
                "desktop",
                vec![1u8; 32],
                now,
            ],
        )
        .unwrap();

        // Initialize device sequence
        conn.execute(
            "INSERT INTO device_sequences (device_id, last_sequence) VALUES (?1, 0)",
            [device_id.to_string()],
        )
        .unwrap();

        (device_id, vault_id, Uuid::new_v4())
    }

    fn auth_extensions(device_id: Uuid) -> Extensions {
        let mut extensions = Extensions::new();
        extensions.insert(device_id);
        extensions
    }

    fn sample_entry(
        sync_id: Uuid,
        version: u64,
        modified_at: i64,
        payload: &[u8],
    ) -> SyncEntryBlob {
        SyncEntryBlob {
            sync_id,
            entry_type: "credential".to_string(),
            sync_version: version,
            modified_at,
            encrypted_payload: STANDARD.encode(payload),
            is_tombstone: false,
            origin_device_id: Uuid::new_v4(),
        }
    }

    #[tokio::test]
    async fn push_enforces_device_sequence_monotonicity() {
        let state = RelayAppState::new(RelayStorage::in_memory().unwrap(), RelayConfig::default());
        let (device_id, _, _) = setup_test_vault(&state);

        // First push with sequence 1
        let req1 = PushRequest {
            device_sequence: 1,
            entries: vec![],
        };
        let _ = push(State(state.clone()), auth_extensions(device_id), Json(req1))
            .await
            .expect("first push succeeds");

        // Second push with sequence 1 (same) should fail
        let req2 = PushRequest {
            device_sequence: 1,
            entries: vec![],
        };
        let err = push(State(state.clone()), auth_extensions(device_id), Json(req2))
            .await
            .expect_err("non-monotonic sequence should fail");

        match err {
            RelayError::Conflict(msg) => {
                assert!(msg.contains("not increasing"));
            }
            other => panic!("expected Conflict error, got: {}", other),
        }

        // Push with sequence 2 should succeed
        let req3 = PushRequest {
            device_sequence: 2,
            entries: vec![],
        };
        let _ = push(State(state), auth_extensions(device_id), Json(req3))
            .await
            .expect("monotonic sequence succeeds");
    }

    #[tokio::test]
    async fn push_rejects_lower_version_entries() {
        let state = RelayAppState::new(RelayStorage::in_memory().unwrap(), RelayConfig::default());
        let (device_id, vault_id, sync_id) = setup_test_vault(&state);
        let conn = state.storage.conn().unwrap();

        // Insert an entry at version 5
        let now = Utc::now().timestamp();
        conn.execute(
            "INSERT INTO sync_entries (sync_id, vault_id, entry_type, sync_version, modified_at,
                                       encrypted_payload, is_tombstone, origin_device_id,
                                       server_sequence, received_at)
             VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9, ?10)",
            rusqlite::params![
                sync_id.to_string(),
                vault_id,
                "credential",
                5i64,
                now - 100,
                vec![1u8, 2, 3], // Raw bytes, not base64
                false,
                Uuid::new_v4().to_string(),
                100i64,
                now - 100,
            ],
        )
        .unwrap();
        drop(conn);

        // Try to push same entry at version 3 (lower)
        let req = PushRequest {
            device_sequence: 1,
            entries: vec![sample_entry(sync_id, 3, now - 50, &[4u8, 5, 6])],
        };

        let resp = push(State(state), auth_extensions(device_id), Json(req))
            .await
            .expect("push succeeds");

        assert_eq!(resp.accepted, 0);
        assert_eq!(resp.rejected, 1);
    }

    #[tokio::test]
    async fn push_uses_modified_at_for_version_tiebreaker() {
        let state = RelayAppState::new(RelayStorage::in_memory().unwrap(), RelayConfig::default());
        let (device_id, vault_id, sync_id) = setup_test_vault(&state);
        let conn = state.storage.conn().unwrap();
        let now = Utc::now().timestamp();

        // Insert an entry at version 5, modified_at = 100
        conn.execute(
            "INSERT INTO sync_entries (sync_id, vault_id, entry_type, sync_version, modified_at,
                                       encrypted_payload, is_tombstone, origin_device_id,
                                       server_sequence, received_at)
             VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9, ?10)",
            rusqlite::params![
                sync_id.to_string(),
                vault_id,
                "credential",
                5i64,
                100i64,
                vec![1u8, 2, 3], // Raw bytes, not base64
                false,
                Uuid::new_v4().to_string(),
                100i64,
                now - 100,
            ],
        )
        .unwrap();
        drop(conn);

        // Try to push same entry at version 5, modified_at = 150 (newer)
        let req = PushRequest {
            device_sequence: 1,
            entries: vec![sample_entry(sync_id, 5, 150, &[4u8, 5, 6])],
        };

        let resp = push(State(state.clone()), auth_extensions(device_id), Json(req))
            .await
            .expect("push succeeds");

        assert_eq!(resp.accepted, 1);
        assert_eq!(resp.rejected, 0);

        // Verify the entry was updated
        let conn = state.storage.conn().unwrap();
        let modified: i64 = conn
            .query_row(
                "SELECT modified_at FROM sync_entries WHERE sync_id = ?1",
                [sync_id.to_string()],
                |row| row.get(0),
            )
            .unwrap();
        assert_eq!(modified, 150);
    }

    #[tokio::test]
    async fn push_increments_server_sequence_per_entry() {
        let state = RelayAppState::new(RelayStorage::in_memory().unwrap(), RelayConfig::default());
        let (device_id, _, _) = setup_test_vault(&state);

        let req = PushRequest {
            device_sequence: 1,
            entries: vec![
                sample_entry(Uuid::new_v4(), 1, 100, &[1u8]),
                sample_entry(Uuid::new_v4(), 1, 101, &[2u8]),
                sample_entry(Uuid::new_v4(), 1, 102, &[3u8]),
            ],
        };

        let resp = push(State(state.clone()), auth_extensions(device_id), Json(req))
            .await
            .expect("push succeeds");

        assert_eq!(resp.accepted, 3);
        assert_eq!(resp.rejected, 0);
        assert_eq!(resp.server_sequence, 3);
    }

    #[tokio::test]
    async fn pull_returns_entries_after_since_sequence() {
        let state = RelayAppState::new(RelayStorage::in_memory().unwrap(), RelayConfig::default());
        let (device_id, vault_id, _sync_id) = setup_test_vault(&state);
        let conn = state.storage.conn().unwrap();
        let now = Utc::now().timestamp();

        // Insert entries at server sequences 1, 2, 3, 4, 5
        for i in 1..=5 {
            conn.execute(
                "INSERT INTO sync_entries (sync_id, vault_id, entry_type, sync_version, modified_at,
                                           encrypted_payload, is_tombstone, origin_device_id,
                                           server_sequence, received_at)
                 VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9, ?10)",
                rusqlite::params![
                    Uuid::new_v4().to_string(),
                    vault_id,
                    "credential",
                    1i64,
                    now,
                    vec![i as u8],  // Raw bytes, not base64
                    false,
                    Uuid::new_v4().to_string(),
                    i,
                    now,
                ],
            )
            .unwrap();
        }
        drop(conn);

        // Pull since sequence 2
        let req = PullRequest {
            since_sequence: 2,
            limit: Some(100),
        };

        let resp = pull(State(state), auth_extensions(device_id), Json(req))
            .await
            .expect("pull succeeds");

        assert_eq!(resp.entries.len(), 3); // entries 3, 4, 5
        assert_eq!(resp.server_sequence, 5);
        assert!(!resp.has_more);
    }

    #[tokio::test]
    async fn pull_paginates_with_limit() {
        let state = RelayAppState::new(RelayStorage::in_memory().unwrap(), RelayConfig::default());
        let (device_id, vault_id, _) = setup_test_vault(&state);
        let conn = state.storage.conn().unwrap();
        let now = Utc::now().timestamp();

        // Insert 5 entries
        for i in 1..=5 {
            conn.execute(
                "INSERT INTO sync_entries (sync_id, vault_id, entry_type, sync_version, modified_at,
                                           encrypted_payload, is_tombstone, origin_device_id,
                                           server_sequence, received_at)
                 VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9, ?10)",
                rusqlite::params![
                    Uuid::new_v4().to_string(),
                    vault_id,
                    "credential",
                    1i64,
                    now,
                    vec![i as u8],  // Raw bytes, not base64
                    false,
                    Uuid::new_v4().to_string(),
                    i,
                    now,
                ],
            )
            .unwrap();
        }
        drop(conn);

        // Pull with limit 2
        let req = PullRequest {
            since_sequence: 0,
            limit: Some(2),
        };

        let resp = pull(State(state), auth_extensions(device_id), Json(req))
            .await
            .expect("pull succeeds");

        assert_eq!(resp.entries.len(), 2);
        assert_eq!(resp.server_sequence, 2);
        assert!(resp.has_more);
    }

    #[tokio::test]
    async fn pull_server_sequence_is_pagination_cursor() {
        let state = RelayAppState::new(RelayStorage::in_memory().unwrap(), RelayConfig::default());
        let (device_id, vault_id, _) = setup_test_vault(&state);
        let storage = state.storage.clone();
        let conn = storage.conn().unwrap();
        let now = Utc::now().timestamp();

        // Insert entries
        for i in 1..=5 {
            conn.execute(
                "INSERT INTO sync_entries (sync_id, vault_id, entry_type, sync_version, modified_at,
                                           encrypted_payload, is_tombstone, origin_device_id,
                                           server_sequence, received_at)
                 VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9, ?10)",
                rusqlite::params![
                    Uuid::new_v4().to_string(),
                    vault_id,
                    "credential",
                    1i64,
                    now,
                    vec![i as u8],  // Raw bytes, not base64
                    false,
                    Uuid::new_v4().to_string(),
                    i,
                    now,
                ],
            )
            .unwrap();
        }
        drop(conn);

        // First page with limit 3
        let req1 = PullRequest {
            since_sequence: 0,
            limit: Some(3),
        };
        let resp1 = pull(State(state.clone()), auth_extensions(device_id), Json(req1))
            .await
            .expect("first pull succeeds");

        assert_eq!(resp1.entries.len(), 3);
        assert_eq!(resp1.server_sequence, 3);
        assert!(resp1.has_more);

        // Second page starting from cursor 3
        let req2 = PullRequest {
            since_sequence: 3,
            limit: Some(3),
        };
        let resp2 = pull(State(state), auth_extensions(device_id), Json(req2))
            .await
            .expect("second pull succeeds");

        assert_eq!(resp2.entries.len(), 2);
        assert_eq!(resp2.server_sequence, 5);
        assert!(!resp2.has_more);
    }

    #[tokio::test]
    async fn status_returns_entry_count_excluding_tombstones() {
        let state = RelayAppState::new(RelayStorage::in_memory().unwrap(), RelayConfig::default());
        let (device_id, vault_id, _) = setup_test_vault(&state);
        let conn = state.storage.conn().unwrap();
        let now = Utc::now().timestamp();

        // Insert 2 regular entries and 1 tombstone
        for i in 1..=3 {
            let is_tombstone = i == 3;
            conn.execute(
                "INSERT INTO sync_entries (sync_id, vault_id, entry_type, sync_version, modified_at,
                                           encrypted_payload, is_tombstone, origin_device_id,
                                           server_sequence, received_at)
                 VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9, ?10)",
                rusqlite::params![
                    Uuid::new_v4().to_string(),
                    vault_id,
                    "credential",
                    1i64,
                    now,
                    vec![i as u8],  // Raw bytes, not base64
                    is_tombstone,
                    Uuid::new_v4().to_string(),
                    i,
                    now,
                ],
            )
            .unwrap();
        }
        drop(conn);

        let resp = status(State(state), auth_extensions(device_id))
            .await
            .expect("status succeeds");

        let entry_count = resp
            .get("entry_count")
            .and_then(|v| v.as_i64())
            .expect("entry_count");
        assert_eq!(entry_count, 2); // Excludes tombstone
    }
}
