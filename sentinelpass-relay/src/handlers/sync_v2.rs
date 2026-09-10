//! Sync protocol v2 handlers (ADR-006): transactional, idempotent push with
//! durable per-object results, and a paginated pull over the append-only
//! vault mutation log.
//!
//! Correctness model (WBS-603/604/606):
//! - A mutation applies iff its `expected_version` equals the stored current
//!   version of its object (CAS; 0 = create). Same-version/higher-timestamp
//!   overwrites — the v1 clock-gamed LWW — do not exist in v2.
//! - EVERY mutation gets a durable result row in the same transaction as the
//!   entry/log/sequence writes. A duplicate request returns the ORIGINAL
//!   stored result. Aged-out duplicates are re-evaluated by the CAS guard,
//!   which rejects them (never replays data).
//! - One SQLite transaction per push request: results, object state, the
//!   log, the sequence counter, and the device framing counter commit
//!   together or not at all.
//!
//! Zero-knowledge: the relay stores encrypted payloads and routing metadata
//! only; `metadata_mac` is an opaque verifier token (a DEK-derived HMAC the
//! relay can neither compute nor invert).

use crate::app_state::RelayAppState;
use crate::error::RelayError;
use axum::extract::State;
use axum::http::Extensions;
use axum::Json;
use base64::Engine;
use chrono::Utc;
use serde::{Deserialize, Serialize};
use uuid::Uuid;

/// Maximum mutations accepted per v2 push request.
pub const MAX_MUTATIONS_PER_PUSH: usize = 500;
/// Maximum size of a single encrypted payload (1 MB, parity with v1).
const MAX_ENTRY_PAYLOAD_SIZE: usize = 1_048_576;
/// A mutation may not jump an object's version by more than this (sanity
/// bound; legitimate clients advance by small steps per push).
const MAX_VERSION_STEP: u64 = 10_000;
/// A mutation may not claim an epoch more than this far ABOVE the vault's
/// current epoch (sanity bound, WBS-614): real rotations advance the epoch
/// by small steps, so an authenticated device cannot brick the vault's
/// other devices with `key_epoch = i64::MAX` (a stale-epoch rejection no
/// real rotation could ever rescue).
const MAX_EPOCH_JUMP: i64 = 100_000;

/// v2 mutation received by the relay (serde-compatible with the client's
/// `sentinelpass_core::sync::v2::MutationV2`).
#[derive(Debug, Clone, Deserialize)]
pub struct MutationV2 {
    pub mutation_id: Uuid,
    pub vault_id: Uuid,
    pub object_id: Uuid,
    pub entry_type: String,
    pub expected_version: u64,
    pub resulting_version: u64,
    pub key_epoch: i64,
    pub origin_device_id: Uuid,
    pub is_tombstone: bool,
    pub encrypted_payload: String, // base64
    pub metadata_mac: String,      // base64 (32 bytes)
}

/// Request body for `POST /api/v2/sync/push`.
#[derive(Debug, Clone, Deserialize)]
pub struct PushRequestV2 {
    pub device_sequence: u64,
    pub mutations: Vec<MutationV2>,
}

#[derive(Debug, Serialize, PartialEq)]
#[serde(rename_all = "snake_case", tag = "outcome")]
pub enum MutationOutcome {
    Applied {
        resulting_version: u64,
        server_sequence: i64,
    },
    Rejected {
        reason: RejectionReason,
    },
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
#[serde(rename_all = "snake_case", tag = "reason")]
pub enum RejectionReason {
    VersionConflict { current_version: u64 },
    StaleEpoch { vault_epoch: i64 },
    Malformed,
}

#[derive(Debug, Serialize, PartialEq)]
pub struct MutationResult {
    pub mutation_id: Uuid,
    pub object_id: Uuid,
    pub outcome: MutationOutcome,
}

impl MutationOutcome {
    /// True only for `Applied` (first-time or replayed).
    #[cfg(test)]
    pub fn is_applied_outcome(&self) -> bool {
        matches!(self, MutationOutcome::Applied { .. })
    }
}

/// A stored idempotency row: (outcome, rejection_reason_json,
/// resulting_version, server_sequence).
type StoredMutationResult = (String, Option<String>, Option<i64>, Option<i64>);

/// Response for `POST /api/v2/sync/push`: one durable result per mutation,
/// in request order.
#[derive(Debug, Serialize)]
pub struct PushResponseV2 {
    pub server_cursor: i64,
    pub results: Vec<MutationResult>,
}

/// Request body for `POST /api/v2/sync/pull`.
#[derive(Debug, Deserialize)]
pub struct PullRequestV2 {
    pub since: i64,
    pub limit: Option<u32>,
}

/// A single appended mutation in the pull page.
#[derive(Debug, Serialize)]
pub struct MutationLogEntry {
    pub server_sequence: i64,
    pub mutation: MutationLogMutation,
}

#[derive(Debug, Serialize)]
pub struct MutationLogMutation {
    pub mutation_id: Uuid,
    pub vault_id: Uuid,
    pub object_id: Uuid,
    pub entry_type: String,
    pub expected_version: u64,
    pub resulting_version: u64,
    pub key_epoch: i64,
    pub origin_device_id: Uuid,
    pub is_tombstone: bool,
    pub encrypted_payload: String, // base64
    pub metadata_mac: String,      // base64
}

/// Response for `POST /api/v2/sync/pull`.
#[derive(Debug, Serialize)]
pub struct PullResponseV2 {
    pub entries: Vec<MutationLogEntry>,
    pub cursor: i64,
    pub has_more: bool,
}

/// Static validation that does not depend on stored state.
fn validate_shape(m: &MutationV2) -> Result<(), RelayError> {
    if m.vault_id.is_nil() || m.object_id.is_nil() || m.mutation_id.is_nil() {
        return Err(RelayError::BadRequest(
            "mutation ids must not be nil".into(),
        ));
    }
    if !matches!(
        m.entry_type.as_str(),
        "credential" | "ssh_key" | "totp_secret"
    ) {
        return Err(RelayError::BadRequest(format!(
            "Unknown entry_type: {}",
            m.entry_type
        )));
    }
    if m.resulting_version == 0 {
        return Err(RelayError::BadRequest(
            "resulting_version must be at least 1".into(),
        ));
    }
    if m.resulting_version <= m.expected_version
        || m.resulting_version - m.expected_version > MAX_VERSION_STEP
    {
        return Err(RelayError::BadRequest(
            "resulting_version must exceed expected_version by a sane step".into(),
        ));
    }
    if m.key_epoch < 1 {
        return Err(RelayError::BadRequest(
            "key_epoch must be a positive epoch".into(),
        ));
    }
    let payload = base64::engine::general_purpose::STANDARD
        .decode(&m.encrypted_payload)
        .map_err(|e| RelayError::BadRequest(format!("Invalid payload: {}", e)))?;
    if payload.len() > MAX_ENTRY_PAYLOAD_SIZE {
        return Err(RelayError::BadRequest(format!(
            "Entry payload exceeds maximum size of {} bytes",
            MAX_ENTRY_PAYLOAD_SIZE
        )));
    }
    let mac = base64::engine::general_purpose::STANDARD
        .decode(&m.metadata_mac)
        .map_err(|e| RelayError::BadRequest(format!("Invalid metadata_mac: {}", e)))?;
    if mac.len() != 32 {
        return Err(RelayError::BadRequest(
            "metadata_mac must decode to exactly 32 bytes".into(),
        ));
    }
    Ok(())
}

/// POST /api/v2/sync/push — idempotent, transactional v2 push.
pub async fn push_v2(
    State(state): State<RelayAppState>,
    extensions: Extensions,
    Json(req): Json<PushRequestV2>,
) -> Result<Json<PushResponseV2>, RelayError> {
    let device_id = extensions
        .get::<Uuid>()
        .ok_or_else(|| RelayError::Auth("No device ID".to_string()))?;

    if req.mutations.len() > MAX_MUTATIONS_PER_PUSH {
        return Err(RelayError::BadRequest(format!(
            "Too many mutations per push (max {MAX_MUTATIONS_PER_PUSH})"
        )));
    }

    let mut conn = state.storage.conn()?;
    let now = Utc::now().timestamp();

    let tx = conn
        .transaction()
        .map_err(|e| RelayError::Database(e.to_string()))?;

    let vault_id: String = tx
        .query_row(
            "SELECT vault_id FROM devices WHERE device_id = ?1",
            [device_id.to_string()],
            |row| row.get(0),
        )
        .map_err(|_| RelayError::NotFound("Device not found".to_string()))?;

    // Vault epoch high-water (WBS-614): mutations below it are stale-device
    // uploads and are rejected; a mutation carrying a HIGHER epoch advances
    // the vault (only a current-DEK holder can produce metadata its peers
    // will verify).
    let mut vault_epoch: i64 = tx
        .query_row(
            "SELECT key_epoch FROM vault_epochs WHERE vault_id = ?1",
            [&vault_id],
            |row| row.get(0),
        )
        .unwrap_or(0);

    let mut results: Vec<MutationResult> = Vec::with_capacity(req.mutations.len());
    let mut epoch_changed = false;

    for m in &req.mutations {
        // Static shape first: a malformed mutation is a terminal request
        // error (before any state is read or written).
        validate_shape(m)?;

        if m.vault_id.to_string() != vault_id {
            return Err(RelayError::BadRequest(
                "mutation vault_id must match the authenticated device's vault".into(),
            ));
        }
        if m.origin_device_id != *device_id {
            return Err(RelayError::BadRequest(
                "origin_device_id must match authenticated device".into(),
            ));
        }

        // --- Idempotency: a duplicate returns its ORIGINAL durable result.
        let stored: Option<StoredMutationResult> = tx
            .query_row(
                "SELECT outcome, rejection_reason, resulting_version, server_sequence
                 FROM mutation_results
                 WHERE mutation_id = ?1 AND device_id = ?2 AND vault_id = ?3",
                rusqlite::params![m.mutation_id.to_string(), device_id.to_string(), &vault_id],
                |row| Ok((row.get(0)?, row.get(1)?, row.get(2)?, row.get(3)?)),
            )
            .ok();
        if let Some((outcome, reason, res_version, seq)) = stored {
            let outcome = match outcome.as_str() {
                "applied" => MutationOutcome::Applied {
                    resulting_version: res_version.unwrap_or_default() as u64,
                    server_sequence: seq.unwrap_or_default(),
                },
                _ => MutationOutcome::Rejected {
                    reason: reason
                        .as_deref()
                        .and_then(parse_rejection_reason)
                        .unwrap_or(RejectionReason::Malformed),
                },
            };
            results.push(MutationResult {
                mutation_id: m.mutation_id,
                object_id: m.object_id,
                outcome,
            });
            continue;
        }

        // --- Epoch gate (stale device rejection, WBS-614).
        if m.key_epoch < vault_epoch {
            let reason = RejectionReason::StaleEpoch { vault_epoch };
            record_result(
                &tx,
                &vault_id,
                *device_id,
                m,
                &reason_to_outcome(&reason),
                now,
            )?;
            results.push(MutationResult {
                mutation_id: m.mutation_id,
                object_id: m.object_id,
                outcome: reason_to_outcome(&reason),
            });
            continue;
        }
        if m.key_epoch > vault_epoch {
            if m.key_epoch - vault_epoch > MAX_EPOCH_JUMP {
                return Err(RelayError::BadRequest(format!(
                    "key_epoch advance of {} exceeds the maximum jump of {MAX_EPOCH_JUMP}",
                    m.key_epoch - vault_epoch
                )));
            }
            vault_epoch = m.key_epoch;
            epoch_changed = true;
        }

        // --- CAS version guard (WBS-603/608): apply iff the stored current
        // version equals expected_version.
        let current: Option<i64> = tx
            .query_row(
                "SELECT current_version FROM sync_entries_v2 WHERE vault_id = ?1 AND object_id = ?2",
                rusqlite::params![&vault_id, m.object_id.to_string()],
                |row| row.get(0),
            )
            .ok();

        let applies = match current {
            None => m.expected_version == 0,
            Some(v) => v as u64 == m.expected_version,
        };

        if !applies {
            let reason = RejectionReason::VersionConflict {
                current_version: current.unwrap_or(0) as u64,
            };
            record_result(
                &tx,
                &vault_id,
                *device_id,
                m,
                &reason_to_outcome(&reason),
                now,
            )?;
            results.push(MutationResult {
                mutation_id: m.mutation_id,
                object_id: m.object_id,
                outcome: reason_to_outcome(&reason),
            });
            continue;
        }

        // --- Apply: allocate the next server sequence, then write the log
        // entry, the object state, and the durable result — all inside this
        // transaction.
        tx.execute(
            "UPDATE sequence_counters SET current_sequence = current_sequence + 1 WHERE vault_id = ?1",
            [&vault_id],
        )
        .map_err(|e| RelayError::Database(e.to_string()))?;
        let server_seq: i64 = tx
            .query_row(
                "SELECT current_sequence FROM sequence_counters WHERE vault_id = ?1",
                [&vault_id],
                |row| row.get(0),
            )
            .map_err(|e| RelayError::Database(e.to_string()))?;

        let payload = base64::engine::general_purpose::STANDARD
            .decode(&m.encrypted_payload)
            .map_err(|e| RelayError::BadRequest(format!("Invalid payload: {}", e)))?;

        tx.execute(
            "INSERT INTO sync_mutations_v2 (
                vault_id, server_sequence, mutation_id, object_id, entry_type,
                expected_version, resulting_version, key_epoch, origin_device_id,
                is_tombstone, metadata_mac, encrypted_payload, received_at
             ) VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9, ?10, ?11, ?12, ?13)",
            rusqlite::params![
                &vault_id,
                server_seq,
                m.mutation_id.to_string(),
                m.object_id.to_string(),
                m.entry_type,
                m.expected_version as i64,
                m.resulting_version as i64,
                m.key_epoch,
                m.origin_device_id.to_string(),
                m.is_tombstone,
                m.metadata_mac,
                payload,
                now,
            ],
        )
        .map_err(|e| RelayError::Database(e.to_string()))?;

        tx.execute(
            "INSERT INTO sync_entries_v2 (
                vault_id, object_id, entry_type, current_version, key_epoch,
                is_tombstone, metadata_mac, encrypted_payload, origin_device_id,
                server_sequence, received_at
             ) VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9, ?10, ?11)
             ON CONFLICT(vault_id, object_id) DO UPDATE SET
                entry_type = excluded.entry_type,
                current_version = excluded.current_version,
                key_epoch = excluded.key_epoch,
                is_tombstone = excluded.is_tombstone,
                metadata_mac = excluded.metadata_mac,
                encrypted_payload = excluded.encrypted_payload,
                origin_device_id = excluded.origin_device_id,
                server_sequence = excluded.server_sequence,
                received_at = excluded.received_at",
            rusqlite::params![
                &vault_id,
                m.object_id.to_string(),
                m.entry_type,
                m.resulting_version as i64,
                m.key_epoch,
                m.is_tombstone,
                m.metadata_mac,
                payload,
                m.origin_device_id.to_string(),
                server_seq,
                now,
            ],
        )
        .map_err(|e| RelayError::Database(e.to_string()))?;

        let outcome = MutationOutcome::Applied {
            resulting_version: m.resulting_version,
            server_sequence: server_seq,
        };
        record_result(&tx, &vault_id, *device_id, m, &outcome, now)?;
        results.push(MutationResult {
            mutation_id: m.mutation_id,
            object_id: m.object_id,
            outcome,
        });
    }

    if epoch_changed {
        tx.execute(
            "INSERT INTO vault_epochs (vault_id, key_epoch, updated_at) VALUES (?1, ?2, ?3)
             ON CONFLICT(vault_id) DO UPDATE SET key_epoch = excluded.key_epoch,
                                                updated_at = excluded.updated_at",
            rusqlite::params![&vault_id, vault_epoch, now],
        )
        .map_err(|e| RelayError::Database(e.to_string()))?;
    }

    // Device framing counter: recorded, never gated on (v2 idempotency makes
    // replay of the same counter safe — the v1 strictly-increasing wedge is
    // gone).
    tx.execute(
        "INSERT INTO device_sequences (device_id, last_sequence) VALUES (?1, ?2)
         ON CONFLICT(device_id) DO UPDATE SET
            last_sequence = MAX(last_sequence, excluded.last_sequence)",
        rusqlite::params![device_id.to_string(), req.device_sequence as i64],
    )
    .map_err(|e| RelayError::Database(e.to_string()))?;

    let server_cursor: i64 = tx
        .query_row(
            "SELECT current_sequence FROM sequence_counters WHERE vault_id = ?1",
            [&vault_id],
            |row| row.get(0),
        )
        .map_err(|e| RelayError::Database(e.to_string()))?;

    tx.commit()
        .map_err(|e| RelayError::Database(e.to_string()))?;

    Ok(Json(PushResponseV2 {
        server_cursor,
        results,
    }))
}

fn reason_to_outcome(reason: &RejectionReason) -> MutationOutcome {
    MutationOutcome::Rejected {
        reason: match reason {
            RejectionReason::VersionConflict { current_version } => {
                RejectionReason::VersionConflict {
                    current_version: *current_version,
                }
            }
            RejectionReason::StaleEpoch { vault_epoch } => RejectionReason::StaleEpoch {
                vault_epoch: *vault_epoch,
            },
            RejectionReason::Malformed => RejectionReason::Malformed,
        },
    }
}

/// Persist a durable result row (idempotency record) inside the caller's
/// transaction.
fn record_result(
    tx: &rusqlite::Transaction<'_>,
    vault_id: &str,
    device_id: Uuid,
    m: &MutationV2,
    outcome: &MutationOutcome,
    now: i64,
) -> Result<(), RelayError> {
    let (outcome_str, reason, resulting_version, server_sequence) = match outcome {
        MutationOutcome::Applied {
            resulting_version,
            server_sequence,
        } => (
            "applied",
            None,
            Some(*resulting_version as i64),
            Some(*server_sequence),
        ),
        MutationOutcome::Rejected { reason } => {
            let reason_json =
                serde_json::to_string(reason).map_err(|e| RelayError::Database(e.to_string()))?;
            ("rejected", Some(reason_json), None, None)
        }
    };
    tx.execute(
        "INSERT INTO mutation_results (
            mutation_id, vault_id, device_id, object_id, outcome,
            rejection_reason, resulting_version, server_sequence, created_at
         ) VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9)
         ON CONFLICT(mutation_id, device_id, vault_id) DO NOTHING",
        rusqlite::params![
            m.mutation_id.to_string(),
            vault_id,
            device_id.to_string(),
            m.object_id.to_string(),
            outcome_str,
            reason,
            resulting_version,
            server_sequence,
            now,
        ],
    )
    .map_err(|e| RelayError::Database(e.to_string()))?;
    Ok(())
}

/// Deserialize a stored rejection-reason JSON back to the wire enum.
fn parse_rejection_reason(json: &str) -> Option<RejectionReason> {
    serde_json::from_str(json).ok()
}

/// POST /api/v2/sync/pull — paged pull over the vault mutation log.
pub async fn pull_v2(
    State(state): State<RelayAppState>,
    extensions: Extensions,
    Json(req): Json<PullRequestV2>,
) -> Result<Json<PullResponseV2>, RelayError> {
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

    let limit = req.limit.unwrap_or(500).clamp(1, 2_000) as i64;

    let mut stmt = conn
        .prepare(
            "SELECT server_sequence, mutation_id, object_id, entry_type,
                    expected_version, resulting_version, key_epoch,
                    origin_device_id, is_tombstone, metadata_mac, encrypted_payload
             FROM sync_mutations_v2
             WHERE vault_id = ?1 AND server_sequence > ?2
             ORDER BY server_sequence ASC
             LIMIT ?3",
        )
        .map_err(|e| RelayError::Database(e.to_string()))?;

    let mut entries: Vec<MutationLogEntry> = Vec::new();
    let mut has_more = false;
    let rows = stmt
        .query_map(rusqlite::params![&vault_id, req.since, limit + 1], |row| {
            let seq: i64 = row.get(0)?;
            let payload: Vec<u8> = row.get(10)?;
            Ok((
                seq,
                row.get::<_, String>(1)?,
                row.get::<_, String>(2)?,
                row.get::<_, String>(3)?,
                row.get::<_, i64>(4)?,
                row.get::<_, i64>(5)?,
                row.get::<_, i64>(6)?,
                row.get::<_, String>(7)?,
                row.get::<_, i64>(8)?,
                row.get::<_, String>(9)?,
                payload,
            ))
        })
        .map_err(|e| RelayError::Database(e.to_string()))?;

    for row in rows {
        let row = row.map_err(|e| RelayError::Database(e.to_string()))?;
        if entries.len() == limit as usize {
            has_more = true;
            break;
        }
        let (
            seq,
            mutation_id,
            object_id,
            entry_type,
            expected_version,
            resulting_version,
            key_epoch,
            origin_device_id,
            is_tombstone,
            metadata_mac,
            payload,
        ) = row;
        entries.push(MutationLogEntry {
            server_sequence: seq,
            mutation: MutationLogMutation {
                mutation_id: Uuid::parse_str(&mutation_id)
                    .map_err(|e| RelayError::Database(e.to_string()))?,
                vault_id: Uuid::parse_str(&vault_id)
                    .map_err(|e| RelayError::Database(e.to_string()))?,
                object_id: Uuid::parse_str(&object_id)
                    .map_err(|e| RelayError::Database(e.to_string()))?,
                entry_type,
                expected_version: expected_version as u64,
                resulting_version: resulting_version as u64,
                key_epoch,
                origin_device_id: Uuid::parse_str(&origin_device_id)
                    .map_err(|e| RelayError::Database(e.to_string()))?,
                is_tombstone: is_tombstone != 0,
                encrypted_payload: base64::engine::general_purpose::STANDARD.encode(&payload),
                metadata_mac,
            },
        });
    }

    let cursor = entries
        .last()
        .map(|e| e.server_sequence)
        .unwrap_or(req.since);

    Ok(Json(PullResponseV2 {
        entries,
        cursor,
        has_more,
    }))
}

#[cfg(test)]
#[allow(clippy::await_holding_lock)] // Test code uses sync DB connections across await points
mod tests {
    use super::*;
    use crate::app_state::RelayAppState;
    use crate::config::RelayConfig;
    use crate::storage::RelayStorage;
    use axum::http::Extensions;
    use base64::engine::general_purpose::STANDARD;
    use chrono::Utc;
    use uuid::Uuid;

    fn auth_extensions(device_id: Uuid) -> Extensions {
        let mut extensions = Extensions::new();
        extensions.insert(device_id);
        extensions
    }

    /// A vault with one registered device and initialized counters.
    fn setup(state: &RelayAppState) -> (Uuid, String, Uuid) {
        let device_id = Uuid::new_v4();
        let vault_id = Uuid::new_v4().to_string();
        let now = Utc::now().timestamp();
        let conn = state.storage.conn().unwrap();
        conn.execute(
            "INSERT INTO vaults (vault_id, created_at) VALUES (?1, ?2)",
            rusqlite::params![&vault_id, now],
        )
        .unwrap();
        conn.execute(
            "INSERT INTO sequence_counters (vault_id, current_sequence) VALUES (?1, 0)",
            [&vault_id],
        )
        .unwrap();
        conn.execute(
            "INSERT INTO devices (device_id, vault_id, device_name, device_type, public_key, registered_at)
             VALUES (?1, ?2, 'Test', 'desktop', ?3, ?4)",
            rusqlite::params![device_id.to_string(), &vault_id, vec![1u8; 32], now],
        )
        .unwrap();
        conn.execute(
            "INSERT INTO device_sequences (device_id, last_sequence) VALUES (?1, 0)",
            [device_id.to_string()],
        )
        .unwrap();
        (device_id, vault_id, Uuid::new_v4())
    }

    fn sample_mutation(
        vault_id: &str,
        object_id: Uuid,
        expected: u64,
        resulting: u64,
    ) -> MutationV2 {
        MutationV2 {
            mutation_id: Uuid::new_v4(),
            vault_id: Uuid::parse_str(vault_id).unwrap(),
            object_id,
            entry_type: "credential".to_string(),
            expected_version: expected,
            resulting_version: resulting,
            key_epoch: 1,
            origin_device_id: Uuid::nil(), // overwritten by caller when needed
            is_tombstone: false,
            encrypted_payload: STANDARD.encode([1u8, 2, 3]),
            metadata_mac: STANDARD.encode([7u8; 32]),
        }
    }

    fn stored_result_count(state: &RelayAppState) -> i64 {
        let conn = state.storage.conn().unwrap();
        conn.query_row("SELECT COUNT(*) FROM mutation_results", [], |r| r.get(0))
            .unwrap()
    }

    /// THE WBS-603 positive: a duplicate push returns the ORIGINAL applied
    /// result (same server sequence), and the object/log state is NOT
    /// duplicated — the log gains exactly one entry for one logical mutation.
    #[tokio::test]
    async fn duplicate_push_returns_original_applied_result() {
        let state = RelayAppState::new(RelayStorage::in_memory().unwrap(), RelayConfig::default());
        let (device_id, vault_id, object_id) = setup(&state);

        let mut m = sample_mutation(&vault_id, object_id, 0, 1);
        m.origin_device_id = device_id;
        let req = PushRequestV2 {
            device_sequence: 1,
            mutations: vec![m.clone()],
        };

        let first = push_v2(
            State(state.clone()),
            auth_extensions(device_id),
            Json(req.clone()),
        )
        .await
        .unwrap();
        assert_eq!(first.results.len(), 1);
        assert_eq!(
            first.results[0].outcome,
            MutationOutcome::Applied {
                resulting_version: 1,
                server_sequence: 1,
            }
        );

        // The retry: SAME mutation (same id), a fresh request.
        let retry = push_v2(State(state.clone()), auth_extensions(device_id), Json(req))
            .await
            .unwrap();

        assert_eq!(
            retry.results[0].outcome, first.results[0].outcome,
            "the original durable result must be replayed verbatim"
        );
        assert_eq!(retry.server_cursor, first.server_cursor);

        // State was not duplicated: one log entry, one result row.
        let log_count: i64 = {
            let conn = state.storage.conn().unwrap();
            conn.query_row("SELECT COUNT(*) FROM sync_mutations_v2", [], |r| r.get(0))
                .unwrap()
        };
        let result_count = stored_result_count(&state);
        assert_eq!(log_count, 1);
        assert_eq!(result_count, 1);
    }

    /// THE WBS-603 negative: a duplicate of a REJECTED mutation replays the
    /// original rejection (the ack survives; the client is not invited to
    /// re-evaluate a decided mutation).
    #[tokio::test]
    async fn duplicate_push_returns_original_rejection() {
        let state = RelayAppState::new(RelayStorage::in_memory().unwrap(), RelayConfig::default());
        let (device_id, vault_id, object_id) = setup(&state);

        // Seed the object at version 3 (another device won).
        {
            let conn = state.storage.conn().unwrap();
            conn.execute(
                "INSERT INTO sync_entries_v2 (vault_id, object_id, entry_type, current_version,
                    key_epoch, is_tombstone, metadata_mac, encrypted_payload, origin_device_id,
                    server_sequence, received_at)
                 VALUES (?1, ?2, 'credential', 3, 1, 0, 'mac', X'00', 'other', 1, 1)",
                rusqlite::params![&vault_id, object_id.to_string()],
            )
            .unwrap();
        }

        // Push an edit based on version 2 (stale expectation) → conflict.
        let mut m = sample_mutation(&vault_id, object_id, 2, 3);
        m.origin_device_id = device_id;
        let req = PushRequestV2 {
            device_sequence: 1,
            mutations: vec![m.clone()],
        };

        let first = push_v2(
            State(state.clone()),
            auth_extensions(device_id),
            Json(req.clone()),
        )
        .await
        .unwrap();
        assert_eq!(
            first.results[0].outcome,
            MutationOutcome::Rejected {
                reason: RejectionReason::VersionConflict { current_version: 3 }
            }
        );

        let retry = push_v2(State(state), auth_extensions(device_id), Json(req))
            .await
            .unwrap();
        assert_eq!(
            retry.results[0].outcome, first.results[0].outcome,
            "duplicate of a rejected mutation must replay the original rejection"
        );
    }

    /// Post-expiry duplicate handling (ADR-006: rejected rather than
    /// replayed): with the idempotency record aged out, the re-evaluation
    /// falls to the CAS guard, which REJECTS the stale duplicate — it never
    /// re-applies or rewrites state.
    #[tokio::test]
    async fn expired_duplicate_is_re_evaluated_by_cas_and_rejected() {
        let state = RelayAppState::new(RelayStorage::in_memory().unwrap(), RelayConfig::default());
        let (device_id, vault_id, object_id) = setup(&state);

        let mut m = sample_mutation(&vault_id, object_id, 0, 1);
        m.origin_device_id = device_id;
        let req = PushRequestV2 {
            device_sequence: 1,
            mutations: vec![m.clone()],
        };

        let first = push_v2(
            State(state.clone()),
            auth_extensions(device_id),
            Json(req.clone()),
        )
        .await
        .unwrap();
        assert!(first.results[0].outcome.is_applied_outcome());

        // Simulate retention expiry of the idempotency record.
        {
            let conn = state.storage.conn().unwrap();
            conn.execute("DELETE FROM mutation_results", []).unwrap();
        }

        let expired_retry = push_v2(State(state.clone()), auth_extensions(device_id), Json(req))
            .await
            .unwrap();

        match &expired_retry.results[0].outcome {
            MutationOutcome::Rejected {
                reason: RejectionReason::VersionConflict { current_version },
            } => {
                assert_eq!(*current_version, 1, "CAS must reject, never replay");
            }
            other => panic!("expected CAS rejection of the expired duplicate, got {other:?}"),
        }

        // The object state was NOT re-applied: still version 1, still ONE
        // log entry (the new attempt appended nothing).
        let (version, log_count): (i64, i64) = {
            let conn = state.storage.conn().unwrap();
            (
                conn.query_row(
                    "SELECT current_version FROM sync_entries_v2 WHERE object_id = ?1",
                    [object_id.to_string()],
                    |r| r.get(0),
                )
                .unwrap(),
                conn.query_row("SELECT COUNT(*) FROM sync_mutations_v2", [], |r| r.get(0))
                    .unwrap(),
            )
        };
        assert_eq!(version, 1);
        assert_eq!(log_count, 1);
    }

    /// Same-version overwrites are REJECTED in v2 regardless of
    /// `modified_at` — the relay no longer runs the clock-gamed LWW
    /// (WBS-603/608 groundwork: acceptance is CAS-only).
    #[tokio::test]
    async fn same_version_overwrite_is_rejected_regardless_of_content() {
        let state = RelayAppState::new(RelayStorage::in_memory().unwrap(), RelayConfig::default());
        let (device_id, vault_id, object_id) = setup(&state);

        let mut first = sample_mutation(&vault_id, object_id, 0, 1);
        first.origin_device_id = device_id;
        let _ = push_v2(
            State(state.clone()),
            auth_extensions(device_id),
            Json(PushRequestV2 {
                device_sequence: 1,
                mutations: vec![first],
            }),
        )
        .await
        .unwrap();

        // Same expected version, DIFFERENT content (different mutation id).
        let mut second = sample_mutation(&vault_id, object_id, 0, 1);
        second.origin_device_id = device_id;
        second.encrypted_payload = STANDARD.encode([9u8, 9, 9]);
        let resp = push_v2(
            State(state.clone()),
            auth_extensions(device_id),
            Json(PushRequestV2 {
                device_sequence: 2,
                mutations: vec![second],
            }),
        )
        .await
        .unwrap();
        assert_eq!(
            resp.results[0].outcome,
            MutationOutcome::Rejected {
                reason: RejectionReason::VersionConflict { current_version: 1 }
            }
        );
    }

    /// A create must claim expected_version 0; against an existing object
    /// any nonzero expectation is a conflict, and a fresh object with a
    /// nonzero expectation is rejected too.
    #[tokio::test]
    async fn create_with_nonzero_expectation_is_rejected() {
        let state = RelayAppState::new(RelayStorage::in_memory().unwrap(), RelayConfig::default());
        let (device_id, vault_id, object_id) = setup(&state);

        let mut m = sample_mutation(&vault_id, object_id, 5, 6);
        m.origin_device_id = device_id;
        let resp = push_v2(
            State(state.clone()),
            auth_extensions(device_id),
            Json(PushRequestV2 {
                device_sequence: 1,
                mutations: vec![m],
            }),
        )
        .await
        .unwrap();
        assert_eq!(
            resp.results[0].outcome,
            MutationOutcome::Rejected {
                reason: RejectionReason::VersionConflict { current_version: 0 }
            }
        );
        assert_eq!(stored_result_count(&state), 1, "rejections are durable too");
    }

    /// Stale-epoch rejection: a mutation from a pre-rotation DEK is rejected
    /// once the vault epoch has advanced; a HIGHER epoch advances the vault
    /// (forward-only) and later mutations still apply at the new epoch.
    #[tokio::test]
    async fn epoch_gate_rejects_stale_and_advances_forward() {
        let state = RelayAppState::new(RelayStorage::in_memory().unwrap(), RelayConfig::default());
        let (device_id, vault_id, object_a) = setup(&state);
        let object_b = Uuid::new_v4();

        // Device pushes at epoch 3 → vault epoch advances to 3.
        let mut m1 = sample_mutation(&vault_id, object_a, 0, 1);
        m1.origin_device_id = device_id;
        m1.key_epoch = 3;
        let resp = push_v2(
            State(state.clone()),
            auth_extensions(device_id),
            Json(PushRequestV2 {
                device_sequence: 1,
                mutations: vec![m1],
            }),
        )
        .await
        .unwrap();
        assert!(resp.results[0].outcome.is_applied_outcome());

        // A stale mutation (epoch 2 < vault 3) is rejected as stale — even
        // though its CAS expectation is technically satisfiable.
        let mut stale = sample_mutation(&vault_id, object_b, 0, 1);
        stale.origin_device_id = device_id;
        stale.key_epoch = 2;
        let resp = push_v2(
            State(state.clone()),
            auth_extensions(device_id),
            Json(PushRequestV2 {
                device_sequence: 2,
                mutations: vec![stale],
            }),
        )
        .await
        .unwrap();
        assert_eq!(
            resp.results[0].outcome,
            MutationOutcome::Rejected {
                reason: RejectionReason::StaleEpoch { vault_epoch: 3 }
            }
        );

        // A current-epoch mutation still applies.
        let mut current = sample_mutation(&vault_id, object_b, 0, 1);
        current.origin_device_id = device_id;
        current.key_epoch = 3;
        let resp = push_v2(
            State(state),
            auth_extensions(device_id),
            Json(PushRequestV2 {
                device_sequence: 3,
                mutations: vec![current],
            }),
        )
        .await
        .unwrap();
        assert!(resp.results[0].outcome.is_applied_outcome());
    }

    /// Shape validation negatives: bad type whitelist, zero resulting
    /// version, inverted versions, short MAC.
    #[tokio::test]
    async fn malformed_mutations_are_terminal_request_errors() {
        let state = RelayAppState::new(RelayStorage::in_memory().unwrap(), RelayConfig::default());
        let (device_id, vault_id, object_id) = setup(&state);

        let cases: Vec<MutationV2> = vec![
            {
                let mut m = sample_mutation(&vault_id, object_id, 0, 1);
                m.entry_type = "note".into();
                m
            },
            {
                let mut m = sample_mutation(&vault_id, object_id, 0, 0);
                m.origin_device_id = device_id;
                m
            },
            {
                let mut m = sample_mutation(&vault_id, object_id, 5, 3);
                m.origin_device_id = device_id;
                m
            },
            {
                let mut m = sample_mutation(&vault_id, object_id, 0, 1);
                m.origin_device_id = device_id;
                m.metadata_mac = STANDARD.encode([7u8; 8]);
                m
            },
        ];

        for m in cases {
            let result = push_v2(
                State(state.clone()),
                auth_extensions(device_id),
                Json(PushRequestV2 {
                    device_sequence: 1,
                    mutations: vec![m],
                }),
            )
            .await;
            assert!(
                matches!(result, Err(RelayError::BadRequest(_))),
                "malformed mutation must be a request-level rejection"
            );
        }
        assert_eq!(
            stored_result_count(&state),
            0,
            "nothing durable for malformed input"
        );
    }

    /// Pull serves the log in order with a pagination cursor; a second page
    /// continues after the first cursor; own-device mutations are served
    /// (the client filters them by origin).
    #[tokio::test]
    async fn pull_pages_the_mutation_log_in_order() {
        let state = RelayAppState::new(RelayStorage::in_memory().unwrap(), RelayConfig::default());
        let (device_id, vault_id, object_a) = setup(&state);
        let object_b = Uuid::new_v4();

        let mut m1 = sample_mutation(&vault_id, object_a, 0, 1);
        m1.origin_device_id = device_id;
        let mut m2 = sample_mutation(&vault_id, object_b, 0, 1);
        m2.origin_device_id = device_id;
        m2.entry_type = "ssh_key".into();

        let push = push_v2(
            State(state.clone()),
            auth_extensions(device_id),
            Json(PushRequestV2 {
                device_sequence: 1,
                mutations: vec![m1, m2],
            }),
        )
        .await
        .unwrap();
        assert_eq!(push.server_cursor, 2);

        // Page 1: only the first mutation.
        let page1 = pull_v2(
            State(state.clone()),
            auth_extensions(device_id),
            Json(PullRequestV2 {
                since: 0,
                limit: Some(1),
            }),
        )
        .await
        .unwrap();
        assert_eq!(page1.entries.len(), 1);
        assert_eq!(page1.cursor, 1);
        assert!(page1.has_more);
        assert_eq!(page1.entries[0].mutation.object_id, object_a);
        assert_eq!(page1.entries[0].mutation.resulting_version, 1);

        // Page 2: the rest.
        let page2 = pull_v2(
            State(state.clone()),
            auth_extensions(device_id),
            Json(PullRequestV2 {
                since: page1.cursor,
                limit: Some(10),
            }),
        )
        .await
        .unwrap();
        assert_eq!(page2.entries.len(), 1);
        assert_eq!(page2.cursor, 2);
        assert!(!page2.has_more);
        assert_eq!(page2.entries[0].mutation.object_id, object_b);

        // Empty page: cursor unchanged.
        let page3 = pull_v2(
            State(state),
            auth_extensions(device_id),
            Json(PullRequestV2 {
                since: 2,
                limit: Some(10),
            }),
        )
        .await
        .unwrap();
        assert!(page3.entries.is_empty());
        assert_eq!(page3.cursor, 2);
        assert!(!page3.has_more);
    }

    /// Sequential CAS within one request: two mutations of the same object
    /// (0→1, 1→2) both apply in order.
    #[tokio::test]
    async fn sequential_mutations_of_one_object_apply_in_order() {
        let state = RelayAppState::new(RelayStorage::in_memory().unwrap(), RelayConfig::default());
        let (device_id, vault_id, object_id) = setup(&state);

        let mut m1 = sample_mutation(&vault_id, object_id, 0, 1);
        m1.origin_device_id = device_id;
        let mut m2 = sample_mutation(&vault_id, object_id, 1, 2);
        m2.origin_device_id = device_id;

        let resp = push_v2(
            State(state),
            auth_extensions(device_id),
            Json(PushRequestV2 {
                device_sequence: 1,
                mutations: vec![m1, m2],
            }),
        )
        .await
        .unwrap();
        assert!(resp.results[0].outcome.is_applied_outcome());
        assert!(resp.results[1].outcome.is_applied_outcome());
        assert_eq!(
            resp.results[1].outcome,
            MutationOutcome::Applied {
                resulting_version: 2,
                server_sequence: 2,
            }
        );
    }

    /// An implausible epoch advance (any authenticated device could
    /// otherwise brick the vault's other devices with an unreachable
    /// stale-epoch gate) is a request-level rejection.
    #[tokio::test]
    async fn implausible_epoch_advance_is_rejected() {
        let state = RelayAppState::new(RelayStorage::in_memory().unwrap(), RelayConfig::default());
        let (device_id, vault_id, object_id) = setup(&state);

        // Establish vault epoch 1.
        let mut first = sample_mutation(&vault_id, object_id, 0, 1);
        first.origin_device_id = device_id;
        first.key_epoch = 1;
        let _ = push_v2(
            State(state.clone()),
            auth_extensions(device_id),
            Json(PushRequestV2 {
                device_sequence: 1,
                mutations: vec![first],
            }),
        )
        .await
        .unwrap();

        // A jump far beyond any real rotation count is rejected.
        let mut hostile = sample_mutation(&vault_id, Uuid::new_v4(), 0, 1);
        hostile.origin_device_id = device_id;
        hostile.key_epoch = 1_000_001;
        let err = push_v2(
            State(state.clone()),
            auth_extensions(device_id),
            Json(PushRequestV2 {
                device_sequence: 2,
                mutations: vec![hostile],
            }),
        )
        .await
        .unwrap_err();
        assert!(matches!(err, RelayError::BadRequest(_)), "got: {err:?}");

        // A plausible advance still passes.
        let mut plausible = sample_mutation(&vault_id, Uuid::new_v4(), 0, 1);
        plausible.origin_device_id = device_id;
        plausible.key_epoch = 3;
        let resp = push_v2(
            State(state),
            auth_extensions(device_id),
            Json(PushRequestV2 {
                device_sequence: 3,
                mutations: vec![plausible],
            }),
        )
        .await
        .unwrap();
        assert!(resp.results[0].outcome.is_applied_outcome());
    }

    /// Cleanup ages out idempotency records and enforces the per-device cap.
    #[test]
    fn cleanup_prunes_mutation_results_by_age_and_cap() {
        let storage = RelayStorage::in_memory().unwrap();
        let conn = storage.conn().unwrap();
        let now = chrono::Utc::now().timestamp();

        // Old record (past the TTL) and two fresh records for one device.
        for (i, age) in [(1, 10 * 24 * 3600), (2, 0), (3, 0)] {
            conn.execute(
                "INSERT INTO mutation_results (mutation_id, vault_id, device_id, object_id,
                    outcome, rejection_reason, resulting_version, server_sequence, created_at)
                 VALUES (?1, 'v', 'd', 'o', 'applied', NULL, 1, ?2, ?3)",
                rusqlite::params![format!("m{i}"), i, now - age],
            )
            .unwrap();
        }
        drop(conn);

        crate::cleanup::run_cleanup(&storage, 90, 60, 300, 7 * 24 * 3600, 2).unwrap();

        let remaining: Vec<String> = {
            let conn = storage.conn().unwrap();
            let mut stmt = conn
                .prepare("SELECT mutation_id FROM mutation_results ORDER BY mutation_id")
                .unwrap();
            stmt.query_map([], |r| r.get(0))
                .unwrap()
                .collect::<Result<Vec<_>, _>>()
                .unwrap()
        };
        // The aged record is gone; the cap keeps the two newest fresh ones.
        assert_eq!(remaining.len(), 2);
        assert!(remaining.contains(&"m2".to_string()) && remaining.contains(&"m3".to_string()));
    }
}
