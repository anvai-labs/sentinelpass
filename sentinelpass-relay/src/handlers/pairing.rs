//! Pairing bootstrap handlers.

use crate::app_state::RelayAppState;
use crate::error::RelayError;
use crate::pairing_security::{hash_pairing_token, hash_registration_proof_b64};
use axum::extract::{Path, State};
use axum::http::Extensions;
use axum::Json;
use base64::Engine;
use chrono::Utc;
use rusqlite::OptionalExtension;
use serde::{Deserialize, Serialize};
use uuid::Uuid;

/// Request body for uploading an encrypted pairing bootstrap blob.
#[derive(Deserialize)]
pub struct UploadBootstrapRequest {
    pub pairing_token: String,
    pub encrypted_bootstrap: String, // base64
    pub pairing_salt: String,        // base64
    pub registration_proof: String,  // base64 (32 bytes)
}

/// Response containing the encrypted bootstrap blob and pairing salt.
#[derive(Debug, Serialize)]
pub struct BootstrapResponse {
    pub encrypted_bootstrap: String, // base64
    pub pairing_salt: String,        // base64
}

/// POST /api/v1/pairing/bootstrap -- Upload an encrypted bootstrap blob for device pairing.
pub async fn upload_bootstrap(
    State(state): State<RelayAppState>,
    extensions: Extensions,
    Json(req): Json<UploadBootstrapRequest>,
) -> Result<Json<serde_json::Value>, RelayError> {
    let uploader_device_id = extensions
        .get::<Uuid>()
        .ok_or_else(|| RelayError::Auth("No device ID".to_string()))?;

    let encrypted = base64::engine::general_purpose::STANDARD
        .decode(&req.encrypted_bootstrap)
        .map_err(|e| RelayError::BadRequest(format!("Invalid bootstrap: {}", e)))?;

    let salt = base64::engine::general_purpose::STANDARD
        .decode(&req.pairing_salt)
        .map_err(|e| RelayError::BadRequest(format!("Invalid salt: {}", e)))?;

    let pairing_token_hash = hash_pairing_token(&req.pairing_token)?;
    let registration_proof_hash = hash_registration_proof_b64(&req.registration_proof)?;

    let mut conn = state.storage.conn()?;
    let now = Utc::now().timestamp();
    let expires_at = now + state.config.pairing_ttl_secs as i64;
    let tx = conn
        .transaction()
        .map_err(|e| RelayError::Database(e.to_string()))?;

    let uploader_vault_id: String = tx
        .query_row(
            "SELECT vault_id FROM devices WHERE device_id = ?1",
            [uploader_device_id.to_string()],
            |row| row.get(0),
        )
        .map_err(|_| RelayError::Auth("Unknown device".to_string()))?;

    // Check active pairing count
    let active_count: i64 = tx
        .query_row(
            "SELECT COUNT(*) FROM pairing_bootstraps WHERE expires_at > ?1 AND consumed = 0",
            [now],
            |row| row.get(0),
        )
        .map_err(|e| RelayError::Database(e.to_string()))?;

    if active_count >= state.config.max_active_pairings as i64 {
        return Err(RelayError::Conflict("Too many active pairings".to_string()));
    }

    tx.execute(
        "INSERT INTO pairing_bootstraps (pairing_token, vault_id, encrypted_bootstrap, pairing_salt, expires_at)
         VALUES (?1, ?2, ?3, ?4, ?5)",
        rusqlite::params![
            &pairing_token_hash,
            &uploader_vault_id,
            &encrypted,
            &salt,
            expires_at
        ],
    )
    .map_err(|e| RelayError::Database(e.to_string()))?;
    tx.execute(
        "INSERT INTO pairing_registration_proofs (proof_hash, pairing_token_hash, vault_id, expires_at)
         VALUES (?1, ?2, ?3, ?4)",
        rusqlite::params![
            &registration_proof_hash,
            &pairing_token_hash,
            &uploader_vault_id,
            expires_at
        ],
    )
    .map_err(|e| RelayError::Database(e.to_string()))?;
    tx.commit()
        .map_err(|e| RelayError::Database(e.to_string()))?;

    Ok(Json(
        serde_json::json!({"status": "uploaded", "expires_at": expires_at}),
    ))
}

/// GET /api/v1/pairing/bootstrap/{token} -- Fetch an encrypted bootstrap blob by pairing token.
pub async fn fetch_bootstrap(
    State(state): State<RelayAppState>,
    Path(token): Path<String>,
) -> Result<Json<BootstrapResponse>, RelayError> {
    let mut conn = state.storage.conn()?;
    let now = Utc::now().timestamp();
    let token_hash = hash_pairing_token(&token)?;
    let token_hash_for_attempts = token_hash.clone();
    let tx = conn
        .transaction()
        .map_err(|e| RelayError::Database(e.to_string()))?;

    let attempt_state: Option<(i64, i64)> = tx
        .query_row(
            "SELECT attempts, blocked_until FROM pairing_fetch_attempts WHERE token_hash = ?1",
            [&token_hash],
            |row| Ok((row.get(0)?, row.get(1)?)),
        )
        .optional()
        .map_err(|e| RelayError::Database(e.to_string()))?;

    if let Some((_attempts, blocked_until)) = attempt_state {
        if blocked_until > now {
            return Err(RelayError::RateLimited);
        }
    }

    let attempts_after = attempt_state.map(|(attempts, _)| attempts + 1).unwrap_or(1);
    tx.execute(
        "INSERT INTO pairing_fetch_attempts (token_hash, attempts, first_attempt_at, last_attempt_at, blocked_until)
         VALUES (?1, ?2, ?3, ?4, 0)
         ON CONFLICT(token_hash) DO UPDATE SET
            attempts = excluded.attempts,
            last_attempt_at = excluded.last_attempt_at",
        rusqlite::params![&token_hash, attempts_after, now, now],
    )
    .map_err(|e| RelayError::Database(e.to_string()))?;

    let attempt_limit = state.config.pairing_fetch_attempt_limit.max(1) as i64;
    if attempts_after > attempt_limit {
        let overflow = (attempts_after - attempt_limit - 1).max(0) as u32;
        let multiplier = 1_u64.checked_shl(overflow.min(16)).unwrap_or(u64::MAX);
        let base_secs = state.config.pairing_fetch_backoff_base_secs.max(1);
        let max_secs = state.config.pairing_fetch_backoff_max_secs.max(base_secs);
        let backoff_secs = base_secs.saturating_mul(multiplier).min(max_secs);
        let blocked_until = now + backoff_secs as i64;
        tx.execute(
            "UPDATE pairing_fetch_attempts SET blocked_until = ?2 WHERE token_hash = ?1",
            rusqlite::params![&token_hash, blocked_until],
        )
        .map_err(|e| RelayError::Database(e.to_string()))?;
        tx.commit()
            .map_err(|e| RelayError::Database(e.to_string()))?;
        tracing::warn!(
            token_hash = %token_hash,
            attempts = attempts_after,
            blocked_until,
            "Pairing bootstrap fetch temporarily blocked due to repeated attempts"
        );
        return Err(RelayError::RateLimited);
    }

    let hashed_hit: Option<(Vec<u8>, Vec<u8>)> = tx
        .query_row(
            "SELECT encrypted_bootstrap, pairing_salt FROM pairing_bootstraps
             WHERE pairing_token = ?1 AND expires_at > ?2 AND consumed = 0",
            rusqlite::params![&token_hash, now],
            |row| Ok((row.get(0)?, row.get(1)?)),
        )
        .optional()
        .map_err(|e| RelayError::Database(e.to_string()))?;

    let (lookup_token, encrypted, salt) = if let Some((encrypted, salt)) = hashed_hit {
        (token_hash, encrypted, salt)
    } else {
        tx.commit()
            .map_err(|e| RelayError::Database(e.to_string()))?;
        return Err(RelayError::NotFound(
            "Pairing token not found or expired".to_string(),
        ));
    };

    // Mark as consumed
    tx.execute(
        "UPDATE pairing_bootstraps SET consumed = 1 WHERE pairing_token = ?1",
        [lookup_token.as_str()],
    )
    .map_err(|e| RelayError::Database(e.to_string()))?;
    tx.execute(
        "DELETE FROM pairing_fetch_attempts WHERE token_hash = ?1",
        [&token_hash_for_attempts],
    )
    .map_err(|e| RelayError::Database(e.to_string()))?;
    tx.commit()
        .map_err(|e| RelayError::Database(e.to_string()))?;

    Ok(Json(BootstrapResponse {
        encrypted_bootstrap: base64::engine::general_purpose::STANDARD.encode(&encrypted),
        pairing_salt: base64::engine::general_purpose::STANDARD.encode(&salt),
    }))
}

#[cfg(test)]
#[allow(clippy::await_holding_lock)] // Test code uses sync DB connections across await points
mod tests {
    use super::*;
    use crate::app_state::RelayAppState;
    use crate::config::RelayConfig;
    use crate::pairing_security::{hash_pairing_token, hash_registration_proof_b64};
    use crate::storage::RelayStorage;
    use axum::extract::State;
    use axum::http::Extensions;
    use axum::Json;
    use base64::engine::general_purpose::STANDARD;
    use chrono::Utc;
    use uuid::Uuid;

    fn state_with_config(pairing_ttl_secs: u64, max_active_pairings: usize) -> RelayAppState {
        let cfg = RelayConfig {
            pairing_ttl_secs,
            max_active_pairings,
            ..RelayConfig::default()
        };
        RelayAppState::new(RelayStorage::in_memory().unwrap(), cfg)
    }

    fn state_with_fetch_policy(
        pairing_fetch_attempt_limit: u32,
        pairing_fetch_backoff_base_secs: u64,
        pairing_fetch_backoff_max_secs: u64,
    ) -> RelayAppState {
        let cfg = RelayConfig {
            pairing_fetch_attempt_limit,
            pairing_fetch_backoff_base_secs,
            pairing_fetch_backoff_max_secs,
            ..RelayConfig::default()
        };
        RelayAppState::new(RelayStorage::in_memory().unwrap(), cfg)
    }

    fn sample_upload_request(token: &str) -> UploadBootstrapRequest {
        UploadBootstrapRequest {
            pairing_token: token.to_string(),
            encrypted_bootstrap: STANDARD.encode([1u8, 2, 3, 4]),
            pairing_salt: STANDARD.encode([5u8; 16]),
            registration_proof: STANDARD.encode([9u8; 32]),
        }
    }

    fn insert_uploader_device(state: &RelayAppState) -> (Uuid, String) {
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
             VALUES (?1, ?2, ?3, ?4, ?5, ?6)",
            rusqlite::params![
                device_id.to_string(),
                &vault_id,
                "Uploader",
                "desktop",
                vec![7u8; 32],
                now,
            ],
        )
        .unwrap();
        (device_id, vault_id)
    }

    fn auth_extensions(device_id: Uuid) -> Extensions {
        let mut extensions = Extensions::new();
        extensions.insert(device_id);
        extensions
    }

    #[tokio::test]
    async fn upload_bootstrap_uses_configured_ttl() {
        let state = state_with_config(42, 5);
        let (device_id, _) = insert_uploader_device(&state);
        let before = Utc::now().timestamp();

        let Json(resp) = upload_bootstrap(
            State(state.clone()),
            auth_extensions(device_id),
            Json(sample_upload_request("ttl-test")),
        )
        .await
        .expect("upload bootstrap");

        let expires_at = resp
            .get("expires_at")
            .and_then(|v| v.as_i64())
            .expect("expires_at");
        let after = Utc::now().timestamp();

        assert!(expires_at >= before + 42);
        assert!(expires_at <= after + 42);
    }

    #[tokio::test]
    async fn upload_bootstrap_enforces_configured_active_limit() {
        let state = state_with_config(300, 1);
        let (device_id, _) = insert_uploader_device(&state);

        let _ = upload_bootstrap(
            State(state.clone()),
            auth_extensions(device_id),
            Json(sample_upload_request("first")),
        )
        .await
        .expect("first upload");

        let err = upload_bootstrap(
            State(state),
            auth_extensions(device_id),
            Json(sample_upload_request("second")),
        )
        .await
        .expect_err("second upload should be rate limited by active pairing count");

        match err {
            RelayError::Conflict(msg) => assert!(msg.contains("Too many active pairings")),
            other => panic!("unexpected error: {}", other),
        }
    }

    #[tokio::test]
    async fn upload_bootstrap_hashes_token_and_stores_registration_proof() {
        let state = state_with_config(300, 5);
        let (device_id, vault_id) = insert_uploader_device(&state);
        let req = sample_upload_request("123456");

        let _ = upload_bootstrap(
            State(state.clone()),
            auth_extensions(device_id),
            Json(UploadBootstrapRequest {
                pairing_token: req.pairing_token.clone(),
                encrypted_bootstrap: req.encrypted_bootstrap.clone(),
                pairing_salt: req.pairing_salt.clone(),
                registration_proof: req.registration_proof.clone(),
            }),
        )
        .await
        .expect("upload bootstrap");

        let conn = state.storage.conn().unwrap();
        let stored_token: String = conn
            .query_row(
                "SELECT pairing_token FROM pairing_bootstraps LIMIT 1",
                [],
                |row| row.get(0),
            )
            .unwrap();
        let stored_vault: String = conn
            .query_row(
                "SELECT vault_id FROM pairing_bootstraps LIMIT 1",
                [],
                |row| row.get(0),
            )
            .unwrap();
        let proof_exists: bool = conn
            .query_row(
                "SELECT EXISTS(SELECT 1 FROM pairing_registration_proofs WHERE proof_hash = ?1)",
                [hash_registration_proof_b64(&req.registration_proof).unwrap()],
                |row| row.get(0),
            )
            .unwrap();

        assert_eq!(
            stored_token,
            hash_pairing_token(&req.pairing_token).unwrap()
        );
        assert_ne!(stored_token, req.pairing_token);
        assert_eq!(stored_vault, vault_id);
        assert!(proof_exists);
    }

    #[tokio::test]
    async fn fetch_bootstrap_rate_limits_repeated_invalid_attempts() {
        let state = state_with_fetch_policy(2, 10, 10);

        let err1 = fetch_bootstrap(State(state.clone()), Path("bad-token".to_string()))
            .await
            .expect_err("first miss");
        let err2 = fetch_bootstrap(State(state.clone()), Path("bad-token".to_string()))
            .await
            .expect_err("second miss");
        let err3 = fetch_bootstrap(State(state.clone()), Path("bad-token".to_string()))
            .await
            .expect_err("third miss should back off");

        assert!(matches!(err1, RelayError::NotFound(_)));
        assert!(matches!(err2, RelayError::NotFound(_)));
        assert!(matches!(err3, RelayError::RateLimited));

        let conn = state.storage.conn().unwrap();
        let (attempts, blocked_until): (i64, i64) = conn
            .query_row(
                "SELECT attempts, blocked_until FROM pairing_fetch_attempts WHERE token_hash = ?1",
                [hash_pairing_token("bad-token").unwrap()],
                |row| Ok((row.get(0)?, row.get(1)?)),
            )
            .unwrap();
        let now = Utc::now().timestamp();

        assert_eq!(attempts, 3);
        assert!(blocked_until > now);
    }

    #[tokio::test]
    async fn fetch_bootstrap_success_clears_attempt_record() {
        let state = state_with_fetch_policy(5, 5, 60);
        let conn = state.storage.conn().unwrap();
        let now = Utc::now().timestamp();
        let token = "valid-token";
        let token_hash = hash_pairing_token(token).unwrap();
        conn.execute(
            "INSERT INTO pairing_bootstraps (pairing_token, vault_id, encrypted_bootstrap, pairing_salt, expires_at, consumed)
             VALUES (?1, ?2, ?3, ?4, ?5, 0)",
            rusqlite::params![&token_hash, "v1", vec![1u8, 2, 3], vec![4u8; 16], now + 300],
        )
        .unwrap();
        conn.execute(
            "INSERT INTO pairing_fetch_attempts (token_hash, attempts, first_attempt_at, last_attempt_at, blocked_until)
             VALUES (?1, ?2, ?3, ?4, ?5)",
            rusqlite::params![&token_hash, 2, now - 20, now - 10, 0],
        )
        .unwrap();
        drop(conn);

        let _ = fetch_bootstrap(State(state.clone()), Path(token.to_string()))
            .await
            .expect("fetch succeeds");

        let conn = state.storage.conn().unwrap();
        let has_attempt_row: bool = conn
            .query_row(
                "SELECT EXISTS(SELECT 1 FROM pairing_fetch_attempts WHERE token_hash = ?1)",
                [&token_hash],
                |row| row.get(0),
            )
            .unwrap();
        assert!(!has_attempt_row);
    }
}
