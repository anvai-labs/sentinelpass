//! Device registration and management handlers.

use crate::app_state::RelayAppState;
use crate::error::RelayError;
use crate::pairing_security::{hash_pairing_token, hash_registration_proof_b64};
use axum::extract::State;
use axum::http::Extensions;
use axum::Json;
use base64::Engine;
use chrono::Utc;
use serde::{Deserialize, Serialize};
use uuid::Uuid;

/// Request body for device registration.
#[derive(Deserialize)]
pub struct RegisterDeviceRequest {
    pub device_id: Uuid,
    pub device_name: String,
    pub device_type: String,
    pub public_key: String, // base64
    pub vault_id: Uuid,
    #[serde(default)]
    pub pairing_token: Option<String>,
    #[serde(default)]
    pub registration_proof: Option<String>, // base64 (32 bytes)
}

/// Device information returned by the list devices endpoint.
#[derive(Serialize)]
pub struct DeviceInfo {
    pub device_id: String,
    pub device_name: String,
    pub device_type: String,
    pub registered_at: i64,
    pub revoked: bool,
}

/// POST /api/v1/devices/register -- Register a new device with its Ed25519 public key.
pub async fn register_device(
    State(state): State<RelayAppState>,
    Json(req): Json<RegisterDeviceRequest>,
) -> Result<Json<serde_json::Value>, RelayError> {
    let public_key = base64::engine::general_purpose::STANDARD
        .decode(&req.public_key)
        .map_err(|e| RelayError::BadRequest(format!("Invalid public key: {}", e)))?;

    if public_key.len() != 32 {
        return Err(RelayError::BadRequest(
            "Public key must be 32 bytes".to_string(),
        ));
    }

    let mut conn = state.storage.conn()?;
    let now = Utc::now().timestamp();
    let vault_id_str = req.vault_id.to_string();
    let device_id_str = req.device_id.to_string();
    let tx = conn
        .transaction()
        .map_err(|e| RelayError::Database(e.to_string()))?;

    // Existing-vault joins require a valid unconsumed pairing registration proof.
    let existing_device_count: i64 = tx
        .query_row(
            "SELECT COUNT(*) FROM devices WHERE vault_id = ?1",
            [&vault_id_str],
            |row| row.get(0),
        )
        .map_err(|e| RelayError::Database(e.to_string()))?;

    if existing_device_count > 0 {
        let pairing_token = req
            .pairing_token
            .as_deref()
            .ok_or_else(|| RelayError::Auth("Pairing token required".to_string()))?;
        let registration_proof = req
            .registration_proof
            .as_deref()
            .ok_or_else(|| RelayError::Auth("Registration proof required".to_string()))?;

        let pairing_token_hash = hash_pairing_token(pairing_token)?;
        let proof_hash = hash_registration_proof_b64(registration_proof)?;

        let consumed = tx
            .execute(
                "UPDATE pairing_registration_proofs
                 SET consumed = 1
                 WHERE proof_hash = ?1
                   AND pairing_token_hash = ?2
                   AND vault_id = ?3
                   AND expires_at > ?4
                   AND consumed = 0",
                rusqlite::params![proof_hash, pairing_token_hash, &vault_id_str, now],
            )
            .map_err(|e| RelayError::Database(e.to_string()))?;

        if consumed == 0 {
            return Err(RelayError::Auth(
                "Missing or invalid pairing registration proof".to_string(),
            ));
        }
    }

    // Ensure vault exists
    tx.execute(
        "INSERT OR IGNORE INTO vaults (vault_id, created_at) VALUES (?1, ?2)",
        rusqlite::params![&vault_id_str, now],
    )
    .map_err(|e| RelayError::Database(e.to_string()))?;

    // Ensure sequence counter exists
    tx.execute(
        "INSERT OR IGNORE INTO sequence_counters (vault_id, current_sequence) VALUES (?1, 0)",
        [&vault_id_str],
    )
    .map_err(|e| RelayError::Database(e.to_string()))?;

    if req.device_name.len() > 255 {
        return Err(RelayError::BadRequest(
            "Device name must be 255 characters or fewer".to_string(),
        ));
    }

    // Register device — public_key is immutable after registration;
    // revoke + re-register through the pairing flow to rotate keys.
    tx.execute(
        "INSERT INTO devices (device_id, vault_id, device_name, device_type, public_key, registered_at)
         VALUES (?1, ?2, ?3, ?4, ?5, ?6)
         ON CONFLICT(device_id) DO UPDATE SET
            device_name = excluded.device_name",
        rusqlite::params![
            &device_id_str,
            &vault_id_str,
            req.device_name,
            req.device_type,
            public_key,
            now,
        ],
    )
    .map_err(|e| RelayError::Database(e.to_string()))?;

    // Init device sequence
    tx.execute(
        "INSERT OR IGNORE INTO device_sequences (device_id, last_sequence) VALUES (?1, 0)",
        [&device_id_str],
    )
    .map_err(|e| RelayError::Database(e.to_string()))?;
    tx.commit()
        .map_err(|e| RelayError::Database(e.to_string()))?;

    Ok(Json(serde_json::json!({"status": "registered"})))
}

/// GET /api/v1/devices -- List all devices in the authenticated device's vault.
pub async fn list_devices(
    State(state): State<RelayAppState>,
    extensions: Extensions,
) -> Result<Json<Vec<DeviceInfo>>, RelayError> {
    let device_id = extensions
        .get::<Uuid>()
        .ok_or_else(|| RelayError::Auth("No device ID".to_string()))?;

    let conn = state.storage.conn()?;

    // Find vault for this device
    let vault_id: String = conn
        .query_row(
            "SELECT vault_id FROM devices WHERE device_id = ?1",
            [device_id.to_string()],
            |row| row.get(0),
        )
        .map_err(|_| RelayError::NotFound("Device not found".to_string()))?;

    let mut stmt = conn
        .prepare(
            "SELECT device_id, device_name, device_type, registered_at, revoked
             FROM devices WHERE vault_id = ?1",
        )
        .map_err(|e| RelayError::Database(e.to_string()))?;

    let devices: Vec<DeviceInfo> = stmt
        .query_map([&vault_id], |row| {
            Ok(DeviceInfo {
                device_id: row.get(0)?,
                device_name: row.get(1)?,
                device_type: row.get(2)?,
                registered_at: row.get(3)?,
                revoked: row.get(4)?,
            })
        })
        .map_err(|e| RelayError::Database(e.to_string()))?
        .collect::<Result<Vec<_>, _>>()
        .map_err(|e| RelayError::Database(e.to_string()))?;

    Ok(Json(devices))
}

/// POST /api/v1/devices/{id}/revoke -- Revoke a device, preventing further sync operations.
pub async fn revoke_device(
    State(state): State<RelayAppState>,
    axum::extract::Path(target_id): axum::extract::Path<String>,
    extensions: Extensions,
) -> Result<Json<serde_json::Value>, RelayError> {
    let requester_id = extensions
        .get::<Uuid>()
        .ok_or_else(|| RelayError::Auth("No device ID".to_string()))?;

    let conn = state.storage.conn()?;

    // Verify both devices belong to the same vault
    let requester_vault: String = conn
        .query_row(
            "SELECT vault_id FROM devices WHERE device_id = ?1",
            [requester_id.to_string()],
            |row| row.get(0),
        )
        .map_err(|_| RelayError::NotFound("Requester device not found".to_string()))?;

    let target_vault: String = conn
        .query_row(
            "SELECT vault_id FROM devices WHERE device_id = ?1",
            [&target_id],
            |row| row.get(0),
        )
        .map_err(|_| RelayError::NotFound("Target device not found".to_string()))?;

    if requester_vault != target_vault {
        return Err(RelayError::Auth(
            "Cannot revoke device from different vault".to_string(),
        ));
    }

    let now = Utc::now().timestamp();
    conn.execute(
        "UPDATE devices SET revoked = 1, revoked_at = ?1 WHERE device_id = ?2",
        rusqlite::params![now, target_id],
    )
    .map_err(|e| RelayError::Database(e.to_string()))?;

    Ok(Json(serde_json::json!({"status": "revoked"})))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::app_state::RelayAppState;
    use crate::config::RelayConfig;
    use crate::pairing_security::{hash_pairing_token, hash_registration_proof_b64};
    use crate::storage::RelayStorage;
    use axum::extract::State;
    use axum::Json;
    use base64::engine::general_purpose::STANDARD;

    fn test_state() -> RelayAppState {
        RelayAppState::new(RelayStorage::in_memory().unwrap(), RelayConfig::default())
    }

    fn register_request(vault_id: Uuid) -> RegisterDeviceRequest {
        RegisterDeviceRequest {
            device_id: Uuid::new_v4(),
            device_name: "Test Device".to_string(),
            device_type: "desktop".to_string(),
            public_key: STANDARD.encode([7u8; 32]),
            vault_id,
            pairing_token: None,
            registration_proof: None,
        }
    }

    fn seed_existing_device(state: &RelayAppState, vault_id: Uuid) {
        let conn = state.storage.conn().unwrap();
        let now = Utc::now().timestamp();
        let vault_id_str = vault_id.to_string();
        conn.execute(
            "INSERT INTO vaults (vault_id, created_at) VALUES (?1, ?2)",
            rusqlite::params![&vault_id_str, now],
        )
        .unwrap();
        conn.execute(
            "INSERT INTO sequence_counters (vault_id, current_sequence) VALUES (?1, 0)",
            [&vault_id_str],
        )
        .unwrap();
        conn.execute(
            "INSERT INTO devices (device_id, vault_id, device_name, device_type, public_key, registered_at)
             VALUES (?1, ?2, ?3, ?4, ?5, ?6)",
            rusqlite::params![
                Uuid::new_v4().to_string(),
                &vault_id_str,
                "Existing Device",
                "desktop",
                vec![1u8; 32],
                now,
            ],
        )
        .unwrap();
    }

    fn seed_registration_proof(
        state: &RelayAppState,
        vault_id: Uuid,
        pairing_token: &str,
        proof_b64: &str,
        expires_at: i64,
    ) {
        let conn = state.storage.conn().unwrap();
        conn.execute(
            "INSERT INTO pairing_registration_proofs (proof_hash, pairing_token_hash, vault_id, expires_at, consumed)
             VALUES (?1, ?2, ?3, ?4, 0)",
            rusqlite::params![
                hash_registration_proof_b64(proof_b64).unwrap(),
                hash_pairing_token(pairing_token).unwrap(),
                vault_id.to_string(),
                expires_at
            ],
        )
        .unwrap();
    }

    #[tokio::test]
    async fn first_device_registration_succeeds_without_pairing_proof() {
        let state = test_state();
        let vault_id = Uuid::new_v4();

        let _ = register_device(State(state.clone()), Json(register_request(vault_id)))
            .await
            .expect("first device registration should succeed");

        let conn = state.storage.conn().unwrap();
        let count: i64 = conn
            .query_row(
                "SELECT COUNT(*) FROM devices WHERE vault_id = ?1",
                [vault_id.to_string()],
                |row| row.get(0),
            )
            .unwrap();
        assert_eq!(count, 1);
    }

    #[tokio::test]
    async fn existing_vault_registration_requires_pairing_proof() {
        let state = test_state();
        let vault_id = Uuid::new_v4();
        seed_existing_device(&state, vault_id);

        let err = register_device(State(state), Json(register_request(vault_id)))
            .await
            .expect_err("existing vault join should require proof");

        match err {
            RelayError::Auth(msg) => assert!(msg.contains("Pairing token required")),
            other => panic!("unexpected error: {}", other),
        }
    }

    #[tokio::test]
    async fn re_registration_does_not_update_public_key() {
        let state = test_state();
        let vault_id = Uuid::new_v4();
        let device_id = Uuid::new_v4();

        let original_key = [7u8; 32];
        let new_key = [9u8; 32];

        // First registration
        let req = RegisterDeviceRequest {
            device_id,
            device_name: "Device A".to_string(),
            device_type: "desktop".to_string(),
            public_key: STANDARD.encode(original_key),
            vault_id,
            pairing_token: None,
            registration_proof: None,
        };
        let _ = register_device(State(state.clone()), Json(req))
            .await
            .expect("first registration should succeed");

        // Re-registration with a different public key requires pairing proof
        // because the vault already has a device registered.
        let pairing_token = "123456";
        let registration_proof = STANDARD.encode([42u8; 32]);
        seed_registration_proof(
            &state,
            vault_id,
            pairing_token,
            &registration_proof,
            Utc::now().timestamp() + 300,
        );

        let req2 = RegisterDeviceRequest {
            device_id,
            device_name: "Device A Renamed".to_string(),
            device_type: "desktop".to_string(),
            public_key: STANDARD.encode(new_key),
            vault_id,
            pairing_token: Some(pairing_token.to_string()),
            registration_proof: Some(registration_proof.clone()),
        };
        let _ = register_device(State(state.clone()), Json(req2))
            .await
            .expect("re-registration should succeed");

        // Verify public_key was NOT updated
        let conn = state.storage.conn().unwrap();
        let stored_key: Vec<u8> = conn
            .query_row(
                "SELECT public_key FROM devices WHERE device_id = ?1",
                [device_id.to_string()],
                |row| row.get(0),
            )
            .unwrap();
        assert_eq!(
            stored_key,
            original_key.to_vec(),
            "public_key must not change on re-registration"
        );

        // Verify device_name WAS updated
        let stored_name: String = conn
            .query_row(
                "SELECT device_name FROM devices WHERE device_id = ?1",
                [device_id.to_string()],
                |row| row.get(0),
            )
            .unwrap();
        assert_eq!(stored_name, "Device A Renamed");
    }

    #[tokio::test]
    async fn rejects_device_name_exceeding_max_length() {
        let state = test_state();
        let vault_id = Uuid::new_v4();

        let mut req = register_request(vault_id);
        req.device_name = "x".repeat(256);

        let err = register_device(State(state), Json(req))
            .await
            .expect_err("should reject oversized device name");

        match err {
            RelayError::BadRequest(msg) => assert!(msg.contains("255")),
            other => panic!("unexpected error: {}", other),
        }
    }

    #[tokio::test]
    async fn existing_vault_registration_succeeds_with_valid_pairing_proof() {
        let state = test_state();
        let vault_id = Uuid::new_v4();
        seed_existing_device(&state, vault_id);

        let pairing_token = "123456";
        let registration_proof = STANDARD.encode([9u8; 32]);
        seed_registration_proof(
            &state,
            vault_id,
            pairing_token,
            &registration_proof,
            Utc::now().timestamp() + 300,
        );

        let mut req = register_request(vault_id);
        req.pairing_token = Some(pairing_token.to_string());
        req.registration_proof = Some(registration_proof.clone());

        let _ = register_device(State(state.clone()), Json(req))
            .await
            .expect("existing vault join with proof should succeed");

        let conn = state.storage.conn().unwrap();
        let consumed: bool = conn
            .query_row(
                "SELECT consumed FROM pairing_registration_proofs WHERE proof_hash = ?1",
                [hash_registration_proof_b64(&registration_proof).unwrap()],
                |row| row.get(0),
            )
            .unwrap();
        assert!(consumed);
    }
}
