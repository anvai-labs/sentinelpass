//! Pairing v2 handlers (WBS-615/616, ADR-006 / SR-SYNC-006): a 256-bit
//! high-entropy secret S is the sole pairing root. The bootstrap is
//! encrypted under HKDF(S) CLIENT-side; the relay stores only Argon2id(S)
//! plus the ciphertext, gates retrieval on knowledge of S (attempt-limited,
//! one-use, short TTL), and never sees the derived key. Pairing material
//! moves in POST bodies — never in URLs. The six-digit transcript shown on
//! both devices is a human comparison aid the relay never sees.

use crate::app_state::RelayAppState;
use crate::error::RelayError;
use crate::pairing_security::{hash_bytes_hex, hash_pairing_token, verify_pairing_token};
use axum::extract::State;
use axum::http::Extensions;
use axum::Json;
use base64::Engine;
use chrono::Utc;
use rusqlite::OptionalExtension;
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use uuid::Uuid;

/// Maximum size of an encrypted bootstrap blob (the bootstrap carries KDF
/// params + a wrapped DEK — tens of bytes of real material).
const MAX_BOOTSTRAP_SIZE: usize = 65_536;
/// The pairing secret must decode to exactly this many bytes (256 bits).
const SECRET_LEN: usize = 32;

/// A validated pairing secret: the raw bytes plus the deterministic
/// bootstrap id (hex(SHA256(S))[..32]).
struct PairingSecret {
    id: String,
    raw: String,
}

/// A stored v2 bootstrap row: (rowid, secret_hash, encrypted_bootstrap,
/// registration_proof, vault_id).
type StoredBootstrapV2 = (i64, String, Vec<u8>, Vec<u8>, String);

fn parse_secret(encoded: &str) -> Result<PairingSecret, RelayError> {
    let bytes = base64::engine::general_purpose::URL_SAFE_NO_PAD
        .decode(encoded.trim())
        .map_err(|e| RelayError::BadRequest(format!("invalid pairing secret encoding: {e}")))?;
    if bytes.len() != SECRET_LEN {
        return Err(RelayError::BadRequest(format!(
            "pairing secret must be {SECRET_LEN} bytes"
        )));
    }
    Ok(PairingSecret {
        id: hex::encode(&Sha256::digest(&bytes)[..16]),
        raw: encoded.trim().to_string(),
    })
}

#[derive(Deserialize)]
pub struct UploadBootstrapV2Request {
    /// base64url 256-bit pairing secret (over TLS; stored as Argon2id only).
    pub secret: String,
    /// base64 encrypted bootstrap (encrypted under HKDF(S) CLIENT-side).
    pub encrypted_bootstrap: String,
    /// base64 registration proof (binds registration to the pairing key).
    pub registration_proof: String,
}

/// POST /api/v2/pairing/bootstrap — upload an encrypted bootstrap bound to a
/// 256-bit secret. Authenticated (the existing device uploads it).
pub async fn upload_bootstrap_v2(
    State(state): State<RelayAppState>,
    extensions: Extensions,
    Json(req): Json<UploadBootstrapV2Request>,
) -> Result<Json<serde_json::Value>, RelayError> {
    let uploader_device_id = extensions
        .get::<Uuid>()
        .ok_or_else(|| RelayError::Auth("No device ID".to_string()))?;

    let secret = parse_secret(&req.secret)?;
    let encrypted = base64::engine::general_purpose::STANDARD
        .decode(&req.encrypted_bootstrap)
        .map_err(|e| RelayError::BadRequest(format!("invalid bootstrap: {e}")))?;
    if encrypted.len() > MAX_BOOTSTRAP_SIZE {
        return Err(RelayError::BadRequest(
            "bootstrap exceeds the maximum size".into(),
        ));
    }
    let proof = base64::engine::general_purpose::STANDARD
        .decode(&req.registration_proof)
        .map_err(|e| RelayError::BadRequest(format!("invalid registration proof: {e}")))?;
    if proof.len() != 32 {
        return Err(RelayError::BadRequest(
            "registration proof must be 32 bytes".into(),
        ));
    }

    let secret_hash = hash_pairing_token(&secret.raw)?;

    let mut conn = state.storage.conn()?;
    let now = Utc::now().timestamp();
    let expires_at = now + state.config.pairing_ttl_secs as i64;
    let tx = conn
        .transaction()
        .map_err(|e| RelayError::Database(e.to_string()))?;

    let uploader_vault: String = tx
        .query_row(
            "SELECT vault_id FROM devices WHERE device_id = ?1",
            [uploader_device_id.to_string()],
            |row| row.get(0),
        )
        .map_err(|_| RelayError::Auth("Unknown device".to_string()))?;

    // Bounded active pairings (relay-wide, parity with v1).
    let active: i64 = tx
        .query_row(
            "SELECT COUNT(*) FROM pairing_bootstraps_v2 WHERE expires_at > ?1 AND consumed = 0",
            [now],
            |row| row.get(0),
        )
        .map_err(|e| RelayError::Database(e.to_string()))?;
    if active >= state.config.max_active_pairings as i64 {
        return Err(RelayError::Conflict("Too many active pairings".to_string()));
    }

    let uploaded = tx
        .execute(
            "INSERT INTO pairing_bootstraps_v2 (
                bootstrap_id, vault_id, secret_hash, encrypted_bootstrap,
                registration_proof, expires_at, received_at
             ) VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7)
             ON CONFLICT(bootstrap_id) DO UPDATE SET
                secret_hash = excluded.secret_hash,
                encrypted_bootstrap = excluded.encrypted_bootstrap,
                registration_proof = excluded.registration_proof,
                expires_at = excluded.expires_at,
                received_at = excluded.received_at
             WHERE pairing_bootstraps_v2.consumed = 0",
            rusqlite::params![
                secret.id,
                &uploader_vault,
                secret_hash,
                encrypted,
                proof,
                expires_at,
                now,
            ],
        )
        .map_err(|e| RelayError::Database(e.to_string()))?;
    if uploaded == 0 {
        return Err(RelayError::Conflict(
            "pairing bootstrap already consumed".to_string(),
        ));
    }

    tx.commit()
        .map_err(|e| RelayError::Database(e.to_string()))?;

    Ok(Json(
        serde_json::json!({"status": "uploaded", "expires_at": expires_at}),
    ))
}

#[derive(Deserialize)]
pub struct RetrieveBootstrapV2Request {
    /// base64url 256-bit pairing secret (knowledge of S is the retrieval
    /// credential; sent in the BODY, never a URL — WBS-616).
    pub secret: String,
}

#[derive(Serialize)]
#[cfg_attr(test, derive(Debug))]
pub struct RetrieveBootstrapV2Response {
    /// base64 encrypted bootstrap (decrypt with HKDF(S)).
    pub encrypted_bootstrap: String,
    /// base64 registration proof (binds device registration to the pairing).
    pub registration_proof: String,
}

/// POST /api/v2/pairing/bootstrap/retrieve — prove knowledge of S to
/// retrieve (and consume) the bootstrap. Attempt-limited with exponential
/// backoff (parity with v1); one-use.
pub async fn retrieve_bootstrap_v2(
    State(state): State<RelayAppState>,
    Json(req): Json<RetrieveBootstrapV2Request>,
) -> Result<Json<RetrieveBootstrapV2Response>, RelayError> {
    let secret = parse_secret(&req.secret)?;

    let mut conn = state.storage.conn()?;
    let now = Utc::now().timestamp();
    // Attempt limiting keys on the bootstrap id (a fast hash of the
    // client-supplied id — the Argon2id secret hash cannot serve as a
    // lookup key).
    let lookup_hash = hash_bytes_hex(secret.id.as_bytes());
    let tx = conn
        .transaction()
        .map_err(|e| RelayError::Database(e.to_string()))?;

    let attempt_state: Option<(i64, i64)> = tx
        .query_row(
            "SELECT attempts, blocked_until FROM pairing_fetch_attempts WHERE token_hash = ?1",
            [&lookup_hash],
            |row| Ok((row.get(0)?, row.get(1)?)),
        )
        .optional()
        .map_err(|e| RelayError::Database(e.to_string()))?;
    if let Some((_, blocked_until)) = attempt_state {
        if blocked_until > now {
            return Err(RelayError::RateLimited);
        }
    }

    let attempts_after = attempt_state.map(|(a, _)| a + 1).unwrap_or(1);
    tx.execute(
        "INSERT INTO pairing_fetch_attempts (token_hash, attempts, first_attempt_at, last_attempt_at, blocked_until)
         VALUES (?1, ?2, ?3, ?3, 0)
         ON CONFLICT(token_hash) DO UPDATE SET
            attempts = excluded.attempts,
            last_attempt_at = excluded.last_attempt_at",
        rusqlite::params![&lookup_hash, attempts_after, now],
    )
    .map_err(|e| RelayError::Database(e.to_string()))?;

    let attempt_limit = state.config.pairing_fetch_attempt_limit.max(1) as i64;
    if attempts_after > attempt_limit {
        let overflow = (attempts_after - attempt_limit - 1).max(0) as u32;
        let multiplier = 1_u64.checked_shl(overflow.min(16)).unwrap_or(u64::MAX);
        let base = state.config.pairing_fetch_backoff_base_secs.max(1);
        let max = state.config.pairing_fetch_backoff_max_secs.max(base);
        let blocked_until = now + base.saturating_mul(multiplier).min(max) as i64;
        tx.execute(
            "UPDATE pairing_fetch_attempts SET blocked_until = ?2 WHERE token_hash = ?1",
            rusqlite::params![&lookup_hash, blocked_until],
        )
        .map_err(|e| RelayError::Database(e.to_string()))?;
        tx.commit()
            .map_err(|e| RelayError::Database(e.to_string()))?;
        tracing::warn!(
            bootstrap_id = %secret.id,
            blocked_until,
            "pairing v2 retrieve temporarily blocked after repeated attempts"
        );
        return Err(RelayError::RateLimited);
    }

    let row: Option<StoredBootstrapV2> = tx
        .query_row(
            "SELECT rowid, secret_hash, encrypted_bootstrap, registration_proof, vault_id
             FROM pairing_bootstraps_v2
             WHERE bootstrap_id = ?1 AND expires_at > ?2 AND consumed = 0",
            rusqlite::params![secret.id, now],
            |row| {
                Ok((
                    row.get(0)?,
                    row.get(1)?,
                    row.get(2)?,
                    row.get(3)?,
                    row.get(4)?,
                ))
            },
        )
        .optional()
        .map_err(|e| RelayError::Database(e.to_string()))?;

    let Some((rowid, stored_hash, encrypted, proof, vault_id)) = row else {
        tx.commit()
            .map_err(|e| RelayError::Database(e.to_string()))?;
        return Err(RelayError::NotFound(
            "pairing bootstrap not found or expired".to_string(),
        ));
    };

    // Argon2id knowledge proof for S.
    if !verify_pairing_token(&secret.raw, &stored_hash).unwrap_or(false) {
        tx.commit()
            .map_err(|e| RelayError::Database(e.to_string()))?;
        return Err(RelayError::NotFound(
            "pairing bootstrap not found or expired".to_string(),
        ));
    }

    // ONE-USE: consume in the SAME statement-flow as the return data.
    tx.execute(
        "UPDATE pairing_bootstraps_v2 SET consumed = 1 WHERE rowid = ?1",
        [rowid],
    )
    .map_err(|e| RelayError::Database(e.to_string()))?;
    tx.execute(
        "DELETE FROM pairing_fetch_attempts WHERE token_hash = ?1",
        [&lookup_hash],
    )
    .map_err(|e| RelayError::Database(e.to_string()))?;
    // Stage the registration proof for the EXISTING register endpoint: the
    // joiner presents (secret, proof) at /api/v1/devices/register; the
    // endpoint matches the proof hash and Argon2-verifies the secret. This
    // binds registration to knowledge of S with a short window.
    tx.execute(
        "INSERT INTO pairing_registration_proofs (proof_hash, pairing_token_hash, vault_id, expires_at)
         VALUES (?1, ?2, ?3, ?4)",
        rusqlite::params![
            crate::pairing_security::hash_registration_proof_b64(&base64::engine::general_purpose::STANDARD.encode(&proof))?,
            hash_pairing_token(&secret.raw)?,
            vault_id,
            now + 300,
        ],
    )
    .map_err(|e| RelayError::Database(e.to_string()))?;
    tx.commit()
        .map_err(|e| RelayError::Database(e.to_string()))?;

    Ok(Json(RetrieveBootstrapV2Response {
        encrypted_bootstrap: base64::engine::general_purpose::STANDARD.encode(&encrypted),
        registration_proof: base64::engine::general_purpose::STANDARD.encode(&proof),
    }))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::app_state::RelayAppState;
    use crate::config::RelayConfig;
    use crate::storage::RelayStorage;
    use base64::engine::general_purpose::{STANDARD, URL_SAFE_NO_PAD};

    fn auth_extensions(device_id: Uuid) -> Extensions {
        let mut extensions = Extensions::new();
        extensions.insert(device_id);
        extensions
    }

    fn setup(state: &RelayAppState) -> Uuid {
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
            "INSERT INTO devices (device_id, vault_id, device_name, device_type, public_key, registered_at)
             VALUES (?1, ?2, 'Uploader', 'desktop', ?3, ?4)",
            rusqlite::params![device_id.to_string(), &vault_id, vec![1u8; 32], now],
        )
        .unwrap();
        device_id
    }

    fn b64url(bytes: &[u8]) -> String {
        URL_SAFE_NO_PAD.encode(bytes)
    }

    /// Full roundtrip: upload bound to S → retrieve proves S → one-use →
    /// second retrieve of the same secret finds nothing.
    #[tokio::test]
    async fn upload_retrieve_roundtrip_is_one_use() {
        let state = RelayAppState::new(RelayStorage::in_memory().unwrap(), RelayConfig::default());
        let device_id = setup(&state);
        let secret = [7u8; 32];

        let _ = upload_bootstrap_v2(
            State(state.clone()),
            auth_extensions(device_id),
            Json(UploadBootstrapV2Request {
                secret: b64url(&secret),
                encrypted_bootstrap: STANDARD.encode([1u8, 2, 3]),
                registration_proof: STANDARD.encode([9u8; 32]),
            }),
        )
        .await
        .unwrap();

        let resp = retrieve_bootstrap_v2(
            State(state.clone()),
            Json(RetrieveBootstrapV2Request {
                secret: b64url(&secret),
            }),
        )
        .await
        .unwrap();
        assert_eq!(
            resp.encrypted_bootstrap,
            STANDARD.encode([1u8, 2, 3]),
            "the ciphertext returns in the body"
        );
        assert!(!resp.registration_proof.is_empty());

        // ONE-USE: the same secret retrieves nothing now.
        let again = retrieve_bootstrap_v2(
            State(state.clone()),
            Json(RetrieveBootstrapV2Request {
                secret: b64url(&secret),
            }),
        )
        .await
        .unwrap_err();
        assert!(matches!(again, RelayError::NotFound(_)));
    }

    /// A WRONG secret keys to a different bootstrap id entirely (ids are
    /// content-derived) — a retrieval miss, and the real record survives.
    #[tokio::test]
    async fn wrong_secret_retrieval_fails() {
        let state = RelayAppState::new(RelayStorage::in_memory().unwrap(), RelayConfig::default());
        let device_id = setup(&state);
        let secret = [7u8; 32];

        let _ = upload_bootstrap_v2(
            State(state.clone()),
            auth_extensions(device_id),
            Json(UploadBootstrapV2Request {
                secret: b64url(&secret),
                encrypted_bootstrap: STANDARD.encode([1u8, 2, 3]),
                registration_proof: STANDARD.encode([9u8; 32]),
            }),
        )
        .await
        .unwrap();

        let wrong = [8u8; 32];
        let err = retrieve_bootstrap_v2(
            State(state.clone()),
            Json(RetrieveBootstrapV2Request {
                secret: b64url(&wrong),
            }),
        )
        .await
        .unwrap_err();
        assert!(matches!(err, RelayError::NotFound(_)));

        // The real secret still retrieves (wrong attempts don't poison it
        // until the attempt limit).
        let resp = retrieve_bootstrap_v2(
            State(state.clone()),
            Json(RetrieveBootstrapV2Request {
                secret: b64url(&secret),
            }),
        )
        .await
        .unwrap();
        assert_eq!(resp.encrypted_bootstrap, STANDARD.encode([1u8, 2, 3]));
    }

    /// Malformed secrets (short numerics — the v1 class) are rejected
    /// before any state is touched.
    #[tokio::test]
    async fn short_numeric_secret_is_rejected() {
        let state = RelayAppState::new(RelayStorage::in_memory().unwrap(), RelayConfig::default());
        setup(&state);
        let err = retrieve_bootstrap_v2(
            State(RelayAppState::new(
                RelayStorage::in_memory().unwrap(),
                RelayConfig::default(),
            )),
            Json(RetrieveBootstrapV2Request {
                secret: "123456".to_string(),
            }),
        )
        .await
        .unwrap_err();
        assert!(matches!(err, RelayError::BadRequest(_)), "got {err:?}");
    }
}
