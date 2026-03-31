//! Ed25519 auth middleware for the relay server.

use crate::app_state::RelayAppState;
use crate::error::RelayError;
use axum::body::Body;
use axum::extract::State;
use axum::http::Request;
use axum::middleware::Next;
use axum::response::Response;
use chrono::Utc;
use ed25519_dalek::{Signature, Verifier, VerifyingKey};
use sha2::{Digest, Sha256};
use uuid::Uuid;

// Import base64 Engine for use in verify_auth function
use base64::Engine;

/// Auth middleware: verifies Ed25519 signature on every authenticated request.
pub async fn auth_middleware(
    State(state): State<RelayAppState>,
    request: Request<Body>,
    next: Next,
) -> Result<Response, RelayError> {
    let auth_header = request
        .headers()
        .get("Authorization")
        .and_then(|v| v.to_str().ok())
        .ok_or_else(|| RelayError::Auth("Missing Authorization header".to_string()))?
        .to_string();

    let method = request.method().as_str().to_string();
    let path = request.uri().path().to_string();

    // Read body for signature verification
    let (parts, body) = request.into_parts();
    let body_bytes = axum::body::to_bytes(body, state.config.max_payload_size)
        .await
        .map_err(|e| RelayError::BadRequest(format!("Failed to read body: {}", e)))?;

    let (device_id, _timestamp, nonce) = verify_auth(
        &auth_header,
        &method,
        &path,
        &body_bytes,
        &state.storage,
        state.config.nonce_window_secs,
    )?;

    // Check nonce dedup
    {
        let conn = state.storage.conn()?;
        let now = Utc::now().timestamp();

        let seen: bool = conn
            .query_row(
                "SELECT EXISTS(SELECT 1 FROM seen_nonces WHERE nonce = ?1)",
                [&nonce],
                |row| row.get(0),
            )
            .map_err(|e| RelayError::Database(e.to_string()))?;

        if seen {
            return Err(RelayError::Auth("Nonce reused".to_string()));
        }

        conn.execute(
            "INSERT INTO seen_nonces (nonce, device_id, seen_at) VALUES (?1, ?2, ?3)",
            rusqlite::params![nonce, device_id.to_string(), now],
        )
        .map_err(|e| RelayError::Database(e.to_string()))?;

        // Cleanup expired nonces (best-effort)
        conn.execute(
            "DELETE FROM seen_nonces WHERE seen_at < ?1",
            [now - state.config.nonce_window_secs],
        )
        .ok();
    }

    // Per-device rate limiting after auth verification and nonce consumption.
    let device_key = format!("auth:{}", device_id);
    if !state.rate_limiter.check(&device_key) {
        return Err(RelayError::RateLimited);
    }

    // Reconstruct request with device_id in extensions and original body
    let mut request = Request::from_parts(parts, Body::from(body_bytes));
    request.extensions_mut().insert(device_id);

    Ok(next.run(request).await)
}

/// Verify Ed25519 authentication header and return device_id, timestamp, and nonce
fn verify_auth(
    header: &str,
    method: &str,
    path: &str,
    body: &[u8],
    storage: &crate::storage::RelayStorage,
    nonce_window_secs: i64,
) -> Result<(Uuid, i64, String), RelayError> {
    let stripped = header
        .strip_prefix("SentinelPass-Ed25519 ")
        .ok_or_else(|| RelayError::Auth("Invalid auth scheme".to_string()))?;

    let parts: Vec<&str> = stripped.splitn(4, ':').collect();
    if parts.len() != 4 {
        return Err(RelayError::Auth("Invalid auth format".to_string()));
    }

    let device_id =
        Uuid::parse_str(parts[0]).map_err(|_| RelayError::Auth("Invalid device ID".to_string()))?;
    let timestamp: i64 = parts[1]
        .parse()
        .map_err(|_| RelayError::Auth("Invalid timestamp".to_string()))?;
    let nonce = parts[2].to_string();
    let sig_bytes = base64::engine::general_purpose::STANDARD
        .decode(parts[3])
        .map_err(|_| RelayError::Auth("Invalid signature encoding".to_string()))?;

    // Check timestamp freshness (5 min window)
    let now = Utc::now().timestamp();
    if (now - timestamp).abs() > nonce_window_secs.max(1) {
        return Err(RelayError::Auth("Request expired".to_string()));
    }

    // Look up device public key
    let conn = storage.conn()?;
    let (public_key_bytes, revoked): (Vec<u8>, bool) = conn
        .query_row(
            "SELECT public_key, revoked FROM devices WHERE device_id = ?1",
            [device_id.to_string()],
            |row| Ok((row.get(0)?, row.get(1)?)),
        )
        .map_err(|_| RelayError::Auth("Unknown device".to_string()))?;

    if revoked {
        return Err(RelayError::Auth("Device revoked".to_string()));
    }

    // Verify signature
    let body_hash = hex::encode(Sha256::digest(body));
    let message = format!(
        "{}\n{}\n{}\n{}\n{}",
        method, path, timestamp, nonce, body_hash
    );

    let key_array: [u8; 32] = public_key_bytes
        .try_into()
        .map_err(|_| RelayError::Auth("Invalid public key".to_string()))?;
    let verifying_key = VerifyingKey::from_bytes(&key_array)
        .map_err(|_| RelayError::Auth("Invalid public key".to_string()))?;

    let sig_array: [u8; 64] = sig_bytes
        .try_into()
        .map_err(|_| RelayError::Auth("Invalid signature length".to_string()))?;
    let signature = Signature::from_bytes(&sig_array);

    verifying_key
        .verify(message.as_bytes(), &signature)
        .map_err(|_| RelayError::Auth("Signature verification failed".to_string()))?;

    Ok((device_id, timestamp, nonce))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::app_state::RelayAppState;
    use crate::config::RelayConfig;
    use crate::rate_limit::RateLimiter;
    use crate::storage::RelayStorage;
    use base64::engine::general_purpose::STANDARD;
    use chrono::Utc;
    use ed25519_dalek::Signer; // Import Signer trait for sign method
    use ed25519_dalek::SigningKey;
    use rand::RngCore; // Import RngCore trait for fill_bytes
    use uuid::Uuid;

    fn generate_signing_key() -> SigningKey {
        let mut secret_bytes = [0u8; 32];
        rand::rngs::OsRng.fill_bytes(&mut secret_bytes);
        SigningKey::from_bytes(&secret_bytes)
    }

    fn setup_test_device(state: &RelayAppState) -> (Uuid, SigningKey) {
        let device_id = Uuid::new_v4();
        let vault_id = Uuid::new_v4().to_string();
        let secret_key = generate_signing_key();
        let public_key_bytes = secret_key.verifying_key().to_bytes();
        let now = Utc::now().timestamp();
        let conn = state.storage.conn().unwrap();

        conn.execute(
            "INSERT INTO vaults (vault_id, created_at) VALUES (?1, ?2)",
            rusqlite::params![&vault_id, now],
        )
        .unwrap();

        conn.execute(
            "INSERT INTO devices (device_id, vault_id, device_name, device_type, public_key, registered_at)
             VALUES (?1, ?2, ?3, ?4, ?5, ?6)",
            rusqlite::params![
                device_id.to_string(),
                &vault_id,
                "Test Device",
                "desktop",
                public_key_bytes.to_vec(),
                now,
            ],
        )
        .unwrap();

        (device_id, secret_key)
    }

    fn build_auth_header(
        secret_key: &SigningKey,
        device_id: Uuid,
        timestamp: i64,
        nonce: &str,
        method: &str,
        path: &str,
        body: &[u8],
    ) -> String {
        let body_hash = hex::encode(sha2::Sha256::digest(body));
        let message = format!(
            "{}\n{}\n{}\n{}\n{}",
            method, path, timestamp, nonce, body_hash
        );

        let sig = secret_key.sign(message.as_bytes());
        format!(
            "SentinelPass-Ed25519 {}:{}:{}:{}",
            device_id,
            timestamp,
            nonce,
            STANDARD.encode(sig.to_bytes())
        )
    }

    #[tokio::test]
    async fn verify_auth_rejects_invalid_scheme() {
        let state = RelayAppState::new(RelayStorage::in_memory().unwrap(), RelayConfig::default());

        let result = verify_auth(
            "InvalidScheme",
            "POST",
            "/api/v1/sync/push",
            b"test body",
            &state.storage,
            300,
        );

        assert!(result.is_err());
        match result.unwrap_err() {
            RelayError::Auth(msg) => assert!(msg.contains("Invalid auth scheme")),
            other => panic!("expected Auth error, got: {}", other),
        }
    }

    #[tokio::test]
    async fn verify_auth_rejects_malformed_header() {
        let state = RelayAppState::new(RelayStorage::in_memory().unwrap(), RelayConfig::default());

        let device_id = Uuid::new_v4();
        let header = format!("SentinelPass-Ed25519 {}:invalid", device_id);

        let result = verify_auth(
            &header,
            "POST",
            "/api/v1/sync/push",
            b"test body",
            &state.storage,
            300,
        );

        assert!(result.is_err());
    }

    #[tokio::test]
    async fn verify_auth_rejects_expired_timestamp() {
        let state = RelayAppState::new(
            RelayStorage::in_memory().unwrap(),
            RelayConfig {
                nonce_window_secs: 300,
                ..RelayConfig::default()
            },
        );

        let old_timestamp = Utc::now().timestamp() - 400;
        let (_, secret_key) = setup_test_device(&state);
        let device_id = Uuid::new_v4();

        let sig = secret_key.sign(b"test");
        let header = format!(
            "SentinelPass-Ed25519 {}:{}:nonce:{}",
            device_id,
            old_timestamp,
            STANDARD.encode(sig.to_bytes())
        );

        let result = verify_auth(
            &header,
            "POST",
            "/api/v1/sync/push",
            b"test body",
            &state.storage,
            300,
        );

        assert!(result.is_err());
        match result.unwrap_err() {
            RelayError::Auth(msg) => assert!(msg.contains("expired")),
            other => panic!("expected Auth error, got: {}", other),
        }
    }

    #[tokio::test]
    async fn verify_auth_rejects_unknown_device() {
        let state = RelayAppState::new(RelayStorage::in_memory().unwrap(), RelayConfig::default());
        let secret_key = generate_signing_key();
        let device_id = Uuid::new_v4();

        let auth_header = build_auth_header(
            &secret_key,
            device_id,
            Utc::now().timestamp(),
            "nonce123",
            "POST",
            "/api/v1/sync/push",
            b"test body",
        );

        let result = verify_auth(
            &auth_header,
            "POST",
            "/api/v1/sync/push",
            b"test body",
            &state.storage,
            300,
        );

        assert!(result.is_err());
        match result.unwrap_err() {
            RelayError::Auth(msg) => assert!(msg.contains("Unknown device")),
            other => panic!("expected Auth error, got: {}", other),
        }
    }

    #[tokio::test]
    async fn verify_auth_rejects_revoked_device() {
        let state = RelayAppState::new(RelayStorage::in_memory().unwrap(), RelayConfig::default());
        let (device_id, secret_key) = setup_test_device(&state);
        let conn = state.storage.conn().unwrap();

        conn.execute(
            "UPDATE devices SET revoked = 1 WHERE device_id = ?1",
            [device_id.to_string()],
        )
        .unwrap();
        drop(conn);

        let auth_header = build_auth_header(
            &secret_key,
            device_id,
            Utc::now().timestamp(),
            "nonce123",
            "POST",
            "/api/v1/sync/push",
            b"test body",
        );

        let result = verify_auth(
            &auth_header,
            "POST",
            "/api/v1/sync/push",
            b"test body",
            &state.storage,
            300,
        );

        assert!(result.is_err());
        match result.unwrap_err() {
            RelayError::Auth(msg) => assert!(msg.contains("revoked")),
            other => panic!("expected Auth error, got: {}", other),
        }
    }

    #[tokio::test]
    async fn verify_auth_rejects_invalid_signature() {
        let state = RelayAppState::new(RelayStorage::in_memory().unwrap(), RelayConfig::default());
        let (_, _secret_key) = setup_test_device(&state);

        // Use wrong key to sign
        let wrong_key = generate_signing_key();
        let device_id = Uuid::new_v4();

        let sig = wrong_key.sign(b"test");
        let header = format!(
            "SentinelPass-Ed25519 {}:{}:nonce:{}",
            device_id,
            Utc::now().timestamp(),
            STANDARD.encode(sig.to_bytes())
        );

        let result = verify_auth(
            &header,
            "POST",
            "/api/v1/sync/push",
            b"test body",
            &state.storage,
            300,
        );

        assert!(result.is_err());
        match result.unwrap_err() {
            RelayError::Auth(msg) => assert!(msg.contains("Unknown device")),
            other => panic!("expected Auth error, got: {}", other),
        }
    }

    #[tokio::test]
    async fn verify_auth_accepts_valid_signature() {
        let state = RelayAppState::new(RelayStorage::in_memory().unwrap(), RelayConfig::default());
        let (device_id, secret_key) = setup_test_device(&state);

        let auth_header = build_auth_header(
            &secret_key,
            device_id,
            Utc::now().timestamp(),
            "unique-nonce-456",
            "POST",
            "/api/v1/sync/push",
            b"test body",
        );

        let result = verify_auth(
            &auth_header,
            "POST",
            "/api/v1/sync/push",
            b"test body",
            &state.storage,
            300,
        );

        assert!(result.is_ok());
        let (returned_device_id, _returned_timestamp, returned_nonce) = result.unwrap();
        assert_eq!(returned_device_id, device_id);
        assert_eq!(returned_nonce, "unique-nonce-456");
    }

    #[tokio::test]
    async fn verify_auth_includes_body_hash_in_signature() {
        let state = RelayAppState::new(RelayStorage::in_memory().unwrap(), RelayConfig::default());
        let (device_id, secret_key) = setup_test_device(&state);
        let timestamp = Utc::now().timestamp();
        let nonce = "test-nonce-hash";

        let auth_header1 = build_auth_header(
            &secret_key,
            device_id,
            timestamp,
            nonce,
            "POST",
            "/api/v1/sync/push",
            b"body one",
        );

        let auth_header2 = build_auth_header(
            &secret_key,
            device_id,
            timestamp,
            nonce,
            "POST",
            "/api/v1/sync/push",
            b"body two",
        );

        // Both signatures should be valid for their respective bodies
        let result1 = verify_auth(
            &auth_header1,
            "POST",
            "/api/v1/sync/push",
            b"body one",
            &state.storage,
            300,
        );

        let result2 = verify_auth(
            &auth_header2,
            "POST",
            "/api/v1/sync/push",
            b"body two",
            &state.storage,
            300,
        );

        assert!(result1.is_ok());
        assert!(result2.is_ok());

        // Using wrong body with signature should fail
        let result_wrong = verify_auth(
            &auth_header1,
            "POST",
            "/api/v1/sync/push",
            b"body two",
            &state.storage,
            300,
        );

        assert!(result_wrong.is_err());
    }

    #[tokio::test]
    async fn rate_limiter_enforces_per_device_limits() {
        let limiter = RateLimiter::new(2); // 2 requests per minute

        assert!(limiter.check("device-a"));
        assert!(limiter.check("device-a"));
        assert!(!limiter.check("device-a"));
    }

    #[tokio::test]
    async fn rate_limiter_is_per_device_key() {
        let limiter = RateLimiter::new(1);

        assert!(limiter.check("device-a"));
        assert!(!limiter.check("device-a"));
        assert!(limiter.check("device-b"));
    }
}
