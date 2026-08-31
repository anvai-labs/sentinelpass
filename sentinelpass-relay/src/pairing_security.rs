//! Pairing token/proof helpers for relay-side verification and at-rest hashing.
//!
//! Pairing tokens are short human codes (6 digits), so at-rest hashing uses
//! salted Argon2id: an offline brute force over the code space must pay a
//! per-row KDF cost. Registration proofs are 32 random bytes, where SHA-256
//! remains appropriate.

use crate::error::RelayError;
use argon2::password_hash::{PasswordHash, PasswordHasher, PasswordVerifier, SaltString};
use argon2::{Algorithm, Argon2, Params, Version};
use base64::Engine;
use sha2::{Digest, Sha256};
use subtle::ConstantTimeEq;

const MAX_PAIRING_TOKEN_LEN: usize = 256;
const REGISTRATION_PROOF_LEN: usize = 32;

/// OWASP baseline Argon2id parameters (m=19 MiB, t=2, p=1): roughly 50 ms per
/// hash on server hardware. Only used for low-entropy pairing codes.
const PAIRING_ARGON2_M_KIB: u32 = 19_456;
const PAIRING_ARGON2_T: u32 = 2;
const PAIRING_ARGON2_P: u32 = 1;

fn pairing_argon2() -> Argon2<'static> {
    let params = Params::new(
        PAIRING_ARGON2_M_KIB,
        PAIRING_ARGON2_T,
        PAIRING_ARGON2_P,
        None,
    )
    .expect("valid Argon2 parameters");
    Argon2::new(Algorithm::Argon2id, Version::V0x13, params)
}

fn validate_pairing_token(token: &str) -> Result<(), RelayError> {
    if token.is_empty() || token.len() > MAX_PAIRING_TOKEN_LEN {
        return Err(RelayError::BadRequest(
            "Invalid pairing token length".to_string(),
        ));
    }
    Ok(())
}

/// Hash a pairing token for at-rest storage as a salted Argon2id PHC string.
pub(crate) fn hash_pairing_token(token: &str) -> Result<String, RelayError> {
    validate_pairing_token(token)?;

    let salt = SaltString::generate(&mut rand::rngs::OsRng);
    pairing_argon2()
        .hash_password(token.as_bytes(), &salt)
        .map(|hash| hash.to_string())
        .map_err(|e| RelayError::Internal(format!("Failed to hash pairing token: {}", e)))
}

/// Verify a presented pairing token against a stored at-rest hash.
///
/// Accepts both Argon2id PHC strings (current format) and legacy bare
/// SHA-256 hex rows written by relay versions <= 0.7. Legacy matches should
/// be upgraded in place by the caller.
pub(crate) fn verify_pairing_token(token: &str, stored: &str) -> Result<bool, RelayError> {
    validate_pairing_token(token)?;

    if stored.starts_with("$argon2") {
        let parsed = PasswordHash::new(stored)
            .map_err(|e| RelayError::Database(format!("Malformed stored pairing hash: {}", e)))?;
        return Ok(pairing_argon2()
            .verify_password(token.as_bytes(), &parsed)
            .is_ok());
    }

    let candidate = hash_bytes_hex(token.as_bytes());
    Ok(bool::from(candidate.as_bytes().ct_eq(stored.as_bytes())))
}

/// True when `stored` still uses the legacy bare SHA-256 format.
pub(crate) fn is_legacy_pairing_hash(stored: &str) -> bool {
    !stored.starts_with("$argon2")
}

pub(crate) fn hash_registration_proof_b64(proof_b64: &str) -> Result<String, RelayError> {
    let proof = base64::engine::general_purpose::STANDARD
        .decode(proof_b64)
        .map_err(|e| RelayError::BadRequest(format!("Invalid registration proof: {}", e)))?;

    if proof.len() != REGISTRATION_PROOF_LEN {
        return Err(RelayError::BadRequest(
            "Registration proof must be 32 bytes".to_string(),
        ));
    }

    Ok(hash_bytes_hex(&proof))
}

pub(crate) fn hash_bytes_hex(bytes: &[u8]) -> String {
    hex::encode(Sha256::digest(bytes))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn hashes_pairing_token_with_salted_argon2id() {
        let token = "123456";
        let hashed = hash_pairing_token(token).unwrap();
        assert_ne!(hashed, token);
        assert!(hashed.starts_with("$argon2id$"));
        assert!(hashed.len() > 64);
    }

    #[test]
    fn argon2_hash_round_trips_and_rejects_wrong_token() {
        let hashed = hash_pairing_token("123456").unwrap();
        assert!(verify_pairing_token("123456", &hashed).unwrap());
        assert!(!verify_pairing_token("654321", &hashed).unwrap());
    }

    #[test]
    fn argon2_salts_are_unique_per_hash() {
        let a = hash_pairing_token("123456").unwrap();
        let b = hash_pairing_token("123456").unwrap();
        assert_ne!(a, b);
        assert!(verify_pairing_token("123456", &a).unwrap());
        assert!(verify_pairing_token("123456", &b).unwrap());
    }

    #[test]
    fn legacy_sha256_rows_verify_and_are_flagged() {
        let legacy = hash_bytes_hex(b"123456");
        assert!(is_legacy_pairing_hash(&legacy));
        assert!(verify_pairing_token("123456", &legacy).unwrap());
        assert!(!verify_pairing_token("000000", &legacy).unwrap());
    }

    #[test]
    fn invalid_token_length_rejected() {
        assert!(hash_pairing_token("").is_err());
        assert!(hash_pairing_token(&"x".repeat(257)).is_err());
        assert!(verify_pairing_token("", "$argon2id$whatever").is_err());
    }

    #[test]
    fn registration_proof_requires_32_bytes() {
        let short = base64::engine::general_purpose::STANDARD.encode([1u8; 8]);
        let err = hash_registration_proof_b64(&short).expect_err("short proof rejected");
        match err {
            RelayError::BadRequest(msg) => assert!(msg.contains("32 bytes")),
            other => panic!("unexpected error: {}", other),
        }
    }
}
