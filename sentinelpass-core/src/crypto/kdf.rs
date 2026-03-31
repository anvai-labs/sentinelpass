//! Argon2id key derivation function for master password processing.
//!
//! Uses Argon2id with parameters:
//! - Memory cost: 256 MB (262,144 KiB)
//! - Time cost: 3 iterations
//! - Parallelism: 4 lanes
//! - Output length: 32 bytes (256 bits)
//! - Salt length: 16 bytes

use crate::crypto::{CryptoError, Result};
use argon2::{
    password_hash::{PasswordHasher, SaltString},
    Algorithm, Argon2, Params, Version,
};
use rand::rngs::OsRng;
use rand::RngCore;
use serde::{Deserialize, Serialize};

/// Parameters for Argon2id key derivation
///
/// These parameters are chosen to provide strong security against
/// both brute-force and side-channel attacks.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct KdfParams {
    /// Salt for key derivation (16 bytes)
    pub salt: [u8; 16],

    /// Memory cost in KiB (262,144 = 256 MB)
    pub mem_cost: u32,

    /// Time cost (number of iterations)
    pub time_cost: u32,

    /// Parallelism (number of lanes)
    pub parallelism: u32,

    /// Output length in bytes
    pub output_length: u32,
}

impl Default for KdfParams {
    fn default() -> Self {
        let mut salt = [0u8; 16];
        OsRng.fill_bytes(&mut salt);
        Self {
            salt,
            mem_cost: 262_144, // 256 MB
            time_cost: 3,
            parallelism: 4,
            output_length: 32,
        }
    }
}

impl KdfParams {
    /// Create new random KDF parameters
    pub fn new() -> Self {
        Self::default()
    }

    /// Verify that parameters are within acceptable ranges
    pub fn validate(&self) -> Result<()> {
        if self.mem_cost < 64_000 {
            return Err(CryptoError::KdfFailed(
                "Memory cost too low (minimum: 64 MB)".to_string(),
            ));
        }
        if self.time_cost < 1 {
            return Err(CryptoError::KdfFailed(
                "Time cost too low (minimum: 1)".to_string(),
            ));
        }
        if self.parallelism < 1 {
            return Err(CryptoError::KdfFailed(
                "Parallelism too low (minimum: 1)".to_string(),
            ));
        }
        if self.output_length < 32 {
            return Err(CryptoError::KdfFailed(
                "Output length too short (minimum: 32 bytes)".to_string(),
            ));
        }
        Ok(())
    }
}

/// Derive a master key from a password using Argon2id
///
/// This is the primary key derivation function used to convert
/// a user's master password into a cryptographic master key.
///
/// # Arguments
/// * `password` - The master password as bytes
/// * `params` - KDF parameters (salt, memory, time, parallelism)
///
/// # Returns
/// A 32-byte master key
///
/// # Security
/// - Uses Argon2id which is resistant to both GPU and ASIC attacks
/// - Parameters chosen to require ~200ms on modern hardware
/// - Constant-time comparison prevents timing attacks
pub fn derive_master_key(password: &[u8], params: &KdfParams) -> Result<[u8; 32]> {
    params.validate()?;

    // Build Argon2id parameters
    let params_obj = Params::new(
        params.mem_cost,
        params.time_cost,
        params.parallelism,
        Some(params.output_length as usize),
    )
    .map_err(|e| CryptoError::KdfFailed(format!("Invalid parameters: {}", e)))?;

    let argon2 = Argon2::new(Algorithm::Argon2id, Version::V0x13, params_obj);

    // Convert salt to SaltString - use raw salt bytes directly
    let salt = SaltString::encode_b64(&params.salt)
        .map_err(|e| CryptoError::KdfFailed(format!("Failed to encode salt: {}", e)))?;

    // Hash the password
    let password_hash = argon2
        .hash_password(password, &salt)
        .map_err(|e| CryptoError::KdfFailed(format!("Hashing failed: {}", e)))?;

    // Extract the output hash
    let hash_bytes = password_hash.hash.map(|h| h.as_bytes().to_vec());
    let hash_bytes =
        hash_bytes.ok_or_else(|| CryptoError::KdfFailed("No hash output".to_string()))?;

    if hash_bytes.len() < 32 {
        return Err(CryptoError::KdfFailed(format!(
            "Hash output too short: {} bytes",
            hash_bytes.len()
        )));
    }

    let mut master_key = [0u8; 32];
    master_key.copy_from_slice(&hash_bytes[..32]);

    Ok(master_key)
}

/// Verify a master password by re-deriving the key and comparing
///
/// This function uses constant-time comparison to prevent timing attacks.
/// It also adds a fixed 200ms delay to further mitigate timing analysis.
///
/// # Arguments
/// * `password` - The password to verify
/// * `params` - The KDF parameters used
/// * `expected_key` - The expected master key
///
/// # Returns
/// Ok(()) if password is correct, Err otherwise
pub fn verify_master_password(
    password: &[u8],
    params: &KdfParams,
    expected_key: &[u8; 32],
) -> Result<()> {
    // Derive the key from the provided password
    let derived_key = derive_master_key(password, params)?;

    // Constant-time comparison
    use subtle::ConstantTimeEq;
    let derived_key_ref = &derived_key as &[u8];
    let expected_key_ref = expected_key as &[u8];

    if derived_key_ref.ct_eq(expected_key_ref).into() {
        // Add fixed delay to prevent timing attacks
        std::thread::sleep(std::time::Duration::from_millis(200));
        Ok(())
    } else {
        // Add fixed delay even on failure
        std::thread::sleep(std::time::Duration::from_millis(200));
        Err(CryptoError::KdfFailed("Invalid password".to_string()))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_kdf_params_default() {
        let params = KdfParams::default();
        assert_eq!(params.mem_cost, 262_144);
        assert_eq!(params.time_cost, 3);
        assert_eq!(params.parallelism, 4);
        assert_eq!(params.output_length, 32);
        assert!(params.validate().is_ok());
    }

    #[test]
    fn test_kdf_params_validation() {
        // Test too low memory
        let params = KdfParams {
            mem_cost: 1000,
            ..Default::default()
        };
        assert!(params.validate().is_err());

        // Test too low time
        let params = KdfParams {
            mem_cost: 262_144,
            time_cost: 0,
            ..Default::default()
        };
        assert!(params.validate().is_err());

        // Test too low parallelism
        let params = KdfParams {
            mem_cost: 262_144,
            time_cost: 3,
            parallelism: 0,
            ..Default::default()
        };
        assert!(params.validate().is_err());

        // Test too short output
        let params = KdfParams {
            mem_cost: 262_144,
            time_cost: 3,
            parallelism: 4,
            output_length: 16,
            ..Default::default()
        };
        assert!(params.validate().is_err());
    }

    #[test]
    fn test_derive_master_key() {
        let password = b"test_password_123!";
        let params = KdfParams::new();

        let key1 = derive_master_key(password, &params).unwrap();
        let key2 = derive_master_key(password, &params).unwrap();

        // Same password and params should produce same key
        assert_eq!(key1, key2);

        // Different password should produce different key
        let key3 = derive_master_key(b"different_password", &params).unwrap();
        assert_ne!(key1, key3);

        // Different salt should produce different key
        let mut params2 = params.clone();
        params2.salt = rand::random();
        let key4 = derive_master_key(password, &params2).unwrap();
        assert_ne!(key1, key4);
    }

    #[test]
    fn test_verify_master_password() {
        let password = b"correct_password";
        let params = KdfParams::new();
        let key = derive_master_key(password, &params).unwrap();

        // Correct password should verify
        assert!(verify_master_password(password, &params, &key).is_ok());

        // Wrong password should fail
        assert!(verify_master_password(b"wrong_password", &params, &key).is_err());
    }

    #[test]
    fn test_key_length() {
        let password = b"test_password";
        let params = KdfParams::new();
        let key = derive_master_key(password, &params).unwrap();

        assert_eq!(key.len(), 32);
    }
}
