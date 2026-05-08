//! AES-256-GCM encryption and decryption for password entries.
//!
//! Uses AES-256-GCM with:
//! - 256-bit key
//! - 96-bit (12 byte) nonce
//! - 128-bit authentication tag
//! - Each entry encrypted with unique nonce

use crate::crypto::{CryptoError, Result};
use aes_gcm::{
    aead::{Aead, AeadCore, KeyInit, OsRng},
    Aes256Gcm, Nonce,
};
use serde::{Deserialize, Serialize};
use zeroize::{Zeroize, Zeroizing};

/// A data encryption key (DEK) used to encrypt individual entries
///
/// The DEK is wrapped (encrypted) with the master key and stored
/// in the database. It's only unwrapped when the vault is unlocked.
#[derive(Clone)]
pub struct DataEncryptionKey {
    key: [u8; 32],
}

impl DataEncryptionKey {
    /// Generate a new random data encryption key
    pub fn new() -> Result<Self> {
        let key = Aes256Gcm::generate_key(&mut OsRng);
        let key_array = key.into();

        Ok(Self { key: key_array })
    }

    /// Create a DEK from raw bytes (use with caution)
    pub fn from_bytes(key: [u8; 32]) -> Self {
        Self { key }
    }

    /// Get the raw key bytes (use sparingly)
    pub fn as_bytes(&self) -> &[u8; 32] {
        &self.key
    }

    /// Convert to raw bytes, wrapped in a zeroizing guard so the caller
    /// can't accidentally leak key material on the stack.
    pub fn into_bytes(self) -> Zeroizing<[u8; 32]> {
        Zeroizing::new(self.key)
    }
}

impl Drop for DataEncryptionKey {
    fn drop(&mut self) {
        self.key.zeroize();
    }
}

/// An encrypted entry with nonce and ciphertext
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct EncryptedEntry {
    /// Unique nonce for this entry (12 bytes)
    pub nonce: [u8; 12],

    /// Encrypted data
    pub ciphertext: Vec<u8>,

    /// Authentication tag (16 bytes)
    pub auth_tag: [u8; 16],
}

impl EncryptedEntry {
    /// Create a new encrypted entry from components
    pub fn new(nonce: [u8; 12], ciphertext: Vec<u8>, auth_tag: [u8; 16]) -> Self {
        Self {
            nonce,
            ciphertext,
            auth_tag,
        }
    }
}

/// Encrypt data using AES-256-GCM
///
/// Each encryption uses a cryptographically secure random nonce.
/// The nonce is stored alongside the ciphertext for later decryption.
///
/// # Arguments
/// * `dek` - The data encryption key
/// * `plaintext` - The data to encrypt
///
/// # Returns
/// An EncryptedEntry containing nonce, ciphertext, and auth tag
///
/// # Security Notes
/// - Never reuse nonces with the same key!
/// - The nonce is generated randomly for each encryption
/// - AES-256-GCM provides both confidentiality and authenticity
pub fn encrypt_entry(dek: &DataEncryptionKey, plaintext: &[u8]) -> Result<EncryptedEntry> {
    // Create cipher with the DEK
    let cipher = Aes256Gcm::new(dek.as_bytes().into());

    // Generate random nonce
    let nonce = Aes256Gcm::generate_nonce(&mut OsRng);
    let nonce_bytes: [u8; 12] = nonce.into();

    // Encrypt the data
    let ciphertext = cipher
        .encrypt(&nonce, plaintext)
        .map_err(|e| CryptoError::EncryptionFailed(format!("{}", e)))?;

    // AES-GCM appends the auth tag to the ciphertext
    if ciphertext.len() < 16 {
        return Err(CryptoError::EncryptionFailed(
            "Ciphertext too short - missing auth tag".to_string(),
        ));
    }

    // Split ciphertext and auth tag
    let tag_start = ciphertext.len() - 16;
    let auth_tag: [u8; 16] = ciphertext[tag_start..]
        .try_into()
        .map_err(|_| CryptoError::EncryptionFailed("Invalid auth tag length".to_string()))?;
    let ciphertext_only = ciphertext[..tag_start].to_vec();

    Ok(EncryptedEntry {
        nonce: nonce_bytes,
        ciphertext: ciphertext_only,
        auth_tag,
    })
}

/// Decrypt data using AES-256-GCM
///
/// # Arguments
/// * `dek` - The data encryption key
/// * `encrypted` - The encrypted entry with nonce and ciphertext
///
/// # Returns
/// The decrypted plaintext
///
/// # Security
/// - Returns error if authentication tag doesn't verify
/// - This prevents tampering with encrypted data
pub fn decrypt_entry(dek: &DataEncryptionKey, encrypted: &EncryptedEntry) -> Result<Vec<u8>> {
    // Create cipher with the DEK
    let cipher = Aes256Gcm::new(dek.as_bytes().into());

    // Reconstruct nonce
    let nonce = Nonce::from(encrypted.nonce);

    // Combine ciphertext and auth tag (avoid redundant clone)
    let mut ciphertext_with_tag = Vec::with_capacity(encrypted.ciphertext.len() + 16);
    ciphertext_with_tag.extend_from_slice(&encrypted.ciphertext);
    ciphertext_with_tag.extend_from_slice(&encrypted.auth_tag);

    // Decrypt and verify
    let plaintext = cipher
        .decrypt(&nonce, ciphertext_with_tag.as_slice())
        .map_err(|_| CryptoError::AuthenticationFailed)?;

    Ok(plaintext)
}

/// Encrypt a string using the DEK
///
/// Convenience function that handles string-to-bytes conversion
pub fn encrypt_string(dek: &DataEncryptionKey, plaintext: &str) -> Result<EncryptedEntry> {
    encrypt_entry(dek, plaintext.as_bytes())
}

/// Decrypt to a string using the DEK
///
/// Convenience function that handles bytes-to-string conversion
pub fn decrypt_to_string(dek: &DataEncryptionKey, encrypted: &EncryptedEntry) -> Result<String> {
    let bytes = decrypt_entry(dek, encrypted)?;
    String::from_utf8(bytes).map_err(|_| CryptoError::DecryptionFailed("Invalid UTF-8".to_string()))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_dek_generation() {
        let dek = DataEncryptionKey::new().unwrap();
        assert_eq!(dek.as_bytes().len(), 32);
    }

    #[test]
    fn test_encrypt_decrypt_roundtrip() {
        let dek = DataEncryptionKey::new().unwrap();
        let plaintext = b"Hello, World! This is a test.";

        let encrypted = encrypt_entry(&dek, plaintext).unwrap();
        let decrypted = decrypt_entry(&dek, &encrypted).unwrap();

        assert_eq!(plaintext.to_vec(), decrypted);
    }

    #[test]
    fn test_encrypt_string_roundtrip() {
        let dek = DataEncryptionKey::new().unwrap();
        let plaintext = "My secret password!";

        let encrypted = encrypt_string(&dek, plaintext).unwrap();
        let decrypted = decrypt_to_string(&dek, &encrypted).unwrap();

        assert_eq!(plaintext, decrypted);
    }

    #[test]
    fn test_different_nonces() {
        let dek = DataEncryptionKey::new().unwrap();
        let plaintext = b"Same data";

        let encrypted1 = encrypt_entry(&dek, plaintext).unwrap();
        let encrypted2 = encrypt_entry(&dek, plaintext).unwrap();

        // Nonces should be different
        assert_ne!(encrypted1.nonce, encrypted2.nonce);

        // Ciphertexts should be different due to different nonces
        assert_ne!(encrypted1.ciphertext, encrypted2.ciphertext);

        // But both should decrypt to the same plaintext
        assert_eq!(
            decrypt_entry(&dek, &encrypted1).unwrap(),
            decrypt_entry(&dek, &encrypted2).unwrap()
        );
    }

    #[test]
    fn test_wrong_key_fails() {
        let dek1 = DataEncryptionKey::new().unwrap();
        let dek2 = DataEncryptionKey::new().unwrap();
        let plaintext = b"Secret data";

        let encrypted = encrypt_entry(&dek1, plaintext).unwrap();

        // Decrypting with wrong key should fail
        assert!(decrypt_entry(&dek2, &encrypted).is_err());
    }

    #[test]
    fn test_tampering_detected() {
        let dek = DataEncryptionKey::new().unwrap();
        let plaintext = b"Original data";

        let mut encrypted = encrypt_entry(&dek, plaintext).unwrap();

        // Tamper with the ciphertext
        if !encrypted.ciphertext.is_empty() {
            encrypted.ciphertext[0] ^= 0xFF;
        }

        // Decryption should detect tampering
        assert!(decrypt_entry(&dek, &encrypted).is_err());
    }

    #[test]
    fn test_empty_data_roundtrip() {
        let dek = DataEncryptionKey::new().unwrap();

        // AES-256-GCM handles zero-length plaintext (output is just the 16-byte auth tag)
        let encrypted = encrypt_entry(&dek, b"").unwrap();
        assert!(encrypted.ciphertext.is_empty());
        let decrypted = decrypt_entry(&dek, &encrypted).unwrap();
        assert!(decrypted.is_empty());

        // Invalid auth tag should still fail authentication
        assert!(decrypt_entry(
            &dek,
            &EncryptedEntry {
                nonce: encrypted.nonce,
                ciphertext: vec![],
                auth_tag: [0u8; 16],
            }
        )
        .is_err());
    }

    use proptest::prelude::*;

    proptest! {
        #[test]
        fn encrypt_decrypt_roundtrip_arbitrary_data(data in proptest::collection::vec(any::<u8>(), 0..4096)) {
            let dek = DataEncryptionKey::new().unwrap();
            let encrypted = encrypt_entry(&dek, &data).unwrap();
            let decrypted = decrypt_entry(&dek, &encrypted).unwrap();
            prop_assert_eq!(data, decrypted);
        }

        #[test]
        fn unique_nonces_for_same_data(data in proptest::collection::vec(any::<u8>(), 1..256)) {
            let dek = DataEncryptionKey::new().unwrap();
            let e1 = encrypt_entry(&dek, &data).unwrap();
            let e2 = encrypt_entry(&dek, &data).unwrap();
            prop_assert_ne!(e1.nonce, e2.nonce);
        }
    }
}
