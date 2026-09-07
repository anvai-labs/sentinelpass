//! Sync encryption: encrypt/decrypt entry payloads for transport.
//!
//! Uses the vault's existing DEK with AES-256-GCM. The wire format is:
//! `nonce(12) || ciphertext || auth_tag(16)`

use crate::crypto::cipher::DataEncryptionKey;
use crate::crypto::CryptoError;
use zeroize::Zeroizing;

/// Encrypt a JSON payload for sync transport.
///
/// Returns `nonce(12) || ciphertext || auth_tag(16)`.
pub fn encrypt_for_sync(dek: &DataEncryptionKey, plaintext: &[u8]) -> Result<Vec<u8>, CryptoError> {
    use aes_gcm::{
        aead::{Aead, AeadCore, KeyInit, OsRng},
        Aes256Gcm,
    };

    if plaintext.is_empty() {
        return Err(CryptoError::EncryptionFailed(
            "Cannot encrypt empty payload".to_string(),
        ));
    }

    let cipher = Aes256Gcm::new(dek.as_bytes().into());
    let nonce = Aes256Gcm::generate_nonce(&mut OsRng);
    let nonce_bytes: [u8; 12] = nonce.into();

    let ciphertext_with_tag = cipher
        .encrypt(&nonce, plaintext)
        .map_err(|e| CryptoError::EncryptionFailed(format!("Sync encryption failed: {}", e)))?;

    // Wire format: nonce || ciphertext || tag
    // aes-gcm appends tag to ciphertext, so ciphertext_with_tag = ciphertext || tag
    let mut result = Vec::with_capacity(12 + ciphertext_with_tag.len());
    result.extend_from_slice(&nonce_bytes);
    result.extend_from_slice(&ciphertext_with_tag);

    Ok(result)
}

/// Decrypt a sync transport payload.
///
/// Expects `nonce(12) || ciphertext || auth_tag(16)`. The decrypted
/// plaintext (a serialized sync payload carrying credential/SSH/TOTP
/// secrets) is zeroize-on-drop (WBS-308 / SR-CRYPTO-004).
pub fn decrypt_from_sync(
    dek: &DataEncryptionKey,
    blob: &[u8],
) -> Result<Zeroizing<Vec<u8>>, CryptoError> {
    use aes_gcm::{aead::Aead, aead::KeyInit, Aes256Gcm, Nonce};

    // Minimum: 12 (nonce) + 1 (ciphertext) + 16 (tag) = 29 bytes
    if blob.len() < 29 {
        return Err(CryptoError::DecryptionFailed(
            "Sync blob too short".to_string(),
        ));
    }

    let nonce_bytes: [u8; 12] = blob[..12]
        .try_into()
        .map_err(|_| CryptoError::InvalidNonce("Invalid nonce length".to_string()))?;
    let ciphertext_with_tag = &blob[12..];

    let cipher = Aes256Gcm::new(dek.as_bytes().into());
    let nonce = Nonce::from(nonce_bytes);

    cipher
        .decrypt(&nonce, ciphertext_with_tag)
        .map(Zeroizing::new)
        .map_err(|_| CryptoError::AuthenticationFailed)
}

/// Pad payload to fixed-size bucket to prevent metadata leakage.
///
/// Buckets: 256, 512, 1024, 2048, 4096, 8192 bytes.
/// Padding byte is 0x00 with a length prefix.
pub fn pad_payload(data: &[u8]) -> Vec<u8> {
    let buckets = [256, 512, 1024, 2048, 4096, 8192];
    // 8 bytes for length prefix
    let total_needed = data.len() + 8;
    let bucket_size = buckets
        .iter()
        .find(|&&b| b >= total_needed)
        .copied()
        .unwrap_or(((total_needed / 8192) + 1) * 8192);

    let mut padded = Vec::with_capacity(bucket_size);
    // Store original length as 8-byte little-endian
    padded.extend_from_slice(&(data.len() as u64).to_le_bytes());
    padded.extend_from_slice(data);
    padded.resize(bucket_size, 0u8);
    padded
}

/// Remove padding from a padded payload. The unpadded plaintext is
/// zeroize-on-drop (WBS-308 / SR-CRYPTO-004).
pub fn unpad_payload(padded: &[u8]) -> Result<Zeroizing<Vec<u8>>, CryptoError> {
    if padded.len() < 8 {
        return Err(CryptoError::DecryptionFailed(
            "Padded payload too short".to_string(),
        ));
    }

    let len_bytes: [u8; 8] = padded[..8]
        .try_into()
        .map_err(|_| CryptoError::DecryptionFailed("Invalid length prefix".to_string()))?;
    let original_len = u64::from_le_bytes(len_bytes) as usize;

    if original_len + 8 > padded.len() {
        return Err(CryptoError::DecryptionFailed(
            "Invalid padded payload length".to_string(),
        ));
    }

    Ok(Zeroizing::new(padded[8..8 + original_len].to_vec()))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn encrypt_decrypt_roundtrip() {
        let dek = DataEncryptionKey::new().unwrap();
        let plaintext = b"Hello sync world!";

        let encrypted = encrypt_for_sync(&dek, plaintext).unwrap();
        let decrypted = decrypt_from_sync(&dek, &encrypted).unwrap();

        assert_eq!(plaintext.to_vec(), decrypted.as_slice());
    }

    #[test]
    fn encrypt_empty_fails() {
        let dek = DataEncryptionKey::new().unwrap();
        assert!(encrypt_for_sync(&dek, b"").is_err());
    }

    #[test]
    fn decrypt_too_short_fails() {
        let dek = DataEncryptionKey::new().unwrap();
        assert!(decrypt_from_sync(&dek, &[0u8; 28]).is_err());
    }

    #[test]
    fn wrong_key_fails() {
        let dek1 = DataEncryptionKey::new().unwrap();
        let dek2 = DataEncryptionKey::new().unwrap();
        let plaintext = b"secret data";

        let encrypted = encrypt_for_sync(&dek1, plaintext).unwrap();
        assert!(decrypt_from_sync(&dek2, &encrypted).is_err());
    }

    #[test]
    fn tampered_blob_fails() {
        let dek = DataEncryptionKey::new().unwrap();
        let plaintext = b"secret data";

        let mut encrypted = encrypt_for_sync(&dek, plaintext).unwrap();
        // Tamper with ciphertext (after nonce)
        encrypted[15] ^= 0xFF;
        assert!(decrypt_from_sync(&dek, &encrypted).is_err());
    }

    #[test]
    fn pad_unpad_roundtrip() {
        let data = b"some payload data";
        let padded = pad_payload(data);

        // Should be in a bucket size
        assert!(padded.len() >= 256);
        assert_eq!(padded.len() % 256, 0);

        let unpadded = unpad_payload(&padded).unwrap();
        assert_eq!(data.to_vec(), unpadded.as_slice());
    }

    #[test]
    fn pad_bucket_sizes() {
        // Small data → 256 bucket
        assert_eq!(pad_payload(&[0u8; 10]).len(), 256);
        // 250 bytes + 8 prefix = 258 → 512 bucket
        assert_eq!(pad_payload(&[0u8; 250]).len(), 512);
        // 1000 bytes + 8 = 1008 → 1024 bucket
        assert_eq!(pad_payload(&[0u8; 1000]).len(), 1024);
    }

    // --- Security tests ---

    #[test]
    fn tampered_nonce_fails() {
        let dek = DataEncryptionKey::new().unwrap();
        let plaintext = b"secret data";

        let mut encrypted = encrypt_for_sync(&dek, plaintext).unwrap();
        // Tamper with nonce (first 12 bytes)
        encrypted[0] ^= 0xFF;
        assert!(decrypt_from_sync(&dek, &encrypted).is_err());
    }

    #[test]
    fn tampered_auth_tag_fails() {
        let dek = DataEncryptionKey::new().unwrap();
        let plaintext = b"secret data";

        let mut encrypted = encrypt_for_sync(&dek, plaintext).unwrap();
        // Tamper with last byte (auth tag region)
        let last = encrypted.len() - 1;
        encrypted[last] ^= 0xFF;
        assert!(decrypt_from_sync(&dek, &encrypted).is_err());
    }

    #[test]
    fn truncated_ciphertext_fails() {
        let dek = DataEncryptionKey::new().unwrap();
        let plaintext = b"secret data";

        let encrypted = encrypt_for_sync(&dek, plaintext).unwrap();
        // Truncate: remove last few bytes
        let truncated = &encrypted[..encrypted.len() - 5];
        assert!(decrypt_from_sync(&dek, truncated).is_err());
    }

    #[test]
    fn unique_nonces_across_encryptions() {
        let dek = DataEncryptionKey::new().unwrap();
        let plaintext = b"same data";

        let enc1 = encrypt_for_sync(&dek, plaintext).unwrap();
        let enc2 = encrypt_for_sync(&dek, plaintext).unwrap();

        // Nonces (first 12 bytes) must differ
        assert_ne!(&enc1[..12], &enc2[..12]);
        // Full ciphertexts must differ (different nonce → different ciphertext)
        assert_ne!(enc1, enc2);

        // Both must decrypt to same plaintext
        assert_eq!(
            decrypt_from_sync(&dek, &enc1).unwrap(),
            decrypt_from_sync(&dek, &enc2).unwrap()
        );
    }

    #[test]
    fn padding_hides_payload_size() {
        // Two very different sized payloads should pad to the same bucket
        let small = b"a";
        let medium = b"this is a longer string with more content";

        let padded_small = pad_payload(small);
        let padded_medium = pad_payload(medium);

        // Both fit in the 256-byte bucket
        assert_eq!(padded_small.len(), 256);
        assert_eq!(padded_medium.len(), 256);

        // But they unpad to different contents
        assert_ne!(
            unpad_payload(&padded_small).unwrap(),
            unpad_payload(&padded_medium).unwrap()
        );
    }

    #[test]
    fn invalid_padding_length_rejected() {
        // Craft a padded payload with a bogus length prefix
        let mut bad_padded = vec![0u8; 256];
        // Set length to 1000 (larger than the buffer)
        bad_padded[..8].copy_from_slice(&1000u64.to_le_bytes());
        assert!(unpad_payload(&bad_padded).is_err());
    }

    #[test]
    fn large_payload_padded_to_multiple_of_bucket() {
        // A payload larger than 8192 should round up to next 8192 multiple
        let large = vec![0u8; 9000];
        let padded = pad_payload(&large);
        assert_eq!(padded.len(), 16384); // 2 * 8192
        assert_eq!(unpad_payload(&padded).unwrap().as_slice(), large);
    }
}
