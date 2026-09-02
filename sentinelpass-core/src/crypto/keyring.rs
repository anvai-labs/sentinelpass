//! Key hierarchy and management.
//!
//! Implements the key wrapping/unwrapping scheme:
//! Master Password → Argon2id → Master Key → wraps → DEK

use crate::crypto::{cipher::DataEncryptionKey, kdf::KdfParams, CryptoError, Result};
use hkdf::Hkdf;
use serde::{Deserialize, Serialize};
use sha2::Sha256;
use zeroize::{ZeroizeOnDrop, Zeroizing};

/// HKDF `info` label binding the credential-registry equality key to its
/// purpose (ADR-001).
///
/// This value is part of the tag semantics: changing it changes every
/// equality tag. Any change must ship together with a bump of
/// `registry::EQUALITY_KEY_ID` so existing tags are rewritten under the new
/// key (suppressed rotation) instead of being misread as mass rotation.
pub const EQUALITY_KEY_INFO: &[u8] = b"sentinelpass-registry-equality-v1";

/// Derive the credential-registry equality key from a DEK.
///
/// HKDF-SHA256 with an empty salt over the DEK, 32-byte output, fixed
/// parameters so independent implementations cannot diverge. The derivation
/// is deterministic for a given DEK — which is what makes equality tags
/// comparable across entries and (paired) devices sharing that DEK.
///
/// The returned buffer is zeroized on drop, is never persisted, and must
/// not be cached across lock.
pub fn derive_equality_key(dek: &DataEncryptionKey) -> Result<Zeroizing<Vec<u8>>> {
    let hk = Hkdf::<Sha256>::new(None, dek.as_bytes());
    let mut okm = Zeroizing::new(vec![0u8; 32]);
    hk.expand(EQUALITY_KEY_INFO, okm.as_mut_slice())
        .map_err(|e| {
            CryptoError::KdfFailed(format!("registry equality key derivation failed: {}", e))
        })?;
    Ok(okm)
}

/// The master key derived from the master password
///
/// This key is used to wrap/unwrap the data encryption key (DEK).
/// It should be kept in secure memory and never persisted.
#[derive(ZeroizeOnDrop)]
pub struct MasterKey {
    key: [u8; 32],
}

impl MasterKey {
    /// Create a master key from raw bytes
    pub fn from_bytes(key: [u8; 32]) -> Self {
        Self { key }
    }

    /// Get a reference to the key bytes (use sparingly)
    pub fn as_bytes(&self) -> &[u8; 32] {
        &self.key
    }
}

/// A wrapped (encrypted) key that can be safely stored
///
/// The DEK is wrapped with the master key using AES-256-GCM.
/// This allows the DEK to be stored in the database while
/// only being accessible when the vault is unlocked.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct WrappedKey {
    /// Wrapped (encrypted) DEK
    pub wrapped_dek: Vec<u8>,

    /// Nonce used for wrapping
    pub nonce: [u8; 12],

    /// Authentication tag
    pub auth_tag: [u8; 16],
}

/// Key hierarchy manager
///
/// Manages the relationship between master key and data encryption keys.
pub struct KeyHierarchy {
    master_key: Option<MasterKey>,
    dek: Option<DataEncryptionKey>,
}

impl KeyHierarchy {
    /// Create a new key hierarchy
    pub fn new() -> Self {
        Self {
            master_key: None,
            dek: None,
        }
    }

    /// Initialize a new vault with a master password
    ///
    /// This derives the master key and generates/DEKs a new DEK.
    ///
    /// # Returns
    /// (KDF params, wrapped DEK) for storage
    pub fn initialize_vault(&mut self, master_password: &[u8]) -> Result<(KdfParams, WrappedKey)> {
        let kdf_params = KdfParams::new();

        // Derive master key from password
        use crate::crypto::kdf::derive_master_key;
        let master_key_bytes = derive_master_key(master_password, &kdf_params)?;
        self.master_key = Some(MasterKey::from_bytes(master_key_bytes));

        // Generate new DEK
        let dek = DataEncryptionKey::new()?;
        self.dek = Some(dek);

        // Wrap the DEK with the master key
        let wrapped = self.wrap_dek()?;

        Ok((kdf_params, wrapped))
    }

    /// Unlock an existing vault
    ///
    /// This derives the master key and unwraps the stored DEK.
    pub fn unlock_vault(
        &mut self,
        master_password: &[u8],
        kdf_params: &KdfParams,
        wrapped_dek: &WrappedKey,
    ) -> Result<()> {
        // Derive master key from password
        use crate::crypto::kdf::derive_master_key;
        let master_key_bytes = derive_master_key(master_password, kdf_params)?;
        self.master_key = Some(MasterKey::from_bytes(master_key_bytes));

        // Unwrap the DEK
        self.dek = Some(self.unwrap_dek(wrapped_dek)?);

        Ok(())
    }

    /// Unlock using an already unwrapped DEK.
    ///
    /// This is used for OS-protected biometric unlock flows where the platform
    /// credential store releases vault key material after local authentication,
    /// so the master password is not persisted or re-derived.
    pub fn unlock_vault_with_dek(&mut self, dek: DataEncryptionKey) {
        self.master_key.take();
        self.dek = Some(dek);
    }

    /// Lock the vault by clearing all keys from memory
    pub fn lock_vault(&mut self) {
        self.master_key.take();
        self.dek.take();
    }

    /// Check if the vault is currently unlocked
    pub fn is_unlocked(&self) -> bool {
        self.dek.is_some()
    }

    /// Get the DEK (only available when unlocked)
    pub fn dek(&self) -> Result<&DataEncryptionKey> {
        self.dek
            .as_ref()
            .ok_or_else(|| CryptoError::EncryptionFailed("Vault is locked".to_string()))
    }

    /// Derive the purpose-bound equality key for the credential registry
    /// (see [`derive_equality_key`]).
    ///
    /// Available on every unlock path — biometric unlock reaches the same
    /// DEK, so registry tags are computable regardless of how the vault was
    /// unlocked.
    pub fn equality_key(&self) -> Result<Zeroizing<Vec<u8>>> {
        derive_equality_key(self.dek()?)
    }

    /// Wrap the DEK with the master key
    fn wrap_dek(&self) -> Result<WrappedKey> {
        let master_key = self
            .master_key
            .as_ref()
            .ok_or_else(|| CryptoError::EncryptionFailed("No master key".to_string()))?;

        let dek = self
            .dek
            .as_ref()
            .ok_or_else(|| CryptoError::EncryptionFailed("No DEK".to_string()))?;

        // Create a cipher with the master key
        use aes_gcm::{
            aead::{Aead, AeadCore, KeyInit, OsRng},
            Aes256Gcm,
        };

        let cipher = Aes256Gcm::new(master_key.as_bytes().into());
        let nonce = Aes256Gcm::generate_nonce(&mut OsRng);
        let nonce_bytes: [u8; 12] = nonce.into();

        let dek_bytes = dek.as_bytes();
        let ciphertext = cipher
            .encrypt(&nonce, dek_bytes.as_ref())
            .map_err(|e| CryptoError::EncryptionFailed(format!("Failed to wrap DEK: {}", e)))?;

        if ciphertext.len() < 16 {
            return Err(CryptoError::EncryptionFailed(
                "Wrapped DEK too short".to_string(),
            ));
        }

        let tag_start = ciphertext.len() - 16;
        let auth_tag: [u8; 16] = ciphertext[tag_start..]
            .try_into()
            .map_err(|_| CryptoError::EncryptionFailed("Invalid auth tag".to_string()))?;
        let wrapped_dek = ciphertext[..tag_start].to_vec();

        Ok(WrappedKey {
            wrapped_dek,
            nonce: nonce_bytes,
            auth_tag,
        })
    }

    /// Unwrap the DEK with the master key
    fn unwrap_dek(&self, wrapped: &WrappedKey) -> Result<DataEncryptionKey> {
        let master_key = self
            .master_key
            .as_ref()
            .ok_or_else(|| CryptoError::DecryptionFailed("No master key".to_string()))?;

        use aes_gcm::{
            aead::{Aead, KeyInit},
            Aes256Gcm, Nonce,
        };

        let cipher = Aes256Gcm::new(master_key.as_bytes().into());
        let nonce = Nonce::from(wrapped.nonce);

        let mut ciphertext_with_tag = wrapped.wrapped_dek.clone();
        ciphertext_with_tag.extend_from_slice(&wrapped.auth_tag);

        let dek_bytes = cipher
            .decrypt(&nonce, ciphertext_with_tag.as_ref())
            .map_err(|_| CryptoError::AuthenticationFailed)?;

        if dek_bytes.len() != 32 {
            return Err(CryptoError::DecryptionFailed(format!(
                "Invalid DEK length: {}",
                dek_bytes.len()
            )));
        }

        let dek_array: [u8; 32] = dek_bytes
            .try_into()
            .map_err(|_| CryptoError::DecryptionFailed("Invalid DEK format".to_string()))?;

        Ok(DataEncryptionKey::from_bytes(&mut { dek_array }))
    }
}

impl Default for KeyHierarchy {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_key_hierarchy_init_unlock() {
        let mut hierarchy = KeyHierarchy::new();
        let password = b"test_password_123!";

        // Initialize vault
        let (kdf_params, wrapped_dek) = hierarchy.initialize_vault(password).unwrap();
        assert!(hierarchy.is_unlocked());

        // Lock vault
        hierarchy.lock_vault();
        assert!(!hierarchy.is_unlocked());

        // Unlock vault
        hierarchy
            .unlock_vault(password, &kdf_params, &wrapped_dek)
            .unwrap();
        assert!(hierarchy.is_unlocked());
    }

    #[test]
    fn test_unlock_with_dek_does_not_require_master_key() {
        let dek = DataEncryptionKey::new().unwrap();
        let mut hierarchy = KeyHierarchy::new();

        hierarchy.unlock_vault_with_dek(dek);

        assert!(hierarchy.is_unlocked());
        assert!(hierarchy.dek().is_ok());
    }

    #[test]
    fn test_unlock_with_wrong_password_fails() {
        let mut hierarchy = KeyHierarchy::new();
        let password = b"correct_password";

        // Initialize vault
        let (kdf_params, wrapped_dek) = hierarchy.initialize_vault(password).unwrap();

        // Lock vault
        hierarchy.lock_vault();

        // Try to unlock with wrong password
        let result = hierarchy.unlock_vault(b"wrong_password", &kdf_params, &wrapped_dek);
        assert!(result.is_err());
    }

    #[test]
    fn test_wrap_unwrap_dek() {
        let mut hierarchy = KeyHierarchy::new();
        let password = b"test_password";

        // Initialize vault
        let (_kdf_params, wrapped_dek) = hierarchy.initialize_vault(password).unwrap();

        // The wrapped DEK should be non-empty
        assert!(!wrapped_dek.wrapped_dek.is_empty());
        assert_ne!(wrapped_dek.nonce, [0u8; 12]);
        assert_ne!(wrapped_dek.auth_tag, [0u8; 16]);
    }

    #[test]
    fn test_multiple_lock_unlock_cycles() {
        let mut hierarchy = KeyHierarchy::new();
        let password = b"cycle_test_password";

        // Initialize vault
        let (kdf_params, wrapped_dek) = hierarchy.initialize_vault(password).unwrap();

        // Multiple lock/unlock cycles
        for _ in 0..5 {
            hierarchy.lock_vault();
            assert!(!hierarchy.is_unlocked());

            hierarchy
                .unlock_vault(password, &kdf_params, &wrapped_dek)
                .unwrap();
            assert!(hierarchy.is_unlocked());
        }
    }

    #[test]
    fn test_equality_key_deterministic_dek_bound_and_lock_gated() {
        // Deterministic for the same DEK, distinct across DEKs
        let mut first = KeyHierarchy::new();
        first.initialize_vault(b"first_password").unwrap();
        let first_a = first.equality_key().unwrap();
        let first_b = first.equality_key().unwrap();
        assert_eq!(first_a.as_slice(), first_b.as_slice());

        let mut second = KeyHierarchy::new();
        second.initialize_vault(b"other_password").unwrap();
        let second_key = second.equality_key().unwrap();
        assert_ne!(first_a.as_slice(), second_key.as_slice());

        // Biometric-style unlock (DEK handed in directly) derives the same key
        let mut dek_bytes = [7u8; 32];
        let dek = DataEncryptionKey::from_bytes(&mut dek_bytes);
        let direct = derive_equality_key(&dek).unwrap();
        let mut hierarchy = KeyHierarchy::new();
        hierarchy.unlock_vault_with_dek(dek);
        assert_eq!(
            hierarchy.equality_key().unwrap().as_slice(),
            direct.as_slice()
        );

        // Locked vaults derive nothing
        hierarchy.lock_vault();
        assert!(hierarchy.equality_key().is_err());
    }
}
