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

    /// True when the wrap was produced by `rotate_master_password` and the
    /// `key_epoch` was bound as AEAD associated data. Always serialized: the
    /// field must be present for bincode (non-self-describing) round-trips.
    /// Legacy (pre-ADR-002) blobs deserialize via `from_bincode_bytes`.
    pub epoch_bound: bool,
}

/// Legacy (<= v0.8.0) wire shape: no `epoch_bound` field.
#[derive(serde::Deserialize)]
struct LegacyWrappedKey {
    wrapped_dek: Vec<u8>,
    nonce: [u8; 12],
    auth_tag: [u8; 16],
}

impl WrappedKey {
    /// Deserialize a `WrappedKey` from bincode bytes, accepting both the
    /// current 4-field shape and the legacy 3-field shape written by
    /// <= v0.8.0 binaries.
    pub fn from_bincode_bytes(bytes: &[u8]) -> Result<Self> {
        match bincode::deserialize::<WrappedKey>(bytes) {
            Ok(key) => Ok(key),
            Err(_) => {
                let legacy: LegacyWrappedKey = bincode::deserialize(bytes).map_err(|e| {
                    CryptoError::DecryptionFailed(format!("Invalid wrapped key: {}", e))
                })?;
                Ok(Self {
                    wrapped_dek: legacy.wrapped_dek,
                    nonce: legacy.nonce,
                    auth_tag: legacy.auth_tag,
                    epoch_bound: false,
                })
            }
        }
    }
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

    /// Unlock an epoch-bound vault: the `key_epoch` is verified as AEAD
    /// associated data inside the wrap, so a `db_metadata` row whose epoch
    /// column was rolled back or tampered with fails authentication.
    pub fn unlock_vault_with_epoch(
        &mut self,
        master_password: &[u8],
        kdf_params: &KdfParams,
        wrapped_dek: &WrappedKey,
        key_epoch: i64,
    ) -> Result<()> {
        use crate::crypto::kdf::derive_master_key;
        let master_key_bytes = derive_master_key(master_password, kdf_params)?;
        self.master_key = Some(MasterKey::from_bytes(master_key_bytes));

        let aad_bytes = if wrapped_dek.epoch_bound {
            Some(key_epoch.to_le_bytes())
        } else {
            None
        };
        self.dek = Some(Self::unwrap_dek_under_key(
            self.master_key.as_ref().unwrap(),
            wrapped_dek,
            aad_bytes.as_ref().map(|b| b.as_slice()),
        )?);

        Ok(())
    }

    /// Install a new master key after a successful rotation. The DEK is
    /// unchanged — only its wrapper was re-derived.
    pub fn adopt_master_key(&mut self, master_key: MasterKey) {
        self.master_key = Some(master_key);
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

        Self::wrap_dek_under_key(master_key, dek, None, false)
    }

    /// Wrap the DEK under the given master key, optionally binding AAD.
    ///
    /// Rotation (ADR-002) binds the `key_epoch` as associated data: a
    /// `db_metadata` row whose epoch column disagrees with the wrap fails
    /// authentication at open time instead of silently opening.
    pub(crate) fn wrap_dek_under_key(
        master_key: &MasterKey,
        dek: &DataEncryptionKey,
        aad: Option<&[u8]>,
        epoch_bound: bool,
    ) -> Result<WrappedKey> {
        use aes_gcm::{
            aead::{Aead, AeadCore, KeyInit, OsRng},
            Aes256Gcm,
        };

        let cipher = Aes256Gcm::new(master_key.as_bytes().into());
        let nonce = Aes256Gcm::generate_nonce(&mut OsRng);
        let nonce_bytes: [u8; 12] = nonce.into();

        let dek_bytes = dek.as_bytes();
        let payload = aes_gcm::aead::Payload {
            msg: dek_bytes.as_ref(),
            aad: aad.unwrap_or(&[]),
        };
        let ciphertext = cipher
            .encrypt(&nonce, payload)
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
            epoch_bound,
        })
    }

    /// Unwrap the DEK with the master key
    fn unwrap_dek(&self, wrapped: &WrappedKey) -> Result<DataEncryptionKey> {
        let master_key = self
            .master_key
            .as_ref()
            .ok_or_else(|| CryptoError::DecryptionFailed("No master key".to_string()))?;

        Self::unwrap_dek_under_key(master_key, wrapped, None)
    }

    /// Unwrap the DEK under the given master key, optionally verifying AAD.
    pub(crate) fn unwrap_dek_under_key(
        master_key: &MasterKey,
        wrapped: &WrappedKey,
        aad: Option<&[u8]>,
    ) -> Result<DataEncryptionKey> {
        use aes_gcm::{
            aead::{Aead, KeyInit},
            Aes256Gcm, Nonce,
        };

        let cipher = Aes256Gcm::new(master_key.as_bytes().into());
        let nonce = Nonce::from(wrapped.nonce);

        let mut ciphertext_with_tag = wrapped.wrapped_dek.clone();
        ciphertext_with_tag.extend_from_slice(&wrapped.auth_tag);

        let dek_bytes = cipher
            .decrypt(
                &nonce,
                aes_gcm::aead::Payload {
                    msg: ciphertext_with_tag.as_ref(),
                    aad: aad.unwrap_or(&[]),
                },
            )
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

/// Rotate the vault's master password: verify the current password against the
/// stored wrap, then re-wrap the SAME DEK under a master key derived from the
/// new password with a fresh salt.
///
/// Zero-trust properties (ADR-002):
/// - The current password is proven by unwrapping the stored wrap (GCM auth);
///   the proven DEK must additionally match the in-memory DEK of the unlocked
///   vault, so a swapped `db_metadata` cannot redirect the rotation.
/// - The new wrap binds the new `key_epoch` as AEAD associated data — a
///   `db_metadata` row with a disagreeing epoch column fails authentication.
/// - The old master key is replaced in memory; the DEK (and therefore every
///   entry ciphertext) is untouched.
///
/// Returns the staged rotation `(new_kdf_params, new_wrapped_dek, new_master)`
/// and does NOT modify the hierarchy: adoption is the caller's last step,
/// after the staged material is durably committed (WBS-309 / TD-SEC-04 —
/// stage → verify → commit → adopt). The staged wrap is verified to open
/// under the new key and yield the same DEK before it is returned, so a
/// caller can never persist an unopenable rotation.
pub fn rotate_master_password(
    hierarchy: &mut KeyHierarchy,
    current_password: &[u8],
    kdf_params: &KdfParams,
    current_wrapped: &WrappedKey,
    current_epoch: i64,
    new_password: &[u8],
) -> Result<(KdfParams, WrappedKey, MasterKey)> {
    use crate::crypto::kdf::derive_master_key;
    use subtle::ConstantTimeEq;

    if new_password == current_password {
        return Err(CryptoError::EncryptionFailed(
            "New master password must differ from the current password".to_string(),
        ));
    }

    // D2: prove the current password by unwrapping the stored wrap. The wrap
    // may be epoch-bound (post-rotation) or legacy (pre-ADR-002).
    let current_master = MasterKey::from_bytes(derive_master_key(current_password, kdf_params)?);
    let aad_bytes = if current_wrapped.epoch_bound {
        Some(current_epoch.to_le_bytes())
    } else {
        None
    };
    let proved_dek = KeyHierarchy::unwrap_dek_under_key(
        &current_master,
        current_wrapped,
        aad_bytes.as_ref().map(|b| b.as_slice()),
    )?;

    // The proved DEK must match the in-memory DEK of the unlocked vault; a
    // mismatch means the on-disk metadata was swapped under us.
    let dek = hierarchy
        .dek()
        .map_err(|_| CryptoError::EncryptionFailed("Vault is locked".to_string()))?;
    if !bool::from(proved_dek.as_bytes().ct_eq(dek.as_bytes())) {
        return Err(CryptoError::AuthenticationFailed);
    }

    // New salt + new master key; re-wrap the SAME DEK with the new epoch as AAD.
    let new_params = KdfParams::new();
    let new_master = MasterKey::from_bytes(derive_master_key(new_password, &new_params)?);
    let new_epoch = current_epoch + 1;
    let wrapped =
        KeyHierarchy::wrap_dek_under_key(&new_master, dek, Some(&new_epoch.to_le_bytes()), true)?;

    // Verify the staged wrap before handing it to the caller: it must open
    // under the new master key and yield the same DEK. A wrap that cannot
    // survive its own round-trip must never reach storage.
    let verified_dek =
        KeyHierarchy::unwrap_dek_under_key(&new_master, &wrapped, Some(&new_epoch.to_le_bytes()))?;
    if !bool::from(verified_dek.as_bytes().ct_eq(dek.as_bytes())) {
        return Err(CryptoError::EncryptionFailed(
            "staged rotation wrap verification failed: DEK mismatch".to_string(),
        ));
    }

    // Deliberately NOT adopting: the caller adopts only after durable commit.
    Ok((new_params, wrapped, new_master))
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

    #[test]
    fn rotation_round_trips_and_rejects_old_password() {
        let old_pw = b"correct-horse-battery";
        let new_pw = b"staple-anchor-quantum-42";
        let mut h = KeyHierarchy::new();
        let (params, wrapped) = h.initialize_vault(old_pw).unwrap();
        let dek_before = *h.dek().unwrap().as_bytes();

        // v0.8.0 wraps are not epoch-bound; the first rotation upgrades them.
        assert!(!wrapped.epoch_bound);

        let (new_params, new_wrapped, new_master) =
            rotate_master_password(&mut h, old_pw, &params, &wrapped, 1, new_pw).unwrap();
        assert!(new_wrapped.epoch_bound);
        assert_eq!(
            *h.dek().unwrap().as_bytes(),
            dek_before,
            "DEK must not change"
        );
        // Staging does not adopt: the caller commits first (WBS-309).
        h.adopt_master_key(new_master);

        // New password opens the new wrap; old password must fail.
        let mut reopened = KeyHierarchy::new();
        reopened
            .unlock_vault_with_epoch(new_pw, &new_params, &new_wrapped, 2)
            .unwrap();
        assert_eq!(*reopened.dek().unwrap().as_bytes(), dek_before);

        let mut old_attempt = KeyHierarchy::new();
        let err = old_attempt
            .unlock_vault_with_epoch(old_pw, &new_params, &new_wrapped, 2)
            .unwrap_err();
        assert!(matches!(err, crate::CryptoError::AuthenticationFailed));

        // Rotation with the wrong current password is rejected.
        match rotate_master_password(
            &mut h,
            b"wrong-password",
            &new_params,
            &new_wrapped,
            2,
            new_pw,
        ) {
            Err(crate::CryptoError::AuthenticationFailed) => {}
            Err(other) => panic!("expected AuthenticationFailed, got {other:?}"),
            Ok(_) => panic!("rotation with the wrong current password must fail"),
        }
    }

    #[test]
    fn rotation_rejects_same_password() {
        let mut h = KeyHierarchy::new();
        let pw = b"correct-horse-battery";
        let (params, wrapped) = h.initialize_vault(pw).unwrap();
        match rotate_master_password(&mut h, pw, &params, &wrapped, 1, pw) {
            Err(e) => assert!(e.to_string().contains("must differ")),
            Ok(_) => panic!("rotation to the same password must fail"),
        }
    }

    #[test]
    fn epoch_aad_binds_the_wrap_against_db_rollback() {
        // Rotate to an epoch-bound wrap, then attempt to open it while claiming
        // a rolled-back epoch: GCM auth must fail (F1).
        let old_pw = b"correct-horse-battery";
        let new_pw = b"staple-anchor-quantum-42";
        let mut h = KeyHierarchy::new();
        let (params, wrapped) = h.initialize_vault(old_pw).unwrap();
        let (_, new_wrapped, _) =
            rotate_master_password(&mut h, old_pw, &params, &wrapped, 1, new_pw).unwrap();

        // Attacker rolls the epoch column back to 1: the AAD no longer matches
        // the wrap, so authentication fails instead of silently opening.
        let mut attempt = KeyHierarchy::new();
        let err = attempt
            .unlock_vault_with_epoch(new_pw, &params, &new_wrapped, 1)
            .unwrap_err();
        assert!(matches!(err, crate::CryptoError::AuthenticationFailed));
    }

    #[test]
    fn rotation_works_from_biometric_unlocked_state() {
        // F2: biometric unlock drops the master key; rotation re-derives it
        // from the supplied current password.
        let pw = b"correct-horse-battery";
        let new_pw = b"staple-anchor-quantum-42";
        let mut h = KeyHierarchy::new();
        let (params, wrapped) = h.initialize_vault(pw).unwrap();
        let dek_before = *h.dek().unwrap().as_bytes();

        h.unlock_vault_with_dek(h.dek().unwrap().clone());
        assert!(h.is_unlocked());

        let (_, new_wrapped, _) =
            rotate_master_password(&mut h, pw, &params, &wrapped, 1, new_pw).unwrap();
        assert_eq!(*h.dek().unwrap().as_bytes(), dek_before);
        assert!(new_wrapped.epoch_bound);
    }

    #[test]
    fn rotation_stages_without_adopting_old_key() {
        // WBS-309: after staging (and before any commit), the in-memory
        // hierarchy still wraps under the OLD master key — a failed commit
        // leaves the vault exactly as it was.
        let old_pw = b"correct-horse-battery";
        let new_pw = b"staple-anchor-quantum-42";
        let mut h = KeyHierarchy::new();
        let (params, wrapped) = h.initialize_vault(old_pw).unwrap();
        let dek = *h.dek().unwrap().as_bytes();

        let (new_params, new_wrapped, new_master) =
            rotate_master_password(&mut h, old_pw, &params, &wrapped, 1, new_pw).unwrap();

        // Staged wrap round-trips under the NEW key (the built-in verify).
        let mut reopened = KeyHierarchy::new();
        reopened
            .unlock_vault_with_epoch(new_pw, &new_params, &new_wrapped, 2)
            .unwrap();
        assert_eq!(*reopened.dek().unwrap().as_bytes(), dek);

        // In-memory hierarchy still operates under the OLD key: a wrap it
        // produces opens with the old password.
        let still_old_wrap = h.wrap_dek().unwrap();
        let mut old_keyed = KeyHierarchy::new();
        old_keyed.unlock_vault(old_pw, &params, &wrapped).unwrap();
        let rewrapped_dek = old_keyed.unwrap_dek(&still_old_wrap).unwrap();
        assert_eq!(*rewrapped_dek.as_bytes(), dek);

        // After adoption, the hierarchy wraps under the NEW key instead.
        h.adopt_master_key(new_master);
        let adopted_wrap = h.wrap_dek().unwrap();
        assert!(
            old_keyed.unwrap_dek(&adopted_wrap).is_err(),
            "post-adoption wrap must not open under the old master key"
        );
        let mut new_keyed = KeyHierarchy::new();
        new_keyed
            .unlock_vault_with_epoch(new_pw, &new_params, &new_wrapped, 2)
            .unwrap();
        assert_eq!(
            *new_keyed.unwrap_dek(&adopted_wrap).unwrap().as_bytes(),
            dek
        );
    }

    #[test]
    fn wrapped_key_legacy_blob_deserializes_without_epoch_flag() {
        // A <= v0.8.0 blob is bincode without the epoch_bound field.
        #[derive(serde::Serialize)]
        struct Legacy {
            wrapped_dek: Vec<u8>,
            nonce: [u8; 12],
            auth_tag: [u8; 16],
        }
        let legacy_bytes = bincode::serialize(&Legacy {
            wrapped_dek: vec![1, 2, 3],
            nonce: [0u8; 12],
            auth_tag: [9u8; 16],
        })
        .unwrap();
        let parsed = WrappedKey::from_bincode_bytes(&legacy_bytes).unwrap();
        assert!(!parsed.epoch_bound);
        assert_eq!(parsed.wrapped_dek, vec![1, 2, 3]);
    }
}
