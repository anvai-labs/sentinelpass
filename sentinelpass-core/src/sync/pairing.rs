//! Device pairing: 6-digit code, HKDF-derived pairing key, bootstrap encrypt/decrypt.

use rand::Rng;

/// Generate a random 6-digit pairing code.
pub fn generate_pairing_code() -> String {
    let code: u32 = rand::thread_rng().gen_range(100_000..1_000_000);
    format!("{:06}", code)
}

/// Derive a 32-byte pairing key from the 6-digit code and a random salt using HKDF-SHA256.
#[cfg(feature = "sync")]
pub fn derive_pairing_key(code: &str, salt: &[u8]) -> Result<[u8; 32], crate::crypto::CryptoError> {
    use hkdf::Hkdf;
    use sha2::Sha256;

    let hkdf = Hkdf::<Sha256>::new(Some(salt), code.as_bytes());
    let mut key = [0u8; 32];
    hkdf.expand(b"sentinelpass-pairing-v1", &mut key)
        .map_err(|e| crate::crypto::CryptoError::KdfFailed(format!("HKDF expand failed: {}", e)))?;
    Ok(key)
}

/// Derive a vault-bound registration proof for authorizing a new device join.
#[cfg(feature = "sync")]
pub fn derive_registration_proof(
    pairing_key: &[u8; 32],
    vault_id: &uuid::Uuid,
) -> Result<[u8; 32], crate::crypto::CryptoError> {
    use hmac::{Hmac, Mac};
    use sha2::Sha256;

    type HmacSha256 = Hmac<Sha256>;

    let mut mac = HmacSha256::new_from_slice(pairing_key)
        .map_err(|e| crate::crypto::CryptoError::KdfFailed(format!("HMAC init failed: {}", e)))?;
    mac.update(b"sentinelpass-pairing-registration-proof-v1");
    mac.update(vault_id.as_bytes());

    let bytes = mac.finalize().into_bytes();
    let mut out = [0u8; 32];
    out.copy_from_slice(&bytes);
    Ok(out)
}

/// Encrypt a VaultBootstrap blob with the pairing key.
#[cfg(feature = "sync")]
pub fn encrypt_bootstrap(
    pairing_key: &[u8; 32],
    bootstrap: &crate::sync::models::VaultBootstrap,
) -> Result<Vec<u8>, crate::crypto::CryptoError> {
    use crate::crypto::cipher::DataEncryptionKey;
    use crate::sync::crypto::encrypt_for_sync;

    let dek = DataEncryptionKey::from_bytes(&mut { *pairing_key });
    let json = serde_json::to_vec(bootstrap).map_err(|e| {
        crate::crypto::CryptoError::EncryptionFailed(format!("Serialize bootstrap: {}", e))
    })?;
    encrypt_for_sync(&dek, &json)
}

/// Decrypt a VaultBootstrap blob with the pairing key.
#[cfg(feature = "sync")]
pub fn decrypt_bootstrap(
    pairing_key: &[u8; 32],
    encrypted: &[u8],
) -> Result<crate::sync::models::VaultBootstrap, crate::crypto::CryptoError> {
    use crate::crypto::cipher::DataEncryptionKey;
    use crate::sync::crypto::decrypt_from_sync;

    let dek = DataEncryptionKey::from_bytes(&mut { *pairing_key });
    let json = decrypt_from_sync(&dek, encrypted)?;
    serde_json::from_slice(&json).map_err(|e| {
        crate::crypto::CryptoError::DecryptionFailed(format!("Deserialize bootstrap: {}", e))
    })
}

/// Generate a random 16-byte salt for HKDF.
pub fn generate_pairing_salt() -> [u8; 16] {
    let mut salt = [0u8; 16];
    rand::thread_rng().fill(&mut salt);
    salt
}

#[cfg(test)]
mod tests {
    use super::*;
    #[cfg(feature = "sync")]
    use crate::sync::models::VaultBootstrap;

    #[test]
    fn pairing_code_format() {
        for _ in 0..100 {
            let code = generate_pairing_code();
            assert_eq!(code.len(), 6);
            assert!(code.chars().all(|c| c.is_ascii_digit()));
            let n: u32 = code.parse().unwrap();
            assert!((100_000..1_000_000).contains(&n));
        }
    }

    #[test]
    fn pairing_salt_randomness() {
        let s1 = generate_pairing_salt();
        let s2 = generate_pairing_salt();
        assert_ne!(s1, s2);
    }

    #[cfg(feature = "sync")]
    #[test]
    fn pairing_key_derivation() {
        let salt = generate_pairing_salt();
        let key1 = derive_pairing_key("123456", &salt).unwrap();
        let key2 = derive_pairing_key("123456", &salt).unwrap();
        assert_eq!(key1, key2);

        let key3 = derive_pairing_key("654321", &salt).unwrap();
        assert_ne!(key1, key3);
    }

    #[cfg(feature = "sync")]
    #[test]
    fn bootstrap_encrypt_decrypt_roundtrip() {
        let salt = generate_pairing_salt();
        let code = generate_pairing_code();
        let pairing_key = derive_pairing_key(&code, &salt).unwrap();

        let bootstrap = VaultBootstrap {
            kdf_params_blob: vec![1, 2, 3],
            wrapped_dek_blob: vec![4, 5, 6],
            relay_url: "https://relay.example.com".to_string(),
            vault_id: uuid::Uuid::new_v4(),
            key_epoch: 3,
        };

        let encrypted = encrypt_bootstrap(&pairing_key, &bootstrap).unwrap();
        let decrypted = decrypt_bootstrap(&pairing_key, &encrypted).unwrap();

        assert_eq!(bootstrap.relay_url, decrypted.relay_url);
        assert_eq!(bootstrap.kdf_params_blob, decrypted.kdf_params_blob);
        assert_eq!(bootstrap.wrapped_dek_blob, decrypted.wrapped_dek_blob);
        assert_eq!(bootstrap.vault_id, decrypted.vault_id);
        assert_eq!(bootstrap.key_epoch, decrypted.key_epoch);
    }

    #[cfg(feature = "sync")]
    #[test]
    fn wrong_pairing_code_fails() {
        let salt = generate_pairing_salt();
        let correct_key = derive_pairing_key("123456", &salt).unwrap();
        let wrong_key = derive_pairing_key("654321", &salt).unwrap();

        let bootstrap = VaultBootstrap {
            kdf_params_blob: vec![1, 2, 3],
            wrapped_dek_blob: vec![4, 5, 6],
            relay_url: "https://relay.example.com".to_string(),
            vault_id: uuid::Uuid::new_v4(),
            key_epoch: 1,
        };

        let encrypted = encrypt_bootstrap(&correct_key, &bootstrap).unwrap();
        assert!(decrypt_bootstrap(&wrong_key, &encrypted).is_err());
    }

    #[cfg(feature = "sync")]
    #[test]
    fn registration_proof_is_deterministic_and_vault_bound() {
        let pairing_key = [7u8; 32];
        let vault_a = uuid::Uuid::new_v4();
        let vault_b = uuid::Uuid::new_v4();

        let a1 = derive_registration_proof(&pairing_key, &vault_a).unwrap();
        let a2 = derive_registration_proof(&pairing_key, &vault_a).unwrap();
        let b = derive_registration_proof(&pairing_key, &vault_b).unwrap();

        assert_eq!(a1, a2);
        assert_ne!(a1, b);
    }
}
