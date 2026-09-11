//! Device pairing.
//!
//! v2 (WBS-615/616, ADR-006 / SR-SYNC-006): pairing uses a 256-bit
//! high-entropy secret S (QR/base64url — never a short numeric) as the sole
//! root: the bootstrap is encrypted under HKDF(S), the relay stores only
//! Argon2id(S) and gates retrieval on knowledge of S (one-use, short TTL,
//! attempt-limited), and a 6-digit TRANSCRIPT derived from S is displayed
//! on BOTH devices purely for human out-of-band comparison — a short
//! numeric value never encrypts bootstrap material. The v1 six-digit HKDF
//! path was offline-guessable (TD-SEC-07) and is retired.
//!
//! Dead giveaway of the identity domain: the v2 pairing key derives from
//! the SECRET, while the v1 key derived from the numeric code.

use rand::Rng;
use sha2::{Digest, Sha256};

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

// --- v2 pairing (WBS-615/616, ADR-006) -------------------------------------

/// Length of the v2 pairing secret: 256 bits — offline-guess resistance by
/// construction (the v1 six-digit code gave ~20 bits and an offline oracle).
pub const PAIRING_SECRET_LEN: usize = 32;

/// Generate a fresh 256-bit pairing secret (CSPRNG).
pub fn generate_pairing_secret() -> [u8; PAIRING_SECRET_LEN] {
    let mut secret = [0u8; PAIRING_SECRET_LEN];
    rand::thread_rng().fill(&mut secret);
    secret
}

/// base64url-nopad encoding for the secret (QR/paste friendly).
pub fn pairing_secret_to_b64(secret: &[u8; PAIRING_SECRET_LEN]) -> String {
    use base64::engine::general_purpose::URL_SAFE_NO_PAD;
    use base64::Engine as _;
    URL_SAFE_NO_PAD.encode(secret)
}

/// Decode a base64url pairing secret; strict length.
pub fn pairing_secret_from_b64(
    encoded: &str,
) -> Result<[u8; PAIRING_SECRET_LEN], crate::crypto::CryptoError> {
    use base64::engine::general_purpose::URL_SAFE_NO_PAD;
    use base64::Engine as _;
    let bytes = URL_SAFE_NO_PAD.decode(encoded.trim()).map_err(|e| {
        crate::crypto::CryptoError::InvalidNonce(format!("pairing secret must be base64url: {e}"))
    })?;
    let secret: [u8; PAIRING_SECRET_LEN] = bytes.try_into().map_err(|bytes: Vec<u8>| {
        crate::crypto::CryptoError::InvalidKeyLength {
            expected: PAIRING_SECRET_LEN,
            got: bytes.len(),
        }
    })?;
    Ok(secret)
}

/// The deterministic relay key for a secret: hex(SHA256(S))[..32]. The
/// relay can recompute it from the submitted secret — the client never
/// needs a separate id, so the QR payload is ONLY the secret.
pub fn bootstrap_id_for(secret: &[u8; PAIRING_SECRET_LEN]) -> String {
    let digest = Sha256::digest(secret);
    hex::encode(&digest[..16])
}

/// HKDF info label for the v2 pairing key (distinct domain: the SECRET —
/// 256 bits — is the IKM, unlike the v1 numeric code).
pub const PAIRING_KEY_INFO_V2: &[u8] = b"sentinelpass-pairing-v2";

/// Derive the v2 pairing key from the high-entropy secret: HKDF-SHA256
/// (ikm = S, empty salt, fixed info). Offline-guess resistant: S is 256
/// bits of CSPRNG output.
pub fn derive_pairing_key_v2(
    secret: &[u8; PAIRING_SECRET_LEN],
) -> Result<[u8; 32], crate::crypto::CryptoError> {
    use hkdf::Hkdf;
    let hk = Hkdf::<Sha256>::new(None, secret);
    let mut key = [0u8; 32];
    hk.expand(PAIRING_KEY_INFO_V2, &mut key)
        .map_err(|e| crate::crypto::CryptoError::KdfFailed(format!("HKDF expand failed: {}", e)))?;
    Ok(key)
}

/// The human TRANSCRIPT bound: six digits derived from S, displayed on BOTH
/// devices for out-of-band comparison. Purely a comparison aid — it NEVER
/// encrypts or gates anything (SR-SYNC-006: short numerics do not encrypt
/// bootstrap material).
pub fn transcript_digits(secret: &[u8; PAIRING_SECRET_LEN]) -> String {
    use hkdf::Hkdf;
    let hk = Hkdf::<Sha256>::new(None, secret);
    let mut okm = [0u8; 32];
    hk.expand(b"sentinelpass-pairing-transcript-v1", &mut okm)
        .expect("32-byte HKDF output is valid");
    let digits = u64::from_be_bytes(okm[..8].try_into().expect("8 bytes")) % 1_000_000;
    format!("{digits:06}")
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

/// v2 pairing tests (WBS-615/616, SR-SYNC-006).
#[cfg(test)]
mod v2_tests {
    use super::*;
    #[cfg(feature = "sync")]
    use crate::sync::models::VaultBootstrap;

    /// THE WBS-615 root: the secret is 256 bits of CSPRNG output — two
    /// secrets never collide, and the encoding round-trips.
    #[test]
    fn pairing_secret_is_256_bit_and_roundtrips() {
        let a = generate_pairing_secret();
        let b = generate_pairing_secret();
        assert_ne!(a, b, "CSPRNG secrets never collide in practice");
        let encoded = pairing_secret_to_b64(&a);
        assert_eq!(pairing_secret_from_b64(&encoded).unwrap(), a);
        assert!(!encoded.contains('='), "base64url-nopad: {encoded}");
    }

    /// A short numeric payload is NEVER accepted as a secret (the v1
    /// offline-oracle class is structurally gone).
    #[test]
    fn short_numeric_secret_is_rejected() {
        assert!(pairing_secret_from_b64("123456").is_err());
        assert!(pairing_secret_from_b64("").is_err());
    }

    /// THE transcript binding: six digits derived from the secret, stable
    /// for human comparison, never used as key material.
    #[test]
    fn transcript_digits_are_stable_and_diverge() {
        let a = generate_pairing_secret();
        let b = generate_pairing_secret();
        let ta = transcript_digits(&a);
        assert_eq!(ta, transcript_digits(&a), "stable for comparison");
        assert_eq!(ta.len(), 6);
        assert!(ta.chars().all(|c| c.is_ascii_digit()));
        assert_ne!(ta, transcript_digits(&b), "secrets diverge");
    }

    /// The bootstrap id is deterministic in the secret (the relay can
    /// recompute it; the QR payload is ONLY the secret).
    #[test]
    fn bootstrap_id_is_deterministic_in_the_secret() {
        let a = generate_pairing_secret();
        assert_eq!(bootstrap_id_for(&a), bootstrap_id_for(&a));
        assert_ne!(
            bootstrap_id_for(&a),
            bootstrap_id_for(&generate_pairing_secret())
        );
        assert_eq!(bootstrap_id_for(&a).len(), 32, "hex of 16 bytes");
    }

    /// The v2 pairing key derives from the SECRET (HKDF), encrypts the
    /// bootstrap, and a wrong secret cannot decrypt.
    #[cfg(feature = "sync")]
    #[test]
    fn pairing_key_v2_encrypts_and_decrypts_the_bootstrap() {
        let secret = generate_pairing_secret();
        let key = derive_pairing_key_v2(&secret).unwrap();
        let bootstrap = VaultBootstrap {
            kdf_params_blob: vec![1, 2, 3],
            wrapped_dek_blob: vec![4, 5, 6],
            relay_url: "https://relay.example.com".to_string(),
            vault_id: uuid::Uuid::new_v4(),
            key_epoch: 1,
        };
        let encrypted = encrypt_bootstrap(&key, &bootstrap).unwrap();
        let decrypted = decrypt_bootstrap(&key, &encrypted).unwrap();
        assert_eq!(decrypted.vault_id, bootstrap.vault_id);

        let wrong = derive_pairing_key_v2(&generate_pairing_secret()).unwrap();
        assert!(decrypt_bootstrap(&wrong, &encrypted).is_err());
    }
}
