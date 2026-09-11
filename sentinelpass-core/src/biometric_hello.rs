//! Windows Hello-bound DEK wrap (WBS-710, TD-CLIENT-04, SR-CLIENT biometric
//! parity with macOS Touch ID).
//!
//! Goal: the vault DEK stored for biometric unlock on Windows must be
//! USABLE ONLY THROUGH a Windows Hello-gated private-key operation — the
//! same property macOS gets from `kSecAccessControlBiometryCurrentSet`
//! (the OS itself gates the secret release on biometry).
//!
//! Platform primitive and why it looks like this: the documented,
//! TPM-backed Hello key surface (`Windows.Security.Credentials.
//! KeyCredentialManager`) supports exactly one private-key operation —
//! SIGNING (passport keys are sign-only by design; NCryptDecrypt on them
//! is undocumented). So the wrap derives its symmetric key from a
//! SIGNATURE:
//!
//! - ENABLE: create/recreate a per-vault Hello key (`sentinelpass.<ref>`),
//!   draw a random 32-byte challenge, sign it TWICE (this prompts Hello),
//!   and require the two signatures to be BYTE-IDENTICAL (RSASSA-PKCS1-v1_5
//!   over a fixed input is deterministic; a platform that randomizes
//!   signatures refuses enable — fail-closed, before any secret is
//!   stored). The wrap key is `HKDF-SHA256(signature || ref-binding)`;
//!   the DEK is AES-256-GCM-sealed under it; a full UNWRAP round-trip is
//!   verified before the blob is accepted.
//! - RELEASE: signing the stored challenge requires the Hello gesture
//!   (the TPM refuses the private-key op without it), the signature
//!   reproduces the wrap key, the GCM tag authenticates it. A refused or
//!   failing gesture leaves the DEK unrecoverable from the blob — the user
//!   falls back to the master password.
//!
//! The at-rest blob therefore contains NO usable secret material: the
//! keyring entry alone (same-user readable, ADR-003 rev 2 scope) cannot
//! yield the DEK without a fresh Hello-gated TPM operation. This closes
//! the TD-CLIENT-04 gap where consent (UserConsentVerifier) and keyring
//! retrieval were independent.
//!
//! Everything here is PLATFORM-FREE and unit-testable: the Windows module
//! in `biometric.rs` supplies the real signer; tests use a fake.

use crate::crypto::cipher::{decrypt_entry, encrypt_entry};
use crate::crypto::DataEncryptionKey;
use crate::{CryptoError, DatabaseError, PasswordManagerError, Result};
use hkdf::Hkdf;
use serde::{Deserialize, Serialize};
use sha2::Sha256;
use zeroize::{Zeroize, ZeroizeOnDrop};

/// Blob format version. v1 = signature-KDF wrap (this module).
pub const HELLO_BOUND_BLOB_VERSION: u8 = 1;

/// HKDF salt for the wrap-key derivation (domain separation).
const WRAP_KEY_SALT: &[u8] = b"sentinelpass.hello-wrap.v1";

/// What the platform must supply: one Hello-gated signature over `data`.
/// The Windows implementation routes to `KeyCredential::RequestSignAsync`
/// (which shows the Hello prompt); tests use a deterministic fake.
pub trait HelloKeySigner {
    /// Sign `data` with the vault's Hello key. Errors cover "Hello not
    /// set up", "user cancelled", and platform failures — all of which
    /// must fail the release.
    fn sign(&self, data: &[u8]) -> Result<Vec<u8>>;

    /// Whether the platform can create/use Hello keys at all.
    fn is_supported(&self) -> bool;
}

/// The stored, NON-SECRET blob (keyring entry value, JSON). Recovering the
/// DEK from it requires a fresh signature over `challenge`.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct HelloBoundBlob {
    pub version: u8,
    /// Hello key (KeyCredential) name for this vault.
    pub key_name: String,
    /// Hex-encoded random 32-byte challenge the release path signs.
    pub challenge_hex: String,
    /// AES-256-GCM parameters sealing the DEK under the wrap key.
    pub nonce: [u8; 12],
    pub ciphertext: Vec<u8>,
    pub auth_tag: [u8; 16],
}

impl HelloBoundBlob {
    /// Serialize for keyring storage (compact JSON).
    pub fn encode(&self) -> String {
        serde_json::to_string(self).unwrap_or_else(|_| {
            // Struct is JSON-safe by construction; unreachable in practice.
            String::new()
        })
    }

    /// Parse a stored value. `None` when the value is not a v1 blob —
    /// the caller treats that as the LEGACY (pre-710, plain base64 DEK)
    /// format and applies the migration path.
    pub fn decode(value: &str) -> Option<Self> {
        let blob: Self = serde_json::from_str(value).ok()?;
        if blob.version != HELLO_BOUND_BLOB_VERSION {
            return None;
        }
        Some(blob)
    }
}

/// Derive the wrap key from a Hello signature, bound to the biometric ref
/// (a signature for one vault's key cannot unwrap another vault's blob —
/// and the binding rides the KDF `info`, not trust in the caller).
pub fn derive_wrap_key(signature: &[u8], biometric_ref: &str) -> ZeroizingKey {
    let hk = Hkdf::<Sha256>::new(Some(WRAP_KEY_SALT), signature);
    let mut okm = ZeroizingKey::zeroed();
    hk.expand(biometric_ref.as_bytes(), okm.as_mut())
        .expect("HKDF-SHA256 expand with a 32-byte key cannot fail");
    okm
}

/// Owned 32-byte wrap key, zeroized on drop (never persisted).
#[derive(Clone, Zeroize, ZeroizeOnDrop)]
pub struct ZeroizingKey([u8; 32]);

impl ZeroizingKey {
    fn zeroed() -> Self {
        Self([0u8; 32])
    }

    fn as_mut(&mut self) -> &mut [u8; 32] {
        &mut self.0
    }

    fn as_bytes(&self) -> &[u8; 32] {
        &self.0
    }
}

/// RSASSA-PKCS1-v1_5 signatures over the same input are deterministic.
/// Enable requires that property of the platform key and verifies it by
/// signing the challenge twice; any divergence refuses the enable.
pub fn require_deterministic_signature(first: &[u8], second: &[u8]) -> Result<()> {
    if first == second {
        Ok(())
    } else {
        Err(PasswordManagerError::from(DatabaseError::Keyring(
            "Windows Hello key produced non-deterministic signatures; \
             Hello-bound storage is unavailable on this platform"
                .to_string(),
        )))
    }
}

/// The enable-time orchestration (platform-free). Signs the challenge via
/// `signer`, self-checks determinism, seals the DEK, and verifies a full
/// release round-trip BEFORE returning the blob to persist. On any failure
/// nothing needs cleanup — the blob was never stored.
pub fn seal_dek_under_hello(
    signer: &dyn HelloKeySigner,
    key_name: &str,
    biometric_ref: &str,
    dek: &DataEncryptionKey,
) -> Result<HelloBoundBlob> {
    if !signer.is_supported() {
        return Err(PasswordManagerError::NotFound(
            "Windows Hello key storage is not supported on this system".to_string(),
        ));
    }

    let challenge: [u8; 32] = rand::random();

    // The two signatures double as the Hello consent at enable time.
    let sig_a = signer.sign(&challenge)?;
    let sig_b = signer.sign(&challenge)?;
    require_deterministic_signature(&sig_a, &sig_b)?;

    let wrap_key = derive_wrap_key(&sig_a, biometric_ref);
    let wrap_dek = DataEncryptionKey::from_bytes(&mut {
        let mut bytes = [0u8; 32];
        bytes.copy_from_slice(wrap_key.as_bytes());
        bytes
    });

    let sealed = encrypt_entry(&wrap_dek, dek.as_bytes())?;

    let blob = HelloBoundBlob {
        version: HELLO_BOUND_BLOB_VERSION,
        key_name: key_name.to_string(),
        challenge_hex: hex::encode(challenge),
        nonce: sealed.nonce,
        ciphertext: sealed.ciphertext,
        auth_tag: sealed.auth_tag,
    };

    // Round-trip before accepting: catches platform signature drift and
    // seal bugs at enable time, when the user is present and can retry.
    let roundtrip = release_dek_under_hello(signer, biometric_ref, &blob)?;
    if roundtrip.as_bytes() != dek.as_bytes() {
        return Err(PasswordManagerError::from(DatabaseError::Keyring(
            "Hello-bound storage round-trip mismatch; refusing to store".to_string(),
        )));
    }

    Ok(blob)
}

/// The release orchestration (platform-free). Signing the stored challenge
/// triggers the platform's Hello prompt; the GCM tag authenticates the
/// derived wrap key, so a refused gesture, a wrong key, or tampered blob
/// bytes all fail closed.
pub fn release_dek_under_hello(
    signer: &dyn HelloKeySigner,
    biometric_ref: &str,
    blob: &HelloBoundBlob,
) -> Result<DataEncryptionKey> {
    let challenge = hex::decode(&blob.challenge_hex).map_err(|_| {
        PasswordManagerError::from(DatabaseError::Keyring(
            "Stored Hello-bound blob has an invalid challenge".to_string(),
        ))
    })?;

    let signature = signer.sign(&challenge)?;
    let wrap_key = derive_wrap_key(&signature, biometric_ref);
    let wrap_dek = DataEncryptionKey::from_bytes(&mut {
        let mut bytes = [0u8; 32];
        bytes.copy_from_slice(wrap_key.as_bytes());
        bytes
    });

    let plaintext = decrypt_entry(
        &wrap_dek,
        &crate::crypto::EncryptedEntry {
            nonce: blob.nonce,
            ciphertext: blob.ciphertext.clone(),
            auth_tag: blob.auth_tag,
        },
    )
    .map_err(|_: CryptoError| {
        // Authentication failure: wrong Hello response, wrong vault, or a
        // tampered/stale blob. Never distinguish which — fail closed.
        PasswordManagerError::from(DatabaseError::Keyring(
            "Hello-bound release failed authentication".to_string(),
        ))
    })?;

    let mut key_bytes = [0u8; 32];
    if plaintext.len() != 32 {
        return Err(PasswordManagerError::from(DatabaseError::Keyring(
            "Stored Hello-bound secret has invalid length".to_string(),
        )));
    }
    key_bytes.copy_from_slice(&plaintext);
    Ok(DataEncryptionKey::from_bytes(&mut key_bytes))
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Deterministic fake: exactly what RSASSA-PKCS1-v1_5 over a fixed
    /// input promises on a real Hello key.
    struct DeterministicSigner {
        supported: bool,
        root: [u8; 32],
        fail_signs: bool,
    }

    impl DeterministicSigner {
        fn new() -> Self {
            Self {
                supported: true,
                root: [0x5Au8; 32],
                fail_signs: false,
            }
        }

        fn signature_for(&self, data: &[u8]) -> Vec<u8> {
            // "RSA signature": HMAC-like deterministic function of input.
            use hmac::{Hmac, Mac};
            let mut mac = Hmac::<Sha256>::new_from_slice(&self.root).unwrap();
            mac.update(data);
            mac.finalize().into_bytes().to_vec()
        }
    }

    impl HelloKeySigner for DeterministicSigner {
        fn sign(&self, data: &[u8]) -> Result<Vec<u8>> {
            if self.fail_signs {
                return Err(PasswordManagerError::from(DatabaseError::Keyring(
                    "Hello prompt refused".to_string(),
                )));
            }
            Ok(self.signature_for(data))
        }

        fn is_supported(&self) -> bool {
            self.supported
        }
    }

    fn test_dek() -> DataEncryptionKey {
        let mut bytes = [0u8; 32];
        bytes.copy_from_slice(&0x11u64.to_le_bytes().repeat(4));
        DataEncryptionKey::from_bytes(&mut bytes)
    }

    #[test]
    fn seal_and_release_roundtrip_recovers_the_dek() {
        let signer = DeterministicSigner::new();
        let dek = test_dek();
        let blob = seal_dek_under_hello(&signer, "sentinelpass.vault-abc", "vault-abc", &dek)
            .expect("seal must succeed");

        // The blob carries no recoverable key material without a signature:
        // it must differ from the plaintext DEK and be non-empty JSON.
        let encoded = blob.encode();
        assert!(HelloBoundBlob::decode(&encoded).is_some());
        assert!(!encoded.contains(&hex::encode(dek.as_bytes())));

        let released =
            release_dek_under_hello(&signer, "vault-abc", &blob).expect("release must succeed");
        assert_eq!(released.as_bytes(), dek.as_bytes());
    }

    #[test]
    fn release_with_a_different_vault_ref_fails_closed() {
        let signer = DeterministicSigner::new();
        let dek = test_dek();
        let blob = seal_dek_under_hello(&signer, "sentinelpass.vault-abc", "vault-abc", &dek)
            .expect("seal must succeed");

        // A signature bound for another vault's ref must not unwrap.
        let result = release_dek_under_hello(&signer, "vault-other", &blob);
        assert!(result.is_err(), "cross-vault release must fail");
    }

    #[test]
    fn a_refused_hello_gesture_fails_the_release() {
        let signer = DeterministicSigner::new();
        let dek = test_dek();
        let blob = seal_dek_under_hello(&signer, "sentinelpass.vault-abc", "vault-abc", &dek)
            .expect("seal must succeed");

        let refusing = DeterministicSigner {
            supported: true,
            root: signer.root,
            fail_signs: true,
        };
        assert!(release_dek_under_hello(&refusing, "vault-abc", &blob).is_err());
    }

    #[test]
    fn a_wrong_key_signature_fails_authentication_not_panic() {
        let signer = DeterministicSigner::new();
        let dek = test_dek();
        let blob = seal_dek_under_hello(&signer, "sentinelpass.vault-abc", "vault-abc", &dek)
            .expect("seal must succeed");

        let other_key = DeterministicSigner {
            supported: true,
            root: [0x01u8; 32],
            fail_signs: false,
        };
        assert!(release_dek_under_hello(&other_key, "vault-abc", &blob).is_err());
    }

    #[test]
    fn tampered_blob_bytes_fail_authentication() {
        let signer = DeterministicSigner::new();
        let dek = test_dek();
        let mut blob = seal_dek_under_hello(&signer, "sentinelpass.vault-abc", "vault-abc", &dek)
            .expect("seal must succeed");
        blob.ciphertext[0] ^= 0x01;
        assert!(release_dek_under_hello(&signer, "vault-abc", &blob).is_err());
    }

    #[test]
    fn non_deterministic_platform_refuses_enable() {
        use std::sync::atomic::{AtomicUsize, Ordering};
        struct RandomizingSigner {
            counter: AtomicUsize,
        }
        impl HelloKeySigner for RandomizingSigner {
            fn sign(&self, data: &[u8]) -> Result<Vec<u8>> {
                // Signature drifts per call — PSS-like randomness.
                let n = self.counter.fetch_add(1, Ordering::SeqCst);
                let mut sig = data.to_vec();
                sig[0] ^= n as u8;
                Ok(sig)
            }
            fn is_supported(&self) -> bool {
                true
            }
        }

        let signer = RandomizingSigner {
            counter: AtomicUsize::new(0),
        };
        let dek = test_dek();
        let result = seal_dek_under_hello(&signer, "sentinelpass.vault-abc", "vault-abc", &dek);
        assert!(
            result.is_err(),
            "a platform with randomized signatures must be refused at enable"
        );
    }

    #[test]
    fn unsupported_platform_refuses_enable() {
        let signer = DeterministicSigner {
            supported: false,
            root: [0u8; 32],
            fail_signs: false,
        };
        let dek = test_dek();
        assert!(seal_dek_under_hello(&signer, "k", "vault-abc", &dek).is_err());
    }

    #[test]
    fn decode_rejects_legacy_and_future_blob_versions() {
        // Legacy keyring value (pre-710 plain base64 DEK) decodes to None.
        use base64::Engine;
        let legacy =
            base64::engine::general_purpose::STANDARD.encode(b"0123456789abcdef0123456789abcdef");
        assert!(HelloBoundBlob::decode(&legacy).is_none());

        // A future version is not readable by this code (fail-closed).
        let blob = HelloBoundBlob {
            version: 99,
            key_name: "k".to_string(),
            challenge_hex: hex::encode([0u8; 32]),
            nonce: [0u8; 12],
            ciphertext: vec![],
            auth_tag: [0u8; 16],
        };
        assert!(HelloBoundBlob::decode(&blob.encode()).is_none());
    }

    #[test]
    fn determinism_check_accepts_equal_and_rejects_divergent() {
        assert!(require_deterministic_signature(b"same", b"same").is_ok());
        assert!(require_deterministic_signature(b"a", b"b").is_err());
    }

    #[test]
    fn wrap_key_is_signature_and_ref_bound() {
        let k1 = derive_wrap_key(b"sig", "vault-abc");
        let k2 = derive_wrap_key(b"sig", "vault-abc");
        let k3 = derive_wrap_key(b"different", "vault-abc");
        let k4 = derive_wrap_key(b"sig", "vault-other");
        assert_eq!(k1.as_bytes(), k2.as_bytes());
        assert_ne!(k1.as_bytes(), k3.as_bytes());
        assert_ne!(k1.as_bytes(), k4.as_bytes());
    }
}
