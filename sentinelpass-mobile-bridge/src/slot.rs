// Platform-slot DEK wrap for mobile (WBS-812 Android Keystore, WBS-821 iOS
// Keychain SecAccessControl) — ADR-009 rev 2.
//
// Property (identical to the Windows Hello design this generalizes,
// `sentinelpass-core/src/biometric_hello.rs`): the at-rest blob carries NO
// usable secret. The DEK is sealed under a wrap key derived as
// `HKDF-SHA256(salt = MOBILE_SLOT_WRAP_SALT, ikm = signature, info = vault
// binding)`, where `signature` comes from an AUTH-BOUND platform key:
// - Android: RSA-2048 in AndroidKeyStore, `SHA256withRSA/PKCS1`
//   (deterministic — required, enable refuses randomized signatures),
//   `setUserAuthenticationRequired(true)` +
//   `setInvalidatedByBiometricEnrollment(true)`, signed through
//   `BiometricPrompt.CryptoObject` so the prompt IS the crypto
//   authorization (a UI prompt alone authorizes nothing — ADR-009).
// - iOS (WBS-821, different mechanism by platform capability): the DEK
//   itself lives in the Keychain under
//   `kSecAttrAccessibleWhenPasscodeSetThisDeviceOnly` +
//   `kSecAccessControlBiometryCurrentSet` — the OS refuses the ITEM READ
//   without the gesture (the biometric.rs mod-macos pattern); Swift then
//   hands the released DEK to sp_slot_open_with_dek. iOS has no
//   deterministic signing primitive in secure hardware, so the
//   signature-KDF path above is Android-only by design.
//
// The platform cannot be invoked from Rust (no upward calls across FFI), so
// the orchestration is SPLIT instead of callback-driven: the host draws a
// challenge (`bridge_slot_challenge`), signs it under its gate, and hands
// the challenge + signatures back (`bridge_slot_seal` / `bridge_slot_unlock`).
// Every step still fails closed: the seal re-verifies determinism AND binds
// the round-trip to the exact challenge bytes via [`CapturedSigner`]; the
// release authenticates through the GCM tag, so a refused gesture (no
// signature), a stale key (signature drifts after biometric re-enrollment →
// invalidated key), a wrong vault binding, or tampered blob bytes all leave
// the DEK unrecoverable.

use crate::bridge::{get_registry, VaultHandle};
use crate::error::{BridgeError, BridgeResult};
use sentinelpass_core::biometric_hello::{
    release_dek_from_signature, seal_dek_with_challenge, HelloBoundBlob, HelloKeySigner,
    MOBILE_SLOT_WRAP_SALT,
};
use sentinelpass_core::vault::VaultManager;

/// Keystore alias (Android) / Keychain label (iOS) for the per-vault
/// auth-bound signing key. ONE vault per device (ADR-009), so a single
/// fixed alias is sufficient and avoids alias enumeration in the blob.
pub const SLOT_KEY_ALIAS: &str = "com.sentinelpass.vault-slot";

/// Draw a fresh 32-byte challenge (hex) for the host platform to sign.
pub fn bridge_slot_challenge() -> BridgeResult<String> {
    Ok(hex::encode(
        sentinelpass_core::biometric_hello::fresh_challenge(),
    ))
}

/// A signer that "signs" only the exact challenge the host attested: the
/// seal's internal round-trip signs the STORED challenge from the blob, so a
/// blob whose challenge differs from the attested one fails the enable
/// instead of producing an unusable slot.
struct CapturedSigner {
    challenge: Vec<u8>,
    signature: Vec<u8>,
}

impl HelloKeySigner for CapturedSigner {
    fn sign(&self, data: &[u8]) -> sentinelpass_core::Result<Vec<u8>> {
        if data == self.challenge {
            Ok(self.signature.clone())
        } else {
            Err(sentinelpass_core::PasswordManagerError::from(
                sentinelpass_core::DatabaseError::Keyring(
                    "slot round-trip signed a mismatched challenge".to_string(),
                ),
            ))
        }
    }

    fn is_supported(&self) -> bool {
        true
    }
}

fn decode_hex_32(input: &str, what: &str) -> BridgeResult<Vec<u8>> {
    let raw = hex::decode(input)
        .map_err(|_| BridgeError::InvalidParam(format!("{what} is not valid hex")))?;
    if raw.len() != 32 {
        return Err(BridgeError::InvalidParam(format!(
            "{what} must be 32 bytes, got {}",
            raw.len()
        )));
    }
    Ok(raw)
}

/// Seal the vault's DEK under the platform signature (ENABLE).
///
/// `challenge_hex` is the challenge the host signed; `sig_a_hex`/`sig_b_hex`
/// are TWO signatures over it from the auth-bound key — they must be
/// byte-identical (deterministic scheme check, exactly like Windows Hello).
/// `binding` is the caller-stable vault identity (the canonical vault file
/// path) and must be presented unchanged at release. Returns the NON-SECRET
/// blob JSON for at-rest storage (app-private file storage — never
/// SharedPreferences; hard rule: no secrets in prefs, and this blob is
/// non-secret anyway).
pub fn bridge_slot_seal(
    handle: VaultHandle,
    challenge_hex: &str,
    sig_a_hex: &str,
    sig_b_hex: &str,
    binding: &str,
) -> BridgeResult<String> {
    let challenge = decode_hex_32(challenge_hex, "challenge")?;
    let sig_a = decode_hex_32(sig_a_hex, "sig_a")?;
    let sig_b = decode_hex_32(sig_b_hex, "sig_b")?;

    // Deterministic-scheme check on the host-supplied pair. Inside the seal
    // the CapturedSigner replays sig_a, so this is the only place a
    // randomized platform is refused — refuse LOUDLY.
    if sig_a != sig_b {
        return Err(BridgeError::Biometric(
            "platform key produced non-deterministic signatures; \
             auth-bound slot storage is unavailable on this platform"
                .into(),
        ));
    }
    if binding.is_empty() {
        return Err(BridgeError::InvalidParam("binding cannot be empty".into()));
    }

    let registry = get_registry()
        .lock()
        .map_err(|_| BridgeError::Unknown("Failed to acquire vault registry lock".into()))?;
    let vault_arc = registry
        .get_vault(handle)
        .ok_or_else(|| BridgeError::InvalidParam(format!("Invalid vault handle: {handle}")))?;
    let vault = vault_arc
        .lock()
        .map_err(|_| BridgeError::Unknown("Failed to acquire vault lock".into()))?;

    // Requires an UNLOCKED vault (locked vaults hold no DEK).
    let dek = vault.current_dek()?;

    let signer = CapturedSigner {
        challenge: challenge.clone(),
        signature: sig_a,
    };
    let challenge_bytes: [u8; 32] = challenge.try_into().expect("checked 32 bytes above");
    let blob = seal_dek_with_challenge(
        MOBILE_SLOT_WRAP_SALT,
        &signer,
        SLOT_KEY_ALIAS,
        binding,
        &dek,
        &challenge_bytes,
    )?;
    Ok(blob.encode())
}

/// Release the DEK from the blob with a fresh platform signature over the
/// blob's challenge and OPEN the vault (UNLOCK). Fails closed on any
/// mismatch; the user falls back to the master password.
///
/// Returns a new vault handle. The blob JSON is the NON-SECRET at-rest blob
/// as returned by [`bridge_slot_seal`]; `binding` must be the identical
/// vault identity used at seal time.
pub fn bridge_slot_unlock(
    vault_path: &str,
    blob_json: &str,
    sig_hex: &str,
    binding: &str,
) -> BridgeResult<VaultHandle> {
    if vault_path.is_empty() {
        return Err(BridgeError::InvalidParam(
            "vault_path cannot be empty".into(),
        ));
    }
    if binding.is_empty() {
        return Err(BridgeError::InvalidParam("binding cannot be empty".into()));
    }

    let blob = HelloBoundBlob::decode(blob_json)
        .ok_or_else(|| BridgeError::InvalidParam("slot blob is not a recognized v1 blob".into()))?;
    let sig_raw = hex::decode(sig_hex)
        .map_err(|_| BridgeError::InvalidParam("signature is not valid hex".to_string()))?;

    let dek = release_dek_from_signature(MOBILE_SLOT_WRAP_SALT, &sig_raw, binding, &blob)?;

    let vault = VaultManager::open_with_released_dek(vault_path, dek, "platform slot")
        .map_err(BridgeError::from)?;

    let mut registry = get_registry()
        .lock()
        .map_err(|_| BridgeError::Unknown("Failed to acquire vault registry lock".into()))?;
    let handle = registry.register_vault(vault);
    Ok(handle)
}

/// Whether a slot blob is well-formed (host-side preflight before offering
/// biometric unlock). No key material involved.
pub fn bridge_slot_has_blob(blob_json: &str) -> bool {
    HelloBoundBlob::decode(blob_json).is_some()
}

/// iOS KEYCHAIN pattern (WBS-821, mirroring core's `biometric.rs mod macos`):
/// the DEK itself lives in the Keychain under
/// `kSecAccessControlBiometryCurrentSet` — the OS refuses the item read
/// without the biometric gesture, which IS the crypto authorization. Swift
/// performs the gated read and hands the released DEK here to open the
/// vault. The DEK bytes are borrowed (FFI rule 1: never retained; the caller
/// zeroizes its copy).
pub fn bridge_slot_open_with_dek(
    vault_path: &str,
    dek_bytes: &[u8],
    source: &str,
) -> BridgeResult<VaultHandle> {
    if vault_path.is_empty() {
        return Err(BridgeError::InvalidParam(
            "vault_path cannot be empty".into(),
        ));
    }
    if dek_bytes.len() != 32 {
        return Err(BridgeError::InvalidParam(format!(
            "DEK must be 32 bytes, got {}",
            dek_bytes.len()
        )));
    }

    let mut key = [0u8; 32];
    key.copy_from_slice(dek_bytes);
    let dek = sentinelpass_core::crypto::DataEncryptionKey::from_bytes(&mut key);

    let vault =
        VaultManager::open_with_released_dek(vault_path, dek, source).map_err(BridgeError::from)?;

    let mut registry = get_registry()
        .lock()
        .map_err(|_| BridgeError::Unknown("Failed to acquire vault registry lock".into()))?;
    let handle = registry.register_vault(vault);
    Ok(handle)
}

#[cfg(test)]
mod tests {
    use super::*;
    use hmac::{Hmac, Mac};
    use sha2::Sha256;
    use std::path::PathBuf;
    use std::sync::atomic::{AtomicU32, Ordering};

    static SEQ: AtomicU32 = AtomicU32::new(0);

    /// The fake "platform": deterministic signatures over the challenge
    /// (what RSA-PKCS1 in a real Keystore/Secure Enclave promises).
    struct FakePlatform {
        root: [u8; 32],
    }

    impl FakePlatform {
        fn sign(&self, data: &[u8]) -> Vec<u8> {
            let mut mac = Hmac::<Sha256>::new_from_slice(&self.root).unwrap();
            mac.update(data);
            mac.finalize().into_bytes().to_vec()
        }

        fn sign_twice(&self, data: &[u8]) -> (Vec<u8>, Vec<u8>) {
            (self.sign(data), self.sign(data))
        }
    }

    fn temp_vault_path() -> PathBuf {
        let dir = std::env::temp_dir().join(format!(
            "sp_slot_test_{}_{}",
            std::process::id(),
            SEQ.fetch_add(1, Ordering::SeqCst)
        ));
        std::fs::create_dir_all(&dir).expect("temp dir");
        dir.join("vault.db")
    }

    fn hex(bytes: &[u8]) -> String {
        hex::encode(bytes)
    }

    #[test]
    fn challenge_is_32_random_bytes() {
        let c1 = bridge_slot_challenge().unwrap();
        let c2 = bridge_slot_challenge().unwrap();
        assert_ne!(c1, c2, "challenges must not repeat");
        assert_eq!(decode_hex_32(&c1, "c").unwrap().len(), 32);
    }

    #[test]
    fn seal_then_unlock_round_trips_a_real_vault() {
        let platform = FakePlatform { root: [0x42u8; 32] };
        let path = temp_vault_path();
        let binding = path.to_str().unwrap().to_string();

        // Create the vault through the normal bridge path.
        let mut registry = get_registry().lock().unwrap();
        let vault =
            sentinelpass_core::vault::VaultManager::create(&path, b"master-password").unwrap();
        let handle = registry.register_vault(vault);
        drop(registry);

        // Enable: challenge -> sign twice -> seal.
        let challenge = bridge_slot_challenge().unwrap();
        let (sig_a, sig_b) = platform.sign_twice(&decode_hex_32(&challenge, "c").unwrap());
        let blob = bridge_slot_seal(handle, &challenge, &hex(&sig_a), &hex(&sig_b), &binding)
            .expect("seal must succeed");
        assert!(bridge_slot_has_blob(&blob));
        assert!(!blob.contains("master-password"));

        // The blob must not carry the DEK or the signature verbatim.
        assert!(!blob.contains(&hex(&sig_a)));

        // Tear the password-open handle down, then unlock from the slot:
        // the platform signs the blob's challenge under its auth gate.
        assert!(crate::bridge::bridge_vault_destroy(handle).is_ok());
        let unlock_sig = platform.sign(&decode_hex_32(&challenge, "challenge").unwrap());
        let unlocked = bridge_slot_unlock(&binding, &blob, &hex(&unlock_sig), &binding)
            .expect("slot unlock must succeed");

        // The unlocked vault works.
        assert!(
            crate::bridge::bridge_vault_is_unlocked(unlocked).unwrap_or(false),
            "slot-unlocked vault must be unlocked"
        );
        crate::bridge::bridge_vault_destroy(unlocked).unwrap();
        let _ = std::fs::remove_dir_all(path.parent().unwrap());
    }

    #[test]
    fn randomized_signature_platform_is_refused_at_seal() {
        let path = temp_vault_path();
        let mut registry = get_registry().lock().unwrap();
        let vault =
            sentinelpass_core::vault::VaultManager::create(&path, b"master-password").unwrap();
        let handle = registry.register_vault(vault);
        drop(registry);

        let challenge = bridge_slot_challenge().unwrap();
        let raw = decode_hex_32(&challenge, "c").unwrap();
        let mut sig_a = raw.clone();
        let mut sig_b = raw.clone();
        sig_a[0] ^= 0x01; // drifts per call, ECDSA-style
        sig_b[0] ^= 0x02;
        assert!(bridge_slot_seal(handle, &challenge, &hex(&sig_a), &hex(&sig_b), "b").is_err());

        crate::bridge::bridge_vault_destroy(handle).unwrap();
        let _ = std::fs::remove_dir_all(path.parent().unwrap());
    }

    #[test]
    fn wrong_signature_fails_the_unlock() {
        let platform = FakePlatform { root: [0x42u8; 32] };
        let wrong = FakePlatform { root: [0x99u8; 32] };
        let path = temp_vault_path();
        let binding = path.to_str().unwrap().to_string();

        let mut registry = get_registry().lock().unwrap();
        let vault =
            sentinelpass_core::vault::VaultManager::create(&path, b"master-password").unwrap();
        let handle = registry.register_vault(vault);
        drop(registry);

        let challenge = bridge_slot_challenge().unwrap();
        let (sig_a, sig_b) = platform.sign_twice(&decode_hex_32(&challenge, "c").unwrap());
        let blob =
            bridge_slot_seal(handle, &challenge, &hex(&sig_a), &hex(&sig_b), &binding).unwrap();
        crate::bridge::bridge_vault_destroy(handle).unwrap();

        let wrong_challenge = bridge_slot_challenge().unwrap();
        assert!(bridge_slot_unlock(
            &binding,
            &blob,
            &hex(&wrong.sign(&decode_hex_32(&wrong_challenge, "c").unwrap())),
            &binding
        )
        .is_err());

        let _ = std::fs::remove_dir_all(path.parent().unwrap());
    }

    #[test]
    fn binding_mismatch_fails_the_unlock() {
        let platform = FakePlatform { root: [0x42u8; 32] };
        let path = temp_vault_path();
        let binding = path.to_str().unwrap().to_string();

        let mut registry = get_registry().lock().unwrap();
        let vault =
            sentinelpass_core::vault::VaultManager::create(&path, b"master-password").unwrap();
        let handle = registry.register_vault(vault);
        drop(registry);

        let challenge = bridge_slot_challenge().unwrap();
        let (sig_a, sig_b) = platform.sign_twice(&decode_hex_32(&challenge, "c").unwrap());
        let blob =
            bridge_slot_seal(handle, &challenge, &hex(&sig_a), &hex(&sig_b), &binding).unwrap();
        crate::bridge::bridge_vault_destroy(handle).unwrap();

        let sig = platform.sign(&decode_hex_32(&challenge, "c").unwrap());
        assert!(bridge_slot_unlock(&binding, &blob, &hex(&sig), "/other/vault/path").is_err());

        let _ = std::fs::remove_dir_all(path.parent().unwrap());
    }

    #[test]
    fn tampered_blob_fails_the_unlock() {
        let platform = FakePlatform { root: [0x42u8; 32] };
        let path = temp_vault_path();
        let binding = path.to_str().unwrap().to_string();

        let mut registry = get_registry().lock().unwrap();
        let vault =
            sentinelpass_core::vault::VaultManager::create(&path, b"master-password").unwrap();
        let handle = registry.register_vault(vault);
        drop(registry);

        let challenge = bridge_slot_challenge().unwrap();
        let (sig_a, sig_b) = platform.sign_twice(&decode_hex_32(&challenge, "c").unwrap());
        let mut blob =
            bridge_slot_seal(handle, &challenge, &hex(&sig_a), &hex(&sig_b), &binding).unwrap();
        crate::bridge::bridge_vault_destroy(handle).unwrap();

        // Flip one hex char inside the ciphertext region.
        let mid = blob.len() / 2;
        let c = blob.as_bytes()[mid];
        let flipped = if c == b'0' { b'1' } else { b'0' };
        blob.replace_range(mid..mid + 1, &(flipped as char).to_string());

        let sig = platform.sign(&decode_hex_32(&challenge, "c").unwrap());
        assert!(bridge_slot_unlock(&binding, &blob, &hex(&sig), &binding).is_err());

        let _ = std::fs::remove_dir_all(path.parent().unwrap());
    }

    #[test]
    fn seal_requires_an_unlocked_vault() {
        let platform = FakePlatform { root: [0x42u8; 32] };
        let path = temp_vault_path();
        let binding = path.to_str().unwrap().to_string();

        let mut registry = get_registry().lock().unwrap();
        let vault =
            sentinelpass_core::vault::VaultManager::create(&path, b"master-password").unwrap();
        let handle = registry.register_vault(vault);
        drop(registry);

        crate::bridge::bridge_vault_lock(handle).unwrap();
        let challenge = bridge_slot_challenge().unwrap();
        let raw = decode_hex_32(&challenge, "c").unwrap();
        let (sig_a, sig_b) = platform.sign_twice(&raw);
        assert!(
            bridge_slot_seal(handle, &challenge, &hex(&sig_a), &hex(&sig_b), &binding).is_err()
        );

        crate::bridge::bridge_vault_destroy(handle).unwrap();
        let _ = std::fs::remove_dir_all(path.parent().unwrap());
    }
}
