//! Ed25519 device identity: keypair generation, storage, loading.

use crate::crypto::cipher::DataEncryptionKey;
use crate::sync::crypto::{decrypt_from_sync, encrypt_for_sync};
use crate::{DatabaseError, PasswordManagerError, Result};
use ed25519_dalek::{SigningKey, VerifyingKey};
use rand::RngCore;
use uuid::Uuid;

/// A device identity: Ed25519 keypair + device metadata.
pub struct DeviceIdentity {
    pub device_id: Uuid,
    pub device_name: String,
    pub signing_key: SigningKey,
}

impl DeviceIdentity {
    /// Generate a new device identity with a fresh Ed25519 keypair.
    pub fn generate(device_name: &str) -> Self {
        let mut secret = [0u8; 32];
        rand::thread_rng().fill_bytes(&mut secret);
        let signing_key = SigningKey::from_bytes(&secret);
        Self {
            device_id: Uuid::new_v4(),
            device_name: device_name.to_string(),
            signing_key,
        }
    }

    /// Get the public (verifying) key.
    pub fn verifying_key(&self) -> VerifyingKey {
        self.signing_key.verifying_key()
    }

    /// Get the public key bytes (32 bytes).
    pub fn public_key_bytes(&self) -> Vec<u8> {
        self.verifying_key().to_bytes().to_vec()
    }

    /// Encrypt the signing key with the DEK and store in the database.
    pub fn save_to_db(&self, conn: &rusqlite::Connection, dek: &DataEncryptionKey) -> Result<()> {
        let signing_key_bytes = self.signing_key.to_bytes();
        let encrypted =
            encrypt_for_sync(dek, &signing_key_bytes).map_err(PasswordManagerError::Crypto)?;

        // Store in sync_metadata (the signing key fields)
        conn.execute(
            "UPDATE sync_metadata SET
                device_signing_key_encrypted = ?1,
                device_id = ?2,
                device_name = ?3
             WHERE id = 1",
            rusqlite::params![encrypted, self.device_id.to_string(), self.device_name,],
        )
        .map_err(DatabaseError::Sqlite)?;

        Ok(())
    }

    /// Load device identity from the database.
    pub fn load_from_db(
        conn: &rusqlite::Connection,
        dek: &DataEncryptionKey,
    ) -> Result<Option<Self>> {
        let result = conn.query_row(
            "SELECT device_id, device_name, device_signing_key_encrypted
             FROM sync_metadata WHERE id = 1",
            [],
            |row| {
                let device_id_str: Option<String> = row.get(0)?;
                let device_name: Option<String> = row.get(1)?;
                let encrypted: Option<Vec<u8>> = row.get(2)?;
                Ok((device_id_str, device_name, encrypted))
            },
        );

        match result {
            Ok((Some(device_id_str), Some(device_name), Some(encrypted))) => {
                let device_id = Uuid::parse_str(&device_id_str).map_err(|e| {
                    PasswordManagerError::InvalidInput(format!("Invalid device_id: {}", e))
                })?;

                let signing_key_bytes =
                    decrypt_from_sync(dek, &encrypted).map_err(PasswordManagerError::Crypto)?;

                if signing_key_bytes.len() != 32 {
                    return Err(PasswordManagerError::InvalidInput(
                        "Invalid signing key length".to_string(),
                    ));
                }

                let key_array: [u8; 32] = signing_key_bytes.try_into().map_err(|_| {
                    PasswordManagerError::InvalidInput("Invalid signing key".to_string())
                })?;

                let signing_key = SigningKey::from_bytes(&key_array);

                Ok(Some(Self {
                    device_id,
                    device_name,
                    signing_key,
                }))
            }
            Ok(_) => Ok(None),
            Err(rusqlite::Error::QueryReturnedNoRows) => Ok(None),
            Err(e) => Err(DatabaseError::Sqlite(e).into()),
        }
    }

    /// Get the device type string for the current platform.
    pub fn current_device_type() -> &'static str {
        #[cfg(target_os = "windows")]
        return "windows";
        #[cfg(target_os = "macos")]
        return "macos";
        #[cfg(target_os = "linux")]
        return "linux";
        #[cfg(not(any(target_os = "windows", target_os = "macos", target_os = "linux")))]
        return "unknown";
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn generate_device_identity() {
        let identity = DeviceIdentity::generate("Test Device");
        assert_eq!(identity.device_name, "Test Device");
        assert_eq!(identity.public_key_bytes().len(), 32);
    }

    #[test]
    fn signing_key_roundtrip() {
        let identity = DeviceIdentity::generate("Test");
        let original_public = identity.public_key_bytes();

        // Simulate save/load by encrypting/decrypting the key
        let dek = DataEncryptionKey::new().unwrap();
        let signing_bytes = identity.signing_key.to_bytes();
        let encrypted = encrypt_for_sync(&dek, &signing_bytes).unwrap();
        let decrypted = decrypt_from_sync(&dek, &encrypted).unwrap();

        let restored_key =
            SigningKey::from_bytes(&<[u8; 32]>::try_from(decrypted.as_slice()).unwrap());
        let restored_public = restored_key.verifying_key().to_bytes().to_vec();

        assert_eq!(original_public, restored_public);
    }

    #[test]
    fn different_identities_have_different_keys() {
        let id1 = DeviceIdentity::generate("Device A");
        let id2 = DeviceIdentity::generate("Device B");

        // Different device IDs
        assert_ne!(id1.device_id, id2.device_id);
        // Different signing keys
        assert_ne!(id1.public_key_bytes(), id2.public_key_bytes());
    }

    #[test]
    fn signing_key_wrong_dek_fails() {
        let identity = DeviceIdentity::generate("Test");
        let dek1 = DataEncryptionKey::new().unwrap();
        let dek2 = DataEncryptionKey::new().unwrap();

        // Encrypt with dek1
        let signing_bytes = identity.signing_key.to_bytes();
        let encrypted = encrypt_for_sync(&dek1, &signing_bytes).unwrap();

        // Decrypt with wrong DEK should fail
        assert!(decrypt_from_sync(&dek2, &encrypted).is_err());
    }

    #[test]
    fn save_and_load_roundtrip() {
        use crate::database::Database;
        use crate::sync::config::SyncConfig;

        let db = Database::in_memory().unwrap();
        db.initialize_schema().unwrap();
        let conn = db.conn();

        // Ensure sync_metadata row exists
        let config = SyncConfig::default();
        config.save(conn).unwrap();

        let dek = DataEncryptionKey::new().unwrap();
        let identity = DeviceIdentity::generate("Test Laptop");

        identity.save_to_db(conn, &dek).unwrap();

        let loaded = DeviceIdentity::load_from_db(conn, &dek).unwrap().unwrap();
        assert_eq!(loaded.device_id, identity.device_id);
        assert_eq!(loaded.device_name, "Test Laptop");
        assert_eq!(loaded.public_key_bytes(), identity.public_key_bytes());
    }

    #[test]
    fn load_from_empty_db_returns_none() {
        use crate::database::Database;

        let db = Database::in_memory().unwrap();
        db.initialize_schema().unwrap();

        let dek = DataEncryptionKey::new().unwrap();
        let loaded = DeviceIdentity::load_from_db(db.conn(), &dek).unwrap();
        assert!(loaded.is_none());
    }

    #[test]
    fn current_device_type_is_known() {
        let device_type = DeviceIdentity::current_device_type();
        assert!(
            ["macos", "linux", "windows"].contains(&device_type),
            "Unexpected device type: {}",
            device_type
        );
    }

    #[test]
    fn verifying_key_matches_public_key_bytes() {
        let identity = DeviceIdentity::generate("Key Test");
        let vk = identity.verifying_key();
        assert_eq!(vk.to_bytes().to_vec(), identity.public_key_bytes());
    }
}
