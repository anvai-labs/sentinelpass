//! Sync-related VaultManager methods.

use crate::{
    crypto::{KdfParams, KeyHierarchy, WrappedKey},
    DatabaseError, PasswordManagerError, Result,
};
use chrono::Utc;

use super::VaultManager;

impl VaultManager {
    /// Get sync status from the database.
    pub fn get_sync_status(&self) -> Result<crate::sync::models::SyncStatus> {
        let db = self.lock_db()?;
        let config = crate::sync::config::SyncConfig::load(db.conn())?;
        let pending = crate::sync::change_tracker::count_pending_changes(db.conn())?;

        Ok(crate::sync::models::SyncStatus {
            enabled: config.sync_enabled,
            device_id: config.device_id,
            device_name: config.device_name.clone(),
            relay_url: config.relay_url.clone(),
            last_sync_at: config.last_sync_at,
            pending_changes: pending,
        })
    }

    /// Load the local sync device identity (Ed25519 signing key + metadata) if present.
    pub fn load_sync_device_identity(&self) -> Result<Option<crate::sync::device::DeviceIdentity>> {
        let dek = self.key_hierarchy.dek()?;
        let db = self.lock_db()?;
        crate::sync::device::DeviceIdentity::load_from_db(db.conn(), dek)
    }

    /// Export the encrypted pairing bootstrap payload used to onboard a new sync device.
    pub fn export_pairing_bootstrap(&self) -> Result<crate::sync::models::VaultBootstrap> {
        let db = self.lock_db()?;
        let config = crate::sync::config::SyncConfig::load(db.conn())?;
        let relay_url = config.relay_url.ok_or_else(|| {
            PasswordManagerError::InvalidInput("Sync relay URL not set".to_string())
        })?;
        let vault_id = config.vault_id.ok_or_else(|| {
            PasswordManagerError::InvalidInput("Sync vault ID not set".to_string())
        })?;

        let (kdf_params, wrapped_dek, _key_epoch) = Self::load_vault_metadata(&db)?;
        let kdf_params_blob = bincode::serialize(&kdf_params)
            .map_err(|e| DatabaseError::Serialization(e.to_string()))?;
        let wrapped_dek_blob = bincode::serialize(&wrapped_dek)
            .map_err(|e| DatabaseError::Serialization(e.to_string()))?;

        Ok(crate::sync::models::VaultBootstrap {
            kdf_params_blob,
            wrapped_dek_blob,
            relay_url,
            vault_id,
        })
    }

    /// Import a pairing bootstrap into an empty local vault and switch this instance to the
    /// remote vault's KDF parameters and wrapped DEK.
    ///
    /// The local vault must be unlocked and contain no entries/SSH keys/TOTP secrets.
    pub fn import_pairing_bootstrap(
        &mut self,
        master_password: &[u8],
        bootstrap: &crate::sync::models::VaultBootstrap,
    ) -> Result<()> {
        if !self.is_unlocked() {
            return Err(PasswordManagerError::VaultLocked);
        }

        let imported_kdf: KdfParams = bincode::deserialize(&bootstrap.kdf_params_blob)
            .map_err(|e| DatabaseError::Serialization(e.to_string()))?;
        let imported_wrapped: WrappedKey = bincode::deserialize(&bootstrap.wrapped_dek_blob)
            .map_err(|e| DatabaseError::Serialization(e.to_string()))?;

        let mut imported_hierarchy = KeyHierarchy::new();
        imported_hierarchy.unlock_vault(master_password, &imported_kdf, &imported_wrapped)?;

        let db = self.lock_db()?;
        let conn = db.conn();

        let entry_count: i64 = conn
            .query_row("SELECT COUNT(*) FROM entries", [], |row| row.get(0))
            .map_err(DatabaseError::Sqlite)?;
        let ssh_key_count: i64 = conn
            .query_row("SELECT COUNT(*) FROM ssh_keys", [], |row| row.get(0))
            .map_err(DatabaseError::Sqlite)?;
        let totp_count: i64 = conn
            .query_row("SELECT COUNT(*) FROM totp_secrets", [], |row| row.get(0))
            .map_err(DatabaseError::Sqlite)?;

        if entry_count > 0 || ssh_key_count > 0 || totp_count > 0 {
            return Err(PasswordManagerError::InvalidInput(
                "Pair-join target vault must be empty".to_string(),
            ));
        }

        let nonce_blob = bincode::serialize(&imported_wrapped.nonce)
            .map_err(|e| DatabaseError::Serialization(e.to_string()))?;
        let rows = conn
            .execute(
                "UPDATE db_metadata
                 SET kdf_params = ?1, wrapped_dek = ?2, dek_nonce = ?3
                 WHERE id = 1",
                rusqlite::params![
                    &bootstrap.kdf_params_blob,
                    &bootstrap.wrapped_dek_blob,
                    &nonce_blob
                ],
            )
            .map_err(DatabaseError::Sqlite)?;
        if rows == 0 {
            return Err(PasswordManagerError::NotFound("Vault metadata".to_string()));
        }

        conn.execute("DELETE FROM sync_devices", [])
            .map_err(DatabaseError::Sqlite)?;
        conn.execute("DELETE FROM sync_tombstones", [])
            .map_err(DatabaseError::Sqlite)?;

        drop(db);

        self.key_hierarchy = imported_hierarchy;
        Ok(())
    }

    /// Configure sync for this vault, saving the device identity.
    pub fn init_sync(
        &self,
        relay_url: &str,
        device_name: &str,
        vault_id: uuid::Uuid,
        identity: &crate::sync::device::DeviceIdentity,
    ) -> Result<()> {
        let db = self.lock_db()?;
        let config = crate::sync::config::SyncConfig {
            sync_enabled: true,
            vault_id: Some(vault_id),
            device_id: Some(identity.device_id),
            device_name: Some(device_name.to_string()),
            relay_url: Some(relay_url.to_string()),
            last_push_sequence: 0,
            last_pull_sequence: 0,
            last_sync_at: None,
        };
        config.save(db.conn())?;
        let dek = self.key_hierarchy.dek()?;
        identity.save_to_db(db.conn(), dek)?;
        Ok(())
    }

    /// Disable sync (preserves identity but sets enabled = false).
    pub fn disable_sync(&self) -> Result<()> {
        let db = self.lock_db()?;
        let mut config = crate::sync::config::SyncConfig::load(db.conn())?;
        config.sync_enabled = false;
        config.save(db.conn())?;
        Ok(())
    }

    /// Run a full sync cycle against the configured relay (push pending changes, pull remote changes).
    #[cfg(feature = "sync")]
    pub async fn sync_now(&self) -> Result<crate::sync::models::SyncStatus> {
        if !self.is_unlocked() {
            return Err(PasswordManagerError::VaultLocked);
        }

        let dek = self.key_hierarchy.dek()?.clone();
        let identity = self.load_sync_device_identity()?.ok_or_else(|| {
            PasswordManagerError::InvalidInput("Sync device identity missing".to_string())
        })?;

        let (relay_url, vault_id) = {
            let db = self
                .db
                .lock()
                .map_err(|e| DatabaseError::LockPoisoned(e.to_string()))?;
            let config = crate::sync::config::SyncConfig::load(db.conn())?;
            if !config.sync_enabled {
                return Err(PasswordManagerError::InvalidInput(
                    "Sync is not enabled".to_string(),
                ));
            }

            let relay_url = config.relay_url.ok_or_else(|| {
                PasswordManagerError::InvalidInput("Sync relay URL missing".to_string())
            })?;
            let vault_id = config.vault_id.ok_or_else(|| {
                PasswordManagerError::InvalidInput("Sync vault ID missing".to_string())
            })?;
            (relay_url, vault_id)
        };

        {
            let preflight = crate::sync::client::SyncClient::new(
                &relay_url,
                identity.device_id,
                identity.signing_key.clone(),
            )?;

            if let Err(err) = preflight.list_devices().await {
                if is_unknown_device_relay_error(&err) {
                    preflight
                        .register_device(
                            &identity.device_name,
                            crate::sync::device::DeviceIdentity::current_device_type(),
                            &identity.public_key_bytes(),
                            &vault_id,
                        )
                        .await?;
                } else {
                    return Err(err);
                }
            }
        }

        let client = crate::sync::client::SyncClient::new(
            &relay_url,
            identity.device_id,
            identity.signing_key,
        )?;
        let engine =
            crate::sync::engine::SyncEngine::new(client, self.db.clone(), identity.device_id);
        engine.sync(&dek).await
    }

    /// List sync devices from local cache.
    pub fn list_sync_devices(&self) -> Result<Vec<crate::sync::models::SyncDeviceInfo>> {
        let db = self.lock_db()?;
        let mut stmt = db.conn().prepare(
            "SELECT device_id, device_name, device_type, public_key, registered_at, last_sync, revoked, revoked_at
             FROM sync_devices ORDER BY registered_at"
        ).map_err(DatabaseError::Sqlite)?;

        let devices = stmt
            .query_map([], |row: &rusqlite::Row<'_>| {
                let device_id_str: String = row.get(0)?;
                Ok(crate::sync::models::SyncDeviceInfo {
                    device_id: uuid::Uuid::parse_str(&device_id_str).unwrap_or_default(),
                    device_name: row.get(1)?,
                    device_type: row.get(2)?,
                    public_key: row.get::<_, Option<Vec<u8>>>(3)?.unwrap_or_default(),
                    registered_at: row.get(4)?,
                    last_sync: row.get(5)?,
                    revoked: row.get(6)?,
                    revoked_at: row.get(7)?,
                })
            })
            .map_err(DatabaseError::Sqlite)?
            .collect::<std::result::Result<Vec<_>, _>>()
            .map_err(DatabaseError::Sqlite)?;

        Ok(devices)
    }

    /// Revoke a sync device locally.
    pub fn revoke_sync_device(&self, device_id: &str) -> Result<()> {
        let db = self.lock_db()?;
        let now = Utc::now().timestamp();
        db.conn()
            .execute(
                "UPDATE sync_devices SET revoked = 1, revoked_at = ?1 WHERE device_id = ?2",
                rusqlite::params![now, device_id],
            )
            .map_err(DatabaseError::Sqlite)?;
        Ok(())
    }
}

#[cfg(feature = "sync")]
fn is_unknown_device_relay_error(err: &PasswordManagerError) -> bool {
    match err {
        PasswordManagerError::InvalidInput(msg) => {
            msg.contains("Unknown device") || msg.contains("Relay error 401")
        }
        _ => false,
    }
}
