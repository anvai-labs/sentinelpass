//! SSH key management operations for VaultManager

use super::{PaginatedResult, PaginationParams, VaultManager};
use crate::{DatabaseError, PasswordManagerError, Result};
use chrono::{DateTime, Utc};

impl VaultManager {
    /// Add an SSH key to the vault from plaintext key material.
    #[allow(clippy::too_many_arguments)]
    pub fn add_ssh_key_plaintext(
        &self,
        name: String,
        comment: Option<String>,
        key_type: crate::ssh::SshKeyType,
        key_size: Option<u32>,
        public_key: String,
        private_key: String,
        fingerprint: String,
    ) -> Result<i64> {
        if !self.is_unlocked() {
            return Err(PasswordManagerError::VaultLocked);
        }

        let dek = self.key_hierarchy.dek()?;
        let ssh_key = crate::ssh::SshKey::create_encrypted(
            dek,
            name,
            comment,
            key_type,
            key_size,
            public_key,
            private_key,
            fingerprint,
        )?;

        self.add_ssh_key(&ssh_key)
    }

    /// Add an SSH key to the vault
    pub fn add_ssh_key(&self, key: &crate::ssh::SshKey) -> Result<i64> {
        if !self.is_unlocked() {
            return Err(PasswordManagerError::VaultLocked);
        }

        let _dek = self.key_hierarchy.dek()?;
        let db = self.lock_db()?;

        let now = Utc::now().timestamp();

        db.conn()
            .execute(
                "INSERT INTO ssh_keys (
                name, comment, key_type, key_size, public_key,
                private_key_encrypted, nonce, auth_tag, fingerprint,
                created_at, modified_at
            ) VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9, ?10, ?11)",
                (
                    &key.name,
                    key.comment.as_deref(),
                    key.key_type.to_string(),
                    key.key_size,
                    &key.public_key,
                    &key.private_key_encrypted,
                    &key.nonce,
                    &key.auth_tag,
                    &key.fingerprint,
                    now,
                    now,
                ),
            )
            .map_err(|e| PasswordManagerError::from(DatabaseError::Sqlite(e)))?;

        Ok(db.conn().last_insert_rowid())
    }

    /// Get an SSH key by ID
    pub fn get_ssh_key(&self, key_id: i64) -> Result<crate::ssh::SshKey> {
        if !self.is_unlocked() {
            return Err(PasswordManagerError::VaultLocked);
        }

        let db = self.lock_db()?;

        let mut stmt = db
            .conn()
            .prepare(
                "SELECT name, comment, key_type, key_size, public_key, private_key_encrypted,
                     nonce, auth_tag, fingerprint, created_at, modified_at
             FROM ssh_keys WHERE key_id = ?1",
            )
            .map_err(|e| PasswordManagerError::from(DatabaseError::Sqlite(e)))?;

        let result = stmt.query_row([key_id], |row| {
            let name: String = row.get(0)?;
            let comment: Option<String> = row.get(1)?;
            let key_type_str: String = row.get(2)?;
            let key_size: Option<u32> = row.get(3)?;
            let public_key: String = row.get(4)?;
            let private_key_encrypted: Vec<u8> = row.get(5)?;
            let nonce: Vec<u8> = row.get(6)?;
            let auth_tag: Vec<u8> = row.get(7)?;
            let fingerprint: String = row.get(8)?;
            let created_at: i64 = row.get(9)?;
            let modified_at: i64 = row.get(10)?;

            Ok((
                name,
                comment,
                key_type_str,
                key_size,
                public_key,
                private_key_encrypted,
                nonce,
                auth_tag,
                fingerprint,
                created_at,
                modified_at,
            ))
        });

        match result {
            Ok((
                name,
                comment,
                key_type_str,
                key_size,
                public_key,
                private_key_encrypted,
                nonce,
                auth_tag,
                fingerprint,
                created_at,
                modified_at,
            )) => {
                let key_type = match key_type_str.as_str() {
                    "RSA" => crate::ssh::SshKeyType::Rsa,
                    "ED25519" => crate::ssh::SshKeyType::Ed25519,
                    "ECDSA" => crate::ssh::SshKeyType::Ecdsa,
                    "ECDSA-SHA2-NISTP256" => crate::ssh::SshKeyType::EcdsaSha256,
                    "ECDSA-SHA2-NISTP384" => crate::ssh::SshKeyType::EcdsaSha384,
                    "ECDSA-SHA2-NISTP521" => crate::ssh::SshKeyType::EcdsaSha521,
                    _ => {
                        return Err(PasswordManagerError::InvalidInput(format!(
                            "Unknown key type: {}",
                            key_type_str
                        )))
                    }
                };

                Ok(crate::ssh::SshKey {
                    key_id: Some(key_id),
                    name,
                    comment,
                    key_type,
                    key_size,
                    public_key,
                    private_key_encrypted,
                    nonce,
                    auth_tag,
                    fingerprint,
                    created_at: DateTime::from_timestamp(created_at, 0).unwrap_or_default(),
                    modified_at: DateTime::from_timestamp(modified_at, 0).unwrap_or_default(),
                })
            }
            Err(_) => Err(PasswordManagerError::NotFound(format!(
                "SSH key {}",
                key_id
            ))),
        }
    }

    /// List all SSH key summaries (without private keys)
    pub fn list_ssh_keys(&self) -> Result<Vec<crate::ssh::SshKeySummary>> {
        if !self.is_unlocked() {
            return Err(PasswordManagerError::VaultLocked);
        }

        let db = self.lock_db()?;

        let mut stmt = db
            .conn()
            .prepare("SELECT key_id, name, comment, key_type, fingerprint FROM ssh_keys")
            .map_err(|e| PasswordManagerError::from(DatabaseError::Sqlite(e)))?;

        let keys = stmt
            .query_map([], |row| {
                let key_id: i64 = row.get(0)?;
                let name: String = row.get(1)?;
                let comment: Option<String> = row.get(2)?;
                let key_type_str: String = row.get(3)?;
                let fingerprint: String = row.get(4)?;

                let key_type = match key_type_str.as_str() {
                    "RSA" => crate::ssh::SshKeyType::Rsa,
                    "ED25519" => crate::ssh::SshKeyType::Ed25519,
                    "ECDSA" => crate::ssh::SshKeyType::Ecdsa,
                    "ECDSA-SHA2-NISTP256" => crate::ssh::SshKeyType::EcdsaSha256,
                    "ECDSA-SHA2-NISTP384" => crate::ssh::SshKeyType::EcdsaSha384,
                    "ECDSA-SHA2-NISTP521" => crate::ssh::SshKeyType::EcdsaSha521,
                    _ => crate::ssh::SshKeyType::Rsa, // Default fallback
                };

                Ok(crate::ssh::SshKeySummary {
                    key_id,
                    name,
                    comment,
                    key_type,
                    fingerprint,
                })
            })
            .map_err(|e| PasswordManagerError::from(DatabaseError::Sqlite(e)))?
            .collect::<std::result::Result<Vec<_>, _>>()
            .map_err(|e| PasswordManagerError::from(DatabaseError::Sqlite(e)))?;

        Ok(keys)
    }

    /// List SSH key summaries with pagination to prevent performance issues with large collections.
    pub fn list_ssh_keys_paginated(
        &self,
        pagination: PaginationParams,
    ) -> Result<PaginatedResult<crate::ssh::SshKeySummary>> {
        if !self.is_unlocked() {
            return Err(PasswordManagerError::VaultLocked);
        }

        let db = self.lock_db()?;

        let total_count: i64 = db
            .conn()
            .query_row("SELECT COUNT(*) FROM ssh_keys", [], |row| row.get(0))
            .map_err(|e| PasswordManagerError::from(DatabaseError::Sqlite(e)))?;

        let limit = i64::from(pagination.limit());
        let offset = i64::from(pagination.offset());

        let mut stmt = db
            .conn()
            .prepare(
                "SELECT key_id, name, comment, key_type, fingerprint FROM ssh_keys
                 ORDER BY name LIMIT ?1 OFFSET ?2",
            )
            .map_err(|e| PasswordManagerError::from(DatabaseError::Sqlite(e)))?;

        let items = stmt
            .query_map([limit, offset], |row: &rusqlite::Row<'_>| {
                let key_id: i64 = row.get(0)?;
                let name: String = row.get(1)?;
                let comment: Option<String> = row.get(2)?;
                let key_type_str: String = row.get(3)?;
                let fingerprint: String = row.get(4)?;

                let key_type = match key_type_str.as_str() {
                    "RSA" => crate::ssh::SshKeyType::Rsa,
                    "ED25519" => crate::ssh::SshKeyType::Ed25519,
                    "ECDSA" => crate::ssh::SshKeyType::Ecdsa,
                    "ECDSA-SHA2-NISTP256" => crate::ssh::SshKeyType::EcdsaSha256,
                    "ECDSA-SHA2-NISTP384" => crate::ssh::SshKeyType::EcdsaSha384,
                    "ECDSA-SHA2-NISTP521" => crate::ssh::SshKeyType::EcdsaSha521,
                    _ => crate::ssh::SshKeyType::Rsa,
                };

                Ok(crate::ssh::SshKeySummary {
                    key_id,
                    name,
                    comment,
                    key_type,
                    fingerprint,
                })
            })
            .map_err(|e| PasswordManagerError::from(DatabaseError::Sqlite(e)))?
            .collect::<std::result::Result<Vec<_>, _>>()
            .map_err(|e| PasswordManagerError::from(DatabaseError::Sqlite(e)))?;

        let has_more = (offset + items.len() as i64) < total_count;

        Ok(PaginatedResult {
            items,
            total_count,
            has_more,
        })
    }

    /// Delete an SSH key
    pub fn delete_ssh_key(&self, key_id: i64) -> Result<()> {
        if !self.is_unlocked() {
            return Err(PasswordManagerError::VaultLocked);
        }

        let db = self.lock_db()?;

        let rows_affected = db
            .conn()
            .execute("DELETE FROM ssh_keys WHERE key_id = ?1", [key_id])
            .map_err(|e| PasswordManagerError::from(DatabaseError::Sqlite(e)))?;

        if rows_affected == 0 {
            return Err(PasswordManagerError::NotFound(format!(
                "SSH key {}",
                key_id
            )));
        }

        Ok(())
    }

    /// Export the decrypted private key for an SSH key
    pub fn export_ssh_private_key(&self, key_id: i64) -> Result<String> {
        if !self.is_unlocked() {
            return Err(PasswordManagerError::VaultLocked);
        }

        let dek = self.key_hierarchy.dek()?;
        let db = self.lock_db()?;

        let mut stmt = db
            .conn()
            .prepare(
                "SELECT private_key_encrypted, nonce, auth_tag FROM ssh_keys WHERE key_id = ?1",
            )
            .map_err(|e| PasswordManagerError::from(DatabaseError::Sqlite(e)))?;

        let result = stmt.query_row([key_id], |row| {
            let private_key_encrypted: Vec<u8> = row.get(0)?;
            let nonce: Vec<u8> = row.get(1)?;
            let auth_tag: Vec<u8> = row.get(2)?;
            Ok((private_key_encrypted, nonce, auth_tag))
        });

        match result {
            Ok((private_key_encrypted, nonce, auth_tag)) => {
                crate::ssh::SshKey::decrypt_private_key(
                    dek,
                    &private_key_encrypted,
                    &nonce,
                    &auth_tag,
                )
            }
            Err(_) => Err(PasswordManagerError::NotFound(format!(
                "SSH key {}",
                key_id
            ))),
        }
    }
}
