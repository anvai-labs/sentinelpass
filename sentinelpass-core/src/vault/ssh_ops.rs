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

    /// Add an SSH key to the vault. The incoming struct carries its
    /// private key in the legacy v1 three-part shape; it is decrypted and
    /// RE-SEALED as a v2 envelope bound to (vault_uuid, sync_id, type,
    /// epoch) before insert (WBS-304). New rows always carry a sync_id.
    pub fn add_ssh_key(&self, key: &crate::ssh::SshKey) -> Result<i64> {
        if !self.is_unlocked() {
            return Err(PasswordManagerError::VaultLocked);
        }

        let dek = self.key_hierarchy.dek()?;

        // A v2-shaped input cannot be re-sealed: its envelope binds the
        // ORIGINAL row's identity, which this call does not know (the
        // supported round trip is get → plaintext →
        // add_ssh_key_plaintext). Refuse with guidance instead of
        // AES-GCM-ing the JSON document with a zero nonce (adoption
        // review: the get→add round trip regression).
        if crate::vault::envelope_ops::is_envelope_blob(&key.private_key_encrypted) {
            return Err(PasswordManagerError::InvalidInput(
                "this SSH key's private-key field is already a v2 envelope from another \
                 row; to copy a key, export its plaintext and add via \
                 add_ssh_key_plaintext"
                    .to_string(),
            ));
        }

        // Recover the plaintext from the incoming v1 components, then
        // seal under the row's new identity.
        let private_key_plaintext = crate::ssh::SshKey::decrypt_private_key(
            dek,
            &key.private_key_encrypted,
            &key.nonce,
            &key.auth_tag,
        )?;

        let sync_id = uuid::Uuid::new_v4().to_string();
        let private_key_blob = crate::vault::envelope_ops::seal_object_field(
            dek,
            self.vault_uuid_str()?,
            &sync_id,
            crate::crypto::aad::ObjectType::SshKey,
            crate::crypto::aad::EnvelopePurpose::Secret,
            &private_key_plaintext,
            self.session_epoch(),
        )?;
        // Deprecated v1 columns — zero-filled on v2 rows (see envelope_ops).
        let (nonce_blob, auth_tag_blob) = crate::vault::envelope_ops::zeroed_legacy_v1_columns();

        // Identity metadata sealed in place (WBS-306): the comment is
        // user-identifying, so the column carries a Summary-purpose
        // envelope under the row's own identity. NULL stays NULL.
        let comment_blob = key
            .comment
            .as_deref()
            .map(|value| {
                crate::vault::envelope_ops::seal_object_field(
                    dek,
                    self.vault_uuid_str()?,
                    &sync_id,
                    crate::crypto::aad::ObjectType::SshKey,
                    crate::crypto::aad::EnvelopePurpose::Summary,
                    value,
                    self.session_epoch(),
                )
            })
            .transpose()?;

        let db = self.lock_db()?;

        let now = Utc::now().timestamp();

        db.conn()
            .execute(
                "INSERT INTO ssh_keys (
                name, comment, key_type, key_size, public_key,
                private_key_encrypted, nonce, auth_tag, fingerprint,
                created_at, modified_at, sync_id
            ) VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9, ?10, ?11, ?12)",
                (
                    &key.name,
                    comment_blob,
                    key.key_type.to_string(),
                    key.key_size,
                    &key.public_key,
                    &private_key_blob,
                    &nonce_blob,
                    &auth_tag_blob,
                    &key.fingerprint,
                    now,
                    now,
                    &sync_id,
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

        let dek = self.key_hierarchy.dek()?;
        let db = self.lock_db()?;

        let mut stmt = db
            .conn()
            .prepare(
                "SELECT name, comment, key_type, key_size, public_key, private_key_encrypted,
                     nonce, auth_tag, fingerprint, created_at, modified_at, sync_id
             FROM ssh_keys WHERE key_id = ?1",
            )
            .map_err(|e| PasswordManagerError::from(DatabaseError::Sqlite(e)))?;

        let result = stmt.query_row([key_id], |row| {
            let name: String = row.get(0)?;
            // Storage-polymorphic since WBS-306 (legacy TEXT vs envelope
            // BLOB) — read dynamically, decode in open_metadata_text_field.
            let comment: Option<rusqlite::types::Value> = row.get(1)?;
            let key_type_str: String = row.get(2)?;
            let key_size: Option<u32> = row.get(3)?;
            let public_key: String = row.get(4)?;
            let private_key_encrypted: Vec<u8> = row.get(5)?;
            let nonce: Vec<u8> = row.get(6)?;
            let auth_tag: Vec<u8> = row.get(7)?;
            let fingerprint: String = row.get(8)?;
            let created_at: i64 = row.get(9)?;
            let modified_at: i64 = row.get(10)?;
            let sync_id: Option<String> = row.get(11)?;

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
                sync_id,
            ))
        });

        match result {
            Ok((
                name,
                comment_blob,
                key_type_str,
                key_size,
                public_key,
                private_key_encrypted,
                nonce,
                auth_tag,
                fingerprint,
                created_at,
                modified_at,
                sync_id,
            )) => {
                // Dual-read (WBS-306): v2 envelope vs legacy plaintext.
                let comment = crate::vault::envelope_ops::open_metadata_text_field(
                    dek,
                    self.vault_uuid.as_deref(),
                    sync_id.as_deref(),
                    crate::crypto::aad::ObjectType::SshKey,
                    comment_blob,
                )?;
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

        let dek = self.key_hierarchy.dek()?;
        let db = self.lock_db()?;

        let mut stmt = db
            .conn()
            .prepare("SELECT key_id, name, comment, key_type, fingerprint, sync_id FROM ssh_keys")
            .map_err(|e| PasswordManagerError::from(DatabaseError::Sqlite(e)))?;

        let keys = stmt
            .query_map([], |row| {
                let key_id: i64 = row.get(0)?;
                let name: String = row.get(1)?;
                let comment: Option<rusqlite::types::Value> = row.get(2)?;
                let key_type_str: String = row.get(3)?;
                let fingerprint: String = row.get(4)?;
                let sync_id: Option<String> = row.get(5)?;

                let key_type = match key_type_str.as_str() {
                    "RSA" => crate::ssh::SshKeyType::Rsa,
                    "ED25519" => crate::ssh::SshKeyType::Ed25519,
                    "ECDSA" => crate::ssh::SshKeyType::Ecdsa,
                    "ECDSA-SHA2-NISTP256" => crate::ssh::SshKeyType::EcdsaSha256,
                    "ECDSA-SHA2-NISTP384" => crate::ssh::SshKeyType::EcdsaSha384,
                    "ECDSA-SHA2-NISTP521" => crate::ssh::SshKeyType::EcdsaSha521,
                    _ => crate::ssh::SshKeyType::Rsa, // Default fallback
                };

                Ok((key_id, name, comment, key_type, fingerprint, sync_id))
            })
            .map_err(|e| PasswordManagerError::from(DatabaseError::Sqlite(e)))?
            .collect::<std::result::Result<Vec<_>, _>>()
            .map_err(|e| PasswordManagerError::from(DatabaseError::Sqlite(e)))?;

        // Dual-read the comment column OUTSIDE the row mapper (envelope
        // opens are fallible; WBS-306).
        let mut keys_out = Vec::with_capacity(keys.len());
        for (key_id, name, comment, key_type, fingerprint, sync_id) in keys {
            let comment = crate::vault::envelope_ops::open_metadata_text_field(
                dek,
                self.vault_uuid.as_deref(),
                sync_id.as_deref(),
                crate::crypto::aad::ObjectType::SshKey,
                comment,
            )?;
            keys_out.push(crate::ssh::SshKeySummary {
                key_id,
                name,
                comment,
                key_type,
                fingerprint,
            });
        }

        Ok(keys_out)
    }

    /// List SSH key summaries with pagination to prevent performance issues with large collections.
    pub fn list_ssh_keys_paginated(
        &self,
        pagination: PaginationParams,
    ) -> Result<PaginatedResult<crate::ssh::SshKeySummary>> {
        if !self.is_unlocked() {
            return Err(PasswordManagerError::VaultLocked);
        }

        let dek = self.key_hierarchy.dek()?;
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
                "SELECT key_id, name, comment, key_type, fingerprint, sync_id FROM ssh_keys
                 ORDER BY name LIMIT ?1 OFFSET ?2",
            )
            .map_err(|e| PasswordManagerError::from(DatabaseError::Sqlite(e)))?;

        let items = stmt
            .query_map([limit, offset], |row: &rusqlite::Row<'_>| {
                let key_id: i64 = row.get(0)?;
                let name: String = row.get(1)?;
                let comment: Option<rusqlite::types::Value> = row.get(2)?;
                let key_type_str: String = row.get(3)?;
                let fingerprint: String = row.get(4)?;
                let sync_id: Option<String> = row.get(5)?;

                let key_type = match key_type_str.as_str() {
                    "RSA" => crate::ssh::SshKeyType::Rsa,
                    "ED25519" => crate::ssh::SshKeyType::Ed25519,
                    "ECDSA" => crate::ssh::SshKeyType::Ecdsa,
                    "ECDSA-SHA2-NISTP256" => crate::ssh::SshKeyType::EcdsaSha256,
                    "ECDSA-SHA2-NISTP384" => crate::ssh::SshKeyType::EcdsaSha384,
                    "ECDSA-SHA2-NISTP521" => crate::ssh::SshKeyType::EcdsaSha521,
                    _ => crate::ssh::SshKeyType::Rsa,
                };

                Ok((key_id, name, comment, key_type, fingerprint, sync_id))
            })
            .map_err(|e| PasswordManagerError::from(DatabaseError::Sqlite(e)))?
            .collect::<std::result::Result<Vec<_>, _>>()
            .map_err(|e| PasswordManagerError::from(DatabaseError::Sqlite(e)))?;

        // Dual-read the comment column OUTSIDE the row mapper (envelope
        // opens are fallible; WBS-306).
        let mut items_out = Vec::with_capacity(items.len());
        for (key_id, name, comment, key_type, fingerprint, sync_id) in items {
            let comment = crate::vault::envelope_ops::open_metadata_text_field(
                dek,
                self.vault_uuid.as_deref(),
                sync_id.as_deref(),
                crate::crypto::aad::ObjectType::SshKey,
                comment,
            )?;
            items_out.push(crate::ssh::SshKeySummary {
                key_id,
                name,
                comment,
                key_type,
                fingerprint,
            });
        }

        let has_more = (offset + items_out.len() as i64) < total_count;

        Ok(PaginatedResult {
            items: items_out,
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
                "SELECT private_key_encrypted, nonce, auth_tag, sync_id FROM ssh_keys WHERE key_id = ?1",
            )
            .map_err(|e| PasswordManagerError::from(DatabaseError::Sqlite(e)))?;

        let result = stmt.query_row([key_id], |row| {
            let private_key_encrypted: Vec<u8> = row.get(0)?;
            let nonce: Vec<u8> = row.get(1)?;
            let auth_tag: Vec<u8> = row.get(2)?;
            let sync_id: Option<String> = row.get(3)?;
            Ok((private_key_encrypted, nonce, auth_tag, sync_id))
        });

        match result {
            Ok((private_key_encrypted, nonce, auth_tag, sync_id)) => {
                // Dual-read (WBS-304): a v2 envelope opens against the
                // row's identity; legacy rows take the v1 three-part path.
                if crate::vault::envelope_ops::is_envelope_blob(&private_key_encrypted) {
                    crate::vault::envelope_ops::open_object_field(
                        dek,
                        self.vault_uuid.as_deref(),
                        sync_id.as_deref(),
                        crate::crypto::aad::ObjectType::SshKey,
                        crate::crypto::aad::EnvelopePurpose::Secret,
                        &private_key_encrypted,
                    )
                    .map(|z| z.to_string())
                } else {
                    // Deliberate export boundary: `export_ssh_private_key`
                    // hands the PEM to the caller's output path, which owns
                    // the plaintext from here (WBS-308 audit).
                    crate::ssh::SshKey::decrypt_private_key(
                        dek,
                        &private_key_encrypted,
                        &nonce,
                        &auth_tag,
                    )
                    .map(|z| z.to_string())
                }
            }
            Err(_) => Err(PasswordManagerError::NotFound(format!(
                "SSH key {}",
                key_id
            ))),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn test_vault() -> VaultManager {
        VaultManager::create(":memory:", b"ssh_test_password").unwrap()
    }

    fn add_key(vault: &VaultManager, comment: Option<&str>) -> i64 {
        vault
            .add_ssh_key_plaintext(
                "deploy-key".to_string(),
                comment.map(ToString::to_string),
                crate::ssh::SshKeyType::Ed25519,
                None,
                "ssh-ed25519 AAAATEST test".to_string(),
                "-----BEGIN OPENSSH PRIVATE KEY-----TEST-----END-----".to_string(),
                "SHA256:testfingerprint".to_string(),
            )
            .unwrap()
    }

    fn raw_comment(vault: &VaultManager, key_id: i64) -> Option<Vec<u8>> {
        let db = vault.db.lock().unwrap();
        db.conn()
            .query_row(
                "SELECT comment FROM ssh_keys WHERE key_id = ?1",
                [key_id],
                |row| row.get(0),
            )
            .unwrap()
    }

    #[test]
    fn comment_is_sealed_and_round_trips() {
        let vault = test_vault();
        let key_id = add_key(&vault, Some("deploy@prod"));

        // At rest: envelope document, plaintext nowhere in the column.
        let comment = raw_comment(&vault, key_id).expect("comment was set");
        assert!(comment.starts_with(crate::crypto::ENVELOPE_MAGIC));
        assert!(!String::from_utf8_lossy(&comment).contains("deploy@prod"));

        // Reads return the exact value (get + both list paths).
        let key = vault.get_ssh_key(key_id).unwrap();
        assert_eq!(key.comment.as_deref(), Some("deploy@prod"));
        let listed = vault.list_ssh_keys().unwrap();
        assert_eq!(listed[0].comment.as_deref(), Some("deploy@prod"));
        let paged = vault
            .list_ssh_keys_paginated(crate::vault::PaginationParams::new(0, 10))
            .unwrap();
        assert_eq!(paged.items[0].comment.as_deref(), Some("deploy@prod"));
    }

    #[test]
    fn absent_comment_stays_absent() {
        let vault = test_vault();
        let key_id = add_key(&vault, None);
        assert!(raw_comment(&vault, key_id).is_none());
        assert!(vault.get_ssh_key(key_id).unwrap().comment.is_none());
    }

    #[test]
    fn legacy_plaintext_comment_still_reads() {
        let vault = test_vault();
        let key_id = add_key(&vault, Some("sealed"));

        // Pre-WBS-306 rows: plaintext TEXT in the column.
        {
            let db = vault.db.lock().unwrap();
            db.conn()
                .execute(
                    "UPDATE ssh_keys SET comment = 'plain comment' WHERE key_id = ?1",
                    [key_id],
                )
                .unwrap();
        }
        let key = vault.get_ssh_key(key_id).unwrap();
        assert_eq!(key.comment.as_deref(), Some("plain comment"));
        let listed = vault.list_ssh_keys().unwrap();
        assert_eq!(listed[0].comment.as_deref(), Some("plain comment"));
    }

    #[test]
    fn tampered_comment_envelope_fails_closed() {
        let vault = test_vault();
        let key_id = add_key(&vault, Some("deploy@prod"));

        {
            let db = vault.db.lock().unwrap();
            let mut blob: Vec<u8> = db
                .conn()
                .query_row(
                    "SELECT comment FROM ssh_keys WHERE key_id = ?1",
                    [key_id],
                    |r| r.get(0),
                )
                .unwrap();
            let idx = blob.len() - 2;
            blob[idx] ^= 0x01;
            db.conn()
                .execute(
                    "UPDATE ssh_keys SET comment = ?1 WHERE key_id = ?2",
                    rusqlite::params![&blob, key_id],
                )
                .unwrap();
        }

        let err = vault.get_ssh_key(key_id).unwrap_err();
        assert!(
            err.to_string().to_lowercase().contains("envelope")
                || err.to_string().contains("decrypt")
                || err.to_string().contains("auth"),
            "tamper must fail closed, got: {err}"
        );
    }
}
