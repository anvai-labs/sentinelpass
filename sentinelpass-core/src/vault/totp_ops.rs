//! TOTP (Time-based One-Time Password) operations for VaultManager

use super::VaultManager;
use crate::{DatabaseError, PasswordManagerError, Result};
use chrono::Utc;

impl VaultManager {
    /// Add or update a TOTP secret for an entry.
    #[allow(clippy::too_many_arguments)]
    pub fn add_totp_secret(
        &self,
        entry_id: i64,
        secret_base32: &str,
        algorithm: crate::totp::TotpAlgorithm,
        digits: u8,
        period: u32,
        issuer: Option<&str>,
        account_name: Option<&str>,
    ) -> Result<i64> {
        if !self.is_unlocked() {
            return Err(PasswordManagerError::VaultLocked);
        }

        let dek = self.key_hierarchy.dek()?;

        let db = self.lock_db()?;

        let entry_exists: i64 = db
            .conn()
            .query_row(
                "SELECT COUNT(*) FROM entries WHERE entry_id = ?1",
                [entry_id],
                |row| row.get(0),
            )
            .map_err(|e| PasswordManagerError::from(DatabaseError::Sqlite(e)))?;

        if entry_exists == 0 {
            return Err(PasswordManagerError::NotFound(format!(
                "Entry {}",
                entry_id
            )));
        }

        // Seal v2 (WBS-304): identity = (vault_uuid, the totp row's OWN
        // sync_id). A re-add to the same entry KEEPS the existing row's
        // sync_id (ON CONFLICT preserves it), so the envelope identity is
        // stable across re-adds; a fresh row gets a fresh sync_id.
        // A missing row is the normal FIRST-add case (None); real SELECT
        // failures (BUSY, I/O) still propagate — masking them would seal
        // under a fresh sync_id the upsert then keeps mismatched
        // (adoption review). The v2 path seals the NORMALIZED secret so
        // add-time base32 validation is preserved (round-2 review: raw
        // sealing deferred 'invalid base32' failures to every read).
        use rusqlite::OptionalExtension;
        let existing_sync_id: Option<String> = db
            .conn()
            .query_row(
                "SELECT sync_id FROM totp_secrets WHERE entry_id = ?1",
                [entry_id],
                |row| row.get(0),
            )
            .optional()
            .map_err(|e| PasswordManagerError::from(DatabaseError::Sqlite(e)))?;
        let sync_id = existing_sync_id.unwrap_or_else(|| uuid::Uuid::new_v4().to_string());
        let normalized = crate::totp::normalize_secret(secret_base32)?;
        let secret_encrypted = crate::vault::envelope_ops::seal_object_field(
            dek,
            self.vault_uuid_str()?,
            &sync_id,
            crate::crypto::aad::ObjectType::TotpSecret,
            crate::crypto::aad::EnvelopePurpose::Secret,
            &normalized,
            self.session_epoch(),
        )?;
        // Deprecated v1 columns — zero-filled on v2 rows (see envelope_ops).
        let (nonce, auth_tag) = crate::vault::envelope_ops::zeroed_legacy_v1_columns();

        // Identity metadata sealed in place (WBS-306): issuer/account_name
        // are user-identifying, so the columns now carry Summary-purpose
        // envelopes under the row's own identity. NULL stays NULL (absence
        // is a NULL, never an empty envelope). Legacy plaintext values in
        // these columns are overwritten here — sealing is the write-path
        // policy; the post-unlock sweep seals legacy rows.
        let issuer_blob = issuer
            .map(|value| {
                crate::vault::envelope_ops::seal_object_field(
                    dek,
                    self.vault_uuid_str()?,
                    &sync_id,
                    crate::crypto::aad::ObjectType::TotpSecret,
                    crate::crypto::aad::EnvelopePurpose::Summary,
                    value,
                    self.session_epoch(),
                )
            })
            .transpose()?;
        let account_name_blob = account_name
            .map(|value| {
                crate::vault::envelope_ops::seal_object_field(
                    dek,
                    self.vault_uuid_str()?,
                    &sync_id,
                    crate::crypto::aad::ObjectType::TotpSecret,
                    crate::crypto::aad::EnvelopePurpose::Summary,
                    value,
                    self.session_epoch(),
                )
            })
            .transpose()?;

        let now = Utc::now().timestamp();

        db.conn()
            .execute(
                "INSERT INTO totp_secrets (
                    entry_id, secret_encrypted, nonce, auth_tag, algorithm,
                    digits, period, issuer, account_name, created_at, sync_id
                ) VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9, ?10, ?11)
                ON CONFLICT(entry_id) DO UPDATE SET
                    secret_encrypted = excluded.secret_encrypted,
                    nonce = excluded.nonce,
                    auth_tag = excluded.auth_tag,
                    sync_id = excluded.sync_id,
                    algorithm = excluded.algorithm,
                    digits = excluded.digits,
                    period = excluded.period,
                    issuer = excluded.issuer,
                    account_name = excluded.account_name,
                    created_at = excluded.created_at",
                (
                    entry_id,
                    &secret_encrypted,
                    &nonce,
                    &auth_tag,
                    algorithm.as_db_value(),
                    digits,
                    period,
                    issuer_blob,
                    account_name_blob,
                    now,
                    &sync_id,
                ),
            )
            .map_err(|e| PasswordManagerError::from(DatabaseError::Sqlite(e)))?;

        let totp_id: i64 = db
            .conn()
            .query_row(
                "SELECT totp_id FROM totp_secrets WHERE entry_id = ?1",
                [entry_id],
                |row| row.get(0),
            )
            .map_err(|e| PasswordManagerError::from(DatabaseError::Sqlite(e)))?;

        Ok(totp_id)
    }

    /// Get TOTP metadata for an entry.
    pub fn get_totp_metadata(&self, entry_id: i64) -> Result<crate::totp::TotpSecretMetadata> {
        if !self.is_unlocked() {
            return Err(PasswordManagerError::VaultLocked);
        }

        let dek = self.key_hierarchy.dek()?;
        let db = self.lock_db()?;

        // issuer/account_name are dual-read (WBS-306): a v2 envelope opens
        // against the row's identity; legacy plaintext bytes pass through.
        let mut stmt = db
            .conn()
            .prepare(
                "SELECT totp_id, entry_id, algorithm, digits, period, issuer, account_name, sync_id
                 FROM totp_secrets WHERE entry_id = ?1",
            )
            .map_err(|e| PasswordManagerError::from(DatabaseError::Sqlite(e)))?;

        let row = stmt.query_row([entry_id], |row| {
            let totp_id: i64 = row.get(0)?;
            let entry_id: i64 = row.get(1)?;
            let algorithm: String = row.get(2)?;
            let digits: u8 = row.get(3)?;
            let period: u32 = row.get(4)?;
            // Storage-polymorphic since WBS-306 (legacy TEXT vs envelope
            // BLOB) — read dynamically, decode in open_metadata_text_field.
            let issuer: Option<rusqlite::types::Value> = row.get(5)?;
            let account_name: Option<rusqlite::types::Value> = row.get(6)?;
            let sync_id: Option<String> = row.get(7)?;
            Ok((
                totp_id,
                entry_id,
                algorithm,
                digits,
                period,
                issuer,
                account_name,
                sync_id,
            ))
        });

        match row {
            Ok((
                totp_id,
                entry_id,
                algorithm_raw,
                digits,
                period,
                issuer_blob,
                account_blob,
                sync_id,
            )) => {
                let algorithm = algorithm_raw
                    .parse::<crate::totp::TotpAlgorithm>()
                    .map_err(|_| {
                        PasswordManagerError::from(DatabaseError::Other(format!(
                            "Invalid TOTP algorithm in database: {}",
                            algorithm_raw
                        )))
                    })?;

                let issuer = crate::vault::envelope_ops::open_metadata_text_field(
                    dek,
                    self.vault_uuid.as_deref(),
                    sync_id.as_deref(),
                    crate::crypto::aad::ObjectType::TotpSecret,
                    issuer_blob,
                )?;
                let account_name = crate::vault::envelope_ops::open_metadata_text_field(
                    dek,
                    self.vault_uuid.as_deref(),
                    sync_id.as_deref(),
                    crate::crypto::aad::ObjectType::TotpSecret,
                    account_blob,
                )?;

                Ok(crate::totp::TotpSecretMetadata {
                    totp_id,
                    entry_id,
                    algorithm,
                    digits,
                    period,
                    issuer,
                    account_name,
                })
            }
            Err(_) => Err(PasswordManagerError::NotFound(format!(
                "TOTP secret for entry {}",
                entry_id
            ))),
        }
    }

    /// Generate the current TOTP code for an entry.
    pub fn generate_totp_code(&self, entry_id: i64) -> Result<crate::totp::TotpCode> {
        if !self.is_unlocked() {
            return Err(PasswordManagerError::VaultLocked);
        }

        let dek = self.key_hierarchy.dek()?;
        let db = self.lock_db()?;

        let mut stmt = db
            .conn()
            .prepare(
                "SELECT secret_encrypted, nonce, auth_tag, algorithm, digits, period, sync_id
                 FROM totp_secrets WHERE entry_id = ?1",
            )
            .map_err(|e| PasswordManagerError::from(DatabaseError::Sqlite(e)))?;

        let row = stmt.query_row([entry_id], |row| {
            let secret_encrypted: Vec<u8> = row.get(0)?;
            let nonce: Vec<u8> = row.get(1)?;
            let auth_tag: Vec<u8> = row.get(2)?;
            let algorithm: String = row.get(3)?;
            let digits: u8 = row.get(4)?;
            let period: u32 = row.get(5)?;
            let sync_id: Option<String> = row.get(6)?;
            Ok((
                secret_encrypted,
                nonce,
                auth_tag,
                algorithm,
                digits,
                period,
                sync_id,
            ))
        });

        let (secret_encrypted, nonce, auth_tag, algorithm_raw, digits, period, sync_id) = match row
        {
            Ok(value) => value,
            Err(_) => {
                return Err(PasswordManagerError::NotFound(format!(
                    "TOTP secret for entry {}",
                    entry_id
                )));
            }
        };

        let algorithm = algorithm_raw
            .parse::<crate::totp::TotpAlgorithm>()
            .map_err(|_| {
                PasswordManagerError::from(DatabaseError::Other(format!(
                    "Invalid TOTP algorithm in database: {}",
                    algorithm_raw
                )))
            })?;

        // Dual-read (WBS-304): v2 envelope against the row's identity,
        // else the v1 three-part path. Both normalize the base32.
        let secret = if crate::vault::envelope_ops::is_envelope_blob(&secret_encrypted) {
            let plaintext = crate::vault::envelope_ops::open_object_field(
                dek,
                self.vault_uuid.as_deref(),
                sync_id.as_deref(),
                crate::crypto::aad::ObjectType::TotpSecret,
                crate::crypto::aad::EnvelopePurpose::Secret,
                &secret_encrypted,
            )?;
            crate::totp::normalize_secret(&plaintext)?
        } else {
            crate::totp::decrypt_totp_secret(dek, &secret_encrypted, &nonce, &auth_tag)?
        };
        let now = Utc::now().timestamp();
        let code = crate::totp::generate_totp_code(&secret, algorithm, digits, period, now)?;
        let seconds_remaining = crate::totp::seconds_remaining(period, now);

        Ok(crate::totp::TotpCode {
            code,
            seconds_remaining,
        })
    }

    /// Remove TOTP secret for an entry.
    pub fn remove_totp_secret(&self, entry_id: i64) -> Result<()> {
        if !self.is_unlocked() {
            return Err(PasswordManagerError::VaultLocked);
        }

        let db = self.lock_db()?;

        let deleted = db
            .conn()
            .execute("DELETE FROM totp_secrets WHERE entry_id = ?1", [entry_id])
            .map_err(|e| PasswordManagerError::from(DatabaseError::Sqlite(e)))?;

        if deleted == 0 {
            return Err(PasswordManagerError::NotFound(format!(
                "TOTP secret for entry {}",
                entry_id
            )));
        }

        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::totp::TotpAlgorithm;

    const SECRET: &str = "JBSWY3DPEHPK3PXP";

    fn test_vault() -> VaultManager {
        VaultManager::create(":memory:", b"totp_test_password").unwrap()
    }

    fn add_entry(vault: &VaultManager) -> i64 {
        vault
            .add_entry(&crate::vault::Entry {
                entry_id: None,
                title: "TOTP entry".to_string(),
                username: "user".to_string(),
                password: "pw".to_string().into(),
                url: None,
                notes: None,
                credential_type: crate::vault::CredentialType::Password,
                created_at: Utc::now(),
                modified_at: Utc::now(),
                favorite: false,
            })
            .unwrap()
    }

    fn raw_metadata_columns(vault: &VaultManager) -> (Option<Vec<u8>>, Option<Vec<u8>>) {
        let db = vault.db.lock().unwrap();
        db.conn()
            .query_row(
                "SELECT issuer, account_name FROM totp_secrets LIMIT 1",
                [],
                |row| Ok((row.get(0)?, row.get(1)?)),
            )
            .unwrap()
    }

    #[test]
    fn issuer_and_account_are_sealed_and_round_trip() {
        let vault = test_vault();
        let entry_id = add_entry(&vault);
        vault
            .add_totp_secret(
                entry_id,
                SECRET,
                TotpAlgorithm::Sha1,
                6,
                30,
                Some("GitHub"),
                Some("user@example.com"),
            )
            .unwrap();

        // At rest: envelope documents, plaintext nowhere in the columns.
        let (issuer, account) = raw_metadata_columns(&vault);
        let issuer = issuer.expect("issuer was set");
        assert!(issuer.starts_with(crate::crypto::ENVELOPE_MAGIC));
        assert!(!String::from_utf8_lossy(&issuer).contains("GitHub"));
        let account = account.expect("account_name was set");
        assert!(account.starts_with(crate::crypto::ENVELOPE_MAGIC));
        assert!(!String::from_utf8_lossy(&account).contains("user@example.com"));

        // Reads return the exact values (dual-read, v2 arm).
        let meta = vault.get_totp_metadata(entry_id).unwrap();
        assert_eq!(meta.issuer.as_deref(), Some("GitHub"));
        assert_eq!(meta.account_name.as_deref(), Some("user@example.com"));
    }

    #[test]
    fn absent_issuer_stays_absent() {
        let vault = test_vault();
        let entry_id = add_entry(&vault);
        vault
            .add_totp_secret(entry_id, SECRET, TotpAlgorithm::Sha1, 6, 30, None, None)
            .unwrap();
        let (issuer, account) = raw_metadata_columns(&vault);
        assert!(issuer.is_none() && account.is_none());
        let meta = vault.get_totp_metadata(entry_id).unwrap();
        assert!(meta.issuer.is_none() && meta.account_name.is_none());
    }

    #[test]
    fn legacy_plaintext_metadata_still_reads() {
        let vault = test_vault();
        let entry_id = add_entry(&vault);
        vault
            .add_totp_secret(
                entry_id,
                SECRET,
                TotpAlgorithm::Sha1,
                6,
                30,
                Some("GitHub"),
                Some("user@example.com"),
            )
            .unwrap();

        // Pre-WBS-306 rows: plaintext TEXT in the columns.
        {
            let db = vault.db.lock().unwrap();
            db.conn()
                .execute(
                    "UPDATE totp_secrets SET issuer = 'PlainIssuer', account_name = 'plain@example.com'",
                    [],
                )
                .unwrap();
        }
        let meta = vault.get_totp_metadata(entry_id).unwrap();
        assert_eq!(meta.issuer.as_deref(), Some("PlainIssuer"));
        assert_eq!(meta.account_name.as_deref(), Some("plain@example.com"));
    }

    #[test]
    fn tampered_issuer_envelope_fails_closed() {
        let vault = test_vault();
        let entry_id = add_entry(&vault);
        vault
            .add_totp_secret(
                entry_id,
                SECRET,
                TotpAlgorithm::Sha1,
                6,
                30,
                Some("GitHub"),
                None,
            )
            .unwrap();

        {
            let db = vault.db.lock().unwrap();
            let mut blob: Vec<u8> = db
                .conn()
                .query_row(
                    "SELECT issuer FROM totp_secrets WHERE entry_id = ?1",
                    [entry_id],
                    |r| r.get(0),
                )
                .unwrap();
            let idx = blob.len() - 2;
            blob[idx] ^= 0x01;
            db.conn()
                .execute(
                    "UPDATE totp_secrets SET issuer = ?1 WHERE entry_id = ?2",
                    rusqlite::params![&blob, entry_id],
                )
                .unwrap();
        }

        let err = vault.get_totp_metadata(entry_id).unwrap_err();
        assert!(
            err.to_string().to_lowercase().contains("envelope")
                || err.to_string().contains("decrypt")
                || err.to_string().contains("auth"),
            "tamper must fail closed, got: {err}"
        );
    }
}
