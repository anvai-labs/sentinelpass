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
        let (secret_encrypted, nonce, auth_tag) =
            crate::totp::encrypt_totp_secret(dek, secret_base32)?;

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

        let now = Utc::now().timestamp();

        db.conn()
            .execute(
                "INSERT INTO totp_secrets (
                    entry_id, secret_encrypted, nonce, auth_tag, algorithm,
                    digits, period, issuer, account_name, created_at
                ) VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9, ?10)
                ON CONFLICT(entry_id) DO UPDATE SET
                    secret_encrypted = excluded.secret_encrypted,
                    nonce = excluded.nonce,
                    auth_tag = excluded.auth_tag,
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
                    issuer,
                    account_name,
                    now,
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

        let db = self.lock_db()?;

        let mut stmt = db
            .conn()
            .prepare(
                "SELECT totp_id, entry_id, algorithm, digits, period, issuer, account_name
                 FROM totp_secrets WHERE entry_id = ?1",
            )
            .map_err(|e| PasswordManagerError::from(DatabaseError::Sqlite(e)))?;

        let row = stmt.query_row([entry_id], |row| {
            let totp_id: i64 = row.get(0)?;
            let entry_id: i64 = row.get(1)?;
            let algorithm: String = row.get(2)?;
            let digits: u8 = row.get(3)?;
            let period: u32 = row.get(4)?;
            let issuer: Option<String> = row.get(5)?;
            let account_name: Option<String> = row.get(6)?;
            Ok((
                totp_id,
                entry_id,
                algorithm,
                digits,
                period,
                issuer,
                account_name,
            ))
        });

        match row {
            Ok((totp_id, entry_id, algorithm_raw, digits, period, issuer, account_name)) => {
                let algorithm = algorithm_raw
                    .parse::<crate::totp::TotpAlgorithm>()
                    .map_err(|_| {
                        PasswordManagerError::from(DatabaseError::Other(format!(
                            "Invalid TOTP algorithm in database: {}",
                            algorithm_raw
                        )))
                    })?;

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
                "SELECT secret_encrypted, nonce, auth_tag, algorithm, digits, period
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
            Ok((secret_encrypted, nonce, auth_tag, algorithm, digits, period))
        });

        let (secret_encrypted, nonce, auth_tag, algorithm_raw, digits, period) = match row {
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

        let secret = crate::totp::decrypt_totp_secret(dek, &secret_encrypted, &nonce, &auth_tag)?;
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
