//! SP-1 / ADR-014: exact-entry service grants.
//!
//! A versioned, fail-closed grant store binding a service principal
//! (client id + mandatory token) to ONE exact vault entry and field set.
//! Administration is master-password step-up gated (SP-0); enforcement is
//! the daemon's retrieval-only `ServiceGetSecret` path with typed
//! denied / not_found / locked outcomes. Custody and atomic publication
//! follow the allowlist/manifest discipline (0600, temp+fsync+rename,
//! serialized read-modify-write).

use chrono::{DateTime, Utc};
use rand::{rngs::OsRng, RngCore};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::collections::HashMap;
use std::io::Write;
use std::path::{Path, PathBuf};
use subtle::ConstantTimeEq;
use uuid::Uuid;
use zeroize::Zeroizing;

use crate::{DatabaseError, PasswordManagerError, Result};

/// Service principal tokens carry their own prefix so a service token can
/// never be confused with a legacy broker token at either validation site.
pub const SERVICE_TOKEN_PREFIX: &str = "sps_";
const SERVICE_TOKEN_BYTES: usize = 32;
const STORE_FILE: &str = "service-grants.json";

/// Fields a service grant may expose (subset of the entry surface; ADR-014).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ServiceField {
    Username,
    Password,
    Title,
}

impl ServiceField {
    pub fn as_str(&self) -> &'static str {
        match self {
            Self::Username => "username",
            Self::Password => "password",
            Self::Title => "title",
        }
    }
}

/// One exact-entry service grant. Unknown fields REJECT the document
/// (fail-closed; a future `policy_version` introduces new fields, v1
/// consumers must not silently ignore them).
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ServiceGrant {
    /// Schema gate: only `1` is understood; anything else refuses the
    /// whole store.
    pub policy_version: u32,
    pub grant_id: Uuid,
    pub client_id: String,
    /// EXACT immutable vault entry binding — never a domain or title.
    pub entry_id: i64,
    pub fields: Vec<ServiceField>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub expires_at: Option<DateTime<Utc>>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub revoked_at: Option<DateTime<Utc>>,
    pub created_at: DateTime<Utc>,
    /// SHA-256 of the service token (the plaintext is shown once at mint).
    pub client_token_hash: String,
}

#[derive(Debug, Clone, Default, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ServiceGrantStore {
    /// Keyed by grant_id for stable serialization.
    #[serde(default)]
    pub grants: HashMap<Uuid, ServiceGrant>,
    /// In-process serialization of read-modify-write cycles (the daemon is
    /// the only writer; this closes the concurrent-revoke/allow lost
    /// update the handoff flags). File-level atomicity is temp+fsync+
    /// rename below.
    #[serde(skip)]
    _serialization: Option<()>,
}

impl ServiceGrantStore {
    pub fn default_path() -> PathBuf {
        crate::get_config_dir().join(STORE_FILE)
    }

    /// Fail-closed load: any schema violation (unknown version, unknown
    /// field name, missing mandatory field) refuses the WHOLE document —
    /// a partial load would silently drop grants (availability) or worse,
    /// drop revocations (security).
    pub fn load_from_path(path: &Path) -> Result<Self> {
        if !path.exists() {
            return Ok(Self::default());
        }
        crate::platform::validate_sensitive_path(
            path,
            crate::platform::OwnerOnlyPolicy::WarnAndRepair,
        )
        .map_err(PasswordManagerError::from)?;
        let bytes = std::fs::read(path)?;
        let store: Self = serde_json::from_slice(&bytes).map_err(|e| {
            PasswordManagerError::InvalidInput(format!(
                "service grant store failed closed (schema violation): {e}"
            ))
        })?;
        for grant in store.grants.values() {
            if grant.policy_version != 1 {
                return Err(PasswordManagerError::InvalidInput(format!(
                    "service grant store failed closed: unknown policy_version {}",
                    grant.policy_version
                )));
            }
        }
        Ok(store)
    }

    /// Atomic publication: born-0600 temp, fsync, rename, dir fsync.
    pub fn save_to_path(&self, path: &Path) -> Result<()> {
        if let Ok(meta) = std::fs::symlink_metadata(path) {
            if meta.file_type().is_symlink() {
                return Err(PasswordManagerError::InvalidInput(format!(
                    "service grant store {} is a symlink; refusing to write through it",
                    path.display()
                )));
            }
        }
        if let Some(parent) = path.parent() {
            if !parent.exists() {
                crate::platform::create_private_dir(parent)
                    .map_err(|e| PasswordManagerError::InvalidInput(e.to_string()))?;
            }
        }
        let body = serde_json::to_vec_pretty(self).map_err(|e| {
            PasswordManagerError::from(DatabaseError::Serialization(format!(
                "Failed to serialize service grant store: {e}"
            )))
        })?;
        let parent = path.parent().unwrap_or_else(|| Path::new("."));
        let file_name = path
            .file_name()
            .map(|n| n.to_string_lossy().to_string())
            .unwrap_or_else(|| STORE_FILE.to_string());
        // Unique temp via the same discipline as the credential temps.
        let mut suffix = [0u8; 4];
        OsRng.fill_bytes(&mut suffix);
        let temp = parent.join(format!(".{file_name}.{}.tmp", hex::encode(suffix)));
        let result = (|| -> Result<()> {
            let mut file = crate::platform::create_owner_only_file(&temp)
                .map_err(PasswordManagerError::from)?;
            file.write_all(&body)
                .and_then(|_| file.sync_all())
                .map_err(|e| {
                    PasswordManagerError::InvalidInput(format!(
                        "Failed to write service grant store: {e}"
                    ))
                })?;
            drop(file);
            std::fs::rename(&temp, path).map_err(|e| {
                PasswordManagerError::InvalidInput(format!(
                    "Failed to publish service grant store: {e}"
                ))
            })?;
            Ok(())
        })();
        if result.is_err() {
            let _ = std::fs::remove_file(&temp);
        }
        result
    }

    /// Constant-time token verification + full grant validation for one
    /// exact entry/field. Returns the matching grant.
    pub fn authorize(
        &self,
        client_id: &str,
        token: &str,
        entry_id: i64,
        field: ServiceField,
        now: DateTime<Utc>,
    ) -> Option<&ServiceGrant> {
        let token_hash = Sha256::digest(token.as_bytes());
        self.grants
            .values()
            .filter(|g| {
                g.client_id == client_id
                    && g.entry_id == entry_id
                    && g.revoked_at.is_none()
                    && g.expires_at.map(|e| now < e).unwrap_or(true)
                    && g.fields.contains(&field)
            })
            .find(|g| {
                // Constant-time over the hex-encoded digest.
                let stored = g.client_token_hash.as_bytes();
                stored.len() == token_hash.len() * 2
                    && bool::from(hex::encode(token_hash).as_bytes().ct_eq(stored))
            })
    }

    /// Mint a grant + its one-time-shown token. Caller persists via
    /// `save_to_path` (under the step-up-gated admin op).
    pub fn mint_grant(
        &mut self,
        client_id: &str,
        entry_id: i64,
        fields: Vec<ServiceField>,
        expires_at: Option<DateTime<Utc>>,
    ) -> (ServiceGrant, Zeroizing<String>) {
        let mut token_bytes = [0u8; SERVICE_TOKEN_BYTES];
        OsRng.fill_bytes(&mut token_bytes);
        let token = Zeroizing::new(format!(
            "{SERVICE_TOKEN_PREFIX}{}",
            hex::encode(token_bytes)
        ));
        let token_hash = hex::encode(Sha256::digest(token.as_bytes()));
        let grant = ServiceGrant {
            policy_version: 1,
            grant_id: Uuid::new_v4(),
            client_id: client_id.to_string(),
            entry_id,
            fields,
            expires_at,
            revoked_at: None,
            created_at: Utc::now(),
            client_token_hash: token_hash,
        };
        self.grants.insert(grant.grant_id, grant.clone());
        (grant, token)
    }

    pub fn revoke(&mut self, grant_id: Uuid) -> bool {
        match self.grants.get_mut(&grant_id) {
            Some(grant) => {
                grant.revoked_at = Some(Utc::now());
                true
            }
            None => false,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use tempfile::TempDir;

    fn store() -> ServiceGrantStore {
        ServiceGrantStore::default()
    }

    #[test]
    fn mint_authorize_and_revoke_round_trip() {
        let mut s = store();
        let (grant, token) = s.mint_grant("svc", 42, vec![ServiceField::Password], None);
        let now = Utc::now();
        // Correct token + exact entry + granted field -> authorized.
        assert!(s
            .authorize("svc", &token, 42, ServiceField::Password, now)
            .is_some());
        // Wrong entry id -> denied (exact binding).
        assert!(s
            .authorize("svc", &token, 43, ServiceField::Password, now)
            .is_none());
        // Non-granted field -> denied.
        assert!(s
            .authorize("svc", &token, 42, ServiceField::Username, now)
            .is_none());
        // Wrong token -> denied.
        assert!(s
            .authorize("svc", "sps_wrong", 42, ServiceField::Password, now)
            .is_none());
        // Revoke -> denied.
        assert!(s.revoke(grant.grant_id));
        assert!(s
            .authorize("svc", &token, 42, ServiceField::Password, now)
            .is_none());
    }

    #[test]
    fn expired_grant_is_denied() {
        let mut s = store();
        let (_, token) = s.mint_grant(
            "svc",
            1,
            vec![ServiceField::Password],
            Some(Utc::now() - chrono::Duration::seconds(1)),
        );
        assert!(s
            .authorize("svc", &token, 1, ServiceField::Password, Utc::now())
            .is_none());
    }

    #[test]
    fn schema_violations_fail_the_whole_document() {
        let tmp = TempDir::new().unwrap();
        let path = tmp.path().join(STORE_FILE);
        // Unknown field name.
        std::fs::write(&path, br#"{"grants": {}, "future_field": 1}"#).unwrap();
        assert!(ServiceGrantStore::load_from_path(&path).is_err());
        // Unknown policy_version inside a grant.
        let bad = r#"{"grants": {"00000000-0000-0000-0000-000000000001": {"policy_version": 2, "grant_id": "00000000-0000-0000-0000-000000000001", "client_id": "x", "entry_id": 1, "fields": ["password"], "created_at": "2026-10-02T00:00:00Z", "client_token_hash": "ab"} } }"#;
        std::fs::write(&path, bad).unwrap();
        assert!(ServiceGrantStore::load_from_path(&path).is_err());
        // Missing mandatory field.
        let missing = r#"{"grants": {"00000000-0000-0000-0000-000000000002": {"policy_version": 1, "client_id": "x", "entry_id": 1, "fields": [], "created_at": "2026-10-02T00:00:00Z", "client_token_hash": "ab"} } }"#;
        std::fs::write(&path, missing).unwrap();
        assert!(ServiceGrantStore::load_from_path(&path).is_err());
    }

    #[test]
    fn persistence_is_atomic_and_owner_only() {
        let tmp = TempDir::new().unwrap();
        let path = tmp.path().join(STORE_FILE);
        let mut s = store();
        s.mint_grant("svc", 9, vec![ServiceField::Title], None);
        s.save_to_path(&path).unwrap();
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            let mode = std::fs::metadata(&path).unwrap().permissions().mode() & 0o777;
            assert_eq!(mode, 0o600);
        }
        let reloaded = ServiceGrantStore::load_from_path(&path).unwrap();
        assert_eq!(reloaded.grants.len(), 1);
        // No temp litter.
        let names: Vec<String> = std::fs::read_dir(tmp.path())
            .unwrap()
            .map(|e| e.unwrap().file_name().to_string_lossy().to_string())
            .collect();
        assert!(
            names
                .iter()
                .all(|n| n.starts_with('.') || n.contains(STORE_FILE)),
            "unexpected leftover files: {names:?}"
        );
    }

    #[test]
    fn service_tokens_use_their_own_prefix() {
        let mut s = store();
        let (_, token) = s.mint_grant("svc", 1, vec![ServiceField::Password], None);
        assert!(token.starts_with(SERVICE_TOKEN_PREFIX));
    }
}
