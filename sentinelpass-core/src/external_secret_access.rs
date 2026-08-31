//! Least-privilege authorization for local tools requesting vault secrets.

use crate::{get_config_dir, DatabaseError, PasswordManagerError, Result};
use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use std::path::{Path, PathBuf};

const ALLOWLIST_FILE: &str = "external-secret-access.json";

pub use sentinelpass_protocol::ExternalSecretField;

/// A single local-tool authorization grant.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ExternalSecretGrant {
    pub client_id: String,
    pub domain: String,
    pub field: ExternalSecretField,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub expires_at: Option<DateTime<Utc>>,
}

impl ExternalSecretGrant {
    pub fn is_expired_at(&self, now: DateTime<Utc>) -> bool {
        self.expires_at.is_some_and(|expires_at| expires_at <= now)
    }

    fn matches_scope(&self, client_id: &str, domain: &str, field: ExternalSecretField) -> bool {
        self.client_id == client_id && self.domain == domain && self.field == field
    }
}

/// JSON-backed allowlist for external secret access.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct ExternalSecretAllowlist {
    pub grants: Vec<ExternalSecretGrant>,
}

impl ExternalSecretAllowlist {
    pub fn default_path() -> PathBuf {
        get_config_dir().join(ALLOWLIST_FILE)
    }

    pub fn load_default() -> Result<Self> {
        Self::load_from_path(&Self::default_path())
    }

    pub fn load_from_path(path: &Path) -> Result<Self> {
        if !path.exists() {
            return Ok(Self::default());
        }

        let contents = std::fs::read_to_string(path)?;
        serde_json::from_str(&contents).map_err(|e| {
            PasswordManagerError::from(DatabaseError::Serialization(format!(
                "Failed to parse external secret allowlist: {}",
                e
            )))
        })
    }

    pub fn save_to_path(&self, path: &Path) -> Result<()> {
        if let Some(parent) = path.parent() {
            std::fs::create_dir_all(parent)?;
        }

        let contents = serde_json::to_string_pretty(self).map_err(|e| {
            PasswordManagerError::from(DatabaseError::Serialization(format!(
                "Failed to serialize external secret allowlist: {}",
                e
            )))
        })?;
        std::fs::write(path, contents)?;

        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            std::fs::set_permissions(path, std::fs::Permissions::from_mode(0o600))?;
        }

        Ok(())
    }

    pub fn allow_default(
        client_id: &str,
        domain: &str,
        field: ExternalSecretField,
    ) -> Result<ExternalSecretGrant> {
        Self::allow_until_default(client_id, domain, field, None)
    }

    pub fn allow_until_default(
        client_id: &str,
        domain: &str,
        field: ExternalSecretField,
        expires_at: Option<DateTime<Utc>>,
    ) -> Result<ExternalSecretGrant> {
        let path = Self::default_path();
        let mut allowlist = Self::load_from_path(&path)?;
        let grant = allowlist.allow_until(client_id, domain, field, expires_at)?;
        allowlist.save_to_path(&path)?;
        Ok(grant)
    }

    pub fn revoke_default(
        client_id: &str,
        domain: &str,
        field: ExternalSecretField,
    ) -> Result<Option<ExternalSecretGrant>> {
        let path = Self::default_path();
        let mut allowlist = Self::load_from_path(&path)?;
        let revoked = allowlist.revoke(client_id, domain, field)?;
        allowlist.save_to_path(&path)?;
        Ok(revoked)
    }

    pub fn allow(
        &mut self,
        client_id: &str,
        domain: &str,
        field: ExternalSecretField,
    ) -> Result<ExternalSecretGrant> {
        self.allow_until(client_id, domain, field, None)
    }

    pub fn allow_until(
        &mut self,
        client_id: &str,
        domain: &str,
        field: ExternalSecretField,
        expires_at: Option<DateTime<Utc>>,
    ) -> Result<ExternalSecretGrant> {
        let client_id = normalize_client_id(client_id)?;
        let domain = normalize_domain(domain)?;
        let grant = ExternalSecretGrant {
            client_id,
            domain,
            field,
            expires_at,
        };

        if let Some(existing) = self
            .grants
            .iter_mut()
            .find(|existing| existing.matches_scope(&grant.client_id, &grant.domain, grant.field))
        {
            *existing = grant.clone();
        } else {
            self.grants.push(grant.clone());
        }

        Ok(grant)
    }

    pub fn revoke(
        &mut self,
        client_id: &str,
        domain: &str,
        field: ExternalSecretField,
    ) -> Result<Option<ExternalSecretGrant>> {
        let target = ExternalSecretGrant {
            client_id: normalize_client_id(client_id)?,
            domain: normalize_domain(domain)?,
            field,
            expires_at: None,
        };

        let Some(index) = self
            .grants
            .iter()
            .position(|grant| grant.matches_scope(&target.client_id, &target.domain, target.field))
        else {
            return Ok(None);
        };

        Ok(Some(self.grants.remove(index)))
    }

    pub fn grants_for_client(&self, client_id: Option<&str>) -> Result<Vec<ExternalSecretGrant>> {
        let client_id = client_id.map(normalize_client_id).transpose()?;
        let mut grants: Vec<ExternalSecretGrant> = self
            .grants
            .iter()
            .filter(|grant| {
                client_id
                    .as_ref()
                    .is_none_or(|client_id| grant.client_id == *client_id)
            })
            .cloned()
            .collect();

        grants.sort_by(|a, b| {
            a.client_id
                .cmp(&b.client_id)
                .then_with(|| a.domain.cmp(&b.domain))
                .then_with(|| a.field.as_str().cmp(b.field.as_str()))
        });

        Ok(grants)
    }

    pub fn is_allowed(&self, client_id: &str, domain: &str, field: ExternalSecretField) -> bool {
        self.is_allowed_at(client_id, domain, field, Utc::now())
    }

    pub fn is_allowed_at(
        &self,
        client_id: &str,
        domain: &str,
        field: ExternalSecretField,
        now: DateTime<Utc>,
    ) -> bool {
        let Ok(client_id) = normalize_client_id(client_id) else {
            return false;
        };
        let Ok(domain) = normalize_domain(domain) else {
            return false;
        };

        self.grants.iter().any(|grant| {
            grant.matches_scope(&client_id, &domain, field) && !grant.is_expired_at(now)
        })
    }
}

fn normalize_client_id(client_id: &str) -> Result<String> {
    let value = client_id.trim().to_ascii_lowercase();
    if value.is_empty()
        || !value
            .chars()
            .all(|ch| ch.is_ascii_alphanumeric() || ch == '-' || ch == '_')
    {
        return Err(PasswordManagerError::InvalidInput(
            "Client id must contain only ASCII letters, digits, '-' or '_'".to_string(),
        ));
    }
    Ok(value)
}

fn normalize_domain(domain: &str) -> Result<String> {
    let value = domain.trim().trim_end_matches('.').to_ascii_lowercase();
    if value.is_empty() || value.contains('/') || value.contains(char::is_whitespace) {
        return Err(PasswordManagerError::InvalidInput(
            "Domain must be a non-empty host or service name".to_string(),
        ));
    }
    Ok(value)
}

#[cfg(test)]
mod tests {
    use super::*;
    use tempfile::TempDir;

    #[test]
    fn allow_grant_authorizes_exact_client_domain_and_field() {
        let mut allowlist = ExternalSecretAllowlist::default();

        allowlist
            .allow("Victor", "Anthropic.", ExternalSecretField::Password)
            .unwrap();

        assert!(allowlist.is_allowed("victor", "anthropic", ExternalSecretField::Password));
        assert!(!allowlist.is_allowed("victor", "openai", ExternalSecretField::Password));
        assert!(!allowlist.is_allowed("victor", "anthropic", ExternalSecretField::Username));
        assert!(!allowlist.is_allowed("other", "anthropic", ExternalSecretField::Password));
    }

    #[test]
    fn duplicate_grants_are_idempotent() {
        let mut allowlist = ExternalSecretAllowlist::default();

        allowlist
            .allow("victor", "anthropic", ExternalSecretField::Password)
            .unwrap();
        allowlist
            .allow("VICTOR", "ANTHROPIC", ExternalSecretField::Password)
            .unwrap();

        assert_eq!(allowlist.grants.len(), 1);
    }

    #[test]
    fn duplicate_grants_update_expiry() {
        let now = chrono::Utc::now();
        let mut allowlist = ExternalSecretAllowlist::default();

        allowlist
            .allow_until(
                "victor",
                "anthropic",
                ExternalSecretField::Password,
                Some(now + chrono::Duration::minutes(5)),
            )
            .unwrap();
        allowlist
            .allow("VICTOR", "ANTHROPIC", ExternalSecretField::Password)
            .unwrap();

        assert_eq!(allowlist.grants.len(), 1);
        assert_eq!(allowlist.grants[0].expires_at, None);
        assert!(allowlist.is_allowed_at(
            "victor",
            "anthropic",
            ExternalSecretField::Password,
            now + chrono::Duration::minutes(6)
        ));
    }

    #[test]
    fn revoke_grant_removes_exact_client_domain_and_field() {
        let mut allowlist = ExternalSecretAllowlist::default();
        allowlist
            .allow("victor", "anthropic", ExternalSecretField::Password)
            .unwrap();
        allowlist
            .allow("victor", "anthropic", ExternalSecretField::Username)
            .unwrap();

        let revoked = allowlist
            .revoke("Victor", "Anthropic.", ExternalSecretField::Password)
            .unwrap();

        assert_eq!(
            revoked,
            Some(ExternalSecretGrant {
                client_id: "victor".to_string(),
                domain: "anthropic".to_string(),
                field: ExternalSecretField::Password,
                expires_at: None,
            })
        );
        assert!(!allowlist.is_allowed("victor", "anthropic", ExternalSecretField::Password));
        assert!(allowlist.is_allowed("victor", "anthropic", ExternalSecretField::Username));
    }

    #[test]
    fn revoke_missing_grant_is_idempotent() {
        let mut allowlist = ExternalSecretAllowlist::default();

        let revoked = allowlist
            .revoke("victor", "anthropic", ExternalSecretField::Password)
            .unwrap();

        assert_eq!(revoked, None);
        assert!(allowlist.grants.is_empty());
    }

    #[test]
    fn grants_for_client_filters_and_sorts() {
        let mut allowlist = ExternalSecretAllowlist::default();
        allowlist
            .allow("victor", "openai", ExternalSecretField::Password)
            .unwrap();
        allowlist
            .allow("other", "anthropic", ExternalSecretField::Password)
            .unwrap();
        allowlist
            .allow("victor", "anthropic", ExternalSecretField::Username)
            .unwrap();

        let grants = allowlist.grants_for_client(Some("VICTOR")).unwrap();

        assert_eq!(grants.len(), 2);
        assert_eq!(grants[0].domain, "anthropic");
        assert_eq!(grants[0].field, ExternalSecretField::Username);
        assert_eq!(grants[1].domain, "openai");
        assert_eq!(grants[1].field, ExternalSecretField::Password);
    }

    #[test]
    fn save_and_load_preserves_grants_with_private_file_permissions() {
        let tmp = TempDir::new().unwrap();
        let path = tmp.path().join("allowlist.json");
        let mut allowlist = ExternalSecretAllowlist::default();
        allowlist
            .allow("victor", "anthropic", ExternalSecretField::Password)
            .unwrap();

        allowlist.save_to_path(&path).unwrap();
        let loaded = ExternalSecretAllowlist::load_from_path(&path).unwrap();

        assert!(loaded.is_allowed("victor", "anthropic", ExternalSecretField::Password));

        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            let mode = std::fs::metadata(&path).unwrap().permissions().mode() & 0o777;
            assert_eq!(mode, 0o600);
        }
    }

    #[test]
    fn load_accepts_legacy_grants_without_expiry() {
        let tmp = TempDir::new().unwrap();
        let path = tmp.path().join("allowlist.json");
        std::fs::write(
            &path,
            r#"{"grants":[{"client_id":"victor","domain":"anthropic","field":"password"}]}"#,
        )
        .unwrap();

        let loaded = ExternalSecretAllowlist::load_from_path(&path).unwrap();

        assert_eq!(loaded.grants.len(), 1);
        assert_eq!(loaded.grants[0].expires_at, None);
        assert!(loaded.is_allowed("victor", "anthropic", ExternalSecretField::Password));
    }

    #[test]
    fn invalid_client_or_domain_is_rejected() {
        let mut allowlist = ExternalSecretAllowlist::default();

        assert!(allowlist
            .allow("", "anthropic", ExternalSecretField::Password)
            .is_err());
        assert!(allowlist
            .allow(
                "victor",
                "https://anthropic.com",
                ExternalSecretField::Password
            )
            .is_err());
    }

    #[test]
    fn expired_grants_are_not_authorized() {
        let now = chrono::Utc::now();
        let mut allowlist = ExternalSecretAllowlist::default();

        allowlist
            .allow_until(
                "victor",
                "anthropic",
                ExternalSecretField::Password,
                Some(now + chrono::Duration::minutes(5)),
            )
            .unwrap();

        assert!(allowlist.is_allowed_at("victor", "anthropic", ExternalSecretField::Password, now));
        assert!(!allowlist.is_allowed_at(
            "victor",
            "anthropic",
            ExternalSecretField::Password,
            now + chrono::Duration::minutes(6)
        ));
    }
}
