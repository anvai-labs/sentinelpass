//! Least-privilege authorization for local tools requesting vault secrets.

use crate::{get_config_dir, DatabaseError, PasswordManagerError, Result};
use base64::Engine;
use chrono::{DateTime, Utc};
use rand::{rngs::OsRng, RngCore};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::collections::HashMap;
use std::path::{Path, PathBuf};
use subtle::ConstantTimeEq;
use zeroize::Zeroize;

const ALLOWLIST_FILE: &str = "external-secret-access.json";
const CLIENT_TOKEN_PREFIX: &str = "spt_";
const CLIENT_TOKEN_BYTES: usize = 32;

pub use sentinelpass_protocol::ExternalSecretField;

fn is_false(value: &bool) -> bool {
    !*value
}

/// A single local-tool authorization grant.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ExternalSecretGrant {
    pub client_id: String,
    pub domain: String,
    pub field: ExternalSecretField,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub expires_at: Option<DateTime<Utc>>,
    /// When true the client may also write (upsert) the secret for this scope.
    #[serde(default, skip_serializing_if = "is_false")]
    pub allow_write: bool,
}

impl ExternalSecretGrant {
    pub fn is_expired_at(&self, now: DateTime<Utc>) -> bool {
        self.expires_at.is_some_and(|expires_at| expires_at <= now)
    }

    fn matches_scope(&self, client_id: &str, domain: &str, field: ExternalSecretField) -> bool {
        self.client_id == client_id && self.domain == domain && self.field == field
    }
}

/// Stored state of a client's grant token. The plaintext token is shown once
/// at mint time; only its SHA-256 hash lives on disk.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ClientTokenRecord {
    pub token_hash: String,
    pub created_at: DateTime<Utc>,
    #[serde(default)]
    pub revoked: bool,
}

/// Whether requests from a client must present a per-client token.
///
/// Clients with a `client_tokens` entry are token-enforced on every grant;
/// clients without one are "legacy" — their grants work without a token.
/// Revocation is fail-closed: a revoked client is denied even with its old
/// token, and never degrades back to legacy.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ClientTokenStatus {
    Enforced,
    Legacy,
    Revoked,
}

/// JSON-backed allowlist for external secret access.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct ExternalSecretAllowlist {
    pub grants: Vec<ExternalSecretGrant>,
    #[serde(default, skip_serializing_if = "HashMap::is_empty")]
    pub client_tokens: HashMap<String, ClientTokenRecord>,
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
        self.upsert_grant(client_id, domain, field, expires_at, false)
    }

    /// Insert or replace a grant with explicit write permission.
    pub fn upsert_grant(
        &mut self,
        client_id: &str,
        domain: &str,
        field: ExternalSecretField,
        expires_at: Option<DateTime<Utc>>,
        allow_write: bool,
    ) -> Result<ExternalSecretGrant> {
        let client_id = normalize_client_id(client_id)?;
        let domain = normalize_domain(domain)?;
        let grant = ExternalSecretGrant {
            client_id,
            domain,
            field,
            expires_at,
            allow_write,
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
            allow_write: false,
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

    /// Remove every grant for a client. Returns the number removed.
    pub fn revoke_all_for_client(&mut self, client_id: &str) -> Result<usize> {
        let client_id = normalize_client_id(client_id)?;
        let before = self.grants.len();
        self.grants.retain(|grant| grant.client_id != client_id);
        Ok(before - self.grants.len())
    }

    /// Mint a client token (shown once), storing only its SHA-256 hash.
    /// Mints and rotates share logic: rotation replaces the hash, killing
    /// the previous token immediately.
    pub fn mint_client_token(&mut self, client_id: &str) -> Result<String> {
        let client_id = normalize_client_id(client_id)?;

        let mut bytes = [0u8; CLIENT_TOKEN_BYTES];
        OsRng.fill_bytes(&mut bytes);
        let token = format!(
            "{CLIENT_TOKEN_PREFIX}{}",
            base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(bytes)
        );
        bytes.zeroize();

        self.client_tokens.insert(
            client_id,
            ClientTokenRecord {
                token_hash: hash_client_token(&token),
                created_at: Utc::now(),
                revoked: false,
            },
        );

        Ok(token)
    }

    /// Replace a client's token; the old token stops working immediately.
    pub fn rotate_client_token(&mut self, client_id: &str) -> Result<String> {
        let normalized = normalize_client_id(client_id)?;
        if !self.client_tokens.contains_key(&normalized) {
            return Err(PasswordManagerError::NotFound(format!(
                "No client token exists for '{}'; use secret allow or token mint",
                normalized
            )));
        }
        self.mint_client_token(client_id)
    }

    /// Revoke a client token. Fail-closed: every grant for this client is
    /// denied afterwards, even when the old token is presented.
    pub fn revoke_client_token(&mut self, client_id: &str) -> Result<bool> {
        let client_id = normalize_client_id(client_id)?;
        Ok(self
            .client_tokens
            .get_mut(&client_id)
            .map(|record| record.revoked = true)
            .is_some())
    }

    /// Whether requests from this client need a token (and are accepted).
    pub fn token_status(&self, client_id: &str) -> ClientTokenStatus {
        match normalize_client_id(client_id)
            .ok()
            .and_then(|id| self.client_tokens.get(&id))
        {
            None => ClientTokenStatus::Legacy,
            Some(record) if record.revoked => ClientTokenStatus::Revoked,
            Some(_) => ClientTokenStatus::Enforced,
        }
    }

    /// Short non-secret identifier of the stored token hash, for display.
    pub fn token_fingerprint(&self, client_id: &str) -> Option<String> {
        let id = normalize_client_id(client_id).ok()?;
        self.client_tokens
            .get(&id)
            .map(|record| record.token_hash.chars().take(8).collect())
    }

    /// Constant-time verification of a presented client token against the
    /// stored hash. Legacy clients (no `client_tokens` entry) pass; revoked
    /// clients always fail.
    pub fn verify_client_token(&self, client_id: &str, presented: Option<&str>) -> bool {
        let Ok(id) = normalize_client_id(client_id) else {
            return false;
        };
        match self.client_tokens.get(&id) {
            None => true,
            Some(record) if record.revoked => false,
            Some(record) => match presented {
                None => false,
                Some(token) => {
                    let candidate = hash_client_token(token);
                    bool::from(candidate.as_bytes().ct_eq(record.token_hash.as_bytes()))
                }
            },
        }
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

fn hash_client_token(token: &str) -> String {
    hex::encode(Sha256::digest(token.as_bytes()))
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
                allow_write: false,
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
    #[test]
    fn minted_client_token_enforces_scopes_and_rotates() {
        let mut allowlist = ExternalSecretAllowlist::default();
        allowlist
            .allow("victor", "anthropic", ExternalSecretField::Password)
            .unwrap();

        // Legacy until a token is minted
        assert_eq!(allowlist.token_status("victor"), ClientTokenStatus::Legacy);
        assert!(allowlist.verify_client_token("victor", None));

        let token = allowlist.mint_client_token("victor").unwrap();
        assert!(token.starts_with("spt_"));
        assert!(!token.contains("hash"));
        assert_eq!(
            allowlist.token_status("victor"),
            ClientTokenStatus::Enforced
        );

        // Correct token passes, missing/wrong tokens fail
        assert!(allowlist.verify_client_token("victor", Some(&token)));
        assert!(!allowlist.verify_client_token("victor", None));
        assert!(!allowlist.verify_client_token("victor", Some("spt_wrong")));

        // Token is stored hashed, never in plaintext
        assert!(!allowlist
            .client_tokens
            .values()
            .any(|record| record.token_hash == token));

        // Rotation kills the old token
        let rotated = allowlist.rotate_client_token("victor").unwrap();
        assert_ne!(token, rotated);
        assert!(!allowlist.verify_client_token("victor", Some(&token)));
        assert!(allowlist.verify_client_token("victor", Some(&rotated)));

        // Unknown clients cannot be verified into existence
        assert_eq!(allowlist.token_status("unknown"), ClientTokenStatus::Legacy);
        assert!(allowlist.verify_client_token("unknown", None));
    }

    #[test]
    fn revoked_client_token_is_fail_closed() {
        let mut allowlist = ExternalSecretAllowlist::default();
        let token = allowlist.mint_client_token("victor").unwrap();
        assert!(allowlist.verify_client_token("victor", Some(&token)));

        assert!(allowlist.revoke_client_token("victor").unwrap());
        assert_eq!(allowlist.token_status("victor"), ClientTokenStatus::Revoked);
        assert!(!allowlist.verify_client_token("victor", Some(&token)));
        assert!(!allowlist.verify_client_token("victor", None));

        // Revoking again is fine; rotating a missing token errors
        assert!(allowlist.revoke_client_token("victor").unwrap());
        assert!(allowlist.rotate_client_token("ghost").is_err());
    }

    #[test]
    fn allow_write_grants_round_trip_through_file() {
        let dir = TempDir::new().unwrap();
        let path = dir.path().join("allowlist.json");

        let mut allowlist = ExternalSecretAllowlist::default();
        allowlist
            .upsert_grant(
                "sandhi",
                "sandhi:anthropic:key",
                ExternalSecretField::Password,
                None,
                true,
            )
            .unwrap();
        let token = allowlist.mint_client_token("sandhi").unwrap();
        allowlist.save_to_path(&path).unwrap();

        let raw = std::fs::read_to_string(&path).unwrap();
        assert!(raw.contains("allow_write"));
        assert!(raw.contains("client_tokens"));
        assert!(
            !raw.contains(&token),
            "plaintext token must not be persisted"
        );

        let loaded = ExternalSecretAllowlist::load_from_path(&path).unwrap();
        assert!(loaded.is_allowed(
            "sandhi",
            "sandhi:anthropic:key",
            ExternalSecretField::Password
        ));
        assert!(loaded.verify_client_token("sandhi", Some(&token)));
        assert_eq!(loaded.token_fingerprint("sandhi").unwrap().len(), 8);
    }

    #[test]
    fn legacy_grant_file_without_token_section_parses() {
        let legacy = r#"{"grants":[{"client_id":"victor","domain":"anthropic","field":"password","expires_at":null}]}"#;
        let parsed: ExternalSecretAllowlist = serde_json::from_str(legacy).unwrap();
        assert!(parsed.is_allowed("victor", "anthropic", ExternalSecretField::Password));
        assert_eq!(parsed.token_status("victor"), ClientTokenStatus::Legacy);
        assert!(parsed.verify_client_token("victor", None));
    }

    #[test]
    fn revoke_all_removes_only_matching_client() {
        let mut allowlist = ExternalSecretAllowlist::default();
        allowlist
            .allow("victor", "a", ExternalSecretField::Password)
            .unwrap();
        allowlist
            .allow("victor", "b", ExternalSecretField::Password)
            .unwrap();
        allowlist
            .allow("sandhi", "a", ExternalSecretField::Password)
            .unwrap();

        assert_eq!(allowlist.revoke_all_for_client("victor").unwrap(), 2);
        assert!(!allowlist.is_allowed("victor", "a", ExternalSecretField::Password));
        assert!(allowlist.is_allowed("sandhi", "a", ExternalSecretField::Password));
    }
}
