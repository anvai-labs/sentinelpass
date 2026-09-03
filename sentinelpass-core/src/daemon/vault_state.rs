//! Daemon vault state management for the daemon
//!
//! The daemon maintains the vault in memory, handling lock/unlock
//! and responding to credential requests.

use crate::{
    get_default_vault_path, CredentialType, DatabaseError, LifecycleSource, PasswordManagerError,
    Result, VaultManager,
};
use std::path::PathBuf;
use std::sync::{Arc, Mutex as SyncMutex};
use std::time::Instant;
use tokio::sync::Mutex;
use tokio::time::{interval, Duration};
use tracing::{info, warn};
use url::Url;

/// Vault state for the daemon
#[derive(Clone, Copy, Debug)]
pub enum VaultState {
    Locked,
    Unlocked,
}

/// Daemon vault manager with auto-lock functionality
pub struct DaemonVault {
    vault: Arc<Mutex<Option<VaultManager>>>,
    state: Arc<SyncMutex<VaultState>>,
    last_activity: Arc<SyncMutex<Instant>>,
    vault_path: PathBuf,
    inactivity_timeout: Duration,
}

/// Extract the bare hostname from a URL or hostname string.
///
/// Tries the `url` crate first (handles schemes, auth, ports, IPv6, encoding).
/// Falls back to treating the input as a bare hostname so that plain domain
/// strings like `"example.com"` still work without a scheme prefix.
fn normalize_host(value: &str) -> Option<String> {
    let trimmed = value.trim().trim_matches('.').to_ascii_lowercase();
    if trimmed.is_empty() {
        return None;
    }

    // Extract the host string from a parsed URL, stripping IPv6 brackets that
    // url::Url includes in host_str() (e.g. "[::1]" → "::1").
    let extract = |url: Url| -> Option<String> {
        let h = url.host_str()?.trim_matches('.');
        let h = h
            .strip_prefix('[')
            .and_then(|s| s.strip_suffix(']'))
            .unwrap_or(h);
        if h.is_empty() {
            None
        } else {
            Some(h.to_string())
        }
    };

    // Try parsing as a full URL first; only use the result if a host was found.
    // "example.com:8443" parses as scheme="example.com" with no host — skip it.
    if let Ok(url) = Url::parse(&trimmed) {
        if let Some(host) = extract(url) {
            return Some(host);
        }
    }

    // No scheme, or scheme-only parse produced no host — prepend a dummy scheme.
    if let Ok(url) = Url::parse(&format!("dummy://{}", trimmed)) {
        if let Some(host) = extract(url) {
            return Some(host);
        }
    }

    // Last resort: bare hostname. Strip stray brackets (e.g. "[]" → "") and dots.
    let host = trimmed
        .trim_matches('.')
        .trim_start_matches('[')
        .trim_end_matches(']')
        .trim_matches('.');
    if host.is_empty() {
        None
    } else {
        Some(host.to_string())
    }
}

fn domains_match(request_domain: &str, entry_url_or_domain: &str) -> bool {
    let Some(request_host) = normalize_host(request_domain) else {
        return false;
    };
    let Some(entry_host) = normalize_host(entry_url_or_domain) else {
        return false;
    };

    if request_host == entry_host {
        return true;
    }

    let request_suffix = format!(".{}", request_host);
    let entry_suffix = format!(".{}", entry_host);
    request_host.ends_with(&entry_suffix) || entry_host.ends_with(&request_suffix)
}

fn usernames_match(lhs: &str, rhs: &str) -> bool {
    lhs.trim().eq_ignore_ascii_case(rhs.trim())
}

impl DaemonVault {
    /// Create a new daemon vault manager
    pub fn new(vault_path: Option<PathBuf>, inactivity_timeout_sec: u64) -> Result<Self> {
        let vault_path = vault_path.unwrap_or_else(get_default_vault_path);

        if !vault_path.exists() {
            return Err(PasswordManagerError::NotFound(format!(
                "No vault found at {:?}",
                vault_path
            )));
        }

        Ok(Self {
            vault: Arc::new(Mutex::new(None)),
            state: Arc::new(SyncMutex::new(VaultState::Locked)),
            last_activity: Arc::new(SyncMutex::new(Instant::now())),
            vault_path,
            inactivity_timeout: Duration::from_secs(inactivity_timeout_sec),
        })
    }

    /// Unlock the vault with master password
    pub async fn unlock(&self, master_password: &[u8]) -> Result<()> {
        let vault = VaultManager::open(&self.vault_path, master_password).map_err(|e| {
            PasswordManagerError::from(DatabaseError::Other(format!(
                "Failed to unlock vault: {}",
                e
            )))
        })?;

        self.unlock_with_manager(vault).await;
        Ok(())
    }

    /// Unlock the daemon with an already opened vault manager.
    pub async fn unlock_with_manager(&self, vault: VaultManager) {
        *self.vault.lock().await = Some(vault);
        *self.state.lock().unwrap() = VaultState::Unlocked;
        *self.last_activity.lock().unwrap() = Instant::now();

        info!("Vault unlocked successfully");

        // Start auto-lock task
        self.start_auto_lock_task();
    }

    /// Unlock the vault with biometric authentication.
    pub async fn unlock_with_biometric(&self, prompt_reason: &str) -> Result<()> {
        let vault =
            VaultManager::open_with_biometric(&self.vault_path, prompt_reason).map_err(|e| {
                PasswordManagerError::from(DatabaseError::Other(format!(
                    "Failed biometric unlock: {}",
                    e
                )))
            })?;

        self.unlock_with_manager(vault).await;
        Ok(())
    }

    /// Lock the vault
    pub async fn lock(&self) {
        *self.vault.lock().await = None;
        *self.state.lock().unwrap() = VaultState::Locked;
        info!("Vault locked");
    }

    /// Check if vault is unlocked
    pub async fn is_unlocked(&self) -> bool {
        matches!(*self.state.lock().unwrap(), VaultState::Unlocked)
    }

    /// Get credential by domain.
    ///
    /// Tries an indexed lookup via `domain_mappings` first (O(1) decryptions
    /// for the matched rows). Falls back to a full entry scan when no
    /// domain mappings exist (e.g. entries created before sync was enabled).
    pub async fn get_credential(&self, domain: &str) -> Result<Option<CredentialResponse>> {
        let vault_guard = self.vault.lock().await;
        let vault = match vault_guard.as_ref() {
            Some(v) => v,
            None => return Ok(None), // locked
        };
        self.record_activity().await;

        // Fast path: indexed lookup via domain_mappings
        if let Some(host) = normalize_host(domain) {
            let indexed = vault.find_entries_by_domain(&host)?;
            if let Some(entry) = indexed
                .into_iter()
                .find(|entry| entry.credential_type.is_retrievable_secret())
            {
                return Ok(Some(CredentialResponse {
                    username: entry.username,
                    password: entry.password.as_str().to_string(),
                    title: entry.title,
                }));
            }
        }

        // Slow path: full scan (entries without domain_mappings)
        let entries = vault.list_entries()?;
        for summary in entries {
            if !summary.credential_type.is_retrievable_secret() {
                continue;
            }
            if let Ok(entry) = vault.get_entry(summary.entry_id) {
                if let Some(ref url) = entry.url {
                    if domains_match(domain, url) {
                        return Ok(Some(CredentialResponse {
                            username: entry.username,
                            password: entry.password.as_str().to_string(),
                            title: entry.title,
                        }));
                    }
                }
            }
        }

        Ok(None)
    }

    /// Get TOTP code by domain.
    ///
    /// Tries an indexed lookup via `domain_mappings` first, then falls back
    /// to a full entry scan.
    pub async fn get_totp_code(&self, domain: &str) -> Result<Option<TotpCodeResponse>> {
        let vault_guard = self.vault.lock().await;
        let vault = match vault_guard.as_ref() {
            Some(v) => v,
            None => return Ok(None), // locked
        };
        self.record_activity().await;

        // Fast path: indexed lookup via domain_mappings
        if let Some(host) = normalize_host(domain) {
            let indexed = vault.find_entries_by_domain(&host)?;
            for entry in &indexed {
                if let Some(entry_id) = entry.entry_id {
                    match vault.generate_totp_code(entry_id) {
                        Ok(code) => {
                            return Ok(Some(TotpCodeResponse {
                                code: code.code,
                                seconds_remaining: code.seconds_remaining,
                            }));
                        }
                        Err(PasswordManagerError::NotFound(_)) => continue,
                        Err(e) => {
                            warn!("Failed to generate TOTP for domain '{}': {}", domain, e);
                            return Err(e);
                        }
                    }
                }
            }
            if !indexed.is_empty() {
                return Ok(None);
            }
        }

        // Slow path: full scan
        let entries = vault.list_entries()?;
        for summary in entries {
            if let Ok(entry) = vault.get_entry(summary.entry_id) {
                if let Some(ref url) = entry.url {
                    if domains_match(domain, url) {
                        match vault.generate_totp_code(summary.entry_id) {
                            Ok(code) => {
                                return Ok(Some(TotpCodeResponse {
                                    code: code.code,
                                    seconds_remaining: code.seconds_remaining,
                                }));
                            }
                            Err(PasswordManagerError::NotFound(_)) => continue,
                            Err(e) => {
                                warn!("Failed to generate TOTP for domain '{}': {}", domain, e);
                                return Err(e);
                            }
                        }
                    }
                }
            }
        }

        Ok(None)
    }

    /// List all credentials matching a base domain (e.g., "google.com" matches "gmail.google.com", "accounts.google.com").
    ///
    /// Tries an indexed lookup via `domain_mappings` first, then falls back
    /// to a full entry scan.
    pub async fn list_domain_credentials(
        &self,
        base_domain: &str,
    ) -> Result<Vec<DomainCredentialResponse>> {
        let vault_guard = self.vault.lock().await;
        let vault = match vault_guard.as_ref() {
            Some(v) => v,
            None => return Ok(Vec::new()), // locked
        };
        self.record_activity().await;

        let mut matching_credentials = Vec::new();

        // Fast path: indexed lookup via domain_mappings
        if let Some(host) = normalize_host(base_domain) {
            let indexed = vault.find_entries_by_domain(&host)?;
            if !indexed.is_empty() {
                for entry in indexed {
                    if !entry.credential_type.is_retrievable_secret() {
                        continue;
                    }
                    let domain = entry
                        .url
                        .as_ref()
                        .and_then(|url| normalize_host(url))
                        .unwrap_or_else(|| base_domain.to_string());

                    matching_credentials.push(DomainCredentialResponse {
                        username: entry.username,
                        title: entry.title,
                        domain,
                    });
                }
                matching_credentials
                    .sort_by(|a, b| (&a.title, &a.username).cmp(&(&b.title, &b.username)));
                return Ok(matching_credentials);
            }
        }

        // Slow path: full scan
        let entries = vault.list_entries()?;
        for summary in entries {
            if !summary.credential_type.is_retrievable_secret() {
                continue;
            }
            if let Ok(entry) = vault.get_entry(summary.entry_id) {
                let matches = if let Some(ref url) = entry.url {
                    domains_match(base_domain, url)
                } else {
                    false
                };

                if matches {
                    let domain = entry
                        .url
                        .as_ref()
                        .and_then(|url| normalize_host(url))
                        .unwrap_or_else(|| base_domain.to_string());

                    matching_credentials.push(DomainCredentialResponse {
                        username: entry.username,
                        title: entry.title,
                        domain,
                    });
                }
            }
        }

        matching_credentials.sort_by(|a, b| (&a.title, &a.username).cmp(&(&b.title, &b.username)));

        Ok(matching_credentials)
    }

    /// Save credential to vault
    pub async fn save_credential(
        &self,
        domain: &str,
        username: &str,
        password: &str,
        url: Option<&str>,
    ) -> Result<()> {
        let vault_guard = self.vault.lock().await;
        let vault = match vault_guard.as_ref() {
            Some(v) => v,
            None => return Err(PasswordManagerError::VaultLocked),
        };
        self.record_activity().await;

        use crate::vault::Entry;
        use chrono::Utc;

        let now = Utc::now();

        let mut existing_entry_id: Option<i64> = None;
        if !username.trim().is_empty() {
            let entries = vault.list_entries()?;
            for summary in entries {
                if let Ok(existing_entry) = vault.get_entry(summary.entry_id) {
                    let url_matches = existing_entry
                        .url
                        .as_ref()
                        .map(|entry_url| domains_match(domain, entry_url))
                        .unwrap_or(false);
                    if url_matches && usernames_match(&existing_entry.username, username) {
                        existing_entry_id = Some(summary.entry_id);
                        break;
                    }
                }
            }
        }

        if let Some(entry_id) = existing_entry_id {
            let mut existing_entry = vault.get_entry(entry_id)?;
            existing_entry.password = password.to_string().into();
            if let Some(incoming_url) = url {
                existing_entry.url = Some(incoming_url.to_string());
            }
            existing_entry.modified_at = now;
            vault.update_entry(entry_id, &existing_entry)?;
            info!(
                "Credential updated for domain: {} (entry_id={})",
                domain, entry_id
            );
            return Ok(());
        }

        let entry = Entry {
            entry_id: None, // Auto-assigned by database
            title: format!("Credential for {}", domain),
            username: username.to_string(),
            password: password.to_string().into(),
            url: url.map(|u| u.to_string()),
            notes: None,
            credential_type: CredentialType::Password,
            created_at: now,
            modified_at: now,
            favorite: false,
        };

        vault.add_entry(&entry)?;
        info!("Credential saved for domain: {}", domain);
        Ok(())
    }

    /// Upsert one secret value for one scope on behalf of an external tool.
    /// Matches an existing entry by domain only (not username); new entries
    /// are typed as API keys since tools store machine credentials here.
    pub async fn save_secret_value(&self, domain: &str, value: &str) -> Result<()> {
        let vault_guard = self.vault.lock().await;
        let vault = match vault_guard.as_ref() {
            Some(v) => v,
            None => return Err(PasswordManagerError::VaultLocked),
        };
        self.record_activity().await;

        use crate::vault::Entry;
        use chrono::Utc;
        let now = Utc::now();

        let mut existing_entry_id: Option<i64> = None;
        let entries = vault.list_entries()?;
        for summary in entries {
            if let Ok(existing_entry) = vault.get_entry(summary.entry_id) {
                let url_matches = existing_entry
                    .url
                    .as_ref()
                    .map(|entry_url| domains_match(domain, entry_url))
                    .unwrap_or(false);
                let title_matches = domains_match(domain, &existing_entry.title);
                if url_matches || title_matches {
                    existing_entry_id = Some(summary.entry_id);
                    break;
                }
            }
        }

        if let Some(entry_id) = existing_entry_id {
            let mut existing_entry = vault.get_entry(entry_id)?;
            existing_entry.password = value.to_string().into();
            existing_entry.modified_at = now;
            vault.update_entry(entry_id, &existing_entry)?;
            // Stamp tool-managed source (ADR-001): deploy-time re-injection
            // of an unchanged value produces an unchanged tag (no rotation
            // stamp), and age-based rotation statuses are suppressed for
            // these entries.
            let _ = vault.set_lifecycle_source(entry_id, LifecycleSource::ToolManaged);
            info!(
                "External secret updated for domain: {} (entry_id={})",
                domain, entry_id
            );
            return Ok(());
        }

        let entry = Entry {
            entry_id: None,
            title: domain.to_string(),
            username: "api-key".to_string(),
            password: value.to_string().into(),
            url: Some(domain.to_string()),
            notes: None,
            credential_type: CredentialType::ApiKey,
            created_at: now,
            modified_at: now,
            favorite: false,
        };
        let new_entry_id = vault.add_entry(&entry)?;
        let _ = vault.set_lifecycle_source(new_entry_id, LifecycleSource::ToolManaged);
        info!("External secret saved for domain: {}", domain);
        Ok(())
    }

    /// Current key epoch (ADR-002); `None` when no vault is loaded. Vault
    /// metadata, not key material — readable while locked.
    pub async fn key_epoch(&self) -> Option<i64> {
        let vault_guard = self.vault.lock().await;
        vault_guard
            .as_ref()
            .and_then(|vault| vault.key_epoch().ok())
    }

    /// Get sync status from the vault database.
    pub async fn get_sync_status(&self) -> Result<crate::sync::models::SyncStatus> {
        let vault_guard = self.vault.lock().await;
        if let Some(ref vault) = *vault_guard {
            vault.get_sync_status()
        } else {
            // Return disabled status when vault is locked
            Ok(crate::sync::models::SyncStatus {
                enabled: false,
                device_id: None,
                device_name: None,
                relay_url: None,
                last_sync_at: None,
                pending_changes: 0,
            })
        }
    }

    /// Run a full sync cycle (push pending changes, pull remote changes).
    #[cfg(feature = "sync")]
    pub async fn sync_now(&self) -> Result<crate::sync::models::SyncStatus> {
        let vault_guard = self.vault.lock().await;
        let vault = vault_guard
            .as_ref()
            .ok_or(PasswordManagerError::VaultLocked)?;
        vault.sync_now().await
    }

    /// Record activity (resets the auto-lock timer)
    pub async fn record_activity(&self) {
        *self.last_activity.lock().unwrap() = Instant::now();
    }

    /// Start the auto-lock background task
    fn start_auto_lock_task(&self) {
        let state = self.state.clone();
        let vault = self.vault.clone();
        let last_activity = self.last_activity.clone();
        let timeout = self.inactivity_timeout;

        tokio::spawn(async move {
            let check_interval = if timeout.is_zero() {
                Duration::from_secs(1)
            } else {
                timeout.min(Duration::from_secs(5))
            };
            let mut timer = interval(check_interval);
            timer.tick().await; // Skip first tick

            loop {
                timer.tick().await;
                let unlocked = matches!(*state.lock().unwrap(), VaultState::Unlocked);
                if unlocked && last_activity.lock().unwrap().elapsed() >= timeout {
                    warn!("Auto-locking vault due to inactivity");
                    *vault.lock().await = None;
                    *state.lock().unwrap() = VaultState::Locked;
                }
            }
        });
    }
}

/// Response with credential data
#[derive(Debug, Clone)]
pub struct CredentialResponse {
    pub username: String,
    pub password: String,
    pub title: String,
}

/// Response with TOTP code data.
#[derive(Debug, Clone)]
pub struct TotpCodeResponse {
    pub code: String,
    pub seconds_remaining: u32,
}

/// Response with domain credential data (excludes password for security)
#[derive(Debug, Clone)]
pub struct DomainCredentialResponse {
    pub username: String,
    pub title: String,
    pub domain: String,
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{Entry, VaultManager};
    use chrono::Utc;
    use tempfile::TempDir;

    fn test_entry(title: &str, password: &str, credential_type: CredentialType) -> Entry {
        Entry {
            entry_id: None,
            title: title.to_string(),
            username: "user@example.com".to_string(),
            password: password.to_string().into(),
            url: Some("https://example.com/login".to_string()),
            notes: None,
            credential_type,
            created_at: Utc::now(),
            modified_at: Utc::now(),
            favorite: false,
        }
    }

    #[tokio::test]
    async fn get_credential_does_not_return_passkey_reference_secret() {
        let tmp = TempDir::new().unwrap();
        let vault_path = tmp.path().join("vault.db");
        let password = b"test_password";

        let vault = VaultManager::create(&vault_path, password).unwrap();
        vault
            .add_entry(&test_entry(
                "Example Passkey",
                "passkey-ref:example.com:user@example.com",
                CredentialType::PasskeyReference,
            ))
            .unwrap();
        drop(vault);

        let daemon_vault = DaemonVault::new(Some(vault_path.clone()), 300).unwrap();
        daemon_vault.unlock(password).await.unwrap();

        let credential = daemon_vault.get_credential("example.com").await.unwrap();

        assert!(credential.is_none());
    }

    #[tokio::test]
    async fn get_credential_skips_passkey_reference_and_returns_password_entry() {
        let tmp = TempDir::new().unwrap();
        let vault_path = tmp.path().join("vault.db");
        let password = b"test_password";

        let vault = VaultManager::create(&vault_path, password).unwrap();
        vault
            .add_entry(&test_entry(
                "Example Passkey",
                "passkey-ref:example.com:user@example.com",
                CredentialType::PasskeyReference,
            ))
            .unwrap();
        vault
            .add_entry(&test_entry(
                "Example Password",
                "password-secret",
                CredentialType::Password,
            ))
            .unwrap();
        drop(vault);

        let daemon_vault = DaemonVault::new(Some(vault_path.clone()), 300).unwrap();
        daemon_vault.unlock(password).await.unwrap();

        let credential = daemon_vault
            .get_credential("example.com")
            .await
            .unwrap()
            .unwrap();

        assert_eq!(credential.password, "password-secret");
    }

    #[tokio::test]
    async fn list_domain_credentials_does_not_include_passkey_references() {
        let tmp = TempDir::new().unwrap();
        let vault_path = tmp.path().join("vault.db");
        let password = b"test_password";

        let vault = VaultManager::create(&vault_path, password).unwrap();
        vault
            .add_entry(&test_entry(
                "Example Passkey",
                "passkey-ref:example.com:user@example.com",
                CredentialType::PasskeyReference,
            ))
            .unwrap();
        drop(vault);

        let daemon_vault = DaemonVault::new(Some(vault_path.clone()), 300).unwrap();
        daemon_vault.unlock(password).await.unwrap();

        let credentials = daemon_vault
            .list_domain_credentials("example.com")
            .await
            .unwrap();

        assert!(credentials.is_empty());
    }

    #[test]
    fn test_vault_state() {
        let state = VaultState::Locked;
        assert!(matches!(state, VaultState::Locked));
    }

    #[test]
    fn test_normalize_host_handles_urls_and_ports() {
        assert_eq!(
            normalize_host("https://Login.Example.com:443/path"),
            Some("login.example.com".to_string())
        );
        assert_eq!(
            normalize_host("example.com"),
            Some("example.com".to_string())
        );
        assert_eq!(
            normalize_host("example.com:8443"),
            Some("example.com".to_string())
        );
        assert_eq!(normalize_host(""), None);
    }

    #[test]
    fn test_domains_match_exact_and_subdomains_only() {
        assert!(domains_match("example.com", "https://example.com/login"));
        assert!(domains_match(
            "accounts.example.com",
            "https://example.com/login"
        ));
        assert!(domains_match(
            "example.com",
            "https://accounts.example.com/login"
        ));
        assert!(!domains_match(
            "evil-example.com",
            "https://example.com/login"
        ));
        assert!(!domains_match(
            "notexample.com",
            "https://example.com/login"
        ));
    }

    #[test]
    fn test_usernames_match_case_insensitive_and_trimmed() {
        assert!(usernames_match(" User@Example.com ", "user@example.com"));
        assert!(!usernames_match("alice@example.com", "bob@example.com"));
    }

    #[test]
    fn test_normalize_host_strips_userinfo() {
        assert_eq!(
            normalize_host("https://user:pass@example.com/path"),
            Some("example.com".to_string())
        );
        assert_eq!(
            normalize_host("user@host.com"),
            Some("host.com".to_string())
        );
    }

    #[test]
    fn test_normalize_host_strips_query_and_fragment() {
        assert_eq!(
            normalize_host("example.com/path?query=1#frag"),
            Some("example.com".to_string())
        );
    }

    #[test]
    fn test_normalize_host_trailing_dots() {
        assert_eq!(
            normalize_host("example.com."),
            Some("example.com".to_string())
        );
        assert_eq!(
            normalize_host("..example.com.."),
            Some("example.com".to_string())
        );
    }

    #[test]
    fn test_normalize_host_whitespace_only() {
        assert_eq!(normalize_host("   "), None);
        assert_eq!(normalize_host(" . "), None);
    }

    #[test]
    fn test_normalize_host_bracketed_ipv6() {
        assert_eq!(normalize_host("[::1]:8080"), Some("::1".to_string()));
        assert_eq!(
            normalize_host("https://[::1]:443/path"),
            Some("::1".to_string())
        );
    }

    #[test]
    fn test_normalize_host_empty_bracketed_ipv6() {
        assert_eq!(normalize_host("[]"), None);
    }

    #[test]
    fn test_normalize_host_bare_ipv6() {
        // Non-bracketed IPv6 -- colons not stripped since it looks like IPv6
        let result = normalize_host("::1");
        assert_eq!(result, Some("::1".to_string()));
    }

    #[test]
    fn test_domains_match_both_empty() {
        assert!(!domains_match("", ""));
        assert!(!domains_match("", "example.com"));
        assert!(!domains_match("example.com", ""));
    }

    #[test]
    fn test_domains_match_different_schemes() {
        assert!(domains_match(
            "http://example.com",
            "https://example.com/login"
        ));
    }

    #[test]
    fn test_domains_match_with_ports() {
        assert!(domains_match(
            "example.com:8443",
            "https://example.com:443/"
        ));
    }

    #[test]
    fn test_vault_state_unlocked() {
        let state = VaultState::Unlocked;
        assert!(matches!(state, VaultState::Unlocked));
    }

    #[test]
    fn test_credential_response_fields() {
        let resp = CredentialResponse {
            username: "alice".to_string(),
            password: "secret".to_string(),
            title: "Test Cred".to_string(),
        };
        assert_eq!(resp.username, "alice");
        assert_eq!(resp.password, "secret");
        assert_eq!(resp.title, "Test Cred");
    }

    #[test]
    fn test_totp_code_response_fields() {
        let resp = TotpCodeResponse {
            code: "123456".to_string(),
            seconds_remaining: 15,
        };
        assert_eq!(resp.code, "123456");
        assert_eq!(resp.seconds_remaining, 15);
    }
}
