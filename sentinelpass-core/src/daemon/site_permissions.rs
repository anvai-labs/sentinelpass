//! Per-site autofill permissions (WBS-712, TD-CLIENT-05).
//!
//! WBS-711 made the daemon default-deny autofill delivery for plain-HTTP
//! and unverifiable origins. This store is the ONLY allow-list: an entry
//! means the user explicitly granted plain-HTTP autofill for one host via
//! the extension popup ("Allow on HTTP — not recommended").
//!
//! Contract:
//! - DEFAULT DENY. A missing store, a missing host, or any parse error
//!   denies — the scheme gate stays fail-closed without the store.
//! - EXACT-HOST grants, normalized with [`crate::domain::normalize_host`]
//!   (the same normalization the vault lookup uses). No suffix matching:
//!   a grant for `example.com` does NOT cover `sub.example.com` (broader
//!   reach than the user saw when granting) and certainly not
//!   `evil-example.com`.
//! - `https:` origins never consult this store — they always deliver.
//! - Grants are visible and revocable from the popup; revocation deletes
//!   the entry immediately.
//!
//! Honest scope (mirrors the capability store, ADR-003 rev 2): the store is
//! same-user readable like every other local file, and the grant decision
//! rides the same native-host capability as every other browser-surface
//! op — this is a safety brake against careless credential delivery, not a
//! defense against same-user code.

use crate::platform::create_owner_only_file;
use crate::{DatabaseError, PasswordManagerError, Result};
use serde::{Deserialize, Serialize};
use std::path::{Path, PathBuf};

/// One persisted per-site grant.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SitePermission {
    /// Normalized bare host (lowercase, no port/path/userinfo).
    pub host: String,
    /// The only grant kind today: explicit consent to plain-HTTP autofill.
    pub allow_insecure: bool,
    /// Unix seconds — when the grant was first made.
    pub granted_at: i64,
    /// Unix seconds — last confirmation (re-granting refreshes this).
    pub updated_at: i64,
}

/// Persisted store (`<config dir>/PasswordManager/site_permissions.json`,
/// 0600). Missing file = empty store = deny.
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct SitePermissionStore {
    #[serde(default, rename = "permissions")]
    pub permissions: Vec<SitePermission>,
}

/// Default store path: `<config dir>/PasswordManager/site_permissions.json`.
pub fn default_store_path() -> PathBuf {
    crate::platform::get_config_dir().join("site_permissions.json")
}

/// Normalize a grant/check host EXACTLY the way the autofill gate's URL
/// parse does: the gate sees punycoded IDN hosts (special-scheme WHATWG
/// parsing), while bare `normalize_host`'s non-special dummy scheme does
/// not IDNA-encode. Parsing behind `https://` here keeps grant storage and
/// gate lookups in the same host alphabet (adversarial review F9).
fn normalize_grant_host(value: &str) -> Option<String> {
    let trimmed = value.trim();
    let candidate = if trimmed.contains("://") {
        trimmed.to_string()
    } else {
        format!("https://{trimmed}")
    };
    match url::Url::parse(&candidate) {
        Ok(parsed) if parsed.scheme() == "https" || parsed.scheme() == "http" => {
            let host = parsed.host_str()?.trim();
            if host.is_empty() {
                None
            } else {
                crate::domain::normalize_host(host)
            }
        }
        _ => crate::domain::normalize_host(trimmed),
    }
}

impl SitePermissionStore {
    pub fn load_from_path(path: &Path) -> Result<Self> {
        match std::fs::read(path) {
            Ok(bytes) => serde_json::from_slice(&bytes).map_err(|e| {
                PasswordManagerError::from(DatabaseError::Serialization(format!(
                    "site permission store unreadable: {e}"
                )))
            }),
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => Ok(Self::default()),
            Err(e) => Err(PasswordManagerError::Io(e)),
        }
    }

    pub fn save_to_path(&self, path: &Path) -> Result<()> {
        let json = serde_json::to_vec_pretty(self)
            .map_err(|e| PasswordManagerError::from(DatabaseError::Serialization(e.to_string())))?;
        // Owner-only FROM BIRTH (adversarial review F6): write through the
        // platform's owner-only creator (symlink/regular-file checks, 0600
        // at open) so a first grant never lands umask-loose even for a
        // moment; the mode repair below remains for pre-existing files.
        let mut file = crate::platform::create_owner_only_file(path).map_err(|e| {
            PasswordManagerError::from(DatabaseError::FileIo(format!(
                "failed to open site permission store owner-only: {e}"
            )))
        })?;
        use std::io::Write;
        file.write_all(&json).map_err(PasswordManagerError::Io)?;
        drop(file);
        crate::platform::set_owner_only_mode(path, false).map_err(|e| {
            PasswordManagerError::from(DatabaseError::FileIo(format!(
                "failed to tighten site permission store mode: {e}"
            )))
        })?;
        Ok(())
    }

    /// Whether plain-HTTP autofill is explicitly granted for `host`.
    /// Normalization failure or normalization mismatch denies.
    pub fn allows_insecure(&self, host: &str) -> bool {
        let Some(normalized) = normalize_grant_host(host) else {
            return false;
        };
        self.permissions
            .iter()
            .any(|p| p.allow_insecure && p.host == normalized)
    }

    /// Grant (or re-confirm) plain-HTTP autofill for `host`. Returns false
    /// when the host could not be normalized (refused — fail-closed).
    pub fn grant_insecure(&mut self, path: &Path, host: &str) -> Result<bool> {
        let Some(normalized) = normalize_grant_host(host) else {
            return Ok(false);
        };
        let now = chrono::Utc::now().timestamp();
        if let Some(existing) = self.permissions.iter_mut().find(|p| p.host == normalized) {
            existing.allow_insecure = true;
            existing.updated_at = now;
        } else {
            self.permissions.push(SitePermission {
                host: normalized,
                allow_insecure: true,
                granted_at: now,
                updated_at: now,
            });
        }
        self.save_to_path(path)?;
        Ok(true)
    }

    /// Revoke any grant for `host`. Returns whether an entry was removed.
    pub fn revoke(&mut self, path: &Path, host: &str) -> Result<bool> {
        let Some(normalized) = normalize_grant_host(host) else {
            return Ok(false);
        };
        let before = self.permissions.len();
        self.permissions.retain(|p| p.host != normalized);
        let removed = before != self.permissions.len();
        if removed {
            self.save_to_path(path)?;
        }
        Ok(removed)
    }

    /// All grants (normalized hosts), oldest grant first.
    pub fn list(&self) -> Vec<SitePermission> {
        let mut permissions = self.permissions.clone();
        permissions.sort_by_key(|p| (p.granted_at, p.host.clone()));
        permissions
    }
}

/// Ensure a store file exists so the popup's first list is a defined empty
/// set and the file mode is tightened from birth.
pub fn ensure_store_file(path: &Path) -> Result<()> {
    if !path.exists() {
        let mut file = create_owner_only_file(path)?;
        use std::io::Write;
        file.write_all(b"{\n  \"permissions\": []\n}")?;
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    fn temp_store() -> (tempfile::TempDir, PathBuf) {
        let tmp = tempfile::TempDir::new().unwrap();
        let path = tmp.path().join("site_permissions.json");
        (tmp, path)
    }

    /// Default deny: missing store denies; only an explicit grant allows.
    #[test]
    fn missing_store_denies_and_grant_allows() {
        let (tmp, path) = temp_store();
        let empty = SitePermissionStore::load_from_path(&path).unwrap();
        assert!(!empty.allows_insecure("example.com"));

        let mut store = SitePermissionStore::default();
        assert!(store.grant_insecure(&path, "example.com").unwrap());
        let loaded = SitePermissionStore::load_from_path(&path).unwrap();
        assert!(loaded.allows_insecure("example.com"));
        let _ = tmp;
    }

    /// Grants are exact-host: siblings and suffixes are NOT covered.
    #[test]
    fn grants_are_exact_host_not_suffix_wide() {
        let (_tmp, path) = temp_store();
        let mut store = SitePermissionStore::default();
        store.grant_insecure(&path, "example.com").unwrap();

        let loaded = SitePermissionStore::load_from_path(&path).unwrap();
        assert!(loaded.allows_insecure("example.com"));
        assert!(loaded.allows_insecure("https://Example.com:8080/login"));
        assert!(
            !loaded.allows_insecure("sub.example.com"),
            "a grant must not silently cover subdomains"
        );
        assert!(
            !loaded.allows_insecure("evil-example.com"),
            "sibling hosts must never match"
        );
        assert!(!loaded.allows_insecure("example.org"));
    }

    /// Unnormalizable hosts are refused for granting and denied for checks.
    #[test]
    fn unnormalizable_hosts_are_refused() {
        let (_tmp, path) = temp_store();
        let mut store = SitePermissionStore::default();
        assert!(!store.grant_insecure(&path, "").unwrap());
        assert!(!store.allows_insecure("   "));
    }

    /// Revocation deletes the entry immediately and survives a reload.
    #[test]
    fn revoke_is_immediate_and_durable() {
        let (_tmp, path) = temp_store();
        let mut store = SitePermissionStore::default();
        store.grant_insecure(&path, "example.com").unwrap();
        store.grant_insecure(&path, "other.example").unwrap();

        let mut loaded = SitePermissionStore::load_from_path(&path).unwrap();
        assert!(loaded.revoke(&path, "example.com").unwrap());
        // Revoking a host with no grant is a defined no-op (false).
        assert!(!loaded.revoke(&path, "example.com").unwrap());

        let reloaded = SitePermissionStore::load_from_path(&path).unwrap();
        assert!(!reloaded.allows_insecure("example.com"));
        assert!(
            reloaded.allows_insecure("other.example"),
            "unrelated grant survives"
        );
    }

    /// Re-granting an existing host refreshes updated_at without
    /// duplicating the entry.
    #[test]
    fn re_grant_is_an_upsert() {
        let (_tmp, path) = temp_store();
        let mut store = SitePermissionStore::default();
        store.grant_insecure(&path, "example.com").unwrap();
        store
            .grant_insecure(&path, "https://example.com/again")
            .unwrap();
        let loaded = SitePermissionStore::load_from_path(&path).unwrap();
        assert_eq!(loaded.permissions.len(), 1);
    }

    /// List is normalized and deterministic.
    #[test]
    fn list_is_normalized_and_sorted() {
        let (_tmp, path) = temp_store();
        let mut store = SitePermissionStore::default();
        store
            .grant_insecure(&path, "https://B.Example.com:443/x")
            .unwrap();
        store.grant_insecure(&path, "a.example.com").unwrap();
        let listed = store.list();
        assert_eq!(listed.len(), 2);
        assert_eq!(listed[0].host, "a.example.com");
        assert_eq!(listed[1].host, "b.example.com");
        assert!(listed.iter().all(|p| p.allow_insecure));
    }

    /// The store is born owner-only when created via the ensure helper.
    #[cfg(unix)]
    #[test]
    fn store_file_is_owner_only() {
        use std::os::unix::fs::PermissionsExt;

        let (_tmp, path) = temp_store();
        ensure_store_file(&path).unwrap();
        let mode = std::fs::metadata(&path).unwrap().permissions().mode() & 0o777;
        assert_eq!(mode, 0o600, "site permission store must be 0600");

        let loaded = SitePermissionStore::load_from_path(&path).unwrap();
        assert!(loaded.permissions.is_empty());
        assert!(!loaded.allows_insecure("example.com"));
    }
}
