//! Daemon-side capability store and verification (WBS-504/505/506,
//! ADR-007, SR-IPC-003).
//!
//! Capabilities replace the self-asserted origin label as the authority for
//! the browser/native-host surface. A capability binds:
//!
//! - `audience` — who may present it (`native-host`, a client id, ...);
//! - `secret` — 32 random bytes shown/stored ONCE; only the SHA-256 digest
//!   is persisted, so the store file alone cannot present the capability;
//! - `issued_at` / `expires_at` — lifetime bounds;
//! - `nonce` — random id that makes every mint distinct.
//!
//! Grants persist in the daemon store (`<config>/ipc-capabilities.json`,
//! 0600) and survive restarts; deleting an entry revokes it immediately
//! ("restart does not silently resurrect revoked grants" — ADR-007).
//!
//! Honest scope (ADR-003 rev 2 damage limitation): the native-host
//! installation capability is same-user readable like every other local
//! secret, and its resource scope is effectively all domains. It removes
//! the ambient "any token-bearing process can claim NativeHost" surface —
//! a hardening boundary, not a defense against same-user code.

use crate::platform::create_owner_only_file;
use crate::{DatabaseError, PasswordManagerError, Result};
use rand::{rngs::OsRng, RngCore};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::path::{Path, PathBuf};
use subtle::ConstantTimeEq;
use zeroize::Zeroizing;

/// Audience of the browser/native-host installation capability.
pub const NATIVE_HOST_AUDIENCE: &str = "native-host";

/// One persisted capability (secret stored hashed).
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Capability {
    pub audience: String,
    /// SHA-256 of the presented secret, hex.
    pub secret_hash: String,
    /// Unix seconds.
    pub issued_at: i64,
    /// Unix seconds; None = never expires.
    pub expires_at: Option<i64>,
    /// Random mint id — distinct per mint, never reused.
    pub nonce: String,
}

/// Persisted capability store (WBS-504: grants persist; restart does not
/// resurrect revoked grants — revocation is deleting the entry).
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct InstallationCapabilities {
    #[serde(default, rename = "capabilities")]
    pub capabilities: Vec<Capability>,
}

/// Default store path: `<config dir>/PasswordManager/ipc-capabilities.json`.
pub fn default_store_path() -> PathBuf {
    crate::platform::get_config_dir().join("ipc-capabilities.json")
}

/// Path of the native-host installation capability SECRET
/// (`<config dir>/PasswordManager/native_host.capability`, 0600) — the one
/// file the native host reads and presents.
pub fn native_host_capability_path() -> PathBuf {
    crate::platform::get_config_dir().join("native_host.capability")
}

impl InstallationCapabilities {
    pub fn load_from_path(path: &Path) -> Result<Self> {
        match std::fs::read(path) {
            Ok(bytes) => serde_json::from_slice(&bytes).map_err(|e| {
                PasswordManagerError::from(DatabaseError::Serialization(format!(
                    "capability store unreadable: {e}"
                )))
            }),
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => Ok(Self::default()),
            Err(e) => Err(PasswordManagerError::Io(e)),
        }
    }

    pub fn save_to_path(&self, path: &Path) -> Result<()> {
        let json = serde_json::to_vec_pretty(self)
            .map_err(|e| PasswordManagerError::from(DatabaseError::Serialization(e.to_string())))?;
        std::fs::write(path, json).map_err(PasswordManagerError::Io)?;
        crate::platform::set_owner_only_mode(path, false).map_err(|e| {
            PasswordManagerError::from(DatabaseError::FileIo(format!(
                "failed to tighten capability store mode: {e}"
            )))
        })?;
        Ok(())
    }

    /// Mint a capability for `audience` and return the PRESENTED SECRET
    /// (shown/stored once; only its hash is persisted). Rotation semantics
    /// (stage-6 review F4): minting for an audience REPLACES all prior
    /// entries for that audience, so stale secrets lose authority instead
    /// of accumulating.
    pub fn mint(
        &mut self,
        path: &Path,
        audience: &str,
        expires_at: Option<i64>,
    ) -> Result<Zeroizing<String>> {
        let mut secret_bytes = [0u8; 32];
        OsRng.fill_bytes(&mut secret_bytes);
        let secret = Zeroizing::new(hex::encode(secret_bytes));
        let mut nonce = [0u8; 16];
        OsRng.fill_bytes(&mut nonce);

        self.capabilities
            .retain(|capability| capability.audience != audience);
        self.capabilities.push(Capability {
            audience: audience.to_string(),
            secret_hash: hex::encode(Sha256::digest(secret.as_bytes())),
            issued_at: chrono::Utc::now().timestamp(),
            expires_at,
            nonce: hex::encode(nonce),
        });
        self.save_to_path(path)?;
        Ok(secret)
    }

    /// Revoke every capability for an audience. Returns how many were
    /// removed.
    pub fn revoke(&mut self, path: &Path, audience: &str) -> Result<usize> {
        let before = self.capabilities.len();
        self.capabilities
            .retain(|capability| capability.audience != audience);
        let removed = before - self.capabilities.len();
        if removed > 0 {
            self.save_to_path(path)?;
        }
        Ok(removed)
    }

    /// Verify a presented secret for an audience (WBS-504 negative suite:
    /// wrong audience, wrong secret, expired, and revoked all deny).
    pub fn verify(&self, audience: &str, presented: Option<&str>) -> bool {
        let Some(presented) = presented else {
            return false;
        };
        if presented.is_empty() {
            return false;
        }
        let presented_hash = Sha256::digest(presented.as_bytes());
        let now = chrono::Utc::now().timestamp();
        self.capabilities.iter().any(|capability| {
            if capability.audience != audience {
                return false; // wrong audience
            }
            if capability
                .expires_at
                .is_some_and(|expires_at| now >= expires_at)
            {
                return false; // expired
            }
            let stored = match hex::decode(&capability.secret_hash) {
                Ok(bytes) => bytes,
                Err(_) => return false,
            };
            // Constant-time compare of the digests.
            bool::from(stored.ct_eq(&presented_hash))
        })
    }
}

/// Ensure the native-host installation capability exists, minting one on
/// first daemon start (WBS-505). Returns the store path; the secret file is
/// written 0600 for the host to read.
pub fn ensure_native_host_capability() -> Result<PathBuf> {
    let secret_path = native_host_capability_path();
    if !secret_path.exists() {
        // Fresh-install case: create the config dir owner-only before any
        // store/secret write (WBS-719 E2E catch — an empty isolated HOME
        // refused the whole daemon start).
        if let Some(parent) = secret_path.parent() {
            if !parent.exists() {
                crate::platform::create_private_dir(parent).map_err(|e| {
                    PasswordManagerError::from(DatabaseError::FileIo(format!(
                        "failed to create the capability directory {}: {e}",
                        parent.display()
                    )))
                })?;
            }
        }
        let mut store = InstallationCapabilities::load_from_path(&default_store_path())?;
        let secret = store.mint(&default_store_path(), NATIVE_HOST_AUDIENCE, None)?;
        // Write the presented secret 0600 (owner-only from birth, symlink
        // refused) for the native host process to read.
        let mut file = create_owner_only_file(&secret_path)?;
        use std::io::Write;
        file.write_all(secret.as_bytes()).map_err(|e| {
            PasswordManagerError::from(DatabaseError::FileIo(format!(
                "failed to write native host capability: {e}"
            )))
        })?;
    }
    Ok(secret_path)
}

/// Load the presented native-host capability secret (host side; mirrored in
/// the protocol crate for clients that must not link core).
pub fn load_native_host_capability() -> Option<String> {
    std::fs::read_to_string(native_host_capability_path())
        .ok()
        .map(|s| s.trim().to_string())
        .filter(|s| !s.is_empty())
}

#[cfg(test)]
mod tests {
    use super::*;

    fn temp_store() -> (tempfile::TempDir, PathBuf) {
        let tmp = tempfile::TempDir::new().unwrap();
        let path = tmp.path().join("ipc-capabilities.json");
        (tmp, path)
    }

    /// WBS-504 positive: a minted capability verifies for its audience.
    #[test]
    fn minted_capability_verifies() {
        let (_tmp, path) = temp_store();
        let mut store = InstallationCapabilities::default();
        let secret = store.mint(&path, NATIVE_HOST_AUDIENCE, None).unwrap();

        let store = InstallationCapabilities::load_from_path(&path).unwrap();
        assert!(store.verify(NATIVE_HOST_AUDIENCE, Some(secret.as_str())));
    }

    /// WBS-504 negatives: wrong audience, wrong secret, expired, and
    /// revoked (deleted) capabilities are all denied.
    #[test]
    fn wrong_audience_wrong_secret_expired_revoked_denied() {
        let (_tmp, path) = temp_store();
        let mut store = InstallationCapabilities::default();
        let secret = store.mint(&path, NATIVE_HOST_AUDIENCE, None).unwrap();

        // Wrong audience: the same secret does NOT verify for another
        // audience.
        let loaded = InstallationCapabilities::load_from_path(&path).unwrap();
        assert!(!loaded.verify("desktop-ui", Some(secret.as_str())));

        // Wrong secret.
        assert!(!loaded.verify(NATIVE_HOST_AUDIENCE, Some("deadbeef")));

        // Missing presentation.
        assert!(!loaded.verify(NATIVE_HOST_AUDIENCE, None));
        assert!(!loaded.verify(NATIVE_HOST_AUDIENCE, Some("")));

        // Expired: mint with expires_at in the past.
        store.capabilities.push(Capability {
            audience: NATIVE_HOST_AUDIENCE.to_string(),
            secret_hash: hex::encode(Sha256::digest(b"expired-secret")),
            issued_at: 0,
            expires_at: Some(1), // 1970 — expired
            nonce: "expired-nonce".to_string(),
        });
        store.save_to_path(&path).unwrap();
        let loaded = InstallationCapabilities::load_from_path(&path).unwrap();
        assert!(!loaded.verify(NATIVE_HOST_AUDIENCE, Some("expired-secret")));

        // Revoked: deleting the entry denies immediately — and a restart
        // (reload from disk) does not resurrect it.
        let mut loaded = loaded;
        assert_eq!(loaded.revoke(&path, NATIVE_HOST_AUDIENCE).unwrap(), 2);
        let reloaded = InstallationCapabilities::load_from_path(&path).unwrap();
        assert!(!reloaded.verify(NATIVE_HOST_AUDIENCE, Some(secret.as_str())));
    }

    /// Store is born owner-only and stays verifiable across reload.
    #[cfg(unix)]
    #[test]
    fn store_is_owner_only_on_disk() {
        use std::os::unix::fs::PermissionsExt;

        let (_tmp, path) = temp_store();
        let mut store = InstallationCapabilities::default();
        let secret = store.mint(&path, NATIVE_HOST_AUDIENCE, None).unwrap();

        let mode = std::fs::metadata(&path).unwrap().permissions().mode() & 0o777;
        assert_eq!(mode, 0o600, "capability store must be 0600");

        let loaded = InstallationCapabilities::load_from_path(&path).unwrap();
        assert!(loaded.verify(NATIVE_HOST_AUDIENCE, Some(secret.as_str())));
    }
}
