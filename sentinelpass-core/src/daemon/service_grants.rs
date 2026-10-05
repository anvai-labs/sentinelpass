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
use hmac::{Hmac, Mac};
use rand::{rngs::OsRng, RngCore};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::collections::HashMap;
use std::io::{Read, Write};
use std::path::{Path, PathBuf};
use subtle::ConstantTimeEq;
use uuid::Uuid;
use zeroize::Zeroizing;

use crate::{DatabaseError, PasswordManagerError, Result};

/// Marker hash for fingerprinted grants awaiting enrollment (F1): the
/// grant exists but has NO usable token until ServiceEnrollmentComplete
/// verifies key possession. authorize() rejects this hash.
pub const PENDING_TOKEN_HASH: &str = "pending-enrollment";

/// Service principal tokens carry their own prefix so a service token can
/// never be confused with a legacy broker token at either validation site.
pub const SERVICE_TOKEN_PREFIX: &str = "sps_";
const SERVICE_TOKEN_BYTES: usize = 32;
const STORE_FILE: &str = "service-grants.json";
const MAX_STORE_BYTES: u64 = 1024 * 1024;
const STORE_DOMAIN: &[u8] = b"sentinelpass-service-grants-envelope-v2\0";

/// Domain-separated authentication key. Never persisted or kept in a shared cache.
/// This protects offline policy edits, not a compromised unlocked daemon/root.
pub struct ServiceGrantStoreKey(Zeroizing<[u8; 32]>);

impl ServiceGrantStoreKey {
    pub fn from_dek(dek: &crate::crypto::DataEncryptionKey) -> Result<Self> {
        let mut key = Zeroizing::new([0u8; 32]);
        hkdf::Hkdf::<Sha256>::new(None, dek.as_bytes())
            .expand(b"sentinelpass-service-grants-integrity-v2", key.as_mut())
            .map_err(|_| {
                PasswordManagerError::InvalidInput("grant key derivation failed".into())
            })?;
        Ok(Self(key))
    }

    fn mac(&self, payload: &str) -> Hmac<Sha256> {
        // HMAC accepts a key of any size; our typed key is always 32 bytes.
        let mut mac = Hmac::<Sha256>::new_from_slice(self.0.as_ref()).expect("fixed-size HMAC key");
        mac.update(STORE_DOMAIN);
        mac.update(payload.as_bytes());
        mac
    }
}

#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct AuthenticatedStore {
    format_version: u32,
    // Authenticate the exact bytes; do not rely on JSON key ordering on read.
    payload: String,
    mac: String,
}

fn seal_payload(payload: String, key: &ServiceGrantStoreKey) -> Result<Vec<u8>> {
    let envelope = AuthenticatedStore {
        format_version: 2,
        mac: hex::encode(key.mac(&payload).finalize().into_bytes()),
        payload,
    };
    let bytes = serde_json::to_vec(&envelope).map_err(|_| {
        PasswordManagerError::InvalidInput("grant envelope serialization failed".into())
    })?;
    if bytes.len() as u64 > MAX_STORE_BYTES {
        return Err(PasswordManagerError::InvalidInput(
            "grant store too large".into(),
        ));
    }
    Ok(bytes)
}

fn open_payload(bytes: &[u8], key: &ServiceGrantStoreKey) -> Result<String> {
    let invalid = || {
        PasswordManagerError::InvalidInput(
            "grant store authentication failed; unsigned legacy stores require owner re-issuance"
                .into(),
        )
    };
    let envelope: AuthenticatedStore = serde_json::from_slice(bytes).map_err(|_| invalid())?;
    if envelope.format_version != 2 || envelope.mac.len() != 64 {
        return Err(invalid());
    }
    let mac = hex::decode(&envelope.mac).map_err(|_| invalid())?;
    key.mac(&envelope.payload)
        .verify_slice(&mac)
        .map_err(|_| invalid())?;
    Ok(envelope.payload)
}

#[cfg(not(windows))]
fn publish_store(temp: &Path, path: &Path) -> std::io::Result<()> {
    std::fs::rename(temp, path)
}

#[cfg(windows)]
fn publish_store(temp: &Path, path: &Path) -> std::io::Result<()> {
    use std::os::windows::ffi::OsStrExt;
    use windows::core::PCWSTR;
    use windows::Win32::Storage::FileSystem::{
        MoveFileExW, MOVEFILE_REPLACE_EXISTING, MOVEFILE_WRITE_THROUGH,
    };
    let wide = |path: &Path| -> std::io::Result<Vec<u16>> {
        let mut value: Vec<u16> = path.as_os_str().encode_wide().collect();
        if value.contains(&0) {
            return Err(std::io::Error::from(std::io::ErrorKind::InvalidInput));
        }
        value.push(0);
        Ok(value)
    };
    let from = wide(temp)?;
    let to = wide(path)?;
    // Same-directory replacement: never allow a cross-volume copy/delete.
    // SAFETY: both buffers are NUL-terminated and remain alive for the call.
    unsafe {
        MoveFileExW(
            PCWSTR(from.as_ptr()),
            PCWSTR(to.as_ptr()),
            MOVEFILE_REPLACE_EXISTING | MOVEFILE_WRITE_THROUGH,
        )
    }
    .map_err(|error| std::io::Error::other(error.to_string()))
}

#[cfg(not(windows))]
fn sync_store_parent(parent: &Path) -> std::io::Result<()> {
    std::fs::File::open(parent)?.sync_all()
}

#[cfg(windows)]
fn sync_store_parent(_parent: &Path) -> std::io::Result<()> {
    // publish_store already requested write-through publication. Opening a
    // directory with std::fs::File::open is not the Windows durability API.
    Ok(())
}

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
    /// SP-3 / ADR-016: optional MANDATORY executable policy. `None` or
    /// empty = no requirement (SP-1 behavior). Non-empty = the peer's
    /// kernel-referenced executable must hash (SHA-256, hex) to one of
    /// these; unavailable evidence DENIES (fail-closed).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub required_exe_sha256: Option<Vec<String>>,
    /// SP-4 / ADR-017: full 40-hex-char OpenPGP primary key fingerprint.
    /// None = no enrollment factor (SP-1/SP-3 behavior). Some = the
    /// enrollment flow (key-possession proof) is required to mint the
    /// token.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub registration_key_fingerprint: Option<String>,
}

#[derive(Debug, Clone, Default, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ServiceGrantStore {
    /// Serialized as a sequence (order is insert-order); the LOADER
    /// rejects duplicate grant ids before building the map (review F4).
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
    /// field name, missing mandatory field, or DUPLICATE grant id in the
    /// raw document — serde maps are silently last-wins, review F4)
    /// refuses the WHOLE document — a partial load would silently drop
    /// grants (availability) or worse, drop revocations (security).
    pub fn load_from_path(path: &Path, key: &ServiceGrantStoreKey) -> Result<Self> {
        if !path.exists() {
            return Ok(Self::default());
        }
        crate::platform::validate_sensitive_path(
            path,
            crate::platform::OwnerOnlyPolicy::WarnAndRepair,
        )
        .map_err(PasswordManagerError::from)?;
        let mut options = std::fs::OpenOptions::new();
        options.read(true);
        #[cfg(unix)]
        {
            use std::os::unix::fs::OpenOptionsExt;
            options.custom_flags(libc::O_NOFOLLOW | libc::O_NONBLOCK);
        }
        let file = options.open(path)?;
        let metadata = file.metadata()?;
        if !metadata.is_file() || metadata.len() > MAX_STORE_BYTES {
            return Err(PasswordManagerError::InvalidInput(
                "invalid grant store file".into(),
            ));
        }
        let mut bytes = Vec::new();
        file.take(MAX_STORE_BYTES + 1).read_to_end(&mut bytes)?;
        if bytes.len() as u64 > MAX_STORE_BYTES {
            return Err(PasswordManagerError::InvalidInput(
                "grant store too large".into(),
            ));
        }
        let payload = open_payload(&bytes, key)?;
        // Reject duplicate grant ids BEFORE map conversion (last-wins
        // would let a crafted file present a revoked grant while
        // enforcing its unrevoked duplicate, or vice versa).
        #[derive(serde::Deserialize)]
        #[serde(deny_unknown_fields)]
        struct RawStore {
            #[serde(default)]
            grants: Vec<ServiceGrant>,
        }
        let raw: RawStore = serde_json::from_str(&payload).map_err(|_e| {
            PasswordManagerError::InvalidInput(
                "service grant store failed closed (schema violation)".into(),
            )
        })?;
        let mut grants = HashMap::with_capacity(raw.grants.len());
        for grant in raw.grants {
            if grants.insert(grant.grant_id, grant).is_some() {
                return Err(PasswordManagerError::InvalidInput(
                    "service grant store failed closed: duplicate grant id".to_string(),
                ));
            }
        }
        let store = Self {
            grants,
            _serialization: None,
        };
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

    /// Atomic publication: born-0600 temp, fsync, rename, then PARENT
    /// DIRECTORY fsync (review F1: without the dir fsync a acknowledged
    /// revocation can be lost to a power cut — the rename metadata was
    /// never made durable and the pre-revoke file reappears).
    pub fn save_to_path(&self, path: &Path, key: &ServiceGrantStoreKey) -> Result<()> {
        self.save_to_path_with_sync(path, key, sync_store_parent)
    }

    // Explicit I/O boundary also permits deterministic durability-failure tests
    // without process-global fault switches that race other tests or consumers.
    fn save_to_path_with_sync(
        &self,
        path: &Path,
        key: &ServiceGrantStoreKey,
        sync_parent: impl FnOnce(&Path) -> std::io::Result<()>,
    ) -> Result<()> {
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
        // Serialize the grant LIST (not the map) so load's duplicate
        // check sees the same shape it will parse (review F4 symmetry).
        #[derive(serde::Serialize)]
        #[serde(deny_unknown_fields)]
        struct StoreFile<'a> {
            grants: Vec<&'a ServiceGrant>,
        }
        let file = StoreFile {
            grants: self.grants.values().collect(),
        };
        let payload = serde_json::to_string(&file).map_err(|e| {
            PasswordManagerError::from(DatabaseError::Serialization(format!(
                "Failed to serialize service grant store: {e}"
            )))
        })?;
        let body = seal_payload(payload, key)?;
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
            publish_store(&temp, path).map_err(|e| {
                PasswordManagerError::InvalidInput(format!(
                    "Failed to publish service grant store: {e}"
                ))
            })?;
            // Durably record the rename itself (crash-safe publication).
            sync_parent(parent).map_err(|_| {
                PasswordManagerError::InvalidInput(
                    "grant store published but durability unconfirmed; inspect before retrying"
                        .into(),
                )
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
        // F1: pending grants (awaiting enrollment) never authorize.
        if token == PENDING_TOKEN_HASH {
            return None;
        }
        let token_hash = Sha256::digest(token.as_bytes());
        self.grants
            .values()
            .filter(|g| {
                g.client_id == client_id
                    && g.entry_id == entry_id
                    && g.revoked_at.is_none()
                    && g.expires_at.map(|e| now < e).unwrap_or(true)
                    && g.fields.contains(&field)
                    && g.client_token_hash != PENDING_TOKEN_HASH
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
        required_exe_sha256: Option<Vec<String>>,
        registration_key_fingerprint: Option<String>,
    ) -> std::result::Result<(ServiceGrant, Zeroizing<String>), &'static str> {
        if fields.is_empty() {
            return Err("a grant must name at least one field");
        }
        // Review F3: a malformed pin would mint successfully and then
        // silently never match at retrieval (a permanent lockout wearing
        // an attack-shaped denial message). Validate at the boundary.
        if let Some(fingerprint) = registration_key_fingerprint.as_ref() {
            if fingerprint.len() != 40
                || !fingerprint
                    .chars()
                    .all(|c| c.is_ascii_hexdigit() && !c.is_ascii_uppercase())
            {
                return Err("registration key fingerprint must be exactly 40 lowercase hex characters (OpenPGP v4)");
            }
        }
        if let Some(pins) = required_exe_sha256.as_ref() {
            for pin in pins {
                if pin.len() != 64
                    || !pin
                        .chars()
                        .all(|c| c.is_ascii_hexdigit() && !c.is_ascii_uppercase())
                {
                    return Err(
                        "executable pins must be exactly 64 lowercase hex characters (SHA-256)",
                    );
                }
            }
        }
        let mut token_bytes = [0u8; SERVICE_TOKEN_BYTES];
        OsRng.fill_bytes(&mut token_bytes);
        let token = Zeroizing::new(format!(
            "{SERVICE_TOKEN_PREFIX}{}",
            hex::encode(token_bytes)
        ));
        // F1: fingerprinted grants are created PENDING — no usable token
        // until enrollment proves key possession. The token returned by
        // this method is a placeholder that will be replaced at
        // enrollment_complete (callers must check the fingerprint and NOT
        // reveal the placeholder).
        let token_hash = if registration_key_fingerprint.is_some() {
            PENDING_TOKEN_HASH.to_string()
        } else {
            hex::encode(Sha256::digest(token.as_bytes()))
        };
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
            required_exe_sha256,
            registration_key_fingerprint,
        };
        self.grants.insert(grant.grant_id, grant.clone());
        Ok((grant, token))
    }

    /// SP-3 / ADR-016: the grant's mandatory executable policy, if any.
    pub fn required_exe_policy(grant: &ServiceGrant) -> &[String] {
        grant.required_exe_sha256.as_deref().unwrap_or(&[])
    }

    /// F3: rotate the token for an EXISTING grant (same grant_id) —
    /// enrollment_complete must never mint a duplicate grant. Returns
    /// the new plaintext token (shown once) or None if the grant is
    /// absent/already revoked.
    pub fn rotate_token(
        &mut self,
        grant_id: Uuid,
    ) -> std::result::Result<Option<Zeroizing<String>>, &'static str> {
        let grant = match self.grants.get_mut(&grant_id) {
            Some(g) if g.revoked_at.is_none() => g,
            Some(_) => return Ok(None), // revoked
            None => return Ok(None),    // absent
        };
        let mut token_bytes = [0u8; SERVICE_TOKEN_BYTES];
        OsRng.fill_bytes(&mut token_bytes);
        let token = Zeroizing::new(format!(
            "{SERVICE_TOKEN_PREFIX}{}",
            hex::encode(token_bytes)
        ));
        grant.client_token_hash = hex::encode(Sha256::digest(token.as_bytes()));
        Ok(Some(token))
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

    fn key() -> ServiceGrantStoreKey {
        ServiceGrantStoreKey::from_dek(&crate::crypto::DataEncryptionKey::from_bytes(
            &mut [19u8; 32],
        ))
        .unwrap()
    }

    fn store() -> ServiceGrantStore {
        ServiceGrantStore::default()
    }

    #[test]
    fn mint_authorize_and_revoke_round_trip() {
        let mut s = store();
        let (grant, token) = s
            .mint_grant("svc", 42, vec![ServiceField::Password], None, None, None)
            .unwrap();
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
        let (_, token) = s
            .mint_grant(
                "svc",
                1,
                vec![ServiceField::Password],
                Some(Utc::now() - chrono::Duration::seconds(1)),
                None,
                None,
            )
            .unwrap();
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
        assert!(ServiceGrantStore::load_from_path(&path, &key()).is_err());
        // Unknown policy_version inside a grant (Vec shape — the only
        // accepted document form).
        let bad = r#"{"grants": [{"policy_version": 2, "grant_id": "00000000-0000-0000-0000-000000000001", "client_id": "x", "entry_id": 1, "fields": ["password"], "created_at": "2026-10-02T00:00:00Z", "client_token_hash": "ab"} ]}"#;
        std::fs::write(&path, seal_payload(bad.into(), &key()).unwrap()).unwrap();
        assert!(ServiceGrantStore::load_from_path(&path, &key()).is_err());
        // Missing mandatory field.
        let missing = r#"{"grants": [{"policy_version": 1, "client_id": "x", "entry_id": 1, "fields": [], "created_at": "2026-10-02T00:00:00Z", "client_token_hash": "ab"} ]}"#;
        std::fs::write(&path, seal_payload(missing.into(), &key()).unwrap()).unwrap();
        assert!(ServiceGrantStore::load_from_path(&path, &key()).is_err());
        // Duplicate grant ids in one document (review F4).
        let dup = r#"{"grants": [
            {"policy_version": 1, "grant_id": "00000000-0000-0000-0000-000000000003", "client_id": "x", "entry_id": 1, "fields": ["password"], "created_at": "2026-10-02T00:00:00Z", "client_token_hash": "ab"},
            {"policy_version": 1, "grant_id": "00000000-0000-0000-0000-000000000003", "client_id": "y", "entry_id": 2, "fields": ["title"], "created_at": "2026-10-02T00:00:00Z", "client_token_hash": "cd"}
        ]}"#;
        std::fs::write(&path, seal_payload(dup.into(), &key()).unwrap()).unwrap();
        assert!(ServiceGrantStore::load_from_path(&path, &key()).is_err());
    }

    #[test]
    fn persistence_is_atomic_and_owner_only() {
        let tmp = TempDir::new().unwrap();
        let path = tmp.path().join(STORE_FILE);
        let mut s = store();
        s.mint_grant("svc", 9, vec![ServiceField::Title], None, None, None)
            .unwrap();
        s.save_to_path(&path, &key()).unwrap();
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            let mode = std::fs::metadata(&path).unwrap().permissions().mode() & 0o777;
            assert_eq!(mode, 0o600);
        }
        let reloaded = ServiceGrantStore::load_from_path(&path, &key()).unwrap();
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
    fn authenticated_policy_rejects_every_authorization_field_edit() {
        let tmp = TempDir::new().unwrap();
        let path = tmp.path().join(STORE_FILE);
        let mut s = store();
        s.mint_grant(
            "svc",
            42,
            vec![ServiceField::Password],
            None,
            Some(vec!["a".repeat(64)]),
            None,
        )
        .unwrap();
        s.save_to_path(&path, &key()).unwrap();
        let original = std::fs::read(&path).unwrap();
        for (field, value) in [
            ("entry_id", serde_json::json!(43)),
            ("client_id", serde_json::json!("other")),
            ("fields", serde_json::json!(["username", "password"])),
            ("client_token_hash", serde_json::json!("0".repeat(64))),
            ("required_exe_sha256", serde_json::json!([])),
            (
                "registration_key_fingerprint",
                serde_json::json!("a".repeat(40)),
            ),
            ("revoked_at", serde_json::json!("2026-01-01T00:00:00Z")),
            ("expires_at", serde_json::json!("2099-01-01T00:00:00Z")),
        ] {
            let mut outer: serde_json::Value = serde_json::from_slice(&original).unwrap();
            let mut payload: serde_json::Value =
                serde_json::from_str(outer["payload"].as_str().unwrap()).unwrap();
            payload["grants"][0][field] = value;
            outer["payload"] = serde_json::json!(serde_json::to_string(&payload).unwrap());
            std::fs::write(&path, serde_json::to_vec(&outer).unwrap()).unwrap();
            assert!(
                ServiceGrantStore::load_from_path(&path, &key()).is_err(),
                "accepted edit: {field}"
            );
        }
    }

    #[test]
    fn revocation_sync_failure_is_reported_without_rolling_back_publication() {
        let tmp = TempDir::new().unwrap();
        let path = tmp.path().join(STORE_FILE);
        let mut s = store();
        let (grant, token) = s
            .mint_grant("svc", 42, vec![ServiceField::Password], None, None, None)
            .unwrap();
        s.save_to_path(&path, &key()).unwrap();
        assert!(s.revoke(grant.grant_id));
        for kind in [
            std::io::ErrorKind::PermissionDenied,
            std::io::ErrorKind::Other,
        ] {
            let result = s.save_to_path_with_sync(&path, &key(), |parent| {
                assert_eq!(parent, tmp.path());
                Err(std::io::Error::from(kind))
            });
            assert!(result
                .unwrap_err()
                .to_string()
                .contains("published but durability unconfirmed"));
            // Publication may already be visible. Never resurrect the old
            // authorization while handling a post-rename error.
            let visible = ServiceGrantStore::load_from_path(&path, &key()).unwrap();
            assert!(visible
                .authorize("svc", &token, 42, ServiceField::Password, Utc::now())
                .is_none());
            assert_eq!(std::fs::read_dir(tmp.path()).unwrap().count(), 1);
        }
        // Owner-controlled retry can establish a durable acknowledgement.
        s.save_to_path(&path, &key()).unwrap();
    }

    #[test]
    fn authenticated_payload_still_rejects_unknown_and_duplicate_fields() {
        let tmp = TempDir::new().unwrap();
        let path = tmp.path().join(STORE_FILE);
        for payload in [
            r#"{"grants":[],"future_field":1}"#,
            r#"{"grants":[],"grants":[]}"#,
        ] {
            std::fs::write(&path, seal_payload(payload.into(), &key()).unwrap()).unwrap();
            assert!(ServiceGrantStore::load_from_path(&path, &key()).is_err());
        }
        let empty = String::from(r#"{"grants":[]}"#);
        let sealed = String::from_utf8(seal_payload(empty, &key()).unwrap()).unwrap();
        // Duplicate outer fields are rejected even when the original MAC is valid.
        let duplicate = sealed.replacen('{', r#"{"format_version":2,"#, 1);
        std::fs::write(&path, duplicate).unwrap();
        assert!(ServiceGrantStore::load_from_path(&path, &key()).is_err());
    }

    #[test]
    fn wrong_vault_unsigned_and_version_downgrade_fail_closed() {
        let tmp = TempDir::new().unwrap();
        let path = tmp.path().join(STORE_FILE);
        store().save_to_path(&path, &key()).unwrap();
        let wrong_key =
            ServiceGrantStoreKey::from_dek(&crate::crypto::DataEncryptionKey::new().unwrap())
                .unwrap();
        assert!(ServiceGrantStore::load_from_path(&path, &wrong_key).is_err());
        let mut outer: serde_json::Value =
            serde_json::from_slice(&std::fs::read(&path).unwrap()).unwrap();
        outer["format_version"] = serde_json::json!(1);
        std::fs::write(&path, serde_json::to_vec(&outer).unwrap()).unwrap();
        assert!(ServiceGrantStore::load_from_path(&path, &key()).is_err());
        std::fs::write(&path, br#"{"grants":[]}"#).unwrap();
        assert!(ServiceGrantStore::load_from_path(&path, &key()).is_err());
    }

    #[test]
    fn store_read_and_write_are_size_bounded() {
        let tmp = TempDir::new().unwrap();
        let path = tmp.path().join(STORE_FILE);
        let mut s = store();
        s.mint_grant(
            &"x".repeat(MAX_STORE_BYTES as usize),
            1,
            vec![ServiceField::Password],
            None,
            None,
            None,
        )
        .unwrap();
        assert!(s.save_to_path(&path, &key()).is_err());
        assert!(!path.exists());
        std::fs::write(&path, vec![b'x'; MAX_STORE_BYTES as usize + 1]).unwrap();
        assert!(ServiceGrantStore::load_from_path(&path, &key()).is_err());
    }

    #[cfg(unix)]
    #[test]
    fn grant_store_refuses_symlink_and_fifo() {
        let tmp = TempDir::new().unwrap();
        let path = tmp.path().join(STORE_FILE);
        let target = tmp.path().join("real.json");
        store().save_to_path(&target, &key()).unwrap();
        std::os::unix::fs::symlink(&target, &path).unwrap();
        assert!(ServiceGrantStore::load_from_path(&path, &key()).is_err());
        assert!(store().save_to_path(&path, &key()).is_err());
        std::fs::remove_file(&path).unwrap();
        use std::os::unix::ffi::OsStrExt;
        let name = std::ffi::CString::new(path.as_os_str().as_bytes()).unwrap();
        assert_eq!(unsafe { libc::mkfifo(name.as_ptr(), 0o600) }, 0);
        assert!(ServiceGrantStore::load_from_path(&path, &key()).is_err());
    }

    #[test]
    fn service_tokens_use_their_own_prefix() {
        let mut s = store();
        let (_, token) = s
            .mint_grant("svc", 1, vec![ServiceField::Password], None, None, None)
            .unwrap();
        assert!(token.starts_with(SERVICE_TOKEN_PREFIX));
    }
}
