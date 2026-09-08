//! Authenticated portable backup and verified restore
//! (WBS-416/417, ADR-008, SR-DATA-005).
//!
//! # Format (registered in docs/DURABLE_WIRE_FORMATS.md §6)
//!
//! A `.spbackup` bundle is ONE file:
//!
//! ```text
//! "SENTINELPASS-BACKUP/1\n"     fixed magic line
//! <manifest JSON> "\n"          compact canonical JSON, one line, <= MAX_MANIFEST_BYTES
//! <snapshot bytes>              exactly manifest.snapshot.len bytes
//! ```
//!
//! The snapshot is a `VACUUM INTO` copy of the live vault database taken
//! under the db lock (a consistent WAL-inclusive read snapshot per
//! ADR-008; the output is a standalone SQLite file, no sidecars). The
//! manifest is authenticated with HMAC-SHA256 under an HKDF-over-DEK key
//! (the key-slot registry MAC precedent, `slot_ops.rs`), and binds the
//! snapshot digest, vault UUID, epoch, schema/format versions, key-slot
//! inventory, and the exact durable key-material blobs. It contains NO
//! plaintext entry content — only operational metadata (counts, flags,
//! timestamps) per ADR-008's stated limits.
//!
//! # Verification order (fail closed)
//!
//! MAC verification precedes any state mutation. The DEK needed for the
//! MAC key comes from the manifest's own wrapped key material (the
//! snapshot's `db_metadata` blobs are mirrored into the manifest), so the
//! chain is: parse format → bounds → typed version gate → Argon2id +
//! unwrap manifest wrap (the password check) → constant-time MAC verify →
//! snapshot SHA-256 digest → ONLY THEN any staging/validation that
//! touches a database, and only AFTER full validation of a staged copy
//! does the live vault get replaced (WBS-417).
//!
//! # Restore atomicity (WBS-417)
//!
//! The database swap is a single `rename` of a fully validated staged
//! copy, with the live `-wal`/`-shm` sidecars removed as part of the swap
//! (after a TRUNCATE checkpoint, so the pre-swap main file is complete).
//! The epoch high-water sidecar is re-baselined as a SEQUENCED SECOND
//! step: its interruption leaves the refused-open rollback state with the
//! documented recovery (the refusal names the sidecar file; an
//! acknowledged re-restore or the ADR-004 rev 4 supervised override
//! completes it). Exactly one pre-restore snapshot is retained at
//! `<vault>.pre-restore`, replaced only after the restored state
//! verifies.
//!
//! # Operational constraints
//!
//! - Backup/restore require the unlocked DEK path (reauthentication by
//!   master password); restore is a STATIC path-based operation — no live
//!   `VaultManager` may hold the target while restoring. A concurrent
//!   daemon/UI connection is not detectable portably: on Windows the
//!   rename fails loudly (sharing violation, live state untouched); on
//!   POSIX the caller MUST close other SentinelPass processes first (the
//!   pre-swap TRUNCATE checkpoint refuses when it cannot complete).
//! - Restore refuses while the LIVE vault has sync enabled unless the
//!   caller passes the explicit disable acknowledgment (ADR-008 branch 2:
//!   disable sync and require re-pairing). The restored snapshot's own
//!   sync lineage is ALWAYS re-baselined: sync disabled, cursors zeroed,
//!   device identity/tombstones cleared — a restored device never reuses
//!   its old pull cursor against the old relay history.

use std::fs;
use std::io::{Read, Write};
use std::path::{Path, PathBuf};

use hkdf::Hkdf;
use hmac::{Hmac, Mac};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use zeroize::Zeroizing;

use crate::crypto::cipher::DataEncryptionKey;
use crate::crypto::{dbwire, KeyHierarchy};
use crate::{audit::AuditEventType, DatabaseError, PasswordManagerError, Result};

use super::VaultManager;

/// Fixed first line of every bundle (magic + container format version).
pub(crate) const BUNDLE_MAGIC_LINE: &str = "SENTINELPASS-BACKUP/1";

/// Manifest format version. ANY shape change bumps this; readers fail
/// closed on unknown versions (ADR-005: no downgrade path).
pub(crate) const BACKUP_MANIFEST_VERSION: i32 = 1;

/// Hard cap on the manifest JSON line, enforced BEFORE any parse. A
/// vault's slot history is the only unbounded input (revocations keep
/// rows); only USABLE slots are recorded, and 16 KiB accommodates far
/// more usable slots than the final-slot guard ever permits.
pub(crate) const MAX_MANIFEST_BYTES: usize = 16384;

/// Hard cap on the snapshot payload, enforced BEFORE allocation (the
/// length is read from the manifest, i.e. attacker-chosen input).
pub(crate) const MAX_SNAPSHOT_BYTES: usize = 1024 * 1024 * 1024; // 1 GiB

/// HKDF `info` label binding the bundle MAC key to its purpose
/// (key-separated from the DEK, the registry MAC key, and every other
/// HKDF consumer — same discipline as `SLOT_REGISTRY_MAC_INFO`).
pub(crate) const BACKUP_MANIFEST_MAC_INFO: &[u8] = b"sentinelpass-backup-manifest-mac-v1";

/// One usable key slot as recorded in the manifest (no key material —
/// the snapshot itself carries the wrapped rows; the manifest inventory
/// is what the MAC binds and what restore cross-checks the snapshot
/// against).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ManifestSlot {
    pub slot_uuid: String,
    /// Slot type string (`password`|`recovery`|`platform`|`trusted_device`).
    pub slot_type: String,
    pub key_epoch: i64,
    /// Always `false` in v1: only usable slots are recorded (bounded
    /// inventory; revocation history stays in the snapshot only).
    pub revoked: bool,
}

/// Snapshot integrity binding.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ManifestSnapshot {
    /// Hex SHA-256 of the snapshot bytes exactly as carried after the
    /// manifest line.
    pub sha256: String,
    /// Exact snapshot length in bytes. Reader enforces it twice: before
    /// allocating (hostile-length rejection) and after reading (trailing
    /// garbage / truncation rejection).
    pub len: u64,
}

/// The authenticated backup manifest (SPBACKUP, v1). Field declaration
/// order IS the wire order (canonical JSON profile). Binary fields are
/// standard padded base64 over the EXACT `db_metadata` column bytes, so
/// restore decodes them through the same bounded dual-read decoders the
/// database uses.
///
/// `Debug` is HAND-WRITTEN: the key-material fields are ciphertext, but
/// they are durable credentials — the derived impl would print them on
/// the first accidental `{:?}` (CLAUDE.md NEVER 1, same discipline as
/// `Entry`).
#[derive(Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct BackupManifest {
    /// Exactly `"SPBACKUP"`.
    pub magic: String,
    /// Exactly [`BACKUP_MANIFEST_VERSION`]; unknown versions fail closed.
    pub v: i32,
    /// Random per-bundle identifier — the audit trail's opaque reference.
    pub backup_id: String,
    /// Creation time (Unix seconds).
    pub created_at: i64,
    /// Creating binary's package version (creation metadata).
    pub app_version: String,
    /// Stable vault identity (WBS-301).
    pub vault_uuid: String,
    /// Master-password key epoch at backup time.
    pub epoch: i64,
    /// SQLite schema version of the snapshot.
    pub schema_version: i32,
    /// Envelope format version (`db_metadata.format_version`).
    pub vault_format_version: i64,
    /// Usable (non-deleted) entry record count — visible operational
    /// metadata per ADR-008.
    pub entry_count: i64,
    /// Tombstoned (soft-deleted) entry count.
    pub tombstone_count: i64,
    /// Exact `db_metadata.kdf_params` column bytes (base64).
    pub kdf_params: String,
    /// Exact `db_metadata.wrapped_dek` column bytes (base64).
    pub wrapped_dek: String,
    /// Exact `db_metadata.dek_nonce` column bytes (base64).
    pub dek_nonce: String,
    /// Exact `db_metadata.slot_registry_mac` column bytes, or `null` for
    /// a pre-bootstrap vault (the epoch digest treats NULL as empty).
    pub slot_registry_mac: Option<String>,
    /// Usable key-slot inventory (MAC-bound; cross-checked at restore).
    pub slots: Vec<ManifestSlot>,
    /// Snapshot integrity binding.
    pub snapshot: ManifestSnapshot,
    /// HMAC-SHA256 over every field above (canonical length-prefixed
    /// feed, declaration order), under HKDF(DEK, [`BACKUP_MANIFEST_MAC_INFO`]).
    pub mac: String,
}

impl std::fmt::Debug for BackupManifest {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("BackupManifest")
            .field("magic", &self.magic)
            .field("v", &self.v)
            .field("backup_id", &self.backup_id)
            .field("created_at", &self.created_at)
            .field("app_version", &self.app_version)
            .field("vault_uuid", &self.vault_uuid)
            .field("epoch", &self.epoch)
            .field("schema_version", &self.schema_version)
            .field("vault_format_version", &self.vault_format_version)
            .field("entry_count", &self.entry_count)
            .field("tombstone_count", &self.tombstone_count)
            .field("kdf_params", &"[REDACTED]")
            .field("wrapped_dek", &"[REDACTED]")
            .field("dek_nonce", &"[REDACTED]")
            .field(
                "slot_registry_mac",
                &self.slot_registry_mac.as_ref().map(|_| "[REDACTED]"),
            )
            .field("slots", &self.slots)
            .field("snapshot", &self.snapshot)
            .field("mac", &"[REDACTED]")
            .finish()
    }
}

/// Length-prefixed MAC feed (u64 LE length + bytes) — the key-slot
/// registry MAC precedent, applied to every manifest field in
/// declaration order. Deterministic across implementations; the MAC
/// authenticates FIELD VALUES (not JSON spelling), matching the
/// canonical profile's structural-reader stance.
fn feed_len_prefixed(mac: &mut Hmac<Sha256>, bytes: &[u8]) {
    mac.update(&(bytes.len() as u64).to_le_bytes());
    mac.update(bytes);
}

fn feed_u64(mac: &mut Hmac<Sha256>, value: u64) {
    mac.update(&value.to_le_bytes());
}

fn feed_i64(mac: &mut Hmac<Sha256>, value: i64) {
    mac.update(&value.to_le_bytes());
}

/// The canonical MAC feed for a manifest: every authenticated field,
/// declaration order, length-prefixed. The `mac` field itself is the
/// output, never an input.
fn feed_manifest_fields(mac: &mut Hmac<Sha256>, m: &BackupManifest) {
    feed_len_prefixed(mac, m.magic.as_bytes());
    feed_i64(mac, i64::from(m.v));
    feed_len_prefixed(mac, m.backup_id.as_bytes());
    feed_i64(mac, m.created_at);
    feed_len_prefixed(mac, m.app_version.as_bytes());
    feed_len_prefixed(mac, m.vault_uuid.as_bytes());
    feed_i64(mac, m.epoch);
    feed_i64(mac, i64::from(m.schema_version));
    feed_i64(mac, m.vault_format_version);
    feed_i64(mac, m.entry_count);
    feed_i64(mac, m.tombstone_count);
    feed_len_prefixed(mac, m.kdf_params.as_bytes());
    feed_len_prefixed(mac, m.wrapped_dek.as_bytes());
    feed_len_prefixed(mac, m.dek_nonce.as_bytes());
    match &m.slot_registry_mac {
        Some(v) => feed_len_prefixed(mac, v.as_bytes()),
        None => feed_len_prefixed(mac, &[]),
    }
    feed_u64(mac, m.slots.len() as u64);
    for s in &m.slots {
        feed_len_prefixed(mac, s.slot_uuid.as_bytes());
        feed_len_prefixed(mac, s.slot_type.as_bytes());
        feed_i64(mac, s.key_epoch);
        feed_len_prefixed(mac, &[u8::from(s.revoked)]);
    }
    feed_len_prefixed(mac, m.snapshot.sha256.as_bytes());
    feed_u64(mac, m.snapshot.len);
}

/// Compute the manifest MAC over `m`'s authenticated fields under
/// `mac_key`.
pub(crate) fn compute_manifest_mac(mac_key: &[u8], m: &BackupManifest) -> Result<[u8; 32]> {
    let mut mac = <Hmac<Sha256> as Mac>::new_from_slice(mac_key)
        .map_err(|e| DatabaseError::Other(format!("backup manifest MAC init failed: {e}")))?;
    feed_manifest_fields(&mut mac, m);
    Ok(mac.finalize().into_bytes().into())
}

/// Derive the bundle MAC key from the DEK (HKDF-SHA256, 32 bytes,
/// purpose-bound info label).
pub(crate) fn derive_backup_mac_key(dek: &DataEncryptionKey) -> Result<Zeroizing<Vec<u8>>> {
    let hk = Hkdf::<Sha256>::new(None, dek.as_bytes());
    let mut okm = Zeroizing::new(vec![0u8; 32]);
    hk.expand(BACKUP_MANIFEST_MAC_INFO, okm.as_mut_slice())
        .map_err(|e| {
            PasswordManagerError::InvalidInput(format!("backup MAC key derivation failed: {e}"))
        })?;
    Ok(okm)
}

fn hex(bytes: &[u8]) -> String {
    bytes.iter().map(|b| format!("{b:02x}")).collect()
}

// ---------------------------------------------------------------------------
// Bundle container reading (bounds before allocation)
// ---------------------------------------------------------------------------

/// A parsed bundle: the authenticated manifest plus the exact snapshot
/// bytes it binds.
#[derive(Debug, Clone)]
pub struct ParsedBundle {
    pub manifest: BackupManifest,
    pub snapshot: Vec<u8>,
}

/// Read and structurally validate a bundle file: magic line, bounded
/// manifest line (no interior newline, JSON-legal), snapshot length
/// pre-checked BEFORE allocation, exact total length (no trailing
/// garbage). No cryptographic verification happens here — that is
/// [`verify_bundle_authenticity`], and MAC-first ordering is its
/// caller's contract.
pub fn read_bundle(bundle_path: &Path) -> Result<ParsedBundle> {
    // Refuse directories/symlinks; a bundle read through a planted link
    // is a read of attacker-chosen content anyway, but consistency with
    // every other sensitive open costs nothing.
    let meta = fs::symlink_metadata(bundle_path).map_err(|e| {
        PasswordManagerError::Io(std::io::Error::other(format!(
            "cannot stat backup bundle {}: {e}",
            bundle_path.display()
        )))
    })?;
    if meta.file_type().is_symlink() {
        return Err(PasswordManagerError::InvalidInput(format!(
            "{} is a symlink — refusing to read a backup bundle through a link",
            bundle_path.display()
        )));
    }
    if !meta.is_file() {
        return Err(PasswordManagerError::InvalidInput(format!(
            "{} is not a regular file",
            bundle_path.display()
        )));
    }

    let mut file = fs::File::open(bundle_path).map_err(|e| {
        PasswordManagerError::Io(std::io::Error::other(format!(
            "cannot open backup bundle {}: {e}",
            bundle_path.display()
        )))
    })?;

    // Line 1: fixed magic.
    let mut magic_buf = vec![0u8; BUNDLE_MAGIC_LINE.len() + 1];
    read_exact_or_eof(&mut file, &mut magic_buf)?;
    let expected_magic = format!("{BUNDLE_MAGIC_LINE}\n");
    if magic_buf != expected_magic.as_bytes() {
        return Err(PasswordManagerError::InvalidInput(
            "not a SentinelPass backup bundle (magic line mismatch) — a raw copy of a \
             live vault database is NOT a backup and cannot be restored as one"
                .to_string(),
        ));
    }

    // Line 2: manifest JSON, capped, no interior newline.
    let mut manifest_buf = Vec::with_capacity(1024);
    let mut byte = [0u8; 1];
    loop {
        file.read_exact(&mut byte).map_err(|_| {
            PasswordManagerError::InvalidInput(
                "backup bundle is truncated inside the manifest line".to_string(),
            )
        })?;
        if byte[0] == b'\n' {
            break;
        }
        manifest_buf.push(byte[0]);
        if manifest_buf.len() > MAX_MANIFEST_BYTES {
            return Err(PasswordManagerError::InvalidInput(format!(
                "backup manifest exceeds the size cap ({MAX_MANIFEST_BYTES} bytes) — \
                 refusing before any parse"
            )));
        }
    }
    if manifest_buf.contains(&b'\n') || manifest_buf.contains(&b'\r') {
        return Err(PasswordManagerError::InvalidInput(
            "backup manifest line contains a newline".to_string(),
        ));
    }

    // Typed structural decode: deny_unknown_fields + duplicate-key
    // rejection come from the derive (same mechanism as the WBS-305
    // documents), depth-capped like every canonical-profile reader.
    if crate::crypto::aad::json_depth_exceeds(&manifest_buf, 4) {
        return Err(PasswordManagerError::InvalidInput(
            "backup manifest exceeds the maximum nesting depth (4)".to_string(),
        ));
    }
    let manifest: BackupManifest = serde_json::from_slice(&manifest_buf).map_err(|e| {
        PasswordManagerError::InvalidInput(format!("malformed backup manifest: {e}"))
    })?;

    // Version gate BEFORE anything else in the manifest is trusted.
    if manifest.v != BACKUP_MANIFEST_VERSION {
        return Err(PasswordManagerError::Crypto(
            crate::crypto::CryptoError::UnsupportedCryptoVersion {
                found: manifest.v,
                supported: BACKUP_MANIFEST_VERSION,
            },
        ));
    }
    if manifest.magic != "SPBACKUP" {
        return Err(PasswordManagerError::InvalidInput(format!(
            "backup manifest magic mismatch (expected \"SPBACKUP\", found {:?})",
            manifest.magic
        )));
    }

    // Snapshot: length pre-checked, read exactly, total length exact.
    if manifest.snapshot.len > MAX_SNAPSHOT_BYTES as u64 {
        return Err(PasswordManagerError::InvalidInput(format!(
            "backup snapshot length {} exceeds the cap ({MAX_SNAPSHOT_BYTES} bytes) — \
             refusing before any allocation",
            manifest.snapshot.len
        )));
    }
    let mut snapshot = vec![0u8; manifest.snapshot.len as usize];
    file.read_exact(&mut snapshot).map_err(|_| {
        PasswordManagerError::InvalidInput(
            "backup bundle is truncated inside the snapshot payload".to_string(),
        )
    })?;
    let mut trailing = [0u8; 1];
    if matches!(file.read(&mut trailing), Ok(n) if n == 1) {
        return Err(PasswordManagerError::InvalidInput(
            "backup bundle carries trailing bytes after the snapshot — refusing \
             (length-prefixed containers must be exact)"
                .to_string(),
        ));
    }

    Ok(ParsedBundle { manifest, snapshot })
}

fn read_exact_or_eof(file: &mut fs::File, buf: &mut [u8]) -> Result<()> {
    file.read_exact(buf).map_err(|_| {
        PasswordManagerError::InvalidInput(
            "backup bundle is shorter than the fixed magic line".to_string(),
        )
    })
}

// ---------------------------------------------------------------------------
// Authenticity verification (MAC-first; no state touched)
// ---------------------------------------------------------------------------

/// Unwrap the DEK from the manifest's own key material with the user's
/// password — the reauthentication primitive. The GCM tag is the password
/// check; failures are typed and burn no lockout budget (same policy as
/// recovery-slot unwrap: the credential is offline data).
fn unwrap_manifest_dek(
    manifest: &BackupManifest,
    master_password: &[u8],
) -> Result<(KeyHierarchy, DataEncryptionKey)> {
    let kdf_params = dbwire::decode_kdf_params(&b64_decode(&manifest.kdf_params, "kdf_params")?)
        .map_err(PasswordManagerError::Crypto)?;
    let wrapped_dek =
        dbwire::decode_wrapped_key(&b64_decode(&manifest.wrapped_dek, "wrapped_dek")?)
            .map_err(PasswordManagerError::Crypto)?;

    let mut hierarchy = KeyHierarchy::new();
    hierarchy
        .unlock_vault_with_epoch(master_password, &kdf_params, &wrapped_dek, manifest.epoch)
        .map_err(|e| {
            PasswordManagerError::Crypto(crate::crypto::CryptoError::DecryptionFailed(format!(
                "backup bundle did not unlock with this master password: {e}"
            )))
        })?;
    let dek = hierarchy.dek()?.clone();
    Ok((hierarchy, dek))
}

/// Standard padded base64 ONLY (the canonical profile's binary encoding);
/// URL-safe and unpadded variants are rejected (DURABLE_WIRE_FORMATS §0).
fn b64_decode(s: &str, field: &str) -> Result<Vec<u8>> {
    use data_encoding::BASE64;
    BASE64.decode(s.as_bytes()).map_err(|_| {
        PasswordManagerError::InvalidInput(format!(
            "backup manifest field {field:?} is not valid standard base64"
        ))
    })
}

/// Verify a parsed bundle end-to-end WITHOUT touching any state: unwrap
/// the manifest DEK (password check), constant-time MAC verification,
/// snapshot digest binding. Returns the authenticated manifest.
///
/// This is the fail-closed core every consumer (deep dry-run validation,
/// restore) runs BEFORE anything else.
pub fn verify_bundle_authenticity(
    parsed: &ParsedBundle,
    master_password: &[u8],
) -> Result<BackupManifest> {
    let manifest = &parsed.manifest;

    // Snapshot digest FIRST for a cheap tamper check with no KDF cost
    // when the payload was swapped/truncated (the MAC key depends on the
    // DEK, not the snapshot, so ordering between digest and MAC is free;
    // both precede any mutation by construction of this function).
    let mut hasher = Sha256::new();
    hasher.update(&parsed.snapshot);
    let digest: [u8; 32] = hasher.finalize().into();
    let expected = manifest.snapshot.sha256.to_lowercase();
    use subtle::ConstantTimeEq;
    let digest_hex = hex(&digest);
    if !bool::from(digest_hex.as_bytes().ct_eq(expected.as_bytes())) {
        return Err(PasswordManagerError::InvalidInput(
            "backup snapshot digest does not match the manifest — the bundle is \
             corrupt or was tampered with; refusing (fail closed)"
                .to_string(),
        ));
    }

    let (_hierarchy, dek) = unwrap_manifest_dek(manifest, master_password)?;
    let mac_key = derive_backup_mac_key(&dek)?;
    let computed = compute_manifest_mac(mac_key.as_slice(), manifest)?;
    if !bool::from(
        computed
            .as_slice()
            .ct_eq(b64_decode(&manifest.mac, "mac")?.as_slice()),
    ) {
        return Err(PasswordManagerError::InvalidInput(
            "backup manifest MAC verification FAILED — the manifest was modified or \
             forged; refusing (fail closed)"
                .to_string(),
        ));
    }

    Ok(manifest.clone())
}

// ---------------------------------------------------------------------------
// Backup creation (WBS-416)
// ---------------------------------------------------------------------------

/// Summary of a created backup bundle.
#[derive(Debug, Clone)]
pub struct BackupSummary {
    pub output: PathBuf,
    pub backup_id: String,
    pub vault_uuid: String,
    pub epoch: i64,
    pub snapshot_bytes: u64,
}

impl VaultManager {
    /// Create an authenticated portable backup bundle (WBS-416).
    ///
    /// Requires the unlocked DEK (backup binds key material; ADR-008).
    /// The snapshot is a `VACUUM INTO` copy taken under the db lock — a
    /// consistent WAL-inclusive read snapshot. The output is written
    /// atomically (temp file + fsync + rename) and refuses to overwrite.
    pub fn create_backup(&self, output: &Path) -> Result<BackupSummary> {
        if !self.is_unlocked() {
            return Err(PasswordManagerError::VaultLocked);
        }
        if self.vault_path.as_os_str() == std::path::Path::new(":memory:") {
            return Err(PasswordManagerError::InvalidInput(
                "an in-memory vault has no durable state to back up".to_string(),
            ));
        }
        let vault_uuid = self.vault_uuid.clone().ok_or_else(|| {
            PasswordManagerError::InvalidInput(
                "vault identity (vault_uuid) is missing; open the vault once with \
                     the current binary before backing it up"
                    .to_string(),
            )
        })?;

        // Output hygiene: parent must exist; refuse to overwrite and
        // refuse symlinked/non-regular targets (the rename would follow
        // a planted link).
        let parent = output
            .parent()
            .filter(|p| !p.as_os_str().is_empty())
            .unwrap_or_else(|| Path::new("."));
        if !parent.is_dir() {
            return Err(PasswordManagerError::InvalidInput(format!(
                "backup output directory {} does not exist",
                parent.display()
            )));
        }
        if let Ok(meta) = fs::symlink_metadata(output) {
            if meta.file_type().is_symlink() {
                return Err(PasswordManagerError::InvalidInput(format!(
                    "{} is a symlink — refusing to write a backup through a link",
                    output.display()
                )));
            }
            return Err(PasswordManagerError::InvalidInput(format!(
                "backup output {} already exists — refusing to overwrite (choose a \
                 new file name)",
                output.display()
            )));
        }

        // Stage: private temp dir (0700) beside the output so the final
        // rename stays on one filesystem. Everything in here is cleanup
        // on every exit path.
        let staging = parent.join(format!(
            ".spbackup-staging-{}",
            uuid::Uuid::new_v4().simple()
        ));
        crate::platform::create_private_dir(&staging).map_err(|e| {
            PasswordManagerError::Io(std::io::Error::other(format!(
                "cannot create backup staging directory: {e}"
            )))
        })?;
        let cleanup = StagingCleanup {
            dirs: vec![staging.clone()],
        };

        let snapshot_path = staging.join("snapshot.db");
        let snapshot_bytes = {
            let db = self.lock_db()?;
            // VACUUM INTO: a consistent WAL-inclusive read snapshot of
            // the live database into a standalone file (ADR-008's
            // sanctioned mechanism; the output has no sidecars).
            let vacuum_path = snapshot_path.to_string_lossy().to_string();
            db.conn()
                .execute("VACUUM INTO ?1", rusqlite::params![vacuum_path])
                .map_err(DatabaseError::Sqlite)?;
            let bytes = fs::read(&snapshot_path).map_err(|e| {
                PasswordManagerError::Io(std::io::Error::other(format!(
                    "cannot read staged backup snapshot: {e}"
                )))
            })?;
            if bytes.len() > MAX_SNAPSHOT_BYTES {
                return Err(PasswordManagerError::InvalidInput(format!(
                    "vault snapshot exceeds the bundle size cap ({MAX_SNAPSHOT_BYTES} bytes)"
                )));
            }
            bytes
        };

        // Authority row + inventories are read from the SNAPSHOT copy
        // (never the live db) so the manifest cannot desync from the
        // payload under a concurrent writer. Read-only connection: this
        // is our own fresh artifact; the Database guards target vault
        // paths, not staging files.
        let snapshot_conn = rusqlite::Connection::open_with_flags(
            &snapshot_path,
            rusqlite::OpenFlags::SQLITE_OPEN_READ_ONLY,
        )
        .map_err(DatabaseError::Sqlite)?;

        type AuthorityRow = (
            Vec<u8>,
            Vec<u8>,
            Vec<u8>,
            Option<Vec<u8>>,
            Option<String>,
            i64,
            i32,
            Option<i64>,
        );
        let row: AuthorityRow = snapshot_conn
            .query_row(
                "SELECT kdf_params, wrapped_dek, dek_nonce, slot_registry_mac, vault_uuid,
                        COALESCE(key_epoch, 1), version, format_version
                 FROM db_metadata WHERE id = 1",
                [],
                |r| {
                    Ok((
                        r.get(0)?,
                        r.get(1)?,
                        r.get(2)?,
                        r.get(3)?,
                        r.get(4)?,
                        r.get(5)?,
                        r.get(6)?,
                        r.get(7)?,
                    ))
                },
            )
            .map_err(DatabaseError::Sqlite)?;
        let snapshot_vault_uuid = row.4.clone().ok_or_else(|| {
            PasswordManagerError::InvalidInput(
                "snapshot has no vault identity; refusing to back up".to_string(),
            )
        })?;
        if snapshot_vault_uuid != vault_uuid {
            return Err(PasswordManagerError::InvalidInput(
                "snapshot identity does not match the live vault — refusing (concurrent \
                 replacement?)"
                    .to_string(),
            ));
        }

        let entry_count: i64 = snapshot_conn
            .query_row("SELECT COUNT(*) FROM entries", [], |r| r.get(0))
            .map_err(DatabaseError::Sqlite)?;
        let tombstone_count: i64 = snapshot_conn
            .query_row(
                "SELECT COUNT(*) FROM entries WHERE is_deleted = 1",
                [],
                |r| r.get(0),
            )
            .map_err(DatabaseError::Sqlite)?;

        // Usable-slot inventory only (bounded manifest inventory; the
        // snapshot carries the full history under the registry MAC).
        let mut stmt = snapshot_conn
            .prepare(
                "SELECT slot_uuid, slot_type, key_epoch FROM key_slots
                 WHERE revoked_at IS NULL",
            )
            .map_err(DatabaseError::Sqlite)?;
        let mut slots: Vec<ManifestSlot> = stmt
            .query_map([], |row| {
                Ok((
                    row.get::<_, String>(0)?,
                    row.get::<_, String>(1)?,
                    row.get::<_, i64>(2)?,
                ))
            })
            .map_err(DatabaseError::Sqlite)?
            .collect::<std::result::Result<Vec<_>, _>>()
            .map_err(DatabaseError::Sqlite)?
            .into_iter()
            .map(|(slot_uuid, slot_type, key_epoch)| ManifestSlot {
                slot_uuid,
                slot_type,
                key_epoch,
                revoked: false,
            })
            .collect();
        slots.sort_by(|a, b| a.slot_uuid.cmp(&b.slot_uuid));
        drop(stmt);
        drop(snapshot_conn);

        let manifest = BackupManifest {
            magic: "SPBACKUP".to_string(),
            v: BACKUP_MANIFEST_VERSION,
            backup_id: uuid::Uuid::new_v4().to_string(),
            created_at: chrono::Utc::now().timestamp(),
            app_version: env!("CARGO_PKG_VERSION").to_string(),
            vault_uuid: snapshot_vault_uuid,
            epoch: row.5,
            schema_version: row.6,
            vault_format_version: row.7.unwrap_or(1),
            entry_count,
            tombstone_count,
            kdf_params: data_encoding::BASE64.encode(&row.0),
            wrapped_dek: data_encoding::BASE64.encode(&row.1),
            dek_nonce: data_encoding::BASE64.encode(&row.2),
            slot_registry_mac: row.3.as_ref().map(|m| data_encoding::BASE64.encode(m)),
            slots,
            snapshot: ManifestSnapshot {
                sha256: {
                    let mut hasher = Sha256::new();
                    hasher.update(&snapshot_bytes);
                    hex(&hasher.finalize())
                },
                len: snapshot_bytes.len() as u64,
            },
            mac: String::new(), // filled below
        };

        let dek = self.key_hierarchy.dek()?.clone();
        let mac_key = derive_backup_mac_key(&dek)?;
        let mac = compute_manifest_mac(mac_key.as_slice(), &manifest)?;
        let mut manifest = manifest;
        manifest.mac = data_encoding::BASE64.encode(&mac);

        let manifest_json = serde_json::to_vec(&manifest)
            .map_err(|e| DatabaseError::Serialization(format!("manifest encode failed: {e}")))?;
        if manifest_json.len() > MAX_MANIFEST_BYTES {
            return Err(PasswordManagerError::InvalidInput(format!(
                "backup manifest exceeds the size cap ({MAX_MANIFEST_BYTES} bytes); \
                 refusing to emit an unreadable bundle"
            )));
        }
        debug_assert!(!manifest_json.contains(&b'\n'));

        // Atomic bundle write: unique temp file, born 0600, fsync, then a
        // single rename onto the output path (same pattern as the epoch
        // sidecar write).
        let tmp = parent.join(format!(".spbackup-{}.tmp", uuid::Uuid::new_v4().simple()));
        let write_result = (|| -> std::io::Result<()> {
            let mut options = fs::OpenOptions::new();
            options.write(true).create_new(true);
            #[cfg(unix)]
            {
                use std::os::unix::fs::OpenOptionsExt;
                options.mode(0o600);
            }
            let mut file = options.open(&tmp)?;
            file.write_all(format!("{BUNDLE_MAGIC_LINE}\n").as_bytes())?;
            file.write_all(&manifest_json)?;
            file.write_all(b"\n")?;
            file.write_all(&snapshot_bytes)?;
            file.sync_all()
        })();
        if let Err(e) = write_result {
            let _ = fs::remove_file(&tmp);
            return Err(PasswordManagerError::Io(std::io::Error::other(format!(
                "backup bundle write failed: {e}"
            ))));
        }
        if let Err(e) = fs::rename(&tmp, output) {
            let _ = fs::remove_file(&tmp);
            return Err(PasswordManagerError::Io(std::io::Error::other(format!(
                "backup bundle rename failed: {e}"
            ))));
        }
        drop(cleanup);

        if let Some(ref logger) = self.audit_logger {
            let _ = logger.log(
                AuditEventType::BackupCreated,
                &format!(
                    "portable backup created: backup_id={} epoch={} snapshot_bytes={}",
                    manifest.backup_id, manifest.epoch, manifest.snapshot.len
                ),
            );
        }

        Ok(BackupSummary {
            output: output.to_path_buf(),
            backup_id: manifest.backup_id,
            vault_uuid: manifest.vault_uuid,
            epoch: manifest.epoch,
            snapshot_bytes: manifest.snapshot.len,
        })
    }

    /// Verify a backup bundle (dry-run, WBS-416/417): full authenticity
    /// (MAC-first) plus — when `deep` — the complete staged validation
    /// chain (identity, slots, schema-migration path, full decrypt) with
    /// NO mutation of any vault. Deep runs against a throwaway staging
    /// copy in the system temp dir.
    pub fn verify_bundle_file(
        bundle_path: &Path,
        master_password: &[u8],
        deep: bool,
    ) -> Result<BackupManifest> {
        let parsed = read_bundle(bundle_path)?;
        let manifest = verify_bundle_authenticity(&parsed, master_password)?;
        if deep {
            let staging =
                std::env::temp_dir().join(format!("sp-verify-{}", uuid::Uuid::new_v4().simple()));
            crate::platform::create_private_dir(&staging).map_err(|e| {
                PasswordManagerError::Io(std::io::Error::other(format!(
                    "cannot create verify staging directory: {e}"
                )))
            })?;
            let cleanup = StagingCleanup {
                dirs: vec![staging.clone()],
            };
            let staged = staging.join("snapshot.db");
            write_staged_snapshot(&staged, &parsed.snapshot)?;
            let report = validate_staged_snapshot(&staged, &manifest, master_password);
            drop(cleanup);
            report?;
        }
        Ok(manifest)
    }
}

// ---------------------------------------------------------------------------
// Shared staging helpers (used by create/verify/restore)
// ---------------------------------------------------------------------------

/// Best-effort cleanup guard: removes the listed directory trees on
/// every exit path so staging never leaks artifacts.
struct StagingCleanup {
    dirs: Vec<PathBuf>,
}

impl Drop for StagingCleanup {
    fn drop(&mut self) {
        for d in &self.dirs {
            let _ = fs::remove_dir_all(d);
        }
    }
}

/// Write snapshot bytes to `staged_path` (created fresh, owner-only,
/// fsynced) — the restore/verify staging step. Any failure removes the
/// partial file.
fn write_staged_snapshot(staged_path: &Path, snapshot: &[u8]) -> Result<()> {
    let mut options = fs::OpenOptions::new();
    options.write(true).create_new(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt;
        options.mode(0o600);
    }
    let mut file = options.open(staged_path).map_err(|e| {
        PasswordManagerError::Io(std::io::Error::other(format!(
            "cannot stage restore snapshot: {e}"
        )))
    })?;
    file.write_all(snapshot).map_err(|e| {
        let _ = fs::remove_file(staged_path);
        PasswordManagerError::Io(std::io::Error::other(format!(
            "cannot write staged restore snapshot: {e}"
        )))
    })?;
    file.sync_all().map_err(|e| {
        let _ = fs::remove_file(staged_path);
        PasswordManagerError::Io(std::io::Error::other(format!(
            "cannot fsync staged restore snapshot: {e}"
        )))
    })
}

/// Full validation of a STAGED snapshot copy against its authenticated
/// manifest (WBS-417 chain): identity, bounds, slot inventory (always
/// compared PRE-migration — the staged bytes are exactly what the
/// manifest authenticated, whatever the binary's era), schema-migration
/// path (older migrates; newer refuses, typed), slot-registry MAC under
/// the DEK, and the full functional/decryption pass.
fn validate_staged_snapshot(
    staged_path: &Path,
    manifest: &BackupManifest,
    master_password: &[u8],
) -> Result<()> {
    let db = crate::database::Database::open(staged_path)?;
    let conn = db.conn();

    // One DEK unwrap for the whole chain (Argon2id is expensive).
    let (hierarchy, dek) = unwrap_manifest_dek(manifest, master_password)?;

    // Identity + provenance, straight from the staged bytes.
    let (staged_uuid, staged_epoch, staged_schema, staged_format): (
        Option<String>,
        i64,
        i32,
        Option<i64>,
    ) = conn
        .query_row(
            "SELECT vault_uuid, COALESCE(key_epoch, 1), version, format_version
             FROM db_metadata WHERE id = 1",
            [],
            |r| Ok((r.get(0)?, r.get(1)?, r.get(2)?, r.get(3)?)),
        )
        .map_err(DatabaseError::Sqlite)?;
    if staged_uuid.as_deref() != Some(manifest.vault_uuid.as_str()) {
        return Err(PasswordManagerError::InvalidInput(
            "staged snapshot identity does not match the manifest — refusing".to_string(),
        ));
    }
    if staged_epoch != manifest.epoch {
        return Err(PasswordManagerError::InvalidInput(format!(
            "staged snapshot epoch {} does not match the manifest epoch {} — refusing",
            staged_epoch, manifest.epoch
        )));
    }
    if staged_schema != manifest.schema_version {
        return Err(PasswordManagerError::InvalidInput(format!(
            "staged snapshot schema version {} does not match the manifest {} — refusing",
            staged_schema, manifest.schema_version
        )));
    }
    if staged_format.unwrap_or(1) != manifest.vault_format_version {
        return Err(PasswordManagerError::InvalidInput(format!(
            "staged snapshot format version {:?} does not match the manifest {} — refusing",
            staged_format, manifest.vault_format_version
        )));
    }

    // Key-material blobs must byte-match what the manifest authenticated.
    let (raw_kdf, raw_wrap, raw_nonce, raw_registry_mac): (
        Vec<u8>,
        Vec<u8>,
        Vec<u8>,
        Option<Vec<u8>>,
    ) = conn
        .query_row(
            "SELECT kdf_params, wrapped_dek, dek_nonce, slot_registry_mac
             FROM db_metadata WHERE id = 1",
            [],
            |r| Ok((r.get(0)?, r.get(1)?, r.get(2)?, r.get(3)?)),
        )
        .map_err(DatabaseError::Sqlite)?;
    let expect = (
        b64_decode(&manifest.kdf_params, "kdf_params")?,
        b64_decode(&manifest.wrapped_dek, "wrapped_dek")?,
        b64_decode(&manifest.dek_nonce, "dek_nonce")?,
        match &manifest.slot_registry_mac {
            Some(v) => Some(b64_decode(v, "slot_registry_mac")?),
            None => None,
        },
    );
    use subtle::ConstantTimeEq;
    let blobs_equal = raw_kdf.len() == expect.0.len()
        && raw_wrap.len() == expect.1.len()
        && raw_nonce.len() == expect.2.len()
        && bool::from(raw_kdf.as_slice().ct_eq(expect.0.as_slice()))
        && bool::from(raw_wrap.as_slice().ct_eq(expect.1.as_slice()))
        && bool::from(raw_nonce.as_slice().ct_eq(expect.2.as_slice()))
        && match (&raw_registry_mac, &expect.3) {
            (Some(a), Some(b)) => {
                a.len() == b.len() && bool::from(a.as_slice().ct_eq(b.as_slice()))
            }
            (None, None) => true,
            _ => false,
        };
    if !blobs_equal {
        return Err(PasswordManagerError::InvalidInput(
            "staged snapshot key material does not match the authenticated manifest — \
             refusing"
                .to_string(),
        ));
    }

    // Slot inventory cross-check (pre-migration: the staged bytes are
    // exactly what the manifest authenticated).
    let key_slots_exists: bool = conn
        .query_row(
            "SELECT EXISTS(SELECT 1 FROM sqlite_master WHERE type='table' AND name='key_slots')",
            [],
            |r| r.get(0),
        )
        .map_err(DatabaseError::Sqlite)?;
    if key_slots_exists {
        let mut stmt = conn
            .prepare(
                "SELECT slot_uuid, slot_type, key_epoch FROM key_slots
                 WHERE revoked_at IS NULL",
            )
            .map_err(DatabaseError::Sqlite)?;
        let mut staged_slots: Vec<ManifestSlot> = stmt
            .query_map([], |row| {
                Ok((
                    row.get::<_, String>(0)?,
                    row.get::<_, String>(1)?,
                    row.get::<_, i64>(2)?,
                ))
            })
            .map_err(DatabaseError::Sqlite)?
            .collect::<std::result::Result<Vec<_>, _>>()
            .map_err(DatabaseError::Sqlite)?
            .into_iter()
            .map(|(slot_uuid, slot_type, key_epoch)| ManifestSlot {
                slot_uuid,
                slot_type,
                key_epoch,
                revoked: false,
            })
            .collect();
        staged_slots.sort_by(|a, b| a.slot_uuid.cmp(&b.slot_uuid));
        drop(stmt);
        if staged_slots != manifest.slots {
            return Err(PasswordManagerError::InvalidInput(
                "staged snapshot key-slot inventory does not match the manifest — \
                 refusing"
                    .to_string(),
            ));
        }
    }

    // Schema-migration path: refuses a NEWER schema with the typed
    // future-version error (WBS-315 gate runs first), migrates an OLDER
    // one to current on the staged copy.
    db.validate_schema_version()?;

    // Key-slot registry MAC under the DEK (fail closed) — only when the
    // snapshot carries a registry (pre-bootstrap vaults re-bootstrap at
    // open, exactly like a normal open of the same state).
    let registry_present: Option<Vec<u8>> = conn
        .query_row(
            "SELECT slot_registry_mac FROM db_metadata WHERE id = 1",
            [],
            |r| r.get(0),
        )
        .map_err(DatabaseError::Sqlite)?;
    if registry_present.is_some() {
        VaultManager::verify_slot_registry(&hierarchy, conn)?;
    }

    // Key-slot availability: at least one usable slot must exist after
    // migration (a restored vault with zero unlock methods is a brick).
    let usable: i64 = conn
        .query_row(
            "SELECT COUNT(*) FROM key_slots WHERE revoked_at IS NULL",
            [],
            |r| r.get(0),
        )
        .map_err(DatabaseError::Sqlite)?;
    if usable == 0 {
        return Err(PasswordManagerError::InvalidInput(
            "staged snapshot has no usable key slot after migration — refusing to \
             restore an unopenable vault"
                .to_string(),
        ));
    }

    // Full functional/decryption check (WBS-405 pass, read-only): every
    // stored envelope and relation must open under its identity. Healthy
    // legacy (v1) rows are decryptable by design and pass — a pre-activation
    // backup restores, then the normal open sweeps convert it.
    let report =
        crate::vault::activation_ops::verify_snapshot_envelopes(conn, &dek, &manifest.vault_uuid)?;
    if !report.failures.is_empty() {
        return Err(PasswordManagerError::InvalidInput(format!(
            "staged snapshot failed the full decryption check ({} failures, first: \
             table {} row {} column {} — {}); refusing to restore",
            report.failures.len(),
            report.failures[0].table,
            report.failures[0].row_id,
            report.failures[0].column,
            report.failures[0].reason
        )));
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::vault::{slot_ops, CredentialType, Entry};
    use chrono::Utc;
    use tempfile::TempDir;

    const PW: &[u8] = b"backup-test-password-1!";

    /// A real file-backed vault with one entry; returns the manager (the
    /// temp dir must outlive it).
    fn make_vault(dir: &TempDir, title: &str, secret: &str) -> VaultManager {
        let vault_path = dir.path().join("vault.db");
        let vault = VaultManager::create(&vault_path, PW).expect("create vault");
        let entry = Entry {
            entry_id: None,
            title: title.to_string(),
            username: "user@example.com".to_string(),
            password: secret.to_string().into(),
            url: Some("https://example.com".to_string()),
            notes: Some("note".to_string()),
            credential_type: CredentialType::Password,
            created_at: Utc::now(),
            modified_at: Utc::now(),
            favorite: false,
        };
        vault.add_entry(&entry).expect("add entry");
        vault
    }

    /// Rewrite one substring inside a bundle's manifest line (in place).
    fn patch_manifest_line(bundle: &Path, from: &str, to: &str) {
        let raw = fs::read(bundle).unwrap();
        let magic_end = BUNDLE_MAGIC_LINE.len() + 1;
        let rest = &raw[magic_end..];
        let manifest_end = rest.iter().position(|b| *b == b'\n').unwrap();
        let manifest = std::str::from_utf8(&rest[..manifest_end]).unwrap();
        assert!(manifest.contains(from), "patch target missing: {from}");
        let patched = manifest.replacen(from, to, 1);
        let mut out = raw[..magic_end].to_vec();
        out.extend_from_slice(patched.as_bytes());
        out.extend_from_slice(&rest[manifest_end..]);
        fs::write(bundle, out).unwrap();
    }

    /// Rebuild a bundle from a raw manifest line + snapshot bytes.
    fn splice(bundle: &Path, new_manifest_line: &[u8], new_snapshot: &[u8]) {
        let mut out = format!("{BUNDLE_MAGIC_LINE}\n").into_bytes();
        out.extend_from_slice(new_manifest_line);
        out.push(b'\n');
        out.extend_from_slice(new_snapshot);
        fs::write(bundle, out).unwrap();
    }

    // ------------------------------------------------------------------
    // Positive evidence
    // ------------------------------------------------------------------

    #[test]
    fn backup_roundtrip_manifest_authenticates_and_binds_vault_facts() {
        let dir = TempDir::new().unwrap();
        let vault = make_vault(&dir, "Bank", "s3cret-value");
        let uuid = vault.vault_uuid().unwrap().to_string();

        let output = dir.path().join("backup.spbackup");
        let summary = vault.create_backup(&output).unwrap();
        assert_eq!(summary.vault_uuid, uuid);
        assert_eq!(summary.epoch, 1);
        assert!(output.exists());

        let parsed = read_bundle(&output).unwrap();
        assert_eq!(parsed.manifest.vault_uuid, uuid);
        assert_eq!(parsed.manifest.epoch, 1);
        assert_eq!(parsed.manifest.entry_count, 1);
        assert_eq!(parsed.manifest.tombstone_count, 0);
        assert!(parsed.manifest.vault_format_version >= 1);
        assert!(
            !parsed.manifest.slots.is_empty(),
            "the usable-slot inventory must be recorded"
        );
        assert!(parsed.manifest.slots.iter().all(|s| !s.revoked));

        let verified = verify_bundle_authenticity(&parsed, PW).unwrap();
        assert_eq!(verified.backup_id, parsed.manifest.backup_id);
        assert_eq!(verified.snapshot.len, parsed.snapshot.len() as u64);
    }

    #[test]
    fn bundle_layout_is_exact_and_manifest_has_no_plaintext_entry_content() {
        let dir = TempDir::new().unwrap();
        let vault = make_vault(&dir, "Top Secret Title", "plaintext-password-value");
        let output = dir.path().join("b.spbackup");
        vault.create_backup(&output).unwrap();

        let raw = fs::read(&output).unwrap();
        let magic_end = BUNDLE_MAGIC_LINE.len() + 1;
        assert!(
            raw.starts_with(format!("{BUNDLE_MAGIC_LINE}\n").as_bytes()),
            "bundle must start with the fixed magic line"
        );
        let rest = &raw[magic_end..];
        let manifest_end = rest.iter().position(|b| *b == b'\n').unwrap();
        let manifest_json = &rest[..manifest_end];
        assert!(
            !manifest_json.contains(&b'\n'),
            "manifest must be a single line"
        );
        assert!(
            manifest_json.len() <= MAX_MANIFEST_BYTES,
            "manifest within the declared cap"
        );
        // ADR-008: no plaintext entry content in the manifest.
        let manifest_text = std::str::from_utf8(manifest_json).unwrap();
        assert!(
            !manifest_text.contains("Top Secret Title"),
            "manifest must not carry plaintext titles"
        );
        assert!(
            !manifest_text.contains("plaintext-password-value"),
            "manifest must not carry plaintext secrets"
        );
        assert!(
            !manifest_text.contains("user@example.com"),
            "manifest must not carry plaintext usernames"
        );
        // Snapshot payload follows exactly; nothing else.
        let parsed = read_bundle(&output).unwrap();
        assert_eq!(
            raw.len(),
            magic_end + manifest_end + 1 + parsed.snapshot.len(),
            "bundle must be exactly magic + manifest + snapshot"
        );
    }

    #[test]
    fn manifest_mac_is_deterministic_and_input_sensitive() {
        let dir = TempDir::new().unwrap();
        let vault = make_vault(&dir, "t", "p");
        let output = dir.path().join("b.spbackup");
        vault.create_backup(&output).unwrap();
        let parsed = read_bundle(&output).unwrap();

        let dek = vault.key_hierarchy.dek().expect("unlocked").clone();
        let key = derive_backup_mac_key(&dek).unwrap();
        let baseline = compute_manifest_mac(key.as_slice(), &parsed.manifest).unwrap();

        // Same inputs, same MAC (deterministic computation contract).
        assert_eq!(
            baseline,
            compute_manifest_mac(key.as_slice(), &parsed.manifest).unwrap()
        );

        // Every mutation class changes the MAC: operational metadata...
        let mut edited = parsed.manifest.clone();
        edited.entry_count += 1;
        assert_ne!(
            baseline,
            compute_manifest_mac(key.as_slice(), &edited).unwrap()
        );
        // ...identity/epoch...
        let mut edited = parsed.manifest.clone();
        edited.epoch += 1;
        assert_ne!(
            baseline,
            compute_manifest_mac(key.as_slice(), &edited).unwrap()
        );
        // ...snapshot binding...
        let mut edited = parsed.manifest.clone();
        edited.snapshot.sha256 = "0".repeat(64);
        assert_ne!(
            baseline,
            compute_manifest_mac(key.as_slice(), &edited).unwrap()
        );
        // ...key-slot inventory...
        let mut edited = parsed.manifest.clone();
        edited.slots.clear();
        assert_ne!(
            baseline,
            compute_manifest_mac(key.as_slice(), &edited).unwrap()
        );
        // ...and key material itself.
        let other_key =
            derive_backup_mac_key(&crate::crypto::cipher::DataEncryptionKey::new().unwrap())
                .unwrap();
        assert_ne!(
            baseline,
            compute_manifest_mac(other_key.as_slice(), &parsed.manifest).unwrap()
        );
    }

    #[test]
    fn backup_mac_key_is_purpose_separated_from_the_registry_mac_key() {
        let dir = TempDir::new().unwrap();
        let vault = make_vault(&dir, "t", "p");
        let dek = vault.key_hierarchy.dek().unwrap().clone();
        let backup_key = derive_backup_mac_key(&dek).unwrap();
        let registry_key = slot_ops::derive_registry_mac_key(&dek).unwrap();
        assert_ne!(backup_key.as_slice(), registry_key.as_slice());
    }

    #[test]
    fn deep_verify_passes_on_a_healthy_bundle() {
        let dir = TempDir::new().unwrap();
        let vault = make_vault(&dir, "Bank", "s3cret-value");
        let output = dir.path().join("b.spbackup");
        vault.create_backup(&output).unwrap();
        VaultManager::verify_bundle_file(&output, PW, true).unwrap();
    }

    // ------------------------------------------------------------------
    // Negative evidence (fail closed)
    // ------------------------------------------------------------------

    #[test]
    fn locked_vault_backup_is_refused_and_writes_nothing() {
        let dir = TempDir::new().unwrap();
        let vault = make_vault(&dir, "t", "p");
        let output = dir.path().join("b.spbackup");
        let mut locked = vault;
        locked.lock();
        let err = locked.create_backup(&output).unwrap_err();
        assert!(matches!(err, PasswordManagerError::VaultLocked));
        assert!(!output.exists(), "no output on refusal");
        // No staging litter beside the output.
        let litter: Vec<_> = fs::read_dir(dir.path())
            .unwrap()
            .filter_map(|e| e.ok())
            .filter(|e| e.file_name().to_string_lossy().starts_with(".spbackup"))
            .collect();
        assert!(litter.is_empty(), "staging must be cleaned up: {litter:?}");
    }

    #[test]
    fn in_memory_vault_backup_is_refused() {
        let vault = VaultManager::create(":memory:", PW).unwrap();
        let err = vault
            .create_backup(&std::env::temp_dir().join("unused.spbackup"))
            .unwrap_err();
        assert!(err.to_string().contains("in-memory"));
    }

    #[test]
    fn backup_refuses_to_overwrite_and_keeps_the_original_intact() {
        let dir = TempDir::new().unwrap();
        let vault = make_vault(&dir, "t", "p");
        let output = dir.path().join("b.spbackup");
        vault.create_backup(&output).unwrap();
        let original = fs::read(&output).unwrap();

        let err = vault.create_backup(&output).unwrap_err();
        assert!(err.to_string().contains("already exists"));
        assert_eq!(fs::read(&output).unwrap(), original, "output untouched");
    }

    #[test]
    #[cfg(unix)]
    fn backup_refuses_a_symlinked_output() {
        let dir = TempDir::new().unwrap();
        let vault = make_vault(&dir, "t", "p");
        let target = dir.path().join("target.txt");
        fs::write(&target, b"do not clobber").unwrap();
        let link = dir.path().join("link.spbackup");
        std::os::unix::fs::symlink(&target, &link).unwrap();

        assert!(vault.create_backup(&link).is_err());
        assert_eq!(
            fs::read(&target).unwrap(),
            b"do not clobber",
            "symlink target must be untouched"
        );
    }

    #[test]
    fn tampered_snapshot_byte_fails_the_digest_binding() {
        let dir = TempDir::new().unwrap();
        let vault = make_vault(&dir, "t", "p");
        let output = dir.path().join("b.spbackup");
        vault.create_backup(&output).unwrap();

        let mut raw = fs::read(&output).unwrap();
        let last = raw.len() - 1;
        raw[last] ^= 0x01;
        fs::write(&output, &raw).unwrap();

        let parsed = read_bundle(&output).unwrap();
        let err = verify_bundle_authenticity(&parsed, PW).unwrap_err();
        assert!(err.to_string().contains("digest"), "got: {err}");
    }

    #[test]
    fn tampered_manifest_field_fails_the_mac() {
        let dir = TempDir::new().unwrap();
        let vault = make_vault(&dir, "t", "p");
        let output = dir.path().join("b.spbackup");
        vault.create_backup(&output).unwrap();

        let parsed = read_bundle(&output).unwrap();
        patch_manifest_line(
            &output,
            &format!("\"entry_count\":{}", parsed.manifest.entry_count),
            &format!("\"entry_count\":{}", parsed.manifest.entry_count + 5),
        );

        let parsed = read_bundle(&output).unwrap();
        let err = verify_bundle_authenticity(&parsed, PW).unwrap_err();
        assert!(err.to_string().contains("MAC"), "got: {err}");
    }

    #[test]
    fn vault_uuid_swap_in_the_manifest_fails_the_mac() {
        let dir = TempDir::new().unwrap();
        let vault = make_vault(&dir, "t", "p");
        let output = dir.path().join("b.spbackup");
        vault.create_backup(&output).unwrap();

        let parsed = read_bundle(&output).unwrap();
        let forged_uuid = uuid::Uuid::new_v4().to_string();
        patch_manifest_line(
            &output,
            &format!("\"vault_uuid\":\"{}\"", parsed.manifest.vault_uuid),
            &format!("\"vault_uuid\":\"{forged_uuid}\""),
        );

        let parsed = read_bundle(&output).unwrap();
        assert!(verify_bundle_authenticity(&parsed, PW).is_err());
    }

    #[test]
    fn cross_bundle_splice_is_caught_by_the_snapshot_digest() {
        let dir = TempDir::new().unwrap();
        let vault = make_vault(&dir, "t", "p");
        let a = dir.path().join("a.spbackup");
        let b = dir.path().join("b.spbackup");
        vault.create_backup(&a).unwrap();
        vault
            .add_entry(&Entry {
                entry_id: None,
                title: "second".to_string(),
                username: "u".to_string(),
                password: "p".to_string().into(),
                url: None,
                notes: None,
                credential_type: CredentialType::Password,
                created_at: Utc::now(),
                modified_at: Utc::now(),
                favorite: false,
            })
            .unwrap();
        vault.create_backup(&b).unwrap();

        // Manifest of A + snapshot of B: same vault, same DEK, so the
        // MAC alone would verify — the SNAPSHOT DIGEST binding is what
        // catches the splice.
        let a_parsed = read_bundle(&a).unwrap();
        let b_parsed = read_bundle(&b).unwrap();
        let a_json = serde_json::to_vec(&a_parsed.manifest).unwrap();
        splice(&a, &a_json, &b_parsed.snapshot);

        let spliced = read_bundle(&a).unwrap();
        let err = verify_bundle_authenticity(&spliced, PW).unwrap_err();
        assert!(err.to_string().contains("digest"), "got: {err}");
    }

    #[test]
    fn truncated_bundle_is_refused() {
        let dir = TempDir::new().unwrap();
        let vault = make_vault(&dir, "t", "p");
        let output = dir.path().join("b.spbackup");
        vault.create_backup(&output).unwrap();

        let raw = fs::read(&output).unwrap();
        fs::write(&output, &raw[..raw.len() - 1]).unwrap();
        assert!(read_bundle(&output).is_err());

        fs::write(&output, &raw[..raw.len() / 3]).unwrap();
        assert!(read_bundle(&output).is_err());
    }

    #[test]
    fn trailing_bytes_after_the_snapshot_are_refused() {
        let dir = TempDir::new().unwrap();
        let vault = make_vault(&dir, "t", "p");
        let output = dir.path().join("b.spbackup");
        vault.create_backup(&output).unwrap();

        let mut raw = fs::read(&output).unwrap();
        raw.extend_from_slice(b"EXTRA");
        fs::write(&output, &raw).unwrap();
        let err = read_bundle(&output).unwrap_err();
        assert!(err.to_string().contains("trailing"), "got: {err}");
    }

    #[test]
    fn hostile_snapshot_length_is_refused_before_allocation() {
        let dir = TempDir::new().unwrap();
        let vault = make_vault(&dir, "t", "p");
        let output = dir.path().join("b.spbackup");
        vault.create_backup(&output).unwrap();

        let parsed = read_bundle(&output).unwrap();
        let mut hostile = parsed.manifest.clone();
        hostile.snapshot.len = (MAX_SNAPSHOT_BYTES as u64) + 1;
        let json = serde_json::to_vec(&hostile).unwrap();
        splice(&output, &json, &parsed.snapshot);

        let err = read_bundle(&output).unwrap_err();
        assert!(
            err.to_string().contains("exceeds the cap"),
            "hostile length must be refused pre-allocation: {err}"
        );
    }

    #[test]
    fn oversized_manifest_line_is_refused_before_parse() {
        let dir = TempDir::new().unwrap();
        let vault = make_vault(&dir, "t", "p");
        let output = dir.path().join("b.spbackup");
        vault.create_backup(&output).unwrap();

        let junk = vec![b'a'; MAX_MANIFEST_BYTES + 1];
        splice(&output, &junk, &[]);
        let err = read_bundle(&output).unwrap_err();
        assert!(err.to_string().contains("size cap"), "got: {err}");
    }

    #[test]
    fn unknown_manifest_version_fails_closed_typed() {
        let dir = TempDir::new().unwrap();
        let vault = make_vault(&dir, "t", "p");
        let output = dir.path().join("b.spbackup");
        vault.create_backup(&output).unwrap();

        let parsed = read_bundle(&output).unwrap();
        let mut future = parsed.manifest.clone();
        future.v = BACKUP_MANIFEST_VERSION + 1;
        let json = serde_json::to_vec(&future).unwrap();
        splice(&output, &json, &parsed.snapshot);

        let err = read_bundle(&output).unwrap_err();
        match err {
            PasswordManagerError::Crypto(
                crate::crypto::CryptoError::UnsupportedCryptoVersion { found, supported },
            ) => {
                assert_eq!(found, BACKUP_MANIFEST_VERSION + 1);
                assert_eq!(supported, BACKUP_MANIFEST_VERSION);
            }
            other => panic!("expected typed UnsupportedCryptoVersion, got {other:?}"),
        }
    }

    #[test]
    fn unknown_and_duplicate_manifest_keys_are_rejected() {
        let dir = TempDir::new().unwrap();
        let vault = make_vault(&dir, "t", "p");
        let output = dir.path().join("b.spbackup");
        vault.create_backup(&output).unwrap();
        let parsed = read_bundle(&output).unwrap();
        let good = serde_json::to_string(&parsed.manifest).unwrap();

        let injected = good.replacen(
            "\"magic\":\"SPBACKUP\"",
            "\"magic\":\"SPBACKUP\",\"injected\":1",
            1,
        );
        splice(&output, injected.as_bytes(), &parsed.snapshot);
        assert!(
            read_bundle(&output).is_err(),
            "unknown key must be rejected"
        );

        let duplicated = good.replacen("\"v\":1", "\"v\":1,\"v\":1", 1);
        splice(&output, duplicated.as_bytes(), &parsed.snapshot);
        assert!(
            read_bundle(&output).is_err(),
            "duplicate key must be rejected structurally"
        );
    }

    #[test]
    fn wrong_password_fails_verification() {
        let dir = TempDir::new().unwrap();
        let vault = make_vault(&dir, "t", "p");
        let output = dir.path().join("b.spbackup");
        vault.create_backup(&output).unwrap();

        let parsed = read_bundle(&output).unwrap();
        let err = verify_bundle_authenticity(&parsed, b"not-the-password-1!").unwrap_err();
        assert!(err.to_string().contains("did not unlock"), "got: {err}");
    }

    #[test]
    fn raw_live_file_copy_is_rejected_as_a_bundle() {
        let dir = TempDir::new().unwrap();
        let vault = make_vault(&dir, "t", "p");
        // A naive `cp` of the live database is NOT a backup (WBS-416
        // negative): it must be refused at the format gate, never
        // half-processed.
        let fake = dir.path().join("live-copy.spbackup");
        fs::copy(vault.vault_path(), &fake).unwrap();

        let err = read_bundle(&fake).unwrap_err();
        assert!(
            err.to_string().contains("raw copy"),
            "refusal must explain that a live-file copy is not a bundle: {err}"
        );
    }

    #[test]
    fn depth_bomb_manifest_is_rejected_before_parse() {
        let dir = TempDir::new().unwrap();
        let vault = make_vault(&dir, "t", "p");
        let output = dir.path().join("b.spbackup");
        vault.create_backup(&output).unwrap();
        let parsed = read_bundle(&output).unwrap();

        let bomb = format!(
            "\"magic\":\"SPBACKUP\",\"x\":{}{}",
            "[".repeat(40),
            "]".repeat(40)
        );
        let json = serde_json::to_string(&parsed.manifest).unwrap().replacen(
            "\"magic\":\"SPBACKUP\"",
            &bomb,
            1,
        );
        splice(&output, json.as_bytes(), &parsed.snapshot);
        let err = read_bundle(&output).unwrap_err();
        assert!(
            err.to_string().contains("nesting depth"),
            "depth bomb must be rejected pre-parse: {err}"
        );
    }
}
