//! Audit logging for security events and operations.
//!
//! The audit trail is a plaintext JSONL file (one [`AuditEntry`] per line)
//! outside `vault.db`. Because it is plaintext, two hardening properties are
//! layered on top of the basic log (SR-DATA-004):
//!
//! # Opaque identifiers (WBS-414)
//!
//! Identifier-bearing fields (`entry_id`, `entity_id`, `domain`, slot
//! uuids) are replaced at record time with keyed HMAC tokens derived from a
//! purpose-bound key HKDF'd over the DEK
//! (`crate::crypto::AUDIT_ID_KEY_INFO`). Tokens are deterministic for a
//! given DEK, so the same entry maps to the same token across the log
//! (audit correlation is preserved), while a reader without the DEK cannot
//! map tokens back to identifiers or correlate them across vaults.
//!
//! Free-text `context` strings must not embed raw identifiers either; call
//! sites record static prose and let the structured fields carry the token.
//!
//! **Owner re-identification procedure** (documented contract): derive the
//! id key with [`crate::crypto::derive_audit_id_key`] from the DEK of the
//! unlocked vault, then recompute candidate tokens with [`entry_token_for`]
//! / [`string_token_for`]. Entry ids are SQLite rowids and enumerable —
//! [`find_entry_id_for`] inverts a token by scanning. Entity ids (UUIDs)
//! and domains are not enumerable; invert those by recomputing tokens over
//! the candidate list from `vault.db` / the user's own domain list
//! ([`find_string_id_for`]). Severity, timestamps, and event types are
//! never opaqued.
//!
//! Deliberately kept raw: `client_id` (the user-chosen local-tool grant
//! label needed by the `secret audit` CLI filter), `field`, `purpose`
//! (descriptive free text), and `ip_address` (network diagnostics — not
//! credential identity).
//!
//! # Hash chain, rotation, retention, verification (WBS-415)
//!
//! Every record written by this binary carries an [`AuditChain`] block:
//!
//! - `seq`: a global 1-based record sequence, contiguous across rotations
//!   and restarts.
//! - `prev`: hex of the previous record's hash (genesis: a fixed
//!   domain-separated SHA-256 constant).
//! - `hash`: hex of `H(prev || canonical_record_bytes)`, where `H` is
//!   HMAC-SHA256 under the DEK-derived chain key
//!   (`crate::crypto::AUDIT_CHAIN_KEY_INFO`) for **sealed** records
//!   (vault unlocked) and keyless SHA-256 for **unsealed** records (record
//!   written while no key material existed — e.g. failed unlock attempts,
//!   epoch-guard refusals before the DEK is available).
//! - `sealed`: which of the two the record used.
//!
//! Deleting, reordering, or editing any record (sealed or unsealed) breaks
//! the chain at the first affected successor and is reported by
//! [`verify_audit_chain`] with the exact file, line, and sequence number.
//! Records written by pre-0.10 binaries have no `chain` field; they are
//! **grandfathered**: exempt from verification, counted and flagged in the
//! verify report, and never rewritten.
//!
//! Chain state lives in the file itself: each append re-derives the chain
//! head from the file tail (bounded scan) under an advisory lock on
//! `audit.lock`. This keeps appends cheap (no full-file rehash), makes
//! in-process multi-logger and cross-process (CLI + daemon) appends share
//! one chain, and survives rotation: the first record of a rotated-to file
//! commits to the last hash of its predecessor file.
//!
//! Rotation is size-based ([`AuditPolicy`]): once `audit.log` reaches
//! `max_file_bytes` it is renamed to `audit.log.1` (older files shift to
//! higher suffixes) and a fresh file continues the chain. Retention is the
//! `max_files` cap: the oldest rotated file is pruned at each shift.
//!
//! ## Known limits (documented, not fixed by this design)
//!
//! - A local attacker who can write the file can delete the whole trail and
//!   let a fresh genesis-anchored log grow in its place. Full deletion is
//!   detectable only by absence of expected history; prevention requires an
//!   external anchor. Each rotation emits the rotated file name and chain
//!   head hash via `tracing` (which reaches the platform system log for the
//!   daemon) as a partial mitigation; operators with high-assurance needs
//!   should back up the audit directory or ship chain heads off-host.
//! - Pruned (retained-out) history is indistinguishable from deleted
//!   history; verification then reports `CarriedOver` as the chain start.
//! - An attacker who can write the file can append **unsealed** records
//!   (the keyless hash is recomputable). They cannot forge sealed records
//!   or splice anything before the next sealed record without detection.
//!
//! # Audit key context
//!
//! [`AuditLogger::install_keys`] derives the id/chain keys from the DEK and
//! stores them process-globally, cleared by [`AuditLogger::clear_keys`] on
//! lock (zeroized on drop). It is process-global **by design**: the daemon
//! deliberately holds two independent `AuditLogger` instances (the IPC
//! server's long-lived logger and the `VaultManager`'s per-open logger) on
//! the same file, and keys must seal both. Records logged while the vault
//! is locked are written unsealed rather than dropped — security events
//! (failed unlocks, guard refusals) must never be lost because no key
//! material exists.

use crate::crypto::{derive_audit_chain_key, derive_audit_id_key, DataEncryptionKey};
use crate::{DatabaseError, PasswordManagerError, Result};
use chrono::{DateTime, Utc};
use data_encoding::HEXLOWER;
use hmac::{Hmac, Mac};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::fs::{File, OpenOptions};
use std::io::{Read, Seek, SeekFrom, Write};
use std::path::{Path, PathBuf};
use std::sync::{OnceLock, RwLock};
use tracing::info;
use zeroize::Zeroizing;

/// Current audit chain record format version (`AuditChain::v`).
pub const AUDIT_CHAIN_FORMAT_VERSION: u8 = 1;

/// Token label for entry (rowid) identifiers.
pub const AUDIT_ID_LABEL_ENTRY: &str = "entry-id";
/// Token label for credential-registry entity identifiers.
pub const AUDIT_ID_LABEL_ENTITY: &str = "entity-id";
/// Token label for domain identifiers.
pub const AUDIT_ID_LABEL_DOMAIN: &str = "domain";
/// Token label for key-slot uuid identifiers.
pub const AUDIT_ID_LABEL_SLOT: &str = "slot-uuid";

const AUDIT_LOG_FILE_NAME: &str = "audit.log";
const AUDIT_LOCK_FILE_NAME: &str = "audit.lock";
/// Domain redaction marker for records written with no key context.
///
/// Domains are credential identity (SR-DATA-004) with a REAL locked-state
/// production path — denied external-secret probes are audited while the
/// vault is locked, when no derivation key exists. Identifier fields that
/// cannot occur while locked (entry/entity/slot ids) keep the raw value in
/// that state (documented in `opaque_event_type`).
const REDACTED_DOMAIN_NO_KEY: &str = "opq:domain:redacted-locked";
const GENESIS_DOMAIN: &[u8] = b"sentinelpass-audit-chain-genesis-v1";
/// Tail window scanned to recover the chain head before each append. Bounded
/// so appends stay cheap; a full backward scan only happens if the tail
/// window contains no chained record at all (mixed-version log).
const CHAIN_TAIL_SCAN_BYTES: u64 = 64 * 1024;

/// Audit log entry types
#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum AuditEventType {
    /// Vault operations
    VaultCreated,
    VaultUnlocked {
        success: bool,
    },
    VaultLocked,
    MasterPasswordChanged {
        success: bool,
        from_epoch: i64,
        to_epoch: i64,
    },
    /// Epoch high-water sidecar state changed: `refused: true` marks an
    /// open REFUSED by the guard (suspected tampering — high severity);
    /// `refused: false` marks a TOFU mint or one-step heal (context text
    /// distinguishes them; ADR-004 rev 4).
    EpochHighWaterRebased {
        refused: bool,
    },
    /// The slot registry failed MAC verification — a distinct control plane
    /// from the epoch sidecar (review finding: previously logged under
    /// EpochHighWaterRebased, mislabeling registry tampering as a sidecar
    /// rollback and vice versa).
    SlotRegistryIntegrityRefused,
    /// Vault access was regained via a recovery key: all prior slots
    /// revoked, new password minted, epoch advanced (local revocation per
    /// ADR-004 rev 4). Severity 5 — this is the vault-takeover event.
    RecoveryPerformed {
        from_epoch: i64,
        to_epoch: i64,
    },
    /// A recovery slot was created or replaced (onboarding).
    RecoverySlotCreated,
    /// A key slot was revoked (the core revocation control, ADR-004) —
    /// previously invisible in the audit trail (review round 2).
    SlotRevoked,
    /// The bulk v1→v2 blob re-encryption sweep converted records (WBS-404).
    /// Kept SEPARATE from RegistryIndexRebuilt so mass-rewrite events are
    /// never confused with registry rebuilds in the audit trail (gate
    /// review, finding 7). Counts ride in the context text.
    V2BlobMigration,

    /// Credential operations. Identifier fields are opaqued at record time
    /// (WBS-414): the serialized entry carries the keyed token, and the
    /// owner recomputes the mapping locally (module docs).
    CredentialCreated {
        entry_id: i64,
    },
    CredentialViewed {
        entry_id: i64,
    },
    CredentialModified {
        entry_id: i64,
    },
    CredentialDeleted {
        entry_id: i64,
    },
    CredentialsListed {
        count: usize,
    },
    ExternalSecretAccess {
        /// Kept raw by design: user-chosen local-tool grant label (not
        /// credential identity), needed by the `secret audit` CLI filter.
        client_id: Option<String>,
        /// Opaqued at record time (WBS-414).
        domain: String,
        field: Option<String>,
        purpose: Option<String>,
        success: bool,
    },
    ExternalSecretWrite {
        client_id: Option<String>,
        /// Opaqued at record time (WBS-414).
        domain: String,
        purpose: Option<String>,
        success: bool,
    },

    /// Authentication events
    AuthenticationAttempt {
        success: bool,
    },
    AuthenticationFailure {
        reason: String,
    },

    /// Security events
    BruteForceDetected {
        ip_address: Option<String>,
    },
    VaultAutoLocked,
    VaultLockedManually,

    /// Import/Export
    DataExported {
        format: String,
    },
    DataImported {
        format: String,
        count: usize,
    },

    /// Registry operations (ADR-001). Identifier fields are opaqued at
    /// record time (WBS-414); context strings stay free of raw ids.
    RegistryEntityCreated {
        entity_id: String,
    },
    RegistryEntityDeleted {
        entity_id: String,
    },
    EntryAssignedToEntity {
        entry_id: i64,
        entity_id: String,
    },
    SecretRotated {
        entry_id: i64,
    },
    RegistryIndexRebuilt {
        entries: usize,
    },

    /// System events
    DaemonStarted,
    DaemonStopped,
    IpcServerStarted,
    IpcClientConnected,
    BiometricUnlockRequested {
        success: bool,
    },
}

/// Tamper-evidence fields attached to every record this binary writes
/// (WBS-415). Absent (`None`, serialized as a missing key) for legacy
/// pre-0.10 records, which are grandfathered.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct AuditChain {
    /// Record format version (see [`AUDIT_CHAIN_FORMAT_VERSION`]).
    pub v: u8,
    /// Global 1-based record sequence — contiguous across rotation files,
    /// restarts, and the sealed/unsealed boundary.
    pub seq: u64,
    /// Hex of the previous record's hash, or the fixed genesis hex for the
    /// first record of a complete history.
    pub prev: String,
    /// Hex of this record's hash over `prev || canonical_record_bytes`.
    pub hash: String,
    /// `true`: HMAC-SHA256 under the DEK-derived chain key (vault was
    /// unlocked). `false`: keyless SHA-256 (record written while locked).
    pub sealed: bool,
}

/// Audit log entry
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AuditEntry {
    /// Timestamp of the event
    pub timestamp: DateTime<Utc>,
    /// Event type
    pub event_type: AuditEventType,
    /// Event severity (0-5, where 5 is most critical)
    pub severity: u8,
    /// Additional context data
    pub context: String,
    /// Process ID (if applicable)
    pub pid: Option<u32>,
    /// Thread ID (if applicable)
    pub tid: Option<u64>,
    /// Tamper-evidence chain fields (WBS-415). `None` only for legacy
    /// (pre-0.10) records; those are grandfathered and never rewritten.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub chain: Option<AuditChain>,
}

/// Size/retention policy for the audit log (WBS-415).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct AuditPolicy {
    /// Rotate `audit.log` once it reaches this size (bytes).
    pub max_file_bytes: u64,
    /// Number of rotated files (`audit.log.1` .. `audit.log.N`) retained.
    /// The oldest is pruned when the cap is exceeded.
    pub max_files: usize,
}

impl Default for AuditPolicy {
    fn default() -> Self {
        // 8 MiB per file, 8 rotated files: a 64 MiB / ~200k-record cap that
        // bounds both disk use (retention DoS) and verification cost.
        Self {
            max_file_bytes: 8 * 1024 * 1024,
            max_files: 8,
        }
    }
}

impl AuditPolicy {
    fn sanitized(self) -> Self {
        Self {
            // Floor only guards pathological configs; real policies are
            // megabyte-scale (Default).
            max_file_bytes: self.max_file_bytes.max(256),
            max_files: self.max_files.max(1),
        }
    }
}

/// Where the verifiable chain begins in the on-disk history.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum AuditChainStart {
    /// The first chained record commits to the fixed genesis hash — the
    /// complete history from the first chained record is present.
    Genesis,
    /// The first chained record commits to an unknown predecessor — older
    /// files were pruned by retention or removed. Everything from that
    /// record forward is still fully verified.
    CarriedOver,
}

/// Why verification failed, and (in [`AuditVerifyOutcome::Failed`]) where.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum AuditVerifyFailure {
    /// A sealed record was encountered but no chain key was supplied.
    MissingChainKey,
    /// Record written by a newer format version.
    UnsupportedVersion { found: u8 },
    /// The record's `seq` does not continue the chain: a record was deleted
    /// or reordered.
    SequenceGap { expected: u64, found: u64 },
    /// The record's `prev` does not match the running chain hash.
    LinkMismatch,
    /// The record's content or `hash` field does not match (tampered).
    HashMismatch,
    /// A chainless record appeared AFTER the chain started — a sealed
    /// record's chain field was likely stripped (suspected splice).
    SuspectedSplice { count: usize },
    /// `prev`/`hash` are not valid hex digests.
    MalformedChainFields,
}

impl std::fmt::Display for AuditVerifyFailure {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::MissingChainKey => write!(f, "chain key unavailable (vault locked?)"),
            Self::UnsupportedVersion { found } => {
                write!(f, "unsupported chain format version {found}")
            }
            Self::SequenceGap { expected, found } => {
                write!(f, "sequence gap: expected seq {expected}, found {found} (record deleted or reordered)")
            }
            Self::LinkMismatch => write!(f, "prev-hash link does not match the chain"),
            Self::HashMismatch => write!(f, "record hash mismatch (content tampered)"),
            Self::MalformedChainFields => write!(f, "chain fields are not valid hex digests"),
            Self::SuspectedSplice { count } => write!(
                f,
                "{count} chainless record(s) after the chain started (suspected splice)"
            ),
        }
    }
}

/// Result of walking the audit trail with [`verify_audit_chain`].
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum AuditVerifyOutcome {
    Verified,
    Failed {
        file: PathBuf,
        /// 1-based line number of the first broken record.
        line: usize,
        seq: Option<u64>,
        reason: AuditVerifyFailure,
    },
}

/// Full verification report (WBS-415).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AuditVerifyReport {
    /// Files walked, oldest first.
    pub files: Vec<PathBuf>,
    pub total_records: usize,
    pub chained_records: usize,
    /// Pre-0.10 records without chain fields: exempt from verification,
    /// flagged here (legacy prefix is grandfathered, never rewritten).
    pub legacy_records: usize,
    /// Chainless records found AFTER the chain started — suspected
    /// splices (stripped-chain attacks), counted separately from the
    /// grandfathered legacy prefix (gate review, finding 1).
    pub suspected_splices: usize,
    /// Chained records written while the vault was locked (keyless SHA-256).
    pub unsealed_records: usize,
    /// Unparseable lines (e.g. a torn tail from a crash mid-write).
    pub malformed_lines: usize,
    pub chain_start: Option<AuditChainStart>,
    pub oldest_record: Option<DateTime<Utc>>,
    pub newest_record: Option<DateTime<Utc>>,
    pub outcome: AuditVerifyOutcome,
}

impl AuditVerifyReport {
    /// True when the chain verified end to end.
    pub fn is_ok(&self) -> bool {
        matches!(self.outcome, AuditVerifyOutcome::Verified)
    }
}

impl std::fmt::Display for AuditVerifyReport {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        writeln!(
            f,
            "Audit trail verification: {}",
            if self.is_ok() { "OK" } else { "FAILED" }
        )?;
        writeln!(f, "  files walked:      {}", self.files.len())?;
        writeln!(f, "  total records:     {}", self.total_records)?;
        writeln!(f, "  chained records:   {}", self.chained_records)?;
        writeln!(
            f,
            "  sealed:            {}",
            self.chained_records - self.unsealed_records
        )?;
        writeln!(f, "  unsealed (locked): {}", self.unsealed_records)?;
        writeln!(f, "  legacy (pre-0.10, exempt): {}", self.legacy_records)?;
        writeln!(f, "  malformed lines:   {}", self.malformed_lines)?;
        match self.chain_start {
            Some(AuditChainStart::Genesis) => {
                writeln!(f, "  chain start:       genesis (complete history present)")?;
            }
            Some(AuditChainStart::CarriedOver) => {
                writeln!(
                    f,
                    "  chain start:       carried-over (older files pruned or removed; \
                     verified from the first available record)"
                )?;
            }
            None => writeln!(f, "  chain start:       none (no chained records)")?,
        }
        if let (Some(o), Some(n)) = (self.oldest_record, self.newest_record) {
            writeln!(f, "  span:              {o} .. {n}")?;
        }
        match &self.outcome {
            AuditVerifyOutcome::Verified => Ok(()),
            AuditVerifyOutcome::Failed {
                file,
                line,
                seq,
                reason,
            } => write!(
                f,
                "  first broken record: {}:{} (seq {}) — {reason}",
                file.display(),
                line,
                seq.map(|s| s.to_string())
                    .unwrap_or_else(|| "?".to_string())
            ),
        }
    }
}

/// Key material for opaque ids and chain sealing, HKDF'd over the DEK.
#[derive(Clone)]
struct AuditKeys {
    id_key: Zeroizing<Vec<u8>>,
    chain_key: Zeroizing<Vec<u8>>,
}

/// Process-global audit key context.
///
/// Deliberately global, not per-logger: the daemon runs TWO independent
/// `AuditLogger` instances (IPC server + VaultManager) over one file, and
/// CLI processes each hold their own — all must seal identically while the
/// vault is unlocked and nothing while it is locked. Buffers are zeroized
/// on drop; [`AuditLogger::clear_keys`] clears on lock.
static AUDIT_KEYS: OnceLock<RwLock<Option<AuditKeys>>> = OnceLock::new();

fn keys_cell() -> &'static RwLock<Option<AuditKeys>> {
    AUDIT_KEYS.get_or_init(|| RwLock::new(None))
}

fn genesis_prev() -> [u8; 32] {
    Sha256::digest(GENESIS_DOMAIN).into()
}

fn canonical_record_bytes(entry: &AuditEntry) -> Result<Vec<u8>> {
    let stripped = AuditEntry {
        chain: None,
        ..entry.clone()
    };
    serde_json::to_vec(&stripped).map_err(|e| {
        PasswordManagerError::from(DatabaseError::Serialization(format!(
            "Failed to canonicalize audit entry: {}",
            e
        )))
    })
}

fn hmac_tag(id_key: &[u8], label: &str, value: &[u8]) -> Vec<u8> {
    let mut mac =
        Hmac::<Sha256>::new_from_slice(id_key).expect("HMAC-SHA256 accepts keys of any length");
    mac.update(label.as_bytes());
    mac.update(b":");
    mac.update(value);
    mac.finalize().into_bytes().to_vec()
}

fn entry_token_from_key(id_key: &[u8], entry_id: i64) -> i64 {
    let tag = hmac_tag(id_key, AUDIT_ID_LABEL_ENTRY, &entry_id.to_le_bytes());
    let raw = i64::from_be_bytes(tag[..8].try_into().expect("tag is 32 bytes"));
    // Mask to positive: tokens read like ids and cannot collide with the
    // negative-error conventions anywhere. 63 bits remain far beyond any
    // realistic identifier population (collision analysis: module docs).
    raw & i64::MAX
}

fn string_token_from_key(id_key: &[u8], label: &str, value: &str) -> String {
    let tag = hmac_tag(id_key, label, value.as_bytes());
    format!("opq:{}:{}", label, HEXLOWER.encode(&tag[..16]))
}

fn chain_hash(
    sealed: bool,
    chain_key: Option<&[u8]>,
    prev: &[u8; 32],
    record: &[u8],
) -> Result<[u8; 32]> {
    let mut input = Vec::with_capacity(32 + record.len());
    input.extend_from_slice(prev);
    input.extend_from_slice(record);
    if sealed {
        let key = chain_key.ok_or_else(|| {
            PasswordManagerError::from(DatabaseError::FileIo(
                "audit chain key unavailable for sealed record".to_string(),
            ))
        })?;
        let mut mac = Hmac::<Sha256>::new_from_slice(key).map_err(|e| {
            PasswordManagerError::from(DatabaseError::FileIo(format!(
                "audit chain HMAC init failed: {}",
                e
            )))
        })?;
        mac.update(&input);
        Ok(mac.finalize().into_bytes().into())
    } else {
        let mut hasher = Sha256::new();
        hasher.update(&input);
        Ok(hasher.finalize().into())
    }
}

/// Advisory cross-process/cross-instance lock serializing appends to the
/// audit directory (held across tail-recovery → write → rotation so the
/// chain can never fork between concurrent writers).
struct DirLockGuard {
    file: File,
}

fn lock_audit_dir(log_file: &Path) -> Result<DirLockGuard> {
    let dir = log_file.parent().unwrap_or_else(|| Path::new("."));
    let lock_path = dir.join(AUDIT_LOCK_FILE_NAME);
    let file = OpenOptions::new()
        .create(true)
        .truncate(false)
        .write(true)
        .open(&lock_path)
        .map_err(|e| {
            PasswordManagerError::from(DatabaseError::FileIo(format!(
                "Failed to open audit lock file: {}",
                e
            )))
        })?;
    lock_exclusive(&file)?;
    Ok(DirLockGuard { file })
}

impl Drop for DirLockGuard {
    fn drop(&mut self) {
        let _ = unlock_file(&self.file);
    }
}

#[cfg(unix)]
fn lock_exclusive(file: &File) -> Result<()> {
    use std::os::unix::io::AsRawFd;
    // Blocking: holders keep the lock for microseconds (append + occasional
    // rename), and the OS releases flock when a holder dies.
    let rc = unsafe { libc::flock(file.as_raw_fd(), libc::LOCK_EX) };
    if rc == -1 {
        return Err(PasswordManagerError::from(DatabaseError::FileIo(
            "Failed to lock audit directory".to_string(),
        )));
    }
    Ok(())
}

#[cfg(unix)]
fn unlock_file(file: &File) -> Result<()> {
    use std::os::unix::io::AsRawFd;
    let rc = unsafe { libc::flock(file.as_raw_fd(), libc::LOCK_UN) };
    if rc == -1 {
        return Err(PasswordManagerError::from(DatabaseError::FileIo(
            "Failed to unlock audit directory".to_string(),
        )));
    }
    Ok(())
}

#[cfg(windows)]
fn lock_exclusive(file: &File) -> Result<()> {
    use std::os::windows::io::AsRawHandle;
    use std::time::Duration;
    use windows::Win32::Foundation::HANDLE;
    use windows::Win32::Storage::FileSystem::{
        LockFileEx, LOCKFILE_EXCLUSIVE_LOCK, LOCKFILE_FAIL_IMMEDIATELY,
    };
    use windows::Win32::System::IO::OVERLAPPED;

    let handle = HANDLE(file.as_raw_handle());
    let mut overlapped = OVERLAPPED::default();
    // Byte-range lock on byte 0 of the dedicated lock file (never renamed,
    // so the lock identity survives rotation). Retry loop stands in for a
    // blocking acquire; holders keep the lock for microseconds.
    for _ in 0..30_000u32 {
        let acquired = unsafe {
            LockFileEx(
                handle,
                LOCKFILE_EXCLUSIVE_LOCK | LOCKFILE_FAIL_IMMEDIATELY,
                None,
                1,
                0,
                &mut overlapped,
            )
        };
        if acquired.is_ok() {
            return Ok(());
        }
        std::thread::sleep(Duration::from_millis(1));
    }
    Err(PasswordManagerError::from(DatabaseError::FileIo(
        "Timed out acquiring the audit directory lock".to_string(),
    )))
}

#[cfg(windows)]
fn unlock_file(file: &File) -> Result<()> {
    use std::os::windows::io::AsRawHandle;
    use windows::Win32::Foundation::HANDLE;
    use windows::Win32::Storage::FileSystem::UnlockFileEx;
    use windows::Win32::System::IO::OVERLAPPED;

    let handle = HANDLE(file.as_raw_handle());
    let mut overlapped = OVERLAPPED::default();
    unsafe { UnlockFileEx(handle, None, 1, 0, &mut overlapped) }.map_err(|e| {
        PasswordManagerError::from(DatabaseError::FileIo(format!(
            "Failed to unlock audit directory: {}",
            e
        )))
    })
}

fn rotated_sibling(log_file: &Path, n: usize) -> PathBuf {
    let dir = log_file.parent().unwrap_or_else(|| Path::new("."));
    let name = log_file
        .file_name()
        .map(|s| s.to_string_lossy().into_owned())
        .unwrap_or_else(|| AUDIT_LOG_FILE_NAME.to_string());
    dir.join(format!("{}.{}", name, n))
}

/// All chain files for this log, oldest first (highest rotation suffix is
/// the oldest retained file; `audit.log` itself is newest).
fn chain_files_oldest_first(log_file: &Path) -> Vec<PathBuf> {
    let dir = log_file.parent().unwrap_or_else(|| Path::new("."));
    let prefix = log_file
        .file_name()
        .map(|s| s.to_string_lossy().into_owned())
        .unwrap_or_else(|| AUDIT_LOG_FILE_NAME.to_string());
    let rotated_prefix = format!("{}.", prefix);
    let mut rotated: Vec<(u64, PathBuf)> = Vec::new();
    if let Ok(entries) = std::fs::read_dir(dir) {
        for entry in entries.flatten() {
            let name = entry.file_name().to_string_lossy().into_owned();
            if let Some(suffix) = name.strip_prefix(&rotated_prefix) {
                if let Ok(n) = suffix.parse::<u64>() {
                    rotated.push((n, entry.path()));
                }
            }
        }
    }
    rotated.sort_by_key(|(n, _)| std::cmp::Reverse(*n));
    rotated.push((0, log_file.to_path_buf()));
    rotated.into_iter().map(|(_, p)| p).collect()
}

/// Last chained record's `(hash, seq)` in one file, scanning the tail
/// (bounded) with a full backward scan as the mixed-version fallback.
fn last_chained_record_in_file(path: &Path) -> Result<Option<([u8; 32], u64)>> {
    let mut file = match File::open(path) {
        Ok(f) => f,
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => return Ok(None),
        Err(e) => {
            return Err(PasswordManagerError::from(DatabaseError::FileIo(format!(
                "Failed to open audit log for chain recovery: {}",
                e
            ))))
        }
    };
    let len = file
        .metadata()
        .map_err(|e| {
            PasswordManagerError::from(DatabaseError::FileIo(format!(
                "Failed to stat audit log: {}",
                e
            )))
        })?
        .len();
    if len == 0 {
        return Ok(None);
    }

    let scan_len = len.min(CHAIN_TAIL_SCAN_BYTES);
    let start = len - scan_len;
    file.seek(SeekFrom::Start(start)).map_err(|e| {
        PasswordManagerError::from(DatabaseError::FileIo(format!(
            "Failed to seek audit log: {}",
            e
        )))
    })?;
    let mut tail = vec![0u8; scan_len as usize];
    file.read_exact(&mut tail).map_err(|e| {
        PasswordManagerError::from(DatabaseError::FileIo(format!(
            "Failed to read audit log tail: {}",
            e
        )))
    })?;

    if let Some(found) = last_chained_in_buffer(&tail, start > 0) {
        return Ok(Some(found));
    }
    if scan_len == len {
        return Ok(None);
    }
    // Fallback (mixed-version log: >64 KiB of chainless records after the
    // last chained one) — bounded by the retention cap, so one full read.
    let mut all = String::new();
    file.seek(SeekFrom::Start(0)).map_err(|e| {
        PasswordManagerError::from(DatabaseError::FileIo(format!(
            "Failed to seek audit log: {}",
            e
        )))
    })?;
    file.read_to_string(&mut all).map_err(|e| {
        PasswordManagerError::from(DatabaseError::FileIo(format!(
            "Failed to read audit log: {}",
            e
        )))
    })?;
    // Whole file: every line is complete.
    Ok(last_chained_in_buffer(all.as_bytes(), false))
}

/// Scan a buffer's lines backwards for the last record carrying chain
/// fields. `drop_first_fragment` marks a window whose first (chronologically
/// oldest, last in the reversed iteration) line may be cut at the window
/// start.
fn last_chained_in_buffer(buf: &[u8], drop_first_fragment: bool) -> Option<([u8; 32], u64)> {
    let text = std::str::from_utf8(buf).ok()?;
    let mut fragments: Vec<&str> = text.split('\n').collect();
    // A file not ending in '\n' has a torn (partially written) final line —
    // never use it for chain recovery.
    if !buf.ends_with(b"\n") && !fragments.is_empty() {
        fragments.pop();
    }
    let count = fragments.len();
    for (idx, line) in fragments.iter().rev().enumerate() {
        if drop_first_fragment && idx == count - 1 {
            // The buffer's first line may be truncated at the window start;
            // it is also the OLDEST scanned line, so skipping it only
            // widens the search, never picks a wrong record.
            continue;
        }
        let line = line.trim();
        if line.is_empty() {
            continue;
        }
        if let Ok(entry) = serde_json::from_str::<AuditEntry>(line) {
            if let Some(chain) = entry.chain {
                let mut hash = [0u8; 32];
                if HEXLOWER
                    .decode_mut(chain.hash.as_bytes(), &mut hash)
                    .is_ok()
                {
                    return Some((hash, chain.seq));
                }
            }
        }
    }
    None
}

/// Recover the chain head `(last_hash, last_seq)` for the log at
/// `log_file`, walking rotated files newest-to-oldest. Defaults to the
/// genesis hash and sequence 0.
fn recover_chain_head(log_file: &Path) -> Result<([u8; 32], u64)> {
    for path in chain_files_oldest_first(log_file).into_iter().rev() {
        if let Some(found) = last_chained_record_in_file(&path)? {
            return Ok(found);
        }
    }
    Ok((genesis_prev(), 0))
}

/// Audit logger
///
/// Cheap to clone-instantiate per component: appends are stateless (chain
/// head re-derived from the file tail under the directory lock), so any
/// number of instances in any number of processes share one verifiable
/// chain.
pub struct AuditLogger {
    log_file: PathBuf,
    policy: AuditPolicy,
}

impl AuditLogger {
    /// Create a new audit logger
    pub fn new(log_dir: PathBuf) -> Result<Self> {
        Self::with_policy(log_dir, AuditPolicy::default())
    }

    /// Create a new audit logger with an explicit rotation/retention policy.
    pub fn with_policy(log_dir: PathBuf, policy: AuditPolicy) -> Result<Self> {
        let policy = policy.sanitized();

        // Ensure log directory exists
        std::fs::create_dir_all(&log_dir).map_err(|e| {
            PasswordManagerError::from(DatabaseError::FileIo(format!(
                "Failed to create audit log directory: {}",
                e
            )))
        })?;

        let log_file = log_dir.join(AUDIT_LOG_FILE_NAME);

        // Open (creating if needed) eagerly: preserves the historical
        // fail-fast on unwritable locations and the create-file behavior.
        OpenOptions::new()
            .create(true)
            .append(true)
            .open(&log_file)
            .map_err(|e| {
                PasswordManagerError::from(DatabaseError::FileIo(format!(
                    "Failed to open audit log: {}",
                    e
                )))
            })?;

        info!("Audit logger initialized: {:?}", log_file);

        Ok(Self { log_file, policy })
    }

    // ---- Audit key context (process-global; see module docs) ----

    /// Derive the audit id/chain keys from the DEK and install them as the
    /// process-wide audit key context (called on every unlock path).
    ///
    /// Installing is required for opaque identifiers and sealed chain
    /// records; without it records are still written, but unsealed with raw
    /// identifiers where identifiers are involved.
    pub fn install_keys(dek: &DataEncryptionKey) -> Result<()> {
        let keys = AuditKeys {
            id_key: derive_audit_id_key(dek)?,
            chain_key: derive_audit_chain_key(dek)?,
        };
        let mut guard = keys_cell()
            .write()
            .unwrap_or_else(|poisoned| poisoned.into_inner());
        *guard = Some(keys);
        Ok(())
    }

    /// Clear the process-wide audit key context (called on every lock
    /// path). Key buffers are zeroized on drop.
    pub fn clear_keys() {
        let mut guard = keys_cell()
            .write()
            .unwrap_or_else(|poisoned| poisoned.into_inner());
        *guard = None;
    }

    /// Whether the audit key context is currently installed.
    /// Scope guard for the audit key context (WBS-308 audit-key lifecycle
    /// review, finding 5): installs the keys on creation and CLEARS them
    /// on drop unless [`defuse`](Self::defuse) is called on the success
    /// path. Use at every open/create/recovery site so a failure after
    /// install cannot leave HKDF key material in a locked/failed process.
    pub fn key_lease(dek: &DataEncryptionKey) -> Result<AuditKeyLease> {
        Self::install_keys(dek)?;
        Ok(AuditKeyLease { armed: true })
    }

    pub fn keys_installed() -> bool {
        Self::snapshot_keys().is_some()
    }

    fn snapshot_keys() -> Option<AuditKeys> {
        let guard = keys_cell()
            .read()
            .unwrap_or_else(|poisoned| poisoned.into_inner());
        guard.clone()
    }

    // ---- Opaque identifiers (WBS-414) ----

    /// The opaque token recorded for `entry_id` under the installed keys,
    /// or `None` when no key context is installed (records then keep raw
    /// ids — locked-period writes only, where credential events cannot
    /// occur anyway).
    pub fn opaque_entry_token(entry_id: i64) -> Option<i64> {
        let keys = Self::snapshot_keys()?;
        Some(entry_token_from_key(keys.id_key.as_slice(), entry_id))
    }

    /// The opaque token recorded for a string identifier under the
    /// installed keys (`None` without a key context).
    pub fn opaque_value(label: &str, value: &str) -> Option<String> {
        let keys = Self::snapshot_keys()?;
        Some(string_token_from_key(keys.id_key.as_slice(), label, value))
    }

    /// Like [`opaque_value`], but falls back to the raw value when no key
    /// context is installed — for call sites that want to embed a token in
    /// a free-text context string.
    pub fn opaque_value_or_raw(label: &str, value: &str) -> String {
        Self::opaque_value(label, value).unwrap_or_else(|| value.to_string())
    }

    fn opaque_event_type(event: AuditEventType, keys: Option<&AuditKeys>) -> AuditEventType {
        let Some(keys) = keys else {
            // Locked-period records: identifiers that cannot occur while
            // locked (entry/entity/slot ids — credential events require an
            // unlocked vault) keep raw values, but domains are credential
            // identity WITH a locked-state path (denied probes) and get
            // redacted rather than logged in plaintext.
            use AuditEventType as E;
            return match event {
                E::ExternalSecretAccess {
                    client_id,
                    field,
                    purpose,
                    success,
                    ..
                } => E::ExternalSecretAccess {
                    client_id,
                    domain: REDACTED_DOMAIN_NO_KEY.to_string(),
                    field,
                    purpose,
                    success,
                },
                E::ExternalSecretWrite {
                    client_id,
                    purpose,
                    success,
                    ..
                } => E::ExternalSecretWrite {
                    client_id,
                    domain: REDACTED_DOMAIN_NO_KEY.to_string(),
                    purpose,
                    success,
                },
                other => other,
            };
        };
        let idk = keys.id_key.as_slice();
        use AuditEventType as E;
        match event {
            E::CredentialCreated { entry_id } => E::CredentialCreated {
                entry_id: entry_token_from_key(idk, entry_id),
            },
            E::CredentialViewed { entry_id } => E::CredentialViewed {
                entry_id: entry_token_from_key(idk, entry_id),
            },
            E::CredentialModified { entry_id } => E::CredentialModified {
                entry_id: entry_token_from_key(idk, entry_id),
            },
            E::CredentialDeleted { entry_id } => E::CredentialDeleted {
                entry_id: entry_token_from_key(idk, entry_id),
            },
            E::SecretRotated { entry_id } => E::SecretRotated {
                entry_id: entry_token_from_key(idk, entry_id),
            },
            E::EntryAssignedToEntity {
                entry_id,
                entity_id,
            } => E::EntryAssignedToEntity {
                entry_id: entry_token_from_key(idk, entry_id),
                entity_id: string_token_from_key(idk, AUDIT_ID_LABEL_ENTITY, &entity_id),
            },
            E::RegistryEntityCreated { entity_id } => E::RegistryEntityCreated {
                entity_id: string_token_from_key(idk, AUDIT_ID_LABEL_ENTITY, &entity_id),
            },
            E::RegistryEntityDeleted { entity_id } => E::RegistryEntityDeleted {
                entity_id: string_token_from_key(idk, AUDIT_ID_LABEL_ENTITY, &entity_id),
            },
            E::ExternalSecretAccess {
                client_id,
                domain,
                field,
                purpose,
                success,
            } => E::ExternalSecretAccess {
                // client_id stays raw by design (module docs).
                client_id,
                domain: string_token_from_key(idk, AUDIT_ID_LABEL_DOMAIN, &domain),
                field,
                purpose,
                success,
            },
            E::ExternalSecretWrite {
                client_id,
                domain,
                purpose,
                success,
            } => E::ExternalSecretWrite {
                client_id,
                domain: string_token_from_key(idk, AUDIT_ID_LABEL_DOMAIN, &domain),
                purpose,
                success,
            },
            other => other,
        }
    }

    // ---- Recording ----

    /// Log an audit event
    pub fn log(&self, event_type: AuditEventType, context: &str) -> Result<()> {
        let severity = Self::severity_for_event(&event_type);
        let keys = Self::snapshot_keys();
        let event_type = Self::opaque_event_type(event_type, keys.as_ref());

        let entry = AuditEntry {
            timestamp: Utc::now(),
            event_type,
            severity,
            context: context.to_string(),
            pid: Some(std::process::id()),
            tid: None, // ThreadId cannot be converted to u64, using None
            chain: None,
        };

        self.append_entry(entry, keys.as_ref())
    }

    /// Chain, serialize, and append one entry; rotate when over policy size.
    ///
    /// Appends are stateless: the chain head is recovered from the file tail
    /// under the directory lock, so instances and processes serialize
    /// without shared memory state.
    fn append_entry(&self, mut entry: AuditEntry, keys: Option<&AuditKeys>) -> Result<()> {
        let _dir_lock = lock_audit_dir(&self.log_file)?;

        let (prev, seq) = recover_chain_head(&self.log_file)?;
        let record = canonical_record_bytes(&entry)?;
        let sealed = keys.is_some();
        let hash = chain_hash(sealed, keys.map(|k| k.chain_key.as_slice()), &prev, &record)?;

        entry.chain = Some(AuditChain {
            v: AUDIT_CHAIN_FORMAT_VERSION,
            seq: seq + 1,
            prev: HEXLOWER.encode(&prev),
            hash: HEXLOWER.encode(&hash),
            sealed,
        });

        let mut line = serde_json::to_string(&entry).map_err(|e| {
            PasswordManagerError::from(DatabaseError::Serialization(format!(
                "Failed to serialize audit entry: {}",
                e
            )))
        })?;
        line.push('\n');

        let mut file = OpenOptions::new()
            .create(true)
            .read(true) // tail-torn repair inspects the last byte
            .append(true)
            .open(&self.log_file)
            .map_err(|e| {
                PasswordManagerError::from(DatabaseError::FileIo(format!(
                    "Failed to open audit log: {}",
                    e
                )))
            })?;

        // Repair a torn tail (crash mid-write): terminate the partial line
        // so this record starts on its own line and the torn fragment stays
        // a countable malformed line instead of corrupting this record.
        let size = file.seek(SeekFrom::End(0)).map_err(|e| {
            PasswordManagerError::from(DatabaseError::FileIo(format!(
                "Failed to seek audit log: {}",
                e
            )))
        })?;
        if size > 0 {
            file.seek(SeekFrom::Start(size - 1)).map_err(|e| {
                PasswordManagerError::from(DatabaseError::FileIo(format!(
                    "Failed to seek audit log: {}",
                    e
                )))
            })?;
            let mut last = [0u8; 1];
            file.read_exact(&mut last).map_err(|e| {
                PasswordManagerError::from(DatabaseError::FileIo(format!(
                    "Failed to read audit log: {}",
                    e
                )))
            })?;
            if last[0] != b'\n' {
                file.write_all(b"\n").map_err(|e| {
                    PasswordManagerError::from(DatabaseError::FileIo(format!(
                        "Failed to repair audit log tail: {}",
                        e
                    )))
                })?;
            }
            // Append mode always writes at end; the cursor position after
            // this point is irrelevant.
        }

        file.write_all(line.as_bytes()).map_err(|e| {
            PasswordManagerError::from(DatabaseError::FileIo(format!(
                "Failed to write audit log: {}",
                e
            )))
        })?;
        file.flush().map_err(|e| {
            PasswordManagerError::from(DatabaseError::FileIo(format!(
                "Failed to flush audit log: {}",
                e
            )))
        })?;

        let size = file.seek(SeekFrom::End(0)).unwrap_or(0);
        if size >= self.policy.max_file_bytes {
            self.rotate();
        }

        Ok(())
    }

    /// Shift `audit.log` to `audit.log.1` (older files shift to higher
    /// suffixes; the oldest is pruned by the shift itself). Called with the
    /// directory lock held, after the triggering record was already
    /// written. Rotation failures are logged and non-fatal: hygiene must
    /// never report an already-durable record as unrecorded.
    fn rotate(&self) {
        for i in (1..self.policy.max_files).rev() {
            let (from, to) = (
                rotated_sibling(&self.log_file, i),
                rotated_sibling(&self.log_file, i + 1),
            );
            if from.exists() {
                let _ = std::fs::remove_file(&to);
                if let Err(e) = std::fs::rename(&from, &to) {
                    tracing::warn!(
                        "audit rotation shift failed ({} -> {}): {}",
                        from.display(),
                        to.display(),
                        e
                    );
                    return;
                }
            }
        }
        match std::fs::rename(&self.log_file, rotated_sibling(&self.log_file, 1)) {
            Ok(()) => {
                // External anchor (module docs): the rotated file name and
                // the carried chain head reach the platform system log for
                // daemon deployments.
                let head = recover_chain_head(&self.log_file)
                    .map(|(h, s)| format!("{}@seq{}", HEXLOWER.encode(&h), s))
                    .unwrap_or_else(|_| "unavailable".to_string());
                info!(file = %rotated_sibling(&self.log_file, 1).display(), head = %head, "audit log rotated");
            }
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => {}
            Err(e) => tracing::warn!("audit rotation failed: {}", e),
        }
    }

    /// Get severity level for an event type (0-5)
    fn severity_for_event(event: &AuditEventType) -> u8 {
        match event {
            // Critical events (5)
            AuditEventType::VaultCreated
            | AuditEventType::DataExported { .. }
            | AuditEventType::EpochHighWaterRebased { refused: true }
            | AuditEventType::SlotRegistryIntegrityRefused
            | AuditEventType::RecoveryPerformed { .. } => 5,

            // Bulk re-encryption sweep (WBS-404): significant but planned.
            AuditEventType::V2BlobMigration => 3,

            // High severity (4)
            AuditEventType::CredentialDeleted { .. }
            | AuditEventType::BruteForceDetected { .. } => 4,

            // Medium-high severity (3)
            AuditEventType::VaultUnlocked { success: true }
            | AuditEventType::CredentialModified { .. }
            | AuditEventType::SecretRotated { .. }
            | AuditEventType::ExternalSecretAccess { success: true, .. }
            | AuditEventType::ExternalSecretWrite { success: true, .. }
            | AuditEventType::MasterPasswordChanged { success: true, .. }
            | AuditEventType::BiometricUnlockRequested { success: true }
            | AuditEventType::EpochHighWaterRebased { refused: false }
            | AuditEventType::RecoverySlotCreated => 3,

            // High severity (4)
            AuditEventType::SlotRevoked => 4,

            // Medium severity (2)
            AuditEventType::VaultLocked
            | AuditEventType::CredentialCreated { .. }
            | AuditEventType::CredentialViewed { .. }
            | AuditEventType::VaultAutoLocked
            | AuditEventType::RegistryEntityCreated { .. }
            | AuditEventType::RegistryEntityDeleted { .. }
            | AuditEventType::ExternalSecretAccess { success: false, .. }
            | AuditEventType::ExternalSecretWrite { success: false, .. }
            | AuditEventType::MasterPasswordChanged { success: false, .. }
            | AuditEventType::BiometricUnlockRequested { success: false } => 2,

            // Low severity (1)
            AuditEventType::CredentialsListed { .. }
            | AuditEventType::DataImported { .. }
            | AuditEventType::EntryAssignedToEntity { .. }
            | AuditEventType::RegistryIndexRebuilt { .. } => 1,

            // Info (0)
            AuditEventType::AuthenticationAttempt { .. }
            | AuditEventType::VaultLockedManually
            | AuditEventType::AuthenticationFailure { .. }
            | AuditEventType::VaultUnlocked { success: false }
            | AuditEventType::DaemonStarted
            | AuditEventType::DaemonStopped
            | AuditEventType::IpcServerStarted
            | AuditEventType::IpcClientConnected => 0,
        }
    }

    // ---- Reading ----

    /// Read every record from all retained files, oldest first.
    fn read_all_entries(&self) -> Result<Vec<AuditEntry>> {
        // A missing current file is legitimate right after a rotation (the
        // next append recreates it); other IO failures still error.
        let current = match std::fs::read_to_string(&self.log_file) {
            Ok(c) => c,
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => String::new(),
            Err(e) => {
                return Err(PasswordManagerError::from(DatabaseError::FileIo(format!(
                    "Failed to read audit log: {}",
                    e
                ))))
            }
        };

        let mut text = String::new();
        for file in chain_files_oldest_first(&self.log_file) {
            if file == self.log_file {
                continue;
            }
            match std::fs::read_to_string(&file) {
                Ok(rotated) => {
                    text.push_str(&rotated);
                    if !rotated.ends_with('\n') {
                        text.push('\n');
                    }
                }
                Err(e) => {
                    // A rotated file becoming unreadable (permission
                    // scrub, disk fault) must not silently truncate the
                    // history the user is about to review.
                    tracing::warn!(file = %file.display(), error = %e,
                        "audit history: skipping unreadable rotated file");
                }
            }
        }
        text.push_str(&current);

        Ok(text
            .lines()
            .filter(|line| !line.trim().is_empty())
            .filter_map(|line| serde_json::from_str::<AuditEntry>(line).ok())
            .collect())
    }

    /// Get all audit entries (most recent first)
    pub fn get_entries(&self, limit: usize) -> Result<Vec<AuditEntry>> {
        let entries = self.read_all_entries()?;
        Ok(entries.into_iter().rev().take(limit).collect())
    }

    /// Get audit entries since a specific timestamp
    pub fn get_entries_since(&self, since: DateTime<Utc>) -> Result<Vec<AuditEntry>> {
        Ok(self
            .read_all_entries()?
            .into_iter()
            .filter(|entry| entry.timestamp > since)
            .collect())
    }

    /// Get audit entries by severity level
    pub fn get_entries_by_severity(&self, min_severity: u8) -> Result<Vec<AuditEntry>> {
        Ok(self
            .read_all_entries()?
            .into_iter()
            .filter(|entry| entry.severity >= min_severity)
            .collect())
    }

    // ---- Verification (WBS-415) ----

    /// Verify the audit chain under the installed key context. Fails when
    /// the vault is locked (sealed records cannot be verified without the
    /// key).
    pub fn verify_with_installed_keys(&self) -> Result<AuditVerifyReport> {
        let keys = Self::snapshot_keys().ok_or_else(|| {
            PasswordManagerError::InvalidInput(
                "audit keys are not installed (vault is locked); unlock the vault to verify \
                 the audit chain"
                    .to_string(),
            )
        })?;
        let dir = self.log_file.parent().unwrap_or_else(|| Path::new("."));
        verify_audit_chain(dir, Some(keys.chain_key.as_slice()))
    }
}

/// Walk every retained audit file (oldest first) and verify the hash chain,
/// reporting the FIRST broken record with its file, line, and sequence.
///
/// Legacy (pre-0.10) records without chain fields are grandfathered: they
/// neither advance nor break the chain, and are counted and flagged in the
/// report. Unsealed records (locked-period writes) are chain-verified
/// keylessly; sealed records require `chain_key`
/// ([`crate::crypto::derive_audit_chain_key`] over the DEK).
pub fn verify_audit_chain(log_dir: &Path, chain_key: Option<&[u8]>) -> Result<AuditVerifyReport> {
    let log_file = log_dir.join(AUDIT_LOG_FILE_NAME);
    // Take the same directory flock the append path uses: without it, a
    // concurrent rotation during the walk silently skipped the newest
    // records while verify reported success (gate review, finding 3 —
    // read-side, short-lived; append holders keep the lock for
    // microseconds so contention is negligible).
    let _verify_lock = crate::audit::lock_audit_dir(&log_file)?;
    let files = chain_files_oldest_first(&log_file);

    let mut report = AuditVerifyReport {
        files: files.clone(),
        total_records: 0,
        chained_records: 0,
        legacy_records: 0,
        suspected_splices: 0,
        unsealed_records: 0,
        malformed_lines: 0,
        chain_start: None,
        oldest_record: None,
        newest_record: None,
        outcome: AuditVerifyOutcome::Verified,
    };

    let mut running = genesis_prev();
    let mut expected_seq: u64 = 1;
    let mut seen_first = false;

    'files: for file in &files {
        let content = match std::fs::read_to_string(file) {
            Ok(c) => c,
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => continue,
            Err(e) => {
                return Err(PasswordManagerError::from(DatabaseError::FileIo(format!(
                    "Failed to read audit log: {}",
                    e
                ))))
            }
        };
        for (idx, line) in content.lines().enumerate() {
            let line_no = idx + 1;
            if line.trim().is_empty() {
                continue;
            }
            report.total_records += 1;
            let entry: AuditEntry = match serde_json::from_str(line) {
                Ok(e) => e,
                Err(_) => {
                    report.malformed_lines += 1;
                    continue;
                }
            };
            if report.oldest_record.is_none() {
                report.oldest_record = Some(entry.timestamp);
            }
            report.newest_record = Some(entry.timestamp);

            let Some(ref chain) = entry.chain else {
                // A chainless record BEFORE the first sealed record is a
                // legitimate pre-0.10 legacy prefix. One AFTER the chain
                // started is a suspected splice: a sealed record's chain
                // field was likely stripped. Counted separately so it is
                // never silently folded into the exempt bucket (gate
                // review, finding 1).
                if seen_first {
                    report.suspected_splices += 1;
                } else {
                    report.legacy_records += 1;
                }
                continue;
            };

            if chain.sealed && chain_key.is_none() {
                report.outcome = AuditVerifyOutcome::Failed {
                    file: file.clone(),
                    line: line_no,
                    seq: Some(chain.seq),
                    reason: AuditVerifyFailure::MissingChainKey,
                };
                break 'files;
            }
            if chain.v != AUDIT_CHAIN_FORMAT_VERSION {
                report.outcome = AuditVerifyOutcome::Failed {
                    file: file.clone(),
                    line: line_no,
                    seq: Some(chain.seq),
                    reason: AuditVerifyFailure::UnsupportedVersion { found: chain.v },
                };
                break 'files;
            }

            if !seen_first {
                seen_first = true;
                if chain.prev == HEXLOWER.encode(&genesis_prev()) {
                    report.chain_start = Some(AuditChainStart::Genesis);
                    if chain.seq != 1 {
                        report.outcome = AuditVerifyOutcome::Failed {
                            file: file.clone(),
                            line: line_no,
                            seq: Some(chain.seq),
                            reason: AuditVerifyFailure::SequenceGap {
                                expected: 1,
                                found: chain.seq,
                            },
                        };
                        break 'files;
                    }
                } else {
                    report.chain_start = Some(AuditChainStart::CarriedOver);
                }
            } else {
                if chain.seq != expected_seq {
                    report.outcome = AuditVerifyOutcome::Failed {
                        file: file.clone(),
                        line: line_no,
                        seq: Some(chain.seq),
                        reason: AuditVerifyFailure::SequenceGap {
                            expected: expected_seq,
                            found: chain.seq,
                        },
                    };
                    break 'files;
                }
                if chain.prev != HEXLOWER.encode(&running) {
                    report.outcome = AuditVerifyOutcome::Failed {
                        file: file.clone(),
                        line: line_no,
                        seq: Some(chain.seq),
                        reason: AuditVerifyFailure::LinkMismatch,
                    };
                    break 'files;
                }
            }

            let mut prev_bytes = [0u8; 32];
            let mut expected = [0u8; 32];
            if HEXLOWER
                .decode_mut(chain.prev.as_bytes(), &mut prev_bytes)
                .is_err()
                || HEXLOWER
                    .decode_mut(chain.hash.as_bytes(), &mut expected)
                    .is_err()
            {
                report.outcome = AuditVerifyOutcome::Failed {
                    file: file.clone(),
                    line: line_no,
                    seq: Some(chain.seq),
                    reason: AuditVerifyFailure::MalformedChainFields,
                };
                break 'files;
            }

            let record = canonical_record_bytes(&entry)?;
            let computed = chain_hash(chain.sealed, chain_key, &prev_bytes, &record)?;
            if computed != expected {
                report.outcome = AuditVerifyOutcome::Failed {
                    file: file.clone(),
                    line: line_no,
                    seq: Some(chain.seq),
                    reason: AuditVerifyFailure::HashMismatch,
                };
                break 'files;
            }

            running = computed;
            expected_seq = chain.seq + 1;
            report.chained_records += 1;
            if !chain.sealed {
                report.unsealed_records += 1;
            }
        }
    }

    // Suspected splices (stripped-chain records after the chain started)
    // fail the verification with the exact count — they are the
    // stripped-chain attack surface the grandfathering exemption could
    // otherwise hide in (gate review, finding 1).
    if report.suspected_splices > 0 {
        report.outcome = AuditVerifyOutcome::Failed {
            file: report
                .files
                .last()
                .cloned()
                .unwrap_or_else(|| PathBuf::from("unknown")),
            line: 0,
            seq: None,
            reason: AuditVerifyFailure::SuspectedSplice {
                count: report.suspected_splices,
            },
        };
    }

    Ok(report)
}

// ---- Owner re-identification (WBS-414 documented procedure) ----

/// Recompute the opaque token recorded for `entry_id` under this DEK.
///
/// Owner-side half of the WBS-414 contract: the same derivation the logger
/// used at record time, run locally by the vault owner (module docs).
pub fn entry_token_for(dek: &DataEncryptionKey, entry_id: i64) -> Result<i64> {
    Ok(entry_token_from_key(
        derive_audit_id_key(dek)?.as_slice(),
        entry_id,
    ))
}

/// Recompute the opaque token recorded for a string identifier (`label` is
/// one of the `AUDIT_ID_LABEL_*` constants).
pub fn string_token_for(dek: &DataEncryptionKey, label: &str, value: &str) -> Result<String> {
    Ok(string_token_from_key(
        derive_audit_id_key(dek)?.as_slice(),
        label,
        value,
    ))
}

/// Invert an entry token by enumeration: entry ids are SQLite rowids, so
/// scanning `0..=max_scan_inclusive` recomputes each candidate token and
/// returns the matching id, if any.
pub fn find_entry_id_for(
    dek: &DataEncryptionKey,
    token: i64,
    max_scan_inclusive: i64,
) -> Result<Option<i64>> {
    let id_key = derive_audit_id_key(dek)?;
    for candidate in 0..=max_scan_inclusive {
        if entry_token_from_key(id_key.as_slice(), candidate) == token {
            return Ok(Some(candidate));
        }
    }
    Ok(None)
}

/// Invert a string token over a candidate list (entity UUIDs and domains
/// are not enumerable; take the candidates from `vault.db` / the owner's
/// own records).
pub fn find_string_id_for(
    dek: &DataEncryptionKey,
    label: &str,
    token: &str,
    candidates: impl IntoIterator<Item = impl AsRef<str>>,
) -> Result<Option<String>> {
    let id_key = derive_audit_id_key(dek)?;
    for candidate in candidates {
        let candidate = candidate.as_ref();
        if string_token_from_key(id_key.as_slice(), label, candidate) == token {
            return Ok(Some(candidate.to_string()));
        }
    }
    Ok(None)
}

/// Get the default audit log directory
pub fn get_audit_log_dir() -> PathBuf {
    crate::get_config_dir().join("audit")
}

/// Get the default audit log file path
pub fn get_audit_log_path() -> PathBuf {
    get_audit_log_dir().join(AUDIT_LOG_FILE_NAME)
}

/// Scope guard for the audit key context: installs on creation, clears on
/// drop unless defused. See [`AuditLogger::key_lease`].
pub struct AuditKeyLease {
    armed: bool,
}

impl AuditKeyLease {
    /// Keep the keys installed past this scope (successful open/session).
    pub fn defuse(mut self) {
        self.armed = false;
    }
}

impl Drop for AuditKeyLease {
    fn drop(&mut self) {
        if self.armed {
            AuditLogger::clear_keys();
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::Mutex;

    fn make_test_dir() -> PathBuf {
        let dir = std::env::temp_dir()
            .join("sentinelpass_test_audit")
            .join(uuid::Uuid::new_v4().to_string());
        std::fs::create_dir_all(&dir).unwrap();
        dir
    }

    /// The audit key context is process-global, so key-sensitive tests
    /// serialize on this mutex and reset the context at their start.
    static KEY_SERIAL: Mutex<()> = Mutex::new(());

    fn test_dek() -> DataEncryptionKey {
        let mut bytes = [7u8; 32];
        DataEncryptionKey::from_bytes(&mut bytes)
    }

    fn other_dek() -> DataEncryptionKey {
        let mut bytes = [11u8; 32];
        DataEncryptionKey::from_bytes(&mut bytes)
    }

    fn chain_key_for(dek: &DataEncryptionKey) -> Vec<u8> {
        crate::crypto::derive_audit_chain_key(dek).unwrap().to_vec()
    }

    fn read_lines(path: &Path) -> Vec<String> {
        std::fs::read_to_string(path)
            .unwrap()
            .lines()
            .map(str::to_string)
            .collect()
    }

    fn write_lines(path: &Path, lines: &[String]) {
        std::fs::write(path, lines.join("\n") + "\n").unwrap();
    }

    #[test]
    fn test_severity_levels() {
        assert_eq!(
            AuditLogger::severity_for_event(&AuditEventType::BruteForceDetected {
                ip_address: None
            }),
            4
        );
        assert_eq!(
            AuditLogger::severity_for_event(&AuditEventType::VaultUnlocked { success: true }),
            3
        );
        assert_eq!(
            AuditLogger::severity_for_event(&AuditEventType::IpcClientConnected),
            0
        );
    }

    #[test]
    fn test_all_severity_levels_complete() {
        // Critical (5)
        assert_eq!(
            AuditLogger::severity_for_event(&AuditEventType::VaultCreated),
            5
        );
        assert_eq!(
            AuditLogger::severity_for_event(&AuditEventType::DataExported {
                format: "json".to_string()
            }),
            5
        );

        // High (4)
        assert_eq!(
            AuditLogger::severity_for_event(&AuditEventType::CredentialDeleted { entry_id: 1 }),
            4
        );

        // Medium-high (3)
        assert_eq!(
            AuditLogger::severity_for_event(&AuditEventType::CredentialModified { entry_id: 1 }),
            3
        );

        // Medium (2)
        assert_eq!(
            AuditLogger::severity_for_event(&AuditEventType::VaultLocked),
            2
        );
        assert_eq!(
            AuditLogger::severity_for_event(&AuditEventType::CredentialCreated { entry_id: 1 }),
            2
        );
        assert_eq!(
            AuditLogger::severity_for_event(&AuditEventType::CredentialViewed { entry_id: 1 }),
            2
        );
        assert_eq!(
            AuditLogger::severity_for_event(&AuditEventType::VaultAutoLocked),
            2
        );

        // Low (1)
        assert_eq!(
            AuditLogger::severity_for_event(&AuditEventType::CredentialsListed { count: 5 }),
            1
        );
        assert_eq!(
            AuditLogger::severity_for_event(&AuditEventType::DataImported {
                format: "csv".to_string(),
                count: 10,
            }),
            1
        );

        // Info (0)
        assert_eq!(
            AuditLogger::severity_for_event(&AuditEventType::AuthenticationAttempt {
                success: true
            }),
            0
        );
        assert_eq!(
            AuditLogger::severity_for_event(&AuditEventType::VaultLockedManually),
            0
        );
        assert_eq!(
            AuditLogger::severity_for_event(&AuditEventType::AuthenticationFailure {
                reason: "bad pw".to_string()
            }),
            0
        );
        assert_eq!(
            AuditLogger::severity_for_event(&AuditEventType::VaultUnlocked { success: false }),
            0
        );
        assert_eq!(
            AuditLogger::severity_for_event(&AuditEventType::DaemonStarted),
            0
        );
        assert_eq!(
            AuditLogger::severity_for_event(&AuditEventType::DaemonStopped),
            0
        );
        assert_eq!(
            AuditLogger::severity_for_event(&AuditEventType::IpcServerStarted),
            0
        );
        assert_eq!(
            AuditLogger::severity_for_event(&AuditEventType::ExternalSecretAccess {
                client_id: Some("victor".to_string()),
                domain: "anthropic".to_string(),
                field: Some("password".to_string()),
                purpose: Some("victor-auth".to_string()),
                success: true,
            }),
            3
        );
        assert_eq!(
            AuditLogger::severity_for_event(&AuditEventType::BiometricUnlockRequested {
                success: true
            }),
            3
        );
    }

    #[test]
    fn test_audit_logger_creates_file() {
        let tmp = make_test_dir();
        let logger = AuditLogger::new(tmp.clone()).unwrap();
        assert!(logger.log_file.exists());
        let _ = std::fs::remove_dir_all(&tmp);
    }

    #[test]
    fn test_audit_log_and_get_entries() {
        let tmp = make_test_dir();
        let logger = AuditLogger::new(tmp.clone()).unwrap();

        logger
            .log(AuditEventType::VaultCreated, "test vault")
            .unwrap();
        logger
            .log(AuditEventType::VaultLocked, "locked after use")
            .unwrap();

        let entries = logger.get_entries(10).unwrap();
        assert_eq!(entries.len(), 2);
        // get_entries returns in reverse order (most recent first)
        assert!(matches!(entries[0].event_type, AuditEventType::VaultLocked));
        assert!(matches!(
            entries[1].event_type,
            AuditEventType::VaultCreated
        ));
        let _ = std::fs::remove_dir_all(&tmp);
    }

    #[test]
    fn test_audit_get_entries_with_limit() {
        let tmp = make_test_dir();
        let logger = AuditLogger::new(tmp.clone()).unwrap();

        for i in 0..5 {
            logger
                .log(AuditEventType::CredentialCreated { entry_id: i }, "adding")
                .unwrap();
        }

        let entries = logger.get_entries(2).unwrap();
        assert_eq!(entries.len(), 2);
        let _ = std::fs::remove_dir_all(&tmp);
    }

    #[test]
    fn test_audit_get_entries_since() {
        let tmp = make_test_dir();
        let logger = AuditLogger::new(tmp.clone()).unwrap();

        let before = Utc::now() - chrono::Duration::seconds(2);

        logger.log(AuditEventType::DaemonStarted, "start").unwrap();
        logger.log(AuditEventType::VaultCreated, "create").unwrap();

        let entries = logger.get_entries_since(before).unwrap();
        assert_eq!(entries.len(), 2);

        // Future timestamp should return none
        let future = Utc::now() + chrono::Duration::seconds(60);
        let entries = logger.get_entries_since(future).unwrap();
        assert!(entries.is_empty());
        let _ = std::fs::remove_dir_all(&tmp);
    }

    #[test]
    fn test_audit_get_entries_by_severity() {
        let tmp = make_test_dir();
        let logger = AuditLogger::new(tmp.clone()).unwrap();

        logger
            .log(AuditEventType::DaemonStarted, "info event")
            .unwrap(); // severity 0
        logger
            .log(AuditEventType::VaultCreated, "critical event")
            .unwrap(); // severity 5
        logger
            .log(
                AuditEventType::CredentialDeleted { entry_id: 1 },
                "high event",
            )
            .unwrap(); // severity 4

        let critical = logger.get_entries_by_severity(5).unwrap();
        assert_eq!(critical.len(), 1);

        let high_and_above = logger.get_entries_by_severity(4).unwrap();
        assert_eq!(high_and_above.len(), 2);

        let all = logger.get_entries_by_severity(0).unwrap();
        assert_eq!(all.len(), 3);
        let _ = std::fs::remove_dir_all(&tmp);
    }

    #[test]
    fn test_audit_entry_serialization_roundtrip() {
        let entry = AuditEntry {
            timestamp: Utc::now(),
            event_type: AuditEventType::CredentialViewed { entry_id: 42 },
            severity: 2,
            context: "test context".to_string(),
            pid: Some(1234),
            tid: None,
            chain: None,
        };

        let json = serde_json::to_string(&entry).unwrap();
        let deserialized: AuditEntry = serde_json::from_str(&json).unwrap();
        assert_eq!(deserialized.severity, 2);
        assert_eq!(deserialized.context, "test context");
        // Legacy shape: no chain key at all when None.
        assert!(!json.contains("chain"));
    }

    #[test]
    fn test_external_secret_access_serialization_roundtrip() {
        let entry = AuditEntry {
            timestamp: Utc::now(),
            event_type: AuditEventType::ExternalSecretAccess {
                client_id: Some("victor".to_string()),
                domain: "anthropic".to_string(),
                field: Some("password".to_string()),
                purpose: Some("victor-auth".to_string()),
                success: true,
            },
            severity: 3,
            context: "secret field retrieved through daemon".to_string(),
            pid: Some(1234),
            tid: None,
            chain: None,
        };

        let json = serde_json::to_string(&entry).unwrap();
        let deserialized: AuditEntry = serde_json::from_str(&json).unwrap();

        match deserialized.event_type {
            AuditEventType::ExternalSecretAccess {
                client_id,
                domain,
                field,
                purpose,
                success,
            } => {
                assert_eq!(client_id, Some("victor".to_string()));
                assert_eq!(domain, "anthropic");
                assert_eq!(field, Some("password".to_string()));
                assert_eq!(purpose, Some("victor-auth".to_string()));
                assert!(success);
            }
            other => panic!("unexpected event: {:?}", other),
        }
        assert_eq!(deserialized.severity, 3);
    }

    #[test]
    fn test_audit_log_paths() {
        let dir = get_audit_log_dir();
        assert!(dir.to_string_lossy().contains("audit"));

        let path = get_audit_log_path();
        assert!(path.to_string_lossy().ends_with("audit.log"));
    }

    // ---- WBS-414: opaque identifiers ----

    /// P: the recorded entry carries the opaque token, not the raw entry id.
    #[test]
    fn recorded_entry_contains_opaque_token_not_raw_entry_id() {
        let _guard = KEY_SERIAL.lock().unwrap();
        AuditLogger::install_keys(&test_dek()).unwrap();
        let tmp = make_test_dir();
        let logger = AuditLogger::new(tmp.clone()).unwrap();

        logger
            .log(AuditEventType::CredentialViewed { entry_id: 42 }, "viewed")
            .unwrap();
        AuditLogger::clear_keys();

        let raw = std::fs::read_to_string(logger.log_file.clone()).unwrap();
        assert!(
            !raw.contains("\"entry_id\":42"),
            "raw entry id leaked into the audit log"
        );
        let stored = logger.get_entries(1).unwrap().remove(0);
        match stored.event_type {
            AuditEventType::CredentialViewed { entry_id: token } => {
                assert_ne!(token, 42);
                assert_eq!(
                    token,
                    entry_token_for(&test_dek(), 42).unwrap(),
                    "stored token must equal the owner-side recomputation"
                );
            }
            other => panic!("unexpected event: {other:?}"),
        }
        let _ = std::fs::remove_dir_all(&tmp);
    }

    /// P: domains and entity ids are opaqued; client_id stays raw by design.
    #[test]
    fn recorded_entries_contain_opaque_domain_and_entity_tokens() {
        let _guard = KEY_SERIAL.lock().unwrap();
        AuditLogger::install_keys(&test_dek()).unwrap();
        let tmp = make_test_dir();
        let logger = AuditLogger::new(tmp.clone()).unwrap();

        logger
            .log(
                AuditEventType::ExternalSecretAccess {
                    client_id: Some("victor".to_string()),
                    domain: "example.com".to_string(),
                    field: Some("password".to_string()),
                    purpose: None,
                    success: true,
                },
                "external access",
            )
            .unwrap();
        logger
            .log(
                AuditEventType::RegistryEntityCreated {
                    entity_id: "0d0f3c5e-6d7a-4a0b-9c1d-2e3f4a5b6c7d".to_string(),
                },
                "entity created",
            )
            .unwrap();
        AuditLogger::clear_keys();

        let raw = std::fs::read_to_string(logger.log_file.clone()).unwrap();
        assert!(!raw.contains("example.com"), "domain leaked");
        assert!(
            !raw.contains("0d0f3c5e-6d7a-4a0b-9c1d-2e3f4a5b6c7d"),
            "entity id leaked"
        );
        // Deliberate design: the grant label stays raw for the CLI filter.
        assert!(raw.contains("victor"));

        let entries = logger.get_entries(10).unwrap();
        match &entries[1].event_type {
            AuditEventType::ExternalSecretAccess { domain, .. } => {
                assert_eq!(
                    domain,
                    &string_token_for(&test_dek(), AUDIT_ID_LABEL_DOMAIN, "example.com").unwrap()
                );
                assert!(domain.starts_with("opq:domain:"));
            }
            other => panic!("unexpected event: {other:?}"),
        }
        match &entries[0].event_type {
            AuditEventType::RegistryEntityCreated { entity_id } => {
                assert!(entity_id.starts_with("opq:entity-id:"));
            }
            other => panic!("unexpected event: {other:?}"),
        }
        let _ = std::fs::remove_dir_all(&tmp);
    }

    /// P: the vault owner can re-derive the mapping locally.
    #[test]
    fn owner_can_rederive_the_token_mapping() {
        let _guard = KEY_SERIAL.lock().unwrap();
        AuditLogger::install_keys(&test_dek()).unwrap();
        let tmp = make_test_dir();
        let logger = AuditLogger::new(tmp.clone()).unwrap();

        for id in [7, 42, 4242] {
            logger
                .log(AuditEventType::CredentialCreated { entry_id: id }, "add")
                .unwrap();
        }
        AuditLogger::clear_keys();

        for id in [7, 42, 4242] {
            let token = entry_token_for(&test_dek(), id).unwrap();
            assert_eq!(
                find_entry_id_for(&test_dek(), token, 10_000).unwrap(),
                Some(id),
                "owner must be able to invert token for id {id}"
            );
        }

        // String identifiers (entity UUIDs, domains) are not enumerable —
        // the owner inverts them over a candidate list (the documented
        // procedure for `vault.db`-sourced candidates).
        let entity = "0d0f3c5e-6d7a-4a0b-9c1d-2e3f4a5b6c7d";
        let entity_token = string_token_for(&test_dek(), AUDIT_ID_LABEL_ENTITY, entity).unwrap();
        let candidates = ["not-this-one", entity, "nor-this-one"];
        assert_eq!(
            find_string_id_for(
                &test_dek(),
                AUDIT_ID_LABEL_ENTITY,
                &entity_token,
                candidates
            )
            .unwrap(),
            Some(entity.to_string())
        );
        let _ = std::fs::remove_dir_all(&tmp);
    }

    /// N: distinct identifiers never collide (property loop, entries and
    /// string labels).
    #[test]
    fn distinct_identifiers_produce_distinct_tokens() {
        let _guard = KEY_SERIAL.lock().unwrap();
        AuditLogger::install_keys(&test_dek()).unwrap();

        let mut seen = std::collections::HashSet::new();
        for id in 0..20_000i64 {
            assert!(seen.insert(AuditLogger::opaque_entry_token(id).unwrap()));
        }
        let mut seen_strings = std::collections::HashSet::new();
        for i in 0..20_000i64 {
            let value = format!("entity-{i}");
            assert!(seen_strings
                .insert(AuditLogger::opaque_value(AUDIT_ID_LABEL_ENTITY, &value).unwrap()));
        }
        // Labels are domain-separated: the same value under two labels
        // must not produce the same token.
        assert_ne!(
            AuditLogger::opaque_value(AUDIT_ID_LABEL_ENTITY, "x").unwrap(),
            AuditLogger::opaque_value(AUDIT_ID_LABEL_DOMAIN, "x").unwrap()
        );
        AuditLogger::clear_keys();
    }

    /// N: token derivation is deterministic per DEK and changes with it.
    #[test]
    fn token_derivation_is_deterministic_and_key_bound() {
        let _guard = KEY_SERIAL.lock().unwrap();
        AuditLogger::install_keys(&test_dek()).unwrap();
        let a = AuditLogger::opaque_entry_token(99).unwrap();
        AuditLogger::clear_keys();

        AuditLogger::install_keys(&test_dek()).unwrap();
        assert_eq!(AuditLogger::opaque_entry_token(99).unwrap(), a);
        AuditLogger::clear_keys();

        AuditLogger::install_keys(&other_dek()).unwrap();
        assert_ne!(
            AuditLogger::opaque_entry_token(99).unwrap(),
            a,
            "wrong DEK must not produce the same tokens"
        );
        AuditLogger::clear_keys();
    }

    /// Documented behavior: without a key context, identifiers that cannot
    /// occur while locked (entry ids — credential events require an
    /// unlocked vault) stay raw.
    #[test]
    fn records_without_installed_keys_keep_raw_identifiers() {
        let _guard = KEY_SERIAL.lock().unwrap();
        AuditLogger::clear_keys();
        let tmp = make_test_dir();
        let logger = AuditLogger::new(tmp.clone()).unwrap();

        logger
            .log(AuditEventType::CredentialViewed { entry_id: 42 }, "viewed")
            .unwrap();

        let raw = std::fs::read_to_string(logger.log_file.clone()).unwrap();
        assert!(raw.contains("\"entry_id\":42"));
        // Such records are chained keylessly (unsealed), not dropped.
        let report = verify_audit_chain(&tmp, Some(&chain_key_for(&test_dek()))).unwrap();
        assert!(report.is_ok());
        assert_eq!(report.unsealed_records, 1);
        assert_eq!(report.chained_records, 1);
        let _ = std::fs::remove_dir_all(&tmp);
    }

    /// N: a denied external-secret probe logged while the vault is LOCKED
    /// (no derivation key exists) must not leak the plaintext domain into
    /// the audit log — it carries the redaction marker instead.
    #[test]
    fn locked_state_domain_probe_is_redacted_not_plaintext() {
        let _guard = KEY_SERIAL.lock().unwrap();
        AuditLogger::clear_keys();
        let tmp = make_test_dir();
        let logger = AuditLogger::new(tmp.clone()).unwrap();

        logger
            .log(
                AuditEventType::ExternalSecretAccess {
                    client_id: Some("victor".to_string()),
                    domain: "secret-domain.example".to_string(),
                    field: Some("password".to_string()),
                    purpose: None,
                    success: false,
                },
                "External secret access denied",
            )
            .unwrap();

        let raw = std::fs::read_to_string(logger.log_file.clone()).unwrap();
        assert!(
            !raw.contains("secret-domain.example"),
            "locked-state probe leaked the plaintext domain"
        );
        assert!(raw.contains(REDACTED_DOMAIN_NO_KEY));
        let entries = logger.get_entries(1).unwrap();
        match &entries[0].event_type {
            AuditEventType::ExternalSecretAccess { domain, .. } => {
                assert_eq!(domain, REDACTED_DOMAIN_NO_KEY);
            }
            other => panic!("unexpected event: {other:?}"),
        }
        let _ = std::fs::remove_dir_all(&tmp);
    }

    // ---- WBS-415: chaining, rotation, retention, verification ----

    /// P: a fresh log verifies with a genesis-anchored chain.
    #[test]
    fn chain_verifies_on_a_fresh_log() {
        let _guard = KEY_SERIAL.lock().unwrap();
        AuditLogger::install_keys(&test_dek()).unwrap();
        let tmp = make_test_dir();
        let logger = AuditLogger::new(tmp.clone()).unwrap();

        for i in 0..5 {
            logger
                .log(AuditEventType::CredentialsListed { count: i }, "listing")
                .unwrap();
        }

        let report = verify_audit_chain(&tmp, Some(&chain_key_for(&test_dek()))).unwrap();
        assert!(report.is_ok(), "report: {report}");
        assert_eq!(report.chained_records, 5);
        assert_eq!(report.unsealed_records, 0);
        assert_eq!(report.legacy_records, 0);
        assert_eq!(report.malformed_lines, 0);
        assert_eq!(report.chain_start, Some(AuditChainStart::Genesis));
        assert!(report.oldest_record.is_some());
        assert!(report.newest_record.is_some());

        // The instance-side API verifies identically.
        assert!(logger.verify_with_installed_keys().unwrap().is_ok());
        let _ = std::fs::remove_dir_all(&tmp);
        AuditLogger::clear_keys();
    }

    /// P: the chain continues across rotation files via the carryover hash.
    #[test]
    fn chain_verifies_across_rotation() {
        let _guard = KEY_SERIAL.lock().unwrap();
        AuditLogger::install_keys(&test_dek()).unwrap();
        let tmp = make_test_dir();
        let logger = AuditLogger::with_policy(
            tmp.clone(),
            AuditPolicy {
                max_file_bytes: 512,
                max_files: 16,
            },
        )
        .unwrap();

        for i in 0..10 {
            logger
                .log(
                    AuditEventType::CredentialsListed { count: i },
                    "rotation walk",
                )
                .unwrap();
        }

        let rotated: Vec<_> = std::fs::read_dir(&tmp)
            .unwrap()
            .flatten()
            .map(|e| e.file_name().to_string_lossy().into_owned())
            .filter(|n| n.starts_with("audit.log."))
            .collect();
        assert!(rotated.len() >= 3, "expected several rotated files");

        let report = verify_audit_chain(&tmp, Some(&chain_key_for(&test_dek()))).unwrap();
        assert!(report.is_ok(), "report: {report}");
        assert_eq!(report.chained_records, 10);
        assert!(report.files.len() >= 4);
        // Sequence is contiguous across files: 1..=10 in walk order.
        let entries = logger.get_entries(100).unwrap();
        let mut seqs: Vec<u64> = entries
            .iter()
            .filter_map(|e| e.chain.as_ref().map(|c| c.seq))
            .collect();
        seqs.reverse();
        assert_eq!(seqs, (1..=10).collect::<Vec<_>>());
        let _ = std::fs::remove_dir_all(&tmp);
        AuditLogger::clear_keys();
    }

    /// P: retention caps the rotated-file count; verification then starts
    /// `CarriedOver` and still verifies everything it can see.
    #[test]
    fn retention_prunes_oldest_rotated_files() {
        let _guard = KEY_SERIAL.lock().unwrap();
        AuditLogger::install_keys(&test_dek()).unwrap();
        let tmp = make_test_dir();
        let logger = AuditLogger::with_policy(
            tmp.clone(),
            AuditPolicy {
                max_file_bytes: 512,
                max_files: 2,
            },
        )
        .unwrap();

        for i in 0..12 {
            logger
                .log(
                    AuditEventType::CredentialsListed { count: i },
                    "retention walk",
                )
                .unwrap();
        }

        let audit_files: Vec<_> = std::fs::read_dir(&tmp)
            .unwrap()
            .flatten()
            .map(|e| e.file_name().to_string_lossy().into_owned())
            .filter(|n| n.starts_with("audit.log"))
            .collect();
        assert!(
            audit_files.len() <= 3,
            "retention cap exceeded: {audit_files:?}"
        );

        let report = verify_audit_chain(&tmp, Some(&chain_key_for(&test_dek()))).unwrap();
        assert!(report.is_ok(), "report: {report}");
        assert_eq!(report.chain_start, Some(AuditChainStart::CarriedOver));
        let _ = std::fs::remove_dir_all(&tmp);
        AuditLogger::clear_keys();
    }

    /// N: flipping one byte in any record is detected with the exact
    /// position.
    #[test]
    fn flipping_a_byte_is_detected_with_exact_position() {
        let _guard = KEY_SERIAL.lock().unwrap();
        AuditLogger::install_keys(&test_dek()).unwrap();
        let tmp = make_test_dir();
        let logger = AuditLogger::new(tmp.clone()).unwrap();

        for i in 0..6 {
            logger
                .log(
                    AuditEventType::CredentialsListed { count: i },
                    &format!("record-{i} marker"),
                )
                .unwrap();
        }
        AuditLogger::clear_keys();

        let mut lines = read_lines(&logger.log_file);
        // Tamper with record at index 3 (seq 4): rewrite its context.
        lines[3] = lines[3].replace("record-3", "record-X");
        write_lines(&logger.log_file, &lines);

        let report = verify_audit_chain(&tmp, Some(&chain_key_for(&test_dek()))).unwrap();
        match report.outcome {
            AuditVerifyOutcome::Failed {
                ref file,
                line,
                seq,
                reason,
            } => {
                assert!(file.ends_with("audit.log"));
                assert_eq!(line, 4, "first broken record is the tampered line");
                assert_eq!(seq, Some(4));
                assert_eq!(reason, AuditVerifyFailure::HashMismatch);
            }
            AuditVerifyOutcome::Verified => panic!("tampering was not detected"),
        }
        let _ = std::fs::remove_dir_all(&tmp);
    }

    /// N: deleting a middle record is detected with the exact position.
    #[test]
    fn deleting_a_record_is_detected_with_exact_position() {
        let _guard = KEY_SERIAL.lock().unwrap();
        AuditLogger::install_keys(&test_dek()).unwrap();
        let tmp = make_test_dir();
        let logger = AuditLogger::new(tmp.clone()).unwrap();

        for i in 0..6 {
            logger
                .log(
                    AuditEventType::CredentialsListed { count: i },
                    "delete probe",
                )
                .unwrap();
        }
        AuditLogger::clear_keys();

        let mut lines = read_lines(&logger.log_file);
        lines.remove(2); // delete record with seq 3
        write_lines(&logger.log_file, &lines);

        let report = verify_audit_chain(&tmp, Some(&chain_key_for(&test_dek()))).unwrap();
        match report.outcome {
            AuditVerifyOutcome::Failed {
                line,
                seq,
                reason: AuditVerifyFailure::SequenceGap { expected, found },
                ..
            } => {
                assert_eq!(
                    line, 3,
                    "first broken record is the deleted slot's successor"
                );
                assert_eq!(seq, Some(4));
                assert_eq!(expected, 3);
                assert_eq!(found, 4);
            }
            other => panic!("expected SequenceGap failure, got: {other:?}"),
        }
        let _ = std::fs::remove_dir_all(&tmp);
    }

    /// N: reordering records is detected with the exact position.
    #[test]
    fn reordering_records_is_detected_with_exact_position() {
        let _guard = KEY_SERIAL.lock().unwrap();
        AuditLogger::install_keys(&test_dek()).unwrap();
        let tmp = make_test_dir();
        let logger = AuditLogger::new(tmp.clone()).unwrap();

        for i in 0..6 {
            logger
                .log(
                    AuditEventType::CredentialsListed { count: i },
                    "reorder probe",
                )
                .unwrap();
        }
        AuditLogger::clear_keys();

        let mut lines = read_lines(&logger.log_file);
        lines.swap(2, 3);
        write_lines(&logger.log_file, &lines);

        let report = verify_audit_chain(&tmp, Some(&chain_key_for(&test_dek()))).unwrap();
        match report.outcome {
            AuditVerifyOutcome::Failed {
                line,
                seq,
                reason: AuditVerifyFailure::SequenceGap { expected, found },
                ..
            } => {
                assert_eq!(line, 3, "the first reordered record is the break point");
                assert_eq!(seq, Some(4));
                assert_eq!(expected, 3);
                assert_eq!(found, 4);
            }
            other => panic!("expected SequenceGap failure, got: {other:?}"),
        }
        let _ = std::fs::remove_dir_all(&tmp);
    }

    /// N: an attacker-crafted tail record (no chain key) fails verification.
    #[test]
    fn forged_tail_record_is_detected() {
        let _guard = KEY_SERIAL.lock().unwrap();
        AuditLogger::install_keys(&test_dek()).unwrap();
        let tmp = make_test_dir();
        let logger = AuditLogger::new(tmp.clone()).unwrap();

        for i in 0..3 {
            logger
                .log(
                    AuditEventType::CredentialsListed { count: i },
                    "forge probe",
                )
                .unwrap();
        }
        AuditLogger::clear_keys();

        // Attacker (no key) copies the last record, bumps the sequence, and
        // keeps the hash: the hash no longer covers the new content/prev.
        let mut lines = read_lines(&logger.log_file);
        let mut forged: AuditEntry = serde_json::from_str(lines.last().unwrap()).unwrap();
        if let Some(chain) = forged.chain.as_mut() {
            chain.seq += 1;
            chain.prev = chain.hash.clone();
        }
        forged.context = "forged by attacker".to_string();
        lines.push(serde_json::to_string(&forged).unwrap());
        write_lines(&logger.log_file, &lines);

        let report = verify_audit_chain(&tmp, Some(&chain_key_for(&test_dek()))).unwrap();
        match report.outcome {
            AuditVerifyOutcome::Failed {
                line,
                reason: AuditVerifyFailure::HashMismatch,
                ..
            } => assert_eq!(line, 4, "the forged record is the first broken one"),
            other => panic!("expected HashMismatch failure, got: {other:?}"),
        }
        let _ = std::fs::remove_dir_all(&tmp);
    }

    /// N: verification is key-bound — a wrong DEK fails at the first sealed
    /// record, and missing keys are reported rather than skipped.
    #[test]
    fn verification_is_key_bound() {
        let _guard = KEY_SERIAL.lock().unwrap();
        AuditLogger::install_keys(&test_dek()).unwrap();
        let tmp = make_test_dir();
        let logger = AuditLogger::new(tmp.clone()).unwrap();

        for i in 0..3 {
            logger
                .log(AuditEventType::CredentialsListed { count: i }, "key probe")
                .unwrap();
        }
        AuditLogger::clear_keys();

        let wrong = verify_audit_chain(&tmp, Some(&chain_key_for(&other_dek()))).unwrap();
        match wrong.outcome {
            AuditVerifyOutcome::Failed {
                line,
                reason: AuditVerifyFailure::HashMismatch,
                ..
            } => assert_eq!(line, 1, "wrong DEK fails at the first sealed record"),
            other => panic!("expected HashMismatch under wrong DEK, got: {other:?}"),
        }

        let keyless = verify_audit_chain(&tmp, None).unwrap();
        assert!(matches!(
            keyless.outcome,
            AuditVerifyOutcome::Failed {
                reason: AuditVerifyFailure::MissingChainKey,
                ..
            }
        ));

        // Instance-side verification refuses without a key context.
        assert!(logger.verify_with_installed_keys().is_err());
        let _ = std::fs::remove_dir_all(&tmp);
    }

    /// P: a legacy (pre-0.10) plaintext prefix is grandfathered — exempt
    /// from verification but flagged in the report — and the chain starts
    /// fresh at the first new-format record.
    #[test]
    fn legacy_prefix_is_grandfathered_but_flagged() {
        let _guard = KEY_SERIAL.lock().unwrap();
        AuditLogger::clear_keys();
        let tmp = make_test_dir();
        let log_file = tmp.join(AUDIT_LOG_FILE_NAME);

        // Two legacy-shape records: no chain key at all.
        let legacy = |ctx: &str| {
            let entry = AuditEntry {
                timestamp: Utc::now(),
                event_type: AuditEventType::VaultLocked,
                severity: 2,
                context: ctx.to_string(),
                pid: Some(1234),
                tid: None,
                chain: None,
            };
            serde_json::to_string(&entry).unwrap()
        };
        std::fs::write(
            &log_file,
            format!("{}\n{}\n", legacy("old-1"), legacy("old-2")),
        )
        .unwrap();

        AuditLogger::install_keys(&test_dek()).unwrap();
        let logger = AuditLogger::new(tmp.clone()).unwrap();
        for i in 0..2 {
            logger
                .log(AuditEventType::CredentialsListed { count: i }, "new format")
                .unwrap();
        }
        AuditLogger::clear_keys();

        let report = verify_audit_chain(&tmp, Some(&chain_key_for(&test_dek()))).unwrap();
        assert!(report.is_ok(), "report: {report}");
        assert_eq!(report.legacy_records, 2);
        assert_eq!(report.chained_records, 2);
        assert_eq!(report.chain_start, Some(AuditChainStart::Genesis));
        let _ = std::fs::remove_dir_all(&tmp);
    }

    /// P: locked-period records chain keylessly and the chain stays
    /// verifiable across the sealed/unsealed boundary.
    #[test]
    fn locked_period_records_chain_keylessly_and_flagged() {
        let _guard = KEY_SERIAL.lock().unwrap();
        let tmp = make_test_dir();
        let logger = AuditLogger::new(tmp.clone()).unwrap();

        AuditLogger::install_keys(&test_dek()).unwrap();
        logger
            .log(AuditEventType::VaultUnlocked { success: true }, "u")
            .unwrap();
        AuditLogger::clear_keys();
        logger
            .log(
                AuditEventType::EpochHighWaterRebased { refused: true },
                "locked r1",
            )
            .unwrap();
        logger
            .log(
                AuditEventType::EpochHighWaterRebased { refused: true },
                "locked r2",
            )
            .unwrap();
        AuditLogger::install_keys(&test_dek()).unwrap();
        logger
            .log(AuditEventType::CredentialsListed { count: 1 }, "after")
            .unwrap();
        AuditLogger::clear_keys();

        let report = verify_audit_chain(&tmp, Some(&chain_key_for(&test_dek()))).unwrap();
        assert!(report.is_ok(), "report: {report}");
        assert_eq!(report.chained_records, 4);
        assert_eq!(report.unsealed_records, 2);
        let _ = std::fs::remove_dir_all(&tmp);
    }

    /// N: editing an unsealed (locked-period) record is detected — both the
    /// naive rewrite and the recomputed-hash rewrite (the attacker can redo
    /// the keyless hash, but the next SEALED record then exposes the splice).
    #[test]
    fn tampering_locked_period_records_is_detected() {
        let _guard = KEY_SERIAL.lock().unwrap();
        let tmp = make_test_dir();
        let logger = AuditLogger::new(tmp.clone()).unwrap();

        AuditLogger::install_keys(&test_dek()).unwrap();
        logger
            .log(AuditEventType::VaultUnlocked { success: true }, "u")
            .unwrap();
        AuditLogger::clear_keys();
        logger
            .log(
                AuditEventType::EpochHighWaterRebased { refused: true },
                "locked-edit-me",
            )
            .unwrap();
        AuditLogger::install_keys(&test_dek()).unwrap();
        logger
            .log(AuditEventType::CredentialsListed { count: 1 }, "after")
            .unwrap();
        AuditLogger::clear_keys();

        // Naive rewrite: content changed, keyless hash not recomputed.
        let mut lines = read_lines(&logger.log_file);
        lines[1] = lines[1].replace("locked-edit-me", "locked-evil");
        write_lines(&logger.log_file, &lines);
        let report = verify_audit_chain(&tmp, Some(&chain_key_for(&test_dek()))).unwrap();
        assert!(matches!(
            report.outcome,
            AuditVerifyOutcome::Failed {
                reason: AuditVerifyFailure::HashMismatch,
                ..
            }
        ));

        // Full rewrite including a recomputed keyless hash: the following
        // SEALED record's prev pointer exposes the splice.
        let mut lines = read_lines(&logger.log_file);
        let mut evil: AuditEntry = serde_json::from_str(&lines[1]).unwrap();
        evil.context = "locked-evil-2".to_string();
        // The attacker recomputes the keyless hash honestly over the
        // rewritten content (they can — it is unsealed).
        {
            let prev_hex = evil.chain.as_ref().unwrap().prev.clone();
            let mut prev_bytes = [0u8; 32];
            HEXLOWER
                .decode_mut(prev_hex.as_bytes(), &mut prev_bytes)
                .unwrap();
            let canonical = canonical_record_bytes(&evil).unwrap();
            let recomputed = chain_hash(false, None, &prev_bytes, &canonical).unwrap();
            evil.chain.as_mut().unwrap().hash = HEXLOWER.encode(&recomputed);
        }
        lines[1] = serde_json::to_string(&evil).unwrap();
        write_lines(&logger.log_file, &lines);
        let key = chain_key_for(&test_dek());
        let report = verify_audit_chain(&tmp, Some(key.as_slice())).unwrap();
        match report.outcome {
            AuditVerifyOutcome::Failed {
                line,
                reason: AuditVerifyFailure::LinkMismatch,
                ..
            } => assert_eq!(line, 3, "the next sealed record exposes the splice"),
            other => panic!("expected LinkMismatch, got: {other:?}"),
        }
        let _ = std::fs::remove_dir_all(&tmp);
    }

    /// A torn tail (crash mid-write) is counted as malformed, never used
    /// for chain recovery, and does not break subsequent appends.
    #[test]
    fn torn_tail_line_is_counted_not_fatal() {
        let _guard = KEY_SERIAL.lock().unwrap();
        AuditLogger::install_keys(&test_dek()).unwrap();
        let tmp = make_test_dir();
        let logger = AuditLogger::new(tmp.clone()).unwrap();

        for i in 0..3 {
            logger
                .log(AuditEventType::CredentialsListed { count: i }, "torn probe")
                .unwrap();
        }
        // Simulate a crash mid-write: partial line, no trailing newline.
        {
            let mut f = OpenOptions::new()
                .append(true)
                .open(&logger.log_file)
                .unwrap();
            f.write_all(b"{\"timestamp\":\"2026").unwrap();
        }
        logger
            .log(AuditEventType::CredentialsListed { count: 9 }, "post-crash")
            .unwrap();
        AuditLogger::clear_keys();

        let report = verify_audit_chain(&tmp, Some(&chain_key_for(&test_dek()))).unwrap();
        assert!(report.is_ok(), "report: {report}");
        assert_eq!(report.malformed_lines, 1);
        assert_eq!(
            report.chained_records, 4,
            "torn line excluded, all else chained"
        );
        let _ = std::fs::remove_dir_all(&tmp);
    }

    /// P: independent logger instances over the same directory (the
    /// daemon's IPC-server logger and VaultManager logger; CLI processes)
    /// share ONE chain — no fork.
    #[test]
    fn concurrent_logger_instances_share_one_chain() {
        let _guard = KEY_SERIAL.lock().unwrap();
        AuditLogger::install_keys(&test_dek()).unwrap();
        let tmp = make_test_dir();
        let vault_logger = AuditLogger::new(tmp.clone()).unwrap();
        let ipc_logger = AuditLogger::new(tmp.clone()).unwrap();

        vault_logger
            .log(AuditEventType::VaultCreated, "vault")
            .unwrap();
        ipc_logger
            .log(AuditEventType::IpcServerStarted, "ipc")
            .unwrap();
        vault_logger
            .log(AuditEventType::CredentialsListed { count: 1 }, "vault2")
            .unwrap();
        ipc_logger
            .log(AuditEventType::IpcClientConnected, "ipc2")
            .unwrap();
        AuditLogger::clear_keys();

        let report = verify_audit_chain(&tmp, Some(&chain_key_for(&test_dek()))).unwrap();
        assert!(report.is_ok(), "report: {report}");
        assert_eq!(report.chained_records, 4);
        let _ = std::fs::remove_dir_all(&tmp);
    }

    /// The chain carries no full-file rehash per append: recovery scans a
    /// bounded tail. (Behavioral probe: a large legacy log does not prevent
    /// correct chain continuation, and appends stay O(tail).)
    #[test]
    fn chain_recovery_handles_large_legacy_prefix() {
        let _guard = KEY_SERIAL.lock().unwrap();
        AuditLogger::clear_keys();
        let tmp = make_test_dir();
        let log_file = tmp.join(AUDIT_LOG_FILE_NAME);

        // ~2000 legacy records (~150 KiB) — beyond the 64 KiB tail window.
        let mut legacy = String::new();
        for i in 0..2000 {
            let entry = AuditEntry {
                timestamp: Utc::now(),
                event_type: AuditEventType::CredentialsListed { count: i },
                severity: 1,
                context: format!("legacy-{i}"),
                pid: Some(1),
                tid: None,
                chain: None,
            };
            legacy.push_str(&serde_json::to_string(&entry).unwrap());
            legacy.push('\n');
        }
        std::fs::write(&log_file, legacy).unwrap();

        AuditLogger::install_keys(&test_dek()).unwrap();
        let logger = AuditLogger::new(tmp.clone()).unwrap();
        logger
            .log(AuditEventType::VaultCreated, "first chained")
            .unwrap();
        logger
            .log(AuditEventType::VaultCreated, "second chained")
            .unwrap();
        AuditLogger::clear_keys();

        let report = verify_audit_chain(&tmp, Some(&chain_key_for(&test_dek()))).unwrap();
        assert!(report.is_ok(), "report: {report}");
        assert_eq!(report.legacy_records, 2000);
        assert_eq!(report.chained_records, 2);
        // The second chained record commits to the first (not to genesis).
        let lines = read_lines(&log_file);
        let second: AuditEntry = serde_json::from_str(&lines[2001]).unwrap();
        let first: AuditEntry = serde_json::from_str(&lines[2000]).unwrap();
        assert_eq!(
            second.chain.as_ref().unwrap().prev,
            first.chain.as_ref().unwrap().hash
        );
        let _ = std::fs::remove_dir_all(&tmp);
    }
}
