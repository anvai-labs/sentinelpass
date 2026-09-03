//! Credential registry: logical entities, secret equality index, and
//! rotation posture (ADR-001).
//!
//! The registry stores no secrets. Its only derived artifact — the equality
//! tag — is an HMAC-SHA256 of the secret under a DEK-derived key, stored
//! DEK-encrypted at rest, and only ever leaves [`crate::vault::VaultManager`]
//! as in-memory aggregates.
//!
//! SQL helpers in this module take a `&rusqlite::Connection` so both the
//! vault layer and the sync apply path (which writes via its own connection
//! handle) share one implementation of the write semantics.

pub mod policy;

pub use policy::RotationStatus;

use crate::crypto::cipher::{decrypt_to_string, encrypt_string, DataEncryptionKey, EncryptedEntry};
use crate::crypto::keyring::derive_equality_key;
use crate::vault::CredentialType;
use crate::{CryptoError, DatabaseError, PasswordManagerError, Result};
use hmac::{Hmac, Mac};
use rusqlite::OptionalExtension;
use serde::{Deserialize, Serialize};
use sha2::Sha256;

/// Identity of the HKDF label currently in effect
/// ([`crate::crypto::keyring::EQUALITY_KEY_INFO`]). Stored on every index
/// row; a mismatch means the key changed and the tag must be rewritten
/// without treating the rewrite as a rotation.
pub const EQUALITY_KEY_ID: i64 = 1;

/// Version of the tag semantics (normalization policy) in effect. Tags are
/// computed over exact UTF-8 bytes; any future normalization change must
/// bump this and trigger a full re-sweep, never reinterpret existing tags.
pub const EQUALITY_ALGORITHM_VERSION: i64 = 1;

type HmacSha256 = Hmac<Sha256>;

// ---------------------------------------------------------------------------
// Domain types
// ---------------------------------------------------------------------------

/// Functional kind of a logical entity. Closed enum so rotation policy
/// defaults stay total; `Other` is the escape hatch.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum EntityKind {
    Broker,
    MarketData,
    RegulatoryData,
    Notification,
    Database,
    Infrastructure,
    Application,
    Other,
}

impl EntityKind {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Broker => "broker",
            Self::MarketData => "market_data",
            Self::RegulatoryData => "regulatory_data",
            Self::Notification => "notification",
            Self::Database => "database",
            Self::Infrastructure => "infrastructure",
            Self::Application => "application",
            Self::Other => "other",
        }
    }

    pub fn parse(value: &str) -> Result<Self> {
        match value {
            "broker" => Ok(Self::Broker),
            "market_data" => Ok(Self::MarketData),
            "regulatory_data" => Ok(Self::RegulatoryData),
            "notification" => Ok(Self::Notification),
            "database" => Ok(Self::Database),
            "infrastructure" => Ok(Self::Infrastructure),
            "application" => Ok(Self::Application),
            "other" => Ok(Self::Other),
            other => Err(PasswordManagerError::InvalidInput(format!(
                "Unsupported entity kind: {} (expected broker, market_data, regulatory_data, \
                 notification, database, infrastructure, application, or other)",
                other
            ))),
        }
    }
}

/// Impact of exposing an entity's credentials. Drives the rotation-interval
/// multiplier.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Criticality {
    Low,
    Medium,
    High,
}

impl Criticality {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Low => "low",
            Self::Medium => "medium",
            Self::High => "high",
        }
    }

    pub fn parse(value: &str) -> Result<Self> {
        match value {
            "low" => Ok(Self::Low),
            "medium" => Ok(Self::Medium),
            "high" => Ok(Self::High),
            other => Err(PasswordManagerError::InvalidInput(format!(
                "Unsupported criticality: {} (expected low, medium, or high)",
                other
            ))),
        }
    }
}

/// How an entry's secret came under custody. `ToolManaged` entries
/// (v0.8.0 external-secret writes) are excluded from age-based rotation
/// statuses by default — their lifecycle is owned by the deploying tool.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum LifecycleSource {
    Manual,
    Imported,
    Generated,
    ToolManaged,
}

impl LifecycleSource {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Manual => "manual",
            Self::Imported => "imported",
            Self::Generated => "generated",
            Self::ToolManaged => "tool_managed",
        }
    }

    pub fn parse(value: &str) -> Result<Self> {
        match value {
            "manual" => Ok(Self::Manual),
            "imported" => Ok(Self::Imported),
            "generated" => Ok(Self::Generated),
            "tool_managed" => Ok(Self::ToolManaged),
            other => Err(PasswordManagerError::InvalidInput(format!(
                "Unsupported lifecycle source: {}",
                other
            ))),
        }
    }
}

/// A logical entity. `name` and `notes` are DEK-encrypted at rest
/// (same field-encryption pattern as entry titles); `kind`, `criticality`,
/// and the policy override are declared policy and stay plaintext.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Entity {
    pub entity_id: String,
    pub name: String,
    pub kind: EntityKind,
    pub criticality: Criticality,
    pub notes: Option<String>,
    pub rotation_interval_days_override: Option<i64>,
    pub created_at: i64,
    pub modified_at: i64,
}

/// Entries that share one equality tag. Deliberately carries no tag
/// material — aggregates only.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ReuseCluster {
    pub size: usize,
    pub entry_ids: Vec<i64>,
    pub titles: Vec<String>,
}

/// Rotation posture for a single entry, as shown by `registry status` /
/// `registry report`.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct EntryPosture {
    pub entry_id: i64,
    pub title: String,
    pub entity_name: Option<String>,
    pub status: policy::RotationStatus,
    pub reasons: Vec<String>,
    pub resolved_interval_days: i64,
    pub days_since_rotation: Option<i64>,
    pub reuse_count: usize,
    pub strength_score: Option<u8>,
    pub tool_managed: bool,
    pub expires_at: Option<i64>,
}

/// Entity list with live credential counts.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct EntitySummary {
    pub entity: Entity,
    pub credential_count: i64,
}

/// Aggregate registry posture. This is the shape surfaced to CLI and (in a
/// later slice) the Tauri dashboard — never the underlying index.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RegistryOverview {
    pub entities: Vec<EntitySummary>,
    pub reuse_clusters: Vec<ReuseCluster>,
    pub posture: Vec<EntryPosture>,
    pub unassigned_entries: usize,
}

/// Aggregate result of a registry index sweep.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct SweepReport {
    pub scanned: usize,
    pub inserted: usize,
    pub unchanged: usize,
    pub rotated: usize,
    pub rekeyed: usize,
    pub removed: usize,
    pub orphans_pruned: usize,
}

/// Result of one equality-index upsert.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum TagUpsert {
    /// No prior row existed (new entry, post-migration backfill, post-restore).
    Inserted,
    /// Prior row present, tag identical.
    Unchanged,
    /// Prior row present under the current key, tag changed: the secret
    /// changed. Rotation was stamped.
    Rotated,
    /// Prior row present under a different equality key: rewritten without
    /// rotation stamping.
    Rekeyed,
    /// Entry is not eligible (passkey reference or empty secret); any
    /// existing row was removed.
    Removed,
}

// ---------------------------------------------------------------------------
// Tag computation
// ---------------------------------------------------------------------------

/// Compute the equality tag for a secret: HMAC-SHA256 under the
/// DEK-derived equality key, over exact UTF-8 bytes.
pub fn compute_equality_tag(equality_key: &[u8], secret: &str) -> Result<[u8; 32]> {
    let mut mac = HmacSha256::new_from_slice(equality_key)
        .map_err(|e| CryptoError::KdfFailed(format!("registry HMAC init failed: {}", e)))?;
    mac.update(secret.as_bytes());
    Ok(mac.finalize().into_bytes().into())
}

/// Entries join the equality index when their credential type carries a
/// retrievable secret and the secret is non-empty. Passkey references carry
/// no secret and TOTP seeds are unique per entry by construction — both
/// excluded.
pub fn is_equality_eligible(credential_type: CredentialType, secret: &str) -> bool {
    credential_type.is_retrievable_secret() && !secret.is_empty()
}

fn serialize_tag_cipher(dek: &DataEncryptionKey, tag_hex: &str) -> Result<Vec<u8>> {
    let encrypted = encrypt_string(dek, tag_hex)?;
    bincode::serialize(&encrypted).map_err(|e| DatabaseError::Serialization(e.to_string()).into())
}

fn deserialize_tag_cipher(dek: &DataEncryptionKey, blob: &[u8]) -> Result<String> {
    let encrypted: EncryptedEntry =
        bincode::deserialize(blob).map_err(|e| DatabaseError::Serialization(e.to_string()))?;
    decrypt_to_string(dek, &encrypted).map_err(PasswordManagerError::from)
}

/// Decrypt a stored equality tag back to its hex form (key holders only —
/// used by posture aggregation; never surfaced in aggregates).
pub fn decrypt_tag_cipher(dek: &DataEncryptionKey, blob: &[u8]) -> Result<String> {
    deserialize_tag_cipher(dek, blob)
}

// ---------------------------------------------------------------------------
// Store operations (shared by vault ops, sweep, and sync apply)
// ---------------------------------------------------------------------------

/// Insert, compare, or rewrite the equality tag for one entry, applying the
/// ADR-001 rotation semantics:
///
/// - no prior row → insert, no rotation stamp (absence is not change);
/// - prior row, same key, different tag → rewrite and stamp
///   `entry_lifecycle.password_rotated_at`;
/// - prior row, different key id → rewrite only (key migration is not
///   rotation);
/// - ineligible entry → remove any row.
///
/// Callers own transaction scope; on the vault write paths this runs in the
/// same connection as the entry write (auto-commit), on the sync path inside
/// the pull loop.
pub fn upsert_equality_tag(
    conn: &rusqlite::Connection,
    dek: &DataEncryptionKey,
    entry_id: i64,
    credential_type: CredentialType,
    secret: &str,
    now: i64,
) -> Result<TagUpsert> {
    let equality_key = derive_equality_key(dek)?;
    upsert_equality_tag_with_key(
        conn,
        dek,
        &equality_key,
        entry_id,
        credential_type,
        secret,
        now,
    )
}

/// As [`upsert_equality_tag`], for callers that already hold the derived
/// key (sweep loops derive once, not per row).
pub fn upsert_equality_tag_with_key(
    conn: &rusqlite::Connection,
    dek: &DataEncryptionKey,
    equality_key: &[u8],
    entry_id: i64,
    credential_type: CredentialType,
    secret: &str,
    now: i64,
) -> Result<TagUpsert> {
    if !is_equality_eligible(credential_type, secret) {
        conn.execute(
            "DELETE FROM secret_equality_index WHERE entry_id = ?1",
            [entry_id],
        )
        .map_err(DatabaseError::Sqlite)?;
        return Ok(TagUpsert::Removed);
    }

    let tag = compute_equality_tag(equality_key, secret)?;
    let tag_cipher = serialize_tag_cipher(dek, &hex::encode(tag))?;

    let prior: Option<(Vec<u8>, i64)> = conn
        .query_row(
            "SELECT tag_cipher, equality_key_id FROM secret_equality_index WHERE entry_id = ?1",
            [entry_id],
            |row| Ok((row.get(0)?, row.get(1)?)),
        )
        .optional()
        .map_err(DatabaseError::Sqlite)?;

    let outcome = match prior {
        None => {
            conn.execute(
                "INSERT INTO secret_equality_index
                    (entry_id, tag_cipher, algorithm_version, equality_key_id, updated_at)
                 VALUES (?1, ?2, ?3, ?4, ?5)",
                rusqlite::params![
                    entry_id,
                    tag_cipher,
                    EQUALITY_ALGORITHM_VERSION,
                    EQUALITY_KEY_ID,
                    now
                ],
            )
            .map_err(DatabaseError::Sqlite)?;
            TagUpsert::Inserted
        }
        Some((prior_cipher, prior_key_id)) => {
            if prior_key_id != EQUALITY_KEY_ID {
                update_tag(conn, &tag_cipher, now, entry_id)?;
                TagUpsert::Rekeyed
            } else {
                let prior_hex = deserialize_tag_cipher(dek, &prior_cipher)?;
                if prior_hex == hex::encode(tag) {
                    TagUpsert::Unchanged
                } else {
                    update_tag(conn, &tag_cipher, now, entry_id)?;
                    stamp_rotation(conn, entry_id, now)?;
                    TagUpsert::Rotated
                }
            }
        }
    };
    Ok(outcome)
}

fn update_tag(
    conn: &rusqlite::Connection,
    tag_cipher: &[u8],
    now: i64,
    entry_id: i64,
) -> Result<()> {
    conn.execute(
        "UPDATE secret_equality_index
         SET tag_cipher = ?1, algorithm_version = ?2, equality_key_id = ?3, updated_at = ?4
         WHERE entry_id = ?5",
        rusqlite::params![
            tag_cipher,
            EQUALITY_ALGORITHM_VERSION,
            EQUALITY_KEY_ID,
            now,
            entry_id
        ],
    )
    .map_err(DatabaseError::Sqlite)?;
    Ok(())
}

/// Stamp `password_rotated_at` on the entry's lifecycle row, creating the
/// row when absent. Other lifecycle columns are left untouched.
pub fn stamp_rotation(conn: &rusqlite::Connection, entry_id: i64, now: i64) -> Result<()> {
    conn.execute(
        "INSERT INTO entry_lifecycle (entry_id, password_rotated_at, source)
         VALUES (?1, ?2, 'manual')
         ON CONFLICT(entry_id) DO UPDATE SET password_rotated_at = excluded.password_rotated_at",
        rusqlite::params![entry_id, now],
    )
    .map_err(DatabaseError::Sqlite)?;
    Ok(())
}

/// Purge every registry row for an entry. Soft delete never fires the FK
/// CASCADE, so delete paths call this explicitly (mirroring the
/// `domain_mappings` cleanup) and sweeps prune orphans as belt-and-braces.
pub fn purge_registry_rows(conn: &rusqlite::Connection, entry_id: i64) -> Result<()> {
    conn.execute(
        "DELETE FROM secret_equality_index WHERE entry_id = ?1",
        [entry_id],
    )
    .map_err(DatabaseError::Sqlite)?;
    conn.execute(
        "DELETE FROM entry_lifecycle WHERE entry_id = ?1",
        [entry_id],
    )
    .map_err(DatabaseError::Sqlite)?;
    conn.execute(
        "DELETE FROM entity_memberships WHERE entry_id = ?1",
        [entry_id],
    )
    .map_err(DatabaseError::Sqlite)?;
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::database::Database;

    fn test_conn() -> Database {
        let db = Database::in_memory().unwrap();
        db.initialize_schema().unwrap();
        db
    }

    /// Insert a minimal live entry row directly (FK target for registry rows).
    fn insert_entry(conn: &rusqlite::Connection, entry_id: i64) {
        conn.execute(
            "INSERT INTO entries (entry_id, vault_id, title, username, password, entry_nonce,
                auth_tag, created_at, modified_at, credential_type)
             VALUES (?1, 1, X'01', X'02', X'03', X'04', X'05', 0, 0, 'password')",
            [entry_id],
        )
        .unwrap();
    }

    #[test]
    fn upsert_inserts_then_unchanged_then_rotates_with_stamp() {
        let db = test_conn();
        let conn = db.conn();
        let dek = DataEncryptionKey::new().unwrap();
        insert_entry(conn, 1);

        assert_eq!(
            upsert_equality_tag(conn, &dek, 1, CredentialType::Password, "secret-a", 100).unwrap(),
            TagUpsert::Inserted
        );
        // No rotation stamp on insert
        let stamped: Option<i64> = conn
            .query_row(
                "SELECT password_rotated_at FROM entry_lifecycle WHERE entry_id = 1",
                [],
                |row| row.get(0),
            )
            .optional()
            .unwrap();
        assert!(stamped.is_none());

        assert_eq!(
            upsert_equality_tag(conn, &dek, 1, CredentialType::Password, "secret-a", 110).unwrap(),
            TagUpsert::Unchanged
        );

        assert_eq!(
            upsert_equality_tag(conn, &dek, 1, CredentialType::Password, "secret-b", 120).unwrap(),
            TagUpsert::Rotated
        );
        let stamped: i64 = conn
            .query_row(
                "SELECT password_rotated_at FROM entry_lifecycle WHERE entry_id = 1",
                [],
                |row| row.get(0),
            )
            .unwrap();
        assert_eq!(stamped, 120);
    }

    #[test]
    fn ineligible_entries_never_join_the_index() {
        let db = test_conn();
        let conn = db.conn();
        let dek = DataEncryptionKey::new().unwrap();
        insert_entry(conn, 1);

        assert_eq!(
            upsert_equality_tag(
                conn,
                &dek,
                1,
                CredentialType::PasskeyReference,
                "whatever",
                100
            )
            .unwrap(),
            TagUpsert::Removed
        );
        assert_eq!(
            upsert_equality_tag(conn, &dek, 1, CredentialType::Password, "", 100).unwrap(),
            TagUpsert::Removed
        );
        let count: i64 = conn
            .query_row("SELECT COUNT(*) FROM secret_equality_index", [], |row| {
                row.get(0)
            })
            .unwrap();
        assert_eq!(count, 0);
    }

    #[test]
    fn key_version_migration_rewrites_without_rotation_stamp() {
        let db = test_conn();
        let conn = db.conn();
        let dek = DataEncryptionKey::new().unwrap();
        insert_entry(conn, 1);

        upsert_equality_tag(conn, &dek, 1, CredentialType::Password, "secret-a", 100).unwrap();

        // Simulate a tag written under an older key version
        conn.execute(
            "UPDATE secret_equality_index SET equality_key_id = 0 WHERE entry_id = 1",
            [],
        )
        .unwrap();

        // Even an identical secret rewrites (Rekeyed), and stamps nothing
        assert_eq!(
            upsert_equality_tag(conn, &dek, 1, CredentialType::Password, "secret-a", 110).unwrap(),
            TagUpsert::Rekeyed
        );
        let key_id: i64 = conn
            .query_row(
                "SELECT equality_key_id FROM secret_equality_index WHERE entry_id = 1",
                [],
                |row| row.get(0),
            )
            .unwrap();
        assert_eq!(key_id, EQUALITY_KEY_ID);
        let stamped: Option<i64> = conn
            .query_row(
                "SELECT password_rotated_at FROM entry_lifecycle WHERE entry_id = 1",
                [],
                |row| row.get(0),
            )
            .optional()
            .unwrap();
        assert!(stamped.is_none());
    }

    #[test]
    fn purge_removes_all_registry_rows_for_an_entry() {
        let db = test_conn();
        let conn = db.conn();
        let dek = DataEncryptionKey::new().unwrap();
        insert_entry(conn, 1);
        conn.execute(
            "INSERT INTO entities (entity_id, name, kind, criticality, created_at, modified_at)
             VALUES ('e1', X'01', 'database', 'high', 0, 0)",
            [],
        )
        .unwrap();
        conn.execute(
            "INSERT INTO entity_memberships (entry_id, entity_id, created_at) VALUES (1, 'e1', 0)",
            [],
        )
        .unwrap();
        upsert_equality_tag(conn, &dek, 1, CredentialType::Password, "secret-a", 100).unwrap();

        purge_registry_rows(conn, 1).unwrap();

        for table in [
            "secret_equality_index",
            "entry_lifecycle",
            "entity_memberships",
        ] {
            let count: i64 = conn
                .query_row(&format!("SELECT COUNT(*) FROM {}", table), [], |row| {
                    row.get(0)
                })
                .unwrap();
            assert_eq!(count, 0, "table {} should be empty after purge", table);
        }
    }

    #[test]
    fn tags_are_stored_encrypted_not_as_plaintext_hmac() {
        let db = test_conn();
        let conn = db.conn();
        let dek = DataEncryptionKey::new().unwrap();
        insert_entry(conn, 1);

        upsert_equality_tag(conn, &dek, 1, CredentialType::Password, "secret-a", 100).unwrap();

        let (stored, plaintext_tag): (Vec<u8>, String) = {
            let equality_key = derive_equality_key(&dek).unwrap();
            let tag = compute_equality_tag(&equality_key, "secret-a").unwrap();
            let stored: Vec<u8> = conn
                .query_row(
                    "SELECT tag_cipher FROM secret_equality_index WHERE entry_id = 1",
                    [],
                    |row| row.get(0),
                )
                .unwrap();
            (stored, hex::encode(tag))
        };

        // The deterministic HMAC must not be readable from the database file
        assert!(!window_contains(&stored, plaintext_tag.as_bytes()));
        // ...and decrypts back to the same tag for the key holder
        assert_eq!(decrypt_tag_cipher(&dek, &stored).unwrap(), plaintext_tag);
    }

    fn window_contains(haystack: &[u8], needle: &[u8]) -> bool {
        haystack
            .windows(needle.len())
            .any(|window| window == needle)
    }
}
