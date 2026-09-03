//! Registry operations for [`VaultManager`] (ADR-001).
//!
//! Entity CRUD, membership assignment, lifecycle metadata, the secret
//! equality index (write hooks, backfill sweep), and posture aggregation.
//! All registry SQL goes through the shared helpers in [`crate::registry`];
//! this layer owns encryption, locking, and audit.

use std::collections::HashMap;

use chrono::Utc;
use rusqlite::OptionalExtension;

use crate::crypto::cipher::{decrypt_to_string, encrypt_string, DataEncryptionKey, EncryptedEntry};
use crate::crypto::{analyze_password, PasswordStrength};
use crate::database::{EntryFilter, EntryRepository, SqliteEntryRepository};
use crate::registry::policy::{self, RecommendationInput};
use crate::registry::{
    decrypt_tag_cipher, purge_registry_rows, stamp_rotation, upsert_equality_tag,
    upsert_equality_tag_with_key, Criticality, Entity, EntityKind, EntitySummary, EntryPosture,
    LifecycleSource, RegistryOverview, ReuseCluster, SweepReport, TagUpsert, EQUALITY_KEY_ID,
};
use crate::{audit::AuditEventType, DatabaseError, PasswordManagerError, Result};

use super::VaultManager;

/// One entry's lifecycle row: `(password_rotated_at, expires_at,
/// rotation_interval_days_override, source)`.
type LifecycleMeta = (Option<i64>, Option<i64>, Option<i64>, String);

impl VaultManager {
    // -----------------------------------------------------------------------
    // Entity CRUD
    // -----------------------------------------------------------------------

    /// Register a logical entity. Names are unique (checked app-level, since
    /// the encrypted name column cannot enforce a SQL UNIQUE constraint).
    pub fn create_entity(
        &self,
        name: &str,
        kind: EntityKind,
        criticality: Criticality,
        notes: Option<&str>,
        rotation_interval_days_override: Option<i64>,
    ) -> Result<Entity> {
        let dek = self.key_hierarchy.dek()?;
        let now = Utc::now().timestamp();

        let db = self.lock_db()?;
        let conn = db.conn();

        let existing = load_entities(conn, dek)?;
        if existing.iter().any(|entity| entity.name == name) {
            return Err(PasswordManagerError::InvalidInput(format!(
                "Entity name already exists: {}",
                name
            )));
        }

        let entity_id = uuid::Uuid::new_v4().to_string();
        let name_blob = serialize_encrypted_string(dek, name)?;
        let notes_blob = notes
            .map(|value| serialize_encrypted_string(dek, value))
            .transpose()?;

        conn.execute(
            "INSERT INTO entities
                (entity_id, name, kind, criticality, notes, rotation_interval_days_override,
                 created_at, modified_at)
             VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8)",
            rusqlite::params![
                entity_id,
                name_blob,
                kind.as_str(),
                criticality.as_str(),
                notes_blob,
                rotation_interval_days_override,
                now,
                now
            ],
        )
        .map_err(DatabaseError::Sqlite)?;

        drop(db);

        if let Some(ref logger) = self.audit_logger {
            // Context carries the id, not the name: the audit log is plaintext.
            let _ = logger.log(
                AuditEventType::RegistryEntityCreated {
                    entity_id: entity_id.clone(),
                },
                &format!("Registry entity created: {}", entity_id),
            );
        }

        Ok(Entity {
            entity_id,
            name: name.to_string(),
            kind,
            criticality,
            notes: notes.map(ToString::to_string),
            rotation_interval_days_override,
            created_at: now,
            modified_at: now,
        })
    }

    /// List all registered entities (names/notes decrypted).
    pub fn list_entities(&self) -> Result<Vec<Entity>> {
        let dek = self.key_hierarchy.dek()?;
        let db = self.lock_db()?;
        load_entities(db.conn(), dek)
    }

    /// Delete an entity. Memberships cascade (hard delete — registry tables
    /// have no sync tombstones); the entries themselves are untouched.
    pub fn delete_entity(&self, entity_id: &str) -> Result<()> {
        let db = self.lock_db()?;
        let deleted = db
            .conn()
            .execute("DELETE FROM entities WHERE entity_id = ?1", [entity_id])
            .map_err(DatabaseError::Sqlite)?;
        drop(db);

        if deleted == 0 {
            return Err(PasswordManagerError::NotFound(format!(
                "Entity {}",
                entity_id
            )));
        }

        if let Some(ref logger) = self.audit_logger {
            let _ = logger.log(
                AuditEventType::RegistryEntityDeleted {
                    entity_id: entity_id.to_string(),
                },
                &format!("Registry entity deleted: {}", entity_id),
            );
        }
        Ok(())
    }

    // -----------------------------------------------------------------------
    // Membership and lifecycle
    // -----------------------------------------------------------------------

    /// Assign a live entry to an entity (single membership per entry; a
    /// re-assignment replaces the previous one). `label` is stored encrypted.
    pub fn assign_entry(&self, entry_id: i64, entity_id: &str, label: Option<&str>) -> Result<()> {
        let dek = self.key_hierarchy.dek()?;
        let now = Utc::now().timestamp();

        let db = self.lock_db()?;
        let conn = db.conn();

        let entity_exists: bool = conn
            .query_row(
                "SELECT EXISTS(SELECT 1 FROM entities WHERE entity_id = ?1)",
                [entity_id],
                |row| row.get(0),
            )
            .map_err(DatabaseError::Sqlite)?;
        if !entity_exists {
            return Err(PasswordManagerError::NotFound(format!(
                "Entity {}",
                entity_id
            )));
        }

        let entry_exists: bool = conn
            .query_row(
                "SELECT EXISTS(SELECT 1 FROM entries WHERE entry_id = ?1 AND is_deleted = 0)",
                [entry_id],
                |row| row.get(0),
            )
            .map_err(DatabaseError::Sqlite)?;
        if !entry_exists {
            return Err(PasswordManagerError::NotFound(format!(
                "Entry {}",
                entry_id
            )));
        }

        let label_blob = label
            .filter(|value| !value.is_empty())
            .map(|value| serialize_encrypted_string(dek, value))
            .transpose()?;

        conn.execute(
            "INSERT INTO entity_memberships (entry_id, entity_id, label, created_at)
             VALUES (?1, ?2, ?3, ?4)
             ON CONFLICT(entry_id) DO UPDATE SET
                entity_id = excluded.entity_id, label = excluded.label",
            rusqlite::params![entry_id, entity_id, label_blob, now],
        )
        .map_err(DatabaseError::Sqlite)?;

        drop(db);

        if let Some(ref logger) = self.audit_logger {
            let _ = logger.log(
                AuditEventType::EntryAssignedToEntity {
                    entry_id,
                    entity_id: entity_id.to_string(),
                },
                &format!("Entry {} assigned to entity {}", entry_id, entity_id),
            );
        }
        Ok(())
    }

    /// Remove an entry's entity assignment (the escape hatch for a wrong
    /// `assign_entry` call — otherwise membership can only be replaced,
    /// never cleared). A no-op (not an error) when the entry has no
    /// assignment.
    pub fn unassign_entry(&self, entry_id: i64) -> Result<()> {
        let db = self.lock_db()?;
        let rows = db
            .conn()
            .execute(
                "DELETE FROM entity_memberships WHERE entry_id = ?1",
                [entry_id],
            )
            .map_err(DatabaseError::Sqlite)?;
        drop(db);

        if rows > 0 {
            if let Some(ref logger) = self.audit_logger {
                let _ = logger.log(
                    AuditEventType::EntryAssignedToEntity {
                        entry_id,
                        entity_id: String::new(),
                    },
                    &format!("Entry {} unassigned from its entity", entry_id),
                );
            }
        }
        Ok(())
    }

    /// Stamp the lifecycle source for an entry (e.g. the daemon's
    /// external-secret write path stamps [`LifecycleSource::ToolManaged`]).
    pub fn set_lifecycle_source(&self, entry_id: i64, source: LifecycleSource) -> Result<()> {
        let db = self.lock_db()?;
        db.conn()
            .execute(
                "INSERT INTO entry_lifecycle (entry_id, source) VALUES (?1, ?2)
                 ON CONFLICT(entry_id) DO UPDATE SET source = excluded.source",
                rusqlite::params![entry_id, source.as_str()],
            )
            .map_err(DatabaseError::Sqlite)?;
        Ok(())
    }

    /// Record a provider-managed expiry for an entry (api-key metadata).
    pub fn set_expires_at(&self, entry_id: i64, expires_at: Option<i64>) -> Result<()> {
        let db = self.lock_db()?;
        db.conn()
            .execute(
                "INSERT INTO entry_lifecycle (entry_id, expires_at) VALUES (?1, ?2)
                 ON CONFLICT(entry_id) DO UPDATE SET expires_at = excluded.expires_at",
                rusqlite::params![entry_id, expires_at],
            )
            .map_err(DatabaseError::Sqlite)?;
        Ok(())
    }

    /// Manually mark an entry's secret as rotated (the "mark rotated" action
    /// for provider-issued keys that cannot be auto-generated).
    pub fn mark_entry_rotated(&self, entry_id: i64) -> Result<()> {
        let now = Utc::now().timestamp();
        let db = self.lock_db()?;
        stamp_rotation(db.conn(), entry_id, now)
    }

    // -----------------------------------------------------------------------
    // Write hooks (called from add_entry / update_entry / delete_entry)
    // -----------------------------------------------------------------------

    /// Index a freshly created entry. Best-effort by contract: the caller
    /// logs failures and the sweep repairs missing rows.
    pub(super) fn registry_on_add(&self, entry_id: i64, entry: &super::Entry) -> Result<()> {
        let dek = self.key_hierarchy.dek()?;
        let now = Utc::now().timestamp();
        let db = self.lock_db()?;
        upsert_equality_tag(
            db.conn(),
            dek,
            entry_id,
            entry.credential_type,
            entry.password.as_str(),
            now,
        )?;
        Ok(())
    }

    /// Re-index an updated entry. A changed tag against a prior row stamps
    /// `password_rotated_at` (in [`crate::registry`]) and emits `SecretRotated`.
    pub(super) fn registry_on_update(&self, entry_id: i64, entry: &super::Entry) -> Result<()> {
        let dek = self.key_hierarchy.dek()?;
        let now = Utc::now().timestamp();

        let outcome = {
            let db = self.lock_db()?;
            upsert_equality_tag(
                db.conn(),
                dek,
                entry_id,
                entry.credential_type,
                entry.password.as_str(),
                now,
            )?
        };

        if outcome == TagUpsert::Rotated {
            if let Some(ref logger) = self.audit_logger {
                let _ = logger.log(
                    AuditEventType::SecretRotated { entry_id },
                    &format!("Secret value changed for entry {}", entry_id),
                );
            }
        }
        Ok(())
    }

    /// Purge registry rows for a deleted entry inside the delete
    /// transaction. Soft delete never fires FK CASCADE.
    pub(super) fn registry_purge_in_tx(
        tx: &rusqlite::Transaction<'_>,
        entry_id: i64,
    ) -> Result<()> {
        purge_registry_rows(tx, entry_id)
    }

    // -----------------------------------------------------------------------
    // Sweep / backfill
    // -----------------------------------------------------------------------

    /// True when the equality index needs a backfill sweep: the completion
    /// flag is missing (fresh migration, restored pre-v5 backup) or the
    /// recorded equality key id is stale. Per-callers contract: checked on
    /// unlock and before registry reads.
    pub fn registry_backfill_needed(&self) -> Result<bool> {
        let db = self.lock_db()?;
        let conn = db.conn();

        let complete: Option<String> = registry_state_value(conn, "backfill_complete")?;
        if complete.as_deref() != Some("1") {
            return Ok(true);
        }

        let key_id: Option<String> = registry_state_value(conn, "equality_key_id")?;
        Ok(key_id.as_deref() != Some(&EQUALITY_KEY_ID.to_string()))
    }

    /// Reconcile the whole equality index with the live entry set:
    /// insert missing tags, stamp rotations, prune orphans, and record
    /// completion. This is the only path that performs a full-vault decrypt
    /// for the registry, and it runs only when [`Self::registry_backfill_needed`]
    /// says the index is incomplete.
    ///
    /// Uses a dedicated decrypt-and-HMAC loop — not `get_entry` — so a sweep
    /// emits no `CredentialViewed` audit events and never routes encrypted
    /// title blobs into the plaintext audit log.
    pub fn sweep_registry_index(&self) -> Result<SweepReport> {
        if !self.is_unlocked() {
            return Err(PasswordManagerError::VaultLocked);
        }
        let dek = self.key_hierarchy.dek()?;
        let equality_key = self.key_hierarchy.equality_key()?;
        let now = Utc::now().timestamp();

        let mut report = SweepReport::default();

        let db = self.lock_db()?;
        {
            let repo = SqliteEntryRepository::new(&db);
            let raw_rows = repo.list_raw(EntryFilter::default())?;
            report.scanned = raw_rows.len();

            for row in &raw_rows {
                let credential_type = match super::CredentialType::parse(&row.credential_type) {
                    Ok(credential_type) => credential_type,
                    Err(_) => continue,
                };
                if !credential_type.is_retrievable_secret() {
                    continue;
                }
                let secret = decrypt_blob_string(dek, &row.password)?;
                let outcome = upsert_equality_tag_with_key(
                    db.conn(),
                    dek,
                    &equality_key,
                    row.entry_id,
                    credential_type,
                    &secret,
                    now,
                )?;
                match outcome {
                    TagUpsert::Inserted => report.inserted += 1,
                    TagUpsert::Unchanged => report.unchanged += 1,
                    TagUpsert::Rotated => report.rotated += 1,
                    TagUpsert::Rekeyed => report.rekeyed += 1,
                    TagUpsert::Removed => report.removed += 1,
                }
            }
        }

        // Orphan pruning: rows pointing at missing or soft-deleted entries
        // (belt-and-braces alongside the delete-path purge).
        for table in [
            "secret_equality_index",
            "entry_lifecycle",
            "entity_memberships",
        ] {
            let sql = format!(
                "DELETE FROM {table} WHERE entry_id NOT IN \
                 (SELECT entry_id FROM entries WHERE is_deleted = 0)"
            );
            report.orphans_pruned += db.conn().execute(&sql, []).map_err(DatabaseError::Sqlite)?;
        }

        set_registry_state(db.conn(), "backfill_complete", "1")?;
        set_registry_state(db.conn(), "equality_key_id", &EQUALITY_KEY_ID.to_string())?;

        drop(db);

        if let Some(ref logger) = self.audit_logger {
            let _ = logger.log(
                AuditEventType::RegistryIndexRebuilt {
                    entries: report.scanned,
                },
                &format!("Registry index swept over {} entries", report.scanned),
            );
        }

        Ok(report)
    }

    // -----------------------------------------------------------------------
    // Posture aggregation
    // -----------------------------------------------------------------------

    /// Aggregate registry posture. `include_strength` decrypts every eligible
    /// secret for strength scoring — the light path (`false`) reads only the
    /// index, memberships, and lifecycle metadata.
    pub fn registry_overview(&self, include_strength: bool) -> Result<RegistryOverview> {
        if !self.is_unlocked() {
            return Err(PasswordManagerError::VaultLocked);
        }
        let dek = self.key_hierarchy.dek()?;
        let now = Utc::now().timestamp();
        let weak_threshold_score = PasswordStrength::Weak.score();

        let db = self.lock_db()?;
        let conn = db.conn();

        let entities = load_entities(conn, dek)?;
        let entity_by_id: HashMap<&str, &Entity> =
            entities.iter().map(|e| (e.entity_id.as_str(), e)).collect();

        let repo = SqliteEntryRepository::new(&db);
        let raw_rows = repo.list_raw(EntryFilter::default())?;

        // Equality tags → reuse groups (decrypted in memory only)
        let mut tag_groups: HashMap<String, Vec<i64>> = HashMap::new();
        {
            let mut stmt = conn
                .prepare("SELECT entry_id, tag_cipher FROM secret_equality_index")
                .map_err(DatabaseError::Sqlite)?;
            let rows = stmt
                .query_map([], |row| {
                    Ok((row.get::<_, i64>(0)?, row.get::<_, Vec<u8>>(1)?))
                })
                .map_err(DatabaseError::Sqlite)?;
            for row in rows {
                let (entry_id, cipher) = row.map_err(DatabaseError::Sqlite)?;
                let tag_hex = decrypt_tag_cipher(dek, &cipher)?;
                tag_groups.entry(tag_hex).or_default().push(entry_id);
            }
        }
        let reuse_of = |entry_id: i64| -> usize {
            tag_groups
                .values()
                .filter(|members| members.contains(&entry_id))
                .map(|members| members.len())
                .find(|size| *size > 1)
                .unwrap_or(1)
        };

        // Memberships: entry → entity
        let mut membership_entity: HashMap<i64, String> = HashMap::new();
        {
            let mut stmt = conn
                .prepare("SELECT entry_id, entity_id FROM entity_memberships")
                .map_err(DatabaseError::Sqlite)?;
            let rows = stmt
                .query_map([], |row| {
                    Ok((row.get::<_, i64>(0)?, row.get::<_, String>(1)?))
                })
                .map_err(DatabaseError::Sqlite)?;
            for row in rows {
                let (entry_id, entity_id) = row.map_err(DatabaseError::Sqlite)?;
                membership_entity.insert(entry_id, entity_id);
            }
        }

        // Lifecycle metadata: (rotated_at, expires_at, interval_override, source)
        let mut lifecycle: HashMap<i64, LifecycleMeta> = HashMap::new();
        {
            let mut stmt = conn
                .prepare(
                    "SELECT entry_id, password_rotated_at, expires_at,
                            rotation_interval_days_override, source
                     FROM entry_lifecycle",
                )
                .map_err(DatabaseError::Sqlite)?;
            let rows = stmt
                .query_map([], |row| {
                    Ok((
                        row.get::<_, i64>(0)?,
                        row.get::<_, Option<i64>>(1)?,
                        row.get::<_, Option<i64>>(2)?,
                        row.get::<_, Option<i64>>(3)?,
                        row.get::<_, String>(4)?,
                    ))
                })
                .map_err(DatabaseError::Sqlite)?;
            for row in rows {
                let (entry_id, rotated, expires, override_days, source) =
                    row.map_err(DatabaseError::Sqlite)?;
                lifecycle.insert(entry_id, (rotated, expires, override_days, source));
            }
        }

        // Entity credential counts (live entries only)
        let mut counts: HashMap<String, i64> = HashMap::new();
        let mut unassigned_entries = 0usize;
        for row in &raw_rows {
            match membership_entity.get(&row.entry_id) {
                Some(entity_id) => *counts.entry(entity_id.clone()).or_default() += 1,
                None => {
                    // Passkey references carry no retrievable secret and are
                    // not posture subjects.
                    let retrievable = super::CredentialType::parse(&row.credential_type)
                        .map(|ct| ct.is_retrievable_secret())
                        .unwrap_or(false);
                    if retrievable {
                        unassigned_entries += 1;
                    }
                }
            }
        }
        let entity_summaries: Vec<EntitySummary> = entities
            .iter()
            .map(|entity| EntitySummary {
                entity: entity.clone(),
                credential_count: counts.get(&entity.entity_id).copied().unwrap_or(0),
            })
            .collect();

        // Reuse clusters (>1), titled
        let mut clusters = Vec::new();
        for members in tag_groups.values() {
            if members.len() < 2 {
                continue;
            }
            let titles = members
                .iter()
                .filter_map(|entry_id| {
                    raw_rows
                        .iter()
                        .find(|row| row.entry_id == *entry_id)
                        .and_then(|row| decrypt_blob_string(dek, &row.title).ok())
                })
                .collect::<Vec<_>>();
            clusters.push(ReuseCluster {
                size: members.len(),
                entry_ids: members.clone(),
                titles,
            });
        }
        clusters.sort_by(|a, b| b.size.cmp(&a.size).then(a.entry_ids.cmp(&b.entry_ids)));

        // Per-entry rotation posture
        let mut posture = Vec::new();
        for row in &raw_rows {
            let Ok(credential_type) = super::CredentialType::parse(&row.credential_type) else {
                continue;
            };
            if !credential_type.is_retrievable_secret() {
                continue;
            }
            let title = decrypt_blob_string(dek, &row.title)?;

            let membership_entity_id = membership_entity.get(&row.entry_id);
            let entity = membership_entity_id.and_then(|id| entity_by_id.get(id.as_str()).copied());
            let (rotated_at, expires_at, entry_override, source) = lifecycle
                .get(&row.entry_id)
                .cloned()
                .unwrap_or((None, None, None, "manual".to_string()));
            let source = LifecycleSource::parse(&source).unwrap_or(LifecycleSource::Manual);

            let age_reference = rotated_at.unwrap_or(row.created_at);
            let age_days = ((now - age_reference).div_euclid(86_400)).max(0);
            let reuse_count = reuse_of(row.entry_id);

            let strength_score = if include_strength
                && crate::registry::is_equality_eligible(credential_type, "x")
            {
                let secret = decrypt_blob_string(dek, &row.password)?;
                let analysis = analyze_password(secret.as_str())?;
                Some(analysis.strength.score())
            } else {
                None
            };

            let entity_override = entity.and_then(|entity| entity.rotation_interval_days_override);
            let recommendation = policy::recommend(&RecommendationInput {
                kind: entity
                    .map(|entity| entity.kind)
                    .unwrap_or(EntityKind::Other),
                criticality: entity
                    .map(|entity| entity.criticality)
                    .unwrap_or(Criticality::Medium),
                entry_override_days: entry_override,
                entity_override_days: entity_override,
                age_days,
                reuse_count,
                strength_score,
                weak_threshold_score,
                expires_at,
                now,
                // Tool-managed secrets are excluded from age-based statuses
                // unless the entity opts back in via an interval override.
                suppress_age: source == LifecycleSource::ToolManaged && entity_override.is_none(),
            });

            posture.push(EntryPosture {
                entry_id: row.entry_id,
                title,
                entity_name: entity.map(|entity| entity.name.clone()),
                status: recommendation.status,
                reasons: recommendation.reasons,
                resolved_interval_days: recommendation.resolved_interval_days,
                days_since_rotation: Some(age_days),
                reuse_count,
                strength_score,
                tool_managed: source == LifecycleSource::ToolManaged,
                expires_at,
            });
        }
        posture.sort_by(|a, b| b.status.cmp(&a.status).then(a.title.cmp(&b.title)));

        Ok(RegistryOverview {
            entities: entity_summaries,
            reuse_clusters: clusters,
            posture,
            unassigned_entries,
        })
    }
}

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

fn serialize_encrypted_string(dek: &DataEncryptionKey, value: &str) -> Result<Vec<u8>> {
    let encrypted = encrypt_string(dek, value)?;
    bincode::serialize(&encrypted).map_err(|e| DatabaseError::Serialization(e.to_string()).into())
}

/// Decrypt a bincode-wrapped [`EncryptedEntry`] string column.
fn decrypt_blob_string(dek: &DataEncryptionKey, blob: &[u8]) -> Result<String> {
    let encrypted: EncryptedEntry =
        bincode::deserialize(blob).map_err(|e| DatabaseError::Serialization(e.to_string()))?;
    decrypt_to_string(dek, &encrypted).map_err(PasswordManagerError::from)
}

fn load_entities(conn: &rusqlite::Connection, dek: &DataEncryptionKey) -> Result<Vec<Entity>> {
    let mut stmt = conn
        .prepare(
            "SELECT entity_id, name, kind, criticality, notes, rotation_interval_days_override,
                    created_at, modified_at
             FROM entities ORDER BY created_at ASC",
        )
        .map_err(DatabaseError::Sqlite)?;

    let rows = stmt
        .query_map([], |row| {
            Ok((
                row.get::<_, String>(0)?,
                row.get::<_, Vec<u8>>(1)?,
                row.get::<_, String>(2)?,
                row.get::<_, String>(3)?,
                row.get::<_, Option<Vec<u8>>>(4)?,
                row.get::<_, Option<i64>>(5)?,
                row.get::<_, i64>(6)?,
                row.get::<_, i64>(7)?,
            ))
        })
        .map_err(DatabaseError::Sqlite)?;

    let mut entities = Vec::new();
    for row in rows {
        let (
            entity_id,
            name_blob,
            kind,
            criticality,
            notes_blob,
            override_days,
            created_at,
            modified_at,
        ) = row.map_err(DatabaseError::Sqlite)?;
        entities.push(Entity {
            entity_id,
            name: decrypt_blob_string(dek, &name_blob)?,
            kind: EntityKind::parse(&kind)?,
            criticality: Criticality::parse(&criticality)?,
            notes: notes_blob
                .map(|blob| decrypt_blob_string(dek, &blob))
                .transpose()?,
            rotation_interval_days_override: override_days,
            created_at,
            modified_at,
        });
    }
    Ok(entities)
}

fn registry_state_value(conn: &rusqlite::Connection, key: &str) -> Result<Option<String>> {
    let value = conn
        .query_row(
            "SELECT value FROM registry_state WHERE key = ?1",
            [key],
            |row| row.get(0),
        )
        .optional()
        .map_err(DatabaseError::Sqlite)?;
    Ok(value)
}

fn set_registry_state(conn: &rusqlite::Connection, key: &str, value: &str) -> Result<()> {
    conn.execute(
        "INSERT INTO registry_state (key, value) VALUES (?1, ?2)
         ON CONFLICT(key) DO UPDATE SET value = excluded.value",
        rusqlite::params![key, value],
    )
    .map_err(DatabaseError::Sqlite)?;
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::registry::policy::RotationStatus;
    use chrono::Utc;

    fn test_vault() -> VaultManager {
        VaultManager::create(":memory:", b"registry_test_password").unwrap()
    }

    fn test_entry(
        title: &str,
        password: &str,
        credential_type: super::super::CredentialType,
    ) -> super::super::Entry {
        super::super::Entry {
            entry_id: None,
            title: title.to_string(),
            username: "svc-account".to_string(),
            password: password.to_string().into(),
            url: None,
            notes: None,
            credential_type,
            created_at: Utc::now(),
            modified_at: Utc::now(),
            favorite: false,
        }
    }

    #[test]
    fn entity_crud_roundtrip_uniqueness_and_delete() {
        let vault = test_vault();

        let entity = vault
            .create_entity(
                "trading-postgres",
                EntityKind::Database,
                Criticality::High,
                Some("primary trading DB"),
                None,
            )
            .unwrap();

        // Round-trips with the name/notes encrypted at rest
        let listed = vault.list_entities().unwrap();
        assert_eq!(listed.len(), 1);
        assert_eq!(listed[0].name, "trading-postgres");
        assert_eq!(listed[0].notes.as_deref(), Some("primary trading DB"));
        assert_eq!(listed[0].kind, EntityKind::Database);
        assert_eq!(listed[0].criticality, Criticality::High);

        // Names are unique (app-level check on the encrypted column)
        let duplicate = vault.create_entity(
            "trading-postgres",
            EntityKind::Database,
            Criticality::Medium,
            None,
            None,
        );
        assert!(duplicate.is_err());

        // The stored name blob must not be plaintext
        {
            let db = vault.db.lock().unwrap();
            let name_blob: Vec<u8> = db
                .conn()
                .query_row("SELECT name FROM entities", [], |row| row.get(0))
                .unwrap();
            assert!(!String::from_utf8_lossy(&name_blob).contains("trading-postgres"));
        }

        vault.delete_entity(&entity.entity_id).unwrap();
        assert!(vault.list_entities().unwrap().is_empty());

        let missing = vault.delete_entity(&entity.entity_id);
        assert!(missing.is_err());
    }

    #[test]
    fn assign_entry_reflected_in_overview() {
        let vault = test_vault();
        let entity = vault
            .create_entity(
                "fred",
                EntityKind::RegulatoryData,
                Criticality::Medium,
                None,
                None,
            )
            .unwrap();
        let entry_id = vault
            .add_entry(&test_entry(
                "FRED key",
                "fred-api-key-value",
                super::super::CredentialType::ApiKey,
            ))
            .unwrap();

        vault
            .assign_entry(entry_id, &entity.entity_id, Some("prod"))
            .unwrap();

        let overview = vault.registry_overview(false).unwrap();
        assert_eq!(overview.entities.len(), 1);
        assert_eq!(overview.entities[0].credential_count, 1);
        assert_eq!(overview.unassigned_entries, 0);
        assert_eq!(overview.posture.len(), 1);
        assert_eq!(overview.posture[0].entity_name.as_deref(), Some("fred"));
        assert!(!overview.posture[0].tool_managed);

        // Tool-managed stamp surfaces in posture
        vault
            .set_lifecycle_source(entry_id, LifecycleSource::ToolManaged)
            .unwrap();
        let overview = vault.registry_overview(false).unwrap();
        assert!(overview.posture[0].tool_managed);
    }

    #[test]
    fn reuse_detection_clusters_across_entities() {
        let vault = test_vault();
        let entity_a = vault
            .create_entity(
                "postgres",
                EntityKind::Database,
                Criticality::High,
                None,
                None,
            )
            .unwrap();
        let entity_b = vault
            .create_entity(
                "webhooks",
                EntityKind::Notification,
                Criticality::Medium,
                None,
                None,
            )
            .unwrap();

        let first = vault
            .add_entry(&test_entry(
                "Primary DB",
                "shared-secret-1",
                super::super::CredentialType::Password,
            ))
            .unwrap();
        let second = vault
            .add_entry(&test_entry(
                "Alert webhook",
                "shared-secret-1",
                super::super::CredentialType::Password,
            ))
            .unwrap();
        let third = vault
            .add_entry(&test_entry(
                "Unique cred",
                "unique-secret",
                super::super::CredentialType::Password,
            ))
            .unwrap();
        vault
            .assign_entry(first, &entity_a.entity_id, None)
            .unwrap();
        vault
            .assign_entry(second, &entity_b.entity_id, None)
            .unwrap();

        // add_entry hooks already indexed everything; the sweep is a no-op
        let report = vault.sweep_registry_index().unwrap();
        assert_eq!(report.scanned, 3);
        assert_eq!(report.inserted, 0);
        assert_eq!(report.unchanged, 3);

        let overview = vault.registry_overview(false).unwrap();
        assert_eq!(overview.reuse_clusters.len(), 1);
        assert_eq!(overview.reuse_clusters[0].size, 2);
        assert_eq!(overview.reuse_clusters[0].entry_ids, vec![first, second]);
        // Aggregate carries titles, never tag material
        assert_eq!(overview.reuse_clusters[0].titles.len(), 2);

        // Reused entry floors its rotation status
        let reused: Vec<_> = overview
            .posture
            .iter()
            .filter(|entry| entry.status == RotationStatus::Reused)
            .collect();
        assert_eq!(reused.len(), 2);
        assert!(reused.iter().all(|entry| entry.reuse_count == 2));
        let _ = third;
    }

    #[test]
    fn rotation_stamp_on_password_change_not_title_edit() {
        let vault = test_vault();
        let entry_id = vault
            .add_entry(&test_entry(
                "DB cred",
                "password-v1",
                super::super::CredentialType::Password,
            ))
            .unwrap();

        let rotated_before: Option<i64> = {
            let db = vault.db.lock().unwrap();
            db.conn()
                .query_row(
                    "SELECT password_rotated_at FROM entry_lifecycle WHERE entry_id = ?1",
                    [entry_id],
                    |row| row.get(0),
                )
                .optional()
                .unwrap()
        };
        assert!(rotated_before.is_none(), "insert must not stamp rotation");

        // Password change → tag change → rotation stamp
        let mut updated = test_entry(
            "DB cred",
            "password-v2",
            super::super::CredentialType::Password,
        );
        updated.entry_id = Some(entry_id);
        vault.update_entry(entry_id, &updated).unwrap();

        let rotated_after_password_change: Option<i64> = {
            let db = vault.db.lock().unwrap();
            db.conn()
                .query_row(
                    "SELECT password_rotated_at FROM entry_lifecycle WHERE entry_id = ?1",
                    [entry_id],
                    |row| row.get(0),
                )
                .optional()
                .unwrap()
        };
        assert!(rotated_after_password_change.is_some());

        // Title-only edit → unchanged tag → no new stamp
        let mut retitled = test_entry(
            "DB cred renamed",
            "password-v2",
            super::super::CredentialType::Password,
        );
        retitled.entry_id = Some(entry_id);
        vault.update_entry(entry_id, &retitled).unwrap();

        let rotated_after_title_edit: Option<i64> = {
            let db = vault.db.lock().unwrap();
            db.conn()
                .query_row(
                    "SELECT password_rotated_at FROM entry_lifecycle WHERE entry_id = ?1",
                    [entry_id],
                    |row| row.get(0),
                )
                .optional()
                .unwrap()
        };
        assert_eq!(
            rotated_after_password_change, rotated_after_title_edit,
            "title-only edit must not stamp rotation"
        );
    }

    #[test]
    fn delete_entry_purges_registry_rows() {
        let vault = test_vault();
        let entity = vault
            .create_entity("gateway", EntityKind::Broker, Criticality::High, None, None)
            .unwrap();
        let entry_id = vault
            .add_entry(&test_entry(
                "IBKR",
                "gateway-secret",
                super::super::CredentialType::Password,
            ))
            .unwrap();
        vault
            .assign_entry(entry_id, &entity.entity_id, None)
            .unwrap();

        vault.delete_entry(entry_id).unwrap();

        {
            let db = vault.db.lock().unwrap();
            let conn = db.conn();
            for table in [
                "secret_equality_index",
                "entry_lifecycle",
                "entity_memberships",
            ] {
                let count: i64 = conn
                    .query_row(
                        &format!("SELECT COUNT(*) FROM {} WHERE entry_id = ?1", table),
                        [entry_id],
                        |row| row.get(0),
                    )
                    .unwrap();
                assert_eq!(count, 0, "{} rows must be purged on delete", table);
            }
        }

        // Aggregates must not resurrect the deleted entry
        let overview = vault.registry_overview(false).unwrap();
        assert_eq!(overview.entities[0].credential_count, 0);
        assert_eq!(overview.posture.len(), 0);
    }

    #[test]
    fn sweep_prunes_orphans_from_soft_deleted_entries() {
        let vault = test_vault();
        let entry_id = vault
            .add_entry(&test_entry(
                "Orphan source",
                "some-secret",
                super::super::CredentialType::Password,
            ))
            .unwrap();

        // Simulate a soft delete that predates the registry purge hook
        // (e.g. an older binary): the entry is dead but its index row stays.
        {
            let db = vault.db.lock().unwrap();
            db.conn()
                .execute(
                    "UPDATE entries SET is_deleted = 1 WHERE entry_id = ?1",
                    [entry_id],
                )
                .unwrap();
        }

        let report = vault.sweep_registry_index().unwrap();
        assert!(
            report.orphans_pruned >= 1,
            "orphaned index row must be pruned"
        );

        let remaining: i64 = {
            let db = vault.db.lock().unwrap();
            db.conn()
                .query_row("SELECT COUNT(*) FROM secret_equality_index", [], |row| {
                    row.get(0)
                })
                .unwrap()
        };
        assert_eq!(remaining, 0);

        // Sweep completion is recorded as database state
        assert!(!vault.registry_backfill_needed().unwrap());
    }
}
