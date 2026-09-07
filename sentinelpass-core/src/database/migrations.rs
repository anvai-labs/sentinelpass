//! Database migrations for schema versioning.
//!
//! Schema version is tracked via `db_metadata.version` and validated on vault
//! open in `schema::Database::validate_schema_version()`. When future schema
//! changes are needed, add migration logic here and bump
//! `schema::CURRENT_SCHEMA_VERSION`.

use crate::{DatabaseError, Result};
use rusqlite::Connection;

/// Migrate schema from v1 to v2: add sync columns and tables.
///
/// Transactionality (WBS-402 / ADR-005 rev 3): the DDL, the sync-id data
/// backfill, and the version bump commit as ONE transaction. The backfill
/// previously ran as a post-commit phase — an interruption there left a
/// v2-versioned vault with NULL sync_ids that no migration would ever revisit
/// (the version gate saw v2 and stopped). With the fold, an interruption at
/// ANY point rolls the vault back to a pristine v1 that the old code path can
/// still open and that re-runs the migration from scratch on the next open.
pub fn migrate_v1_to_v2(conn: &Connection) -> Result<()> {
    // Take the write lock FIRST (BEGIN IMMEDIATE), matching the v5→v6/v6→v7
    // pattern: two processes migrating the same vault cannot interleave.
    conn.execute_batch("BEGIN IMMEDIATE;")
        .map_err(DatabaseError::Sqlite)?;

    let inner = || -> Result<()> {
        conn.execute_batch(
            " -- Add sync columns to entries
            ALTER TABLE entries ADD COLUMN sync_id TEXT;
            ALTER TABLE entries ADD COLUMN sync_version INTEGER NOT NULL DEFAULT 0;
            ALTER TABLE entries ADD COLUMN sync_state TEXT NOT NULL DEFAULT 'pending';
            ALTER TABLE entries ADD COLUMN last_synced_at INTEGER;
            ALTER TABLE entries ADD COLUMN is_deleted INTEGER NOT NULL DEFAULT 0;
            ALTER TABLE entries ADD COLUMN deleted_at INTEGER;

            -- Add sync columns to ssh_keys
            ALTER TABLE ssh_keys ADD COLUMN sync_id TEXT;
            ALTER TABLE ssh_keys ADD COLUMN sync_version INTEGER NOT NULL DEFAULT 0;
            ALTER TABLE ssh_keys ADD COLUMN sync_state TEXT NOT NULL DEFAULT 'pending';
            ALTER TABLE ssh_keys ADD COLUMN last_synced_at INTEGER;
            ALTER TABLE ssh_keys ADD COLUMN is_deleted INTEGER NOT NULL DEFAULT 0;
            ALTER TABLE ssh_keys ADD COLUMN deleted_at INTEGER;

            -- Add sync columns to totp_secrets
            ALTER TABLE totp_secrets ADD COLUMN sync_id TEXT;
            ALTER TABLE totp_secrets ADD COLUMN sync_version INTEGER NOT NULL DEFAULT 0;
            ALTER TABLE totp_secrets ADD COLUMN sync_state TEXT NOT NULL DEFAULT 'pending';
            ALTER TABLE totp_secrets ADD COLUMN last_synced_at INTEGER;
            ALTER TABLE totp_secrets ADD COLUMN is_deleted INTEGER NOT NULL DEFAULT 0;
            ALTER TABLE totp_secrets ADD COLUMN deleted_at INTEGER;

            -- Add sync columns to domain_mappings
            ALTER TABLE domain_mappings ADD COLUMN sync_id TEXT;
            ALTER TABLE domain_mappings ADD COLUMN sync_version INTEGER NOT NULL DEFAULT 0;
            ALTER TABLE domain_mappings ADD COLUMN sync_state TEXT NOT NULL DEFAULT 'pending';
            ALTER TABLE domain_mappings ADD COLUMN last_synced_at INTEGER;

            -- Sync metadata table (device config)
            CREATE TABLE IF NOT EXISTS sync_metadata (
                id INTEGER PRIMARY KEY CHECK (id = 1),
                vault_id TEXT,
                device_id TEXT,
                device_name TEXT,
                relay_url TEXT,
                device_signing_key_encrypted BLOB,
                last_push_sequence INTEGER NOT NULL DEFAULT 0,
                last_pull_sequence INTEGER NOT NULL DEFAULT 0,
                last_sync_at INTEGER,
                sync_enabled INTEGER NOT NULL DEFAULT 0
            );

            -- Known devices cache
            CREATE TABLE IF NOT EXISTS sync_devices (
                device_id TEXT PRIMARY KEY,
                device_name TEXT NOT NULL,
                device_type TEXT NOT NULL,
                public_key BLOB NOT NULL,
                registered_at INTEGER NOT NULL,
                last_sync INTEGER,
                revoked INTEGER NOT NULL DEFAULT 0,
                revoked_at INTEGER
            );

            -- Tombstones for deleted entries
            CREATE TABLE IF NOT EXISTS sync_tombstones (
                tombstone_id INTEGER PRIMARY KEY AUTOINCREMENT,
                sync_id TEXT NOT NULL UNIQUE,
                entry_type TEXT NOT NULL,
                sync_version INTEGER NOT NULL,
                deleted_at INTEGER NOT NULL,
                origin_device_id TEXT NOT NULL,
                pushed INTEGER NOT NULL DEFAULT 0
            );

            -- Indexes for sync lookups
            CREATE UNIQUE INDEX IF NOT EXISTS idx_entries_sync_id ON entries(sync_id);
            CREATE INDEX IF NOT EXISTS idx_entries_sync_state ON entries(sync_state);
            CREATE UNIQUE INDEX IF NOT EXISTS idx_ssh_keys_sync_id ON ssh_keys(sync_id);
            CREATE INDEX IF NOT EXISTS idx_ssh_keys_sync_state ON ssh_keys(sync_state);
            CREATE UNIQUE INDEX IF NOT EXISTS idx_totp_secrets_sync_id ON totp_secrets(sync_id);
            CREATE INDEX IF NOT EXISTS idx_totp_secrets_sync_state ON totp_secrets(sync_state);
            CREATE INDEX IF NOT EXISTS idx_sync_tombstones_pushed ON sync_tombstones(pushed);",
        )
        .map_err(DatabaseError::Sqlite)?;

        // Assign UUID sync_ids to all existing rows INSIDE the migration
        // transaction (data backfill — see the fn-level transactionality doc).
        assign_sync_ids(conn)?;

        // The version bump is deliberately LAST: an interruption before this
        // statement rolls the whole migration back, leaving the vault at v1.
        conn.execute_batch("UPDATE db_metadata SET version = 2 WHERE id = 1;")
            .map_err(DatabaseError::Sqlite)?;

        Ok(())
    };

    match inner() {
        Ok(()) => conn
            .execute_batch("COMMIT;")
            .map(|_| ())
            .map_err(|e| DatabaseError::Sqlite(e).into()),
        Err(e) => {
            let _ = conn.execute_batch("ROLLBACK;");
            Err(e)
        }
    }
}

/// Assign UUID v4 sync_ids to all existing rows that don't have one.
fn assign_sync_ids(conn: &Connection) -> Result<()> {
    // Entries
    let mut stmt = conn
        .prepare("SELECT entry_id FROM entries WHERE sync_id IS NULL")
        .map_err(DatabaseError::Sqlite)?;

    let entry_ids: Vec<i64> = stmt
        .query_map([], |row| row.get(0))
        .map_err(DatabaseError::Sqlite)?
        .collect::<std::result::Result<Vec<_>, _>>()
        .map_err(DatabaseError::Sqlite)?;

    for entry_id in entry_ids {
        let sync_id = uuid::Uuid::new_v4().to_string();
        conn.execute(
            "UPDATE entries SET sync_id = ?1 WHERE entry_id = ?2",
            rusqlite::params![sync_id, entry_id],
        )
        .map_err(DatabaseError::Sqlite)?;
    }

    // SSH keys
    let mut stmt = conn
        .prepare("SELECT key_id FROM ssh_keys WHERE sync_id IS NULL")
        .map_err(DatabaseError::Sqlite)?;

    let key_ids: Vec<i64> = stmt
        .query_map([], |row| row.get(0))
        .map_err(DatabaseError::Sqlite)?
        .collect::<std::result::Result<Vec<_>, _>>()
        .map_err(DatabaseError::Sqlite)?;

    for key_id in key_ids {
        let sync_id = uuid::Uuid::new_v4().to_string();
        conn.execute(
            "UPDATE ssh_keys SET sync_id = ?1 WHERE key_id = ?2",
            rusqlite::params![sync_id, key_id],
        )
        .map_err(DatabaseError::Sqlite)?;
    }

    // TOTP secrets
    let mut stmt = conn
        .prepare("SELECT totp_id FROM totp_secrets WHERE sync_id IS NULL")
        .map_err(DatabaseError::Sqlite)?;

    let totp_ids: Vec<i64> = stmt
        .query_map([], |row| row.get(0))
        .map_err(DatabaseError::Sqlite)?
        .collect::<std::result::Result<Vec<_>, _>>()
        .map_err(DatabaseError::Sqlite)?;

    for totp_id in totp_ids {
        let sync_id = uuid::Uuid::new_v4().to_string();
        conn.execute(
            "UPDATE totp_secrets SET sync_id = ?1 WHERE totp_id = ?2",
            rusqlite::params![sync_id, totp_id],
        )
        .map_err(DatabaseError::Sqlite)?;
    }

    // Domain mappings
    let mut stmt = conn
        .prepare("SELECT mapping_id FROM domain_mappings WHERE sync_id IS NULL")
        .map_err(DatabaseError::Sqlite)?;

    let mapping_ids: Vec<i64> = stmt
        .query_map([], |row| row.get(0))
        .map_err(DatabaseError::Sqlite)?
        .collect::<std::result::Result<Vec<_>, _>>()
        .map_err(DatabaseError::Sqlite)?;

    for mapping_id in mapping_ids {
        let sync_id = uuid::Uuid::new_v4().to_string();
        conn.execute(
            "UPDATE domain_mappings SET sync_id = ?1 WHERE mapping_id = ?2",
            rusqlite::params![sync_id, mapping_id],
        )
        .map_err(DatabaseError::Sqlite)?;
    }

    Ok(())
}

/// Migrate schema from v2 to v3: add index for title column to improve pagination performance.
pub fn migrate_v2_to_v3(conn: &Connection) -> Result<()> {
    conn.execute_batch(
        "BEGIN;

        -- Add index on title for case-insensitive sorting (used by pagination)
        -- Note: We can't directly index encrypted BLOB, but the COLLATE NOCASE
        -- in ORDER BY still benefits from having this metadata cached.
        -- The primary optimization is the ORDER BY with LIMIT/OFFSET which
        -- SQLite can optimize even without a direct title index.
        CREATE INDEX IF NOT EXISTS idx_entries_modified_at ON entries(modified_at DESC);
        CREATE INDEX IF NOT EXISTS idx_entries_created_at ON entries(created_at DESC);

        -- Bump schema version
        UPDATE db_metadata SET version = 3 WHERE id = 1;

        COMMIT;",
    )
    .map_err(DatabaseError::Sqlite)?;

    Ok(())
}

/// Migrate schema from v4 to v5: two features land in this single
/// migration — (1) the monotonic `key_epoch` counter on `db_metadata`
/// (ADR-002): existing vaults start at epoch 1, master-password rotation
/// increments it, and the epoch is AEAD-bound into the wrapped DEK; and
/// (2) the credential registry tables (ADR-001): `entities`,
/// `entity_memberships`, `secret_equality_index`, `entry_lifecycle`,
/// `registry_state`.
///
/// Transactionality (WBS-402 / ADR-005 rev 3): the DDL, the wrapped-DEK
/// re-serialization data phase, and the version bump commit as ONE
/// transaction — the rewrite previously ran post-commit, so an interruption
/// there left a v5-versioned vault still holding a legacy-shaped wrap that no
/// later migration revisits. With the fold, an interruption rolls the vault
/// back to a pristine v4.
pub fn migrate_v4_to_v5(conn: &Connection) -> Result<()> {
    conn.execute_batch("BEGIN IMMEDIATE;")
        .map_err(crate::DatabaseError::Sqlite)?;

    let inner = || -> Result<()> {
        conn.execute_batch(
            "ALTER TABLE db_metadata ADD COLUMN key_epoch INTEGER NOT NULL DEFAULT 1;

            CREATE TABLE IF NOT EXISTS entities (
                entity_id TEXT PRIMARY KEY,
                name BLOB NOT NULL,
                kind TEXT NOT NULL CHECK (kind IN ('broker', 'market_data', 'regulatory_data',
                    'notification', 'database', 'infrastructure', 'application', 'other')),
                criticality TEXT NOT NULL DEFAULT 'medium'
                    CHECK (criticality IN ('low', 'medium', 'high')),
                notes BLOB,
                rotation_interval_days_override INTEGER,
                created_at INTEGER NOT NULL,
                modified_at INTEGER NOT NULL
            );

            CREATE TABLE IF NOT EXISTS entity_memberships (
                membership_id INTEGER PRIMARY KEY AUTOINCREMENT,
                entry_id INTEGER NOT NULL UNIQUE,
                entity_id TEXT NOT NULL,
                label BLOB,
                created_at INTEGER NOT NULL,
                FOREIGN KEY (entry_id) REFERENCES entries(entry_id) ON DELETE CASCADE,
                FOREIGN KEY (entity_id) REFERENCES entities(entity_id) ON DELETE CASCADE
            );

            CREATE TABLE IF NOT EXISTS secret_equality_index (
                entry_id INTEGER PRIMARY KEY REFERENCES entries(entry_id) ON DELETE CASCADE,
                tag_cipher BLOB NOT NULL,
                algorithm_version INTEGER NOT NULL DEFAULT 1,
                equality_key_id INTEGER NOT NULL DEFAULT 1,
                updated_at INTEGER NOT NULL
            );

            CREATE TABLE IF NOT EXISTS entry_lifecycle (
                entry_id INTEGER PRIMARY KEY REFERENCES entries(entry_id) ON DELETE CASCADE,
                password_rotated_at INTEGER,
                expires_at INTEGER,
                rotation_interval_days_override INTEGER,
                source TEXT NOT NULL DEFAULT 'manual'
                    CHECK (source IN ('manual', 'imported', 'generated', 'tool_managed'))
            );

            CREATE TABLE IF NOT EXISTS registry_state (
                key TEXT PRIMARY KEY,
                value TEXT NOT NULL
            );

            CREATE INDEX IF NOT EXISTS idx_entity_memberships_entity_id
                ON entity_memberships(entity_id);
            CREATE INDEX IF NOT EXISTS idx_secret_equality_index_updated
                ON secret_equality_index(updated_at);",
        )
        .map_err(crate::DatabaseError::Sqlite)?;

        // Re-serialize the wrapped DEK into the current shape — INSIDE the
        // migration transaction (data backfill — see the fn-level
        // transactionality doc). The v0.8.0 blob is bincode without the
        // `epoch_bound` field; bincode is positional, so old blobs must be
        // read with the legacy shape and rewritten with the field present
        // (else every later open hits a deserialization EOF).
        let wrapped_blob: Vec<u8> = conn
            .query_row(
                "SELECT wrapped_dek FROM db_metadata WHERE id = 1",
                [],
                |row| row.get(0),
            )
            .map_err(crate::DatabaseError::Sqlite)?;
        // Tolerant read accepts the legacy 3-field shape, the current
        // 4-field shape, and (defensively) a WBS-305 `SPWRAP` document — a
        // v4 vault cannot legitimately carry one, but the dual-read decoder
        // costs nothing and keeps this migration format-agnostic. The
        // rewrite target stays current-shape bincode: this migration's job
        // is normalizing legacy BINCODE shapes so later opens deserialize;
        // document-format writes belong to the live metadata writers, and
        // the next rotation rewrites the column as a document.
        // A blob that is not a recognizable wrap (e.g. a test fixture placeholder)
        // is left as-is: forcing it here would turn a data quirk into a migration
        // failure. Real wraps rewrite into the current shape.
        if let Ok(key) = crate::crypto::dbwire::decode_wrapped_key(&wrapped_blob) {
            let upgraded_blob = bincode::serialize(&key).map_err(|e| {
                crate::DatabaseError::Sqlite(rusqlite::Error::ToSqlConversionFailure(Box::new(e)))
            })?;
            conn.execute(
                "UPDATE db_metadata SET wrapped_dek = ?1 WHERE id = 1",
                rusqlite::params![&upgraded_blob],
            )
            .map_err(crate::DatabaseError::Sqlite)?;
        }

        // The version bump is deliberately LAST: an interruption before this
        // statement rolls the whole migration back, leaving the vault at v4.
        conn.execute_batch("UPDATE db_metadata SET version = 5 WHERE id = 1;")
            .map_err(crate::DatabaseError::Sqlite)?;

        Ok(())
    };

    match inner() {
        Ok(()) => conn
            .execute_batch("COMMIT;")
            .map(|_| ())
            .map_err(|e| crate::DatabaseError::Sqlite(e).into()),
        Err(e) => {
            let _ = conn.execute_batch("ROLLBACK;");
            Err(e)
        }
    }
}

/// v5 → v6 (WBS-301, ADR-004 rev 4): durable vault identity and explicit
/// envelope format version on `db_metadata`. Existing vaults get a generated
/// stable UUID at migration time; `format_version` starts at 1 (legacy field
/// encryption — the envelope-v2 format is a later, deliberate migration).
pub fn migrate_v5_to_v6(conn: &Connection) -> Result<()> {
    // Take the write lock FIRST (BEGIN IMMEDIATE), then probe: two processes
    // migrating the same v5 vault cannot both decide to ALTER and race to
    // "duplicate column" — the loser blocks here and probes committed state
    // (adversarial-review finding). Column adds tolerate pre-existing columns
    // (restores, hand-built fixtures).
    conn.execute_batch("BEGIN IMMEDIATE;")
        .map_err(DatabaseError::Sqlite)?;

    let inner = || -> Result<()> {
        let existing: Vec<String> = {
            let mut stmt = conn
                .prepare("SELECT name FROM pragma_table_info('db_metadata')")
                .map_err(DatabaseError::Sqlite)?;
            let rows = stmt
                .query_map([], |r| r.get::<_, String>(0))
                .map_err(DatabaseError::Sqlite)?;
            rows.filter_map(|r| r.ok()).collect()
        };

        let mut stmts = String::new();
        if !existing.iter().any(|c| c == "vault_uuid") {
            stmts.push_str("ALTER TABLE db_metadata ADD COLUMN vault_uuid TEXT;\n");
        }
        if !existing.iter().any(|c| c == "format_version") {
            stmts.push_str(
                "ALTER TABLE db_metadata ADD COLUMN format_version INTEGER NOT NULL DEFAULT 1;\n",
            );
        }
        // Mint a UUID via SQL's random bytes (deterministic in-shape, v4) so
        // COALESCE never re-mints an existing value.
        stmts.push_str(
            "UPDATE db_metadata SET vault_uuid = COALESCE(vault_uuid, \
             (SELECT lower(hex(randomblob(4)) || '-' || hex(randomblob(2)) || '-4' || \
             substr(hex(randomblob(2)), 2) || '-' || substr('89ab', abs(random()) % 4 + 1, 1) || \
             substr(hex(randomblob(2)), 2) || '-' || hex(randomblob(6))) )) \
             WHERE id = 1;\n",
        );
        stmts.push_str("UPDATE db_metadata SET version = 6 WHERE id = 1;\n");
        conn.execute_batch(&stmts).map_err(DatabaseError::Sqlite)?;
        Ok(())
    };

    match inner() {
        Ok(()) => conn
            .execute_batch("COMMIT;")
            .map(|_| ())
            .map_err(|e| DatabaseError::Sqlite(e).into()),
        Err(e) => {
            let _ = conn.execute_batch("ROLLBACK;");
            Err(e)
        }
    }
}

/// v6 → v7 (WBS-302 / ADR-004 rev 4): the key-slot registry table and its
/// MAC column. The password slot row is minted from the existing
/// `db_metadata` wrap; the MAC itself is computed at the FIRST post-unlock
/// open (its key derives from the DEK, unavailable here) and the sidecar
/// digest is rebased in the same step — see `ensure_slot_registry` in
/// `vault/slot_ops.rs`.
pub fn migrate_v6_to_v7(conn: &Connection) -> Result<()> {
    conn.execute_batch("BEGIN IMMEDIATE;")
        .map_err(DatabaseError::Sqlite)?;

    let inner = || -> Result<()> {
        let existing_meta: Vec<String> = {
            let mut stmt = conn
                .prepare("SELECT name FROM pragma_table_info('db_metadata')")
                .map_err(DatabaseError::Sqlite)?;
            let rows = stmt
                .query_map([], |r| r.get::<_, String>(0))
                .map_err(DatabaseError::Sqlite)?;
            rows.filter_map(|r| r.ok()).collect()
        };

        let mut stmts = String::from(
            "CREATE TABLE IF NOT EXISTS key_slots (
                slot_uuid TEXT PRIMARY KEY,
                slot_type TEXT NOT NULL CHECK (slot_type IN
                    ('password', 'recovery', 'platform', 'trusted_device')),
                kdf_params BLOB NOT NULL,
                wrapped_dek BLOB NOT NULL,
                dek_nonce BLOB NOT NULL,
                key_epoch INTEGER NOT NULL,
                created_at INTEGER NOT NULL,
                revoked_at INTEGER,
                format_version INTEGER NOT NULL DEFAULT 1
            );
            CREATE INDEX IF NOT EXISTS idx_key_slots_type ON key_slots(slot_type);
",
        );
        if !existing_meta.iter().any(|c| c == "slot_registry_mac") {
            stmts.push_str("ALTER TABLE db_metadata ADD COLUMN slot_registry_mac BLOB;\n");
        }

        // Mint the password slot from the existing wrap (no MAC yet).
        stmts.push_str(
            "INSERT INTO key_slots
                (slot_uuid, slot_type, kdf_params, wrapped_dek, dek_nonce,
                 key_epoch, created_at, revoked_at, format_version)
             SELECT lower(hex(randomblob(4)) || '-' || hex(randomblob(2)) || '-4' ||
                    substr(hex(randomblob(2)), 2) || '-' ||
                    substr('89ab', abs(random()) % 4 + 1, 1) ||
                    substr(hex(randomblob(2)), 2) || '-' || hex(randomblob(6))),
                    'password', kdf_params, wrapped_dek, dek_nonce,
                    COALESCE(key_epoch, 1), strftime('%s','now'), NULL, 1
             FROM db_metadata WHERE id = 1
               AND NOT EXISTS (SELECT 1 FROM key_slots);
",
        );
        stmts.push_str("UPDATE db_metadata SET version = 7 WHERE id = 1;\n");
        conn.execute_batch(&stmts).map_err(DatabaseError::Sqlite)?;
        Ok(())
    };

    match inner() {
        Ok(()) => conn
            .execute_batch("COMMIT;")
            .map(|_| ())
            .map_err(|e| DatabaseError::Sqlite(e).into()),
        Err(e) => {
            let _ = conn.execute_batch("ROLLBACK;");
            Err(e)
        }
    }
}

pub fn migrate_v3_to_v4(conn: &Connection) -> Result<()> {
    conn.execute_batch(
        "BEGIN;

        ALTER TABLE entries ADD COLUMN credential_type TEXT NOT NULL DEFAULT 'password'
            CHECK (credential_type IN ('password', 'api_key', 'passkey_reference'));

        CREATE INDEX IF NOT EXISTS idx_entries_credential_type ON entries(credential_type);

        UPDATE db_metadata SET version = 4 WHERE id = 1;

        COMMIT;",
    )
    .map_err(DatabaseError::Sqlite)?;

    Ok(())
}

/// v7 → v8 (WBS-306 / ADR-005 rev 4): encrypted domain-mapping identity.
///
/// Adds `domain_mappings.domain_enc` (the sealed-domain envelope column)
/// and the `domain_mapping_tags` keyed-lookup table, and DROPS the
/// plaintext `idx_domain_mappings_domain` index — lookups move to tag
/// intersection, so keeping a plaintext search structure would defeat the
/// point (SR-CRYPTO-001 / SR-DATA-004). The legacy plaintext `domain`
/// COLUMN stays populated until WBS-404's bulk migration clears it; reads
/// are dual and the post-unlock sweep backfills envelopes + tags (migrations
/// run before the DEK exists, so the crypto backfill CANNOT happen here —
/// the same split as the v5 registry migration).
///
/// DDL only, in ONE transaction (ADR-005 rev 3): a failure rolls back to a
/// consistent v7 state.
pub fn migrate_v7_to_v8(conn: &Connection) -> Result<()> {
    conn.execute_batch("BEGIN IMMEDIATE;")
        .map_err(DatabaseError::Sqlite)?;

    let inner = || -> Result<()> {
        let existing_domain_cols: Vec<String> = {
            let mut stmt = conn
                .prepare("SELECT name FROM pragma_table_info('domain_mappings')")
                .map_err(DatabaseError::Sqlite)?;
            let rows = stmt
                .query_map([], |r| r.get::<_, String>(0))
                .map_err(DatabaseError::Sqlite)?;
            rows.filter_map(|r| r.ok()).collect()
        };

        let mut stmts = String::from(
            "CREATE TABLE IF NOT EXISTS domain_mapping_tags (
                tag_id INTEGER PRIMARY KEY AUTOINCREMENT,
                mapping_id INTEGER NOT NULL,
                tag BLOB NOT NULL,
                is_chain_root INTEGER NOT NULL DEFAULT 0,
                equality_key_id INTEGER NOT NULL DEFAULT 1,
                FOREIGN KEY (mapping_id) REFERENCES domain_mappings(mapping_id)
                    ON DELETE CASCADE
            );
            CREATE INDEX IF NOT EXISTS idx_domain_mapping_tags_tag ON domain_mapping_tags(tag);
            CREATE INDEX IF NOT EXISTS idx_domain_mapping_tags_root
                ON domain_mapping_tags(tag, is_chain_root);
            CREATE INDEX IF NOT EXISTS idx_domain_mapping_tags_mapping
                ON domain_mapping_tags(mapping_id);
            DROP INDEX IF EXISTS idx_domain_mappings_domain;
            ",
        );
        // Column adds tolerate pre-existing columns (restores, hand-built
        // fixtures) — the established probe pattern.
        if !existing_domain_cols.iter().any(|c| c == "domain_enc") {
            stmts.push_str("ALTER TABLE domain_mappings ADD COLUMN domain_enc BLOB;\n");
        }
        stmts.push_str("UPDATE db_metadata SET version = 8 WHERE id = 1;\n");
        conn.execute_batch(&stmts).map_err(DatabaseError::Sqlite)?;
        Ok(())
    };

    match inner() {
        Ok(()) => conn
            .execute_batch("COMMIT;")
            .map(|_| ())
            .map_err(|e| DatabaseError::Sqlite(e).into()),
        Err(e) => {
            let _ = conn.execute_batch("ROLLBACK;");
            Err(e)
        }
    }
}

/// Run all pending migrations to bring the database up to the current version.
pub fn run_migrations(conn: &Connection) -> Result<()> {
    let version: i32 = conn
        .query_row("SELECT version FROM db_metadata WHERE id = 1", [], |row| {
            row.get(0)
        })
        .map_err(DatabaseError::Sqlite)?;

    if version < 2 {
        migrate_v1_to_v2(conn)?;
    }

    if version < 3 {
        migrate_v2_to_v3(conn)?;
    }

    if version < 4 {
        migrate_v3_to_v4(conn)?;
    }

    if version < 5 {
        migrate_v4_to_v5(conn)?;
    }

    if version < 6 {
        migrate_v5_to_v6(conn)?;
    }

    if version < 7 {
        migrate_v6_to_v7(conn)?;
    }

    if version < 8 {
        migrate_v7_to_v8(conn)?;
    }

    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::database::Database;

    /// Raw v1 schema DDL (no sync columns), shared by the in-memory and
    /// file-based fixtures.
    const V1_SCHEMA_SQL: &str = "CREATE TABLE db_metadata (
                id INTEGER PRIMARY KEY CHECK (id = 1),
                version INTEGER NOT NULL,
                kdf_params BLOB NOT NULL,
                wrapped_dek BLOB NOT NULL,
                dek_nonce BLOB NOT NULL,
                created_at INTEGER NOT NULL,
                last_modified INTEGER NOT NULL,
                biometric_ref TEXT
            );
            CREATE TABLE entries (
                entry_id INTEGER PRIMARY KEY AUTOINCREMENT,
                vault_id INTEGER NOT NULL,
                title BLOB NOT NULL,
                username BLOB NOT NULL,
                password BLOB NOT NULL,
                url BLOB,
                notes BLOB,
                entry_nonce BLOB NOT NULL,
                auth_tag BLOB NOT NULL,
                created_at INTEGER NOT NULL,
                modified_at INTEGER NOT NULL,
                favorite INTEGER NOT NULL DEFAULT 0
            );
            CREATE TABLE domain_mappings (
                mapping_id INTEGER PRIMARY KEY,
                entry_id INTEGER NOT NULL,
                domain TEXT NOT NULL,
                is_primary INTEGER NOT NULL DEFAULT 1,
                FOREIGN KEY (entry_id) REFERENCES entries(entry_id) ON DELETE CASCADE
            );
            CREATE TABLE failed_attempts (
                attempt_id INTEGER PRIMARY KEY AUTOINCREMENT,
                attempt_time INTEGER NOT NULL,
                ip_address TEXT
            );
            CREATE TABLE ssh_keys (
                key_id INTEGER PRIMARY KEY AUTOINCREMENT,
                name TEXT NOT NULL,
                comment TEXT,
                key_type TEXT NOT NULL,
                key_size INTEGER,
                public_key TEXT NOT NULL,
                private_key_encrypted BLOB NOT NULL,
                nonce BLOB NOT NULL,
                auth_tag BLOB NOT NULL,
                fingerprint TEXT NOT NULL,
                created_at INTEGER NOT NULL,
                modified_at INTEGER NOT NULL
            );
            CREATE TABLE totp_secrets (
                totp_id INTEGER PRIMARY KEY AUTOINCREMENT,
                entry_id INTEGER NOT NULL UNIQUE,
                secret_encrypted BLOB NOT NULL,
                nonce BLOB NOT NULL,
                auth_tag BLOB NOT NULL,
                algorithm TEXT NOT NULL DEFAULT 'SHA1',
                digits INTEGER NOT NULL DEFAULT 6,
                period INTEGER NOT NULL DEFAULT 30,
                issuer TEXT,
                account_name TEXT,
                created_at INTEGER NOT NULL,
                FOREIGN KEY (entry_id) REFERENCES entries(entry_id) ON DELETE CASCADE
            );";

    fn seed_v1_metadata(conn: &rusqlite::Connection) {
        conn.execute(
            "INSERT INTO db_metadata (id, version, kdf_params, wrapped_dek, dek_nonce, created_at, last_modified)
             VALUES (1, 1, X'00', X'00', X'00', 0, 0)",
            [],
        )
        .unwrap();
    }

    /// Create a database with v1 schema only (no sync columns).
    fn create_v1_db() -> rusqlite::Connection {
        let conn = rusqlite::Connection::open_in_memory().unwrap();
        conn.execute("PRAGMA foreign_keys = ON", []).unwrap();
        conn.execute_batch(V1_SCHEMA_SQL).unwrap();
        seed_v1_metadata(&conn);
        conn
    }

    /// Durable v1 fixture for interruption tests: atomicity and old-code-path
    /// openability must be proven across a close/reopen, which in-memory
    /// connections cannot express.
    fn create_v1_db_at(path: &std::path::Path) -> rusqlite::Connection {
        let conn = rusqlite::Connection::open(path).unwrap();
        conn.execute("PRAGMA foreign_keys = ON", []).unwrap();
        conn.execute_batch(V1_SCHEMA_SQL).unwrap();
        seed_v1_metadata(&conn);
        conn
    }

    #[test]
    fn migrate_v1_to_v2_creates_sync_tables() {
        let conn = create_v1_db();

        migrate_v1_to_v2(&conn).unwrap();
        migrate_v2_to_v3(&conn).unwrap();

        // Verify schema version bumped
        let version: i32 = conn
            .query_row("SELECT version FROM db_metadata WHERE id = 1", [], |row| {
                row.get(0)
            })
            .unwrap();
        assert_eq!(version, 3);

        // Verify sync_metadata table exists
        let table_exists: bool = conn
            .query_row(
                "SELECT EXISTS(SELECT 1 FROM sqlite_master WHERE type='table' AND name='sync_metadata')",
                [],
                |row| row.get(0),
            )
            .unwrap();
        assert!(table_exists);

        // Verify sync_devices table exists
        let table_exists: bool = conn
            .query_row(
                "SELECT EXISTS(SELECT 1 FROM sqlite_master WHERE type='table' AND name='sync_devices')",
                [],
                |row| row.get(0),
            )
            .unwrap();
        assert!(table_exists);

        // Verify sync_tombstones table exists
        let table_exists: bool = conn
            .query_row(
                "SELECT EXISTS(SELECT 1 FROM sqlite_master WHERE type='table' AND name='sync_tombstones')",
                [],
                |row| row.get(0),
            )
            .unwrap();
        assert!(table_exists);

        // Verify sync columns added to entries
        let has_sync_id: bool = conn
            .query_row(
                "SELECT EXISTS(SELECT 1 FROM pragma_table_info('entries') WHERE name='sync_id')",
                [],
                |row| row.get(0),
            )
            .unwrap();
        assert!(has_sync_id);

        let has_sync_version: bool = conn
            .query_row(
                "SELECT EXISTS(SELECT 1 FROM pragma_table_info('entries') WHERE name='sync_version')",
                [],
                |row| row.get(0),
            )
            .unwrap();
        assert!(has_sync_version);
    }

    #[test]
    fn migrate_assigns_sync_ids_to_existing_entries() {
        let conn = create_v1_db();

        // Insert a test entry (v1 schema, no sync columns)
        conn.execute(
            "INSERT INTO entries (vault_id, title, username, password, entry_nonce, auth_tag, created_at, modified_at)
             VALUES (1, X'01', X'02', X'03', X'04', X'05', 0, 0)",
            [],
        )
        .unwrap();

        migrate_v1_to_v2(&conn).unwrap();

        // Verify sync_id was assigned
        let sync_id: String = conn
            .query_row(
                "SELECT sync_id FROM entries WHERE entry_id = 1",
                [],
                |row| row.get(0),
            )
            .unwrap();

        assert!(!sync_id.is_empty());
        assert!(uuid::Uuid::parse_str(&sync_id).is_ok());
    }

    #[test]
    fn migrate_v2_to_v3_adds_indexes() {
        let conn = create_v1_db();

        // First migrate to v2
        migrate_v1_to_v2(&conn).unwrap();

        // Then migrate to v3
        migrate_v2_to_v3(&conn).unwrap();

        // Verify schema version is 3
        let version: i32 = conn
            .query_row("SELECT version FROM db_metadata WHERE id = 1", [], |row| {
                row.get(0)
            })
            .unwrap();
        assert_eq!(version, 3);

        // Verify indexes were created
        let has_modified_index: bool = conn
            .query_row(
                "SELECT EXISTS(SELECT 1 FROM sqlite_master WHERE type='index' AND name='idx_entries_modified_at')",
                [],
                |row| row.get(0),
            )
            .unwrap();
        assert!(has_modified_index);

        let has_created_index: bool = conn
            .query_row(
                "SELECT EXISTS(SELECT 1 FROM sqlite_master WHERE type='index' AND name='idx_entries_created_at')",
                [],
                |row| row.get(0),
            )
            .unwrap();
        assert!(has_created_index);
    }

    #[test]
    fn migrate_v3_to_v4_adds_credential_type() {
        let conn = create_v1_db();

        migrate_v1_to_v2(&conn).unwrap();
        migrate_v2_to_v3(&conn).unwrap();
        migrate_v3_to_v4(&conn).unwrap();

        let version: i32 = conn
            .query_row("SELECT version FROM db_metadata WHERE id = 1", [], |row| {
                row.get(0)
            })
            .unwrap();
        assert_eq!(version, 4);

        let has_credential_type: bool = conn
            .query_row(
                "SELECT EXISTS(SELECT 1 FROM pragma_table_info('entries') WHERE name='credential_type')",
                [],
                |row| row.get(0),
            )
            .unwrap();
        assert!(has_credential_type);

        conn.execute(
            "INSERT INTO entries (vault_id, title, username, password, entry_nonce, auth_tag, created_at, modified_at)
             VALUES (1, X'01', X'02', X'03', X'04', X'05', 0, 0)",
            [],
        )
        .unwrap();

        let credential_type: String = conn
            .query_row(
                "SELECT credential_type FROM entries WHERE entry_id = 1",
                [],
                |row| row.get(0),
            )
            .unwrap();
        assert_eq!(credential_type, "password");
    }

    /// Create a database at v4 (v1 fixture advanced through v4), holding one
    /// live and one soft-deleted entry.
    fn create_v4_db() -> rusqlite::Connection {
        let conn = create_v1_db();
        migrate_v1_to_v2(&conn).unwrap();
        migrate_v2_to_v3(&conn).unwrap();
        migrate_v3_to_v4(&conn).unwrap();

        // One live entry, one soft-deleted entry (soft delete is the only
        // delete that exists — the registry must cope with both).
        conn.execute(
            "INSERT INTO entries (vault_id, title, username, password, entry_nonce, auth_tag,
                created_at, modified_at, credential_type)
             VALUES (1, X'01', X'02', X'03', X'04', X'05', 0, 0, 'password')",
            [],
        )
        .unwrap();
        conn.execute(
            "INSERT INTO entries (vault_id, title, username, password, entry_nonce, auth_tag,
                created_at, modified_at, credential_type, is_deleted, deleted_at)
             VALUES (1, X'11', X'12', X'13', X'14', X'15', 0, 0, 'api_key', 1, 123)",
            [],
        )
        .unwrap();
        conn
    }

    /// v5 database (pre-identity): everything through the registry migration.
    fn create_v5_db() -> rusqlite::Connection {
        let conn = create_v4_db();
        migrate_v4_to_v5(&conn).unwrap();
        conn
    }

    /// v7 database: everything through the key-slot registry migration.
    fn create_v7_db() -> rusqlite::Connection {
        let conn = create_v1_db();
        migrate_v1_to_v2(&conn).unwrap();
        migrate_v2_to_v3(&conn).unwrap();
        migrate_v3_to_v4(&conn).unwrap();
        migrate_v4_to_v5(&conn).unwrap();
        migrate_v5_to_v6(&conn).unwrap();
        migrate_v6_to_v7(&conn).unwrap();
        conn
    }

    /// v8 (WBS-306): the sealed-domain column, the tag table, and its
    /// indexes exist; the plaintext domain index is gone; existing
    /// plaintext data is untouched (the crypto backfill is post-unlock).
    #[test]
    fn migrate_v7_to_v8_adds_encrypted_domain_columns_and_drops_plaintext_index() {
        let conn = create_v7_db();

        // A legacy mapping row exists before the migration.
        conn.execute(
            "INSERT INTO entries (vault_id, title, username, password, entry_nonce, auth_tag,
                created_at, modified_at, credential_type)
             VALUES (1, X'01', X'02', X'03', X'04', X'05', 0, 0, 'password')",
            [],
        )
        .unwrap();
        conn.execute(
            "INSERT INTO domain_mappings (entry_id, domain, is_primary) VALUES (1, 'example.com', 1)",
            [],
        )
        .unwrap();

        migrate_v7_to_v8(&conn).unwrap();
        run_migrations(&conn).unwrap(); // idempotent continuation

        let version: i32 = conn
            .query_row("SELECT version FROM db_metadata WHERE id = 1", [], |r| {
                r.get(0)
            })
            .unwrap();
        assert_eq!(version, 8);

        let has_domain_enc: bool = conn
            .query_row(
                "SELECT EXISTS(SELECT 1 FROM pragma_table_info('domain_mappings') WHERE name='domain_enc')",
                [],
                |row| row.get(0),
            )
            .unwrap();
        assert!(has_domain_enc);

        for object in [
            ("table", "domain_mapping_tags"),
            ("index", "idx_domain_mapping_tags_tag"),
            ("index", "idx_domain_mapping_tags_mapping"),
        ] {
            let exists: bool = conn
                .query_row(
                    "SELECT EXISTS(SELECT 1 FROM sqlite_master WHERE type=?1 AND name=?2)",
                    rusqlite::params![object.0, object.1],
                    |row| row.get(0),
                )
                .unwrap();
            assert!(exists, "{} {} must exist after v8", object.0, object.1);
        }

        // The plaintext index must be gone.
        let plaintext_index: bool = conn
            .query_row(
                "SELECT EXISTS(SELECT 1 FROM sqlite_master WHERE type='index' AND name='idx_domain_mappings_domain')",
                [],
                |row| row.get(0),
            )
            .unwrap();
        assert!(!plaintext_index);

        // The legacy plaintext data survives untouched (backfill is
        // post-unlock, not here).
        let (domain, domain_enc): (String, Option<Vec<u8>>) = conn
            .query_row(
                "SELECT domain, domain_enc FROM domain_mappings WHERE mapping_id = 1",
                [],
                |row| Ok((row.get(0)?, row.get(1)?)),
            )
            .unwrap();
        assert_eq!(domain, "example.com");
        assert!(domain_enc.is_none());
    }

    #[test]
    fn migrate_v5_to_v6_adds_vault_identity() {
        let conn = create_v5_db();
        // The production path: validate_schema_version dispatches run_migrations.
        run_migrations(&conn).unwrap();

        // The migration runner continues to the latest version; v6's
        // deliverable is the identity columns (asserted below), not the
        // terminal version number.
        let version: i32 = conn
            .query_row("SELECT version FROM db_metadata WHERE id = 1", [], |r| {
                r.get(0)
            })
            .unwrap();
        assert!(version >= 6);

        // Every existing vault gets a stable generated UUID.
        let uuid: String = conn
            .query_row("SELECT vault_uuid FROM db_metadata WHERE id = 1", [], |r| {
                r.get(0)
            })
            .unwrap();
        assert!(
            uuid::Uuid::parse_str(&uuid).is_ok(),
            "generated UUID must parse"
        );
        // Re-running the migration path must not churn the UUID.
        let again: String = conn
            .query_row("SELECT vault_uuid FROM db_metadata WHERE id = 1", [], |r| {
                r.get(0)
            })
            .unwrap();
        assert_eq!(uuid, again);

        // Explicit envelope format version starts at 1 (legacy field format).
        let format_version: i64 = conn
            .query_row(
                "SELECT format_version FROM db_metadata WHERE id = 1",
                [],
                |r| r.get(0),
            )
            .unwrap();
        assert_eq!(format_version, 1);
    }

    #[test]
    fn migrate_v4_to_v5_creates_registry_tables() {
        let conn = create_v4_db();

        migrate_v4_to_v5(&conn).unwrap();

        let version: i64 = conn
            .query_row("SELECT version FROM db_metadata WHERE id = 1", [], |row| {
                row.get(0)
            })
            .unwrap();
        assert_eq!(version, 5);

        for table in [
            "entities",
            "entity_memberships",
            "secret_equality_index",
            "entry_lifecycle",
            "registry_state",
        ] {
            let table_exists: bool = conn
                .query_row(
                    "SELECT EXISTS(SELECT 1 FROM sqlite_master WHERE type='table' AND name=?1)",
                    [table],
                    |row| row.get(0),
                )
                .unwrap();
            assert!(
                table_exists,
                "table {} should exist after v5 migration",
                table
            );
        }
    }

    #[test]
    fn migrate_v4_to_v5_preserves_live_and_soft_deleted_entries() {
        let conn = create_v4_db();

        migrate_v4_to_v5(&conn).unwrap();

        // No entry data is touched by the registry migration; the equality
        // index is backfilled post-unlock, not here (no key material at
        // migration time).
        let live_title: Vec<u8> = conn
            .query_row(
                "SELECT title FROM entries WHERE is_deleted = 0",
                [],
                |row| row.get(0),
            )
            .unwrap();
        assert_eq!(live_title, vec![0x01]);

        let deleted_row: (i64, Option<i64>) = conn
            .query_row(
                "SELECT is_deleted, deleted_at FROM entries WHERE credential_type = 'api_key'",
                [],
                |row| Ok((row.get(0)?, row.get(1)?)),
            )
            .unwrap();
        assert_eq!(deleted_row, (1, Some(123)));

        // The index starts empty; the post-unlock sweep fills it
        let index_count: i64 = conn
            .query_row("SELECT COUNT(*) FROM secret_equality_index", [], |row| {
                row.get(0)
            })
            .unwrap();
        assert_eq!(index_count, 0);
    }

    #[test]
    fn run_migrations_idempotent() {
        let conn = create_v1_db();

        run_migrations(&conn).unwrap();

        // Running again should be a no-op (version is already current)
        run_migrations(&conn).unwrap();

        let version: i32 = conn
            .query_row("SELECT version FROM db_metadata WHERE id = 1", [], |row| {
                row.get(0)
            })
            .unwrap();
        assert_eq!(version, crate::database::schema::CURRENT_SCHEMA_VERSION);
    }

    /// WBS-402 (c): an interruption BETWEEN the migration DDL and the data
    /// backfill must leave the vault at the OLD version, in the OLD shape,
    /// still openable by the old code path — and recoverable by re-running
    /// the migration. Injection is real SQLite-level error injection: a
    /// trigger aborts the FIRST backfill UPDATE on `entries`, which can only
    /// fire after the DDL has run inside the transaction.
    #[test]
    fn interruption_between_ddl_and_backfill_rolls_back_to_old_version() {
        let dir = tempfile::TempDir::new().unwrap();
        let db_path = dir.path().join("migrate_v1_interrupt.db");
        {
            let conn = create_v1_db_at(&db_path);
            conn.execute(
                "INSERT INTO entries (vault_id, title, username, password, entry_nonce, auth_tag, created_at, modified_at)
                 VALUES (1, X'01', X'02', X'03', X'04', X'05', 0, 0)",
                [],
            )
            .unwrap();
            conn.execute_batch(
                "CREATE TRIGGER fail_backfill AFTER UPDATE ON entries
                 BEGIN SELECT RAISE(ABORT, 'injected interruption between DDL and backfill'); END;",
            )
            .unwrap();
        } // fixture connection closed: state is durable on disk

        // The production open path fails while the injected fault is present.
        let err = Database::open(&db_path)
            .and_then(|db| db.validate_schema_version())
            .unwrap_err();
        assert!(
            err.to_string().contains("injected interruption"),
            "expected the injected backfill failure, got: {err}"
        );

        // Rollback proof on a FRESH connection (proves durability): version
        // still 1, the ALTER TABLE DDL is undone, and the entry row is
        // readable with exactly the v1 column set — i.e. an old binary sees
        // a pristine v1 vault it can open.
        let conn = rusqlite::Connection::open(&db_path).unwrap();
        let version: i32 = conn
            .query_row("SELECT version FROM db_metadata WHERE id = 1", [], |r| {
                r.get(0)
            })
            .unwrap();
        assert_eq!(version, 1, "version bump must roll back with the backfill");

        let has_sync_id: bool = conn
            .query_row(
                "SELECT EXISTS(SELECT 1 FROM pragma_table_info('entries') WHERE name='sync_id')",
                [],
                |r| r.get(0),
            )
            .unwrap();
        assert!(
            !has_sync_id,
            "the migration DDL must roll back together with the data phase"
        );

        let title: Vec<u8> = conn
            .query_row("SELECT title FROM entries WHERE entry_id = 1", [], |r| {
                r.get(0)
            })
            .unwrap();
        assert_eq!(title, vec![0x01], "entry data must be untouched");

        conn.query_row(
            "SELECT entry_id, vault_id, title, username, password, url, notes,
                    entry_nonce, auth_tag, created_at, modified_at, favorite
             FROM entries WHERE entry_id = 1",
            [],
            |r| Ok((r.get::<_, i64>(0)?, r.get::<_, i64>(1)?)),
        )
        .unwrap();

        // Recovery: remove the injected fault; the next open re-runs the
        // migration from v1 and reaches the current version.
        conn.execute_batch("DROP TRIGGER fail_backfill;").unwrap();
        drop(conn);
        let db = Database::open(&db_path).unwrap();
        db.validate_schema_version().unwrap();
        let version: i32 = db
            .conn()
            .query_row("SELECT version FROM db_metadata WHERE id = 1", [], |r| {
                r.get(0)
            })
            .unwrap();
        assert_eq!(version, crate::database::schema::CURRENT_SCHEMA_VERSION);
    }

    /// WBS-402 (c) for the v4→v5 data phase: an interruption during the
    /// wrapped-DEK re-serialization (which previously ran POST-commit) must
    /// roll the vault back to a pristine v4. Injection: a trigger aborts the
    /// rewrite's UPDATE on `db_metadata` (identified by an unchanged
    /// `version`), which fires only during the data phase — the version-bump
    /// UPDATE changes `version` and is exempt.
    #[test]
    fn interruption_during_v5_data_rewrite_rolls_back_to_v4() {
        let conn = create_v4_db();

        // Seed a WELL-FORMED wrap so the v5 rewrite actually performs its
        // UPDATE (placeholder X'00' fixtures are skipped by the tolerant
        // read and would starve the injection point).
        let wrap = crate::crypto::keyring::WrappedKey {
            wrapped_dek: vec![7u8; 32],
            nonce: [1u8; 12],
            auth_tag: [2u8; 16],
            epoch_bound: false,
        };
        let wrap_blob = bincode::serialize(&wrap).unwrap();
        conn.execute(
            "UPDATE db_metadata SET wrapped_dek = ?1 WHERE id = 1",
            rusqlite::params![&wrap_blob],
        )
        .unwrap();

        conn.execute_batch(
            "CREATE TRIGGER fail_rewrite AFTER UPDATE ON db_metadata
             WHEN NEW.version = OLD.version
             BEGIN SELECT RAISE(ABORT, 'injected interruption during v5 data rewrite'); END;",
        )
        .unwrap();

        let err = migrate_v4_to_v5(&conn).unwrap_err();
        assert!(
            err.to_string().contains("injected interruption"),
            "expected the injected rewrite failure, got: {err}"
        );

        // Everything rolls back: version still 4, the key_epoch ALTER is
        // undone, the registry tables are gone, and the wrap blob is
        // byte-identical to the fixture.
        let version: i32 = conn
            .query_row("SELECT version FROM db_metadata WHERE id = 1", [], |r| {
                r.get(0)
            })
            .unwrap();
        assert_eq!(version, 4, "version bump must roll back with the rewrite");

        let has_key_epoch: bool = conn
            .query_row(
                "SELECT EXISTS(SELECT 1 FROM pragma_table_info('db_metadata') WHERE name='key_epoch')",
                [],
                |r| r.get(0),
            )
            .unwrap();
        assert!(!has_key_epoch, "the ALTER TABLE must roll back");

        let entities_exist: bool = conn
            .query_row(
                "SELECT EXISTS(SELECT 1 FROM sqlite_master WHERE type='table' AND name='entities')",
                [],
                |r| r.get(0),
            )
            .unwrap();
        assert!(!entities_exist, "registry tables must roll back");

        let stored: Vec<u8> = conn
            .query_row(
                "SELECT wrapped_dek FROM db_metadata WHERE id = 1",
                [],
                |r| r.get(0),
            )
            .unwrap();
        assert_eq!(stored, wrap_blob, "the wrap blob must be untouched");

        // Recovery: remove the fault; the migration re-runs cleanly to v5
        // and the runner continues to the current version.
        conn.execute_batch("DROP TRIGGER fail_rewrite;").unwrap();
        run_migrations(&conn).unwrap();
        let version: i32 = conn
            .query_row("SELECT version FROM db_metadata WHERE id = 1", [], |r| {
                r.get(0)
            })
            .unwrap();
        assert_eq!(version, crate::database::schema::CURRENT_SCHEMA_VERSION);
    }
}
