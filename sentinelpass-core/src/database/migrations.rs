//! Database migrations for schema versioning.
//!
//! Schema version is tracked via `db_metadata.version` and validated on vault
//! open in `schema::Database::validate_schema_version()`. When future schema
//! changes are needed, add migration logic here and bump
//! `schema::CURRENT_SCHEMA_VERSION`.

use crate::{DatabaseError, Result};
use rusqlite::Connection;

/// Migrate schema from v1 to v2: add sync columns and tables.
pub fn migrate_v1_to_v2(conn: &Connection) -> Result<()> {
    conn.execute_batch(
        "BEGIN;

        -- Add sync columns to entries
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
        CREATE INDEX IF NOT EXISTS idx_sync_tombstones_pushed ON sync_tombstones(pushed);

        -- Bump schema version
        UPDATE db_metadata SET version = 2 WHERE id = 1;

        COMMIT;",
    )
    .map_err(DatabaseError::Sqlite)?;

    // Assign UUID sync_ids to all existing entries
    assign_sync_ids(conn)?;

    Ok(())
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
pub fn migrate_v4_to_v5(conn: &Connection) -> Result<()> {
    conn.execute_batch(
        "BEGIN;

        ALTER TABLE db_metadata ADD COLUMN key_epoch INTEGER NOT NULL DEFAULT 1;

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
            ON secret_equality_index(updated_at);

        -- Bump schema version
        UPDATE db_metadata SET version = 5 WHERE id = 1;

        COMMIT;",
    )
    .map_err(crate::DatabaseError::Sqlite)?;

    // Re-serialize the wrapped DEK into the current shape. The v0.8.0 blob is
    // bincode without the `epoch_bound` field; bincode is positional, so old
    // blobs must be read with the legacy shape and rewritten with the field
    // present (else every later open hits a deserialization EOF).
    let wrapped_blob: Vec<u8> = conn
        .query_row(
            "SELECT wrapped_dek FROM db_metadata WHERE id = 1",
            [],
            |row| row.get(0),
        )
        .map_err(crate::DatabaseError::Sqlite)?;
    // Tolerant read accepts both the legacy 3-field shape and the current
    // 4-field shape; the rewrite normalizes legacy blobs so every later open
    // deserializes cleanly.
    // A blob that is not a recognizable wrap (e.g. a test fixture placeholder)
    // is left as-is: forcing it here would turn a data quirk into a migration
    // failure. Real wraps rewrite into the current shape.
    if let Ok(key) = crate::crypto::keyring::WrappedKey::from_bincode_bytes(&wrapped_blob) {
        let upgraded_blob = bincode::serialize(&key).map_err(|e| {
            crate::DatabaseError::Sqlite(rusqlite::Error::ToSqlConversionFailure(Box::new(e)))
        })?;
        conn.execute(
            "UPDATE db_metadata SET wrapped_dek = ?1 WHERE id = 1",
            rusqlite::params![&upgraded_blob],
        )
        .map_err(crate::DatabaseError::Sqlite)?;
    }

    Ok(())
}

/// Migrate schema from v3 to v4: add the credential type discriminator
/// (`password` | `api_key` | `passkey_reference`) to `entries`.
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

    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Create a database with v1 schema only (no sync columns).
    fn create_v1_db() -> rusqlite::Connection {
        let conn = rusqlite::Connection::open_in_memory().unwrap();
        conn.execute("PRAGMA foreign_keys = ON", []).unwrap();
        conn.execute_batch(
            "CREATE TABLE db_metadata (
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
            );
            INSERT INTO db_metadata (id, version, kdf_params, wrapped_dek, dek_nonce, created_at, last_modified)
            VALUES (1, 1, X'00', X'00', X'00', 0, 0);",
        )
        .unwrap();
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
}
