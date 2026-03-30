//! Database schema and connection management.

use crate::{DatabaseError, PasswordManagerError, Result};
use rusqlite::Connection;
use std::path::Path;
use tracing::warn;

/// Current schema version. Incremented when the schema changes.
pub const CURRENT_SCHEMA_VERSION: i32 = 3;

/// Main database connection and schema manager
pub struct Database {
    conn: Connection,
}

impl Database {
    /// Open a database at the specified path
    pub fn open<P: AsRef<Path>>(path: P) -> Result<Self> {
        let conn = Connection::open(path).map_err(DatabaseError::Sqlite)?;

        // Enable foreign key constraints
        conn.execute("PRAGMA foreign_keys = ON", [])
            .map_err(DatabaseError::Sqlite)?;

        Ok(Self { conn })
    }

    /// Create a new in-memory database for testing
    pub fn in_memory() -> Result<Self> {
        let conn = Connection::open_in_memory().map_err(DatabaseError::Sqlite)?;

        conn.execute("PRAGMA foreign_keys = ON", [])
            .map_err(DatabaseError::Sqlite)?;

        Ok(Self { conn })
    }

    /// Initialize the database schema (creates v2 tables for new vaults)
    pub fn initialize_schema(&self) -> Result<()> {
        self.create_db_metadata_table()?;
        self.create_entries_table()?;
        self.create_domain_mappings_table()?;
        self.create_failed_attempts_table()?;
        self.create_ssh_keys_table()?;
        self.create_totp_secrets_table()?;
        self.create_sync_tables()?;
        self.create_indexes()?;
        self.create_triggers()?;
        Ok(())
    }

    fn create_db_metadata_table(&self) -> Result<()> {
        self.conn
            .execute(
                "CREATE TABLE IF NOT EXISTS db_metadata (
                id INTEGER PRIMARY KEY CHECK (id = 1),
                version INTEGER NOT NULL,
                kdf_params BLOB NOT NULL,
                wrapped_dek BLOB NOT NULL,
                dek_nonce BLOB NOT NULL,
                created_at INTEGER NOT NULL,
                last_modified INTEGER NOT NULL,
                biometric_ref TEXT
            )",
                [],
            )
            .map_err(DatabaseError::Sqlite)?;
        Ok(())
    }

    fn create_entries_table(&self) -> Result<()> {
        self.conn
            .execute(
                "CREATE TABLE IF NOT EXISTS entries (
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
                favorite INTEGER NOT NULL DEFAULT 0,
                sync_id TEXT,
                sync_version INTEGER NOT NULL DEFAULT 0,
                sync_state TEXT NOT NULL DEFAULT 'pending',
                last_synced_at INTEGER,
                is_deleted INTEGER NOT NULL DEFAULT 0,
                deleted_at INTEGER
            )",
                [],
            )
            .map_err(DatabaseError::Sqlite)?;
        Ok(())
    }

    fn create_domain_mappings_table(&self) -> Result<()> {
        self.conn
            .execute(
                "CREATE TABLE IF NOT EXISTS domain_mappings (
                mapping_id INTEGER PRIMARY KEY,
                entry_id INTEGER NOT NULL,
                domain TEXT NOT NULL,
                is_primary INTEGER NOT NULL DEFAULT 1,
                sync_id TEXT,
                sync_version INTEGER NOT NULL DEFAULT 0,
                sync_state TEXT NOT NULL DEFAULT 'pending',
                last_synced_at INTEGER,
                FOREIGN KEY (entry_id) REFERENCES entries(entry_id) ON DELETE CASCADE
            )",
                [],
            )
            .map_err(DatabaseError::Sqlite)?;
        Ok(())
    }

    fn create_failed_attempts_table(&self) -> Result<()> {
        self.conn
            .execute(
                "CREATE TABLE IF NOT EXISTS failed_attempts (
                attempt_id INTEGER PRIMARY KEY AUTOINCREMENT,
                attempt_time INTEGER NOT NULL,
                ip_address TEXT
            )",
                [],
            )
            .map_err(DatabaseError::Sqlite)?;
        Ok(())
    }

    fn create_ssh_keys_table(&self) -> Result<()> {
        self.conn
            .execute(
                "CREATE TABLE IF NOT EXISTS ssh_keys (
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
                modified_at INTEGER NOT NULL,
                sync_id TEXT,
                sync_version INTEGER NOT NULL DEFAULT 0,
                sync_state TEXT NOT NULL DEFAULT 'pending',
                last_synced_at INTEGER,
                is_deleted INTEGER NOT NULL DEFAULT 0,
                deleted_at INTEGER
            )",
                [],
            )
            .map_err(DatabaseError::Sqlite)?;
        Ok(())
    }

    fn create_totp_secrets_table(&self) -> Result<()> {
        self.conn
            .execute(
                "CREATE TABLE IF NOT EXISTS totp_secrets (
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
                sync_id TEXT,
                sync_version INTEGER NOT NULL DEFAULT 0,
                sync_state TEXT NOT NULL DEFAULT 'pending',
                last_synced_at INTEGER,
                is_deleted INTEGER NOT NULL DEFAULT 0,
                deleted_at INTEGER,
                FOREIGN KEY (entry_id) REFERENCES entries(entry_id) ON DELETE CASCADE
            )",
                [],
            )
            .map_err(DatabaseError::Sqlite)?;
        Ok(())
    }

    fn create_sync_tables(&self) -> Result<()> {
        self.conn
            .execute_batch(
                "CREATE TABLE IF NOT EXISTS sync_metadata (
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

                CREATE TABLE IF NOT EXISTS sync_tombstones (
                    tombstone_id INTEGER PRIMARY KEY AUTOINCREMENT,
                    sync_id TEXT NOT NULL UNIQUE,
                    entry_type TEXT NOT NULL,
                    sync_version INTEGER NOT NULL,
                    deleted_at INTEGER NOT NULL,
                    origin_device_id TEXT NOT NULL,
                    pushed INTEGER NOT NULL DEFAULT 0
                );",
            )
            .map_err(DatabaseError::Sqlite)?;
        Ok(())
    }

    fn create_indexes(&self) -> Result<()> {
        let indexes = [
            "CREATE INDEX IF NOT EXISTS idx_entries_vault_id ON entries(vault_id)",
            "CREATE INDEX IF NOT EXISTS idx_entries_favorite ON entries(favorite)",
            "CREATE UNIQUE INDEX IF NOT EXISTS idx_entries_sync_id ON entries(sync_id)",
            "CREATE INDEX IF NOT EXISTS idx_entries_sync_state ON entries(sync_state)",
            "CREATE INDEX IF NOT EXISTS idx_domain_mappings_entry_id ON domain_mappings(entry_id)",
            "CREATE INDEX IF NOT EXISTS idx_domain_mappings_domain ON domain_mappings(domain)",
            "CREATE INDEX IF NOT EXISTS idx_totp_secrets_entry_id ON totp_secrets(entry_id)",
            "CREATE UNIQUE INDEX IF NOT EXISTS idx_ssh_keys_sync_id ON ssh_keys(sync_id)",
            "CREATE INDEX IF NOT EXISTS idx_ssh_keys_sync_state ON ssh_keys(sync_state)",
            "CREATE UNIQUE INDEX IF NOT EXISTS idx_totp_secrets_sync_id ON totp_secrets(sync_id)",
            "CREATE INDEX IF NOT EXISTS idx_totp_secrets_sync_state ON totp_secrets(sync_state)",
            "CREATE INDEX IF NOT EXISTS idx_sync_tombstones_pushed ON sync_tombstones(pushed)",
            // v3 indexes for pagination performance
            "CREATE INDEX IF NOT EXISTS idx_entries_modified_at ON entries(modified_at DESC)",
            "CREATE INDEX IF NOT EXISTS idx_entries_created_at ON entries(created_at DESC)",
        ];
        for sql in &indexes {
            self.conn.execute(sql, []).map_err(DatabaseError::Sqlite)?;
        }
        Ok(())
    }

    fn create_triggers(&self) -> Result<()> {
        self.conn
            .execute_batch(
                "CREATE TRIGGER IF NOT EXISTS update_db_metadata_timestamp
                 AFTER UPDATE ON db_metadata
                 FOR EACH ROW
                 BEGIN
                     UPDATE db_metadata SET last_modified = (strftime('%s', 'now')) WHERE id = 1;
                 END;

                 CREATE TRIGGER IF NOT EXISTS update_entry_modified_timestamp
                 AFTER UPDATE OF title, username, password, url, notes, favorite ON entries
                 FOR EACH ROW
                 BEGIN
                     UPDATE entries SET
                         modified_at = (strftime('%s', 'now')),
                         sync_version = OLD.sync_version + 1,
                         sync_state = 'pending'
                     WHERE entry_id = NEW.entry_id;
                 END;",
            )
            .map_err(DatabaseError::Sqlite)?;
        Ok(())
    }

    /// Validate the database schema version, running migrations if needed.
    ///
    /// - Older databases are auto-migrated forward (v1 → v2 → v3).
    /// - Newer databases (created by a newer binary) are allowed if they are
    ///   within a forward-compatible range, since newer schema versions only add
    ///   non-breaking changes (indexes, optional columns).
    pub fn validate_schema_version(&self) -> Result<()> {
        let version: i32 = self
            .conn
            .query_row("SELECT version FROM db_metadata WHERE id = 1", [], |row| {
                row.get(0)
            })
            .map_err(DatabaseError::Sqlite)?;

        if version == CURRENT_SCHEMA_VERSION {
            return Ok(());
        }

        // Auto-migrate from older versions
        if version < CURRENT_SCHEMA_VERSION {
            crate::database::migrations::run_migrations(&self.conn)?;

            // Verify migration reached the expected version
            let new_version: i32 = self
                .conn
                .query_row("SELECT version FROM db_metadata WHERE id = 1", [], |row| {
                    row.get(0)
                })
                .map_err(DatabaseError::Sqlite)?;

            if new_version != CURRENT_SCHEMA_VERSION {
                return Err(PasswordManagerError::from(DatabaseError::SchemaMismatch {
                    expected: CURRENT_SCHEMA_VERSION,
                    found: new_version,
                }));
            }

            return Ok(());
        }

        // Database was created/migrated by a newer binary. Allow it — newer
        // schema versions only add non-breaking changes (indexes, optional
        // columns, new tables). The code queries specific columns/tables and
        // SQLite will produce a clear error if something is truly missing.
        warn!(
            db_version = version,
            code_version = CURRENT_SCHEMA_VERSION,
            "Database schema version is newer than this binary expects; proceeding anyway"
        );
        Ok(())
    }

    /// Get a reference to the underlying connection
    pub fn conn(&self) -> &Connection {
        &self.conn
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_in_memory_database() {
        let db = Database::in_memory().unwrap();
        db.initialize_schema().unwrap();

        // Verify tables exist
        let table_names: Vec<String> = db
            .conn
            .prepare("SELECT name FROM sqlite_master WHERE type='table'")
            .unwrap()
            .query_map([], |row| row.get(0))
            .unwrap()
            .collect::<std::result::Result<Vec<_>, _>>()
            .unwrap();

        assert!(table_names.contains(&"db_metadata".to_string()));
        assert!(table_names.contains(&"entries".to_string()));
        assert!(table_names.contains(&"domain_mappings".to_string()));
        assert!(table_names.contains(&"failed_attempts".to_string()));
        assert!(table_names.contains(&"ssh_keys".to_string()));
        assert!(table_names.contains(&"totp_secrets".to_string()));

        // Verify indexes exist
        let index_names: Vec<String> = db
            .conn
            .prepare("SELECT name FROM sqlite_master WHERE type='index' AND name LIKE 'idx_%'")
            .unwrap()
            .query_map([], |row| row.get(0))
            .unwrap()
            .collect::<std::result::Result<Vec<_>, _>>()
            .unwrap();

        assert!(index_names.contains(&"idx_entries_vault_id".to_string()));
        assert!(index_names.contains(&"idx_entries_favorite".to_string()));
        assert!(index_names.contains(&"idx_domain_mappings_entry_id".to_string()));
        assert!(index_names.contains(&"idx_domain_mappings_domain".to_string()));
        assert!(index_names.contains(&"idx_totp_secrets_entry_id".to_string()));
        // v3 indexes must be present for new vaults too
        assert!(index_names.contains(&"idx_entries_modified_at".to_string()));
        assert!(index_names.contains(&"idx_entries_created_at".to_string()));

        // Verify triggers exist
        let trigger_names: Vec<String> = db
            .conn
            .prepare("SELECT name FROM sqlite_master WHERE type='trigger'")
            .unwrap()
            .query_map([], |row| row.get(0))
            .unwrap()
            .collect::<std::result::Result<Vec<_>, _>>()
            .unwrap();

        assert!(trigger_names.contains(&"update_db_metadata_timestamp".to_string()));
        assert!(trigger_names.contains(&"update_entry_modified_timestamp".to_string()));
    }

    #[test]
    fn newer_db_version_does_not_error() {
        // Simulates opening a DB that was migrated by a newer binary.
        // The code should allow this instead of hard-failing.
        let db = Database::in_memory().unwrap();
        db.initialize_schema().unwrap();

        // Insert metadata at a future version (e.g., v99)
        db.conn()
            .execute(
                "INSERT INTO db_metadata (id, version, kdf_params, wrapped_dek, dek_nonce, created_at, last_modified)
                 VALUES (1, 99, X'00', X'00', X'00', 0, 0)",
                [],
            )
            .unwrap();

        // Should succeed (warn, not error)
        db.validate_schema_version().unwrap();
    }

    #[test]
    fn older_db_version_triggers_migration() {
        // Create a genuine v1 database (no sync columns)
        let db = Database::in_memory().unwrap();
        db.conn()
            .execute_batch(
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

        // Should run migrations v1→v2→v3 and succeed
        db.validate_schema_version().unwrap();

        // Verify version was bumped to current
        let version: i32 = db
            .conn()
            .query_row("SELECT version FROM db_metadata WHERE id = 1", [], |row| {
                row.get(0)
            })
            .unwrap();
        assert_eq!(version, CURRENT_SCHEMA_VERSION);
    }
}
