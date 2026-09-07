//! Database schema and connection management.

use crate::platform::{
    set_owner_only_mode, validate_sensitive_path, warn_on_loose_parent_dir, OwnerOnlyPolicy,
    SensitivePathError,
};
use crate::{DatabaseError, PasswordManagerError, Result};
use rusqlite::Connection;
use std::path::{Path, PathBuf};
use tracing::warn;

/// Current schema version. Incremented when the schema changes.
///
/// v8 (WBS-306 / ADR-005 rev 4): `domain_mappings.domain_enc` (sealed
/// domain) + the `domain_mapping_tags` keyed-lookup table; the plaintext
/// domain INDEX is dropped (lookups move to tags). The legacy plaintext
/// `domain` COLUMN remains until the WBS-404 bulk migration clears it.
/// v9 (WBS-409 / TD-ROB-02): the `update_entry_modified_timestamp` echo
/// trigger is DROPPED — remote sync applies wrote `sync_state = 'synced'`
/// explicitly, and this trigger rewrote it back to `'pending'` (the applied
/// change re-pushed forever). Every local mutation path writes sync
/// bookkeeping explicitly (repository insert/update, delete, sweeps), so
/// the trigger is load-bearing for nothing; see `migrate_v8_to_v9`.
pub const CURRENT_SCHEMA_VERSION: i32 = 9;

/// Current vault ENVELOPE FORMAT version (`db_metadata.format_version`,
/// WBS-406). Deliberately distinct from [`CURRENT_SCHEMA_VERSION`] (the
/// table/column layout): this tracks the CONTENT format —
/// `1` = legacy context-free field encryption (v1 blobs, dual-read),
/// `2` = the ACTIVATED v2 envelope state: every stored blob is an
/// identity-bound SPENV envelope AND the full WBS-405 verification pass
/// proved every one of them (plus every domain-mapping relation) opens.
///
/// The value is stamped ONLY by the post-unlock activation step
/// (`vault/activation_ops.rs`) — migrations run before the DEK exists and
/// cannot verify content, so they never touch it. An open refuses a
/// `format_version` GREATER than this constant with the same fail-closed
/// discipline as the schema gate (SR-CRYPTO-005 / TD-ROB-07): a newer
/// content format's rows must never be interpreted by an older binary.
/// Absent column (pre-v6 schemas) and NULL both read as legacy `1`.
pub const CURRENT_VAULT_FORMAT_VERSION: i64 = 2;

/// Main database connection and schema manager
pub struct Database {
    conn: Connection,
}

impl Database {
    /// Open a database at the specified path.
    ///
    /// The vault database is sensitive at rest, so the open path enforces its
    /// on-disk file protections (WBS-412/413, SR-DATA-003):
    ///
    /// - **New file**: created with an explicit owner-only mode. On Unix a
    ///   private umask (0o077) is held across the open and the PRAGMA setup
    ///   so the database AND the `-wal`/`-shm` sidecars SQLite creates are
    ///   born 0600 — no umask-exposed window — with an explicit chmod as a
    ///   belt-and-braces backstop.
    /// - **Existing file**: validated (not a symlink, regular file, owned by
    ///   the current user) and its mode verified owner-only under the Refuse
    ///   policy: a vault database with group/world read is REFUSED with a
    ///   remediation hint. Silent tightening was deliberately rejected — it
    ///   would launder an attacker-loosened state without the user ever
    ///   learning about it. Chosen policy, documented in
    ///   docs/SECURITY_STATUS_MATRIX.md.
    ///
    /// `:memory:` (in-memory/dev vaults) skips all FS guards: Windows stats
    /// the reserved colon as ERROR_INVALID_NAME, not NotFound (WBS-306
    /// lesson), and there is no file to protect.
    pub fn open<P: AsRef<Path>>(path: P) -> Result<Self> {
        let path = path.as_ref();
        let fs_guarded = path != std::path::Path::new(":memory:");

        let mut created = false;
        if fs_guarded {
            warn_on_loose_parent_dir(path);
            match std::fs::symlink_metadata(path) {
                // Regular file only: a directory (Windows reports len() 0
                // for directories — the Unix assumption that zero length
                // implies a touch(1)-leftover file does NOT hold there) or
                // a FIFO/device node falls through to the full validation,
                // which refuses non-regular targets.
                Ok(meta) if meta.len() == 0 && meta.is_file() => {
                    // Zero-byte file (e.g. a touch(1) leftover — the
                    // documented create-path allowance: there is no data to
                    // destroy). ADOPT it: pin the mode owner-only and take
                    // the creation path so WAL/SHM are born private too.
                    set_owner_only_mode(path, false)?;
                    created = true;
                }
                Ok(meta) if meta.is_dir() => {
                    return Err(PasswordManagerError::InvalidInput(format!(
                        "{} is a directory, not a regular file — a vault database path \
                         must be a regular file; remove the directory and retry",
                        path.display()
                    )));
                }
                Ok(_) => {
                    Self::validate_vault_file(path)?;
                }
                Err(e) if e.kind() == std::io::ErrorKind::NotFound => created = true,
                // A stat error on a real path is allowed through (matching
                // the create-path precedent): Connection::open below
                // surfaces any genuine problem.
                Err(_) => {}
            }
        }

        // Hold a private umask across open + PRAGMAs so a freshly created
        // database and its WAL/SHM sidecars are born owner-only (same
        // technique as the daemon's Unix-socket bind). Unix-only: the
        // umask swap is a libc operation; on non-Unix the guard (and its
        // drop) never existed, so the restore is cfg-gated to match
        // (Windows CI compile failure, gate-review fix cycle).
        // The guard restores at the end of the cfg block; the connection
        // outlives it (umask only needs to cover the CREATE).
        #[cfg(unix)]
        let conn = {
            let _umask_guard = UmaskGuard::if_created(created);
            let conn = Connection::open(path).map_err(DatabaseError::Sqlite)?;
            Self::apply_pragmas(&conn)?;
            conn
        };
        #[cfg(not(unix))]
        let conn = Connection::open(path).map_err(DatabaseError::Sqlite)?;

        if created && fs_guarded {
            // Belt-and-braces: explicit owner-only mode even if another
            // thread raced the umask or the filesystem ignored it.
            set_owner_only_mode(path, false)?;
            for ext in ["-wal", "-shm"] {
                // Sidecars are transient (SQLite removes them on clean
                // close); best-effort is sufficient here.
                let _ = set_owner_only_mode(&sidecar_path(path, ext), false);
            }
        } else if fs_guarded {
            // Post-open re-check: narrows the check-then-open TOCTOU window
            // (a symlink or mode swap landing between the pre-open stat and
            // the open is refused here; rusqlite exposes no O_NOFOLLOW open,
            // so the residual race is documented rather than eliminated).
            Self::validate_vault_file(path)?;
            // Tighten stale WAL/SHM sidecars too (gate review, finding on
            // the existing-file path): a pre-0.10 vault.db-wal born 0644
            // keeps receiving page writes even after the main db is
            // chmod'd 0600.
            for ext in ["-wal", "-shm"] {
                let sidecar = sidecar_path(path, ext);
                if let Ok(meta) = std::fs::metadata(&sidecar) {
                    if meta.len() > 0 {
                        let _ = set_owner_only_mode(&sidecar, false);
                    }
                }
            }
        }

        Ok(Self { conn })
    }

    /// Validate an existing vault database file under the Refuse policy,
    /// with an actionable error for the loose-mode case.
    fn validate_vault_file(path: &Path) -> Result<()> {
        validate_sensitive_path(path, OwnerOnlyPolicy::Refuse).map_err(|e| match e {
            SensitivePathError::LooseMode { path, actual } => {
                PasswordManagerError::InvalidInput(format!(
                    "vault database {} has permissive mode {actual:#06o} \
                     (group/world-readable); refusing to open (SR-DATA-003). \
                     If this is your own vault, repair with: chmod 600 {} \
                     (and the same for its -wal/-shm sidecars if present)",
                    path.display(),
                    path.display()
                ))
            }
            other => other.into(),
        })
    }

    /// Create a new in-memory database for testing
    pub fn in_memory() -> Result<Self> {
        let conn = Connection::open_in_memory().map_err(DatabaseError::Sqlite)?;
        // WAL and busy_timeout are no-ops for in-memory; foreign_keys still matters.
        conn.execute("PRAGMA foreign_keys = ON", [])
            .map_err(DatabaseError::Sqlite)?;
        Ok(Self { conn })
    }

    /// Apply connection-level PRAGMAs that improve reliability and performance.
    ///
    /// WAL mode — allows concurrent readers while a writer is active.
    /// busy_timeout — retries for up to 5 s before returning SQLITE_BUSY instead
    ///   of failing immediately under concurrent daemon access.
    /// synchronous = NORMAL — safe with WAL (the WAL itself is always fsynced);
    ///   faster than FULL without sacrificing durability for typical workloads.
    /// cache_size = -16000 — 16 MB page cache; avoids repeated disk reads for
    ///   large vaults and outperforms SQLite's 2 MB default.
    /// temp_store = MEMORY — temp tables and indexes stay in memory instead of
    ///   being written to a temp file; matters for sort-heavy list/search queries.
    ///
    /// Uses `pragma_update` (not `execute`) for pragmas that return a result row
    /// such as `journal_mode`, which would cause an error with plain `execute`.
    fn apply_pragmas(conn: &Connection) -> Result<()> {
        use rusqlite::DatabaseName;
        conn.pragma_update(None, "foreign_keys", true)
            .map_err(DatabaseError::Sqlite)?;
        conn.pragma_update(Some(DatabaseName::Main), "journal_mode", "WAL")
            .map_err(DatabaseError::Sqlite)?;
        conn.pragma_update(None, "busy_timeout", 5000i64)
            .map_err(DatabaseError::Sqlite)?;
        conn.pragma_update(None, "synchronous", "NORMAL")
            .map_err(DatabaseError::Sqlite)?;
        // Negative value = kibibytes; -16000 ≈ 16 MB.
        conn.pragma_update(None, "cache_size", -16000i64)
            .map_err(DatabaseError::Sqlite)?;
        conn.pragma_update(None, "temp_store", "MEMORY")
            .map_err(DatabaseError::Sqlite)?;
        Ok(())
    }

    /// Trigger a passive WAL checkpoint to reclaim space after bulk writes.
    ///
    /// A passive checkpoint writes dirty WAL pages back to the main database
    /// file without blocking readers or the writer. Call this after large sync
    /// operations so the WAL file doesn't grow unboundedly.
    pub fn wal_checkpoint(&self) -> Result<()> {
        self.conn
            .execute("PRAGMA wal_checkpoint(PASSIVE)", [])
            .map_err(DatabaseError::Sqlite)?;
        Ok(())
    }

    /// Initialize the database schema (creates current tables for new vaults)
    pub fn initialize_schema(&self) -> Result<()> {
        self.create_db_metadata_table()?;

        self.create_key_slots_table()?;
        self.create_entries_table()?;
        self.create_domain_mappings_table()?;
        self.create_domain_mapping_tags_table()?;
        self.create_failed_attempts_table()?;
        self.create_ssh_keys_table()?;
        self.create_totp_secrets_table()?;
        self.create_sync_tables()?;
        self.create_registry_tables()?;
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
                biometric_ref TEXT,
                key_epoch INTEGER NOT NULL DEFAULT 1,
                vault_uuid TEXT,
                format_version INTEGER NOT NULL DEFAULT 1,
                slot_registry_mac BLOB
            )",
                [],
            )
            .map_err(DatabaseError::Sqlite)?;
        Ok(())
    }

    fn create_key_slots_table(&self) -> Result<()> {
        self.conn
            .execute_batch(
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
                CREATE INDEX IF NOT EXISTS idx_key_slots_type ON key_slots(slot_type);",
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
                credential_type TEXT NOT NULL DEFAULT 'password'
                    CHECK (credential_type IN ('password', 'api_key', 'passkey_reference')),
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
                domain_enc BLOB,
                FOREIGN KEY (entry_id) REFERENCES entries(entry_id) ON DELETE CASCADE
            )",
                [],
            )
            .map_err(DatabaseError::Sqlite)?;
        Ok(())
    }

    /// Keyed equality tags for encrypted domain lookups (WBS-306 /
    /// ADR-005 rev 4): one HMAC-SHA256 per label-chain suffix of the
    /// mapping's normalized host, under the DEK-derived domain-tag key.
    /// `is_chain_root` marks the FULL-host tag (the suffix-match predicate
    /// needs the root/suffix distinction — shared suffix chains alone, e.g.
    /// `com`, must never produce matches). Tags make the sealed
    /// `domain_enc` column searchable WITHOUT a plaintext index; rows die
    /// with their mapping (FK CASCADE).
    fn create_domain_mapping_tags_table(&self) -> Result<()> {
        self.conn
            .execute(
                "CREATE TABLE IF NOT EXISTS domain_mapping_tags (
                tag_id INTEGER PRIMARY KEY AUTOINCREMENT,
                mapping_id INTEGER NOT NULL,
                tag BLOB NOT NULL,
                is_chain_root INTEGER NOT NULL DEFAULT 0,
                equality_key_id INTEGER NOT NULL DEFAULT 1,
                FOREIGN KEY (mapping_id) REFERENCES domain_mappings(mapping_id)
                    ON DELETE CASCADE
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

    /// Registry tables (ADR-001): entities, membership, the encrypted
    /// secret-equality index, entry lifecycle, and sweep bookkeeping.
    ///
    /// `entities.name`/`notes` and `entity_memberships.label` are
    /// DEK-encrypted blobs (same field-encryption pattern as entry fields);
    /// kind/criticality/policy columns are declared policy and stay
    /// plaintext. `entry_lifecycle` is deliberately a sibling table rather
    /// than columns on `entries`: rotation stamps must not fabricate sync
    /// churn there. (Historically this also kept them out of the reach of
    /// the `update_entry_modified_timestamp` echo trigger, removed in
    /// schema v9 / WBS-409.)
    fn create_registry_tables(&self) -> Result<()> {
        self.conn
            .execute_batch(
                "CREATE TABLE IF NOT EXISTS entities (
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
            // v8 (WBS-306): lookups run through keyed equality tags; the
            // plaintext domain index is gone (dropped by migrate_v7_to_v8).
            "CREATE INDEX IF NOT EXISTS idx_domain_mapping_tags_tag ON domain_mapping_tags(tag)",
            "CREATE INDEX IF NOT EXISTS idx_domain_mapping_tags_root ON domain_mapping_tags(tag, is_chain_root)",
            "CREATE INDEX IF NOT EXISTS idx_domain_mapping_tags_mapping ON domain_mapping_tags(mapping_id)",
            "CREATE INDEX IF NOT EXISTS idx_totp_secrets_entry_id ON totp_secrets(entry_id)",
            "CREATE UNIQUE INDEX IF NOT EXISTS idx_ssh_keys_sync_id ON ssh_keys(sync_id)",
            "CREATE INDEX IF NOT EXISTS idx_ssh_keys_sync_state ON ssh_keys(sync_state)",
            "CREATE UNIQUE INDEX IF NOT EXISTS idx_totp_secrets_sync_id ON totp_secrets(sync_id)",
            "CREATE INDEX IF NOT EXISTS idx_totp_secrets_sync_state ON totp_secrets(sync_state)",
            "CREATE INDEX IF NOT EXISTS idx_sync_tombstones_pushed ON sync_tombstones(pushed)",
            // v3 indexes for pagination performance
            "CREATE INDEX IF NOT EXISTS idx_entries_modified_at ON entries(modified_at DESC)",
            "CREATE INDEX IF NOT EXISTS idx_entries_created_at ON entries(created_at DESC)",
            // v4 index for credential category filtering
            "CREATE INDEX IF NOT EXISTS idx_entries_credential_type ON entries(credential_type)",
            // v5 registry indexes
            "CREATE INDEX IF NOT EXISTS idx_entity_memberships_entity_id ON entity_memberships(entity_id)",
            "CREATE INDEX IF NOT EXISTS idx_secret_equality_index_updated ON secret_equality_index(updated_at)",
        ];
        for sql in &indexes {
            self.conn.execute(sql, []).map_err(DatabaseError::Sqlite)?;
        }
        Ok(())
    }

    /// Create the database triggers.
    ///
    /// Only the `db_metadata` timestamp trigger remains here as of schema
    /// v9 (WBS-409 / TD-ROB-02): the former `update_entry_modified_timestamp`
    /// echo trigger on `entries` was removed. On a remote sync apply it
    /// rewrote the applied row behind the apply's back: `sync_state` back
    /// to `'pending'` (the applied change re-pushed; with `modified_at`
    /// stamped to apply-time the rewritten row also won the peer's LWW
    /// tie-break, see-sawing the entry between devices), and
    /// `sync_version = OLD.sync_version + 1` — which silently CORRUPTED the
    /// applied version whenever the local row was more than one version
    /// behind (remote v5 over a local v2 landed as v3). Every local
    /// mutation writes sync bookkeeping explicitly, so the trigger was
    /// load-bearing for nothing:
    /// - insert: `repository::create` (version 1, `'pending'`)
    /// - update: `repository::update` (version + 1, `'pending'`)
    /// - delete: `VaultManager::delete_entry` (version + 1, `'pending'`,
    ///   inside one transaction)
    /// - v1→v2 blob sweep: `vault::migration_ops` (preserves scanned
    ///   bookkeeping)
    ///
    /// Vaults that predate v9 have the trigger dropped by
    /// `migrate_v8_to_v9` (both the OF-list shape created here and the
    /// legacy no-list shape from v1 binaries).
    fn create_triggers(&self) -> Result<()> {
        self.conn
            .execute_batch(
                "CREATE TRIGGER IF NOT EXISTS update_db_metadata_timestamp
                 AFTER UPDATE ON db_metadata
                 FOR EACH ROW
                 BEGIN
                     UPDATE db_metadata SET last_modified = (strftime('%s', 'now')) WHERE id = 1;
                 END;",
            )
            .map_err(DatabaseError::Sqlite)?;
        Ok(())
    }

    /// The stored vault envelope format version (WBS-406 activation
    /// marker), tolerant of pre-v6 schemas whose `db_metadata` predates the
    /// column: an absent column or a NULL value is the legacy format `1`.
    /// Never fails on legacy vaults — only on genuine SQLite errors.
    pub fn stored_format_version(&self) -> Result<i64> {
        let has_column: bool = self
            .conn
            .query_row(
                "SELECT EXISTS(SELECT 1 FROM pragma_table_info('db_metadata') \
                 WHERE name = 'format_version')",
                [],
                |row| row.get(0),
            )
            .map_err(DatabaseError::Sqlite)?;
        if !has_column {
            return Ok(1);
        }
        let value: Option<i64> = self
            .conn
            .query_row(
                "SELECT format_version FROM db_metadata WHERE id = 1",
                [],
                |row| row.get(0),
            )
            .map_err(DatabaseError::Sqlite)?;
        Ok(value.unwrap_or(1))
    }

    /// Validate the database schema version, running migrations if needed.
    ///
    /// - The envelope FORMAT gate (WBS-406) runs FIRST: a vault activated
    ///   by a newer binary (`format_version` > [`CURRENT_VAULT_FORMAT_VERSION`])
    ///   is refused with the typed [`DatabaseError::UnsupportedFutureFormat`]
    ///   before the schema version is even read — there is no downgrade
    ///   path into a content format this build cannot interpret.
    /// - Older databases are auto-migrated forward (v1 → v2 → … → current).
    /// - Newer databases (created by a newer binary) fail CLOSED with the
    ///   typed [`DatabaseError::UnsupportedFutureSchema`] error (WBS-315 /
    ///   SR-CRYPTO-005). This is the FIRST read on every vault-open path and
    ///   touches only `db_metadata` — a refused vault has no entry data read
    ///   or modified, so a future schema's rows are never interpreted by an
    ///   older binary that cannot know their shape.
    pub fn validate_schema_version(&self) -> Result<()> {
        let format_version = self.stored_format_version()?;
        if format_version > CURRENT_VAULT_FORMAT_VERSION {
            warn!(
                format_version = format_version,
                supported = CURRENT_VAULT_FORMAT_VERSION,
                "vault envelope format is newer than this binary supports; refusing to open"
            );
            return Err(PasswordManagerError::from(
                DatabaseError::UnsupportedFutureFormat {
                    found: format_version,
                    supported: CURRENT_VAULT_FORMAT_VERSION,
                },
            ));
        }

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

        // Database was created/migrated by a newer binary — refuse without
        // reading or mutating any entry data. Newer versions may change row
        // shapes, column semantics, or crypto formats in ways this build
        // cannot know; "works by luck" is not an open policy.
        warn!(
            db_version = version,
            code_version = CURRENT_SCHEMA_VERSION,
            "vault schema is newer than this binary supports; refusing to open"
        );
        Err(PasswordManagerError::from(
            DatabaseError::UnsupportedFutureSchema {
                found: version,
                supported: CURRENT_SCHEMA_VERSION,
            },
        ))
    }

    /// Get a reference to the underlying connection
    pub fn conn(&self) -> &Connection {
        &self.conn
    }
}

/// Path of a SQLite sidecar file (`-wal` / `-shm`) for a database path.
fn sidecar_path(db_path: &Path, ext: &str) -> PathBuf {
    let mut s = db_path.as_os_str().to_os_string();
    s.push(ext);
    PathBuf::from(s)
}

/// (Unix) RAII guard holding a private umask (0o077) so files created while
/// it is held are born owner-only; the previous umask is restored on drop.
#[cfg(unix)]
struct UmaskGuard {
    previous: libc::mode_t,
}

#[cfg(unix)]
impl UmaskGuard {
    /// Holds the private umask only when a fresh vault database is about to
    /// be created; existing-file opens leave the process umask untouched.
    fn if_created(created: bool) -> Option<Self> {
        if created {
            // SAFETY: umask is process-global with no preconditions; the
            // previous value is restored on drop.
            Some(Self {
                previous: unsafe { libc::umask(0o077) },
            })
        } else {
            None
        }
    }
}

#[cfg(unix)]
impl Drop for UmaskGuard {
    fn drop(&mut self) {
        // SAFETY: see if_created.
        unsafe { libc::umask(self.previous) };
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn in_memory_path_bypasses_fs_guards() {
        // Regression (WBS-412): ":memory:" must never be stat'd — Windows
        // answers ERROR_INVALID_NAME, not NotFound — and must open freely.
        assert!(Database::open(":memory:").is_ok());
    }

    #[test]
    fn open_refuses_directory_at_vault_path() {
        // Cross-platform (runs on the Windows CI leg): a directory at the
        // sensitive path is not a regular file.
        let dir = tempfile::TempDir::new().unwrap();
        let as_db = dir.path().join("as_db");
        std::fs::create_dir_all(&as_db).unwrap();
        let err = Database::open(&as_db).err().expect("expected refusal");
        assert!(
            err.to_string().contains("not a regular file"),
            "expected NotRegularFile refusal, got: {err}"
        );
    }

    #[cfg(unix)]
    #[test]
    fn created_vault_database_and_sidecars_are_owner_only() {
        use std::os::unix::fs::PermissionsExt;

        let dir = tempfile::TempDir::new().unwrap();
        let db_path = dir.path().join("vault.db");
        {
            // SQLite materializes the WAL/SHM sidecars lazily on the first
            // write, so force one; they then exist for as long as the
            // connection is held.
            let _db = Database::open(&db_path).unwrap();
            _db.conn()
                .execute("CREATE TABLE sidecar_probe (x INTEGER)", [])
                .unwrap();
            for p in [
                db_path.clone(),
                sidecar_path(&db_path, "-wal"),
                sidecar_path(&db_path, "-shm"),
            ] {
                let mode = std::fs::metadata(&p).unwrap().permissions().mode() & 0o777;
                assert_eq!(mode, 0o600, "expected 0600 on {}", p.display());
            }
        }
    }

    #[cfg(unix)]
    #[test]
    fn open_refuses_group_or_world_readable_vault_database() {
        use std::os::unix::fs::PermissionsExt;

        let dir = tempfile::TempDir::new().unwrap();
        let db_path = dir.path().join("vault.db");
        drop(Database::open(&db_path).unwrap());

        for loose in [0o644, 0o604, 0o640, 0o600 /* control: tight */] {
            std::fs::set_permissions(&db_path, std::fs::Permissions::from_mode(loose)).unwrap();
            let result = Database::open(&db_path);
            if loose & 0o077 == 0 {
                assert!(result.is_ok(), "0{loose:o} is owner-only and must open");
            } else {
                let err = result.err().expect("expected mode refusal");
                let msg = err.to_string();
                assert!(
                    msg.contains("permissive mode") && msg.contains("chmod 600"),
                    "expected actionable refusal, got: {msg}"
                );
            }
        }
    }

    #[cfg(unix)]
    #[test]
    fn open_refuses_symlinked_vault_database() {
        let dir = tempfile::TempDir::new().unwrap();
        let real = dir.path().join("real.db");
        drop(Database::open(&real).unwrap());
        let link = dir.path().join("link.db");
        std::os::unix::fs::symlink(&real, &link).unwrap();

        let err = Database::open(&link)
            .err()
            .expect("expected symlink refusal");
        assert!(
            err.to_string().contains("symlink"),
            "expected symlink refusal, got: {err}"
        );
    }

    #[cfg(unix)]
    #[test]
    fn zero_byte_file_is_adopted_with_owner_only_mode() {
        use std::os::unix::fs::PermissionsExt;

        let dir = tempfile::TempDir::new().unwrap();
        let db_path = dir.path().join("touched.db");
        // touch(1) leftover: born with umask mode (typically 0644 — but do
        // NOT assert the initial mode: sibling tests run in parallel and the
        // creation-time UmaskGuard in Database::open may pin it to 0600).
        std::fs::write(&db_path, b"").unwrap();

        {
            let db = Database::open(&db_path).unwrap();
            db.validate_schema_version().unwrap_err(); // fresh empty db: no schema yet
        }
        assert_eq!(
            std::fs::metadata(&db_path).unwrap().permissions().mode() & 0o777,
            0o600,
            "adopted zero-byte file must be tightened to 0600"
        );
    }

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
        // v5 registry tables
        assert!(table_names.contains(&"entities".to_string()));
        assert!(table_names.contains(&"entity_memberships".to_string()));
        assert!(table_names.contains(&"secret_equality_index".to_string()));
        assert!(table_names.contains(&"entry_lifecycle".to_string()));
        assert!(table_names.contains(&"registry_state".to_string()));

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
        // v8 (WBS-306): the plaintext domain index is replaced by the
        // keyed tag indexes.
        assert!(index_names.contains(&"idx_domain_mapping_tags_tag".to_string()));
        assert!(index_names.contains(&"idx_domain_mapping_tags_root".to_string()));
        assert!(index_names.contains(&"idx_domain_mapping_tags_mapping".to_string()));
        assert!(!index_names.contains(&"idx_domain_mappings_domain".to_string()));
        assert!(index_names.contains(&"idx_totp_secrets_entry_id".to_string()));
        // v3 indexes must be present for new vaults too
        assert!(index_names.contains(&"idx_entries_modified_at".to_string()));
        assert!(index_names.contains(&"idx_entries_created_at".to_string()));
        // v4 index must be present for new vaults too
        assert!(index_names.contains(&"idx_entries_credential_type".to_string()));
        // v5 registry indexes must be present for new vaults too
        assert!(index_names.contains(&"idx_entity_memberships_entity_id".to_string()));
        assert!(index_names.contains(&"idx_secret_equality_index_updated".to_string()));

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
        // WBS-409 (TD-ROB-02): the entries echo trigger must NEVER come
        // back — it rewrote remote applies behind the apply's back
        // ('synced' -> 'pending', modified_at clobbered to apply-time
        // feeding an LWW see-saw, and the applied sync_version corrupted
        // to OLD+1 whenever the local row was >1 version behind).
        assert!(!trigger_names.contains(&"update_entry_modified_timestamp".to_string()));
    }

    #[test]
    fn newer_db_version_fails_closed() {
        // WBS-315 / SR-CRYPTO-005: a vault whose schema version is NEWER than
        // this build must be refused with the specific typed compatibility
        // error — never opened, never migrated backward, never probed.
        // (Supersedes the pre-WBS-315 `newer_db_version_does_not_error`,
        // which pinned the old warn-and-proceed behavior.) The version is
        // expressed RELATIVE to CURRENT_SCHEMA_VERSION so a routine bump by
        // another workstream does not require edits here.
        let db = Database::in_memory().unwrap();
        db.initialize_schema().unwrap();

        let future = CURRENT_SCHEMA_VERSION + 1;
        db.conn()
            .execute(
                "INSERT INTO db_metadata (id, version, kdf_params, wrapped_dek, dek_nonce, created_at, last_modified)
                 VALUES (1, ?1, X'00', X'00', X'00', 0, 0)",
                rusqlite::params![future],
            )
            .unwrap();

        match db.validate_schema_version() {
            Err(PasswordManagerError::Database(DatabaseError::UnsupportedFutureSchema {
                found,
                supported,
            })) => {
                assert_eq!(found, future);
                assert_eq!(supported, CURRENT_SCHEMA_VERSION);
            }
            other => panic!(
                "future-version vault must fail closed with UnsupportedFutureSchema, got {other:?}"
            ),
        }
    }

    #[test]
    fn newer_version_gate_runs_before_any_entry_table_read() {
        // Ordering proof for WBS-315: the version check must precede ANY
        // entry/metadata-content read. With the version set to a future
        // value and the entries table ABSENT (here: renamed away), a
        // fail-closed open must surface the TYPED version error — a Sqlite
        // "no such table" error would mean the open proceeded past the
        // version gate and started touching other tables.
        let db = Database::in_memory().unwrap();
        db.initialize_schema().unwrap();
        db.conn().execute("DROP TABLE entries", []).unwrap();
        let future = CURRENT_SCHEMA_VERSION + 1;
        db.conn()
            .execute(
                "INSERT INTO db_metadata (id, version, kdf_params, wrapped_dek, dek_nonce, created_at, last_modified)
                 VALUES (1, ?1, X'00', X'00', X'00', 0, 0)",
                rusqlite::params![future],
            )
            .unwrap();

        match db.validate_schema_version() {
            Err(PasswordManagerError::Database(DatabaseError::UnsupportedFutureSchema {
                ..
            })) => {}
            other => panic!("version gate must fire before any other table access, got {other:?}"),
        }
    }

    #[test]
    fn newer_format_version_fails_closed() {
        // WBS-406 / SR-CRYPTO-005: a vault whose envelope format version is
        // NEWER than this build's activated format must be refused with the
        // specific typed compatibility error — the downgrade-block twin of
        // `newer_db_version_fails_closed`. Expressed RELATIVE to
        // CURRENT_VAULT_FORMAT_VERSION so an activation-level bump by
        // another workstream does not require edits here.
        let db = Database::in_memory().unwrap();
        db.initialize_schema().unwrap();

        let future = CURRENT_VAULT_FORMAT_VERSION + 1;
        db.conn()
            .execute(
                "INSERT INTO db_metadata (id, version, kdf_params, wrapped_dek, dek_nonce, created_at, last_modified, format_version)
                 VALUES (1, ?1, X'00', X'00', X'00', 0, 0, ?2)",
                rusqlite::params![CURRENT_SCHEMA_VERSION, future],
            )
            .unwrap();

        match db.validate_schema_version() {
            Err(PasswordManagerError::Database(DatabaseError::UnsupportedFutureFormat {
                found,
                supported,
            })) => {
                assert_eq!(found, future);
                assert_eq!(supported, CURRENT_VAULT_FORMAT_VERSION);
            }
            other => panic!(
                "future-format vault must fail closed with UnsupportedFutureFormat, got {other:?}"
            ),
        }
    }

    #[test]
    fn format_gate_runs_before_the_schema_version_read() {
        // Ordering proof for WBS-406: the format gate precedes even the
        // schema version read. With the entries table ABSENT (renamed away)
        // and a future format_version, the open must surface the TYPED
        // FORMAT error — a Sqlite error of any other kind would mean the
        // open proceeded past the format gate.
        let db = Database::in_memory().unwrap();
        db.initialize_schema().unwrap();
        db.conn().execute("DROP TABLE entries", []).unwrap();
        db.conn()
            .execute(
                "INSERT INTO db_metadata (id, version, kdf_params, wrapped_dek, dek_nonce, created_at, last_modified, format_version)
                 VALUES (1, ?1, X'00', X'00', X'00', 0, 0, ?2)",
                rusqlite::params![CURRENT_SCHEMA_VERSION, CURRENT_VAULT_FORMAT_VERSION + 1],
            )
            .unwrap();

        match db.validate_schema_version() {
            Err(PasswordManagerError::Database(DatabaseError::UnsupportedFutureFormat {
                ..
            })) => {}
            other => panic!("format gate must fire before any other access, got {other:?}"),
        }
    }

    #[test]
    fn legacy_and_activated_format_versions_validate_cleanly() {
        // Positive control for the downgrade-block flip: DEFAULT-omitted
        // (legacy write path), explicit 1 (migrated, not yet activated),
        // and explicit 2 (activated) must ALL keep validating — the gate
        // refuses only genuinely newer formats and never locks out vaults
        // this build understands.
        for format_version in [
            Option::<i64>::None,
            Some(1),
            Some(CURRENT_VAULT_FORMAT_VERSION),
        ] {
            let db = Database::in_memory().unwrap();
            db.initialize_schema().unwrap();
            db.conn()
                .execute(
                    "INSERT INTO db_metadata (id, version, kdf_params, wrapped_dek, dek_nonce, created_at, last_modified, format_version)
                     VALUES (1, ?1, X'00', X'00', X'00', 0, 0, COALESCE(?2, 1))",
                    rusqlite::params![CURRENT_SCHEMA_VERSION, format_version],
                )
                .unwrap();
            db.validate_schema_version()
                .unwrap_or_else(|e| panic!("format {format_version:?} must validate, got {e}"));
        }
    }

    #[test]
    fn absent_format_version_column_reads_as_legacy() {
        // A raw pre-v6 schema has no format_version column at all; the
        // gate must treat that as legacy format 1 (never a Sqlite error,
        // which would brick every v1-v5 vault at open). The full v1
        // schema is shared with the WBS-407 fixture builder.
        let db = Database::in_memory().unwrap();
        db.conn()
            .execute_batch(crate::database::fixtures::V1_SCHEMA_SQL)
            .unwrap();
        db.conn()
            .execute(
                "INSERT INTO db_metadata (id, version, kdf_params, wrapped_dek, dek_nonce, created_at, last_modified)
                 VALUES (1, 1, X'00', X'00', X'00', 0, 0)",
                [],
            )
            .unwrap();

        assert_eq!(db.stored_format_version().unwrap(), 1);
        // The full validate path migrates and still succeeds.
        db.validate_schema_version().unwrap();
    }

    #[test]
    fn current_schema_version_validates_cleanly() {
        // Positive control for the fail-closed flip: a CURRENT-version vault
        // must keep validating without error (the flip must never lock out
        // vaults this build fully understands).
        let db = Database::in_memory().unwrap();
        db.initialize_schema().unwrap();
        db.conn()
            .execute(
                "INSERT INTO db_metadata (id, version, kdf_params, wrapped_dek, dek_nonce, created_at, last_modified)
                 VALUES (1, ?1, X'00', X'00', X'00', 0, 0)",
                rusqlite::params![CURRENT_SCHEMA_VERSION],
            )
            .unwrap();

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
