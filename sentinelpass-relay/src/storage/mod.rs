//! SQLite storage backend for the relay.

pub mod models;

use crate::error::RelayError;
use rusqlite::Connection;
use std::path::Path;
use std::sync::{Arc, Mutex};

/// Thread-safe relay storage.
#[derive(Clone)]
pub struct RelayStorage {
    conn: Arc<Mutex<Connection>>,
}

impl RelayStorage {
    /// Open a SQLite database at the given path and initialize the schema.
    pub fn open(path: &Path) -> Result<Self, anyhow::Error> {
        let conn = Connection::open(path)?;
        conn.execute("PRAGMA foreign_keys = ON", [])?;
        conn.execute("PRAGMA journal_mode = WAL", [])?;

        let storage = Self {
            conn: Arc::new(Mutex::new(conn)),
        };
        storage.initialize_schema()?;
        Ok(storage)
    }

    /// Create an in-memory SQLite database for testing.
    #[allow(dead_code)]
    pub fn in_memory() -> Result<Self, anyhow::Error> {
        let conn = Connection::open_in_memory()?;
        conn.execute("PRAGMA foreign_keys = ON", [])?;

        let storage = Self {
            conn: Arc::new(Mutex::new(conn)),
        };
        storage.initialize_schema()?;
        Ok(storage)
    }

    fn initialize_schema(&self) -> Result<(), anyhow::Error> {
        let conn = self.conn.lock().map_err(|e| anyhow::anyhow!("{}", e))?;
        conn.execute_batch(
            "CREATE TABLE IF NOT EXISTS vaults (
                vault_id TEXT PRIMARY KEY,
                created_at INTEGER NOT NULL,
                entry_count INTEGER NOT NULL DEFAULT 0
            );

            CREATE TABLE IF NOT EXISTS devices (
                device_id TEXT PRIMARY KEY,
                vault_id TEXT NOT NULL,
                device_name TEXT NOT NULL,
                device_type TEXT NOT NULL,
                public_key BLOB NOT NULL,
                registered_at INTEGER NOT NULL,
                revoked INTEGER NOT NULL DEFAULT 0,
                revoked_at INTEGER,
                FOREIGN KEY (vault_id) REFERENCES vaults(vault_id)
            );

            CREATE TABLE IF NOT EXISTS sync_entries (
                sync_id TEXT NOT NULL,
                vault_id TEXT NOT NULL,
                entry_type TEXT NOT NULL,
                sync_version INTEGER NOT NULL,
                modified_at INTEGER NOT NULL,
                encrypted_payload BLOB NOT NULL,
                is_tombstone INTEGER NOT NULL DEFAULT 0,
                origin_device_id TEXT NOT NULL,
                server_sequence INTEGER NOT NULL,
                received_at INTEGER NOT NULL,
                PRIMARY KEY (sync_id, vault_id)
            );

            CREATE TABLE IF NOT EXISTS sequence_counters (
                vault_id TEXT PRIMARY KEY,
                current_sequence INTEGER NOT NULL DEFAULT 0
            );

            CREATE TABLE IF NOT EXISTS device_sequences (
                device_id TEXT PRIMARY KEY,
                last_sequence INTEGER NOT NULL DEFAULT 0
            );

            CREATE TABLE IF NOT EXISTS pairing_bootstraps (
                pairing_token TEXT PRIMARY KEY,
                vault_id TEXT NOT NULL,
                encrypted_bootstrap BLOB NOT NULL,
                pairing_salt BLOB NOT NULL,
                expires_at INTEGER NOT NULL,
                consumed INTEGER NOT NULL DEFAULT 0
            );

            CREATE TABLE IF NOT EXISTS pairing_registration_proofs (
                proof_hash TEXT PRIMARY KEY,
                pairing_token_hash TEXT NOT NULL,
                vault_id TEXT NOT NULL,
                expires_at INTEGER NOT NULL,
                consumed INTEGER NOT NULL DEFAULT 0
            );

            CREATE TABLE IF NOT EXISTS pairing_fetch_attempts (
                token_hash TEXT PRIMARY KEY,
                attempts INTEGER NOT NULL DEFAULT 0,
                first_attempt_at INTEGER NOT NULL,
                last_attempt_at INTEGER NOT NULL,
                blocked_until INTEGER NOT NULL DEFAULT 0
            );

            CREATE TABLE IF NOT EXISTS seen_nonces (
                nonce TEXT PRIMARY KEY,
                device_id TEXT NOT NULL,
                seen_at INTEGER NOT NULL
            );

            -- v2 protocol (ADR-006): current object state, CAS-guarded.
            -- Additive/parallel to the v1 `sync_entries` table; v1 rows are
            -- never migrated or rewritten (v1 retirement is client-side
            -- abandonment).
            CREATE TABLE IF NOT EXISTS sync_entries_v2 (
                vault_id TEXT NOT NULL,
                object_id TEXT NOT NULL,
                entry_type TEXT NOT NULL,
                current_version INTEGER NOT NULL,
                key_epoch INTEGER NOT NULL,
                is_tombstone INTEGER NOT NULL DEFAULT 0,
                metadata_mac TEXT NOT NULL,
                encrypted_payload BLOB NOT NULL,
                origin_device_id TEXT NOT NULL,
                server_sequence INTEGER NOT NULL,
                received_at INTEGER NOT NULL,
                PRIMARY KEY (vault_id, object_id)
            );

            -- v2 protocol: append-only vault mutation log (pull source).
            CREATE TABLE IF NOT EXISTS sync_mutations_v2 (
                vault_id TEXT NOT NULL,
                server_sequence INTEGER NOT NULL,
                mutation_id TEXT NOT NULL,
                object_id TEXT NOT NULL,
                entry_type TEXT NOT NULL,
                expected_version INTEGER NOT NULL,
                resulting_version INTEGER NOT NULL,
                key_epoch INTEGER NOT NULL,
                origin_device_id TEXT NOT NULL,
                is_tombstone INTEGER NOT NULL DEFAULT 0,
                metadata_mac TEXT NOT NULL,
                encrypted_payload BLOB NOT NULL,
                received_at INTEGER NOT NULL,
                PRIMARY KEY (vault_id, server_sequence)
            );

            -- v2 protocol: durable per-mutation results. The ack SURVIVES the
            -- response: a duplicate request returns the stored original
            -- result (ADR-006). Bounded: aged out by
            -- `mutation_result_ttl_secs` and capped per device by
            -- `max_mutation_results_per_device`; after expiry a duplicate is
            -- re-evaluated by the CAS guard, which REJECTS it rather than
            -- replaying it.
            CREATE TABLE IF NOT EXISTS mutation_results (
                mutation_id TEXT NOT NULL,
                vault_id TEXT NOT NULL,
                device_id TEXT NOT NULL,
                object_id TEXT NOT NULL,
                outcome TEXT NOT NULL CHECK (outcome IN ('applied', 'rejected')),
                rejection_reason TEXT,
                resulting_version INTEGER,
                server_sequence INTEGER,
                created_at INTEGER NOT NULL,
                PRIMARY KEY (mutation_id, device_id, vault_id)
            );

            -- v2 protocol: vault key-epoch high-water (ADR-004/006). Advanced
            -- only forward, by mutations carrying a higher epoch.
            CREATE TABLE IF NOT EXISTS vault_epochs (
                vault_id TEXT PRIMARY KEY,
                key_epoch INTEGER NOT NULL DEFAULT 0,
                updated_at INTEGER NOT NULL
            );

            CREATE INDEX IF NOT EXISTS idx_sync_entries_v2_vault_seq
                ON sync_entries_v2(vault_id, server_sequence);
            CREATE INDEX IF NOT EXISTS idx_sync_mutations_v2_object
                ON sync_mutations_v2(vault_id, object_id, resulting_version);
            CREATE INDEX IF NOT EXISTS idx_mutation_results_age
                ON mutation_results(created_at);
            CREATE INDEX IF NOT EXISTS idx_mutation_results_device
                ON mutation_results(device_id, created_at);

            CREATE INDEX IF NOT EXISTS idx_sync_entries_vault_seq
                ON sync_entries(vault_id, server_sequence);
            CREATE INDEX IF NOT EXISTS idx_devices_vault
                ON devices(vault_id);
            CREATE INDEX IF NOT EXISTS idx_seen_nonces_seen_at
                ON seen_nonces(seen_at);
            CREATE INDEX IF NOT EXISTS idx_pairing_expires
                ON pairing_bootstraps(expires_at);
            CREATE INDEX IF NOT EXISTS idx_pairing_registration_proofs_expires
                ON pairing_registration_proofs(expires_at);
            CREATE INDEX IF NOT EXISTS idx_pairing_registration_proofs_vault
                ON pairing_registration_proofs(vault_id);
            CREATE INDEX IF NOT EXISTS idx_pairing_fetch_attempts_last_attempt
                ON pairing_fetch_attempts(last_attempt_at);
            CREATE INDEX IF NOT EXISTS idx_pairing_fetch_attempts_blocked_until
                ON pairing_fetch_attempts(blocked_until);",
        )?;
        Ok(())
    }

    /// Acquire a lock on the database connection.
    pub fn conn(&self) -> Result<std::sync::MutexGuard<'_, Connection>, RelayError> {
        self.conn
            .lock()
            .map_err(|e| RelayError::Internal(format!("Lock error: {}", e)))
    }
}
