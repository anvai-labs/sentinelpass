//! Schema fixtures for every released schema version (WBS-407, TV-005 /
//! ADR-005 rev 3).
//!
//! A builder that constructs one vault FILE per released schema version
//! (v1..=[`super::schema::CURRENT_SCHEMA_VERSION`]) PROGRAMMATICALLY from
//! the ACTUAL schema definitions — the v1 base DDL the migration tests
//! have always used as the canonical pre-sync shape, advanced by the REAL
//! migration ladder (`super::migrations::*`) — never the drifted
//! `migrations/v1_initial.sql` labels.
//!
//! Fixtures carry REAL crypto material (one shared key hierarchy: the
//! fixtures are independent vault FILES, not independent keys — one
//! Argon2 initialization for the whole set) and REAL encrypted content
//! (an entry with all five fields, an SSH private key, a TOTP secret, a
//! plaintext domain mapping) inserted at the v1 column set BEFORE the
//! ladder runs, so every version's fixture flows through the same data
//! backfills (sync_id assignment, wrapped-DEK re-serialization, slot
//! minting) a real legacy vault experienced.
//!
//! Crypto-blob anachronism (deliberate, documented): the `db_metadata`
//! key-material columns are written as current-shape bincode (the
//! `WrappedKey` struct includes `epoch_bound = false`, which is exactly
//! the semantic content of every pre-epoch legacy blob), not the byte-
//! exact 3-field legacy encoding. Every decoder is dual-read and treats
//! the two as identical; fixture fidelity is about the SCHEMA ladder,
//! which is byte-exact.
//!
//! If `CURRENT_SCHEMA_VERSION` is bumped, the ladder below MUST be
//! extended in the same commit — the version assertion on each fixture
//! fails otherwise, so the drift is caught by the test run, not by a
//! release.

use super::migrations::{
    migrate_v1_to_v2, migrate_v2_to_v3, migrate_v3_to_v4, migrate_v4_to_v5, migrate_v5_to_v6,
    migrate_v6_to_v7, migrate_v7_to_v8,
};
use super::schema::CURRENT_SCHEMA_VERSION;
use crate::crypto::cipher::{encrypt_entry, encrypt_string, DataEncryptionKey};
use crate::crypto::{KdfParams, KeyHierarchy, WrappedKey};
use std::path::PathBuf;

/// Raw v1 schema DDL (no sync columns, no registry, no key slots) — the
/// canonical pre-sync shape shared with the migration tests.
pub(crate) const V1_SCHEMA_SQL: &str = "CREATE TABLE db_metadata (
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

/// The plaintext content every fixture carries (the read-back assertions
/// in the tests below pin these strings end to end).
pub(crate) struct FixtureContent {
    pub entry_title: &'static str,
    pub entry_username: &'static str,
    pub entry_password: &'static str,
    pub entry_url: &'static str,
    pub entry_notes: &'static str,
    pub ssh_public_key: &'static str,
    pub ssh_private_pem: &'static str,
    /// Already NORMALIZED base32 — what v1 blobs store.
    pub totp_secret: &'static str,
    pub domain: &'static str,
}

pub(crate) const FIXTURE_CONTENT: FixtureContent = FixtureContent {
    entry_title: "Fixture Site",
    entry_username: "fixture@example.com",
    entry_password: "fixture-pass-31337",
    entry_url: "https://fixture.example.com",
    entry_notes: "fixture notes with ünïcode",
    ssh_public_key: "ssh-ed25519 AAAAC3NZAfixture",
    ssh_private_pem: "-----BEGIN OPENSSH PRIVATE KEY-----FIXTURE-----END",
    totp_secret: "JBSWY3DPEHPK3PXP",
    domain: "fixture.example.com",
};

/// One shared key hierarchy: fixtures are independent FILES, not
/// independent keys.
pub(crate) struct FixtureMaterial {
    pub password: Vec<u8>,
    pub kdf_params: KdfParams,
    pub wrapped_dek: WrappedKey,
    pub dek: DataEncryptionKey,
}

/// One built fixture: a vault file whose `db_metadata.version` is exactly
/// `version`, with real encrypted content at the v1 column set.
pub(crate) struct SchemaFixture {
    pub version: i32,
    pub path: PathBuf,
}

/// The whole set plus the material to unlock it. `TempDir` owns file
/// lifetimes — keep it alive while the fixtures are in use.
pub(crate) struct SchemaFixtureSet {
    pub _dir: tempfile::TempDir,
    pub material: FixtureMaterial,
    pub fixtures: Vec<SchemaFixture>,
}

/// The ACTUAL schema ladder, one step per released version. Extend in the
/// same commit as any `CURRENT_SCHEMA_VERSION` bump (module docs).
fn migrate_ladder_to(conn: &rusqlite::Connection, target: i32) {
    assert!(
        (1..=CURRENT_SCHEMA_VERSION).contains(&target),
        "fixture target version {target} is outside the released range"
    );
    if target >= 2 {
        migrate_v1_to_v2(conn).unwrap();
    }
    if target >= 3 {
        migrate_v2_to_v3(conn).unwrap();
    }
    if target >= 4 {
        migrate_v3_to_v4(conn).unwrap();
    }
    if target >= 5 {
        migrate_v4_to_v5(conn).unwrap();
    }
    if target >= 6 {
        migrate_v5_to_v6(conn).unwrap();
    }
    if target >= 7 {
        migrate_v6_to_v7(conn).unwrap();
    }
    if target >= 8 {
        migrate_v7_to_v8(conn).unwrap();
    }
    let version: i32 = conn
        .query_row("SELECT version FROM db_metadata WHERE id = 1", [], |r| {
            r.get(0)
        })
        .unwrap();
    assert_eq!(
        version, target,
        "the ladder must land exactly on the fixture's target version — \
         extend migrate_ladder_to when CURRENT_SCHEMA_VERSION bumps"
    );
}

/// Build one fixture FILE at `target` with the shared crypto material and
/// the standard content rows (inserted at the v1 column set, BEFORE the
/// ladder, so migrations backfill real data).
fn build_fixture(dir: &std::path::Path, target: i32, material: &FixtureMaterial) -> SchemaFixture {
    let path = dir.join(format!("schema-v{target}.db"));
    let conn = rusqlite::Connection::open(&path).unwrap();
    conn.execute("PRAGMA foreign_keys = ON", []).unwrap();
    conn.execute_batch(V1_SCHEMA_SQL).unwrap();

    // db_metadata row at the v1 column set, REAL key material (legacy
    // bincode encoding — what every pre-WBS-305 vault carries; the
    // current-shape struct with epoch_bound=false is semantically the
    // legacy blob).
    conn.execute(
        "INSERT INTO db_metadata (id, version, kdf_params, wrapped_dek, dek_nonce, created_at, last_modified)
         VALUES (1, 1, ?1, ?2, ?3, 1700000000, 1700000000)",
        rusqlite::params![
            bincode::serialize(&material.kdf_params).unwrap(),
            bincode::serialize(&material.wrapped_dek).unwrap(),
            bincode::serialize(&material.wrapped_dek.nonce).unwrap(),
        ],
    )
    .unwrap();

    // Content rows at the v1 column set — real encrypted blobs, so
    // "current code reads it" is a crypto assertion, not just a schema
    // one. Only v1 columns are named: the INSERT is valid at EVERY
    // schema version (later versions add columns with defaults).
    let c = &FIXTURE_CONTENT;
    let title = encrypt_string(&material.dek, c.entry_title).unwrap();
    let username = encrypt_string(&material.dek, c.entry_username).unwrap();
    let password = encrypt_string(&material.dek, c.entry_password).unwrap();
    let url = encrypt_string(&material.dek, c.entry_url).unwrap();
    let notes = encrypt_string(&material.dek, c.entry_notes).unwrap();
    conn.execute(
        "INSERT INTO entries (vault_id, title, username, password, url, notes,
            entry_nonce, auth_tag, created_at, modified_at, favorite)
         VALUES (1, ?1, ?2, ?3, ?4, ?5, ?6, ?7, 1700000000, 1700000000, 0)",
        rusqlite::params![
            bincode::serialize(&title).unwrap(),
            bincode::serialize(&username).unwrap(),
            bincode::serialize(&password).unwrap(),
            bincode::serialize(&url).unwrap(),
            bincode::serialize(&notes).unwrap(),
            bincode::serialize(&title.nonce).unwrap(),
            bincode::serialize(&title.auth_tag).unwrap(),
        ],
    )
    .unwrap();

    let ssh = encrypt_entry(&material.dek, c.ssh_private_pem.as_bytes()).unwrap();
    conn.execute(
        "INSERT INTO ssh_keys (name, comment, key_type, key_size, public_key,
            private_key_encrypted, nonce, auth_tag, fingerprint, created_at, modified_at)
         VALUES ('deploy-key', NULL, 'ED25519', NULL, ?1, ?2, ?3, ?4, 'SHA256:fixturefp',
                 1700000000, 1700000000)",
        rusqlite::params![
            c.ssh_public_key,
            ssh.ciphertext,
            ssh.nonce.to_vec(),
            ssh.auth_tag.to_vec(),
        ],
    )
    .unwrap();

    let totp = encrypt_string(&material.dek, c.totp_secret).unwrap();
    conn.execute(
        "INSERT INTO totp_secrets (entry_id, secret_encrypted, nonce, auth_tag,
            algorithm, digits, period, created_at)
         VALUES (1, ?1, ?2, ?3, 'SHA1', 6, 30, 1700000000)",
        rusqlite::params![totp.ciphertext, totp.nonce.to_vec(), totp.auth_tag.to_vec(),],
    )
    .unwrap();

    conn.execute(
        "INSERT INTO domain_mappings (entry_id, domain, is_primary) VALUES (1, ?1, 1)",
        [c.domain],
    )
    .unwrap();

    // The ACTUAL migration ladder, from the pristine v1 state to target.
    migrate_ladder_to(&conn, target);
    conn.close().unwrap();
    SchemaFixture {
        version: target,
        path,
    }
}

/// Build the full set: one file per released schema version, all from one
/// key hierarchy.
pub(crate) fn build_fixture_set() -> SchemaFixtureSet {
    let dir = tempfile::TempDir::new().unwrap();
    let password = b"fixture-master-password".to_vec();

    // ONE real key hierarchy for the whole set (module docs).
    let mut hierarchy = KeyHierarchy::new();
    let (kdf_params, wrapped_dek) = hierarchy.initialize_vault(&password).unwrap();
    let dek = hierarchy.dek().unwrap().clone();
    let material = FixtureMaterial {
        password,
        kdf_params,
        wrapped_dek,
        dek,
    };

    let fixtures = (1..=CURRENT_SCHEMA_VERSION)
        .map(|version| build_fixture(dir.path(), version, &material))
        .collect();
    SchemaFixtureSet {
        _dir: dir,
        material,
        fixtures,
    }
}

// ---------------------------------------------------------------------------
// Tests: every fixture opens under its schema, migrates to current, and is
// fully readable (and fully verifiable + activatable) by current code.
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;
    use crate::database::schema::Database;
    use crate::vault::VaultManager;

    /// Shape self-check: each fixture reports EXACTLY its own version and
    /// carries the structural markers of that release (and none of the
    /// later ones). This is the "regenerated from actual schema
    /// definitions" guarantee, pinned per version.
    #[test]
    fn fixtures_carry_the_exact_schema_of_each_released_version() {
        let set = build_fixture_set();
        assert_eq!(
            set.fixtures.len(),
            CURRENT_SCHEMA_VERSION as usize,
            "one fixture per released version"
        );

        for fixture in &set.fixtures {
            let db = Database::open(&fixture.path).unwrap();
            let conn = db.conn();
            let version: i32 = conn
                .query_row("SELECT version FROM db_metadata WHERE id = 1", [], |r| {
                    r.get(0)
                })
                .unwrap();
            assert_eq!(version, fixture.version, "fixture v{}", fixture.version);

            let has_column = |table: &str, column: &str| -> bool {
                conn.query_row(
                    "SELECT EXISTS(SELECT 1 FROM pragma_table_info(?1) WHERE name = ?2)",
                    rusqlite::params![table, column],
                    |r| r.get(0),
                )
                .unwrap()
            };
            let has_object = |obj_type: &str, name: &str| -> bool {
                conn.query_row(
                    "SELECT EXISTS(SELECT 1 FROM sqlite_master WHERE type = ?1 AND name = ?2)",
                    rusqlite::params![obj_type, name],
                    |r| r.get(0),
                )
                .unwrap()
            };

            // v1 base shape never goes away.
            for table in [
                "db_metadata",
                "entries",
                "domain_mappings",
                "failed_attempts",
                "ssh_keys",
                "totp_secrets",
            ] {
                assert!(
                    has_object("table", table),
                    "v{} must have {table}",
                    fixture.version
                );
            }
            assert_eq!(
                has_column("entries", "sync_id"),
                fixture.version >= 2,
                "v{}: sync_id arrives in v2",
                fixture.version
            );
            assert_eq!(
                has_column("entries", "credential_type"),
                fixture.version >= 4,
                "v{}: credential_type arrives in v4",
                fixture.version
            );
            assert_eq!(
                has_object("table", "registry_state"),
                fixture.version >= 5,
                "v{}: registry arrives in v5",
                fixture.version
            );
            if fixture.version >= 6 {
                let (vault_uuid, format_version): (Option<String>, i64) = conn
                    .query_row(
                        "SELECT vault_uuid, format_version FROM db_metadata WHERE id = 1",
                        [],
                        |r| Ok((r.get(0)?, r.get(1)?)),
                    )
                    .unwrap();
                assert!(
                    uuid::Uuid::parse_str(&vault_uuid.unwrap()).is_ok(),
                    "v{}: durable vault identity present",
                    fixture.version
                );
                assert_eq!(
                    format_version, 1,
                    "v{}: format starts legacy — activation is post-unlock (WBS-406)",
                    fixture.version
                );
            }
            assert_eq!(
                has_object("table", "key_slots"),
                fixture.version >= 7,
                "v{}: key-slot registry arrives in v7",
                fixture.version
            );
            assert_eq!(
                has_column("domain_mappings", "domain_enc"),
                fixture.version >= 8,
                "v{}: sealed-domain column arrives in v8",
                fixture.version
            );
            if fixture.version >= 8 {
                assert!(
                    !has_object("index", "idx_domain_mappings_domain"),
                    "v8 drops the plaintext domain index"
                );
            }
        }

        // Content flowed through the ladder intact: every fixture still
        // holds exactly one of each object.
        for fixture in &set.fixtures {
            let db = Database::open(&fixture.path).unwrap();
            let counts: (i64, i64, i64, i64) = db
                .conn()
                .query_row(
                    "SELECT (SELECT COUNT(*) FROM entries),
                            (SELECT COUNT(*) FROM ssh_keys),
                            (SELECT COUNT(*) FROM totp_secrets),
                            (SELECT COUNT(*) FROM domain_mappings)",
                    [],
                    |r| Ok((r.get(0)?, r.get(1)?, r.get(2)?, r.get(3)?)),
                )
                .unwrap();
            assert_eq!(counts, (1, 1, 1, 1), "v{} content intact", fixture.version);
        }
    }

    /// THE WBS-407 ladder test: every fixture migrates to CURRENT through
    /// the production open path, and current code FULLY reads it —
    /// entries (all five fields), SSH private key, TOTP code, suffix-chain
    /// domain lookup — after the post-unlock sweeps have converted every
    /// blob. The WBS-405 verification pass must report the migrated vault
    /// clean, and the WBS-406 open hook must have activated it.
    #[test]
    fn every_fixture_migrates_to_current_and_is_fully_read_by_current_code() {
        let set = build_fixture_set();
        let c = &FIXTURE_CONTENT;

        for fixture in &set.fixtures {
            let context = format!("fixture v{}", fixture.version);

            // (1) The production open path migrates and unlocks.
            let vault = VaultManager::open(&fixture.path, &set.material.password)
                .unwrap_or_else(|e| panic!("{context}: open failed: {e}"));

            // (2) Entry: all five fields decrypt to the fixture plaintext.
            let entries = vault
                .list_entries()
                .unwrap_or_else(|e| panic!("{context}: list failed: {e}"));
            assert_eq!(entries.len(), 1, "{context}");
            assert_eq!(entries[0].title, c.entry_title, "{context}");
            let entry = vault.get_entry(entries[0].entry_id).unwrap();
            assert_eq!(entry.username, c.entry_username, "{context}");
            assert_eq!(entry.password.as_str(), c.entry_password, "{context}");
            assert_eq!(entry.url.as_deref(), Some(c.entry_url), "{context}");
            assert_eq!(entry.notes.as_deref(), Some(c.entry_notes), "{context}");

            // (3) SSH private key decrypts (v2 envelope after the sweep).
            let keys = vault.list_ssh_keys().unwrap();
            assert_eq!(keys.len(), 1, "{context}");
            assert_eq!(
                vault.export_ssh_private_key(keys[0].key_id).unwrap(),
                c.ssh_private_pem,
                "{context}"
            );

            // (4) TOTP generates (secret decrypted from the swept blob).
            let code = vault.generate_totp_code(entries[0].entry_id).unwrap();
            assert_eq!(code.code.len(), 6, "{context}");

            // (5) Domain lookup works through the sealed + tagged mapping,
            // both exact and suffix-chain.
            let exact = vault.find_entries_by_domain(c.domain).unwrap();
            assert_eq!(exact.len(), 1, "{context}: exact domain lookup");
            assert_eq!(exact[0].entry_id, Some(entries[0].entry_id), "{context}");
            let child = format!("sub.{}", c.domain);
            let chained = vault.find_entries_by_domain(&child).unwrap();
            assert_eq!(chained.len(), 1, "{context}: suffix-chain lookup");

            // (6) WBS-405: the migrated vault verifies CLEAN — every
            // envelope + relation opens under its identity.
            let report = vault
                .verify_vault_envelopes()
                .unwrap_or_else(|e| panic!("{context}: verify failed: {e}"));
            assert!(
                report.is_clean(),
                "{context}: verification must be clean, got {report:?}"
            );
            assert_eq!(report.entry_fields_verified, 5, "{context}");
            assert_eq!(report.ssh_keys_verified, 1, "{context}");
            assert_eq!(report.totp_secrets_verified, 1, "{context}");
            assert_eq!(report.domain_mappings_verified, 1, "{context}");

            // (7) WBS-406: the open hook activated the migrated vault.
            assert!(
                vault.is_v2_format_activated().unwrap(),
                "{context}: open hook must activate the fully-converted fixture"
            );
        }
    }

    /// Negative: the fixtures are not just "some schema" — a fixture's
    /// PRE-migration state must carry the version-partial shape (e.g. a
    /// v6 fixture has no key_slots table yet), proving the ladder stops
    /// exactly where asked instead of running to current.
    #[test]
    fn fixture_ladder_stops_at_the_requested_version() {
        let set = build_fixture_set();
        // Pick the mid-ladder fixtures whose marker tables prove the stop.
        for (version, marker_table, must_exist) in [
            (6_i32, "key_slots", false),
            (7, "key_slots", true),
            (6, "registry_state", true),
            (1, "entries", true),
        ] {
            let fixture = set
                .fixtures
                .iter()
                .find(|f| f.version == version)
                .unwrap_or_else(|| panic!("fixture v{version} must exist"));
            let db = Database::open(&fixture.path).unwrap();
            let exists: bool = db
                .conn()
                .query_row(
                    "SELECT EXISTS(SELECT 1 FROM sqlite_master WHERE type='table' AND name=?1)",
                    [marker_table],
                    |r| r.get(0),
                )
                .unwrap();
            assert_eq!(
                exists, must_exist,
                "v{version} fixture: {marker_table} presence"
            );
        }
    }
}
