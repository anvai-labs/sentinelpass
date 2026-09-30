//! Authenticated entry receipts outside SQLite. A valid GCM blob is not
//! necessarily the latest blob. Receipts bind all columns (including NULLs)
//! and the complete entry and domain-mapping sets to the last acknowledged
//! transaction, including tombstones and mapping ownership.
//!
//! The two-state journal is durable BEFORE SQLite commits; recovery accepts
//! only the complete old or complete new snapshot. Successful writes finalize
//! the new snapshot before returning. Coordinated rollback of BOTH artifacts
//! remains outside this local guard's threat model; an external monotonic
//! service or hardware anchor is needed against that adversary.
use crate::crypto::DataEncryptionKey;
use crate::database::{RawEntryRow, SqliteEntryRepository};
use crate::{DatabaseError, PasswordManagerError, Result};
use hmac::{Hmac, Mac};
use rusqlite::{Connection, OptionalExtension, Transaction};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::collections::BTreeMap;
use std::fs::{File, OpenOptions};
use std::io::{Read, Write};
use std::ops::{Deref, DerefMut};
use std::path::{Path, PathBuf};
use zeroize::Zeroizing;

const MARKER: &str = "entry_receipts_v1";
const MAX_BYTES: u64 = 64 * 1024 * 1024;
type Receipts = BTreeMap<String, String>;

#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct State {
    version: u32,
    vault: String,
    stable: Receipts,
    pending: Option<Receipts>,
}

#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct Document {
    state: State,
    mac: String,
    #[serde(default)]
    secondary_mac: Option<String>,
}

fn refusal() -> PasswordManagerError {
    PasswordManagerError::InvalidInput(
        "entry integrity receipt mismatch or missing: possible rollback; use verified backup restore".into(),
    )
}

fn paths(conn: &Connection) -> Option<(PathBuf, PathBuf)> {
    let path = conn.path().filter(|p| !p.is_empty())?;
    Some((
        PathBuf::from(format!("{path}.contents")),
        PathBuf::from(format!("{path}.contents.lock")),
    ))
}

fn key(dek: &DataEncryptionKey) -> Result<Zeroizing<[u8; 32]>> {
    let mut key = Zeroizing::new([0; 32]);
    hkdf::Hkdf::<Sha256>::new(None, dek.as_bytes())
        .expand(b"sentinelpass-entry-receipts-v1", key.as_mut())
        .map_err(|_| refusal())?;
    Ok(key)
}

fn mac(state: &State, key: &[u8]) -> Result<Hmac<Sha256>> {
    let mut mac = Hmac::<Sha256>::new_from_slice(key).map_err(|_| refusal())?;
    mac.update(&serde_json::to_vec(state).map_err(|_| refusal())?);
    Ok(mac)
}

fn load(path: &Path, key: &[u8], vault: &str) -> Result<Option<State>> {
    match std::fs::symlink_metadata(path) {
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => return Ok(None),
        Err(e) => return Err(e.into()),
        Ok(_) => {}
    }
    crate::platform::validate_sensitive_path(path, crate::platform::OwnerOnlyPolicy::Refuse)?;
    let mut bytes = Vec::new();
    File::open(path)?
        .take(MAX_BYTES + 1)
        .read_to_end(&mut bytes)?;
    if bytes.len() as u64 > MAX_BYTES {
        return Err(refusal());
    }
    let doc: Document = serde_json::from_slice(&bytes).map_err(|_| refusal())?;
    let valid = |tag: &str| -> Result<bool> {
        let tag = hex::decode(tag).map_err(|_| refusal())?;
        Ok(mac(&doc.state, key)?.verify_slice(&tag).is_ok())
    };
    if !valid(&doc.mac)?
        && !doc
            .secondary_mac
            .as_deref()
            .map(valid)
            .transpose()?
            .unwrap_or(false)
    {
        return Err(refusal());
    }
    if doc.state.version != 1 || doc.state.vault != vault {
        return Err(refusal());
    }
    Ok(Some(doc.state))
}

fn save(path: &Path, state: &State, key: &[u8]) -> Result<()> {
    save_with_secondary(path, state, key, None)
}

fn save_with_secondary(
    path: &Path,
    state: &State,
    key: &[u8],
    secondary: Option<&[u8]>,
) -> Result<()> {
    let tag = hex::encode(mac(state, key)?.finalize().into_bytes());
    let mut document = serde_json::json!({"state": state, "mac": tag});
    if let Some(key) = secondary {
        document["secondary_mac"] = hex::encode(mac(state, key)?.finalize().into_bytes()).into();
    }
    let bytes = serde_json::to_vec(&document).map_err(|_| refusal())?;
    if bytes.len() as u64 > MAX_BYTES {
        return Err(refusal());
    }
    let tmp = path.with_extension(format!("contents.{}.tmp", uuid::Uuid::new_v4()));
    let result = (|| -> Result<()> {
        let mut options = OpenOptions::new();
        options.write(true).create_new(true);
        #[cfg(unix)]
        {
            use std::os::unix::fs::OpenOptionsExt;
            options.mode(0o600);
        }
        let mut file = options.open(&tmp)?;
        file.write_all(&bytes)?;
        file.sync_all()?;
        std::fs::rename(&tmp, path)?;
        #[cfg(unix)]
        File::open(path.parent().unwrap_or_else(|| Path::new(".")))?.sync_all()?;
        Ok(())
    })();
    if result.is_err() {
        let _ = std::fs::remove_file(tmp);
    }
    result
}

fn acquire(path: &Path) -> Result<File> {
    if path.exists() {
        crate::platform::validate_sensitive_path(path, crate::platform::OwnerOnlyPolicy::Refuse)?;
    }
    let mut options = OpenOptions::new();
    options.read(true).write(true).create(true).truncate(false);
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt;
        options.mode(0o600).custom_flags(libc::O_NOFOLLOW);
    }
    let file = options.open(path)?;
    file.lock()?;
    Ok(file)
}

fn fingerprint(row: &RawEntryRow, is_deleted: bool) -> Result<String> {
    let bytes = serde_json::to_vec(&(
        row.entry_id,
        &row.sync_id,
        &row.credential_type,
        &row.title,
        &row.username,
        &row.password,
        &row.url,
        &row.notes,
        row.created_at,
        row.modified_at,
        row.favorite,
        is_deleted,
    ))
    .map_err(|_| refusal())?;
    Ok(hex::encode(Sha256::digest(bytes)))
}

fn snapshot(conn: &Connection) -> Result<Receipts> {
    let mut stmt = conn.prepare("SELECT entry_id,title,username,password,url,notes,credential_type,entry_nonce,auth_tag,created_at,modified_at,favorite,sync_id,sync_version,is_deleted FROM entries ORDER BY entry_id")
        .map_err(DatabaseError::Sqlite)?;
    let rows = stmt
        .query_map([], |r| {
            Ok((SqliteEntryRepository::parse_row(r)?, r.get::<_, bool>(14)?))
        })
        .map_err(DatabaseError::Sqlite)?;
    let mut receipts: Receipts = rows
        .map(|r| {
            let (r, deleted) = r.map_err(DatabaseError::Sqlite)?;
            Ok((format!("entry:{}", r.entry_id), fingerprint(&r, deleted)?))
        })
        .collect::<Result<_>>()?;
    // Domain identity alone does not authenticate which credential owns it.
    // Bind the relationship and complete mapping set before lookups or sync
    // can turn an attacker-edited entry_id into a credential disclosure.
    let mut stmt = conn.prepare("SELECT mapping_id,entry_id,domain,is_primary,sync_id,domain_enc FROM domain_mappings ORDER BY mapping_id")
        .map_err(DatabaseError::Sqlite)?;
    let rows = stmt
        .query_map([], |r| {
            Ok((
                r.get::<_, i64>(0)?,
                r.get::<_, i64>(1)?,
                r.get::<_, String>(2)?,
                r.get::<_, bool>(3)?,
                r.get::<_, Option<String>>(4)?,
                r.get::<_, Option<Vec<u8>>>(5)?,
            ))
        })
        .map_err(DatabaseError::Sqlite)?;
    for row in rows {
        let row = row.map_err(DatabaseError::Sqlite)?;
        let bytes = serde_json::to_vec(&row).map_err(|_| refusal())?;
        receipts.insert(
            format!("mapping:{}", row.0),
            hex::encode(Sha256::digest(bytes)),
        );
    }
    // Missing tags otherwise suppress candidates before envelope verification
    // can inspect them. Authenticate the index set as well as each mapping.
    let mut stmt = conn.prepare("SELECT tag_id,mapping_id,tag,is_chain_root,equality_key_id FROM domain_mapping_tags ORDER BY tag_id")
        .map_err(DatabaseError::Sqlite)?;
    let rows = stmt
        .query_map([], |r| {
            Ok((
                r.get::<_, i64>(0)?,
                r.get::<_, i64>(1)?,
                r.get::<_, Vec<u8>>(2)?,
                r.get::<_, i64>(3)?,
                r.get::<_, i64>(4)?,
            ))
        })
        .map_err(DatabaseError::Sqlite)?;
    for row in rows {
        let row = row.map_err(DatabaseError::Sqlite)?;
        let bytes = serde_json::to_vec(&row).map_err(|_| refusal())?;
        receipts.insert(
            format!("domain-tag:{}", row.0),
            hex::encode(Sha256::digest(bytes)),
        );
    }
    Ok(receipts)
}

fn vault_id(conn: &Connection) -> Result<String> {
    conn.query_row("SELECT vault_uuid FROM db_metadata WHERE id=1", [], |r| {
        r.get(0)
    })
    .map_err(DatabaseError::Sqlite)
    .map_err(Into::into)
}

fn marked(conn: &Connection) -> Result<bool> {
    let value: Option<String> = conn
        .query_row(
            "SELECT value FROM registry_state WHERE key=?1",
            [MARKER],
            |r| r.get(0),
        )
        .optional()
        .map_err(DatabaseError::Sqlite)?;
    Ok(value.is_some())
}

pub(crate) struct ContentTransaction<'a> {
    tx: Option<Transaction<'a>>,
    guard: Option<(File, PathBuf, State, Zeroizing<[u8; 32]>)>,
}

impl<'a> ContentTransaction<'a> {
    pub(crate) fn begin(conn: &'a Connection, dek: &DataEncryptionKey) -> Result<Self> {
        let location = paths(conn)
            .map(|(path, lock)| acquire(&lock).map(|file| (path, file)))
            .transpose()?;
        // Take SQLite's write reservation before checking the snapshot. A
        // competing writer cannot change data between verification and BEGIN.
        let tx = Transaction::new_unchecked(conn, rusqlite::TransactionBehavior::Immediate)
            .map_err(DatabaseError::Sqlite)?;
        let guard = if let Some((path, file)) = location {
            let key = key(dek)?;
            let vault = vault_id(conn)?;
            let current = snapshot(conn)?;
            let mut state = match load(&path, key.as_ref(), &vault)? {
                Some(state) => state,
                None if !marked(conn)? => {
                    if !current.is_empty() {
                        tracing::warn!("initial entry-integrity baseline established; prior content rollback cannot be detected");
                    }
                    State {
                        version: 1,
                        vault,
                        stable: current.clone(),
                        pending: None,
                    }
                }
                None => return Err(refusal()),
            };
            if state.stable != current {
                if state.pending.as_ref() != Some(&current) {
                    return Err(refusal());
                }
                state.stable = current;
            }
            state.pending = None;
            Some((file, path, state, key))
        } else {
            None
        };
        if guard.is_some() {
            tx.execute(
                "INSERT OR IGNORE INTO registry_state(key,value) VALUES (?1,'1')",
                [MARKER],
            )
            .map_err(DatabaseError::Sqlite)?;
        }
        Ok(Self {
            tx: Some(tx),
            guard,
        })
    }

    pub(crate) fn commit(mut self) -> Result<()> {
        self.commit_inner(0)
    }

    /// Pairing may replace the DEK only on an empty vault. Publish a receipt
    /// authenticated by either key BEFORE the SQLite adoption commits. Both
    /// crash outcomes can open; the next ordinary commit removes the old MAC.
    /// No fallible filesystem work follows SQL commit, so caller key adoption
    /// cannot be skipped after the new key is durable.
    pub(super) fn commit_empty_key_change(mut self, replacement: &DataEncryptionKey) -> Result<()> {
        if !snapshot(self.tx.as_ref().unwrap())?.is_empty() {
            return Err(refusal());
        }
        if let Some((_, path, state, old_key)) = &mut self.guard {
            if !state.stable.is_empty() {
                return Err(refusal());
            }
            state.pending = Some(BTreeMap::new());
            let replacement_key = key(replacement)?;
            save_with_secondary(
                path,
                state,
                old_key.as_ref(),
                Some(replacement_key.as_ref()),
            )?;
        }
        self.tx
            .take()
            .unwrap()
            .commit()
            .map_err(DatabaseError::Sqlite)?;
        Ok(())
    }

    fn commit_inner(&mut self, fault: u8) -> Result<()> {
        if let Some((_, path, state, key)) = &mut self.guard {
            state.pending = Some(snapshot(self.tx.as_ref().unwrap())?);
            save(path, state, key.as_ref())?;
        }
        if fault == 1 {
            return Err(refusal());
        }
        self.tx
            .take()
            .unwrap()
            .commit()
            .map_err(DatabaseError::Sqlite)?;
        if fault == 2 {
            return Err(refusal());
        }
        if let Some((_, path, state, key)) = &mut self.guard {
            state.stable = state.pending.take().unwrap();
            save(path, state, key.as_ref())?;
        }
        Ok(())
    }
}

impl<'a> Deref for ContentTransaction<'a> {
    type Target = Transaction<'a>;
    fn deref(&self) -> &Self::Target {
        self.tx.as_ref().unwrap()
    }
}
impl DerefMut for ContentTransaction<'_> {
    fn deref_mut(&mut self) -> &mut Self::Target {
        self.tx.as_mut().unwrap()
    }
}

pub(crate) fn verify_row(
    conn: &Connection,
    dek: &DataEncryptionKey,
    row: &RawEntryRow,
) -> Result<()> {
    verify_stored_row(conn, dek, row, false)
}

pub(crate) fn verify_stored_row(
    conn: &Connection,
    dek: &DataEncryptionKey,
    row: &RawEntryRow,
    is_deleted: bool,
) -> Result<()> {
    let Some((path, lock)) = paths(conn) else {
        return Ok(());
    };
    let _lock = acquire(&lock)?;
    let key = key(dek)?;
    let state = match load(&path, key.as_ref(), &vault_id(conn)?)? {
        Some(state) => state,
        None if !marked(conn)? => return Ok(()), // pre-upgrade snapshot only
        None => return Err(refusal()),
    };
    let expected = if let Some(pending) = &state.pending {
        let current = snapshot(conn)?;
        if current == *pending {
            pending
        } else if current == state.stable {
            &state.stable
        } else {
            return Err(refusal());
        }
    } else {
        &state.stable
    };
    if expected.get(&format!("entry:{}", row.entry_id)) != Some(&fingerprint(row, is_deleted)?) {
        return Err(refusal());
    }
    Ok(())
}

pub(crate) fn initialize(conn: &Connection, dek: &DataEncryptionKey) -> Result<()> {
    ContentTransaction::begin(conn, dek)?.commit()
}

pub(crate) fn verify_snapshot(conn: &Connection, dek: &DataEncryptionKey) -> Result<()> {
    let Some((path, lock)) = paths(conn) else {
        return Ok(());
    };
    let _lock = acquire(&lock)?;
    let key = key(dek)?;
    let state = match load(&path, key.as_ref(), &vault_id(conn)?)? {
        Some(state) => state,
        None if !marked(conn)? => return Ok(()),
        None => return Err(refusal()),
    };
    let current = snapshot(conn)?;
    if current != state.stable && state.pending.as_ref() != Some(&current) {
        return Err(refusal());
    }
    Ok(())
}

pub(super) fn verify_copy(
    source: &Connection,
    copy: &Connection,
    dek: &DataEncryptionKey,
) -> Result<()> {
    if vault_id(source)? != vault_id(copy)? {
        return Err(refusal());
    }
    let current = snapshot(copy)?;
    if let Some((path, lock)) = paths(source) {
        let _lock = acquire(&lock)?;
        let key = key(dek)?;
        match load(&path, key.as_ref(), &vault_id(source)?)? {
            Some(state) => {
                if current != state.stable && state.pending.as_ref() != Some(&current) {
                    return Err(refusal());
                }
            }
            None if !marked(source)? => {
                if snapshot(source)? != current {
                    return Err(refusal());
                }
            }
            None => return Err(refusal()),
        }
    } else if snapshot(source)? != current {
        return Err(refusal());
    }
    Ok(())
}

/// Call ONLY after authenticating a backup manifest and verifying the restored
/// snapshot's envelopes. A supervised restore deliberately resets freshness.
pub(super) fn rebase_verified_restore(conn: &Connection, dek: &DataEncryptionKey) -> Result<()> {
    let Some((path, lock)) = paths(conn) else {
        return Ok(());
    };
    let _lock = acquire(&lock)?;
    let key = key(dek)?;
    let state = State {
        version: 1,
        vault: vault_id(conn)?,
        stable: snapshot(conn)?,
        pending: None,
    };
    save(&path, &state, key.as_ref())
}

#[cfg(test)]
mod tests {
    use super::*;

    fn fixture() -> (tempfile::TempDir, Connection, DataEncryptionKey) {
        let dir = tempfile::tempdir().unwrap();
        let conn = Connection::open(dir.path().join("receipt.db")).unwrap();
        conn.execute_batch("CREATE TABLE db_metadata(id INTEGER, vault_uuid TEXT);
            INSERT INTO db_metadata VALUES(1,'synthetic-vault');
            CREATE TABLE registry_state(key TEXT PRIMARY KEY, value TEXT);
            CREATE TABLE domain_mappings(mapping_id INTEGER PRIMARY KEY, entry_id INTEGER,
            domain TEXT NOT NULL, is_primary INTEGER, sync_id TEXT, domain_enc BLOB);
            CREATE TABLE domain_mapping_tags(tag_id INTEGER PRIMARY KEY, mapping_id INTEGER,
            tag BLOB, is_chain_root INTEGER, equality_key_id INTEGER);
            CREATE TABLE entries(entry_id INTEGER PRIMARY KEY, title BLOB, username BLOB,
            password BLOB, url BLOB, notes BLOB, credential_type TEXT, entry_nonce BLOB,
            auth_tag BLOB, created_at INTEGER, modified_at INTEGER, favorite INTEGER,
            sync_id TEXT, sync_version INTEGER, is_deleted INTEGER DEFAULT 0);
            INSERT INTO entries VALUES(1,X'01',X'02',X'03',NULL,NULL,'api_key',X'',X'',1,1,0,'entry',1,0);")
            .unwrap();
        let dek = DataEncryptionKey::new().unwrap();
        initialize(&conn, &dek).unwrap();
        (dir, conn, dek)
    }

    #[test]
    fn acknowledged_changes_refuse_field_and_whole_row_replay() {
        let (_dir, conn, dek) = fixture();
        let tx = ContentTransaction::begin(&conn, &dek).unwrap();
        tx.execute("UPDATE entries SET password=X'04', modified_at=2", [])
            .unwrap();
        tx.commit().unwrap();
        conn.execute("UPDATE entries SET password=X'03'", [])
            .unwrap();
        assert!(verify_snapshot(&conn, &dek).is_err());
        conn.execute("UPDATE entries SET modified_at=1", [])
            .unwrap();
        assert!(verify_snapshot(&conn, &dek).is_err());
        assert!(ContentTransaction::begin(&conn, &dek).is_err());
    }

    #[test]
    fn interrupted_commit_recovers_only_complete_old_or_new_state() {
        for fault in [1, 2] {
            let (_dir, conn, dek) = fixture();
            {
                let mut tx = ContentTransaction::begin(&conn, &dek).unwrap();
                tx.execute("UPDATE entries SET password=X'04', notes=X'05'", [])
                    .unwrap();
                assert!(tx.commit_inner(fault).is_err());
            }
            verify_snapshot(&conn, &dek).unwrap();
            initialize(&conn, &dek).unwrap(); // settles the journal
            let value: Vec<u8> = conn
                .query_row("SELECT password FROM entries", [], |r| r.get(0))
                .unwrap();
            assert_eq!(value, vec![if fault == 1 { 3 } else { 4 }]);
            conn.execute("UPDATE entries SET password=X'09'", [])
                .unwrap();
            assert!(verify_snapshot(&conn, &dek).is_err());
        }
    }

    #[test]
    fn empty_key_handoff_is_crash_readable_and_nonempty_handoff_is_refused() {
        let (_dir, conn, old) = fixture();
        let new = DataEncryptionKey::new().unwrap();
        assert!(ContentTransaction::begin(&conn, &old)
            .unwrap()
            .commit_empty_key_change(&new)
            .is_err());
        let tx = ContentTransaction::begin(&conn, &old).unwrap();
        tx.execute("DELETE FROM entries", []).unwrap();
        tx.commit().unwrap();
        ContentTransaction::begin(&conn, &old)
            .unwrap()
            .commit_empty_key_change(&new)
            .unwrap();
        // The durable handoff is valid for either SQLite crash outcome.
        verify_snapshot(&conn, &old).unwrap();
        verify_snapshot(&conn, &new).unwrap();
        initialize(&conn, &new).unwrap();
        assert!(verify_snapshot(&conn, &old).is_err());
        verify_snapshot(&conn, &new).unwrap();
    }

    #[test]
    fn optional_absence_and_deletion_are_authenticated() {
        let (_dir, conn, dek) = fixture();
        conn.execute("UPDATE entries SET notes=X''", []).unwrap();
        assert!(verify_snapshot(&conn, &dek).is_err());
        conn.execute("UPDATE entries SET notes=NULL, is_deleted=1", [])
            .unwrap();
        assert!(verify_snapshot(&conn, &dek).is_err());
    }

    #[test]
    fn missing_forged_and_wrong_key_receipts_fail_closed() {
        let (_dir, conn, dek) = fixture();
        assert!(verify_snapshot(&conn, &DataEncryptionKey::new().unwrap()).is_err());
        let (path, _) = paths(&conn).unwrap();
        let original = std::fs::read(&path).unwrap();
        let mut doc: serde_json::Value = serde_json::from_slice(&original).unwrap();
        doc["state"]["stable"]["1"] = "forged".into();
        std::fs::write(&path, serde_json::to_vec(&doc).unwrap()).unwrap();
        assert!(verify_snapshot(&conn, &dek).is_err());
        std::fs::remove_file(&path).unwrap();
        assert!(initialize(&conn, &dek).is_err());
    }
}
