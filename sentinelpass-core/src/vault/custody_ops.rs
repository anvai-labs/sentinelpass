//! Dedicated personal custody storage. Internal only: the native authority owns
//! approval and enrollment. No service-grant, password-entry or JSON secret API.
use super::{content_guard, VaultManager};
use crate::crypto::aad::{AadContext, EnvelopePurpose, ObjectType, AAD_VERSION};
use crate::crypto::{open_envelope, seal_envelope, DataEncryptionKey, SUPPORTED_CRYPTO_VERSION};
use crate::custody::NativeSecret;
use rusqlite::{params, Connection, OptionalExtension};
use sentinelpass_protocol::custody::{CustodyError, CustodyScope, ObjectRef, Result};
use sha2::{Digest, Sha256};
use zeroize::Zeroizing;

const MAX_DOCUMENT: usize = 4096;
fn unavailable<T>(_: T) -> CustodyError {
    CustodyError::Unavailable
}
fn denied<T>(_: T) -> CustodyError {
    CustodyError::Denied
}

// Fixed field order, typed canonical serialization; never concatenate unframed
// identifiers. The full digest is the SPENV object identity (no UUID truncation).
fn context(
    vault: &str,
    scope: &CustodyScope,
    reference: &ObjectRef,
    deleted: bool,
) -> Result<AadContext> {
    scope.validate()?;
    reference.validate()?;
    let metadata = serde_json::to_vec(&(scope, reference)).map_err(unavailable)?;
    Ok(AadContext {
        aad_version: AAD_VERSION,
        vault: vault.into(),
        object: hex::encode(Sha256::digest(metadata)),
        purpose: EnvelopePurpose::Secret,
        object_type: ObjectType::PersonalCustody,
        schema_version: 1,
        crypto_version: SUPPORTED_CRYPTO_VERSION,
        // Mailbox epoch lives in the commitment as a lossless u64 string.
        // This is the custody format epoch, independent of vault password wraps.
        epoch: 1,
        tombstone: Some(deleted),
    })
}

pub(crate) struct Row {
    pub object_id: String,
    pub scope: CustodyScope,
    pub reference: ObjectRef,
    pub envelope: Vec<u8>,
    pub deleted: bool,
}
pub(super) fn check_row_bounds(row: &rusqlite::Row<'_>) -> rusqlite::Result<()> {
    let decode_error = || rusqlite::Error::InvalidQuery;
    // Bounds before owned allocation, even if an offline writer bypassed the
    // table CHECK constraints. SQLite owns the borrowed row memory here.
    for (column, limit) in [
        (0, 128),
        (1, MAX_DOCUMENT),
        (2, MAX_DOCUMENT),
        (3, MAX_DOCUMENT),
    ] {
        let bytes = match row.get_ref(column)? {
            rusqlite::types::ValueRef::Text(bytes) if column != 3 => bytes,
            rusqlite::types::ValueRef::Blob(bytes) if column == 3 => bytes,
            _ => return Err(decode_error()),
        };
        if bytes.len() > limit {
            return Err(decode_error());
        }
    }
    Ok(())
}
fn parse(row: &rusqlite::Row<'_>) -> rusqlite::Result<Row> {
    check_row_bounds(row)?;
    let decode_error = || rusqlite::Error::InvalidQuery;
    let scope: String = row.get(1)?;
    let reference: String = row.get(2)?;
    let envelope: Vec<u8> = row.get(3)?;
    if envelope.len() > MAX_DOCUMENT {
        return Err(decode_error());
    }
    let result = Row {
        object_id: row.get(0)?,
        scope: CustodyScope::decode(scope.as_bytes()).map_err(|_| decode_error())?,
        reference: ObjectRef::decode(reference.as_bytes()).map_err(|_| decode_error())?,
        envelope,
        deleted: row.get(4)?,
    };
    if result.object_id != result.reference.object_id {
        return Err(decode_error());
    }
    Ok(result)
}
fn find(conn: &Connection, id: &str) -> Result<Option<Row>> {
    conn.query_row("SELECT object_id,scope_json,reference_json,envelope,deleted FROM custody_objects WHERE object_id=?1", [id], parse)
        .optional().map_err(denied)
}
fn open(dek: &DataEncryptionKey, vault: &str, row: &Row) -> Result<Zeroizing<Vec<u8>>> {
    let value = open_envelope(
        dek,
        context(vault, &row.scope, &row.reference, row.deleted)?,
        &row.envelope,
    )
    .map_err(denied)?;
    if value.len() != if row.deleted { 0 } else { 32 } {
        return Err(CustodyError::Denied);
    }
    Ok(value)
}
fn exact(
    dek: &DataEncryptionKey,
    vault: &str,
    row: &Row,
    scope: &CustodyScope,
    reference: &ObjectRef,
) -> Result<Zeroizing<Vec<u8>>> {
    let value = open(dek, vault, row)?; // authenticate before interpreting metadata
    if row.deleted {
        return Err(CustodyError::NotFound);
    }
    if &row.scope != scope {
        return Err(CustodyError::Denied);
    }
    if &row.reference != reference {
        return Err(CustodyError::StaleReference);
    }
    Ok(value)
}

impl VaultManager {
    #[cfg(test)]
    pub(crate) fn custody_test_audit_dir(&mut self, path: std::path::PathBuf) {
        self.audit_logger = Some(std::sync::Arc::new(crate::AuditLogger::new(path).unwrap()));
    }
    #[cfg(test)]
    pub(crate) fn custody_test_lock_db(
        &self,
    ) -> std::sync::MutexGuard<'_, crate::database::Database> {
        self.lock_db().unwrap()
    }
    /// Loaded-provider benchmark fixture ONLY. The random DEK is installed
    /// directly so KDF peak RSS cannot hide custody's incremental memory. The
    /// dummy wraps deliberately cannot reopen; functional tests use real opens.
    #[cfg(test)]
    pub(crate) fn custody_benchmark_fixture(path: &std::path::Path) -> Self {
        let db = crate::database::Database::open(path).unwrap();
        db.initialize_schema().unwrap();
        let vault_uuid = uuid::Uuid::new_v4().to_string();
        db.conn().execute("INSERT INTO db_metadata(id,version,kdf_params,wrapped_dek,dek_nonce,created_at,last_modified,vault_uuid) VALUES(1,14,X'',X'',X'',0,0,?1)", [&vault_uuid]).unwrap();
        let mut key_hierarchy = crate::crypto::KeyHierarchy::new();
        key_hierarchy.unlock_vault_with_dek(DataEncryptionKey::new().unwrap());
        content_guard::initialize(db.conn(), key_hierarchy.dek().unwrap()).unwrap();
        Self {
            key_hierarchy,
            db: std::sync::Arc::new(std::sync::Mutex::new(db)),
            vault_path: path.to_owned(),
            audit_logger: Some(std::sync::Arc::new(
                crate::AuditLogger::new(path.with_extension("audit")).unwrap(),
            )),
            epoch_sidecar: None,
            vault_uuid: Some(vault_uuid),
            session_epoch: std::sync::atomic::AtomicI64::new(1),
        }
    }
    pub(crate) fn custody_audit(
        &self,
        operation: crate::audit::CustodyAuditOperation,
        success: bool,
    ) {
        if let Some(logger) = &self.audit_logger {
            if logger
                .log(
                    crate::AuditEventType::PersonalCustody { operation, success },
                    "Personal custody operation",
                )
                .is_err()
            {
                tracing::warn!("Personal custody audit write failed");
            }
        }
    }
    #[cfg(test)]
    pub(crate) fn custody_read(
        &self,
        scope: &CustodyScope,
        reference: &ObjectRef,
    ) -> Result<NativeSecret> {
        self.custody_read_checked(scope, reference, || Ok(()))
    }
    pub(crate) fn custody_read_checked(
        &self,
        scope: &CustodyScope,
        reference: &ObjectRef,
        check: impl Fn() -> Result<()>,
    ) -> Result<NativeSecret> {
        check()?;
        scope.validate()?;
        reference.validate()?;
        let dek = self.key_hierarchy.dek().map_err(|_| CustodyError::Locked)?;
        let db = self.lock_db().map_err(unavailable)?;
        check()?;
        // Hold the SQLite snapshot across receipt verification and row read.
        let _snapshot = db.conn().unchecked_transaction().map_err(unavailable)?;
        content_guard::verify_snapshot(db.conn(), dek).map_err(denied)?;
        check()?;
        let row = find(db.conn(), &reference.object_id)?.ok_or(CustodyError::NotFound)?;
        let plaintext = exact(
            dek,
            self.vault_uuid_str().map_err(denied)?,
            &row,
            scope,
            reference,
        )?;
        let mut value = Zeroizing::new([0; 32]);
        value.copy_from_slice(&plaintext);
        Ok(NativeSecret(value))
    }

    #[cfg(test)]
    pub(crate) fn custody_put(
        &self,
        scope: &CustodyScope,
        expected: Option<&ObjectRef>,
        reference: &ObjectRef,
        value: &NativeSecret,
    ) -> Result<()> {
        self.custody_put_checked(scope, expected, reference, value, || Ok(()), || Ok(()))
    }
    pub(crate) fn custody_put_checked(
        &self,
        scope: &CustodyScope,
        expected: Option<&ObjectRef>,
        reference: &ObjectRef,
        value: &NativeSecret,
        check: impl Fn() -> Result<()>,
        before_commit: impl FnOnce() -> Result<()>,
    ) -> Result<()> {
        check()?;
        scope.validate()?;
        reference.validate()?;
        if let Some(old) = expected {
            old.validate()?;
        }
        let dek = self.key_hierarchy.dek().map_err(|_| CustodyError::Locked)?;
        let vault = self.vault_uuid_str().map_err(denied)?;
        let db = self.lock_db().map_err(unavailable)?;
        check()?;
        let tx = content_guard::ContentTransaction::begin(db.conn(), dek).map_err(denied)?;
        check()?;
        match (find(&tx, &reference.object_id)?, expected) {
            (None, None) => {}
            (Some(row), Some(old)) => {
                drop(exact(dek, vault, &row, scope, old)?);
                if old.object_id != reference.object_id
                    || old
                        .revision
                        .parse::<u64>()
                        .ok()
                        .and_then(|r| r.checked_add(1))
                        != reference.revision.parse().ok()
                    || reference.key_epoch.parse::<u64>().map_err(denied)?
                        < old.key_epoch.parse::<u64>().map_err(denied)?
                {
                    return Err(CustodyError::Conflict);
                }
            }
            _ => return Err(CustodyError::Conflict),
        }
        let envelope = seal_envelope(
            dek,
            context(vault, scope, reference, false)?,
            value.0.as_ref(),
            32,
        )
        .map_err(unavailable)?;
        tx.execute("INSERT INTO custody_objects(object_id,scope_json,reference_json,envelope,deleted) VALUES(?1,?2,?3,?4,0)
            ON CONFLICT(object_id) DO UPDATE SET scope_json=excluded.scope_json,reference_json=excluded.reference_json,envelope=excluded.envelope",
            params![reference.object_id, serde_json::to_string(scope).map_err(unavailable)?, serde_json::to_string(reference).map_err(unavailable)?, envelope])
            .map_err(unavailable)?;
        before_commit()?;
        tx.commit().map_err(unavailable)
    }

    #[cfg(test)]
    pub(crate) fn custody_remove(&self, scope: &CustodyScope, expected: &ObjectRef) -> Result<()> {
        self.custody_remove_checked(scope, expected, || Ok(()), || Ok(()))
    }
    pub(crate) fn custody_remove_checked(
        &self,
        scope: &CustodyScope,
        expected: &ObjectRef,
        check: impl Fn() -> Result<()>,
        before_commit: impl FnOnce() -> Result<()>,
    ) -> Result<()> {
        check()?;
        scope.validate()?;
        expected.validate()?;
        let dek = self.key_hierarchy.dek().map_err(|_| CustodyError::Locked)?;
        let vault = self.vault_uuid_str().map_err(denied)?;
        let db = self.lock_db().map_err(unavailable)?;
        check()?;
        let tx = content_guard::ContentTransaction::begin(db.conn(), dek).map_err(denied)?;
        check()?;
        let row = find(&tx, &expected.object_id)?.ok_or(CustodyError::NotFound)?;
        drop(exact(dek, vault, &row, scope, expected)?);
        // Authenticated tombstone retains identity/revision, but no secret.
        let envelope = seal_envelope(dek, context(vault, scope, expected, true)?, &[], 0)
            .map_err(unavailable)?;
        tx.execute(
            "UPDATE custody_objects SET envelope=?1,deleted=1 WHERE object_id=?2",
            params![envelope, expected.object_id],
        )
        .map_err(unavailable)?;
        before_commit()?;
        tx.commit().map_err(unavailable)
    }
}

// The table is absent only in historical snapshots/isolated old-schema fixtures.
// Current schema must contain it; dropping it from a v14 vault fails closed.
pub(crate) fn table_exists(conn: &Connection) -> crate::Result<bool> {
    let present: bool = conn.query_row("SELECT EXISTS(SELECT 1 FROM sqlite_master WHERE type='table' AND name='custody_objects')", [], |r| r.get(0)).map_err(crate::DatabaseError::Sqlite)?;
    if !present {
        let version: i64 = conn
            .query_row("SELECT version FROM db_metadata WHERE id=1", [], |r| {
                r.get(0)
            })
            .map_err(crate::DatabaseError::Sqlite)?;
        if version >= 14 {
            return Err(integrity_error());
        }
    }
    Ok(present)
}
fn integrity_error() -> crate::PasswordManagerError {
    crate::PasswordManagerError::InvalidInput(
        "personal custody integrity verification failed".into(),
    )
}
pub(crate) fn verify(conn: &Connection, dek: &DataEncryptionKey, vault: &str) -> crate::Result<()> {
    if !table_exists(conn)? {
        return Ok(());
    }
    let mut stmt = conn
        .prepare("SELECT object_id,scope_json,reference_json,envelope,deleted FROM custody_objects")
        .map_err(crate::DatabaseError::Sqlite)?;
    let rows = stmt
        .query_map([], parse)
        .map_err(crate::DatabaseError::Sqlite)?;
    let mut identities = std::collections::HashSet::new();
    for row in rows {
        let row = row.map_err(|_| integrity_error())?;
        if !identities.insert(row.object_id.clone()) {
            return Err(integrity_error());
        }
        drop(open(dek, vault, &row).map_err(|_| integrity_error())?);
    }
    Ok(())
}
pub(crate) fn rekey(
    conn: &Connection,
    old: &DataEncryptionKey,
    new: &DataEncryptionKey,
    old_vault: &str,
    new_vault: &str,
) -> crate::Result<()> {
    let mut stmt = conn
        .prepare("SELECT object_id,scope_json,reference_json,envelope,deleted FROM custody_objects")
        .map_err(crate::DatabaseError::Sqlite)?;
    let rows = stmt
        .query_map([], parse)
        .map_err(crate::DatabaseError::Sqlite)?
        .collect::<std::result::Result<Vec<_>, _>>()
        .map_err(crate::DatabaseError::Sqlite)?;
    drop(stmt);
    for row in rows {
        let plaintext = open(old, old_vault, &row).map_err(|_| integrity_error())?;
        let context = context(new_vault, &row.scope, &row.reference, row.deleted)
            .map_err(|_| integrity_error())?;
        let envelope = seal_envelope(new, context, &plaintext, 32)?;
        conn.execute(
            "UPDATE custody_objects SET envelope=?1 WHERE object_id=?2",
            params![envelope, row.object_id],
        )
        .map_err(crate::DatabaseError::Sqlite)?;
    }
    Ok(())
}
