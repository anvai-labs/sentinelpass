//! Entry-field envelope adoption (WBS-304 second half): routes entry
//! field encryption through the authenticated v2 envelope while keeping
//! dual-read compatibility with v1 (`EncryptedEntry` bincode) rows.
//!
//! Format policy:
//! - NEW rows (`add_entry`) seal ALL sensitive fields as v2 envelopes.
//!   Every new row carries a `sync_id` (the stable object identity the
//!   AAD binds), so this is always possible.
//! - EXISTING v1 rows keep the v1 write path on `update_entry` — a row is
//!   never mixed-format (determined by the magic prefix of its existing
//!   password blob). Bulk v1→v2 re-encryption is WBS-404's migration.
//! - READS are dual: a blob with the SPENV magic prefix opens as a v2
//!   envelope against the row's identity; anything else falls back to the
//!   v1 bincode path. Wrong-class blobs that are neither fail closed.
//! - SYNC paths (push collect, pull apply) use the same free functions
//!   with the vault UUID read from db_metadata — a v2 payload pulled from
//!   a peer is re-sealed under the local identity, never downgraded to v1.
//!
//! Epoch policy: entry envelopes use
//! [`open_envelope_relaxed_epoch`] — the DEK is rotation-invariant, so an
//! entry sealed before a master-password rotation must still open after
//! it. The epoch stays tag-bound (authenticated, tamper-refused); it is
//! simply not required to equal the reader's current epoch. Rotation-
//! variant classes (key slots) never go through this module. The epoch
//! value comes from the SESSION CACHE on `VaultManager` (set at
//! open/create, updated at every rotation commit) — never from a
//! `key_epoch()` re-lock, because the DB Mutex is not reentrant and the
//! registry sweep holds it across decrypt loops.
//!
//! Schema-version policy (adoption review, finding 2): the AAD binds a
//! dedicated [`ENTRY_ENVELOPE_SCHEMA`] constant, NOT the database schema
//! version — the DB schema auto-migrates forward on open while entry
//! envelopes stay sealed, so binding the DB version would brick every v2
//! entry at the next routine migration. Bump the constant only when the
//! entry-envelope identity contract itself changes (which requires a
//! re-seal migration to ship in the same release).

use super::VaultManager;
use crate::crypto::aad::{AadContext, AadContextBuilder, EnvelopePurpose, ObjectType};
use crate::crypto::{open_envelope_relaxed_epoch, seal_envelope, ENVELOPE_MAGIC};
use crate::vault::CredentialType;
use crate::{DatabaseError, PasswordManagerError, Result};
use zeroize::Zeroizing;

/// The identity-contract version for ENTRY envelopes. Deliberately
/// independent of the database schema version (see module docs).
pub const ENTRY_ENVELOPE_SCHEMA: i32 = 1;

/// Field-class plaintext ceilings (policy bound under the envelope's 1 MiB
/// ciphertext cap; b64 inflation ×4/3 keeps a 2 MiB secret well under the
/// 4 MiB document cap). Generous by design — imports of legacy vaults
/// must not start failing mid-file (adoption review, finding 5) — while
/// still catching runaway values at seal.
pub(crate) const MAX_SUMMARY_PLAINTEXT: usize = 64 * 1024;
pub(crate) const MAX_SECRET_PLAINTEXT: usize = 2 * 1024 * 1024;

pub(crate) fn envelope_object_type(cred: CredentialType) -> ObjectType {
    match cred {
        CredentialType::Password => ObjectType::Password,
        CredentialType::ApiKey => ObjectType::ApiKey,
        CredentialType::PasskeyReference => ObjectType::PasskeyReference,
    }
}

/// The trusted identity of one entry field, as the sync-shared core needs
/// it. `vault_uuid` and `sync_id` come from trusted storage (the metadata
/// row / the entry row), never from the blob being opened.
#[derive(Clone, Copy)]
pub(crate) struct EntryFieldIdentity<'a> {
    pub vault_uuid: &'a str,
    pub sync_id: &'a str,
    pub cred: CredentialType,
}

fn identity_context(
    vault_uuid: &str,
    object_id: &str,
    object_type: ObjectType,
    purpose: EnvelopePurpose,
    epoch: i64,
) -> Result<AadContext> {
    let vault = uuid::Uuid::parse_str(vault_uuid).map_err(|e| {
        PasswordManagerError::InvalidInput(format!("stored vault_uuid is not a UUID: {e}"))
    })?;
    let object = uuid::Uuid::parse_str(object_id)
        .map_err(|e| PasswordManagerError::InvalidInput(format!("object id is not a UUID: {e}")))?;
    AadContextBuilder::new()
        .vault(vault)
        .object(object)
        .purpose(purpose)
        .object_type(object_type)
        .schema_version(ENTRY_ENVELOPE_SCHEMA)
        .crypto_version(crate::crypto::SUPPORTED_CRYPTO_VERSION)
        .epoch(epoch)
        .build()
}

/// The LOCAL vault identity (vault UUID + key epoch), read from
/// db_metadata on the given connection — the single accessor for sync
/// paths that hold only a `&Connection` (engine + collectors; six
/// hand-copied SELECT pairs consolidated here, adoption review). Fails
/// closed on a missing/NULL vault_uuid: a broken metadata row must
/// surface as a DB error, not masquerade later as a tamper refusal.
pub(crate) fn read_local_identity(conn: &rusqlite::Connection) -> Result<(String, i64)> {
    let (vault_uuid, epoch): (Option<String>, i64) = conn
        .query_row(
            "SELECT vault_uuid, COALESCE(key_epoch, 1) FROM db_metadata WHERE id = 1",
            [],
            |r| Ok((r.get(0)?, r.get(1)?)),
        )
        .map_err(DatabaseError::Sqlite)?;
    let vault_uuid = vault_uuid.ok_or_else(|| {
        PasswordManagerError::InvalidInput(
            "vault identity (vault_uuid) is missing from db_metadata; refusing sync \
             envelope operation"
                .to_string(),
        )
    })?;
    Ok((vault_uuid, epoch))
}

/// The versioned v2 marker test — the ONE owner of "is this blob an
/// envelope" row-format policy (a second accepted prefix, e.g. a v3
/// magic, changes here and nowhere else; adoption review, gate round).
pub(crate) fn is_envelope_blob(blob: &[u8]) -> bool {
    blob.starts_with(ENVELOPE_MAGIC)
}

/// The zero-filled placeholders for the DEPRECATED v1 nonce/auth_tag
/// columns on v2 rows (v1 readers are gone; the columns are NOT NULL
/// until the v2 schema migration drops them). One helper owns the policy
/// — nine hand-rolled sites consolidated (adoption review).
pub(crate) fn zeroed_legacy_v1_columns() -> (Vec<u8>, Vec<u8>) {
    (
        bincode::serialize(&[0u8; 12]).expect("bincode of a fixed array cannot fail"),
        bincode::serialize(&[0u8; 16]).expect("bincode of a fixed array cannot fail"),
    )
}

/// Seal one field of ANY envelope-bearing object (entry, registry entity,
/// SSH key, TOTP secret) — the shared core every class routes through.
pub(crate) fn seal_object_field(
    dek: &crate::crypto::DataEncryptionKey,
    vault_uuid: &str,
    object_id: &str,
    object_type: ObjectType,
    purpose: EnvelopePurpose,
    plaintext: &str,
    epoch: i64,
) -> Result<Vec<u8>> {
    let max = match purpose {
        EnvelopePurpose::Summary => MAX_SUMMARY_PLAINTEXT,
        EnvelopePurpose::Secret => MAX_SECRET_PLAINTEXT,
    };
    let ctx = identity_context(vault_uuid, object_id, object_type, purpose, epoch)?;
    seal_envelope(dek, ctx, plaintext.as_bytes(), max).map_err(PasswordManagerError::from)
}

/// Dual-read one field of ANY envelope-bearing object. A SPENV-prefixed
/// blob MUST have both identity components to open (their absence on a v2
/// blob is tamper, not fallback); anything else takes the v1 bincode
/// path. Plaintext is zeroize-on-drop.
pub(crate) fn open_object_field(
    dek: &crate::crypto::DataEncryptionKey,
    vault_uuid: Option<&str>,
    object_id: Option<&str>,
    object_type: ObjectType,
    purpose: EnvelopePurpose,
    blob: &[u8],
) -> Result<Zeroizing<String>> {
    if blob.starts_with(ENVELOPE_MAGIC) {
        let (vault_uuid, object_id) = match (vault_uuid, object_id) {
            (Some(v), Some(o)) => (v, o),
            _ => {
                return Err(PasswordManagerError::InvalidInput(
                    "v2 envelope on a row with no stable identity — refusing (identity cannot \
                     be established; the row may have been tampered with)"
                        .to_string(),
                ))
            }
        };
        // The relaxed open takes the epoch from the authenticated document
        // (rotation-invariant DEK policy), so the context's epoch is
        // overwritten before the AAD is derived.
        let expected = identity_context(vault_uuid, object_id, object_type, purpose, 0)?;
        let plaintext = open_envelope_relaxed_epoch(dek, expected, blob)?;
        let s = String::from_utf8(plaintext.to_vec()).map_err(|_| {
            PasswordManagerError::from(DatabaseError::Serialization(
                "envelope plaintext is not valid UTF-8".to_string(),
            ))
        })?;
        Ok(Zeroizing::new(s))
    } else {
        // v1 legacy path: context-free bincode EncryptedEntry.
        let encrypted: crate::crypto::EncryptedEntry = bincode::deserialize(blob)
            .map_err(|e| PasswordManagerError::from(DatabaseError::Serialization(e.to_string())))?;
        crate::crypto::cipher::decrypt_to_string(dek, &encrypted)
            .map_err(PasswordManagerError::from)
    }
}

/// Dual-read one ENTRY field (identity expressed via
/// [`EntryFieldIdentity`] — the sync paths' shape).
pub(crate) fn open_entry_field_with_identity(
    dek: &crate::crypto::DataEncryptionKey,
    identity: Option<EntryFieldIdentity<'_>>,
    purpose: EnvelopePurpose,
    blob: &[u8],
) -> Result<Zeroizing<String>> {
    let (vault_uuid, object_id, object_type) = match identity {
        Some(identity) => (
            Some(identity.vault_uuid),
            Some(identity.sync_id),
            envelope_object_type(identity.cred),
        ),
        None => (None, None, ObjectType::Password),
    };
    open_object_field(dek, vault_uuid, object_id, object_type, purpose, blob)
}

/// Dual-read a FORMERLY-plaintext TEXT metadata column (WBS-306: totp
/// issuer/account_name, ssh comment) that may now hold a NULL, a legacy
/// plaintext string, or a v2 envelope document.
///
/// The column value arrives as a DYNAMIC [`rusqlite::types::Value`]
/// because the column is storage-polymorphic since WBS-306: legacy rows
/// hold TEXT, v2 rows hold a BLOB envelope document. A typed
/// `Option<Vec<u8>>` read would ERROR on the legacy TEXT rows (rusqlite is
/// strictly typed even though SQLite is not) — the dynamic read is what
/// makes dual-read actually dual.
///
/// - NULL → absent stays absent;
/// - BLOB with the SPENV prefix → opened as a v2 envelope against the
///   row's identity (Summary purpose — these are listing-time metadata);
///   a v2 blob with no stable identity is tamper, not fallback;
/// - TEXT → the legacy plaintext, passed through;
/// - BLOB without the SPENV prefix → legacy bytes, UTF-8 decoded;
/// - any other storage class → refused (never silently coerced).
pub(crate) fn open_metadata_text_field(
    dek: &crate::crypto::DataEncryptionKey,
    vault_uuid: Option<&str>,
    object_id: Option<&str>,
    object_type: ObjectType,
    value: Option<rusqlite::types::Value>,
) -> Result<Option<String>> {
    use rusqlite::types::Value;
    match value {
        None | Some(Value::Null) => Ok(None),
        Some(Value::Text(s)) => Ok(Some(s)),
        Some(Value::Blob(blob)) => {
            if blob.starts_with(ENVELOPE_MAGIC) {
                open_object_field(
                    dek,
                    vault_uuid,
                    object_id,
                    object_type,
                    EnvelopePurpose::Summary,
                    &blob,
                )
                .map(|z| Some(z.to_string()))
            } else {
                String::from_utf8(blob).map(Some).map_err(|_| {
                    PasswordManagerError::from(DatabaseError::Serialization(
                        "legacy metadata column is not valid UTF-8".to_string(),
                    ))
                })
            }
        }
        Some(Value::Integer(_) | Value::Real(_)) => {
            Err(PasswordManagerError::from(DatabaseError::Serialization(
                "metadata column holds an unexpected storage class (integer/real)".to_string(),
            )))
        }
    }
}

/// The sealed five-field blob set for one entry row (v2), with the
/// zero-filled deprecated v1 columns. One structure names the slots so a
/// field/purpose mix-up or an arity slip is a compile error, not silent
/// ciphertext-column swapping (adoption review, simplification finding).
pub(crate) struct SealedEntryFields {
    pub title: Vec<u8>,
    pub username: Vec<u8>,
    pub password: Vec<u8>,
    pub url: Option<Vec<u8>>,
    pub notes: Option<Vec<u8>>,
}

/// Seal ALL sensitive fields of one entry (the single owner of the
/// field→purpose classification: title/username = Summary,
/// password/url/notes = Secret). Used by add_entry, update_entry (v2
/// rows), and sync apply.
pub(crate) fn seal_entry_fields(
    dek: &crate::crypto::DataEncryptionKey,
    vault_uuid: &str,
    sync_id: &str,
    cred: CredentialType,
    entry: &crate::vault::Entry,
    epoch: i64,
) -> Result<SealedEntryFields> {
    let ot = envelope_object_type(cred);
    Ok(SealedEntryFields {
        title: seal_object_field(
            dek,
            vault_uuid,
            sync_id,
            ot,
            EnvelopePurpose::Summary,
            &entry.title,
            epoch,
        )?,
        username: seal_object_field(
            dek,
            vault_uuid,
            sync_id,
            ot,
            EnvelopePurpose::Summary,
            &entry.username,
            epoch,
        )?,
        password: seal_object_field(
            dek,
            vault_uuid,
            sync_id,
            ot,
            EnvelopePurpose::Secret,
            entry.password.as_str(),
            epoch,
        )?,
        url: entry
            .url
            .as_ref()
            .map(|u| {
                seal_object_field(
                    dek,
                    vault_uuid,
                    sync_id,
                    ot,
                    EnvelopePurpose::Secret,
                    u,
                    epoch,
                )
            })
            .transpose()?,
        notes: entry
            .notes
            .as_ref()
            .map(|n| {
                seal_object_field(
                    dek,
                    vault_uuid,
                    sync_id,
                    ot,
                    EnvelopePurpose::Secret,
                    n,
                    epoch,
                )
            })
            .transpose()?,
    })
}

impl VaultManager {
    /// The stored vault UUID, or an actionable refusal.
    pub(super) fn vault_uuid_str(&self) -> Result<&str> {
        self.vault_uuid.as_deref().ok_or_else(|| {
            PasswordManagerError::InvalidInput(
                "vault identity (vault_uuid) is missing; refusing envelope operation".to_string(),
            )
        })
    }

    /// Seal one entry field as a v2 envelope (add/update on v2 rows).
    /// Safe under a held `lock_db()`: the epoch comes from the session
    /// cache (set at open/create, updated at every rotation commit),
    /// never from a re-lock.
    pub(super) fn seal_entry_field(
        &self,
        sync_id: &str,
        cred: CredentialType,
        purpose: EnvelopePurpose,
        plaintext: &str,
    ) -> Result<Vec<u8>> {
        seal_object_field(
            self.key_hierarchy.dek()?,
            self.vault_uuid_str()?,
            sync_id,
            envelope_object_type(cred),
            purpose,
            plaintext,
            self.session_epoch(),
        )
    }

    /// Read one entry field: dual-read (v2 envelope if SPENV-prefixed,
    /// else the v1 bincode path). `sync_id` is required for v2 blobs — a
    /// v2 blob on a row without a stable identity is an integrity error,
    /// not a fallback (v2 rows always have one; its absence on a v2 blob
    /// means the row was tampered with). Safe under a held `lock_db()`
    /// (see [`Self::seal_entry_field`]).
    pub(super) fn open_entry_field(
        &self,
        sync_id: Option<&str>,
        cred: CredentialType,
        purpose: EnvelopePurpose,
        blob: &[u8],
    ) -> Result<Zeroizing<String>> {
        open_object_field(
            self.key_hierarchy.dek()?,
            self.vault_uuid.as_deref(),
            sync_id,
            envelope_object_type(cred),
            purpose,
            blob,
        )
    }
}
