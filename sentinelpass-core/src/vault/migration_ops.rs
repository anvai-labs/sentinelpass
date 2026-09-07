//! Bulk v1→v2 envelope re-encryption migration (WBS-404).
//!
//! Since the envelope-v2 adoption (WBS-304) all READS are dual (a v2
//! envelope if the blob carries the SPENV magic, else the v1 path) and all
//! NEW writes are v2 — but legacy rows still hold v1 blobs: context-free
//! bincode `EncryptedEntry` columns for entries, and the three-part
//! (ciphertext, nonce, auth_tag) columns for SSH private keys and TOTP
//! secrets. This sweep converts every remaining v1 blob to a v2 envelope
//! bound to the row's identity, following the post-unlock backfill-sweep
//! pattern the domain-mapping sweep (WBS-306) established: count/flag
//! triggered, ONE transaction, idempotent, best-effort at open (a failed
//! pass retries on the next open and never fails the unlock).
//!
//! Scope (WBS-404): `entries` (title/username/password/url/notes — identity
//! = the row's `sync_id` via [`EntryFieldIdentity`]),
//! `ssh_keys.private_key_encrypted` (identity = the row's `sync_id`), and
//! `totp_secrets.secret_encrypted` (same). A row whose stored identity is
//! NULL gets a minted `sync_id` written in the same transaction (the
//! `totp_ops` upsert precedent); without it the row could never be sealed
//! under any identity and would block completion forever.
//!
//! Row policy (the hard rules this module exists to enforce):
//! - VERIFY-EVERY-RESULT: every sealed blob is opened right back and
//!   constant-time-compared against the plaintext it was sealed from
//!   BEFORE the row's UPDATE is issued. A mismatch or seal failure means
//!   the row is not written at all (there is nothing to roll back — the
//!   write never happens), is counted, and warned.
//! - A row that fails DECRYPTION (corrupt v1 blob) is never dropped,
//!   zeroed, or overwritten: it is skipped untouched, warned with the row
//!   identity, and left v1 (dual-read keeps it readable if it ever was;
//!   corrupt stays corrupt-but-untouched — we do not destroy data we
//!   cannot read). The per-row flow is decrypt-everything-then-write, so
//!   a row is never half-converted.
//! - Idempotent: a row whose blob(s) already start with the envelope magic
//!   is skipped (per-row self-evident completion). The
//!   `v2_blob_sweep_complete` registry-state key is recorded (timestamp)
//!   only when a full pass finds zero v1 rows — including zero skipped
//!   unreadable rows — so the open hook stops re-running.
//! - Sync interplay: only blob columns (+ a minted `sync_id` + the
//!   deprecated zeroed v1 nonce/tag columns) change. Sync bookkeeping is
//!   NOT touched.
//!
//! The entries sync trigger (historical note — adversarial pre-check A1):
//! the former `update_entry_modified_timestamp` trigger fired on UPDATE OF
//! exactly the columns this sweep must rewrite, silently re-marking every
//! converted row for a full-vault re-push. The sweep used to capture and
//! restore each row's (sync_version, sync_state, modified_at) around its
//! writes. That trigger was DROPPED by the schema v9 migration
//! (`migrate_v8_to_v9`, WBS-409 / TD-ROB-02) — it cannot exist by the time
//! any sweep runs — so the capture/restore neutralization is removed and
//! the blob UPDATE alone is the net row diff.
//!
//! Reentrancy (adversarial pre-check A3): the DB Mutex is not reentrant.
//! The sweep takes `lock_db()` ONCE, fetches (vault_uuid, epoch) once via
//! [`envelope_ops::read_local_identity`], and never calls `key_epoch()`
//! or re-locks inside the decrypt loop.
//!
//! Residuals (deliberately NOT done here): the `domain_mappings.domain`
//! plaintext column (clearing it needs a NOT NULL table rebuild) and the
//! `ssh_keys.comment` / `totp_secrets.issuer` / `account_name` legacy
//! plaintext metadata columns are separate cleanup, not v1 blob classes.

use crate::crypto::aad::{EnvelopePurpose, ObjectType};
use crate::crypto::cipher::DataEncryptionKey;
use crate::vault::CredentialType;
use crate::{DatabaseError, PasswordManagerError, Result};
use chrono::Utc;
use rusqlite::{Connection, OptionalExtension};
use subtle::ConstantTimeEq;
use zeroize::Zeroizing;

use super::envelope_ops::{self, EntryFieldIdentity};
use super::VaultManager;

/// Registry-state key recording that a full sweep pass found zero v1 rows.
/// Presence (any value — a timestamp) gates the post-unlock hook.
const SWEEP_COMPLETE_KEY: &str = "v2_blob_sweep_complete";

/// Outcome of one [`VaultManager::sweep_v1_blobs_to_v2`] pass
/// (SweepReport-style counting, as the registry/domain sweeps).
#[derive(Debug, Default, Clone, PartialEq, Eq)]
pub struct V2BlobSweepReport {
    /// Rows examined across all three blob families.
    pub scanned: usize,
    /// Rows re-encrypted v1 → v2 (including mixed-format rows healed to
    /// all-v2 and rows whose NULL identity was minted).
    pub converted: usize,
    /// Rows left untouched because a v1 blob failed to decrypt (corrupt) —
    /// never destroyed, warned with the row identity, retried next pass.
    pub skipped_unreadable: usize,
    /// Rows NOT written because sealing or the verify-back-open failed
    /// (e.g. an oversized plaintext exceeding the envelope field caps).
    pub failed: usize,
}

/// True when the sweep-completion flag is absent — i.e. no full pass has
/// yet found zero v1 rows. The post-unlock hook runs the sweep when this
/// returns true; the sweep itself re-checks every row (SPENV magic), so a
/// flagged vault is never falsely skipped by the row-level policy.
pub(crate) fn v2_blob_sweep_complete(conn: &Connection) -> Result<bool> {
    let recorded: Option<String> = conn
        .query_row(
            "SELECT value FROM registry_state WHERE key = ?1",
            [SWEEP_COMPLETE_KEY],
            |row| row.get(0),
        )
        .optional()
        .map_err(DatabaseError::Sqlite)?;
    Ok(recorded.is_some())
}

fn set_sweep_complete_flag(conn: &Connection, completed_at: &str) -> Result<()> {
    conn.execute(
        "INSERT INTO registry_state (key, value) VALUES (?1, ?2)
         ON CONFLICT(key) DO UPDATE SET value = excluded.value",
        rusqlite::params![SWEEP_COMPLETE_KEY, completed_at],
    )
    .map_err(DatabaseError::Sqlite)?;
    Ok(())
}

/// A NULL optional blob column is format-NEUTRAL (absence is NULL — the
/// same rule `update_entry`'s mixed-format gate applies).
fn optional_blob_is_envelope(blob: &Option<Vec<u8>>) -> bool {
    match blob {
        Some(b) => envelope_ops::is_envelope_blob(b),
        None => true,
    }
}

/// Seal one field and VERIFY it before the caller may write: open the
/// fresh envelope right back and constant-time-compare the plaintext.
/// Any mismatch or failure is an error — the caller must not write the row.
fn seal_and_verify_field(
    dek: &DataEncryptionKey,
    vault_uuid: &str,
    object_id: &str,
    object_type: ObjectType,
    purpose: EnvelopePurpose,
    plaintext: &str,
    epoch: i64,
) -> Result<Vec<u8>> {
    let sealed = envelope_ops::seal_object_field(
        dek,
        vault_uuid,
        object_id,
        object_type,
        purpose,
        plaintext,
        epoch,
    )?;
    let reopened = envelope_ops::open_object_field(
        dek,
        Some(vault_uuid),
        Some(object_id),
        object_type,
        purpose,
        &sealed,
    )?;
    if !bool::from(reopened.as_bytes().ct_eq(plaintext.as_bytes())) {
        return Err(PasswordManagerError::InvalidInput(format!(
            "v2 blob sweep: seal-verify mismatch for object {object_id} ({purpose:?}) — \
             refusing to write the row"
        )));
    }
    Ok(sealed)
}

// ---------------------------------------------------------------------------
// Entries
// ---------------------------------------------------------------------------

/// One scan row of the `entries` table: identity, credential class, and
/// the five blob columns. (Sync bookkeeping columns are deliberately NOT
/// scanned: the sweep never writes them, and the echo trigger that made a
/// restore necessary was dropped by the schema v9 migration — WBS-409.)
type EntryScanRow = (
    i64,
    Option<String>,
    String,
    Vec<u8>,
    Vec<u8>,
    Vec<u8>,
    Option<Vec<u8>>,
    Option<Vec<u8>>,
);

/// The five present-or-absent blob columns of one entry row (borrowed scan
/// shape, so the decrypt helper stays under the argument ceiling).
struct EntryBlobs<'a> {
    title: &'a [u8],
    username: &'a [u8],
    password: &'a [u8],
    url: Option<&'a [u8]>,
    notes: Option<&'a [u8]>,
}

/// The decrypted plaintext of one entry row's fields (zeroize-on-drop).
struct OpenedEntryFields {
    title: Zeroizing<String>,
    username: Zeroizing<String>,
    password: Zeroizing<String>,
    url: Option<Zeroizing<String>>,
    notes: Option<Zeroizing<String>>,
}

/// Dual-read every present column (v1 arm for v1 blobs — identity is
/// ignored there — v2 arm for any v2 column on a mixed row, which fails
/// closed when the identity does not match).
fn decrypt_entry_fields(
    dek: &DataEncryptionKey,
    identity: EntryFieldIdentity<'_>,
    blobs: &EntryBlobs<'_>,
) -> Result<OpenedEntryFields> {
    let open = |purpose, blob: &[u8]| {
        envelope_ops::open_entry_field_with_identity(dek, Some(identity), purpose, blob)
    };
    Ok(OpenedEntryFields {
        title: open(EnvelopePurpose::Summary, blobs.title)?,
        username: open(EnvelopePurpose::Summary, blobs.username)?,
        password: open(EnvelopePurpose::Secret, blobs.password)?,
        url: blobs
            .url
            .map(|blob| open(EnvelopePurpose::Secret, blob))
            .transpose()?,
        notes: blobs
            .notes
            .map(|blob| open(EnvelopePurpose::Secret, blob))
            .transpose()?,
    })
}

/// Seal + verify ALL five fields of one entry (field→purpose
/// classification matches [`envelope_ops::seal_entry_fields`]: title/
/// username = Summary, password/url/notes = Secret).
fn seal_and_verify_entry_fields(
    dek: &DataEncryptionKey,
    vault_uuid: &str,
    sync_id: &str,
    cred: CredentialType,
    epoch: i64,
    opened: &OpenedEntryFields,
) -> Result<envelope_ops::SealedEntryFields> {
    let object_type = envelope_ops::envelope_object_type(cred);
    Ok(envelope_ops::SealedEntryFields {
        title: seal_and_verify_field(
            dek,
            vault_uuid,
            sync_id,
            object_type,
            EnvelopePurpose::Summary,
            &opened.title,
            epoch,
        )?,
        username: seal_and_verify_field(
            dek,
            vault_uuid,
            sync_id,
            object_type,
            EnvelopePurpose::Summary,
            &opened.username,
            epoch,
        )?,
        password: seal_and_verify_field(
            dek,
            vault_uuid,
            sync_id,
            object_type,
            EnvelopePurpose::Secret,
            &opened.password,
            epoch,
        )?,
        url: opened
            .url
            .as_ref()
            .map(|value| {
                seal_and_verify_field(
                    dek,
                    vault_uuid,
                    sync_id,
                    object_type,
                    EnvelopePurpose::Secret,
                    value,
                    epoch,
                )
            })
            .transpose()?,
        notes: opened
            .notes
            .as_ref()
            .map(|value| {
                seal_and_verify_field(
                    dek,
                    vault_uuid,
                    sync_id,
                    object_type,
                    EnvelopePurpose::Secret,
                    value,
                    epoch,
                )
            })
            .transpose()?,
    })
}

fn sweep_entry_rows(
    tx: &rusqlite::Transaction<'_>,
    dek: &DataEncryptionKey,
    vault_uuid: &str,
    epoch: i64,
    report: &mut V2BlobSweepReport,
) -> Result<()> {
    let rows: Vec<EntryScanRow> = {
        let mut stmt = tx
            .prepare(
                "SELECT entry_id, sync_id, credential_type, title, username, password,
                        url, notes
                 FROM entries",
            )
            .map_err(DatabaseError::Sqlite)?;
        let collected = stmt
            .query_map([], |row| {
                Ok((
                    row.get(0)?,
                    row.get(1)?,
                    row.get(2)?,
                    row.get(3)?,
                    row.get(4)?,
                    row.get(5)?,
                    row.get(6)?,
                    row.get(7)?,
                ))
            })
            .map_err(DatabaseError::Sqlite)?
            .collect::<std::result::Result<Vec<_>, _>>()
            .map_err(DatabaseError::Sqlite)?;
        collected
    };

    for (entry_id, sync_id, credential_type, title, username, password, url, notes) in rows {
        report.scanned += 1;
        let already_v2 = envelope_ops::is_envelope_blob(&title)
            && envelope_ops::is_envelope_blob(&username)
            && envelope_ops::is_envelope_blob(&password)
            && optional_blob_is_envelope(&url)
            && optional_blob_is_envelope(&notes);
        if already_v2 {
            continue;
        }

        let cred = match CredentialType::parse(&credential_type) {
            Ok(cred) => cred,
            Err(e) => {
                report.skipped_unreadable += 1;
                tracing::warn!(
                    entry_id,
                    error = %e,
                    "v2 blob sweep: entry row has an unknown credential_type; leaving it \
                     untouched (v1)"
                );
                continue;
            }
        };
        // The envelope identity is the row's sync_id, minted when a legacy
        // row never got one (written back in the same transaction below).
        let sync_id = sync_id.unwrap_or_else(|| uuid::Uuid::new_v4().to_string());
        let identity = EntryFieldIdentity {
            vault_uuid,
            sync_id: &sync_id,
            cred,
        };

        // Decrypt EVERYTHING before writing ANYTHING: a corrupt column skips
        // the whole row untouched (never half-converted, never destroyed).
        let blobs = EntryBlobs {
            title: &title,
            username: &username,
            password: &password,
            url: url.as_deref(),
            notes: notes.as_deref(),
        };
        let opened = match decrypt_entry_fields(dek, identity, &blobs) {
            Ok(opened) => opened,
            Err(e) => {
                report.skipped_unreadable += 1;
                tracing::warn!(
                    entry_id,
                    error = %e,
                    "v2 blob sweep: legacy entry row is unreadable; skipping untouched (stays v1)"
                );
                continue;
            }
        };

        // Seal + verify every field; a failure here writes NOTHING.
        let sealed =
            match seal_and_verify_entry_fields(dek, vault_uuid, &sync_id, cred, epoch, &opened) {
                Ok(sealed) => sealed,
                Err(e) => {
                    report.failed += 1;
                    tracing::warn!(
                        entry_id,
                        error = %e,
                        "v2 blob sweep: seal/verify failed; the row was NOT written"
                    );
                    continue;
                }
            };

        let (zero_nonce, zero_tag) = envelope_ops::zeroed_legacy_v1_columns();
        // The blob UPDATE below touches ONLY blob columns (+ identity) —
        // sync bookkeeping is never written, so the scanned
        // sync_version/sync_state/modified_at are preserved byte-identical.
        // (Historically a follow-up UPDATE restored bookkeeping clobbered
        // by the `update_entry_modified_timestamp` echo trigger; that
        // trigger was dropped by the schema v9 migration — WBS-409 /
        // TD-ROB-02 — so no restore is needed, and `modified_at` stays
        // exactly as scanned.)
        tx.execute(
            "UPDATE entries SET title = ?1, username = ?2, password = ?3, url = ?4,
             notes = ?5, entry_nonce = ?6, auth_tag = ?7, sync_id = ?8
             WHERE entry_id = ?9",
            rusqlite::params![
                sealed.title,
                sealed.username,
                sealed.password,
                sealed.url,
                sealed.notes,
                zero_nonce,
                zero_tag,
                sync_id,
                entry_id
            ],
        )
        .map_err(DatabaseError::Sqlite)?;

        report.converted += 1;
    }
    Ok(())
}

// ---------------------------------------------------------------------------
// SSH keys / TOTP secrets (three-part v1 columns)
// ---------------------------------------------------------------------------

/// The v1 three-part reader for one secret-blob family: (dek, blob, nonce,
/// auth_tag) → plaintext (ssh PEM / normalized TOTP secret).
type ThreePartDecrypt =
    dyn Fn(&DataEncryptionKey, &[u8], &[u8], &[u8]) -> Result<Zeroizing<String>>;

/// Shared conversion for the single-secret-blob families (ssh/totp):
/// decrypt the v1 three-part columns, seal + verify under the row's
/// identity (minting a NULL `sync_id`), and write the envelope plus the
/// zeroed legacy columns. `decrypt` is the family's v1 reader; `object_type`
/// is its envelope class.
#[allow(clippy::too_many_arguments)]
fn sweep_three_part_rows(
    tx: &rusqlite::Transaction<'_>,
    dek: &DataEncryptionKey,
    vault_uuid: &str,
    epoch: i64,
    report: &mut V2BlobSweepReport,
    table: &str,
    id_column: &str,
    blob_column: &str,
    object_type: ObjectType,
    decrypt: &ThreePartDecrypt,
) -> Result<()> {
    // (row_id, sync_id, secret_blob, nonce, auth_tag).
    type ThreePartRow = (i64, Option<String>, Vec<u8>, Vec<u8>, Vec<u8>);
    let sql = format!("SELECT {id_column}, sync_id, {blob_column}, nonce, auth_tag FROM {table}");
    let rows: Vec<ThreePartRow> = {
        let mut stmt = tx.prepare(&sql).map_err(DatabaseError::Sqlite)?;
        let collected = stmt
            .query_map([], |row| {
                Ok((
                    row.get(0)?,
                    row.get(1)?,
                    row.get(2)?,
                    row.get(3)?,
                    row.get(4)?,
                ))
            })
            .map_err(DatabaseError::Sqlite)?
            .collect::<std::result::Result<Vec<_>, _>>()
            .map_err(DatabaseError::Sqlite)?;
        collected
    };

    for (row_id, sync_id, secret_blob, nonce, auth_tag) in rows {
        report.scanned += 1;
        if envelope_ops::is_envelope_blob(&secret_blob) {
            continue;
        }
        let sync_id = sync_id.unwrap_or_else(|| uuid::Uuid::new_v4().to_string());

        let plaintext = match decrypt(dek, &secret_blob, &nonce, &auth_tag) {
            Ok(plaintext) => plaintext,
            Err(e) => {
                report.skipped_unreadable += 1;
                tracing::warn!(
                    table,
                    row_id,
                    error = %e,
                    "v2 blob sweep: legacy three-part blob is unreadable; skipping untouched \
                     (stays v1)"
                );
                continue;
            }
        };
        let sealed = match seal_and_verify_field(
            dek,
            vault_uuid,
            &sync_id,
            object_type,
            EnvelopePurpose::Secret,
            &plaintext,
            epoch,
        ) {
            Ok(sealed) => sealed,
            Err(e) => {
                report.failed += 1;
                tracing::warn!(
                    table,
                    row_id,
                    error = %e,
                    "v2 blob sweep: seal/verify failed; the row was NOT written"
                );
                continue;
            }
        };

        let (zero_nonce, zero_tag) = envelope_ops::zeroed_legacy_v1_columns();
        let update_sql = format!(
            "UPDATE {table} SET {blob_column} = ?1, nonce = ?2, auth_tag = ?3, \
             sync_id = ?4 WHERE {id_column} = ?5"
        );
        tx.execute(
            &update_sql,
            rusqlite::params![sealed, zero_nonce, zero_tag, sync_id, row_id],
        )
        .map_err(DatabaseError::Sqlite)?;

        report.converted += 1;
    }
    Ok(())
}

impl VaultManager {
    /// True when [`Self::sweep_v1_blobs_to_v2`] has (or may still have)
    /// work to do: no completed full pass is on record yet.
    pub fn v2_blob_sweep_needed(&self) -> Result<bool> {
        let db = self.lock_db()?;
        Ok(!v2_blob_sweep_complete(db.conn())?)
    }

    /// Convert every remaining v1 blob (entry fields, SSH private keys,
    /// TOTP secrets) to identity-bound v2 envelopes — ONE transaction, one
    /// `lock_db()` acquisition, (vault_uuid, epoch) fetched once at sweep
    /// start via [`envelope_ops::read_local_identity`]. Idempotent (SPENV
    /// magic skip per row); a full pass that finds zero v1 rows records
    /// the `v2_blob_sweep_complete` flag. Called post-unlock, best-effort:
    /// any propagated error rolls the transaction back whole and retries
    /// on the next open — it never fails the unlock.
    ///
    /// Trigger note (WBS-409): the sweep never touches sync bookkeeping.
    /// Historically this required an in-transaction capture/drop/recreate
    /// of the `update_entry_modified_timestamp` echo trigger, which fired
    /// on the blob UPDATEs; the schema v9 migration dropped the trigger
    /// (both shapes) before any sweep can run, so the neutralization is
    /// gone.
    pub fn sweep_v1_blobs_to_v2(&self) -> Result<V2BlobSweepReport> {
        if !self.is_unlocked() {
            return Err(PasswordManagerError::VaultLocked);
        }
        let dek = self.key_hierarchy.dek()?;
        let db = self.lock_db()?;
        let (vault_uuid, epoch) = envelope_ops::read_local_identity(db.conn())?;
        let tx = db
            .conn()
            .unchecked_transaction()
            .map_err(DatabaseError::Sqlite)?;

        let mut report = V2BlobSweepReport::default();
        sweep_entry_rows(&tx, dek, &vault_uuid, epoch, &mut report)?;
        sweep_three_part_rows(
            &tx,
            dek,
            &vault_uuid,
            epoch,
            &mut report,
            "ssh_keys",
            "key_id",
            "private_key_encrypted",
            ObjectType::SshKey,
            &|dek, blob, nonce, tag| crate::ssh::SshKey::decrypt_private_key(dek, blob, nonce, tag),
        )?;
        sweep_three_part_rows(
            &tx,
            dek,
            &vault_uuid,
            epoch,
            &mut report,
            "totp_secrets",
            "totp_id",
            "secret_encrypted",
            ObjectType::TotpSecret,
            // v1 TOTP blobs hold the NORMALIZED secret; decrypt_totp_secret
            // returns the normalized plaintext, which is what gets sealed.
            &|dek, blob, nonce, tag| crate::totp::decrypt_totp_secret(dek, blob, nonce, tag),
        )?;

        // Terminal state for DETERMINISTIC failures (gate review,
        // finding 2): decrypt/seal failures are input-determined — the
        // same row fails identically on every pass — so a pass that
        // converts nothing while rows still fail records the completion
        // flag WITH a residual annotation and stops re-running. Without
        // this, one corrupt or cap-exceeding row re-scans the whole vault
        // at every open forever. The rows stay byte-untouched (readable
        // via dual-read if decryptable; otherwise every read fails closed
        // — the standing tamper signal). Clear the registry key to retry.
        if report.converted == 0 && (report.skipped_unreadable > 0 || report.failed > 0) {
            set_sweep_complete_flag(
                &tx,
                &format!(
                    "residual: {} unreadable + {} failed rows left as-is (deterministic                      failures; clear this key to retry)",
                    report.skipped_unreadable, report.failed
                ),
            )?;
        } else if report.converted == 0 && report.skipped_unreadable == 0 && report.failed == 0 {
            set_sweep_complete_flag(&tx, &Utc::now().to_rfc3339())?;
        }
        tx.commit().map_err(DatabaseError::Sqlite)?;

        tracing::info!(
            scanned = report.scanned,
            converted = report.converted,
            skipped_unreadable = report.skipped_unreadable,
            failed = report.failed,
            "v1-to-v2 blob sweep pass complete"
        );

        if report.converted > 0 {
            if let Some(ref logger) = self.audit_logger {
                let _ = logger.log(
                    crate::audit::AuditEventType::V2BlobMigration,
                    &format!(
                        "v1-to-v2 blob sweep: {} converted, {} skipped (unreadable), {} \
                         failed seal/verify, of {} rows",
                        report.converted, report.skipped_unreadable, report.failed, report.scanned
                    ),
                );
            }
        }

        Ok(report)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::crypto::cipher::{encrypt_entry, encrypt_string};

    fn test_vault() -> VaultManager {
        VaultManager::create(":memory:", b"v2sweep_test_password").unwrap()
    }

    fn ser_entry(e: &crate::crypto::EncryptedEntry) -> Vec<u8> {
        bincode::serialize(e).unwrap()
    }

    /// Hand-insert a legacy v1 entry row: context-free bincode blobs, the
    /// exact shape every pre-WBS-304 row has. Bookkeeping defaults to
    /// `sync_version = 1, sync_state = 'synced', modified_at = 1700000000`.
    fn insert_v1_entry(
        vault: &VaultManager,
        sync_id: Option<&str>,
        title: &str,
        username: &str,
        password: &str,
        url: Option<&str>,
        notes: Option<&str>,
    ) -> i64 {
        let dek = vault.key_hierarchy.dek().unwrap();
        let t = encrypt_string(dek, title).unwrap();
        let u = encrypt_string(dek, username).unwrap();
        let p = encrypt_string(dek, password).unwrap();
        let url_e = url.map(|s| encrypt_string(dek, s).unwrap());
        let notes_e = notes.map(|s| encrypt_string(dek, s).unwrap());
        let db = vault.lock_db().unwrap();
        db.conn()
            .execute(
                "INSERT INTO entries (vault_id, title, username, password, url, notes,
                    credential_type, entry_nonce, auth_tag, created_at, modified_at,
                    favorite, sync_id, sync_version, sync_state)
                 VALUES (1, ?1, ?2, ?3, ?4, ?5, 'password', ?6, ?7, 1700000000,
                         1700000000, 0, ?8, 1, 'synced')",
                rusqlite::params![
                    ser_entry(&t),
                    ser_entry(&u),
                    ser_entry(&p),
                    url_e.as_ref().map(ser_entry),
                    notes_e.as_ref().map(ser_entry),
                    bincode::serialize(&t.nonce).unwrap(),
                    bincode::serialize(&t.auth_tag).unwrap(),
                    sync_id,
                ],
            )
            .unwrap();
        db.conn().last_insert_rowid()
    }

    /// Hand-insert a legacy v1 ssh_keys row: three-part (ct, nonce, tag)
    /// private-key columns, the exact pre-WBS-304 shape.
    fn insert_v1_ssh(vault: &VaultManager, sync_id: Option<&str>, private_key: &str) -> i64 {
        let dek = vault.key_hierarchy.dek().unwrap();
        let encrypted = encrypt_entry(dek, private_key.as_bytes()).unwrap();
        let db = vault.lock_db().unwrap();
        db.conn()
            .execute(
                "INSERT INTO ssh_keys (name, comment, key_type, key_size, public_key,
                    private_key_encrypted, nonce, auth_tag, fingerprint, created_at,
                    modified_at, sync_id)
                 VALUES ('deploy-key', NULL, 'ED25519', NULL, 'ssh-ed25519 AAAATEST',
                         ?1, ?2, ?3, 'SHA256:testfp', 1700000000, 1700000000, ?4)",
                rusqlite::params![
                    encrypted.ciphertext,
                    encrypted.nonce.to_vec(),
                    encrypted.auth_tag.to_vec(),
                    sync_id,
                ],
            )
            .unwrap();
        db.conn().last_insert_rowid()
    }

    /// Hand-insert a legacy v1 totp_secrets row. `secret` must already be
    /// NORMALIZED (base32, no separators) — that is what v1 blobs store.
    fn insert_v1_totp(
        vault: &VaultManager,
        entry_id: i64,
        sync_id: Option<&str>,
        secret: &str,
    ) -> i64 {
        let dek = vault.key_hierarchy.dek().unwrap();
        let encrypted = encrypt_string(dek, secret).unwrap();
        let db = vault.lock_db().unwrap();
        db.conn()
            .execute(
                "INSERT INTO totp_secrets (entry_id, secret_encrypted, nonce, auth_tag,
                    algorithm, digits, period, created_at, sync_id)
                 VALUES (?1, ?2, ?3, ?4, 'SHA1', 6, 30, 1700000000, ?5)",
                rusqlite::params![
                    entry_id,
                    encrypted.ciphertext,
                    encrypted.nonce.to_vec(),
                    encrypted.auth_tag.to_vec(),
                    sync_id,
                ],
            )
            .unwrap();
        db.conn().last_insert_rowid()
    }

    fn one_blob(vault: &VaultManager, sql: &str, id: i64) -> Vec<u8> {
        let db = vault.lock_db().unwrap();
        db.conn()
            .query_row(sql, rusqlite::params![id], |row| row.get(0))
            .unwrap()
    }

    fn entry_row_flags(vault: &VaultManager, entry_id: i64) -> (i64, String, i64) {
        let db = vault.lock_db().unwrap();
        db.conn()
            .query_row(
                "SELECT sync_version, sync_state, modified_at FROM entries
                 WHERE entry_id = ?1",
                rusqlite::params![entry_id],
                |row| Ok((row.get(0)?, row.get(1)?, row.get(2)?)),
            )
            .unwrap()
    }

    // --- P: legacy rows -> sweep -> v2, reading back identically ----------

    #[test]
    fn sweep_converts_legacy_entry_and_reads_back_identically() {
        let vault = test_vault();
        let sid = uuid::Uuid::new_v4().to_string();
        let entry_id = insert_v1_entry(
            &vault,
            Some(&sid),
            "Legacy Site",
            "legacy@example.com",
            "legacy-pass",
            Some("https://legacy.example.com"),
            Some("top secret notes"),
        );

        let report = vault.sweep_v1_blobs_to_v2().unwrap();
        assert_eq!(report.scanned, 1);
        assert_eq!(report.converted, 1);
        assert_eq!(report.skipped_unreadable, 0);
        assert_eq!(report.failed, 0);

        // Every blob column is now a v2 envelope.
        {
            let db = vault.lock_db().unwrap();
            for col in ["title", "username", "password", "url", "notes"] {
                let blob: Vec<u8> = db
                    .conn()
                    .query_row(
                        &format!("SELECT {col} FROM entries WHERE entry_id = ?1"),
                        rusqlite::params![entry_id],
                        |r| r.get(0),
                    )
                    .unwrap();
                assert!(
                    blob.starts_with(crate::crypto::ENVELOPE_MAGIC),
                    "{col} must be a v2 envelope after the sweep"
                );
            }
        }

        // The public API reads back IDENTICAL plaintext.
        let fetched = vault.get_entry(entry_id).unwrap();
        assert_eq!(fetched.title, "Legacy Site");
        assert_eq!(fetched.username, "legacy@example.com");
        assert_eq!(fetched.password.as_str(), "legacy-pass");
        assert_eq!(fetched.url.as_deref(), Some("https://legacy.example.com"));
        assert_eq!(fetched.notes.as_deref(), Some("top secret notes"));
        assert_eq!(vault.list_entries().unwrap()[0].title, "Legacy Site");
    }

    #[test]
    fn sweep_is_idempotent_and_sets_the_completion_flag() {
        let vault = test_vault();
        assert!(vault.v2_blob_sweep_needed().unwrap());

        insert_v1_entry(
            &vault,
            Some(&uuid::Uuid::new_v4().to_string()),
            "A",
            "u",
            "p",
            None,
            None,
        );
        let first = vault.sweep_v1_blobs_to_v2().unwrap();
        assert_eq!(first.converted, 1);
        // A pass that CONVERTED rows did not find zero v1 rows: the flag
        // stays unset so the next open confirms with a clean pass.
        assert!(vault.v2_blob_sweep_needed().unwrap());

        let second = vault.sweep_v1_blobs_to_v2().unwrap();
        assert_eq!(second.converted, 0, "completed sweep must be a no-op");
        assert_eq!(second.scanned, 1);
        assert!(
            !vault.v2_blob_sweep_needed().unwrap(),
            "zero-v1 pass records completion"
        );

        // A vault that never had v1 rows flags completion on its first pass.
        let fresh = test_vault();
        fresh
            .add_entry(&crate::vault::Entry {
                entry_id: None,
                title: "Fresh".to_string(),
                username: "u".to_string(),
                password: "p".to_string().into(),
                url: None,
                notes: None,
                credential_type: crate::vault::CredentialType::Password,
                created_at: Utc::now(),
                modified_at: Utc::now(),
                favorite: false,
            })
            .unwrap();
        let report = fresh.sweep_v1_blobs_to_v2().unwrap();
        assert_eq!(report.converted, 0);
        assert!(!fresh.v2_blob_sweep_needed().unwrap());
    }

    #[test]
    fn sweep_mints_sync_ids_for_identityless_legacy_rows() {
        let vault = test_vault();
        let entry_id = insert_v1_entry(&vault, None, "NoId", "u", "p", None, None);
        let ssh_id = insert_v1_ssh(&vault, None, "-----BEGIN OPENSSH PRIVATE KEY-----K");
        let totp_id = insert_v1_totp(&vault, entry_id, None, "JBSWY3DPEHPK3PXP");

        let report = vault.sweep_v1_blobs_to_v2().unwrap();
        assert_eq!(report.converted, 3);

        // Each row gained a real UUID identity, and its blob is v2 now.
        let blob_columns = [
            ("entries", "entry_id", "password", entry_id),
            ("ssh_keys", "key_id", "private_key_encrypted", ssh_id),
            ("totp_secrets", "totp_id", "secret_encrypted", totp_id),
        ];
        for (table, id_column, blob_column, id) in blob_columns {
            let (sid, blob): (String, Vec<u8>) = {
                let db = vault.lock_db().unwrap();
                db.conn()
                    .query_row(
                        &format!(
                            "SELECT sync_id, {blob_column} FROM {table} WHERE {id_column} = ?1"
                        ),
                        rusqlite::params![id],
                        |r| Ok((r.get(0)?, r.get(1)?)),
                    )
                    .unwrap_or_else(|e| panic!("row in {table}: {e}"))
            };
            assert!(
                uuid::Uuid::parse_str(&sid).is_ok(),
                "{table} row must have a minted UUID sync_id, got {sid}"
            );
            assert!(
                blob.starts_with(crate::crypto::ENVELOPE_MAGIC),
                "{table} blob must be v2 after identity minting"
            );
        }

        // The public API works through the minted identities.
        assert!(vault.get_entry(entry_id).is_ok());
        assert_eq!(
            vault.export_ssh_private_key(ssh_id).unwrap(),
            "-----BEGIN OPENSSH PRIVATE KEY-----K"
        );
        assert!(vault.generate_totp_code(entry_id).is_ok());
    }

    #[test]
    fn sweep_converts_ssh_and_totp_three_part_blobs() {
        let vault = test_vault();
        let entry_id = insert_v1_entry(
            &vault,
            Some(&uuid::Uuid::new_v4().to_string()),
            "E",
            "u",
            "p",
            None,
            None,
        );
        let pem = "-----BEGIN OPENSSH PRIVATE KEY-----TEST-----END";
        let ssh_id = insert_v1_ssh(&vault, Some(&uuid::Uuid::new_v4().to_string()), pem);
        let totp_sid = uuid::Uuid::new_v4().to_string();
        let totp_id = insert_v1_totp(&vault, entry_id, Some(&totp_sid), "JBSWY3DPEHPK3PXP");
        // Pre-set ssh/totp bookkeeping to prove the sweep leaves it alone
        // (these tables have no trigger, so the UPDATE must not touch it).
        {
            let db = vault.lock_db().unwrap();
            db.conn()
                .execute(
                    "UPDATE ssh_keys SET sync_version = 5, sync_state = 'synced' WHERE key_id = ?1",
                    [ssh_id],
                )
                .unwrap();
            db.conn()
                .execute(
                    "UPDATE totp_secrets SET sync_version = 4, sync_state = 'synced'
                     WHERE totp_id = ?1",
                    [totp_id],
                )
                .unwrap();
        }
        let pem_before = vault.export_ssh_private_key(ssh_id).unwrap();

        let report = vault.sweep_v1_blobs_to_v2().unwrap();
        assert_eq!(report.converted, 3);

        let pk_blob = one_blob(
            &vault,
            "SELECT private_key_encrypted FROM ssh_keys WHERE key_id = ?1",
            ssh_id,
        );
        let totp_blob = one_blob(
            &vault,
            "SELECT secret_encrypted FROM totp_secrets WHERE totp_id = ?1",
            totp_id,
        );
        assert!(pk_blob.starts_with(crate::crypto::ENVELOPE_MAGIC));
        assert!(totp_blob.starts_with(crate::crypto::ENVELOPE_MAGIC));

        // Public API reads back identically.
        assert_eq!(vault.export_ssh_private_key(ssh_id).unwrap(), pem_before);
        assert_eq!(vault.export_ssh_private_key(ssh_id).unwrap(), pem);
        let code = vault.generate_totp_code(entry_id).unwrap();
        assert_eq!(code.code.len(), 6);

        // The sealed TOTP plaintext is the NORMALIZED secret.
        let vault_uuid = vault.vault_uuid_str().unwrap().to_string();
        let normalized = envelope_ops::open_object_field(
            vault.key_hierarchy.dek().unwrap(),
            Some(&vault_uuid),
            Some(&totp_sid),
            ObjectType::TotpSecret,
            EnvelopePurpose::Secret,
            &totp_blob,
        )
        .unwrap();
        assert_eq!(normalized.as_str(), "JBSWY3DPEHPK3PXP");

        // No sync bookkeeping moved (no triggers on these tables; the
        // sweep's UPDATE only touches blob columns + sync_id).
        let db = vault.lock_db().unwrap();
        let (ssh_v, ssh_state): (i64, String) = db
            .conn()
            .query_row(
                "SELECT sync_version, sync_state FROM ssh_keys WHERE key_id = ?1",
                [ssh_id],
                |r| Ok((r.get(0)?, r.get(1)?)),
            )
            .unwrap();
        let (totp_v, totp_state): (i64, String) = db
            .conn()
            .query_row(
                "SELECT sync_version, sync_state FROM totp_secrets WHERE totp_id = ?1",
                [totp_id],
                |r| Ok((r.get(0)?, r.get(1)?)),
            )
            .unwrap();
        assert_eq!((ssh_v, ssh_state.as_str()), (5, "synced"));
        assert_eq!((totp_v, totp_state.as_str()), (4, "synced"));
    }

    #[test]
    fn sweep_converts_only_v1_rows_in_a_mixed_vault() {
        let vault = test_vault();
        // v2 rows (born sealed).
        let v2_entry = vault
            .add_entry(&crate::vault::Entry {
                entry_id: None,
                title: "Born V2".to_string(),
                username: "u".to_string(),
                password: "v2-pass".to_string().into(),
                url: None,
                notes: None,
                credential_type: crate::vault::CredentialType::Password,
                created_at: Utc::now(),
                modified_at: Utc::now(),
                favorite: false,
            })
            .unwrap();
        let v2_ssh = vault
            .add_ssh_key_plaintext(
                "v2-key".to_string(),
                None,
                crate::ssh::SshKeyType::Ed25519,
                None,
                "ssh-ed25519 AAAAV2".to_string(),
                "-----BEGIN OPENSSH PRIVATE KEY-----V2".to_string(),
                "SHA256:v2fp".to_string(),
            )
            .unwrap();
        // v1 rows (hand-inserted legacy).
        let v1_entry = insert_v1_entry(
            &vault,
            Some(&uuid::Uuid::new_v4().to_string()),
            "Born V1",
            "v1@u",
            "v1-pass",
            None,
            None,
        );
        let v1_ssh = insert_v1_ssh(
            &vault,
            Some(&uuid::Uuid::new_v4().to_string()),
            "-----BEGIN OPENSSH PRIVATE KEY-----V1",
        );

        let v2_pass_before = one_blob(
            &vault,
            "SELECT password FROM entries WHERE entry_id = ?1",
            v2_entry,
        );
        let v2_ssh_before = one_blob(
            &vault,
            "SELECT private_key_encrypted FROM ssh_keys WHERE key_id = ?1",
            v2_ssh,
        );

        let report = vault.sweep_v1_blobs_to_v2().unwrap();
        assert_eq!(report.scanned, 4);
        assert_eq!(report.converted, 2, "only the v1 rows convert");

        // v2 rows byte-identical (skipped, not rewritten).
        assert_eq!(
            one_blob(
                &vault,
                "SELECT password FROM entries WHERE entry_id = ?1",
                v2_entry
            ),
            v2_pass_before
        );
        assert_eq!(
            one_blob(
                &vault,
                "SELECT private_key_encrypted FROM ssh_keys WHERE key_id = ?1",
                v2_ssh
            ),
            v2_ssh_before
        );
        // v1 rows are envelopes now and read correctly.
        assert!(one_blob(
            &vault,
            "SELECT password FROM entries WHERE entry_id = ?1",
            v1_entry
        )
        .starts_with(crate::crypto::ENVELOPE_MAGIC));
        assert!(one_blob(
            &vault,
            "SELECT private_key_encrypted FROM ssh_keys WHERE key_id = ?1",
            v1_ssh
        )
        .starts_with(crate::crypto::ENVELOPE_MAGIC));
        assert_eq!(
            vault.get_entry(v1_entry).unwrap().password.as_str(),
            "v1-pass"
        );
        assert_eq!(
            vault.get_entry(v2_entry).unwrap().password.as_str(),
            "v2-pass"
        );
    }

    /// THE hook test: the sweep runs as part of `VaultManager::open`, so a
    /// legacy vault is converted by the act of opening it — no explicit
    /// call. The second open records completion.
    #[test]
    fn open_hook_converts_legacy_rows_on_reopen() {
        fn temp_vault_path(name: &str) -> std::path::PathBuf {
            std::env::temp_dir().join(format!(
                "sp-wbs404-{}-{}.db",
                name,
                uuid::Uuid::new_v4().simple()
            ))
        }
        fn cleanup(path: &std::path::Path) {
            let _ = std::fs::remove_file(path);
            let _ = std::fs::remove_file(crate::vault::epoch_guard::sidecar_path(path));
        }

        let path = temp_vault_path("hook");
        {
            let vault = VaultManager::create(&path, b"correct-horse-battery").unwrap();
            insert_v1_entry(
                &vault,
                Some(&uuid::Uuid::new_v4().to_string()),
                "Hooked",
                "u",
                "hook-pass",
                None,
                None,
            );
        }

        let reopened = VaultManager::open(&path, b"correct-horse-battery").unwrap();
        let entry_id: i64 = {
            let db = reopened.lock_db().unwrap();
            db.conn()
                .query_row("SELECT entry_id FROM entries", [], |r| r.get(0))
                .unwrap()
        };
        assert!(
            one_blob(
                &reopened,
                "SELECT password FROM entries WHERE entry_id = ?1",
                entry_id
            )
            .starts_with(crate::crypto::ENVELOPE_MAGIC),
            "the open hook must have converted the legacy row"
        );
        assert_eq!(
            reopened.get_entry(entry_id).unwrap().password.as_str(),
            "hook-pass"
        );
        assert!(
            reopened.v2_blob_sweep_needed().unwrap(),
            "conversion pass is not a zero-v1 pass"
        );

        drop(reopened);
        let second = VaultManager::open(&path, b"correct-horse-battery").unwrap();
        assert!(
            !second.v2_blob_sweep_needed().unwrap(),
            "second open confirms completion"
        );
        drop(second);
        cleanup(&path);
    }

    // --- N: corruption, seal failures, sync interplay ---------------------

    #[test]
    fn sweep_skips_corrupt_v1_blob_untouched_and_converts_the_rest() {
        let vault = test_vault();
        let corrupt_id = insert_v1_entry(
            &vault,
            Some(&uuid::Uuid::new_v4().to_string()),
            "Corrupt",
            "u",
            "p",
            None,
            None,
        );
        let healthy_id = insert_v1_entry(
            &vault,
            Some(&uuid::Uuid::new_v4().to_string()),
            "Healthy",
            "u",
            "healthy-pass",
            None,
            None,
        );
        // Corrupt row A: truncated garbage in the password column.
        let garbage = vec![0xDEu8, 0xAD, 0xBE, 0xEF, 0x00, 0x01, 0x02];
        {
            let db = vault.lock_db().unwrap();
            db.conn()
                .execute(
                    "UPDATE entries SET password = ?1 WHERE entry_id = ?2",
                    rusqlite::params![garbage, corrupt_id],
                )
                .unwrap();
        }

        let report = vault.sweep_v1_blobs_to_v2().unwrap();
        assert_eq!(report.scanned, 2);
        assert_eq!(report.converted, 1, "the healthy row converts");
        assert_eq!(report.skipped_unreadable, 1, "the corrupt row is skipped");

        // The corrupt row's blob is byte-identical (never dropped or
        // overwritten), and the public API fails CLOSED on it.
        assert_eq!(
            one_blob(
                &vault,
                "SELECT password FROM entries WHERE entry_id = ?1",
                corrupt_id
            ),
            garbage
        );
        let err = vault.get_entry(corrupt_id).unwrap_err();
        assert!(
            err.to_string().contains("Serialization") || err.to_string().contains("deserialize"),
            "expected a clean typed refusal, got: {err}"
        );
        // The healthy row converted and reads fine.
        assert_eq!(
            vault.get_entry(healthy_id).unwrap().password.as_str(),
            "healthy-pass"
        );

        // Skipped rows keep the completion flag unset: the next pass retries.
        assert!(vault.v2_blob_sweep_needed().unwrap());
        let retry = vault.sweep_v1_blobs_to_v2().unwrap();
        assert_eq!(
            retry.skipped_unreadable, 1,
            "the corrupt row is retried, still untouched"
        );
        assert_eq!(retry.converted, 0);
    }

    #[test]
    fn sweep_does_not_write_rows_that_fail_seal_verification() {
        let vault = test_vault();
        // A plaintext over the Secret field-class cap fails at seal; the
        // whole row must be refused (nothing written), not partially.
        let oversized = "x".repeat(envelope_ops::MAX_SECRET_PLAINTEXT + 1);
        let entry_id = insert_v1_entry(
            &vault,
            Some(&uuid::Uuid::new_v4().to_string()),
            "TooBig",
            "u",
            &oversized,
            Some("https://keep-me.example"),
            None,
        );
        let before: (Vec<u8>, Vec<u8>, Vec<u8>, Option<Vec<u8>>) = {
            let db = vault.lock_db().unwrap();
            db.conn()
                .query_row(
                    "SELECT title, password, entry_nonce, url FROM entries WHERE entry_id = ?1",
                    rusqlite::params![entry_id],
                    |r| Ok((r.get(0)?, r.get(1)?, r.get(2)?, r.get(3)?)),
                )
                .unwrap()
        };

        let report = vault.sweep_v1_blobs_to_v2().unwrap();
        assert_eq!(report.failed, 1);
        assert_eq!(report.converted, 0);

        // NOTHING on the row moved: still v1 everywhere, same nonce column.
        let after: (Vec<u8>, Vec<u8>, Vec<u8>, Option<Vec<u8>>) = {
            let db = vault.lock_db().unwrap();
            db.conn()
                .query_row(
                    "SELECT title, password, entry_nonce, url FROM entries WHERE entry_id = ?1",
                    rusqlite::params![entry_id],
                    |r| Ok((r.get(0)?, r.get(1)?, r.get(2)?, r.get(3)?)),
                )
                .unwrap()
        };
        assert_eq!(
            before, after,
            "a failed seal/verify must leave the row untouched"
        );
        assert!(!after.1.starts_with(crate::crypto::ENVELOPE_MAGIC));

        // Terminal state (gate review, finding 2): the deterministic
        // failure dead-letters — the completion flag records the residual
        // and the sweep stops re-running at every open forever. The row
        // itself stays byte-untouched; clearing the registry key retries.
        assert!(
            !vault.v2_blob_sweep_needed().unwrap(),
            "a deterministic failure must dead-letter, not retry forever"
        );
        {
            let db = vault.lock_db().unwrap();
            let marker: String = db
                .conn()
                .query_row(
                    "SELECT value FROM registry_state WHERE key = 'v2_blob_sweep_complete'",
                    [],
                    |r| r.get(0),
                )
                .unwrap();
            assert!(
                marker.contains("residual"),
                "expected the residual annotation, got: {marker}"
            );
        }
    }

    /// THE sync-interplay property (adversarial pre-check A1, post-WBS-409
    /// shape): converting a row does NOT re-mark it pending — sync_version,
    /// sync_state, and modified_at are byte-identical after the sweep,
    /// because the sweep writes only blob columns and (since schema v9) no
    /// echo trigger exists to stamp bookkeeping behind its back.
    /// The CONTROL at the end proves a real update still bumps via the
    /// repository's EXPLICIT bookkeeping, so a regression on either side
    /// (sweep touching bookkeeping, or local edits losing theirs) is
    /// caught by this test.
    #[test]
    fn sweep_does_not_remark_converted_rows_pending() {
        let vault = test_vault();
        let entry_id = insert_v1_entry(
            &vault,
            Some(&uuid::Uuid::new_v4().to_string()),
            "SyncedRow",
            "u",
            "sync-pass",
            None,
            None,
        );
        {
            let db = vault.lock_db().unwrap();
            db.conn()
                .execute(
                    "UPDATE entries SET sync_version = 7, sync_state = 'synced',
                     modified_at = 1234567 WHERE entry_id = ?1",
                    [entry_id],
                )
                .unwrap();
        }

        vault.sweep_v1_blobs_to_v2().unwrap();

        // Converted to v2 AND bookkeeping untouched.
        assert!(one_blob(
            &vault,
            "SELECT password FROM entries WHERE entry_id = ?1",
            entry_id
        )
        .starts_with(crate::crypto::ENVELOPE_MAGIC));
        assert_eq!(
            entry_row_flags(&vault, entry_id),
            (7, "synced".to_string(), 1234567)
        );

        // CONTROL: a real update DOES bump (the trigger is live, so the
        // sweep's suppression above is deliberate, not vacuous).
        let mut entry = vault.get_entry(entry_id).unwrap();
        entry.title = "SyncedRow Edited".to_string();
        vault.update_entry(entry_id, &entry).unwrap();
        let (version, state, _) = entry_row_flags(&vault, entry_id);
        assert_eq!(version, 8, "the control update must bump sync_version");
        assert_eq!(state, "pending", "the control update must re-mark pending");
    }
}
