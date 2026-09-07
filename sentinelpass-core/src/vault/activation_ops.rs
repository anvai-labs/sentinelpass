//! Full-vault verification pass (WBS-405) and atomic v2-format activation
//! (WBS-406) — the trust statement that closes the v2-migration story.
//!
//! # Verify before activation (WBS-405, TV-005)
//!
//! [`VaultManager::sweep_v1_blobs_to_v2`] (WBS-404) re-encrypts legacy blobs
//! with per-row verify-before-write, but its completion flag only proves
//! "no v1-magic rows remain". Before the migration is considered
//! TRUSTWORTHY, every converted envelope — and every relation — must be
//! proven to decrypt and authenticate UNDER ITS IDENTITY:
//!
//! - `entries`: all five field envelopes (title/username = Summary,
//!   password/url/notes = Secret) open against the row's
//!   (vault_uuid, sync_id, credential class);
//! - `ssh_keys.private_key_encrypted` / `totp_secrets.secret_encrypted`:
//!   the v2 envelope opens against the row's identity;
//! - `domain_mappings`: the sealed domain opens, and the stored
//!   `domain_mapping_tags` rows are EXACTLY the chain tags of the
//!   decrypted host (the tag/envelope integrity contract from WBS-306,
//!   applied vault-wide, not just per lookup candidate).
//!
//! The pass is STRICTLY READ-ONLY: a blob that fails to open is reported
//! in [`VaultVerificationReport::failures`] with its table, row id, and
//! column — never modified, never dropped. Rows still holding healthy
//! legacy (v1) blobs are counted separately ([`VaultVerificationReport::rows_still_v1`])
//! so "not yet converted" is distinguishable from "corrupt".
//!
//! # Atomic activation; block downgrade (WBS-406, SR-CRYPTO-005, TD-ROB-07)
//!
//! [`VaultManager::activate_v2_format`] turns a clean verification report
//! into the durable ACTIVATED marker: `db_metadata.format_version` is
//! bumped to [`CURRENT_VAULT_FORMAT_VERSION`] (2) and a
//! `v2_format_activated` registry-state row records the verified-at
//! timestamp — ONE transaction, so the marker pair cannot tear. The
//! format column already existed (added by the v6 migration, documented
//! there as "starts at 1 — the envelope-v2 format is a later, deliberate
//! migration"); activation is that deliberate migration's commit point.
//!
//! Downgrade blocking, by layer:
//! - an OLDER binary opening an activated vault fails at its OWN v1
//!   context-free readers (a SPENV document is not bincode — the
//!   `older_v1_client_cannot_read_activated_vault_blobs` test pins the
//!   loud typed failure per blob family), and post-WBS-315 binaries
//!   refuse the newer schema/format at the version probe outright;
//! - THIS and any future build refuse `format_version` GREATER than the
//!   supported constant at the very first read of every open path
//!   (`schema::Database::validate_schema_version`, typed
//!   [`crate::DatabaseError::UnsupportedFutureFormat`]) — the
//!   downgrade-block twin of the WBS-315 schema gate;
//! - no write path demotes a v2 row: `update_entry` keeps v2 rows on the
//!   v2 path and refuses mixed-format rows (WBS-304 gate review), the
//!   sweep only ever writes v2, and activation is never cleared by any
//!   migration or rotation (the epoch-guard material digest deliberately
//!   excludes `format_version`).
//!
//! Much of WBS-406 already held before this module (verified, not
//! assumed): the newer-schema fail-closed gate and its
//! gate-runs-first test (WBS-315), the future envelope
//! `envelope_version`/`crypto_version` refusals at the crypto layer
//! (`crypto::envelope` fail-closed tests), the mixed-format update
//! refusal, and the create-over-existing-file guard (WBS-402). The
//! activation marker and the format gate are the only genuinely missing
//! pieces; nothing here re-implements them.
//!
//! # Open-hook placement and retry/dead-letter policy
//!
//! Like the WBS-404 sweep, activation is best-effort at open: it never
//! fails the unlock. A Blocked outcome is only dead-lettered (the
//! `v2_activation_blocked` registry key — clear it to retry) when it is
//! input-determined: named verification failures never heal by
//! themselves, and a `rows_still_v1` residual after the sweep's own
//! completion flag is recorded is likewise permanent. While the sweep is
//! still actively converting (flag absent), a Blocked report writes NO
//! marker — the next open retries after the sweep has made progress, so
//! a mid-migration vault is never falsely dead-lettered (adversarial
//! pre-check A1).
//!
//! Audit note (documented deviation): `audit.rs` is owned by a parallel
//! workstream, so activation reuses the existing `V2BlobMigration` event
//! type with an unambiguous "v2 format ACTIVATED" context string instead
//! of adding a dedicated variant; the durable record of activation is the
//! format column + registry marker, not the log.

use crate::crypto::aad::{EnvelopePurpose, ObjectType};
use crate::crypto::cipher::DataEncryptionKey;
use crate::crypto::keyring::derive_domain_tag_key;
use crate::database::schema::CURRENT_VAULT_FORMAT_VERSION;
use crate::vault::CredentialType;
use crate::{DatabaseError, PasswordManagerError, Result};
use chrono::Utc;
use rusqlite::Connection;

use super::domain_ops;
use super::envelope_ops::{self, EntryFieldIdentity};
use super::migration_ops;
use super::VaultManager;

/// Registry-state key recording the verified-at timestamp of activation.
const V2_ACTIVATED_KEY: &str = "v2_format_activated";

/// Registry-state key dead-lettering a DETERMINISTIC activation block
/// (clear this key to retry after repairing the vault).
const V2_ACTIVATION_BLOCKED_KEY: &str = "v2_activation_blocked";

/// One named verification failure: exactly which stored blob failed to
/// decrypt/authenticate, and why. `row_id` is the table's primary key;
/// `sync_id` is the envelope identity the open attempted (when the row
/// carried one).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct VaultVerificationFailure {
    pub table: &'static str,
    pub row_id: i64,
    pub sync_id: Option<String>,
    pub column: &'static str,
    pub reason: String,
}

/// Outcome of one full-vault [`VaultManager::verify_vault_envelopes`] pass.
#[derive(Debug, Default, Clone, PartialEq, Eq)]
pub struct VaultVerificationReport {
    /// `entries` rows examined.
    pub entries_scanned: usize,
    /// Individual entry field envelopes that opened and authenticated.
    pub entry_fields_verified: usize,
    /// `ssh_keys` rows examined / private-key envelopes verified.
    pub ssh_keys_scanned: usize,
    pub ssh_keys_verified: usize,
    /// `totp_secrets` rows examined / secret envelopes verified.
    pub totp_secrets_scanned: usize,
    pub totp_secrets_verified: usize,
    /// `domain_mappings` rows examined / sealed domains verified together
    /// with their tag sets.
    pub domain_mappings_scanned: usize,
    pub domain_mappings_verified: usize,
    /// Rows still holding ONLY healthy legacy (v1) blobs — decryptable,
    /// pending conversion. Distinct from failures: not yet converted is
    /// not corrupt.
    pub rows_still_v1: usize,
    /// Named blobs that FAILED to decrypt or authenticate (or rows whose
    /// stored state is structurally inconsistent). Never modified by the
    /// pass — a failure here is a report, not a repair.
    pub failures: Vec<VaultVerificationFailure>,
}

impl VaultVerificationReport {
    /// True when every scanned blob is a verified v2 envelope (or an
    /// absent optional field) and every relation is consistent: the only
    /// state activation may stamp.
    pub fn is_clean(&self) -> bool {
        self.failures.is_empty() && self.rows_still_v1 == 0
    }

    /// One-line human summary for logs and the blocked marker value.
    pub fn summary_line(&self) -> String {
        format!(
            "entries={} ({} fields), ssh={}, totp={}, mappings={} verified; \
             {} rows still v1, {} failures",
            self.entries_scanned,
            self.entry_fields_verified,
            self.ssh_keys_verified,
            self.totp_secrets_verified,
            self.domain_mappings_verified,
            self.rows_still_v1,
            self.failures.len(),
        )
    }
}

/// Result of [`VaultManager::activate_v2_format`].
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum V2ActivationOutcome {
    /// Verification was clean and the marker pair was committed.
    Activated { verified_at: String },
    /// `format_version` already records the activated format — no-op.
    AlreadyActivated,
    /// Verification found something. `dead_lettered` tells the caller
    /// whether the block was recorded as deterministic (true) or will be
    /// retried on the next open because the migration may still progress
    /// (false).
    Blocked {
        report: VaultVerificationReport,
        dead_lettered: bool,
    },
}

/// The per-row blob format classification the pass is built on.
fn is_envelope(blob: &[u8]) -> bool {
    envelope_ops::is_envelope_blob(blob)
}

/// Open one present entry column under the row identity (dual-read: v2
/// envelope against the identity, legacy bincode without it).
fn open_entry_column(
    dek: &DataEncryptionKey,
    identity: &EntryFieldIdentity<'_>,
    purpose: EnvelopePurpose,
    blob: &[u8],
) -> Result<zeroize::Zeroizing<String>> {
    envelope_ops::open_entry_field_with_identity(dek, Some(*identity), purpose, blob)
}

// ---------------------------------------------------------------------------
// Entries
// ---------------------------------------------------------------------------

/// One scan row of `entries`: (entry_id, sync_id, credential_type,
/// title, username, password, url, notes).
type EntryVerifyRow = (
    i64,
    Option<String>,
    String,
    Vec<u8>,
    Vec<u8>,
    Vec<u8>,
    Option<Vec<u8>>,
    Option<Vec<u8>>,
);

fn verify_entry_rows(
    conn: &Connection,
    dek: &DataEncryptionKey,
    vault_uuid: &str,
    report: &mut VaultVerificationReport,
) -> Result<()> {
    let rows: Vec<EntryVerifyRow> = {
        let mut stmt = conn
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
        report.entries_scanned += 1;

        let cred = match CredentialType::parse(&credential_type) {
            Ok(cred) => cred,
            Err(e) => {
                report.failures.push(VaultVerificationFailure {
                    table: "entries",
                    row_id: entry_id,
                    sync_id: sync_id.clone(),
                    column: "credential_type",
                    reason: format!("envelope identity class cannot be established: {e}"),
                });
                continue;
            }
        };
        let identity = EntryFieldIdentity {
            vault_uuid,
            sync_id: sync_id.as_deref().unwrap_or(""),
            cred,
        };

        // Present columns only (a NULL optional column is format-neutral:
        // absence is NULL, never a v1 blob).
        let present: Vec<(&'static str, EnvelopePurpose, &Vec<u8>)> = [
            ("title", EnvelopePurpose::Summary, Some(&title)),
            ("username", EnvelopePurpose::Summary, Some(&username)),
            ("password", EnvelopePurpose::Secret, Some(&password)),
            ("url", EnvelopePurpose::Secret, url.as_ref()),
            ("notes", EnvelopePurpose::Secret, notes.as_ref()),
        ]
        .into_iter()
        .filter_map(|(name, purpose, value)| value.map(|blob| (name, purpose, blob)))
        .collect();

        // Format classification across all PRESENT columns (the same
        // policy update_entry enforces per row): a mixed v1/v2 row is not
        // a legacy row — it is inconsistent stored state and is reported.
        let envelope_count = present.iter().filter(|(_, _, b)| is_envelope(b)).count();
        let legacy_count = present.len() - envelope_count;

        if envelope_count > 0 && legacy_count > 0 {
            let mixed_column = present
                .iter()
                .find(|(_, _, b)| !is_envelope(b))
                .map(|(name, _, _)| *name)
                .unwrap_or("?");
            report.failures.push(VaultVerificationFailure {
                table: "entries",
                row_id: entry_id,
                sync_id: sync_id.clone(),
                column: mixed_column,
                reason: "row has mixed v1/v2 field formats — inconsistent stored state".to_string(),
            });
            continue;
        }

        if legacy_count == present.len() {
            // Fully legacy row: healthy v1 content still decrypts via the
            // dual-read path (counted as pending, NOT a failure); a blob
            // that fails to decrypt is corruption and is named.
            let mut row_ok = true;
            for (name, purpose, blob) in &present {
                if let Err(e) = open_entry_column(dek, &identity, *purpose, blob) {
                    report.failures.push(VaultVerificationFailure {
                        table: "entries",
                        row_id: entry_id,
                        sync_id: sync_id.clone(),
                        column: name,
                        reason: format!("legacy blob failed to decrypt: {e}"),
                    });
                    row_ok = false;
                }
            }
            if row_ok {
                report.rows_still_v1 += 1;
            }
            continue;
        }

        // Fully v2 row: every present envelope MUST open under the row's
        // identity. A v2 blob with no sync_id has no identity to bind —
        // the open would refuse; report that directly.
        let Some(sid) = sync_id.as_deref() else {
            report.failures.push(VaultVerificationFailure {
                table: "entries",
                row_id: entry_id,
                sync_id: None,
                column: "sync_id",
                reason: "row holds v2 envelopes but has no stable identity — refusing \
                         (identity cannot be established)"
                    .to_string(),
            });
            continue;
        };
        let identity = EntryFieldIdentity {
            vault_uuid,
            sync_id: sid,
            cred,
        };
        for (name, purpose, blob) in &present {
            match open_entry_column(dek, &identity, *purpose, blob) {
                Ok(_) => report.entry_fields_verified += 1,
                Err(e) => report.failures.push(VaultVerificationFailure {
                    table: "entries",
                    row_id: entry_id,
                    sync_id: sync_id.clone(),
                    column: name,
                    reason: format!("v2 envelope failed to open under the row identity: {e}"),
                }),
            }
        }
    }
    Ok(())
}

// ---------------------------------------------------------------------------
// SSH keys / TOTP secrets (single secret-blob columns)
// ---------------------------------------------------------------------------

/// One scan row of the three-part families: (row_id, sync_id, blob, nonce, tag).
type ThreePartVerifyRow = (i64, Option<String>, Vec<u8>, Vec<u8>, Vec<u8>);

/// The v1 three-part reader for one family.
type ThreePartReader =
    dyn Fn(&DataEncryptionKey, &[u8], &[u8], &[u8]) -> Result<zeroize::Zeroizing<String>>;

#[allow(clippy::too_many_arguments)]
fn verify_three_part_rows(
    conn: &Connection,
    dek: &DataEncryptionKey,
    vault_uuid: &str,
    report: &mut VaultVerificationReport,
    table: &'static str,
    id_column: &str,
    blob_column: &'static str,
    object_type: ObjectType,
    v1_reader: &ThreePartReader,
) -> Result<(usize, usize)> {
    let sql = format!("SELECT {id_column}, sync_id, {blob_column}, nonce, auth_tag FROM {table}");
    let rows: Vec<ThreePartVerifyRow> = {
        let mut stmt = conn.prepare(&sql).map_err(DatabaseError::Sqlite)?;
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

    let mut scanned = 0usize;
    let mut verified = 0usize;
    for (row_id, sync_id, blob, nonce, auth_tag) in rows {
        scanned += 1;
        if is_envelope(&blob) {
            let Some(sid) = sync_id.as_deref() else {
                report.failures.push(VaultVerificationFailure {
                    table,
                    row_id,
                    sync_id: None,
                    column: "sync_id",
                    reason: "row holds a v2 envelope but has no stable identity — refusing \
                             (identity cannot be established)"
                        .to_string(),
                });
                continue;
            };
            match envelope_ops::open_object_field(
                dek,
                Some(vault_uuid),
                Some(sid),
                object_type,
                EnvelopePurpose::Secret,
                &blob,
            ) {
                Ok(_) => verified += 1,
                Err(e) => report.failures.push(VaultVerificationFailure {
                    table,
                    row_id,
                    sync_id: sync_id.clone(),
                    column: blob_column,
                    reason: format!("v2 envelope failed to open under the row identity: {e}"),
                }),
            }
        } else {
            // Legacy three-part blob: healthy v1 content decrypts (pending
            // conversion); anything else is named corruption.
            match v1_reader(dek, &blob, &nonce, &auth_tag) {
                Ok(_) => report.rows_still_v1 += 1,
                Err(e) => report.failures.push(VaultVerificationFailure {
                    table,
                    row_id,
                    sync_id: sync_id.clone(),
                    column: blob_column,
                    reason: format!("legacy blob failed to decrypt: {e}"),
                }),
            }
        }
    }
    Ok((scanned, verified))
}

// ---------------------------------------------------------------------------
// Domain mappings + tags (the relations)
// ---------------------------------------------------------------------------

/// One scan row of `domain_mappings`: (mapping_id, sync_id, domain, domain_enc).
type MappingVerifyRow = (i64, Option<String>, Option<String>, Option<Vec<u8>>);

fn verify_domain_rows(
    conn: &Connection,
    dek: &DataEncryptionKey,
    vault_uuid: &str,
    tag_key: &[u8],
    report: &mut VaultVerificationReport,
) -> Result<()> {
    let rows: Vec<MappingVerifyRow> = {
        let mut stmt = conn
            .prepare("SELECT mapping_id, sync_id, domain, domain_enc FROM domain_mappings")
            .map_err(DatabaseError::Sqlite)?;
        let collected = stmt
            .query_map([], |row| {
                Ok((row.get(0)?, row.get(1)?, row.get(2)?, row.get(3)?))
            })
            .map_err(DatabaseError::Sqlite)?
            .collect::<std::result::Result<Vec<_>, _>>()
            .map_err(DatabaseError::Sqlite)?;
        collected
    };

    for (mapping_id, sync_id, _domain, domain_enc) in rows {
        report.domain_mappings_scanned += 1;
        match domain_enc {
            Some(blob) if is_envelope(&blob) => {
                let Some(sid) = sync_id.as_deref() else {
                    report.failures.push(VaultVerificationFailure {
                        table: "domain_mappings",
                        row_id: mapping_id,
                        sync_id: None,
                        column: "sync_id",
                        reason: "row holds a sealed domain but has no stable identity — \
                                 refusing (identity cannot be established)"
                            .to_string(),
                    });
                    continue;
                };
                match domain_ops::verify_mapping_seal(
                    conn, dek, vault_uuid, tag_key, mapping_id, sid, &blob,
                ) {
                    Ok(_) => report.domain_mappings_verified += 1,
                    Err(e) => report.failures.push(VaultVerificationFailure {
                        table: "domain_mappings",
                        row_id: mapping_id,
                        sync_id: sync_id.clone(),
                        column: "domain_enc",
                        reason: format!("sealed domain/tag relation failed to verify: {e}"),
                    }),
                }
            }
            Some(_) => {
                // The sealed column only ever receives envelope documents
                // (the v8 migration adds it NULL; the sweep and sync apply
                // write envelopes). Anything else is foreign state.
                report.failures.push(VaultVerificationFailure {
                    table: "domain_mappings",
                    row_id: mapping_id,
                    sync_id: sync_id.clone(),
                    column: "domain_enc",
                    reason: "column holds a non-envelope blob — inconsistent stored state"
                        .to_string(),
                });
            }
            None => {
                // Legacy plaintext-only row: healthy pending backfill —
                // unless tag rows already exist, which the sweep never
                // produces (envelope + tags land in ONE transaction), so
                // tags without an envelope are inconsistent state.
                let tag_rows: i64 = conn
                    .query_row(
                        "SELECT COUNT(*) FROM domain_mapping_tags WHERE mapping_id = ?1",
                        [mapping_id],
                        |row| row.get(0),
                    )
                    .map_err(DatabaseError::Sqlite)?;
                if tag_rows > 0 {
                    report.failures.push(VaultVerificationFailure {
                        table: "domain_mappings",
                        row_id: mapping_id,
                        sync_id: sync_id.clone(),
                        column: "domain_mapping_tags",
                        reason: "tag rows exist without a sealed domain — inconsistent \
                                 stored state"
                            .to_string(),
                    });
                } else {
                    report.rows_still_v1 += 1;
                }
            }
        }
    }
    Ok(())
}

// ---------------------------------------------------------------------------
// VaultManager API
// ---------------------------------------------------------------------------

fn registry_value(conn: &Connection, key: &str) -> Result<Option<String>> {
    use rusqlite::OptionalExtension;
    Ok(conn
        .query_row(
            "SELECT value FROM registry_state WHERE key = ?1",
            [key],
            |row| row.get(0),
        )
        .optional()
        .map_err(DatabaseError::Sqlite)?)
}

fn set_registry_value(conn: &Connection, key: &str, value: &str) -> Result<()> {
    conn.execute(
        "INSERT INTO registry_state (key, value) VALUES (?1, ?2)
         ON CONFLICT(key) DO UPDATE SET value = excluded.value",
        rusqlite::params![key, value],
    )
    .map_err(DatabaseError::Sqlite)?;
    Ok(())
}

impl VaultManager {
    /// True when the vault's envelope format is (or exceeds) this build's
    /// ACTIVATED format — the durable downgrade-block marker (WBS-406).
    pub fn is_v2_format_activated(&self) -> Result<bool> {
        let db = self.lock_db()?;
        Ok(db.stored_format_version()? >= CURRENT_VAULT_FORMAT_VERSION)
    }

    /// True when [`Self::activate_v2_format`] has (or may still have)
    /// work to do: not yet activated and no deterministic block is on
    /// record. The open hook consults this to keep steady-state opens at
    /// one metadata SELECT.
    pub(crate) fn v2_activation_needed(&self) -> Result<bool> {
        if self.is_v2_format_activated()? {
            return Ok(false);
        }
        let db = self.lock_db()?;
        let blocked = registry_value(db.conn(), V2_ACTIVATION_BLOCKED_KEY)?;
        Ok(blocked.is_none())
    }

    /// Full-vault verification pass (WBS-405). STRICTLY READ-ONLY: proves
    /// every stored envelope — entries (all five fields), SSH private
    /// keys, TOTP secrets — decrypts and authenticates under its row
    /// identity, and every domain-mapping relation (sealed domain + tag
    /// set) is consistent. Healthy legacy rows are counted in
    /// [`VaultVerificationReport::rows_still_v1`]; corrupt or
    /// structurally inconsistent rows are NAMED in `failures` and never
    /// touched.
    pub fn verify_vault_envelopes(&self) -> Result<VaultVerificationReport> {
        if !self.is_unlocked() {
            return Err(PasswordManagerError::VaultLocked);
        }
        let dek = self.key_hierarchy.dek()?;
        let vault_uuid = self.vault_uuid_str()?.to_string();
        let tag_key = derive_domain_tag_key(dek)?;

        // ONE lock acquisition for the whole pass (the DB Mutex is not
        // reentrant — the sweep's discipline).
        let db = self.lock_db()?;
        let conn = db.conn();
        let mut report = VaultVerificationReport::default();
        verify_entry_rows(conn, dek, &vault_uuid, &mut report)?;
        let (ssh_scanned, ssh_verified) = verify_three_part_rows(
            conn,
            dek,
            &vault_uuid,
            &mut report,
            "ssh_keys",
            "key_id",
            "private_key_encrypted",
            ObjectType::SshKey,
            &|dek, blob, nonce, tag| crate::ssh::SshKey::decrypt_private_key(dek, blob, nonce, tag),
        )?;
        report.ssh_keys_scanned += ssh_scanned;
        report.ssh_keys_verified += ssh_verified;
        let (totp_scanned, totp_verified) = verify_three_part_rows(
            conn,
            dek,
            &vault_uuid,
            &mut report,
            "totp_secrets",
            "totp_id",
            "secret_encrypted",
            ObjectType::TotpSecret,
            &|dek, blob, nonce, tag| crate::totp::decrypt_totp_secret(dek, blob, nonce, tag),
        )?;
        report.totp_secrets_scanned += totp_scanned;
        report.totp_secrets_verified += totp_verified;
        verify_domain_rows(conn, dek, &vault_uuid, &tag_key, &mut report)?;
        Ok(report)
    }

    /// Attempt the atomic v2-format activation (WBS-406): a clean
    /// full-vault verification stamps `db_metadata.format_version =
    /// CURRENT_VAULT_FORMAT_VERSION` and the `v2_format_activated`
    /// verified-at marker in ONE transaction. Idempotent; a Blocked
    /// outcome is dead-lettered ONLY when it is input-determined (named
    /// failures, or legacy rows left over after the sweep's own
    /// completion flag — see the module docs).
    pub fn activate_v2_format(&self) -> Result<V2ActivationOutcome> {
        if !self.is_unlocked() {
            return Err(PasswordManagerError::VaultLocked);
        }

        // Fast idempotence path: the format column is authoritative.
        if self.is_v2_format_activated()? {
            return Ok(V2ActivationOutcome::AlreadyActivated);
        }

        // Full verification pass (its own lock scope — never held across
        // the activation transaction).
        let report = self.verify_vault_envelopes()?;
        if !report.is_clean() {
            // Deterministic ONLY if the failures can't be healed by the
            // sweep still making progress: named failures never heal on
            // their own; residual legacy rows DO heal while the sweep has
            // not yet recorded its completion flag (it converts on every
            // open until a zero-v1 pass).
            let sweep_finished = {
                let db = self.lock_db()?;
                migration_ops::v2_blob_sweep_complete(db.conn())?
            };
            let dead_letter = !report.failures.is_empty() || sweep_finished;
            if dead_letter {
                let db = self.lock_db()?;
                set_registry_value(
                    db.conn(),
                    V2_ACTIVATION_BLOCKED_KEY,
                    &format!(
                        "blocked: {} — clear this key to retry after repairing the vault",
                        report.summary_line()
                    ),
                )?;
            }
            tracing::warn!(
                summary = %report.summary_line(),
                dead_letter,
                "v2 format activation blocked: verification did not pass"
            );
            return Ok(V2ActivationOutcome::Blocked {
                report,
                dead_lettered: dead_letter,
            });
        }

        // Atomic activation: marker pair in ONE transaction (ADR-005 rev 3
        // discipline). The optimistic `format_version <` predicate makes a
        // concurrent activation race safe: exactly one writer flips the
        // column, the loser commits only the (idempotent, truthy) marker.
        let verified_at = Utc::now().to_rfc3339();
        let db = self.lock_db()?;
        let conn = db.conn();
        conn.execute_batch("BEGIN IMMEDIATE;")
            .map_err(DatabaseError::Sqlite)?;

        let inner = || -> Result<usize> {
            set_registry_value(conn, V2_ACTIVATED_KEY, &verified_at)?;
            let rows = conn.execute(
                "UPDATE db_metadata SET format_version = ?1
                 WHERE id = 1 AND COALESCE(format_version, 1) < ?1",
                rusqlite::params![CURRENT_VAULT_FORMAT_VERSION],
            );
            match rows {
                Ok(n) => Ok(n),
                Err(e) => Err(DatabaseError::Sqlite(e).into()),
            }
        };

        let outcome = match inner() {
            Ok(1) => {
                conn.execute_batch("COMMIT;")
                    .map_err(DatabaseError::Sqlite)?;
                Ok(V2ActivationOutcome::Activated { verified_at })
            }
            Ok(_) => {
                // Lost a concurrent race — the winner already flipped the
                // column; the marker we wrote is true either way.
                conn.execute_batch("COMMIT;")
                    .map_err(DatabaseError::Sqlite)?;
                Ok(V2ActivationOutcome::AlreadyActivated)
            }
            Err(e) => {
                let _ = conn.execute_batch("ROLLBACK;");
                Err(e)
            }
        };

        if let Ok(V2ActivationOutcome::Activated { ref verified_at }) = outcome {
            // Deliberately LAST, best-effort, outside the transaction.
            // (Deviation documented in the module docs: audit.rs is owned
            // by a parallel workstream, so the existing mass-migration
            // event type carries the activation context until a dedicated
            // variant lands there.)
            if let Some(ref logger) = self.audit_logger {
                let _ = logger.log(
                    crate::audit::AuditEventType::V2BlobMigration,
                    &format!(
                        "v2 format ACTIVATED (format_version = \
                         {CURRENT_VAULT_FORMAT_VERSION}) after full-vault verification: {}",
                        report.summary_line()
                    ),
                );
            }
            tracing::info!(
                verified_at = %verified_at,
                "v2 envelope format activated after verified full-vault pass"
            );
        }

        outcome
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::crypto::cipher::{decrypt_to_string, encrypt_string, EncryptedEntry};
    use crate::vault::Entry;
    use chrono::Utc;

    fn test_vault() -> VaultManager {
        VaultManager::create(":memory:", b"activation_test_password").unwrap()
    }

    fn test_entry(title: &str, password: &str) -> Entry {
        Entry {
            entry_id: None,
            title: title.to_string(),
            username: "user@example.com".to_string(),
            password: password.to_string().into(),
            url: Some("https://example.com".to_string()),
            notes: Some("notes".to_string()),
            credential_type: crate::vault::CredentialType::Password,
            created_at: Utc::now(),
            modified_at: Utc::now(),
            favorite: false,
        }
    }

    /// Build a FULLY v2 vault: born-v2 entry, SSH key, TOTP secret, and a
    /// sealed domain mapping; a confirming zero-v1 sweep pass so the
    /// sweep-completion flag is on record.
    fn fully_converted_vault() -> VaultManager {
        let vault = test_vault();
        let entry_id = vault.add_entry(&test_entry("Site", "site-pass")).unwrap();
        vault
            .add_ssh_key_plaintext(
                "deploy-key".to_string(),
                None,
                crate::ssh::SshKeyType::Ed25519,
                None,
                "ssh-ed25519 AAAATEST".to_string(),
                "-----BEGIN OPENSSH PRIVATE KEY-----TEST-----END".to_string(),
                "SHA256:testfp".to_string(),
            )
            .unwrap();
        vault
            .add_totp_secret(
                entry_id,
                "JBSWY3DPEHPK3PXP",
                crate::totp::TotpAlgorithm::Sha1,
                6,
                30,
                None,
                None,
            )
            .unwrap();
        // Legacy-shaped plaintext mapping -> the domain sweep seals it.
        {
            let db = vault.lock_db().unwrap();
            db.conn()
                .execute(
                    "INSERT INTO domain_mappings (entry_id, domain, is_primary) VALUES (?1, 'example.com', 1)",
                    [entry_id],
                )
                .unwrap();
        }
        vault.sweep_domain_mappings().unwrap();
        let first = vault.sweep_v1_blobs_to_v2().unwrap();
        assert_eq!(first.converted, 0, "born-v2 vault has nothing to convert");
        assert!(!vault.v2_blob_sweep_needed().unwrap());
        vault
    }

    // --- P: verification + activation on a healthy converted vault -------

    #[test]
    fn verify_pass_is_clean_on_fully_converted_vault_and_activates() {
        let vault = fully_converted_vault();

        let report = vault.verify_vault_envelopes().unwrap();
        assert!(report.is_clean(), "expected clean, got: {report:?}");
        assert_eq!(report.entries_scanned, 1);
        assert_eq!(
            report.entry_fields_verified, 5,
            "title+username+password+url+notes"
        );
        assert_eq!(report.ssh_keys_scanned, 1);
        assert_eq!(report.ssh_keys_verified, 1);
        assert_eq!(report.totp_secrets_scanned, 1);
        assert_eq!(report.totp_secrets_verified, 1);
        assert_eq!(report.domain_mappings_scanned, 1);
        assert_eq!(report.domain_mappings_verified, 1, "sealed domain + tags");
        assert_eq!(report.rows_still_v1, 0);
        assert!(report.failures.is_empty());

        assert!(!vault.is_v2_format_activated().unwrap());
        match vault.activate_v2_format().unwrap() {
            V2ActivationOutcome::Activated { .. } => {}
            other => panic!("expected activation, got {other:?}"),
        }
        assert!(vault.is_v2_format_activated().unwrap());

        // The marker pair is durable and consistent.
        {
            let db = vault.lock_db().unwrap();
            let format: i64 = db
                .conn()
                .query_row(
                    "SELECT format_version FROM db_metadata WHERE id = 1",
                    [],
                    |r| r.get(0),
                )
                .unwrap();
            assert_eq!(format, CURRENT_VAULT_FORMAT_VERSION);
            let marker: String = db
                .conn()
                .query_row(
                    "SELECT value FROM registry_state WHERE key = 'v2_format_activated'",
                    [],
                    |r| r.get(0),
                )
                .unwrap();
            assert!(!marker.is_empty());
        }
    }

    #[test]
    fn activation_is_idempotent_and_second_call_is_a_no_op() {
        let vault = fully_converted_vault();
        assert!(matches!(
            vault.activate_v2_format().unwrap(),
            V2ActivationOutcome::Activated { .. }
        ));
        // A second call short-circuits WITHOUT re-running verification
        // (fast path on the format column).
        assert!(matches!(
            vault.activate_v2_format().unwrap(),
            V2ActivationOutcome::AlreadyActivated
        ));
        assert!(vault.is_v2_format_activated().unwrap());
        assert!(!vault.v2_activation_needed().unwrap());
    }

    #[test]
    fn open_hook_activates_a_converted_file_vault() {
        fn temp_vault_path(name: &str) -> std::path::PathBuf {
            std::env::temp_dir().join(format!(
                "sp-wbs406-{}-{}.db",
                name,
                uuid::Uuid::new_v4().simple()
            ))
        }
        fn cleanup(path: &std::path::Path) {
            let _ = std::fs::remove_file(path);
            let _ = std::fs::remove_file(crate::vault::epoch_guard::sidecar_path(path));
        }

        let path = temp_vault_path("activate");
        {
            let vault = VaultManager::create(&path, b"activate-hook-pass").unwrap();
            // A legacy v1 row (hand-inserted, the exact pre-WBS-304
            // shape), so the open must sweep THEN activate.
            let dek = vault.key_hierarchy.dek().unwrap();
            let t = encrypt_string(dek, "Hooked").unwrap();
            let db = vault.lock_db().unwrap();
            db.conn()
                .execute(
                    "INSERT INTO entries (vault_id, title, username, password, url, notes,
                        credential_type, entry_nonce, auth_tag, created_at, modified_at,
                        favorite, sync_id, sync_version, sync_state)
                     VALUES (1, ?1, ?2, ?3, ?4, ?5, 'password', ?6, ?7, 1700000000,
                             1700000000, 0, ?8, 1, 'synced')",
                    rusqlite::params![
                        bincode::serialize(&t).unwrap(),
                        bincode::serialize(&t).unwrap(),
                        bincode::serialize(&t).unwrap(),
                        Option::<Vec<u8>>::None,
                        Option::<Vec<u8>>::None,
                        bincode::serialize(&t.nonce).unwrap(),
                        bincode::serialize(&t.auth_tag).unwrap(),
                        uuid::Uuid::new_v4().to_string(),
                    ],
                )
                .unwrap();
        }

        let reopened = VaultManager::open(&path, b"activate-hook-pass").unwrap();
        assert!(
            reopened.is_v2_format_activated().unwrap(),
            "the open hook must sweep, verify, and activate"
        );
        let entry_id: i64 = {
            let db = reopened.lock_db().unwrap();
            db.conn()
                .query_row("SELECT entry_id FROM entries", [], |r| r.get(0))
                .unwrap()
        };
        assert_eq!(reopened.get_entry(entry_id).unwrap().title, "Hooked");
        drop(reopened);

        // Reopen: activation survives, vault still opens (the format gate
        // accepts its own activated state).
        let second = VaultManager::open(&path, b"activate-hook-pass").unwrap();
        assert!(second.is_v2_format_activated().unwrap());
        drop(second);
        cleanup(&path);
    }

    /// Downgrade-write blocking: after activation, ordinary CRUD stays v2
    /// and the activation marker survives (no path demotes the vault).
    #[test]
    fn updates_after_activation_stay_v2_and_activation_survives() {
        let vault = fully_converted_vault();
        vault.activate_v2_format().unwrap();
        let entry_id = vault.list_entries().unwrap()[0].entry_id;

        let mut entry = vault.get_entry(entry_id).unwrap();
        entry.title = "Site Edited".to_string();
        entry.password = "rotated-pass".to_string().into();
        vault.update_entry(entry_id, &entry).unwrap();

        // The rewritten row is still all-v2, and the vault still verifies
        // clean at the SAME activation level.
        let report = vault.verify_vault_envelopes().unwrap();
        assert!(report.is_clean(), "post-update verification: {report:?}");
        assert!(vault.is_v2_format_activated().unwrap());
        assert_eq!(
            vault.get_entry(entry_id).unwrap().password.as_str(),
            "rotated-pass"
        );
    }

    #[test]
    fn verify_refuses_when_locked() {
        let mut vault = fully_converted_vault();
        vault.lock();
        assert!(matches!(
            vault.verify_vault_envelopes().unwrap_err(),
            PasswordManagerError::VaultLocked
        ));
        assert!(matches!(
            vault.activate_v2_format().unwrap_err(),
            PasswordManagerError::VaultLocked
        ));
    }

    // --- N: corruption / tamper detection ---------------------------------

    /// THE WBS-405 negative: a tampered CONVERTED blob is DETECTED by the
    /// pass, reported as a named row, and left byte-identical.
    #[test]
    fn tampered_converted_blob_is_detected_named_and_not_modified() {
        let vault = fully_converted_vault();
        let entry_id = vault.list_entries().unwrap()[0].entry_id;
        let sync_id: String = {
            let db = vault.lock_db().unwrap();
            db.conn()
                .query_row(
                    "SELECT sync_id FROM entries WHERE entry_id = ?1",
                    [entry_id],
                    |r| r.get(0),
                )
                .unwrap()
        };
        let before: Vec<u8> = {
            let db = vault.lock_db().unwrap();
            db.conn()
                .query_row(
                    "SELECT password FROM entries WHERE entry_id = ?1",
                    [entry_id],
                    |r| r.get(0),
                )
                .unwrap()
        };

        // Flip one ciphertext byte of the sealed password.
        let mut tampered = before.clone();
        let idx = tampered.len() - 2;
        tampered[idx] ^= 0x01;
        {
            let db = vault.lock_db().unwrap();
            db.conn()
                .execute(
                    "UPDATE entries SET password = ?1 WHERE entry_id = ?2",
                    rusqlite::params![&tampered, entry_id],
                )
                .unwrap();
        }

        let report = vault.verify_vault_envelopes().unwrap();
        assert!(!report.is_clean());
        assert_eq!(
            report.failures.len(),
            1,
            "exactly the tampered column is named: {report:?}"
        );
        let failure = &report.failures[0];
        assert_eq!(failure.table, "entries");
        assert_eq!(failure.row_id, entry_id);
        assert_eq!(failure.sync_id.as_deref(), Some(sync_id.as_str()));
        assert_eq!(failure.column, "password");
        assert_eq!(
            report.entry_fields_verified, 4,
            "the other four still verify"
        );

        // The pass is read-only: the blob is byte-identical afterwards.
        let after: Vec<u8> = {
            let db = vault.lock_db().unwrap();
            db.conn()
                .query_row(
                    "SELECT password FROM entries WHERE entry_id = ?1",
                    [entry_id],
                    |r| r.get(0),
                )
                .unwrap()
        };
        assert_eq!(after, tampered, "verification must never modify the blob");
        assert_ne!(after, before);

        // Activation is blocked by the failure and dead-letters (the sweep
        // has finished: this cannot heal on its own).
        match vault.activate_v2_format().unwrap() {
            V2ActivationOutcome::Blocked {
                dead_lettered: true,
                ..
            } => {}
            other => panic!("expected a dead-lettered block, got {other:?}"),
        }
        assert!(!vault.is_v2_format_activated().unwrap());
        assert!(!vault.v2_activation_needed().unwrap(), "dead-lettered");
        // The format column was NOT flipped by the blocked attempt.
        let format: i64 = {
            let db = vault.lock_db().unwrap();
            db.conn()
                .query_row(
                    "SELECT format_version FROM db_metadata WHERE id = 1",
                    [],
                    |r| r.get(0),
                )
                .unwrap()
        };
        assert_eq!(format, 1);
    }

    #[test]
    fn tampered_ssh_and_totp_envelopes_are_detected_and_named() {
        let vault = fully_converted_vault();
        // Tamper the SSH private key envelope.
        {
            let db = vault.lock_db().unwrap();
            let mut blob: Vec<u8> = db
                .conn()
                .query_row("SELECT private_key_encrypted FROM ssh_keys", [], |r| {
                    r.get(0)
                })
                .unwrap();
            let idx = blob.len() - 1;
            blob[idx] ^= 0x80;
            db.conn()
                .execute("UPDATE ssh_keys SET private_key_encrypted = ?1", [&blob])
                .unwrap();
        }
        let report = vault.verify_vault_envelopes().unwrap();
        assert!(!report.is_clean());
        let ssh_failure = report
            .failures
            .iter()
            .find(|f| f.table == "ssh_keys")
            .expect("ssh failure must be named");
        assert_eq!(ssh_failure.column, "private_key_encrypted");
        assert_eq!(report.ssh_keys_verified, 0);
        // TOTP and the rest still verify.
        assert_eq!(report.totp_secrets_verified, 1);
        assert_eq!(report.domain_mappings_verified, 1);

        // Tamper the TOTP secret envelope too; both families are named in
        // ONE report.
        {
            let db = vault.lock_db().unwrap();
            let mut blob: Vec<u8> = db
                .conn()
                .query_row("SELECT secret_encrypted FROM totp_secrets", [], |r| {
                    r.get(0)
                })
                .unwrap();
            let idx = blob.len() - 1;
            blob[idx] ^= 0x80;
            db.conn()
                .execute("UPDATE totp_secrets SET secret_encrypted = ?1", [&blob])
                .unwrap();
        }
        let report = vault.verify_vault_envelopes().unwrap();
        assert!(report.failures.iter().any(|f| f.table == "totp_secrets"));
        assert_eq!(report.totp_secrets_verified, 0);
    }

    /// Relocation, not just corruption: swapping two entries' valid
    /// envelopes must fail BOTH rows — the envelopes authenticate only
    /// under their own row identities (AAD binding).
    #[test]
    fn relocated_envelopes_fail_verification_for_both_rows() {
        let vault = fully_converted_vault();
        let second_id = vault
            .add_entry(&test_entry("Second", "second-pass"))
            .unwrap();
        vault.sweep_v1_blobs_to_v2().unwrap();

        let (id_a, id_b) = {
            let ids: Vec<i64> = {
                let db = vault.lock_db().unwrap();
                let mut stmt = db
                    .conn()
                    .prepare("SELECT entry_id FROM entries ORDER BY entry_id")
                    .unwrap();
                let rows = stmt
                    .query_map([], |r| r.get(0))
                    .unwrap()
                    .collect::<std::result::Result<Vec<i64>, _>>()
                    .unwrap();
                rows
            };
            (ids[0], ids[1])
        };
        assert_eq!(id_b, second_id);

        let (blob_a, blob_b): (Vec<u8>, Vec<u8>) = {
            let db = vault.lock_db().unwrap();
            let a: Vec<u8> = db
                .conn()
                .query_row(
                    "SELECT password FROM entries WHERE entry_id = ?1",
                    [id_a],
                    |r| r.get(0),
                )
                .unwrap();
            let b: Vec<u8> = db
                .conn()
                .query_row(
                    "SELECT password FROM entries WHERE entry_id = ?1",
                    [id_b],
                    |r| r.get(0),
                )
                .unwrap();
            (a, b)
        };
        {
            let db = vault.lock_db().unwrap();
            db.conn()
                .execute(
                    "UPDATE entries SET password = ?1 WHERE entry_id = ?2",
                    rusqlite::params![&blob_b, id_a],
                )
                .unwrap();
            db.conn()
                .execute(
                    "UPDATE entries SET password = ?1 WHERE entry_id = ?2",
                    rusqlite::params![&blob_a, id_b],
                )
                .unwrap();
        }

        let report = vault.verify_vault_envelopes().unwrap();
        assert!(!report.is_clean());
        let named: Vec<(i64, &'static str)> = report
            .failures
            .iter()
            .map(|f| (f.row_id, f.column))
            .collect();
        assert!(
            named.contains(&(id_a, "password")) && named.contains(&(id_b, "password")),
            "both relocated rows must be named, got: {named:?}"
        );
    }

    /// The relation half of WBS-405: a forged tag row (valid length, wrong
    /// bytes) makes the mapping's tag set disagree with its sealed domain.
    #[test]
    fn forged_domain_tag_is_detected_as_a_relation_failure() {
        let vault = fully_converted_vault();
        {
            let db = vault.lock_db().unwrap();
            // Overwrite the ROOT tag row with same-length junk.
            let changed = db
                .conn()
                .execute(
                    "UPDATE domain_mapping_tags SET tag = ?1
                     WHERE is_chain_root = 1",
                    [vec![0xABu8; 32]],
                )
                .unwrap();
            assert_eq!(changed, 1, "exactly one root tag row exists");
        }

        let report = vault.verify_vault_envelopes().unwrap();
        assert!(!report.is_clean());
        let failure = report
            .failures
            .iter()
            .find(|f| f.table == "domain_mappings")
            .expect("the mapping relation must be named");
        assert_eq!(failure.column, "domain_enc");
        assert!(
            failure.reason.contains("tag"),
            "the refusal must name the tag/envelope disagreement: {}",
            failure.reason
        );
        assert_eq!(report.domain_mappings_verified, 0);
    }

    // --- N: blocked activation retry policy --------------------------------

    /// A vault with an unreadable legacy row: the sweep dead-letters it
    /// (deterministic), verification names it, activation blocks AND
    /// dead-letters (failures cannot self-heal).
    #[test]
    fn corrupt_legacy_row_blocks_activation_and_dead_letters() {
        let vault = test_vault();
        let entry_id = {
            // Hand-insert a legacy row, then corrupt its password blob.
            let dek = vault.key_hierarchy.dek().unwrap();
            let t = encrypt_string(dek, "Corrupt").unwrap();
            let db = vault.lock_db().unwrap();
            db.conn()
                .execute(
                    "INSERT INTO entries (vault_id, title, username, password, url, notes,
                        credential_type, entry_nonce, auth_tag, created_at, modified_at,
                        favorite, sync_id, sync_version, sync_state)
                     VALUES (1, ?1, ?2, ?3, NULL, NULL, 'password', ?4, ?5, 1700000000,
                             1700000000, 0, ?6, 1, 'synced')",
                    rusqlite::params![
                        bincode::serialize(&t).unwrap(),
                        bincode::serialize(&t).unwrap(),
                        vec![0xDEu8, 0xAD, 0xBE, 0xEF],
                        bincode::serialize(&t.nonce).unwrap(),
                        bincode::serialize(&t.auth_tag).unwrap(),
                        uuid::Uuid::new_v4().to_string(),
                    ],
                )
                .unwrap();
            db.conn().last_insert_rowid()
        };

        // The sweep skips the corrupt row and dead-letters its own pass.
        let sweep = vault.sweep_v1_blobs_to_v2().unwrap();
        assert_eq!(sweep.skipped_unreadable, 1);
        assert!(!vault.v2_blob_sweep_needed().unwrap());

        let report = vault.verify_vault_envelopes().unwrap();
        assert!(!report.is_clean());
        assert_eq!(report.failures.len(), 1);
        assert_eq!(report.failures[0].row_id, entry_id);
        assert_eq!(report.failures[0].column, "password");

        match vault.activate_v2_format().unwrap() {
            V2ActivationOutcome::Blocked {
                dead_lettered: true,
                ..
            } => {}
            other => panic!("expected a dead-lettered block, got {other:?}"),
        }
        assert!(!vault.v2_activation_needed().unwrap());
    }

    /// A vault with HEALTHY legacy rows while the sweep is still active
    /// (completion flag absent): activation blocks but does NOT
    /// dead-letter — the next open converts the rows and retries
    /// (adversarial pre-check A1).
    #[test]
    fn blocked_while_sweep_still_active_does_not_dead_letter() {
        let vault = test_vault();
        let dek = vault.key_hierarchy.dek().unwrap();
        let t = encrypt_string(dek, "Pending").unwrap();
        {
            let db = vault.lock_db().unwrap();
            db.conn()
                .execute(
                    "INSERT INTO entries (vault_id, title, username, password, url, notes,
                        credential_type, entry_nonce, auth_tag, created_at, modified_at,
                        favorite, sync_id, sync_version, sync_state)
                     VALUES (1, ?1, ?2, ?3, NULL, NULL, 'password', ?4, ?5, 1700000000,
                             1700000000, 0, ?6, 1, 'synced')",
                    rusqlite::params![
                        bincode::serialize(&t).unwrap(),
                        bincode::serialize(&t).unwrap(),
                        bincode::serialize(&t).unwrap(),
                        bincode::serialize(&t.nonce).unwrap(),
                        bincode::serialize(&t.auth_tag).unwrap(),
                        uuid::Uuid::new_v4().to_string(),
                    ],
                )
                .unwrap();
        }

        // Sweep has NOT run: the completion flag is absent.
        assert!(vault.v2_blob_sweep_needed().unwrap());

        let report = vault.verify_vault_envelopes().unwrap();
        assert!(!report.is_clean());
        assert_eq!(report.rows_still_v1, 1, "healthy legacy row");
        assert!(report.failures.is_empty(), "nothing is corrupt");

        match vault.activate_v2_format().unwrap() {
            V2ActivationOutcome::Blocked {
                dead_lettered: false,
                ..
            } => {}
            other => panic!("expected a retriable block, got {other:?}"),
        }
        // NOT dead-lettered: the hook will retry after the sweep converts.
        assert!(vault.v2_activation_needed().unwrap());
        assert!(!vault.is_v2_format_activated().unwrap());

        // And the retry succeeds once the sweep has converted the row.
        vault.sweep_v1_blobs_to_v2().unwrap();
        assert!(matches!(
            vault.activate_v2_format().unwrap(),
            V2ActivationOutcome::Activated { .. }
        ));
    }

    // --- N: the older-client downgrade refusal (WBS-406 core negative) ----

    /// An OLDER binary (a client that only understands v1 context-free
    /// blobs) must refuse an activated vault's data LOUDLY — typed
    /// failures per blob family, never silently-decoded plaintext.
    #[test]
    fn older_v1_client_cannot_read_activated_vault_blobs() {
        let vault = fully_converted_vault();
        vault.activate_v2_format().unwrap();

        let dek = vault.key_hierarchy.dek().unwrap();
        let fetch = |sql: &str| -> Vec<u8> {
            let db = vault.lock_db().unwrap();
            db.conn().query_row(sql, [], |r| r.get(0)).unwrap()
        };

        // (1) Entry fields: the old client's full read path is bincode
        // `EncryptedEntry` deserialize THEN context-free decrypt. A SPENV
        // JSON document is not bincode (deserialize refuses) — and even
        // if bytes were reinterpreted, GCM refuses the open. Either way
        // the v1-only client gets a loud typed failure, never plaintext.
        for col in ["title", "username", "password", "url", "notes"] {
            let blob: Vec<u8> = fetch(&format!("SELECT {col} FROM entries LIMIT 1"));
            assert!(blob.starts_with(crate::crypto::ENVELOPE_MAGIC));
            let old_client_read = match bincode::deserialize::<EncryptedEntry>(&blob) {
                Err(e) => Err(format!("deserialize refused: {e}")),
                Ok(enc) => decrypt_to_string(dek, &enc)
                    .map(|_| ())
                    .map_err(|e| format!("decrypt refused: {e}")),
            };
            assert!(
                old_client_read.is_err(),
                "the v1-only client must fail loudly on the v2 {col} blob, not decode it"
            );
        }

        // (2) Even a FORGED bincode-shaped shell around envelope bytes
        // fails at AES-GCM authentication — the old client can never
        // extract plaintext from an envelope body by repackaging it.
        let blob = fetch("SELECT password FROM entries LIMIT 1");
        let forged = EncryptedEntry {
            nonce: [7u8; 12],
            ciphertext: blob,
            auth_tag: [9u8; 16],
        };
        let forged_result = decrypt_to_string(dek, &forged);
        assert!(
            forged_result.is_err(),
            "repackaged envelope bytes must fail GCM authentication"
        );

        // (3) SSH private key through the old three-part reader: the v2
        // envelope as "ciphertext" with the zeroed legacy nonce/tag fails
        // authentication.
        let pk = fetch("SELECT private_key_encrypted FROM ssh_keys");
        let nonce: Vec<u8> = fetch("SELECT nonce FROM ssh_keys");
        let tag: Vec<u8> = fetch("SELECT auth_tag FROM ssh_keys");
        assert!(crate::ssh::SshKey::decrypt_private_key(dek, &pk, &nonce, &tag).is_err());

        // (4) TOTP secret likewise.
        let secret = fetch("SELECT secret_encrypted FROM totp_secrets");
        let t_nonce: Vec<u8> = fetch("SELECT nonce FROM totp_secrets");
        let t_tag: Vec<u8> = fetch("SELECT auth_tag FROM totp_secrets");
        assert!(crate::totp::decrypt_totp_secret(dek, &secret, &t_nonce, &t_tag).is_err());
    }

    /// The current build's own downgrade block: a vault whose activation
    /// marker claims a FUTURE format is refused at open, before any entry
    /// data is read (end-to-end through VaultManager::open, file-backed).
    #[test]
    fn future_format_marker_refuses_vault_open_end_to_end() {
        fn temp_vault_path(name: &str) -> std::path::PathBuf {
            std::env::temp_dir().join(format!(
                "sp-wbs406-fmt-{}-{}.db",
                name,
                uuid::Uuid::new_v4().simple()
            ))
        }
        fn cleanup(path: &std::path::Path) {
            let _ = std::fs::remove_file(path);
            let _ = std::fs::remove_file(crate::vault::epoch_guard::sidecar_path(path));
        }

        let path = temp_vault_path("future-fmt");
        {
            let vault = VaultManager::create(&path, b"future-format-pass").unwrap();
            vault.add_entry(&test_entry("Kept", "kept-pass")).unwrap();
            vault.activate_v2_format().unwrap();
        }
        // Simulate a FUTURE activation level.
        {
            let db = crate::database::Database::open(&path).unwrap();
            db.conn()
                .execute(
                    "UPDATE db_metadata SET format_version = ?1 WHERE id = 1",
                    [CURRENT_VAULT_FORMAT_VERSION + 1],
                )
                .unwrap();
        }

        let open_result = VaultManager::open(&path, b"future-format-pass");
        match open_result {
            Err(PasswordManagerError::Database(DatabaseError::UnsupportedFutureFormat {
                found,
                supported,
            })) => {
                assert_eq!(found, CURRENT_VAULT_FORMAT_VERSION + 1);
                assert_eq!(supported, CURRENT_VAULT_FORMAT_VERSION);
            }
            Err(other) => panic!("expected the typed future-format refusal, got {other:?}"),
            Ok(_) => panic!("a future-format vault must NOT open"),
        }

        // The vault file is untouched by the refusal (fail closed = no
        // write, no migration, no entry read).
        let db = crate::database::Database::open(&path).unwrap();
        let (version, format): (i32, i64) = db
            .conn()
            .query_row(
                "SELECT version, format_version FROM db_metadata WHERE id = 1",
                [],
                |r| Ok((r.get(0)?, r.get(1)?)),
            )
            .unwrap();
        assert_eq!(version, crate::database::schema::CURRENT_SCHEMA_VERSION);
        assert_eq!(format, CURRENT_VAULT_FORMAT_VERSION + 1);
        drop(db);
        cleanup(&path);
    }
}
