//! Encrypted domain-mapping identity + keyed lookup tags (WBS-306 /
//! ADR-005 rev 4, SR-CRYPTO-001 / SR-DATA-004 / TD-ROB-10).
//!
//! The `domain_mappings.domain` column (and its SQL index) used to be
//! plaintext. This module:
//!
//! - SEALS each mapping's domain as a v2 envelope
//!   ([`ObjectType::DomainMapping`], Summary purpose) bound to
//!   (vault_uuid, the mapping row's `sync_id`) — written on every mapping
//!   write (sync apply) and backfilled for legacy rows by
//!   [`VaultManager::sweep_domain_mappings`];
//! - maintains KEYED EQUALITY TAGS (one HMAC-SHA256 per label-chain suffix
//!   of the normalized host, under the DEK-derived domain-tag key) in the
//!   `domain_mapping_tags` table, so lookups stay index-backed without a
//!   plaintext index. Tag semantics are exactly the legacy
//!   `domains_match` suffix-chain semantics (see `crate::domain`);
//! - LOOKS UP by tag-set intersection as a PRE-FILTER, then opens every
//!   candidate's sealed domain and verifies the decrypted host's tag set
//!   actually intersects the query's (constant-time). Tags are a hint; the
//!   ENVELOPE is the authority. A storage attacker who copies a legit tag
//!   set onto another row cannot redirect a lookup: that row's own envelope
//!   opens under ITS identity and its domain will not chain-match the
//!   query, which is an integrity refusal (fail closed), not a match.
//!
//! Migration/backfill split (adversarial pre-check A3): migrations run at
//! vault open BEFORE the DEK exists, so the v8 migration is pure DDL (one
//! `BEGIN IMMEDIATE` transaction); the DEK-dependent backfill is the
//! post-unlock sweep below — the same split the v5 registry migration
//! established. The sweep writes every row's (envelope, tags) pair inside
//! ONE transaction: a crash mid-sweep rolls back to the fully-legacy state
//! and retries on the next open, never leaving a half-tagged row.
//!
//! Transition: legacy rows keep their plaintext `domain` until WBS-404's
//! bulk migration clears the column. Reads are dual (envelope preferred,
//! plaintext fallback restricted to `domain_enc IS NULL` rows); writes are
//! always sealed. The plaintext INDEX is dropped by the v8 migration —
//! lookups no longer have a plaintext search structure.

use crate::crypto::aad::{EnvelopePurpose, ObjectType};
use crate::crypto::cipher::DataEncryptionKey;
use crate::crypto::keyring::derive_domain_tag_key;
use crate::database::repository::EntryRepository;
use crate::domain::{
    compute_chain_tags_for_normalized, compute_domain_chain_tags, domains_match, normalize_host,
    ChainTags, DOMAIN_TAG_KEY_ID,
};
use crate::{DatabaseError, PasswordManagerError, Result};
use rusqlite::{Connection, OptionalExtension};
use subtle::ConstantTimeEq;

use super::envelope_ops;
use super::VaultManager;

// ---------------------------------------------------------------------------
// Write paths (shared by the sync apply path and the backfill sweep)
// ---------------------------------------------------------------------------

/// One lookup pre-filter candidate: `(mapping_id, domain_enc, sync_id, entry_id)`.
type TagCandidateRow = (i64, Option<Vec<u8>>, Option<String>, i64);
/// One sweep scan row: `(mapping_id, domain, sync_id, domain_enc)`.
type StoredMappingRow = (i64, Option<String>, Option<String>, Option<Vec<u8>>);

/// The sealing context for one mapping write: the DEK-derived key material
/// and vault identity, bundled so the write helpers stay under clippy's
/// argument ceiling without losing explicitness.
pub(crate) struct MappingSealCtx<'a> {
    pub dek: &'a DataEncryptionKey,
    pub vault_uuid: &'a str,
    pub epoch: i64,
    pub tag_key: &'a [u8],
}

/// Seal one domain string for an EXISTING mapping row and (re)write its
/// tag set.
///
/// `mapping_sync_id` is the envelope's object identity — the mapping row's
/// `sync_id`, minted when absent. The row's `domain_enc` column receives
/// the envelope; the `domain_mapping_tags` rows are replaced wholesale.
/// Does NOT touch the legacy plaintext `domain` column (dual-read keeps it
/// for pre-backfill compatibility; WBS-404 clears it).
///
/// Caller owns the transaction (or accepts auto-commit semantics); the
/// envelope and tags land on the same connection so they are always
/// consistent.
pub(crate) fn seal_mapping_and_write_tags(
    conn: &Connection,
    ctx: &MappingSealCtx<'_>,
    mapping_id: i64,
    mapping_sync_id: &str,
    domain: &str,
) -> Result<()> {
    let domain_enc = envelope_ops::seal_object_field(
        ctx.dek,
        ctx.vault_uuid,
        mapping_sync_id,
        ObjectType::DomainMapping,
        EnvelopePurpose::Summary,
        domain,
        ctx.epoch,
    )?;

    conn.execute(
        "UPDATE domain_mappings SET domain_enc = ?1, sync_id = ?2 WHERE mapping_id = ?3",
        rusqlite::params![&domain_enc, mapping_sync_id, mapping_id],
    )
    .map_err(DatabaseError::Sqlite)?;

    write_mapping_tags(conn, mapping_id, domain, ctx.tag_key)
}

/// Insert one mapping row (minting its identity) together with its sealed
/// domain and tag set — the ONE write path for new mappings (sync apply).
/// Returns the new mapping_id.
///
/// The legacy plaintext `domain` column is NOT NULL and stays populated on
/// new rows for the transition (it is inert for post-v8 lookups: the
/// plaintext fallback only reads `domain_enc IS NULL` rows). WBS-404's
/// bulk migration clears the column.
///
/// `cfg` mirror of the sync module's own gating: its only production
/// caller is the feature-gated sync apply path; tests exercise it
/// directly.
#[cfg(any(test, feature = "sync"))]
pub(crate) fn insert_sealed_domain_mapping(
    conn: &Connection,
    ctx: &MappingSealCtx<'_>,
    entry_id: i64,
    domain: &str,
    is_primary: bool,
) -> Result<i64> {
    let mapping_sync_id = uuid::Uuid::new_v4().to_string();
    let domain_enc = envelope_ops::seal_object_field(
        ctx.dek,
        ctx.vault_uuid,
        &mapping_sync_id,
        ObjectType::DomainMapping,
        EnvelopePurpose::Summary,
        domain,
        ctx.epoch,
    )?;

    conn.execute(
        "INSERT INTO domain_mappings (entry_id, domain, is_primary, sync_id, domain_enc)
         VALUES (?1, ?2, ?3, ?4, ?5)",
        rusqlite::params![
            entry_id,
            domain,
            is_primary as i64,
            &mapping_sync_id,
            &domain_enc
        ],
    )
    .map_err(DatabaseError::Sqlite)?;
    let mapping_id = conn.last_insert_rowid();

    write_mapping_tags(conn, mapping_id, domain, ctx.tag_key)?;
    Ok(mapping_id)
}

/// Replace one mapping's tag rows with the chain tags of `domain`: the
/// ROOT tag (full normalized host, `is_chain_root = 1`) plus one row per
/// proper suffix. Rows for unnormalizable domains get an empty tag set
/// (sealed but not findable — the same visibility an empty domain has
/// today).
fn write_mapping_tags(
    conn: &Connection,
    mapping_id: i64,
    domain: &str,
    tag_key: &[u8],
) -> Result<()> {
    conn.execute(
        "DELETE FROM domain_mapping_tags WHERE mapping_id = ?1",
        [mapping_id],
    )
    .map_err(DatabaseError::Sqlite)?;

    let Some(tags) = compute_domain_chain_tags(tag_key, domain)? else {
        return Ok(());
    };
    conn.execute(
        "INSERT INTO domain_mapping_tags (mapping_id, tag, is_chain_root, equality_key_id)
         VALUES (?1, ?2, 1, ?3)",
        rusqlite::params![mapping_id, &tags.root.to_vec(), DOMAIN_TAG_KEY_ID],
    )
    .map_err(DatabaseError::Sqlite)?;
    for tag in &tags.suffixes {
        conn.execute(
            "INSERT INTO domain_mapping_tags (mapping_id, tag, is_chain_root, equality_key_id)
             VALUES (?1, ?2, 0, ?3)",
            rusqlite::params![mapping_id, &tag.to_vec(), DOMAIN_TAG_KEY_ID],
        )
        .map_err(DatabaseError::Sqlite)?;
    }
    Ok(())
}

// ---------------------------------------------------------------------------
// Lookups
// ---------------------------------------------------------------------------

/// Tag pre-filter + envelope verification (WBS-306 adversarial pre-check
/// A1/A2). Returns the entry_ids whose mappings genuinely match
/// `query_host` under `domains_match` semantics.
///
/// Pre-filter (index-backed, selective): a stored mapping is a candidate
/// when its ROOT tag equals the query's full-host tag (query is a suffix
/// of the stored host) or any of the query's chain tags equals a stored
/// ROOT tag (stored host is a suffix of the query). Shared suffix chains
/// alone (e.g. `com`) match nothing — that is what keeps
/// `notgitlab.com` from matching `gitlab.com`.
///
/// Per candidate, in order:
/// 1. structural integrity (fail closed): sealed domain AND stable
///    identity must exist; the sealed domain must open under the row's
///    identity (relocation fails GCM/AAD);
/// 2. tag-set integrity (fail closed, constant-time): the row's stored
///    tags must be EXACTLY the chain tags of the decrypted domain — a
///    copied/forged tag set cannot satisfy both the tag rows and the
///    envelope (whose AAD binds the row identity);
/// 3. semantics: `domains_match(query, decrypted)` decides match/no-match;
///    innocent shared-suffix pre-filter hits are skipped, not errors.
fn verified_tag_candidate_entry_ids(
    conn: &Connection,
    dek: &DataEncryptionKey,
    vault_uuid: &str,
    query_host: &str,
    query_tags: &ChainTags,
    tag_key: &[u8],
) -> Result<Vec<i64>> {
    // Fixed-width bind list: ?1 = query root tag, then the full query
    // chain set (padded with the root). Placeholders only — no
    // string-built SQL.
    let mut chain_binds: Vec<Vec<u8>> = query_tags.all().iter().map(|t| t.to_vec()).collect();
    while chain_binds.len() < crate::domain::MAX_CHAIN_TAGS {
        chain_binds.push(query_tags.root.to_vec());
    }

    let mut binds: Vec<Vec<u8>> = Vec::with_capacity(chain_binds.len() + 1);
    binds.push(query_tags.root.to_vec());
    binds.extend(chain_binds);

    let candidates: Vec<TagCandidateRow> = {
        let mut stmt = conn
            .prepare(
                "SELECT dm.mapping_id, dm.domain_enc, dm.sync_id, dm.entry_id
                 FROM domain_mappings dm
                 JOIN entries e ON e.entry_id = dm.entry_id AND e.is_deleted = 0
                 WHERE dm.mapping_id IN (
                     SELECT mapping_id FROM domain_mapping_tags
                     WHERE tag = ?1
                        OR (is_chain_root = 1 AND tag IN (?2, ?3, ?4, ?5, ?6,
                            ?7, ?8, ?9, ?10, ?11))
                 )",
            )
            .map_err(DatabaseError::Sqlite)?;
        let rows = stmt
            .query_map(rusqlite::params_from_iter(binds.iter()), |row| {
                Ok((
                    row.get::<_, i64>(0)?,
                    row.get::<_, Option<Vec<u8>>>(1)?,
                    row.get::<_, Option<String>>(2)?,
                    row.get::<_, i64>(3)?,
                ))
            })
            .map_err(DatabaseError::Sqlite)?
            .collect::<std::result::Result<Vec<_>, _>>()
            .map_err(DatabaseError::Sqlite)?;
        rows
    };

    let mut verified = Vec::new();
    for (mapping_id, domain_enc, sync_id, entry_id) in candidates {
        let domain_enc = domain_enc.ok_or_else(|| {
            PasswordManagerError::InvalidInput(format!(
                "domain mapping {mapping_id} matched the lookup tag index but carries no \
                 sealed domain — the row is inconsistent and may have been tampered with"
            ))
        })?;
        let sync_id = sync_id.ok_or_else(|| {
            PasswordManagerError::InvalidInput(format!(
                "domain mapping {mapping_id} carries a sealed domain but no stable \
                 identity — refusing (the row may have been tampered with)"
            ))
        })?;

        // THE authority check: open under the row's identity — a whole-
        // envelope relocation fails GCM/AAD right here.
        let domain = envelope_ops::open_object_field(
            dek,
            Some(vault_uuid),
            Some(&sync_id),
            ObjectType::DomainMapping,
            EnvelopePurpose::Summary,
            &domain_enc,
        )
        .map_err(|e| {
            PasswordManagerError::InvalidInput(format!(
                "sealed domain of mapping {mapping_id} failed to open during lookup: {e}"
            ))
        })?;

        // Tag-set integrity: the stored tag rows must be exactly the chain
        // tags of the decrypted domain (root flag included). This is what
        // catches tags RELOCATED between rows — the envelope opens fine,
        // but the stored tag set then disagrees with the decrypted host.
        let domain = domain.to_string();
        let expected = compute_domain_chain_tags(tag_key, &domain)?.ok_or_else(|| {
            PasswordManagerError::InvalidInput(format!(
                "sealed domain of mapping {mapping_id} is not a normalizable host"
            ))
        })?;
        let stored = load_stored_tags(conn, mapping_id)?;
        let tags_consistent = stored_tags_match_expected(&stored, &expected);
        if !tags_consistent {
            return Err(PasswordManagerError::InvalidInput(format!(
                "domain mapping {mapping_id}: tag index does not match its sealed \
                 domain — the tag index may have been tampered with"
            )));
        }

        // Semantics: decide with the exact legacy predicate. Innocent
        // shared-suffix pre-filter hits skip here; only integrity failures
        // above are errors.
        if domains_match(query_host, &domain) {
            verified.push(entry_id);
        }
    }
    Ok(verified)
}

/// One stored tag row: `(tag, is_chain_root)`.
fn load_stored_tags(conn: &Connection, mapping_id: i64) -> Result<Vec<(Vec<u8>, bool)>> {
    let mut stmt = conn
        .prepare("SELECT tag, is_chain_root FROM domain_mapping_tags WHERE mapping_id = ?1")
        .map_err(DatabaseError::Sqlite)?;
    let rows = stmt
        .query_map([mapping_id], |row| {
            Ok((row.get::<_, Vec<u8>>(0)?, row.get::<_, i64>(1)? != 0))
        })
        .map_err(DatabaseError::Sqlite)?
        .collect::<std::result::Result<Vec<_>, _>>()
        .map_err(DatabaseError::Sqlite)?;
    Ok(rows)
}

/// Constant-time-ish structural comparison of a row's stored tags against
/// the tags recomputed from its decrypted domain. Lengths (set cardinalities,
/// tag widths) are fixed by construction and compared first; the byte
/// comparisons themselves are constant-time per pair via `subtle` and run
/// over the whole sets (no content-dependent early exit).
fn stored_tags_match_expected(stored: &[(Vec<u8>, bool)], expected: &ChainTags) -> bool {
    let root_count = stored.iter().filter(|(_, is_root)| *is_root).count();
    let suffix_count = stored.iter().filter(|(_, is_root)| !*is_root).count();
    if root_count != 1 || suffix_count != expected.suffixes.len() {
        return false;
    }

    let mut consistent = 1u8;
    for (tag, is_root) in stored {
        let eq_root = tag.as_slice().ct_eq(expected.root.as_slice()).unwrap_u8();
        let in_suffixes = expected.suffixes.iter().fold(0u8, |acc, s| {
            acc | s.as_slice().ct_eq(tag.as_slice()).unwrap_u8()
        });
        consistent &= if *is_root {
            eq_root
        } else {
            in_suffixes & (1 - eq_root)
        };
    }
    consistent == 1
}

/// Legacy fallback: entry_ids of mappings that still carry ONLY the
/// plaintext column (pre-backfill rows). Exact-match semantics — the same
/// semantics the plaintext index had (suffix chains arrive via the tag
/// path once backfilled). Restricted to `domain_enc IS NULL` so a
/// backfilled row can never be matched through its lingering plaintext
/// copy.
pub(crate) fn legacy_plaintext_candidate_entry_ids(
    conn: &Connection,
    query_host: &str,
) -> Result<Vec<i64>> {
    let mut stmt = conn
        .prepare(
            "SELECT dm.entry_id
             FROM domain_mappings dm
             JOIN entries e ON e.entry_id = dm.entry_id AND e.is_deleted = 0
             WHERE dm.domain = ?1 AND dm.domain_enc IS NULL",
        )
        .map_err(DatabaseError::Sqlite)?;
    let ids = stmt
        .query_map([query_host], |row| row.get::<_, i64>(0))
        .map_err(DatabaseError::Sqlite)?
        .collect::<std::result::Result<Vec<_>, _>>()
        .map_err(DatabaseError::Sqlite)?;
    Ok(ids)
}

// ---------------------------------------------------------------------------
// Backfill sweep
// ---------------------------------------------------------------------------

/// Outcome of a [`VaultManager::sweep_domain_mappings`] run.
#[derive(Debug, Default, Clone, PartialEq, Eq)]
pub struct DomainSweepReport {
    /// Mapping rows examined.
    pub scanned: usize,
    /// Legacy rows that gained a sealed domain (and tags).
    pub sealed: usize,
    /// Rows re-tagged because the tag key id changed.
    pub retagged: usize,
}

/// True when the domain-mapping index needs a backfill sweep: unsealed
/// plaintext rows exist, or the recorded tag key id is stale.
pub(crate) fn domain_backfill_needed(conn: &Connection) -> Result<bool> {
    let unsealed: i64 = conn
        .query_row(
            "SELECT COUNT(*) FROM domain_mappings
             WHERE domain_enc IS NULL AND domain IS NOT NULL",
            [],
            |row| row.get(0),
        )
        .map_err(DatabaseError::Sqlite)?;
    if unsealed > 0 {
        return Ok(true);
    }

    let stored_key_id: Option<String> = conn
        .query_row(
            "SELECT value FROM registry_state WHERE key = 'domain_tag_key_id'",
            [],
            |row| row.get(0),
        )
        .optional()
        .map_err(DatabaseError::Sqlite)?;
    Ok(stored_key_id.as_deref() != Some(&DOMAIN_TAG_KEY_ID.to_string()))
}

fn set_domain_state(conn: &Connection, key: &str, value: &str) -> Result<()> {
    conn.execute(
        "INSERT INTO registry_state (key, value) VALUES (?1, ?2)
         ON CONFLICT(key) DO UPDATE SET value = excluded.value",
        rusqlite::params![key, value],
    )
    .map_err(DatabaseError::Sqlite)?;
    Ok(())
}

impl VaultManager {
    /// True when [`Self::sweep_domain_mappings`] has work to do.
    pub fn domain_backfill_needed(&self) -> Result<bool> {
        let db = self.lock_db()?;
        domain_backfill_needed(db.conn())
    }

    /// Backfill the encrypted domain index: seal every legacy plaintext
    /// mapping, (re)write tags, and record the tag-key bookkeeping — all in
    /// ONE transaction (ADR-005 rev 3: a failed sweep rolls back whole; a
    /// half-tagged row can never exist). Also re-tags everything when the
    /// tag key id changed (label migration). Idempotent: a completed sweep
    /// is a no-op scan.
    ///
    /// This sweep only SEALS (from plaintext it already holds) — it never
    /// opens stored envelopes — so it cannot wedge on tampered rows.
    pub fn sweep_domain_mappings(&self) -> Result<DomainSweepReport> {
        if !self.is_unlocked() {
            return Err(PasswordManagerError::VaultLocked);
        }
        let dek = self.key_hierarchy.dek()?;
        let vault_uuid = self.vault_uuid_str()?.to_string();
        let epoch = self.session_epoch();
        let tag_key = derive_domain_tag_key(dek)?;
        let ctx = MappingSealCtx {
            dek,
            vault_uuid: &vault_uuid,
            epoch,
            tag_key: &tag_key,
        };

        let db = self.lock_db()?;
        let tx = db
            .conn()
            .unchecked_transaction()
            .map_err(DatabaseError::Sqlite)?;

        let mut report = DomainSweepReport::default();

        let rows: Vec<StoredMappingRow> = {
            let mut stmt = tx
                .prepare("SELECT mapping_id, domain, sync_id, domain_enc FROM domain_mappings")
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
        report.scanned = rows.len();

        let key_id_stale: bool = {
            let stored: Option<String> = tx
                .query_row(
                    "SELECT value FROM registry_state WHERE key = 'domain_tag_key_id'",
                    [],
                    |row| row.get(0),
                )
                .optional()
                .map_err(DatabaseError::Sqlite)?;
            stored.as_deref() != Some(&DOMAIN_TAG_KEY_ID.to_string())
        };

        for (mapping_id, domain, sync_id, domain_enc) in rows {
            if domain_enc.is_some() && !key_id_stale {
                continue;
            }
            let Some(domain) = domain else {
                continue; // nothing to seal from
            };
            let mapping_sync_id = match sync_id {
                Some(sid) => sid,
                None => uuid::Uuid::new_v4().to_string(),
            };
            seal_mapping_and_write_tags(&tx, &ctx, mapping_id, &mapping_sync_id, &domain)?;
            if domain_enc.is_some() {
                report.retagged += 1;
            } else {
                report.sealed += 1;
            }
        }

        set_domain_state(&tx, "domain_tag_key_id", &DOMAIN_TAG_KEY_ID.to_string())?;
        tx.commit().map_err(DatabaseError::Sqlite)?;

        if report.sealed > 0 || report.retagged > 0 {
            if let Some(ref logger) = self.audit_logger {
                let _ = logger.log(
                    crate::audit::AuditEventType::RegistryIndexRebuilt {
                        entries: report.scanned,
                    },
                    &format!(
                        "Domain-mapping index swept: {} sealed, {} re-tagged of {} rows",
                        report.sealed, report.retagged, report.scanned
                    ),
                );
            }
        }

        Ok(report)
    }

    /// The encrypted domain lookup backing
    /// [`VaultManager::find_entries_by_domain`] (kept here so all WBS-306
    /// lookup logic lives in one module).
    ///
    /// Tag intersection + envelope verification, falling back to exact
    /// plaintext matching for rows not yet backfilled. Suffix-chain
    /// semantics (`sub.gitlab.com` ↔ `gitlab.com`) come from the chain-tag
    /// sets; see `crate::domain`.
    ///
    /// Runs under a single `lock_db()` acquisition: the tag query, the
    /// envelope opens, and the entry-row fetch all use one connection
    /// guard (the old implementation dropped the guard mid-lookup; with
    /// verification the lookup is one consistent read).
    pub(super) fn domain_lookup(&self, domain: &str) -> Result<Vec<super::Entry>> {
        if !self.is_unlocked() {
            return Err(PasswordManagerError::VaultLocked);
        }

        let Some(query_host) = normalize_host(domain) else {
            return Ok(Vec::new());
        };

        let dek = self.key_hierarchy.dek()?;
        let vault_uuid = self.vault_uuid_str()?.to_string();
        let tag_key = derive_domain_tag_key(dek)?;
        let query_tags =
            compute_chain_tags_for_normalized(&tag_key, &query_host)?.ok_or_else(|| {
                PasswordManagerError::InvalidInput(
                    "query host did not normalize; refusing domain lookup".to_string(),
                )
            })?;

        let db = self.lock_db()?;
        let conn = db.conn();

        let mut entry_ids = verified_tag_candidate_entry_ids(
            conn,
            dek,
            &vault_uuid,
            &query_host,
            &query_tags,
            &tag_key,
        )?;
        for id in legacy_plaintext_candidate_entry_ids(conn, &query_host)? {
            if !entry_ids.contains(&id) {
                entry_ids.push(id);
            }
        }

        let repo = crate::database::SqliteEntryRepository::new(&db);
        entry_ids
            .iter()
            .filter_map(|id| repo.get_raw(*id).transpose())
            .collect::<std::result::Result<Vec<_>, _>>()
            .map_err(PasswordManagerError::from)?
            .iter()
            .map(|row| self.decrypt_entry_row(row))
            .collect()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::vault::Entry;
    use chrono::Utc;

    fn test_vault() -> VaultManager {
        VaultManager::create(":memory:", b"domain_test_password").unwrap()
    }

    fn test_entry(title: &str, password: &str) -> Entry {
        Entry {
            entry_id: None,
            title: title.to_string(),
            username: "user@example.com".to_string(),
            password: password.to_string().into(),
            url: None,
            notes: None,
            credential_type: super::super::CredentialType::Password,
            created_at: Utc::now(),
            modified_at: Utc::now(),
            favorite: false,
        }
    }

    /// Insert a legacy (plaintext-only) mapping row the way pre-v8 binaries
    /// and the v1 migration left them.
    fn insert_legacy_mapping(vault: &VaultManager, entry_id: i64, domain: &str) -> i64 {
        let db = vault.db.lock().unwrap();
        db.conn()
            .execute(
                "INSERT INTO domain_mappings (entry_id, domain, is_primary) VALUES (?1, ?2, 1)",
                rusqlite::params![entry_id, domain],
            )
            .unwrap();
        db.conn().last_insert_rowid()
    }

    fn mapping_row(vault: &VaultManager, mapping_id: i64) -> (Option<Vec<u8>>, Option<String>) {
        let db = vault.db.lock().unwrap();
        db.conn()
            .query_row(
                "SELECT domain_enc, domain FROM domain_mappings WHERE mapping_id = ?1",
                [mapping_id],
                |row| Ok((row.get(0)?, row.get(1)?)),
            )
            .unwrap()
    }

    fn tag_count(vault: &VaultManager, mapping_id: i64) -> i64 {
        let db = vault.db.lock().unwrap();
        db.conn()
            .query_row(
                "SELECT COUNT(*) FROM domain_mapping_tags WHERE mapping_id = ?1",
                [mapping_id],
                |row| row.get(0),
            )
            .unwrap()
    }

    // --- P: legacy row -> sweep -> suffix-chain lookup ----------------------

    #[test]
    fn sealed_mapping_lookup_via_suffix_chain_after_backfill() {
        let vault = test_vault();
        let entry_id = vault.add_entry(&test_entry("GitLab", "gl-secret")).unwrap();
        let mapping_id = insert_legacy_mapping(&vault, entry_id, "gitlab.com");
        vault.sweep_domain_mappings().unwrap();

        // The row is sealed and tagged.
        let (domain_enc, _) = mapping_row(&vault, mapping_id);
        let domain_enc = domain_enc.expect("sweep must seal the domain");
        assert!(domain_enc.starts_with(crate::crypto::ENVELOPE_MAGIC));
        assert!(
            !String::from_utf8_lossy(&domain_enc).contains("gitlab"),
            "the sealed document must not contain the domain"
        );
        assert!(
            tag_count(&vault, mapping_id) >= 2,
            "gitlab.com -> {{gitlab.com, com}} chains"
        );

        // Suffix-chain lookups, BOTH directions (gitlab ↔ sub.gitlab).
        let found = vault.find_entries_by_domain("sub.gitlab.com").unwrap();
        assert_eq!(found.len(), 1, "dotted child must find bare parent");
        assert_eq!(found[0].entry_id, Some(entry_id));

        let found = vault.find_entries_by_domain("gitlab.com").unwrap();
        assert_eq!(found.len(), 1);

        // Unrelated hosts do not match.
        assert!(vault
            .find_entries_by_domain("gitlab.org")
            .unwrap()
            .is_empty());
        assert!(vault
            .find_entries_by_domain("notgitlab.com")
            .unwrap()
            .is_empty());
    }

    #[test]
    fn dotted_child_stored_bare_parent_query_matches() {
        let vault = test_vault();
        let entry_id = vault.add_entry(&test_entry("Sub", "sub-secret")).unwrap();
        insert_legacy_mapping(&vault, entry_id, "sub.example.com");
        vault.sweep_domain_mappings().unwrap();

        let found = vault.find_entries_by_domain("example.com").unwrap();
        assert_eq!(found.len(), 1, "bare parent must find dotted child");
        assert_eq!(found[0].username, "user@example.com");
    }

    #[test]
    fn legacy_plaintext_rows_match_exactly_until_backfill() {
        let vault = test_vault();
        let entry_id = vault
            .add_entry(&test_entry("Legacy", "legacy-secret"))
            .unwrap();
        insert_legacy_mapping(&vault, entry_id, "legacy.example");

        // No sweep yet: the plaintext fallback answers EXACT matches only
        // (today's indexed semantics), never suffix chains.
        let exact = vault.find_entries_by_domain("legacy.example").unwrap();
        assert_eq!(exact.len(), 1);
        assert!(vault
            .find_entries_by_domain("sub.legacy.example")
            .unwrap()
            .is_empty());
    }

    #[test]
    fn new_writes_are_sealed_from_birth_and_plaintext_is_inert() {
        let vault = test_vault();
        let entry_id = vault
            .add_entry(&test_entry("Fresh", "fresh-secret"))
            .unwrap();
        vault.sweep_domain_mappings().unwrap(); // record tag-key bookkeeping

        let dek = vault.key_hierarchy.dek().unwrap();
        let tag_key = derive_domain_tag_key(dek).unwrap();
        let vault_uuid = vault.vault_uuid_str().unwrap().to_string();
        let epoch = vault.session_epoch();
        let ctx = MappingSealCtx {
            dek,
            vault_uuid: &vault_uuid,
            epoch,
            tag_key: &tag_key,
        };
        let db = vault.db.lock().unwrap();
        let mapping_id =
            insert_sealed_domain_mapping(db.conn(), &ctx, entry_id, "app.example.com", true)
                .unwrap();

        // Transition contract: the legacy plaintext column is NOT NULL, so
        // new rows keep a COPY until WBS-404 clears it. That copy must be
        // INERT for lookups: rewrite it to a different domain and prove a
        // query for that other domain does not match through it.
        db.conn()
            .execute(
                "UPDATE domain_mappings SET domain = 'inert.example' WHERE mapping_id = ?1",
                [mapping_id],
            )
            .unwrap();
        drop(db);

        let (domain_enc, legacy) = mapping_row(&vault, mapping_id);
        assert!(legacy.as_deref() == Some("inert.example"));
        assert!(domain_enc
            .as_deref()
            .is_some_and(|b| b.starts_with(crate::crypto::ENVELOPE_MAGIC)));

        // The plaintext rewrite matches NOTHING (fallback is gated on
        // domain_enc IS NULL); the tag/envelope path still resolves the
        // REAL domain.
        assert!(vault
            .find_entries_by_domain("inert.example")
            .unwrap()
            .is_empty());
        let found = vault.find_entries_by_domain("app.example.com").unwrap();
        assert_eq!(found.len(), 1);
    }

    #[test]
    fn sweep_is_idempotent_and_records_key_bookkeeping() {
        let vault = test_vault();
        let entry_id = vault
            .add_entry(&test_entry("Sweep", "sweep-secret"))
            .unwrap();
        insert_legacy_mapping(&vault, entry_id, "sweep.example");

        let first = vault.sweep_domain_mappings().unwrap();
        assert_eq!(first.sealed, 1);
        assert!(!vault.domain_backfill_needed().unwrap());

        let second = vault.sweep_domain_mappings().unwrap();
        assert_eq!(second.sealed, 0, "completed sweep must be a no-op");
        assert_eq!(second.scanned, 1);
        assert!(!vault.domain_backfill_needed().unwrap());
    }

    #[test]
    fn unnormalizable_domain_is_sealed_but_never_crashes_lookup() {
        let vault = test_vault();
        let entry_id = vault
            .add_entry(&test_entry("Weird", "weird-secret"))
            .unwrap();
        insert_legacy_mapping(&vault, entry_id, "   ");
        vault.sweep_domain_mappings().unwrap();

        // Sealed (present) but with an empty tag set.
        assert_eq!(tag_count(&vault, 1), 0);
        assert!(vault.find_entries_by_domain("").unwrap().is_empty());
        assert!(vault.find_entries_by_domain("   ").unwrap().is_empty());
    }

    #[test]
    fn deleting_entry_removes_mappings_and_tags() {
        let vault = test_vault();
        let entry_id = vault
            .add_entry(&test_entry("Doomed", "doomed-secret"))
            .unwrap();
        insert_legacy_mapping(&vault, entry_id, "doomed.example");
        vault.sweep_domain_mappings().unwrap();
        assert_eq!(tag_count(&vault, 1), 2);

        vault.delete_entry(entry_id).unwrap();

        let db = vault.db.lock().unwrap();
        let mappings: i64 = db
            .conn()
            .query_row("SELECT COUNT(*) FROM domain_mappings", [], |r| r.get(0))
            .unwrap();
        let tags: i64 = db
            .conn()
            .query_row("SELECT COUNT(*) FROM domain_mapping_tags", [], |r| r.get(0))
            .unwrap();
        assert_eq!(mappings, 0, "mappings die with the entry");
        assert_eq!(tags, 0, "tag rows cascade with their mapping");
    }

    // --- N: tamper / relocation / wrong identity all fail closed ----------

    #[test]
    fn tampered_sealed_domain_fails_the_lookup_closed() {
        let vault = test_vault();
        let entry_id = vault
            .add_entry(&test_entry("Tamper", "tamper-secret"))
            .unwrap();
        insert_legacy_mapping(&vault, entry_id, "tamper.example");
        vault.sweep_domain_mappings().unwrap();

        // Flip one ciphertext byte in the sealed domain.
        {
            let db = vault.db.lock().unwrap();
            let mut blob: Vec<u8> = db
                .conn()
                .query_row(
                    "SELECT domain_enc FROM domain_mappings WHERE mapping_id = 1",
                    [],
                    |r| r.get(0),
                )
                .unwrap();
            let idx = blob.len() - 2;
            blob[idx] ^= 0x01;
            db.conn()
                .execute(
                    "UPDATE domain_mappings SET domain_enc = ?1 WHERE mapping_id = 1",
                    [&blob],
                )
                .unwrap();
        }

        let err = vault.find_entries_by_domain("tamper.example").unwrap_err();
        assert!(
            err.to_string().contains("failed to open"),
            "expected the open-failure refusal, got: {err}"
        );
    }

    #[test]
    fn relocated_tags_are_caught_by_the_envelope_authority_check() {
        let vault = test_vault();
        let gl_id = vault.add_entry(&test_entry("GitLab", "gl-secret")).unwrap();
        let evil_id = vault.add_entry(&test_entry("Evil", "evil-secret")).unwrap();
        let gl_mapping = insert_legacy_mapping(&vault, gl_id, "gitlab.com");
        let evil_mapping = insert_legacy_mapping(&vault, evil_id, "evil.example");
        vault.sweep_domain_mappings().unwrap();

        // Storage attacker: copy gitlab.com's (valid, keyed) tag set onto
        // the evil.example row so gitlab queries pre-filter to it.
        {
            let db = vault.db.lock().unwrap();
            db.conn()
                .execute(
                    "INSERT INTO domain_mapping_tags (mapping_id, tag, equality_key_id)
                     SELECT ?1, tag, equality_key_id FROM domain_mapping_tags
                     WHERE mapping_id = ?2",
                    rusqlite::params![evil_mapping, gl_mapping],
                )
                .unwrap();
        }

        // The tag pre-filter now yields the evil row — but its sealed
        // domain says evil.example, which does not chain-match the query.
        // Refusal (fail closed), never a misdirected credential.
        let err = vault.find_entries_by_domain("gitlab.com").unwrap_err();
        assert!(
            err.to_string().contains("tag index may have been tampered"),
            "expected the tag/envelope disagreement refusal, got: {err}"
        );

        // The honest mapping resolves again once the copied tags are gone.
        {
            let db = vault.db.lock().unwrap();
            db.conn()
                .execute(
                    "DELETE FROM domain_mapping_tags WHERE mapping_id = ?1 AND tag IN
                     (SELECT tag FROM domain_mapping_tags WHERE mapping_id = ?2)",
                    rusqlite::params![evil_mapping, gl_mapping],
                )
                .unwrap();
        }
        let found = vault.find_entries_by_domain("gitlab.com").unwrap();
        assert_eq!(found.len(), 1);
        assert_eq!(found[0].entry_id, Some(gl_id));
    }

    #[test]
    fn wrong_vault_envelope_is_refused_by_identity() {
        let vault = test_vault();
        let entry_id = vault
            .add_entry(&test_entry("Other", "other-secret"))
            .unwrap();
        let mapping_id = insert_legacy_mapping(&vault, entry_id, "other.example");
        vault.sweep_domain_mappings().unwrap();

        // Swap in a valid envelope that was sealed under a DIFFERENT vault
        // identity (same DEK, same mapping sync_id): the AAD must refuse it.
        let dek = vault.key_hierarchy.dek().unwrap();
        let sync_id: String = {
            let db = vault.db.lock().unwrap();
            db.conn()
                .query_row(
                    "SELECT sync_id FROM domain_mappings WHERE mapping_id = ?1",
                    [mapping_id],
                    |r| r.get(0),
                )
                .unwrap()
        };
        let wrong_vault_blob = crate::vault::envelope_ops::seal_object_field(
            dek,
            "00000000-aaaa-bbbb-cccc-000000000000",
            &sync_id,
            ObjectType::DomainMapping,
            EnvelopePurpose::Summary,
            "other.example",
            vault.session_epoch(),
        )
        .unwrap();
        {
            let db = vault.db.lock().unwrap();
            db.conn()
                .execute(
                    "UPDATE domain_mappings SET domain_enc = ?1 WHERE mapping_id = ?2",
                    rusqlite::params![&wrong_vault_blob, mapping_id],
                )
                .unwrap();
        }

        let err = vault.find_entries_by_domain("other.example").unwrap_err();
        assert!(
            err.to_string().contains("failed to open"),
            "wrong-vault envelope must be refused via AAD, got: {err}"
        );
    }

    #[test]
    fn inconsistent_tagged_row_without_sealed_domain_is_refused() {
        let vault = test_vault();
        let entry_id = vault
            .add_entry(&test_entry("Ghost", "ghost-secret"))
            .unwrap();
        let mapping_id = insert_legacy_mapping(&vault, entry_id, "ghost.example");
        vault.sweep_domain_mappings().unwrap();

        // Tamper: keep the tags, NULL out the sealed column.
        {
            let db = vault.db.lock().unwrap();
            db.conn()
                .execute(
                    "UPDATE domain_mappings SET domain_enc = NULL WHERE mapping_id = ?1",
                    [mapping_id],
                )
                .unwrap();
        }
        let err = vault.find_entries_by_domain("ghost.example").unwrap_err();
        assert!(
            err.to_string().contains("no sealed domain"),
            "inconsistent row must be refused, got: {err}"
        );
    }
}
