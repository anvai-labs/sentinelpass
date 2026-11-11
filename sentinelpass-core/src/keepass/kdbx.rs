//! KDBX (encrypted KeePass database) import
//!
//! Parses KeePass KDBX 3.1 / 4.0 / 4.1 database files directly using the
//! [`keepass`] crate, so users can migrate from KeePass / KeePassXC without
//! first exporting unencrypted XML.
//!
//! # Security notes
//!
//! - The file master password is accepted as `Zeroizing<String>` and is
//!   zeroized on drop; it is never logged.
//! - Only the fields needed for migration are extracted (title, username,
//!   password, URL, notes, tags, timestamps, TOTP settings); attachments,
//!   icons, history and auto-type configuration are intentionally ignored.
//! - Entries inside the recycle bin are skipped.
//!
//! # TOTP mapping
//!
//! - KeePassXC-style entries carry an `otp` string field with an
//!   `otpauth://totp/...` URL (parsed via the crate's `totp` feature).
//! - Classic KeePass entries carry `TOTP Seed` + `TOTP Settings`
//!   (`"<period>;<digits>"`) string fields; the seed may be Base32 or hex and
//!   is normalized to canonical (unpadded) Base32.

use std::path::Path;

use keepass::{db::fields, db::GroupRef, Database, DatabaseKey};
use zeroize::Zeroizing;

use super::KeePassEntry;
use crate::{PasswordManagerError, Result};
use chrono::{DateTime, TimeZone, Utc};

/// TOTP settings extracted from a KDBX entry, normalized for
/// [`crate::VaultManager`] TOTP storage (Base32 secret, SHA-1/SHA-256/SHA-512).
#[derive(Debug, Clone)]
pub struct KdbxTotp {
    /// Base32-encoded secret (canonical, no padding)
    pub secret: Zeroizing<String>,
    /// Hash algorithm ("SHA1", "SHA256", "SHA512")
    pub algorithm: Option<String>,
    /// Code digit count
    pub digits: Option<u8>,
    /// Time step in seconds
    pub period: Option<u32>,
    /// Issuer label, if present in the otpauth URL
    pub issuer: Option<String>,
    /// Account label, if present in the otpauth URL
    pub account_name: Option<String>,
}

/// One entry parsed from a KDBX database
#[derive(Debug, Clone)]
pub struct KdbxEntry {
    /// Standard fields, mapped the same way as KeePass XML imports
    pub entry: KeePassEntry,
    /// Full group path (e.g. `"Email/Banking"`), `None` for root-level entries
    pub group_path: Option<String>,
    /// TOTP settings, if the entry has them
    pub totp: Option<KdbxTotp>,
}

/// KDBX on-disk signatures: 0x9AA2D903 (KDBX 3.x) and 0x9AA2D904 (KDBX 4.x),
/// stored little-endian.
const KDBX_SIGNATURES: [[u8; 4]; 2] = [[0x03, 0xD9, 0xA2, 0x9A], [0x04, 0xD9, 0xA2, 0x9A]];

/// Check whether a file looks like a KDBX database (by signature bytes),
/// as opposed to KeePass 2.x unencrypted XML.
pub fn is_kdbx_file(path: &Path) -> bool {
    use std::io::Read;
    let mut magic = [0u8; 4];
    let Ok(mut file) = std::fs::File::open(path) else {
        return false;
    };
    matches!(
        file.read_exact(&mut magic),
        Ok(())
        if KDBX_SIGNATURES.contains(&magic)
    )
}

/// Parse a KDBX database file and extract all importable entries.
///
/// `password` is the *database file's* master password (not the SentinelPass
/// vault password).
pub fn parse_keepass_kdbx(input: &Path, password: &Zeroizing<String>) -> Result<Vec<KdbxEntry>> {
    let mut file = std::fs::File::open(input).map_err(|e| {
        PasswordManagerError::from(crate::DatabaseError::FileIo(format!(
            "Failed to open KeePass database file: {}",
            e
        )))
    })?;

    let key = DatabaseKey::new().with_password(password.as_str());
    let db = Database::open(&mut file, key).map_err(map_open_error)?;

    let recycle_bin_id = db.recycle_bin().map(|g| g.id());
    let mut out = Vec::new();
    walk_group(db.root(), None, recycle_bin_id, &mut out);
    Ok(out)
}

fn map_open_error(e: keepass::db::DatabaseOpenError) -> PasswordManagerError {
    // Deliberately coarse: never echo file contents or key material.
    if matches!(e, keepass::db::DatabaseOpenError::Key(_)) {
        PasswordManagerError::InvalidInput(
            "Failed to open KeePass database: incorrect master password or key file required"
                .to_string(),
        )
    } else {
        PasswordManagerError::InvalidInput(format!(
            "Failed to open KeePass database (unsupported or corrupt file): {e}"
        ))
    }
}

fn walk_group(
    group: GroupRef<'_>,
    parent_path: Option<&str>,
    recycle_bin_id: Option<keepass::db::GroupId>,
    out: &mut Vec<KdbxEntry>,
) {
    // Skip the recycle bin (and everything inside it) entirely.
    if recycle_bin_id == Some(group.id()) {
        return;
    }

    // The root group usually has an empty name; only non-root group names
    // contribute to the path.
    let path = if group.name.is_empty() {
        parent_path.map(|p| p.to_string())
    } else {
        Some(match parent_path {
            Some(parent) => format!("{parent}/{}", group.name),
            None => group.name.clone(),
        })
    };

    for entry in group.entries() {
        if let Some(parsed) = convert_entry(&entry, path.as_deref()) {
            out.push(parsed);
        }
    }

    for child in group.groups() {
        walk_group(child, path.as_deref(), recycle_bin_id, out);
    }
}

fn convert_entry(entry: &keepass::db::EntryRef<'_>, group_path: Option<&str>) -> Option<KdbxEntry> {
    let title = entry
        .get_title()
        .or(entry.get_username())
        .unwrap_or("Untitled")
        .to_string();
    let username = entry.get_username().unwrap_or("").to_string();
    let password = entry.get_password().unwrap_or("").to_string();
    let url = entry.get_url().map(|s| s.to_string());
    let notes = entry.get(fields::NOTES).map(|s| s.to_string());

    // Preserve the group hierarchy the same way tags are preserved: as a
    // structured line in the notes field ("Group: a/b"), since SentinelPass
    // entries have no native folder concept.
    let notes = match (&notes, group_path) {
        (Some(n), Some(p)) => Some(format!("{n}\n\nGroup: {p}")),
        (Some(n), None) => Some(n.clone()),
        (None, Some(p)) => Some(format!("Group: {p}")),
        (None, None) => None,
    };

    let tags = if entry.tags.is_empty() {
        None
    } else {
        Some(entry.tags.clone())
    };

    let created_at = entry.times.creation.map(naive_to_utc);
    let modified_at = entry.times.last_modification.map(naive_to_utc);

    let ke_entry = KeePassEntry {
        title,
        username,
        password,
        url,
        notes,
        tags,
        created_at,
        modified_at,
    };

    Some(KdbxEntry {
        entry: ke_entry,
        group_path: group_path.map(|p| p.to_string()),
        totp: extract_totp(entry),
    })
}

fn extract_totp(entry: &keepass::db::EntryRef<'_>) -> Option<KdbxTotp> {
    // KeePassXC-style `otp` field (otpauth:// URL)
    if let Ok(totp) = entry.get_otp() {
        let account_name = match (&totp.issuer, totp.label.rsplit_once(':')) {
            (Some(issuer), Some((prefix, account))) if prefix == issuer && !account.is_empty() => {
                Some(account.to_string())
            }
            _ => None,
        };
        return Some(KdbxTotp {
            secret: Zeroizing::new(totp.get_secret()),
            algorithm: Some(algorithm_name(&totp.algorithm).to_string()),
            digits: u8::try_from(totp.digits).ok(),
            period: u32::try_from(totp.period).ok(),
            issuer: totp.issuer.clone(),
            account_name,
        });
    }

    // Classic KeePass style: "TOTP Seed" + "TOTP Settings" ("period;digits")
    let seed = entry.get("TOTP Seed")?;
    if seed.trim().is_empty() {
        return None;
    }
    let secret = normalize_seed(seed.trim())?;

    let settings = entry.get("TOTP Settings").and_then(|s| {
        let mut parts = s.trim().split(';');
        let period = parts.next()?.trim().parse::<u32>().ok();
        let digits = parts.next().and_then(|d| d.trim().parse::<u8>().ok());
        Some((period, digits))
    });

    Some(KdbxTotp {
        secret: Zeroizing::new(secret),
        algorithm: Some("SHA1".to_string()),
        digits: settings.and_then(|(_, d)| d),
        period: settings.and_then(|(p, _)| p),
        issuer: None,
        account_name: None,
    })
}

fn algorithm_name(algorithm: &keepass::db::TOTPAlgorithm) -> &'static str {
    match algorithm {
        keepass::db::TOTPAlgorithm::Sha1 => "SHA1",
        keepass::db::TOTPAlgorithm::Sha256 => "SHA256",
        keepass::db::TOTPAlgorithm::Sha512 => "SHA512",
        // Non-exhaustive enum: treat unknown algorithms as SHA-1 (RFC 6238
        // default) rather than failing the whole import.
        _ => "SHA1",
    }
}

/// Normalize a raw TOTP seed (Base32 or hex, possibly spaced) to canonical
/// unpadded Base32. Returns `None` when the seed is neither format.
fn normalize_seed(seed: &str) -> Option<String> {
    use data_encoding::{BASE32_NOPAD, HEXUPPER};

    let compact: String = seed.chars().filter(|c| !c.is_whitespace()).collect();
    let upper = compact.to_ascii_uppercase();

    // Strip padding for Base32 decoding; hex never has padding.
    let unpadded = upper.trim_end_matches('=');

    if let Ok(raw) = BASE32_NOPAD.decode(unpadded.as_bytes()) {
        return Some(BASE32_NOPAD.encode(&raw));
    }
    if let Ok(raw) = HEXUPPER.decode(upper.as_bytes()) {
        return Some(BASE32_NOPAD.encode(&raw));
    }
    None
}

fn naive_to_utc(naive: chrono::NaiveDateTime) -> DateTime<Utc> {
    Utc.from_utc_datetime(&naive)
}

#[cfg(test)]
mod tests {
    use super::*;
    use keepass::db::{fields, GroupMut};
    use std::io::Write;

    const TEST_PASSWORD: &str = "kdbx-test-password";

    /// Build a KDBX4 fixture database in memory covering: root entry,
    /// nested group entry, otpauth TOTP entry, classic TOTP Seed entry,
    /// hex-encoded seed, and an entry in the recycle bin.
    fn fixture_kdbx() -> Vec<u8> {
        let mut db = Database::new();

        let mut root = db.root_mut();
        root.add_entry().edit(|e: &mut keepass::db::EntryMut<'_>| {
            e.set_unprotected(fields::TITLE, "root entry");
            e.set_unprotected(fields::USERNAME, "rootuser");
            e.set_protected(fields::PASSWORD, "rootpass");
            e.set_unprotected(fields::URL, "https://root.example.com");
            e.set_unprotected(fields::NOTES, "root notes");
            e.tags.push("root-tag".into());
        });

        let mut email = root.add_group();
        email.edit(|g: &mut GroupMut<'_>| {
            g.name = "Email".into();
        });
        let mut email_ref = email;
        email_ref
            .add_entry()
            .edit(|e: &mut keepass::db::EntryMut<'_>| {
                e.set_unprotected(fields::TITLE, "mail entry");
                e.set_unprotected(fields::USERNAME, "mailuser");
                e.set_protected(fields::PASSWORD, "mailpass");
            });

        let mut banking = email_ref.add_group();
        banking.edit(|g: &mut GroupMut<'_>| {
            g.name = "Banking".into();
        });
        let mut banking_ref = banking;
        banking_ref
            .add_entry()
            .edit(|e: &mut keepass::db::EntryMut<'_>| {
                e.set_unprotected(fields::TITLE, "otpauth entry");
                e.set_unprotected(fields::USERNAME, "otpuser");
                e.set_protected(fields::PASSWORD, "otppass");
                e.set_unprotected(
                    fields::OTP,
                    "otpauth://totp/TestIssuer:alice@example.com?secret=JBSWY3DPEHPK3PXP&period=60&digits=8&algorithm=SHA256&issuer=TestIssuer",
                );
            });

        banking_ref
            .add_entry()
            .edit(|e: &mut keepass::db::EntryMut<'_>| {
                e.set_unprotected(fields::TITLE, "classic totp entry");
                e.set_unprotected(fields::USERNAME, "classicuser");
                e.set_protected(fields::PASSWORD, "classicpass");
                e.set_unprotected("TOTP Seed", "JBSW Y3DP EHPK 3PXP");
                e.set_unprotected("TOTP Settings", "30;6");
            });

        banking_ref
            .add_entry()
            .edit(|e: &mut keepass::db::EntryMut<'_>| {
                e.set_unprotected(fields::TITLE, "hex seed entry");
                e.set_unprotected(fields::USERNAME, "hexuser");
                e.set_protected(fields::PASSWORD, "hexpass");
                e.set_unprotected("TOTP Seed", "48656c6c6f21deadbeef");
                e.set_unprotected("TOTP Settings", "45;7");
            });

        // Recycle-bin entry must be skipped by the importer.
        let bin_uuid = uuid::Uuid::new_v4();
        let mut bin = root
            .add_group_with_id(keepass::db::GroupId::from_uuid(bin_uuid))
            .expect("add recycle bin group");
        bin.edit(|g: &mut GroupMut<'_>| {
            g.name = "Recycle Bin".into();
        });
        bin.add_entry().edit(|e: &mut keepass::db::EntryMut<'_>| {
            e.set_unprotected(fields::TITLE, "deleted entry");
        });
        let _ = bin.id();
        db.meta.recyclebin_uuid = Some(bin_uuid);

        let mut buf = Vec::new();
        db.save(&mut buf, DatabaseKey::new().with_password(TEST_PASSWORD))
            .expect("fixture save");
        buf
    }

    fn parse_fixture() -> Vec<KdbxEntry> {
        let dir = tempfile::tempdir().expect("tempdir");
        let path = dir.path().join("fixture.kdbx");
        let mut f = std::fs::File::create(&path).expect("create fixture");
        f.write_all(&fixture_kdbx()).expect("write fixture");
        drop(f);
        parse_keepass_kdbx(&path, &Zeroizing::new(TEST_PASSWORD.to_string())).expect("parse")
    }

    #[test]
    fn detects_kdbx_signature() {
        let dir = tempfile::tempdir().expect("tempdir");
        let kdbx_path = dir.path().join("db.kdbx");
        std::fs::write(&kdbx_path, fixture_kdbx()).expect("write");
        assert!(is_kdbx_file(&kdbx_path));

        let xml_path = dir.path().join("db.xml");
        std::fs::write(&xml_path, "<?xml version=\"1.0\"?><KeePassFile/>").expect("write");
        assert!(!is_kdbx_file(&xml_path));
    }

    #[test]
    fn imports_all_live_entries_with_fields() {
        let entries = parse_fixture();
        // root + mail + otpauth + classic + hex = 5 (recycle-bin entry skipped)
        assert_eq!(entries.len(), 5);

        let root = entries
            .iter()
            .find(|e| e.entry.title == "root entry")
            .expect("root entry");
        assert_eq!(root.entry.username, "rootuser");
        assert_eq!(root.entry.password, "rootpass");
        assert_eq!(root.entry.url.as_deref(), Some("https://root.example.com"));
        assert!(root.entry.notes.as_deref().unwrap().contains("root notes"));
        assert!(root.group_path.is_none());
    }

    #[test]
    fn preserves_group_hierarchy_in_notes() {
        let entries = parse_fixture();

        let mail = entries
            .iter()
            .find(|e| e.entry.title == "mail entry")
            .expect("mail entry");
        assert_eq!(mail.group_path.as_deref(), Some("Email"));
        assert!(mail
            .entry
            .notes
            .as_deref()
            .unwrap()
            .contains("Group: Email"));

        let otpauth = entries
            .iter()
            .find(|e| e.entry.title == "otpauth entry")
            .expect("otpauth entry");
        assert_eq!(otpauth.group_path.as_deref(), Some("Email/Banking"));
    }

    #[test]
    fn imports_otpauth_totp_settings() {
        let entries = parse_fixture();
        let e = entries
            .iter()
            .find(|e| e.entry.title == "otpauth entry")
            .expect("otpauth entry");
        let totp = e.totp.as_ref().expect("totp");
        assert_eq!(totp.secret.as_str(), "JBSWY3DPEHPK3PXP");
        assert_eq!(totp.algorithm.as_deref(), Some("SHA256"));
        assert_eq!(totp.digits, Some(8));
        assert_eq!(totp.period, Some(60));
        assert_eq!(totp.issuer.as_deref(), Some("TestIssuer"));
        assert_eq!(totp.account_name.as_deref(), Some("alice@example.com"));
    }

    #[test]
    fn imports_classic_totp_seed_base32() {
        let entries = parse_fixture();
        let e = entries
            .iter()
            .find(|e| e.entry.title == "classic totp entry")
            .expect("classic entry");
        let totp = e.totp.as_ref().expect("totp");
        // Whitespace is stripped and the seed re-encoded canonically.
        assert_eq!(totp.secret.as_str(), "JBSWY3DPEHPK3PXP");
        assert_eq!(totp.algorithm.as_deref(), Some("SHA1"));
        assert_eq!(totp.digits, Some(6));
        assert_eq!(totp.period, Some(30));
    }

    #[test]
    fn imports_hex_totp_seed() {
        let entries = parse_fixture();
        let e = entries
            .iter()
            .find(|e| e.entry.title == "hex seed entry")
            .expect("hex entry");
        let totp = e.totp.as_ref().expect("totp");
        // "Hello!\xDE\xAD\xBE\xEF" in canonical Base32
        assert_eq!(totp.secret.as_str(), "JBSWY3DPEHPK3PXP");
        assert_eq!(totp.digits, Some(7));
        assert_eq!(totp.period, Some(45));
    }

    #[test]
    fn rejects_wrong_password_without_leaking() {
        let dir = tempfile::tempdir().expect("tempdir");
        let path = dir.path().join("fixture.kdbx");
        std::fs::write(&path, fixture_kdbx()).expect("write");

        let err = parse_keepass_kdbx(&path, &Zeroizing::new("wrong".to_string()))
            .expect_err("wrong password must fail");
        let msg = err.to_string();
        assert!(msg.contains("incorrect master password"), "msg: {msg}");
        assert!(!msg.contains(TEST_PASSWORD));
    }

    #[test]
    fn rejects_non_kdbx_input() {
        let dir = tempfile::tempdir().expect("tempdir");
        let path = dir.path().join("not-a-db");
        std::fs::write(&path, b"definitely not a kdbx database").expect("write");

        let err = parse_keepass_kdbx(&path, &Zeroizing::new(TEST_PASSWORD.to_string()))
            .expect_err("garbage must fail");
        assert!(err.to_string().contains("unsupported or corrupt"));
    }

    #[test]
    fn preserves_timestamps() {
        let entries = parse_fixture();
        let root = entries
            .iter()
            .find(|e| e.entry.title == "root entry")
            .expect("root entry");
        // Fixture entries are created "now"; both timestamps should be set.
        assert!(root.entry.created_at.is_some());
        assert!(root.entry.modified_at.is_some());
    }
}
