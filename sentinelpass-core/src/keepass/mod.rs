//! KeePass import/export functionality
//!
//! This module provides support for importing from and exporting to KeePass format.
//!
//! # Supported Formats
//!
//! - **KeePass XML**: Unencrypted KeePass 2.x XML export/import
//! - **KDBX**: KeePass encrypted database format (future - requires KDBX decryption)
//!
//! # Field Mapping
//!
//! | KeePass Field | SentinelPass Field |
//! |---------------|-------------------|
//! | Title | title |
//! | UserName | username |
//! | Password | password |
//! | URL | url |
//! | Notes | notes |
//! | Tags/Group | Appended to notes as "Tags: xxx" |
//! | Icon ID | Not stored (we don't have icon support yet) |
//! | Expires | Not stored (we don't have expiry support yet) |
//! | Created | created_at |
//! | Modified | modified_at |

pub mod xml;

use crate::{CredentialType, Entry, PasswordManagerError, Result, VaultManager};
use serde::{Deserialize, Serialize};
use std::io::Write;
use std::path::Path;

/// KeePass entry (from XML export or KDBX)
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct KeePassEntry {
    /// Entry title
    pub title: String,
    /// Username
    pub username: String,
    /// Password
    pub password: String,
    /// URL
    pub url: Option<String>,
    /// Notes
    pub notes: Option<String>,
    /// Tags (from group or custom tags)
    pub tags: Option<Vec<String>>,
    /// Creation time
    pub created_at: Option<chrono::DateTime<chrono::Utc>>,
    /// Last modification time
    pub modified_at: Option<chrono::DateTime<chrono::Utc>>,
}

impl From<KeePassEntry> for Entry {
    fn from(ke: KeePassEntry) -> Self {
        let now = chrono::Utc::now();
        let notes = match (ke.notes, ke.tags) {
            (Some(notes), Some(tags)) if !tags.is_empty() => {
                let tags_str = tags.join(", ");
                format!("{}\n\nTags: {}", notes, tags_str)
            }
            (Some(notes), _) => notes,
            (_, Some(tags)) if !tags.is_empty() => {
                format!("Tags: {}", tags.join(", "))
            }
            _ => String::new(),
        };

        Self {
            entry_id: None,
            title: ke.title,
            username: ke.username,
            password: ke.password,
            url: ke.url,
            notes: if notes.is_empty() { None } else { Some(notes) },
            credential_type: CredentialType::Password,
            created_at: ke.created_at.unwrap_or(now),
            modified_at: ke.modified_at.unwrap_or(now),
            favorite: false,
        }
    }
}

impl From<Entry> for KeePassEntry {
    fn from(entry: Entry) -> Self {
        let (notes, tags) = parse_tags_from_notes(&entry.notes);

        Self {
            title: entry.title,
            username: entry.username,
            password: entry.password,
            url: entry.url,
            notes: Some(notes),
            tags: if tags.is_empty() { None } else { Some(tags) },
            created_at: Some(entry.created_at),
            modified_at: Some(entry.modified_at),
        }
    }
}

/// Parse tags from notes field
/// Extracts "Tags: xxx, yyy" from notes if present
fn parse_tags_from_notes(notes: &Option<String>) -> (String, Vec<String>) {
    let Some(notes_str) = notes else {
        return (String::new(), Vec::new());
    };

    // Check if notes contains "Tags:" prefix
    if let Some(tags_idx) = notes_str.find("Tags:") {
        let before_tags = notes_str[..tags_idx].trim().to_string();
        let after_tags = notes_str[tags_idx + 5..].trim();

        let tags = after_tags
            .split(',')
            .map(|s| s.trim().to_string())
            .filter(|s| !s.is_empty())
            .collect();

        (before_tags.trim().to_string(), tags)
    } else {
        (notes_str.clone(), Vec::new())
    }
}

/// Import entries from KeePass XML file
///
/// This function reads a KeePass XML export (unencrypted) and imports all entries.
/// Users can export their KeePass database as XML from KeePass 2.x.
pub fn import_from_keepass_xml(vault: &mut VaultManager, input: &Path) -> Result<usize> {
    if !vault.is_unlocked() {
        return Err(PasswordManagerError::VaultLocked);
    }

    let entries = xml::parse_keepass_xml(input)?;

    let mut imported = 0;
    for ke_entry in entries {
        let entry = Entry::from(ke_entry);
        vault.add_entry(&entry)?;
        imported += 1;
    }

    Ok(imported)
}

/// Export vault entries to KeePass XML format
///
/// This function exports all vault entries to KeePass XML format.
/// The output is unencrypted XML that can be imported into KeePass 2.x.
pub fn export_to_keepass_xml(vault: &VaultManager, output: &Path) -> Result<()> {
    if !vault.is_unlocked() {
        return Err(PasswordManagerError::VaultLocked);
    }

    let summaries = vault.list_entries()?;
    let mut ke_entries = Vec::new();

    for summary in summaries {
        match vault.get_entry(summary.entry_id) {
            Ok(entry) => {
                ke_entries.push(KeePassEntry::from(entry));
            }
            Err(e) => {
                return Err(PasswordManagerError::from(crate::DatabaseError::Other(
                    format!("Failed to export entry {}: {}", summary.entry_id, e),
                )));
            }
        }
    }

    let xml_output = xml::generate_keepass_xml(&ke_entries)?;

    let mut file = std::fs::File::create(output).map_err(|e| {
        PasswordManagerError::from(crate::DatabaseError::FileIo(format!(
            "Failed to create export file: {}",
            e
        )))
    })?;

    file.write_all(xml_output.as_bytes()).map_err(|e| {
        PasswordManagerError::from(crate::DatabaseError::FileIo(format!(
            "Failed to write export: {}",
            e
        )))
    })?;

    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_parse_tags_from_notes() {
        let notes = "My notes\n\nTags: work, personal".to_string();
        let (cleaned_notes, tags) = parse_tags_from_notes(&Some(notes));
        assert_eq!(cleaned_notes, "My notes");
        assert_eq!(tags, vec!["work", "personal"]);
    }

    #[test]
    fn test_parse_tags_from_notes_no_tags() {
        let notes = "Just notes".to_string();
        let (cleaned_notes, tags) = parse_tags_from_notes(&Some(notes));
        assert_eq!(cleaned_notes, "Just notes");
        assert!(tags.is_empty());
    }

    #[test]
    fn test_parse_tags_from_notes_empty() {
        let (_, tags) = parse_tags_from_notes(&None);
        assert!(tags.is_empty());
    }

    #[test]
    fn test_keepass_entry_to_entry_conversion() {
        let ke = KeePassEntry {
            title: "Test Site".to_string(),
            username: "user@example.com".to_string(),
            password: "password123".to_string(),
            url: Some("https://example.com".to_string()),
            notes: Some("My notes".to_string()),
            tags: Some(vec!["work".to_string(), "important".to_string()]),
            created_at: Some(chrono::Utc::now()),
            modified_at: Some(chrono::Utc::now()),
        };

        let entry: Entry = ke.into();
        assert_eq!(entry.title, "Test Site");
        assert_eq!(entry.username, "user@example.com");
        assert_eq!(entry.password, "password123");
        assert_eq!(entry.url, Some("https://example.com".to_string()));
        assert!(entry.notes.as_ref().unwrap().contains("Tags:"));
    }

    #[test]
    fn test_entry_to_keepass_entry_conversion() {
        let now = chrono::Utc::now();
        let entry = Entry {
            entry_id: None,
            title: "Test Site".to_string(),
            username: "user@example.com".to_string(),
            password: "password123".to_string(),
            url: Some("https://example.com".to_string()),
            notes: Some("My notes\n\nTags: work".to_string()),
            credential_type: CredentialType::Password,
            created_at: now,
            modified_at: now,
            favorite: false,
        };

        let ke: KeePassEntry = entry.into();
        assert_eq!(ke.title, "Test Site");
        assert_eq!(ke.username, "user@example.com");
        assert_eq!(ke.password, "password123");
        // Tags should be extracted
        assert!(ke.tags.as_ref().unwrap().contains(&"work".to_string()));
    }
}
