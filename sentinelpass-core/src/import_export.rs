//! Import/export functionality for password vault

use crate::{CredentialType, DatabaseError, Entry, PasswordManagerError, Result, VaultManager};
use serde::{Deserialize, Serialize};
use std::fs::Permissions;
use std::io::{BufRead, BufReader, Write};
use std::path::Path;

#[cfg(unix)]
use std::os::unix::fs::PermissionsExt;

const PLAINTEXT_EXPORT_WARNING: &str =
    "WARNING: This file contains UNENCRYPTED passwords. \
     Treat it like a master password. Delete it immediately after use.";

/// Restrict an export file to owner-read/write only (mode 0600 on Unix).
/// On non-Unix platforms this is a no-op; the caller's OS-level protections apply.
fn set_export_permissions(file: &std::fs::File) -> Result<()> {
    #[cfg(unix)]
    {
        file.set_permissions(Permissions::from_mode(0o600))
            .map_err(|e| {
                PasswordManagerError::from(DatabaseError::FileIo(format!(
                    "Failed to restrict export file permissions: {}",
                    e
                )))
            })?;
    }
    #[cfg(not(unix))]
    let _ = file;
    Ok(())
}

/// Export format for vault data
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ExportEntry {
    pub title: String,
    pub username: String,
    pub password: String,
    pub url: Option<String>,
    pub notes: Option<String>,
    pub created_at: String,
    pub modified_at: String,
    pub favorite: bool,
}

impl From<Entry> for ExportEntry {
    fn from(entry: Entry) -> Self {
        Self {
            title: entry.title,
            username: entry.username,
            password: entry.password.as_str().to_string(),
            url: entry.url,
            notes: entry.notes,
            created_at: entry.created_at.to_rfc3339(),
            modified_at: entry.modified_at.to_rfc3339(),
            favorite: entry.favorite,
        }
    }
}

/// Export vault to JSON format
pub fn export_to_json(vault: &VaultManager, output: &Path) -> Result<()> {
    if !vault.is_unlocked() {
        return Err(PasswordManagerError::VaultLocked);
    }

    let entries = vault.list_entries()?;
    let mut export_entries = Vec::new();

    for summary in entries {
        if !summary.credential_type.is_generic_password_exportable() {
            continue;
        }
        match vault.get_entry(summary.entry_id) {
            Ok(entry) => {
                export_entries.push(ExportEntry::from(entry));
            }
            Err(e) => {
                return Err(PasswordManagerError::from(DatabaseError::Other(format!(
                    "Failed to export entry {}: {}",
                    summary.entry_id, e
                ))));
            }
        }
    }

    let json = serde_json::to_string_pretty(&export_entries)
        .map_err(|e| PasswordManagerError::from(DatabaseError::Serialization(e.to_string())))?;

    let mut file = std::fs::File::create(output).map_err(|e| {
        PasswordManagerError::from(DatabaseError::FileIo(format!(
            "Failed to create export file: {}",
            e
        )))
    })?;

    set_export_permissions(&file)?;

    // Prepend a plaintext warning so the file is obviously sensitive.
    write!(file, "// {}\n", PLAINTEXT_EXPORT_WARNING).map_err(|e| {
        PasswordManagerError::from(DatabaseError::FileIo(format!(
            "Failed to write export warning: {}",
            e
        )))
    })?;

    file.write_all(json.as_bytes()).map_err(|e| {
        PasswordManagerError::from(DatabaseError::FileIo(format!(
            "Failed to write export: {}",
            e
        )))
    })?;

    Ok(())
}

/// Export vault to CSV format
pub fn export_to_csv(vault: &VaultManager, output: &Path) -> Result<()> {
    if !vault.is_unlocked() {
        return Err(PasswordManagerError::VaultLocked);
    }

    let entries = vault.list_entries()?;
    let mut file = std::fs::File::create(output).map_err(|e| {
        PasswordManagerError::from(DatabaseError::FileIo(format!(
            "Failed to create export file: {}",
            e
        )))
    })?;

    set_export_permissions(&file)?;

    // Write CSV header with plaintext warning prepended.
    writeln!(file, "# {}", PLAINTEXT_EXPORT_WARNING).map_err(|e| {
        PasswordManagerError::from(DatabaseError::FileIo(format!(
            "Failed to write export warning: {}",
            e
        )))
    })?;
    writeln!(
        file,
        "Title,Username,Password,URL,Notes,Created At,Modified At,Favorite"
    )
    .map_err(|e| {
        PasswordManagerError::from(DatabaseError::FileIo(format!("Failed to write CSV: {}", e)))
    })?;

    for summary in entries {
        if !summary.credential_type.is_generic_password_exportable() {
            continue;
        }
        let entry = vault.get_entry(summary.entry_id)?;

        // Escape CSV fields
        let escape = |s: &str| {
            let needs_quotes = s.contains(',') || s.contains('"') || s.contains('\n');
            let escaped = s.replace('"', "\"\"");
            if needs_quotes {
                format!("\"{}\"", escaped)
            } else {
                escaped.to_string()
            }
        };

        writeln!(
            file,
            "{},{},{},{},{},{},{},{}",
            escape(&entry.title),
            escape(&entry.username),
            escape(&entry.password),
            entry
                .url
                .as_ref()
                .map(|s| escape(s))
                .unwrap_or_else(|| "".to_string()),
            entry
                .notes
                .as_ref()
                .map(|s| escape(s))
                .unwrap_or_else(|| "".to_string()),
            escape(&entry.created_at.to_rfc3339()),
            escape(&entry.modified_at.to_rfc3339()),
            entry.favorite
        )
        .map_err(|e| {
            PasswordManagerError::from(DatabaseError::FileIo(format!("Failed to write CSV: {}", e)))
        })?;
    }

    Ok(())
}

/// Import entries from JSON format
pub fn import_from_json(vault: &mut VaultManager, input: &Path) -> Result<usize> {
    if !vault.is_unlocked() {
        return Err(PasswordManagerError::VaultLocked);
    }

    let file = std::fs::File::open(input).map_err(|e| {
        PasswordManagerError::from(DatabaseError::FileIo(format!(
            "Failed to open import file: {}",
            e
        )))
    })?;

    let reader = BufReader::new(file);
    let export_entries: Vec<ExportEntry> = serde_json::from_reader(reader).map_err(|e| {
        PasswordManagerError::from(DatabaseError::Serialization(format!(
            "Failed to parse JSON: {}",
            e
        )))
    })?;

    let mut imported = 0;
    for export_entry in export_entries {
        let entry = Entry {
            entry_id: None,
            title: export_entry.title,
            username: export_entry.username,
            password: export_entry.password.into(),
            url: export_entry.url,
            notes: export_entry.notes,
            credential_type: CredentialType::Password,
            created_at: export_entry.created_at.parse().map_err(|e| {
                PasswordManagerError::from(DatabaseError::Serialization(format!(
                    "Invalid created_at date: {}",
                    e
                )))
            })?,
            modified_at: export_entry.modified_at.parse().map_err(|e| {
                PasswordManagerError::from(DatabaseError::Serialization(format!(
                    "Invalid modified_at date: {}",
                    e
                )))
            })?,
            favorite: export_entry.favorite,
        };

        vault.add_entry(&entry)?;
        imported += 1;
    }

    Ok(imported)
}

/// Import entries from CSV format
pub fn import_from_csv(vault: &mut VaultManager, input: &Path) -> Result<usize> {
    if !vault.is_unlocked() {
        return Err(PasswordManagerError::VaultLocked);
    }

    let file = std::fs::File::open(input).map_err(|e| {
        PasswordManagerError::from(DatabaseError::FileIo(format!(
            "Failed to open import file: {}",
            e
        )))
    })?;

    let reader = BufReader::new(file);
    let mut lines = reader.lines();

    // Skip header line
    let _header = lines
        .next()
        .ok_or_else(|| {
            PasswordManagerError::from(DatabaseError::FileIo("Empty CSV file".to_string()))
        })?
        .map_err(|e| {
            PasswordManagerError::from(DatabaseError::FileIo(format!(
                "Failed to read CSV header: {}",
                e
            )))
        })?;

    let mut imported = 0;

    for (line_num, line_result) in lines.enumerate().take(10000) {
        let line = line_result.map_err(|e| {
            PasswordManagerError::from(DatabaseError::FileIo(format!(
                "Failed to read line {}: {}",
                line_num + 2,
                e
            )))
        })?;

        if line.trim().is_empty() {
            continue;
        }

        let record = parse_csv_line(&line).map_err(|e| {
            PasswordManagerError::from(DatabaseError::Serialization(format!(
                "Failed to parse line {}: {}",
                line_num + 2,
                e
            )))
        })?;

        let empty = &String::new();
        let entry = Entry {
            entry_id: None,
            title: record.first().unwrap_or(empty).to_string(),
            username: record.get(1).unwrap_or(empty).to_string(),
            password: record.get(2).unwrap_or(empty).to_string().into(),
            url: {
                let url_str = record.get(3).unwrap_or(empty);
                if url_str.is_empty() {
                    None
                } else {
                    Some(url_str.to_string())
                }
            },
            notes: {
                let notes_str = record.get(4).unwrap_or(empty);
                if notes_str.is_empty() {
                    None
                } else {
                    Some(notes_str.to_string())
                }
            },
            credential_type: CredentialType::Password,
            created_at: chrono::Utc::now(),
            modified_at: chrono::Utc::now(),
            favorite: record.get(7).map(|s| s == "true").unwrap_or(false),
        };

        vault.add_entry(&entry)?;
        imported += 1;
    }

    Ok(imported)
}

/// Parse a CSV line, handling quoted fields
fn parse_csv_line(line: &str) -> Result<Vec<String>> {
    let mut fields = Vec::new();
    let mut current = String::new();
    let mut in_quotes = false;
    let mut chars = line.chars().peekable();

    while let Some(c) = chars.next() {
        match c {
            '"' => {
                if in_quotes {
                    // Check for escaped quote ("")
                    if chars.peek() == Some(&'"') {
                        current.push('"');
                        chars.next();
                    } else {
                        in_quotes = false;
                    }
                } else {
                    in_quotes = true;
                }
            }
            ',' if !in_quotes => {
                fields.push(current.clone());
                current.clear();
            }
            _ => {
                current.push(c);
            }
        }
    }

    fields.push(current);

    // Unescape quoted fields
    let unescaped: Vec<String> = fields
        .into_iter()
        .map(|s| s.replace("\"\"", "\""))
        .collect();

    Ok(unescaped)
}

#[cfg(test)]
mod tests {
    use super::*;
    use chrono::{TimeZone, Utc};

    fn temp_export_path(name: &str) -> std::path::PathBuf {
        let suffix = uuid::Uuid::new_v4().simple().to_string();
        std::env::temp_dir().join(format!("sentinelpass_{name}_{suffix}"))
    }

    fn test_entry(title: &str, password: &str, credential_type: CredentialType) -> Entry {
        Entry {
            entry_id: None,
            title: title.to_string(),
            username: "user@example.com".to_string(),
            password: password.to_string().into(),
            url: Some("https://example.com".to_string()),
            notes: None,
            credential_type,
            created_at: Utc.with_ymd_and_hms(2024, 1, 1, 0, 0, 0).unwrap(),
            modified_at: Utc.with_ymd_and_hms(2024, 1, 1, 0, 0, 0).unwrap(),
            favorite: false,
        }
    }

    #[test]
    fn test_parse_csv_simple() {
        let line =
            r#"title,username,password,url,notes,2024-01-01T00:00:00Z,2024-01-01T00:00:00Z,false"#;
        let result = parse_csv_line(line).unwrap();
        assert_eq!(result.len(), 8);
        assert_eq!(result[0], "title");
        assert_eq!(result[1], "username");
    }

    #[test]
    fn test_parse_csv_with_comma() {
        let line = r#""Last, First",user,pass,"https://example.com/path?param=value",note,2024-01-01T00:00:00Z,2024-01-01T00:00:00Z,false"#;
        let result = parse_csv_line(line).unwrap();
        assert_eq!(result.len(), 8);
        assert_eq!(result[0], "Last, First");
        assert_eq!(result[3], "https://example.com/path?param=value");
    }

    #[test]
    fn test_parse_csv_with_quotes() {
        let line =
            r#"title,user,"pass""word",url,note,2024-01-01T00:00:00Z,2024-01-01T00:00:00Z,false"#;
        let result = parse_csv_line(line).unwrap();
        assert_eq!(result.len(), 8);
        assert_eq!(result[2], "pass\"word");
    }

    #[test]
    fn test_export_entry_from_entry() {
        let entry = Entry {
            entry_id: Some(1),
            title: "Test".to_string(),
            username: "user@example.com".to_string(),
            password: "password123".to_string().into(),
            url: Some("https://example.com".to_string()),
            notes: Some("Test notes".to_string()),
            credential_type: CredentialType::Password,
            created_at: chrono::Utc.with_ymd_and_hms(2024, 1, 1, 0, 0, 0).unwrap(),
            modified_at: chrono::Utc.with_ymd_and_hms(2024, 1, 1, 0, 0, 0).unwrap(),
            favorite: true,
        };

        let export = ExportEntry::from(entry);
        assert_eq!(export.title, "Test");
        assert_eq!(export.username, "user@example.com");
        assert!(export.favorite);
    }

    #[test]
    fn export_json_excludes_passkey_references_from_password_backup() {
        let vault_path = temp_export_path("vault_json.db");
        let output_path = temp_export_path("export.json");
        let vault = VaultManager::create(&vault_path, b"test_password").unwrap();
        vault
            .add_entry(&test_entry(
                "Example Passkey",
                "passkey-ref:example.com:user@example.com",
                CredentialType::PasskeyReference,
            ))
            .unwrap();
        vault
            .add_entry(&test_entry(
                "Example Password",
                "password-secret",
                CredentialType::Password,
            ))
            .unwrap();

        export_to_json(&vault, &output_path).unwrap();

        let exported = std::fs::read_to_string(&output_path).unwrap();
        assert!(exported.contains("Example Password"));
        assert!(!exported.contains("Example Passkey"));
        assert!(!exported.contains("passkey-ref:example.com:user@example.com"));

        let _ = std::fs::remove_file(vault_path);
        let _ = std::fs::remove_file(output_path);
    }

    #[test]
    fn export_csv_excludes_passkey_references_from_password_backup() {
        let vault_path = temp_export_path("vault_csv.db");
        let output_path = temp_export_path("export.csv");
        let vault = VaultManager::create(&vault_path, b"test_password").unwrap();
        vault
            .add_entry(&test_entry(
                "Example Passkey",
                "passkey-ref:example.com:user@example.com",
                CredentialType::PasskeyReference,
            ))
            .unwrap();
        vault
            .add_entry(&test_entry(
                "Example Password",
                "password-secret",
                CredentialType::Password,
            ))
            .unwrap();

        export_to_csv(&vault, &output_path).unwrap();

        let exported = std::fs::read_to_string(&output_path).unwrap();
        assert!(exported.contains("Example Password"));
        assert!(!exported.contains("Example Passkey"));
        assert!(!exported.contains("passkey-ref:example.com:user@example.com"));

        let _ = std::fs::remove_file(vault_path);
        let _ = std::fs::remove_file(output_path);
    }
}
