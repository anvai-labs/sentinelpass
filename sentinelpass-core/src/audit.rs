//! Audit logging for security events and operations

use crate::{DatabaseError, PasswordManagerError, Result};
use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use std::fs::{File, OpenOptions};
use std::io::Write;
use std::path::PathBuf;
use std::sync::{Arc, Mutex};
use tracing::info;

/// Audit log entry types
#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum AuditEventType {
    /// Vault operations
    VaultCreated,
    VaultUnlocked {
        success: bool,
    },
    VaultLocked,

    /// Credential operations
    CredentialCreated {
        entry_id: i64,
    },
    CredentialViewed {
        entry_id: i64,
    },
    CredentialModified {
        entry_id: i64,
    },
    CredentialDeleted {
        entry_id: i64,
    },
    CredentialsListed {
        count: usize,
    },
    ExternalSecretAccess {
        client_id: Option<String>,
        domain: String,
        field: Option<String>,
        purpose: Option<String>,
        success: bool,
    },
    ExternalSecretWrite {
        client_id: Option<String>,
        domain: String,
        purpose: Option<String>,
        success: bool,
    },

    /// Authentication events
    AuthenticationAttempt {
        success: bool,
    },
    AuthenticationFailure {
        reason: String,
    },

    /// Security events
    BruteForceDetected {
        ip_address: Option<String>,
    },
    VaultAutoLocked,
    VaultLockedManually,

    /// Import/Export
    DataExported {
        format: String,
    },
    DataImported {
        format: String,
        count: usize,
    },

    /// System events
    DaemonStarted,
    DaemonStopped,
    IpcServerStarted,
    IpcClientConnected,
    BiometricUnlockRequested {
        success: bool,
    },
}

/// Audit log entry
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AuditEntry {
    /// Timestamp of the event
    pub timestamp: DateTime<Utc>,
    /// Event type
    pub event_type: AuditEventType,
    /// Event severity (0-5, where 5 is most critical)
    pub severity: u8,
    /// Additional context data
    pub context: String,
    /// Process ID (if applicable)
    pub pid: Option<u32>,
    /// Thread ID (if applicable)
    pub tid: Option<u64>,
}

/// Audit logger
pub struct AuditLogger {
    log_file: PathBuf,
    writer: Arc<Mutex<Option<File>>>,
}

impl AuditLogger {
    /// Create a new audit logger
    pub fn new(log_dir: PathBuf) -> Result<Self> {
        let log_file = log_dir.join("audit.log");

        // Ensure log directory exists
        std::fs::create_dir_all(&log_dir).map_err(|e| {
            PasswordManagerError::from(DatabaseError::FileIo(format!(
                "Failed to create audit log directory: {}",
                e
            )))
        })?;

        // Open log file in append mode
        let file = OpenOptions::new()
            .create(true)
            .append(true)
            .open(&log_file)
            .map_err(|e| {
                PasswordManagerError::from(DatabaseError::FileIo(format!(
                    "Failed to open audit log: {}",
                    e
                )))
            })?;

        info!("Audit logger initialized: {:?}", log_file);

        Ok(Self {
            log_file,
            writer: Arc::new(Mutex::new(Some(file))),
        })
    }

    /// Log an audit event
    pub fn log(&self, event_type: AuditEventType, context: &str) -> Result<()> {
        let severity = Self::severity_for_event(&event_type);

        let entry = AuditEntry {
            timestamp: Utc::now(),
            event_type,
            severity,
            context: context.to_string(),
            pid: Some(std::process::id()),
            tid: None, // ThreadId cannot be converted to u64, using None
        };

        let json = serde_json::to_string(&entry).map_err(|e| {
            PasswordManagerError::from(DatabaseError::Serialization(format!(
                "Failed to serialize audit entry: {}",
                e
            )))
        })?;

        let log_line = format!("{}\n", json);

        if let Some(ref mut writer) = *self.writer.lock().map_err(|_| {
            PasswordManagerError::from(DatabaseError::LockPoisoned(
                "Failed to lock audit writer".to_string(),
            ))
        })? {
            writer.write_all(log_line.as_bytes()).map_err(|e| {
                PasswordManagerError::from(DatabaseError::FileIo(format!(
                    "Failed to write audit log: {}",
                    e
                )))
            })?;
            writer.flush().map_err(|e| {
                PasswordManagerError::from(DatabaseError::FileIo(format!(
                    "Failed to flush audit log: {}",
                    e
                )))
            })?;
        }

        Ok(())
    }

    /// Get severity level for an event type (0-5)
    fn severity_for_event(event: &AuditEventType) -> u8 {
        match event {
            // Critical events (5)
            AuditEventType::VaultCreated | AuditEventType::DataExported { .. } => 5,

            // High severity (4)
            AuditEventType::CredentialDeleted { .. }
            | AuditEventType::BruteForceDetected { .. } => 4,

            // Medium-high severity (3)
            AuditEventType::VaultUnlocked { success: true }
            | AuditEventType::CredentialModified { .. }
            | AuditEventType::ExternalSecretAccess { success: true, .. }
            | AuditEventType::ExternalSecretWrite { success: true, .. }
            | AuditEventType::BiometricUnlockRequested { success: true } => 3,

            // Medium severity (2)
            AuditEventType::VaultLocked
            | AuditEventType::CredentialCreated { .. }
            | AuditEventType::CredentialViewed { .. }
            | AuditEventType::VaultAutoLocked
            | AuditEventType::ExternalSecretAccess { success: false, .. }
            | AuditEventType::ExternalSecretWrite { success: false, .. }
            | AuditEventType::BiometricUnlockRequested { success: false } => 2,

            // Low severity (1)
            AuditEventType::CredentialsListed { .. } | AuditEventType::DataImported { .. } => 1,

            // Info (0)
            AuditEventType::AuthenticationAttempt { .. }
            | AuditEventType::VaultLockedManually
            | AuditEventType::AuthenticationFailure { .. }
            | AuditEventType::VaultUnlocked { success: false }
            | AuditEventType::DaemonStarted
            | AuditEventType::DaemonStopped
            | AuditEventType::IpcServerStarted
            | AuditEventType::IpcClientConnected => 0,
        }
    }

    /// Get all audit entries
    pub fn get_entries(&self, limit: usize) -> Result<Vec<AuditEntry>> {
        let content = std::fs::read_to_string(&self.log_file).map_err(|e| {
            PasswordManagerError::from(DatabaseError::FileIo(format!(
                "Failed to read audit log: {}",
                e
            )))
        })?;

        let entries: Vec<AuditEntry> = content
            .lines()
            .filter(|line| !line.trim().is_empty())
            .filter_map(|line| serde_json::from_str::<AuditEntry>(line).ok())
            .rev()
            .take(limit)
            .collect();

        Ok(entries)
    }

    /// Get audit entries since a specific timestamp
    pub fn get_entries_since(&self, since: DateTime<Utc>) -> Result<Vec<AuditEntry>> {
        let content = std::fs::read_to_string(&self.log_file).map_err(|e| {
            PasswordManagerError::from(DatabaseError::FileIo(format!(
                "Failed to read audit log: {}",
                e
            )))
        })?;

        let entries: Vec<AuditEntry> = content
            .lines()
            .filter(|line| !line.trim().is_empty())
            .filter_map(|line| serde_json::from_str::<AuditEntry>(line).ok())
            .filter(|entry| entry.timestamp > since)
            .collect();

        Ok(entries)
    }

    /// Get audit entries by severity level
    pub fn get_entries_by_severity(&self, min_severity: u8) -> Result<Vec<AuditEntry>> {
        let content = std::fs::read_to_string(&self.log_file).map_err(|e| {
            PasswordManagerError::from(DatabaseError::FileIo(format!(
                "Failed to read audit log: {}",
                e
            )))
        })?;

        let entries: Vec<AuditEntry> = content
            .lines()
            .filter(|line| !line.trim().is_empty())
            .filter_map(|line| serde_json::from_str::<AuditEntry>(line).ok())
            .filter(|entry| entry.severity >= min_severity)
            .collect();

        Ok(entries)
    }
}

/// Get the default audit log directory
pub fn get_audit_log_dir() -> PathBuf {
    crate::get_config_dir().join("audit")
}

/// Get the default audit log file path
pub fn get_audit_log_path() -> PathBuf {
    get_audit_log_dir().join("audit.log")
}

#[cfg(test)]
mod tests {
    use super::*;
    fn make_test_dir() -> PathBuf {
        let dir = std::env::temp_dir()
            .join("sentinelpass_test_audit")
            .join(uuid::Uuid::new_v4().to_string());
        std::fs::create_dir_all(&dir).unwrap();
        dir
    }

    #[test]
    fn test_severity_levels() {
        assert_eq!(
            AuditLogger::severity_for_event(&AuditEventType::BruteForceDetected {
                ip_address: None
            }),
            4
        );
        assert_eq!(
            AuditLogger::severity_for_event(&AuditEventType::VaultUnlocked { success: true }),
            3
        );
        assert_eq!(
            AuditLogger::severity_for_event(&AuditEventType::IpcClientConnected),
            0
        );
    }

    #[test]
    fn test_all_severity_levels_complete() {
        // Critical (5)
        assert_eq!(
            AuditLogger::severity_for_event(&AuditEventType::VaultCreated),
            5
        );
        assert_eq!(
            AuditLogger::severity_for_event(&AuditEventType::DataExported {
                format: "json".to_string()
            }),
            5
        );

        // High (4)
        assert_eq!(
            AuditLogger::severity_for_event(&AuditEventType::CredentialDeleted { entry_id: 1 }),
            4
        );

        // Medium-high (3)
        assert_eq!(
            AuditLogger::severity_for_event(&AuditEventType::CredentialModified { entry_id: 1 }),
            3
        );

        // Medium (2)
        assert_eq!(
            AuditLogger::severity_for_event(&AuditEventType::VaultLocked),
            2
        );
        assert_eq!(
            AuditLogger::severity_for_event(&AuditEventType::CredentialCreated { entry_id: 1 }),
            2
        );
        assert_eq!(
            AuditLogger::severity_for_event(&AuditEventType::CredentialViewed { entry_id: 1 }),
            2
        );
        assert_eq!(
            AuditLogger::severity_for_event(&AuditEventType::VaultAutoLocked),
            2
        );

        // Low (1)
        assert_eq!(
            AuditLogger::severity_for_event(&AuditEventType::CredentialsListed { count: 5 }),
            1
        );
        assert_eq!(
            AuditLogger::severity_for_event(&AuditEventType::DataImported {
                format: "csv".to_string(),
                count: 10,
            }),
            1
        );

        // Info (0)
        assert_eq!(
            AuditLogger::severity_for_event(&AuditEventType::AuthenticationAttempt {
                success: true
            }),
            0
        );
        assert_eq!(
            AuditLogger::severity_for_event(&AuditEventType::VaultLockedManually),
            0
        );
        assert_eq!(
            AuditLogger::severity_for_event(&AuditEventType::AuthenticationFailure {
                reason: "bad pw".to_string()
            }),
            0
        );
        assert_eq!(
            AuditLogger::severity_for_event(&AuditEventType::VaultUnlocked { success: false }),
            0
        );
        assert_eq!(
            AuditLogger::severity_for_event(&AuditEventType::DaemonStarted),
            0
        );
        assert_eq!(
            AuditLogger::severity_for_event(&AuditEventType::DaemonStopped),
            0
        );
        assert_eq!(
            AuditLogger::severity_for_event(&AuditEventType::IpcServerStarted),
            0
        );
        assert_eq!(
            AuditLogger::severity_for_event(&AuditEventType::ExternalSecretAccess {
                client_id: Some("victor".to_string()),
                domain: "anthropic".to_string(),
                field: Some("password".to_string()),
                purpose: Some("victor-auth".to_string()),
                success: true,
            }),
            3
        );
        assert_eq!(
            AuditLogger::severity_for_event(&AuditEventType::BiometricUnlockRequested {
                success: true
            }),
            3
        );
    }

    #[test]
    fn test_audit_logger_creates_file() {
        let tmp = make_test_dir();
        let logger = AuditLogger::new(tmp.clone()).unwrap();
        assert!(logger.log_file.exists());
        let _ = std::fs::remove_dir_all(&tmp);
    }

    #[test]
    fn test_audit_log_and_get_entries() {
        let tmp = make_test_dir();
        let logger = AuditLogger::new(tmp.clone()).unwrap();

        logger
            .log(AuditEventType::VaultCreated, "test vault")
            .unwrap();
        logger
            .log(AuditEventType::VaultLocked, "locked after use")
            .unwrap();

        let entries = logger.get_entries(10).unwrap();
        assert_eq!(entries.len(), 2);
        // get_entries returns in reverse order (most recent first)
        assert!(matches!(entries[0].event_type, AuditEventType::VaultLocked));
        assert!(matches!(
            entries[1].event_type,
            AuditEventType::VaultCreated
        ));
        let _ = std::fs::remove_dir_all(&tmp);
    }

    #[test]
    fn test_audit_get_entries_with_limit() {
        let tmp = make_test_dir();
        let logger = AuditLogger::new(tmp.clone()).unwrap();

        for i in 0..5 {
            logger
                .log(AuditEventType::CredentialCreated { entry_id: i }, "adding")
                .unwrap();
        }

        let entries = logger.get_entries(2).unwrap();
        assert_eq!(entries.len(), 2);
        let _ = std::fs::remove_dir_all(&tmp);
    }

    #[test]
    fn test_audit_get_entries_since() {
        let tmp = make_test_dir();
        let logger = AuditLogger::new(tmp.clone()).unwrap();

        let before = Utc::now() - chrono::Duration::seconds(2);

        logger.log(AuditEventType::DaemonStarted, "start").unwrap();
        logger.log(AuditEventType::VaultCreated, "create").unwrap();

        let entries = logger.get_entries_since(before).unwrap();
        assert_eq!(entries.len(), 2);

        // Future timestamp should return none
        let future = Utc::now() + chrono::Duration::seconds(60);
        let entries = logger.get_entries_since(future).unwrap();
        assert!(entries.is_empty());
        let _ = std::fs::remove_dir_all(&tmp);
    }

    #[test]
    fn test_audit_get_entries_by_severity() {
        let tmp = make_test_dir();
        let logger = AuditLogger::new(tmp.clone()).unwrap();

        logger
            .log(AuditEventType::DaemonStarted, "info event")
            .unwrap(); // severity 0
        logger
            .log(AuditEventType::VaultCreated, "critical event")
            .unwrap(); // severity 5
        logger
            .log(
                AuditEventType::CredentialDeleted { entry_id: 1 },
                "high event",
            )
            .unwrap(); // severity 4

        let critical = logger.get_entries_by_severity(5).unwrap();
        assert_eq!(critical.len(), 1);

        let high_and_above = logger.get_entries_by_severity(4).unwrap();
        assert_eq!(high_and_above.len(), 2);

        let all = logger.get_entries_by_severity(0).unwrap();
        assert_eq!(all.len(), 3);
        let _ = std::fs::remove_dir_all(&tmp);
    }

    #[test]
    fn test_audit_entry_serialization_roundtrip() {
        let entry = AuditEntry {
            timestamp: Utc::now(),
            event_type: AuditEventType::CredentialViewed { entry_id: 42 },
            severity: 2,
            context: "test context".to_string(),
            pid: Some(1234),
            tid: None,
        };

        let json = serde_json::to_string(&entry).unwrap();
        let deserialized: AuditEntry = serde_json::from_str(&json).unwrap();
        assert_eq!(deserialized.severity, 2);
        assert_eq!(deserialized.context, "test context");
    }

    #[test]
    fn test_external_secret_access_serialization_roundtrip() {
        let entry = AuditEntry {
            timestamp: Utc::now(),
            event_type: AuditEventType::ExternalSecretAccess {
                client_id: Some("victor".to_string()),
                domain: "anthropic".to_string(),
                field: Some("password".to_string()),
                purpose: Some("victor-auth".to_string()),
                success: true,
            },
            severity: 3,
            context: "secret field retrieved through daemon".to_string(),
            pid: Some(1234),
            tid: None,
        };

        let json = serde_json::to_string(&entry).unwrap();
        let deserialized: AuditEntry = serde_json::from_str(&json).unwrap();

        match deserialized.event_type {
            AuditEventType::ExternalSecretAccess {
                client_id,
                domain,
                field,
                purpose,
                success,
            } => {
                assert_eq!(client_id, Some("victor".to_string()));
                assert_eq!(domain, "anthropic");
                assert_eq!(field, Some("password".to_string()));
                assert_eq!(purpose, Some("victor-auth".to_string()));
                assert!(success);
            }
            other => panic!("unexpected event: {:?}", other),
        }
        assert_eq!(deserialized.severity, 3);
    }

    #[test]
    fn test_audit_log_paths() {
        let dir = get_audit_log_dir();
        assert!(dir.to_string_lossy().contains("audit"));

        let path = get_audit_log_path();
        assert!(path.to_string_lossy().ends_with("audit.log"));
    }
}
