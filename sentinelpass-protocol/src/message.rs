//! IPC message types — the daemon request/response vocabulary.

use serde::{Deserialize, Serialize};

/// Secret field that a local tool may request.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ExternalSecretField {
    Username,
    Password,
    Title,
}

impl ExternalSecretField {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Username => "username",
            Self::Password => "password",
            Self::Title => "title",
        }
    }
}

/// IPC message types
#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum IpcMessage {
    GetCredential {
        domain: String,
    },
    GetExternalSecret {
        client_id: String,
        domain: String,
        field: ExternalSecretField,
        purpose: Option<String>,
    },
    GetExternalSecretResponse {
        value: Option<String>,
        authorized: bool,
        error: Option<String>,
        /// Some(true) = vault locked (distinct from not-found).
        #[serde(default, skip_serializing_if = "Option::is_none")]
        locked: Option<bool>,
    },
    GetCredentialResponse {
        username: Option<String>,
        password: Option<String>,
        title: Option<String>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        locked: Option<bool>,
    },
    ListDomainCredentials {
        base_domain: String,
    },
    ListDomainCredentialsResponse {
        credentials: Vec<CredentialSummary>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        locked: Option<bool>,
    },
    GetTotpCode {
        domain: String,
    },
    GetTotpCodeResponse {
        code: Option<String>,
        seconds_remaining: Option<u32>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        locked: Option<bool>,
    },
    SaveCredential {
        domain: String,
        username: String,
        password: String,
        url: Option<String>,
    },
    SaveCredentialResponse {
        success: bool,
        error: Option<String>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        locked: Option<bool>,
    },
    /// External tool writes (upserts) one secret value for one scope.
    /// Requires a token-enforced grant with allow_write.
    SaveSecret {
        client_id: String,
        domain: String,
        value: String,
        purpose: Option<String>,
    },
    SaveSecretResponse {
        success: bool,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        locked: Option<bool>,
        error: Option<String>,
    },
    /// Defined for protocol completeness; the daemon currently rejects
    /// deletion because third-party-created entries have no ownership
    /// tracking yet (schema v5 shipped registry ownership groundwork; the
    /// delete decision itself stays deliberately rejected per ADR-001 D1).
    DeleteSecret {
        client_id: String,
        domain: String,
    },
    DeleteSecretResponse {
        deleted: bool,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        locked: Option<bool>,
        error: Option<String>,
    },
    UnlockVault {
        master_password: String,
    },
    UnlockVaultBiometric {
        prompt_reason: Option<String>,
    },
    UnlockVaultResponse {
        success: bool,
        error: Option<String>,
    },
    CheckVault,
    VaultStatusResponse {
        unlocked: bool,
        /// Master-password rotation generation of the vault (ADR-002).
        /// serde default keeps pre-epoch clients deserializing; 0 means
        /// the responder could not read metadata.
        #[serde(default)]
        key_epoch: i64,
    },
    LockVault,
    Shutdown,

    // --- Sync messages ---
    /// Trigger a sync cycle now (push + pull).
    SyncNow,
    /// Response to SyncNow.
    SyncNowResponse {
        success: bool,
        pushed: u64,
        pulled: u64,
        error: Option<String>,
    },
    /// Get sync status.
    SyncStatus,
    /// Sync status response.
    SyncStatusResponse {
        enabled: bool,
        device_id: Option<String>,
        device_name: Option<String>,
        relay_url: Option<String>,
        last_sync_at: Option<i64>,
        pending_changes: u64,
    },
}

/// Summary of a credential for listing (excludes password for bulk operations)
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CredentialSummary {
    pub username: String,
    pub title: Option<String>,
    pub domain: String,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_ipc_envelope_round_trip_is_in_envelope_tests() {
        // Envelope tests live in envelope.rs; this placeholder documents that.
    }

    #[test]
    fn test_credential_summary_serialization() {
        let summary = CredentialSummary {
            username: "user@example.com".to_string(),
            title: Some("Example Account".to_string()),
            domain: "example.com".to_string(),
        };

        let serialized = serde_json::to_string(&summary).unwrap();
        let deserialized: CredentialSummary = serde_json::from_str(&serialized).unwrap();

        assert_eq!(deserialized.username, summary.username);
        assert_eq!(deserialized.title, summary.title);
        assert_eq!(deserialized.domain, summary.domain);
    }

    #[test]
    fn test_credential_summary_without_title() {
        let summary = CredentialSummary {
            username: "user@example.com".to_string(),
            title: None,
            domain: "example.com".to_string(),
        };

        let serialized = serde_json::to_string(&summary).unwrap();
        let deserialized: CredentialSummary = serde_json::from_str(&serialized).unwrap();

        assert_eq!(deserialized.username, summary.username);
        assert_eq!(deserialized.title, None);
        assert_eq!(deserialized.domain, summary.domain);
    }

    #[test]
    fn test_message_types_serialize_correctly() {
        let messages = vec![
            IpcMessage::GetCredential {
                domain: "example.com".to_string(),
            },
            IpcMessage::GetExternalSecret {
                client_id: "victor".to_string(),
                domain: "anthropic".to_string(),
                field: ExternalSecretField::Password,
                purpose: Some("victor-auth".to_string()),
            },
            IpcMessage::CheckVault,
            IpcMessage::LockVault,
            IpcMessage::Shutdown,
            IpcMessage::ListDomainCredentials {
                base_domain: "example.com".to_string(),
            },
        ];

        for msg in messages {
            let serialized = serde_json::to_string(&msg).unwrap();
            let deserialized: IpcMessage = serde_json::from_str(&serialized).unwrap();

            // Verify round-trip
            match (&msg, &deserialized) {
                (
                    IpcMessage::GetCredential { domain: d1 },
                    IpcMessage::GetCredential { domain: d2 },
                ) => {
                    assert_eq!(d1, d2);
                }
                (
                    IpcMessage::GetExternalSecret {
                        client_id: c1,
                        domain: d1,
                        field: f1,
                        purpose: p1,
                    },
                    IpcMessage::GetExternalSecret {
                        client_id: c2,
                        domain: d2,
                        field: f2,
                        purpose: p2,
                    },
                ) => {
                    assert_eq!(c1, c2);
                    assert_eq!(d1, d2);
                    assert_eq!(f1, f2);
                    assert_eq!(p1, p2);
                }
                (
                    IpcMessage::ListDomainCredentials { base_domain: b1 },
                    IpcMessage::ListDomainCredentials { base_domain: b2 },
                ) => {
                    assert_eq!(b1, b2);
                }
                (IpcMessage::CheckVault, IpcMessage::CheckVault) => {}
                (IpcMessage::LockVault, IpcMessage::LockVault) => {}
                (IpcMessage::Shutdown, IpcMessage::Shutdown) => {}
                _ => panic!("Message type mismatch during round-trip"),
            }
        }
    }

    #[test]
    fn test_get_credential_response_serialization() {
        let response = IpcMessage::GetCredentialResponse {
            username: Some("user@example.com".to_string()),
            password: Some("password123".to_string()),
            title: Some("Example".to_string()),
            locked: None,
        };

        let serialized = serde_json::to_string(&response).unwrap();
        let deserialized: IpcMessage = serde_json::from_str(&serialized).unwrap();

        match deserialized {
            IpcMessage::GetCredentialResponse {
                username,
                password,
                title,
                locked: None,
            } => {
                assert_eq!(username, Some("user@example.com".to_string()));
                assert_eq!(password, Some("password123".to_string()));
                assert_eq!(title, Some("Example".to_string()));
            }
            _ => panic!("Wrong response type"),
        }
    }

    #[test]
    fn test_get_external_secret_response_serialization() {
        let response = IpcMessage::GetExternalSecretResponse {
            value: Some("secret-value".to_string()),
            authorized: true,
            error: None,
            locked: None,
        };

        let serialized = serde_json::to_string(&response).unwrap();
        let deserialized: IpcMessage = serde_json::from_str(&serialized).unwrap();

        match deserialized {
            IpcMessage::GetExternalSecretResponse {
                value,
                authorized,
                error,
                locked: None,
            } => {
                assert_eq!(value, Some("secret-value".to_string()));
                assert!(authorized);
                assert_eq!(error, None);
            }
            _ => panic!("Wrong response type"),
        }
    }

    #[test]
    fn test_list_domain_credentials_response_serialization() {
        let credentials = vec![
            CredentialSummary {
                username: "user1@example.com".to_string(),
                title: Some("Account 1".to_string()),
                domain: "example.com".to_string(),
            },
            CredentialSummary {
                username: "user2@example.com".to_string(),
                title: Some("Account 2".to_string()),
                domain: "example.com".to_string(),
            },
        ];

        let response = IpcMessage::ListDomainCredentialsResponse {
            credentials: credentials.clone(),
            locked: None,
        };

        let serialized = serde_json::to_string(&response).unwrap();
        let deserialized: IpcMessage = serde_json::from_str(&serialized).unwrap();

        match deserialized {
            IpcMessage::ListDomainCredentialsResponse {
                credentials: decoded,
                locked: None,
            } => {
                assert_eq!(decoded.len(), 2);
                assert_eq!(decoded[0].username, "user1@example.com");
                assert_eq!(decoded[1].username, "user2@example.com");
            }
            _ => panic!("Wrong response type"),
        }
    }

    #[test]
    fn test_save_credential_response_serialization() {
        let response = IpcMessage::SaveCredentialResponse {
            success: true,
            error: None,
            locked: None,
        };

        let serialized = serde_json::to_string(&response).unwrap();
        let deserialized: IpcMessage = serde_json::from_str(&serialized).unwrap();

        match deserialized {
            IpcMessage::SaveCredentialResponse {
                success,
                error,
                locked: None,
            } => {
                assert!(success);
                assert!(error.is_none());
            }
            _ => panic!("Wrong response type"),
        }
    }

    #[test]
    fn test_save_credential_error_response_serialization() {
        let response = IpcMessage::SaveCredentialResponse {
            success: false,
            error: Some("Vault is locked".to_string()),
            locked: None,
        };

        let serialized = serde_json::to_string(&response).unwrap();
        let deserialized: IpcMessage = serde_json::from_str(&serialized).unwrap();

        match deserialized {
            IpcMessage::SaveCredentialResponse {
                success,
                error,
                locked,
            } => {
                assert!(!success);
                assert_eq!(error, Some("Vault is locked".to_string()));
                assert_eq!(locked, None);
            }
            _ => panic!("Wrong response type"),
        }
    }

    #[test]
    fn test_unlock_vault_response_serialization() {
        let response = IpcMessage::UnlockVaultResponse {
            success: true,
            error: None,
        };

        let serialized = serde_json::to_string(&response).unwrap();
        let deserialized: IpcMessage = serde_json::from_str(&serialized).unwrap();

        match deserialized {
            IpcMessage::UnlockVaultResponse { success, error } => {
                assert!(success);
                assert!(error.is_none());
            }
            _ => panic!("Wrong response type"),
        }
    }

    #[test]
    fn test_vault_status_response_serialization() {
        let response = IpcMessage::VaultStatusResponse {
            unlocked: true,
            key_epoch: 1,
        };

        let serialized = serde_json::to_string(&response).unwrap();
        let deserialized: IpcMessage = serde_json::from_str(&serialized).unwrap();

        match deserialized {
            IpcMessage::VaultStatusResponse {
                unlocked,
                key_epoch,
            } => {
                assert!(unlocked);
                assert_eq!(key_epoch, 1);
            }
            _ => panic!("Wrong response type"),
        }
    }

    #[test]
    fn test_totp_response_serialization() {
        let response = IpcMessage::GetTotpCodeResponse {
            code: Some("123456".to_string()),
            seconds_remaining: Some(30),
            locked: None,
        };

        let serialized = serde_json::to_string(&response).unwrap();
        let deserialized: IpcMessage = serde_json::from_str(&serialized).unwrap();

        match deserialized {
            IpcMessage::GetTotpCodeResponse {
                code,
                seconds_remaining,
                locked: None,
            } => {
                assert_eq!(code, Some("123456".to_string()));
                assert_eq!(seconds_remaining, Some(30));
            }
            _ => panic!("Wrong response type"),
        }
    }

    #[test]
    fn test_save_credential_message_serialization() {
        let msg = IpcMessage::SaveCredential {
            domain: "example.com".to_string(),
            username: "user@example.com".to_string(),
            password: "secure_password".to_string(),
            url: Some("https://example.com".to_string()),
        };

        let serialized = serde_json::to_string(&msg).unwrap();
        let deserialized: IpcMessage = serde_json::from_str(&serialized).unwrap();

        match deserialized {
            IpcMessage::SaveCredential {
                domain,
                username,
                password,
                url,
            } => {
                assert_eq!(domain, "example.com");
                assert_eq!(username, "user@example.com");
                assert_eq!(password, "secure_password");
                assert_eq!(url, Some("https://example.com".to_string()));
            }
            _ => panic!("Wrong message type"),
        }
    }

    #[test]
    fn test_unlock_vault_message_serialization() {
        let msg = IpcMessage::UnlockVault {
            master_password: "test_password".to_string(),
        };

        let serialized = serde_json::to_string(&msg).unwrap();
        let deserialized: IpcMessage = serde_json::from_str(&serialized).unwrap();

        match deserialized {
            IpcMessage::UnlockVault { master_password } => {
                assert_eq!(master_password, "test_password");
            }
            _ => panic!("Wrong message type"),
        }
    }

    #[test]
    fn test_unlock_vault_biometric_message_serialization() {
        let msg = IpcMessage::UnlockVaultBiometric {
            prompt_reason: Some("Authenticate to unlock".to_string()),
        };

        let serialized = serde_json::to_string(&msg).unwrap();
        let deserialized: IpcMessage = serde_json::from_str(&serialized).unwrap();

        match deserialized {
            IpcMessage::UnlockVaultBiometric { prompt_reason } => {
                assert_eq!(prompt_reason, Some("Authenticate to unlock".to_string()));
            }
            _ => panic!("Wrong response type"),
        }
    }

    #[test]
    fn test_empty_credential_list_serialization() {
        let response = IpcMessage::ListDomainCredentialsResponse {
            credentials: vec![],
            locked: None,
        };

        let serialized = serde_json::to_string(&response).unwrap();
        let deserialized: IpcMessage = serde_json::from_str(&serialized).unwrap();

        match deserialized {
            IpcMessage::ListDomainCredentialsResponse {
                credentials,
                locked: None,
            } => {
                assert!(credentials.is_empty());
            }
            _ => panic!("Wrong response type"),
        }
    }

    #[test]
    fn test_get_totp_code_message_serialization() {
        let msg = IpcMessage::GetTotpCode {
            domain: "example.com".to_string(),
        };

        let serialized = serde_json::to_string(&msg).unwrap();
        let deserialized: IpcMessage = serde_json::from_str(&serialized).unwrap();

        match deserialized {
            IpcMessage::GetTotpCode { domain } => {
                assert_eq!(domain, "example.com");
            }
            _ => panic!("Wrong message type"),
        }
    }

    #[test]
    fn test_sync_status_message_serialization() {
        let msg = IpcMessage::SyncStatus;

        let serialized = serde_json::to_string(&msg).unwrap();
        let deserialized: IpcMessage = serde_json::from_str(&serialized).unwrap();

        match deserialized {
            IpcMessage::SyncStatus => {}
            _ => panic!("Wrong message type"),
        }
    }

    #[test]
    fn test_sync_status_response_serialization() {
        let response = IpcMessage::SyncStatusResponse {
            enabled: true,
            device_id: Some("device-123".to_string()),
            device_name: Some("Test Device".to_string()),
            relay_url: Some("https://relay.example.com".to_string()),
            last_sync_at: Some(1700000000),
            pending_changes: 5,
        };

        let serialized = serde_json::to_string(&response).unwrap();
        let deserialized: IpcMessage = serde_json::from_str(&serialized).unwrap();

        match deserialized {
            IpcMessage::SyncStatusResponse {
                enabled,
                device_id,
                device_name,
                relay_url,
                last_sync_at,
                pending_changes,
            } => {
                assert!(enabled);
                assert_eq!(device_id, Some("device-123".to_string()));
                assert_eq!(device_name, Some("Test Device".to_string()));
                assert_eq!(relay_url, Some("https://relay.example.com".to_string()));
                assert_eq!(last_sync_at, Some(1700000000));
                assert_eq!(pending_changes, 5);
            }
            _ => panic!("Wrong response type"),
        }
    }
}
