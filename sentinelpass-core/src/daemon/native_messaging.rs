//! Native messaging protocol for browser extension communication.

use crate::daemon::ipc::{default_ipc_socket_path, IpcClient, IpcMessage};
use serde::{Deserialize, Serialize};
use std::io::{self, Read, Write};
use tracing::{error, info};

/// Native messaging protocol version
pub const PROTOCOL_VERSION: u32 = 1;

/// Message types
pub const MSG_GET_CREDENTIAL: &str = "get_credential";
pub const MSG_CREDENTIAL_RESPONSE: &str = "credential_response";
pub const MSG_SAVE_CREDENTIAL: &str = "save_credential";
pub const MSG_CHECK_CREDENTIAL_EXISTS: &str = "check_credential_exists";
pub const MSG_GET_TOTP_CODE: &str = "get_totp_code";
pub const MSG_TOTP_RESPONSE: &str = "totp_response";
pub const MSG_CHECK_VAULT: &str = "check_vault_status";
pub const MSG_LOCK_VAULT: &str = "lock_vault";
pub const MSG_VAULT_STATUS: &str = "vault_status";
pub const MSG_VAULT_STATUS_RESPONSE: &str = "vault_status_response";
pub const MSG_LIST_DOMAIN_CREDENTIALS: &str = "list_domain_credentials";

const fn default_protocol_version() -> u32 {
    PROTOCOL_VERSION
}

/// A native message from the browser extension
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct NativeMessage {
    #[serde(default = "default_protocol_version")]
    pub version: u32,
    #[serde(rename = "type")]
    pub msg_type: String,
    pub domain: Option<String>,
    #[serde(rename = "request_id")]
    pub request_id: Option<String>,
    #[serde(default)]
    pub data: Option<CredentialData>,
}

/// Response to a native message
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct NativeResponse {
    pub version: u32,
    #[serde(rename = "type")]
    pub msg_type: String,
    #[serde(rename = "request_id")]
    pub request_id: String,
    pub success: bool,
    pub data: Option<CredentialData>,
    pub error: Option<String>,
    pub unlocked: Option<bool>,
    pub exists: Option<bool>,
    pub totp_code: Option<String>,
    pub seconds_remaining: Option<u32>,
    pub credentials: Option<Vec<CredentialData>>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CredentialData {
    pub username: String,
    pub password: String,
    #[serde(default)]
    pub title: Option<String>,
    #[serde(default)]
    pub url: Option<String>,
}

/// Native messaging host for communication with browser
pub struct NativeMessagingHost;

impl Default for NativeMessagingHost {
    fn default() -> Self {
        Self::new()
    }
}

impl NativeMessagingHost {
    pub fn new() -> Self {
        Self
    }

    /// Run the native messaging host
    pub fn run(&mut self) -> Result<(), String> {
        // Read message from stdin
        let message = Self::read_message()?;
        let msg_type = message.msg_type.clone();
        let request_id = message
            .request_id
            .clone()
            .unwrap_or_else(|| uuid::Uuid::new_v4().to_string());

        info!(
            "Received native message: type={}, domain={:?}",
            message.msg_type, message.domain
        );

        // Create IPC client to communicate with daemon
        let socket_path = default_ipc_socket_path();
        let ipc_client = IpcClient::new(socket_path)
            .map_err(|e| format!("Failed to initialize IPC client: {}", e))?;

        // Convert native message to IPC message
        let ipc_msg = match msg_type.as_str() {
            MSG_GET_CREDENTIAL => {
                if let Some(domain) = message.domain.clone() {
                    IpcMessage::GetCredential { domain }
                } else {
                    Self::send_error(request_id, "Missing domain parameter")?;
                    return Ok(());
                }
            }
            MSG_CHECK_CREDENTIAL_EXISTS => {
                if let Some(domain) = message.domain.clone() {
                    IpcMessage::GetCredential { domain }
                } else {
                    Self::send_error(request_id, "Missing domain parameter")?;
                    return Ok(());
                }
            }
            MSG_GET_TOTP_CODE => {
                if let Some(domain) = message.domain.clone() {
                    IpcMessage::GetTotpCode { domain }
                } else {
                    Self::send_error(request_id, "Missing domain parameter")?;
                    return Ok(());
                }
            }
            MSG_SAVE_CREDENTIAL => {
                if let (Some(domain), Some(cred_data)) =
                    (message.domain.clone(), message.data.as_ref())
                {
                    IpcMessage::SaveCredential {
                        domain,
                        username: cred_data.username.clone(),
                        password: cred_data.password.clone(),
                        // Prefer explicit URL, fallback to title for older extension payloads.
                        url: cred_data.url.clone().or_else(|| cred_data.title.clone()),
                    }
                } else {
                    Self::send_error(request_id, "Missing domain or data parameter")?;
                    return Ok(());
                }
            }
            MSG_CHECK_VAULT => IpcMessage::CheckVault,
            MSG_LOCK_VAULT => IpcMessage::LockVault,
            MSG_LIST_DOMAIN_CREDENTIALS => {
                if let Some(domain) = message.domain.clone() {
                    IpcMessage::ListDomainCredentials {
                        base_domain: domain,
                    }
                } else {
                    Self::send_error(request_id, "Missing domain parameter")?;
                    return Ok(());
                }
            }
            _ => {
                Self::send_error(request_id, &format!("Unknown message type: {}", msg_type))?;
                return Ok(());
            }
        };

        // Send to daemon and get response
        let rt = tokio::runtime::Runtime::new()
            .map_err(|e| format!("Failed to create runtime: {}", e))?;

        let response = rt.block_on(async { ipc_client.send(ipc_msg).await });

        match response {
            Ok(IpcMessage::GetCredentialResponse {
                username,
                password,
                title,
                ..
            }) => {
                if msg_type == MSG_CHECK_CREDENTIAL_EXISTS {
                    let exists = username.is_some() && password.is_some();
                    Self::send_exists(request_id, exists)?;
                } else if let (Some(user), Some(pass)) = (username, password) {
                    Self::send_credential(request_id, user, pass, title)?;
                } else {
                    Self::send_error(request_id, "No credential found for domain")?;
                }
            }
            Ok(IpcMessage::GetTotpCodeResponse {
                code,
                seconds_remaining,
                ..
            }) => {
                if let Some(code) = code {
                    let seconds_remaining = seconds_remaining.unwrap_or(0);
                    Self::send_totp_code(request_id, code, seconds_remaining)?;
                } else {
                    Self::send_error(request_id, "No TOTP code found for domain")?;
                }
            }
            Ok(IpcMessage::SaveCredentialResponse { success, error, .. }) => {
                if msg_type == MSG_SAVE_CREDENTIAL {
                    Self::send_action_status(
                        request_id,
                        MSG_CREDENTIAL_RESPONSE,
                        success,
                        None,
                        error,
                    )?;
                } else {
                    Self::send_error(
                        request_id,
                        "Unexpected save-credential response for non-save request",
                    )?;
                }
            }
            Ok(IpcMessage::VaultStatusResponse { unlocked }) => {
                if msg_type == MSG_SAVE_CREDENTIAL {
                    Self::send_error(
                        request_id,
                        "Invalid daemon response for save_credential request",
                    )?;
                } else {
                    Self::send_vault_status(request_id, unlocked)?;
                }
            }
            Ok(IpcMessage::ListDomainCredentialsResponse { credentials, .. }) => {
                if msg_type == MSG_LIST_DOMAIN_CREDENTIALS {
                    Self::send_credential_list(request_id, credentials)?;
                } else {
                    Self::send_error(
                        request_id,
                        "Unexpected ListDomainCredentialsResponse for non-list request",
                    )?;
                }
            }
            Ok(_) => {
                Self::send_error(request_id, "Unexpected response from daemon")?;
            }
            Err(e) => {
                error!("IPC error: {}", e);
                Self::send_error(
                    request_id,
                    &format!("Failed to communicate with daemon: {}", e),
                )?;
            }
        }

        Ok(())
    }

    /// Read a message from stdin (length-prefixed JSON)
    fn read_message() -> Result<NativeMessage, String> {
        let mut length_bytes = [0u8; 4];
        io::stdin()
            .read_exact(&mut length_bytes)
            .map_err(|e| format!("Failed to read length: {}", e))?;

        let length = u32::from_le_bytes(length_bytes) as usize;

        if length == 0 || length > 1024 * 1024 {
            // Max 1MB
            return Err("Invalid message length".to_string());
        }

        let mut buffer = vec![0u8; length];
        io::stdin()
            .read_exact(&mut buffer)
            .map_err(|e| format!("Failed to read message: {}", e))?;

        serde_json::from_slice(&buffer).map_err(|e| format!("Failed to parse JSON: {}", e))
    }

    /// Write a response to stdout (length-prefixed JSON)
    fn write_response(response: &NativeResponse) -> Result<(), String> {
        let json = serde_json::to_vec(response)
            .map_err(|e| format!("Failed to serialize response: {}", e))?;

        let length = json.len() as u32;
        io::stdout()
            .write_all(&length.to_le_bytes())
            .map_err(|e| format!("Failed to write length: {}", e))?;

        io::stdout()
            .write_all(&json)
            .map_err(|e| format!("Failed to write response: {}", e))?;

        io::stdout()
            .flush()
            .map_err(|e| format!("Failed to flush: {}", e))?;

        Ok(())
    }

    /// Send error response
    pub fn send_error(request_id: String, error_msg: &str) -> Result<(), String> {
        let response = NativeResponse {
            version: PROTOCOL_VERSION,
            msg_type: MSG_CREDENTIAL_RESPONSE.to_string(),
            request_id,
            success: false,
            data: None,
            error: Some(error_msg.to_string()),
            unlocked: None,
            exists: None,
            totp_code: None,
            seconds_remaining: None,
            credentials: None,
        };
        Self::write_response(&response)
    }

    /// Send success response with credential
    pub fn send_credential(
        request_id: String,
        username: String,
        password: String,
        title: Option<String>,
    ) -> Result<(), String> {
        let response = NativeResponse {
            version: PROTOCOL_VERSION,
            msg_type: MSG_CREDENTIAL_RESPONSE.to_string(),
            request_id,
            success: true,
            data: Some(CredentialData {
                username,
                password,
                title,
                url: None,
            }),
            error: None,
            unlocked: None,
            exists: None,
            totp_code: None,
            seconds_remaining: None,
            credentials: None,
        };
        Self::write_response(&response)
    }

    /// Send vault status response
    pub fn send_vault_status(request_id: String, unlocked: bool) -> Result<(), String> {
        let response = NativeResponse {
            version: PROTOCOL_VERSION,
            msg_type: MSG_VAULT_STATUS.to_string(),
            request_id,
            success: true,
            data: None,
            error: None,
            unlocked: Some(unlocked),
            exists: None,
            totp_code: None,
            seconds_remaining: None,
            credentials: None,
        };
        Self::write_response(&response)
    }

    /// Send credential list response for list_domain_credentials
    pub fn send_credential_list(
        request_id: String,
        credentials: Vec<crate::daemon::ipc::CredentialSummary>,
    ) -> Result<(), String> {
        let credential_data: Vec<CredentialData> = credentials
            .into_iter()
            .map(|cred| CredentialData {
                username: cred.username,
                password: String::new(), // Passwords not included in domain list for security
                title: cred.title,
                url: Some(cred.domain),
            })
            .collect();

        let response = NativeResponse {
            version: PROTOCOL_VERSION,
            msg_type: MSG_CREDENTIAL_RESPONSE.to_string(),
            request_id,
            success: true,
            data: None,
            error: None,
            unlocked: None,
            exists: None,
            totp_code: None,
            seconds_remaining: None,
            credentials: Some(credential_data),
        };
        Self::write_response(&response)
    }

    /// Send existence response for check_credential_exists
    pub fn send_exists(request_id: String, exists: bool) -> Result<(), String> {
        let response = NativeResponse {
            version: PROTOCOL_VERSION,
            msg_type: MSG_CREDENTIAL_RESPONSE.to_string(),
            request_id,
            success: true,
            data: None,
            error: None,
            unlocked: None,
            exists: Some(exists),
            totp_code: None,
            seconds_remaining: None,
            credentials: None,
        };
        Self::write_response(&response)
    }

    /// Send success response with TOTP code.
    pub fn send_totp_code(
        request_id: String,
        totp_code: String,
        seconds_remaining: u32,
    ) -> Result<(), String> {
        let response = NativeResponse {
            version: PROTOCOL_VERSION,
            msg_type: MSG_TOTP_RESPONSE.to_string(),
            request_id,
            success: true,
            data: None,
            error: None,
            unlocked: None,
            exists: None,
            totp_code: Some(totp_code),
            seconds_remaining: Some(seconds_remaining),
            credentials: None,
        };
        Self::write_response(&response)
    }

    /// Send generic action status response
    pub fn send_action_status(
        request_id: String,
        msg_type: &str,
        success: bool,
        unlocked: Option<bool>,
        error: Option<String>,
    ) -> Result<(), String> {
        let response = NativeResponse {
            version: PROTOCOL_VERSION,
            msg_type: msg_type.to_string(),
            request_id,
            success,
            data: None,
            error,
            unlocked,
            exists: None,
            totp_code: None,
            seconds_remaining: None,
            credentials: None,
        };
        Self::write_response(&response)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn native_message_deserialization_full() {
        let json = r#"{
            "version": 1,
            "type": "get_credential",
            "domain": "example.com",
            "request_id": "abc-123"
        }"#;
        let msg: NativeMessage = serde_json::from_str(json).unwrap();
        assert_eq!(msg.version, 1);
        assert_eq!(msg.msg_type, "get_credential");
        assert_eq!(msg.domain.as_deref(), Some("example.com"));
        assert_eq!(msg.request_id.as_deref(), Some("abc-123"));
        assert!(msg.data.is_none());
    }

    #[test]
    fn native_message_deserialization_minimal() {
        let json = r#"{"type": "check_vault_status"}"#;
        let msg: NativeMessage = serde_json::from_str(json).unwrap();
        assert_eq!(msg.version, PROTOCOL_VERSION); // default
        assert_eq!(msg.msg_type, "check_vault_status");
        assert!(msg.domain.is_none());
        assert!(msg.request_id.is_none());
    }

    #[test]
    fn native_message_with_credential_data() {
        let json = r#"{
            "type": "save_credential",
            "domain": "github.com",
            "data": {
                "username": "dev@gh.com",
                "password": "secret123",
                "title": "GitHub",
                "url": "https://github.com"
            }
        }"#;
        let msg: NativeMessage = serde_json::from_str(json).unwrap();
        assert_eq!(msg.msg_type, "save_credential");
        let data = msg.data.unwrap();
        assert_eq!(data.username, "dev@gh.com");
        assert_eq!(data.password, "secret123");
        assert_eq!(data.title.as_deref(), Some("GitHub"));
        assert_eq!(data.url.as_deref(), Some("https://github.com"));
    }

    #[test]
    fn native_response_serialization() {
        let response = NativeResponse {
            version: PROTOCOL_VERSION,
            msg_type: MSG_CREDENTIAL_RESPONSE.to_string(),
            request_id: "req-1".to_string(),
            success: true,
            data: Some(CredentialData {
                username: "user".to_string(),
                password: "pass".to_string(),
                title: Some("Test".to_string()),
                url: None,
            }),
            error: None,
            unlocked: None,
            exists: None,
            totp_code: None,
            seconds_remaining: None,
            credentials: None,
        };

        let json = serde_json::to_string(&response).unwrap();
        assert!(json.contains("\"success\":true"));
        assert!(json.contains("\"username\":\"user\""));

        let deserialized: NativeResponse = serde_json::from_str(&json).unwrap();
        assert_eq!(deserialized.version, PROTOCOL_VERSION);
        assert!(deserialized.success);
        assert!(deserialized.data.is_some());
    }

    #[test]
    fn native_response_error() {
        let response = NativeResponse {
            version: PROTOCOL_VERSION,
            msg_type: MSG_CREDENTIAL_RESPONSE.to_string(),
            request_id: "req-2".to_string(),
            success: false,
            data: None,
            error: Some("No credential found".to_string()),
            unlocked: None,
            exists: None,
            totp_code: None,
            seconds_remaining: None,
            credentials: None,
        };

        let json = serde_json::to_string(&response).unwrap();
        let deserialized: NativeResponse = serde_json::from_str(&json).unwrap();
        assert!(!deserialized.success);
        assert_eq!(deserialized.error.as_deref(), Some("No credential found"));
    }

    #[test]
    fn native_response_vault_status() {
        let response = NativeResponse {
            version: PROTOCOL_VERSION,
            msg_type: MSG_VAULT_STATUS.to_string(),
            request_id: "req-3".to_string(),
            success: true,
            data: None,
            error: None,
            unlocked: Some(true),
            exists: None,
            totp_code: None,
            seconds_remaining: None,
            credentials: None,
        };

        let json = serde_json::to_string(&response).unwrap();
        let deserialized: NativeResponse = serde_json::from_str(&json).unwrap();
        assert_eq!(deserialized.unlocked, Some(true));
    }

    #[test]
    fn native_response_exists() {
        let response = NativeResponse {
            version: PROTOCOL_VERSION,
            msg_type: MSG_CREDENTIAL_RESPONSE.to_string(),
            request_id: "req-4".to_string(),
            success: true,
            data: None,
            error: None,
            unlocked: None,
            exists: Some(true),
            totp_code: None,
            seconds_remaining: None,
            credentials: None,
        };

        let json = serde_json::to_string(&response).unwrap();
        let deserialized: NativeResponse = serde_json::from_str(&json).unwrap();
        assert_eq!(deserialized.exists, Some(true));
    }

    #[test]
    fn native_response_totp_code() {
        let response = NativeResponse {
            version: PROTOCOL_VERSION,
            msg_type: MSG_TOTP_RESPONSE.to_string(),
            request_id: "req-5".to_string(),
            success: true,
            data: None,
            error: None,
            unlocked: None,
            exists: None,
            totp_code: Some("123456".to_string()),
            seconds_remaining: Some(15),
            credentials: None,
        };

        let json = serde_json::to_string(&response).unwrap();
        let deserialized: NativeResponse = serde_json::from_str(&json).unwrap();
        assert_eq!(deserialized.totp_code.as_deref(), Some("123456"));
        assert_eq!(deserialized.seconds_remaining, Some(15));
    }

    #[test]
    fn credential_data_optional_fields() {
        let json = r#"{"username": "u", "password": "p"}"#;
        let data: CredentialData = serde_json::from_str(json).unwrap();
        assert_eq!(data.username, "u");
        assert!(data.title.is_none());
        assert!(data.url.is_none());
    }

    #[test]
    fn native_messaging_host_construction() {
        let _host = NativeMessagingHost::new();
        let _host2 = NativeMessagingHost;
    }

    #[test]
    fn message_type_constants() {
        assert_eq!(MSG_GET_CREDENTIAL, "get_credential");
        assert_eq!(MSG_SAVE_CREDENTIAL, "save_credential");
        assert_eq!(MSG_CHECK_CREDENTIAL_EXISTS, "check_credential_exists");
        assert_eq!(MSG_GET_TOTP_CODE, "get_totp_code");
        assert_eq!(MSG_CHECK_VAULT, "check_vault_status");
        assert_eq!(MSG_LOCK_VAULT, "lock_vault");
        assert_eq!(MSG_CREDENTIAL_RESPONSE, "credential_response");
        assert_eq!(MSG_TOTP_RESPONSE, "totp_response");
        assert_eq!(MSG_VAULT_STATUS, "vault_status");
        assert_eq!(MSG_VAULT_STATUS_RESPONSE, "vault_status_response");
        assert_eq!(PROTOCOL_VERSION, 1);
    }
}
