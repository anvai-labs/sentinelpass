//! Authentication envelope for IPC frames.

use crate::message::IpcMessage;
use serde::{Deserialize, Serialize};

/// Where a request originated. This is provenance labeling for deprecation
/// gating and logging — NOT authentication. The security boundary for
/// external tools is the daemon token plus per-client grant tokens.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Origin {
    /// The browser native-messaging host process.
    NativeHost,
    /// A CLI invocation acting on behalf of a user or local tool.
    Cli,
}

/// Every IPC frame carries the daemon auth token alongside the message.
///
/// `client_token` and `origin` are optional and serde-defaulted in both
/// directions: an old client's frames parse on a new daemon and vice versa.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct IpcEnvelope {
    pub token: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub client_token: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub origin: Option<Origin>,
    pub message: IpcMessage,
}

impl IpcEnvelope {
    pub fn new(token: String, message: IpcMessage) -> Self {
        Self {
            token,
            client_token: None,
            origin: None,
            message,
        }
    }

    pub fn with_client_token(mut self, client_token: Option<String>) -> Self {
        self.client_token = client_token;
        self
    }

    pub fn with_origin(mut self, origin: Origin) -> Self {
        self.origin = Some(origin);
        self
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_ipc_envelope_serialization() {
        let envelope = IpcEnvelope {
            token: "test_token_12345".to_string(),
            client_token: None,
            origin: None,
            message: IpcMessage::GetCredential {
                domain: "example.com".to_string(),
            },
        };

        let serialized = serde_json::to_string(&envelope).unwrap();
        let deserialized: IpcEnvelope = serde_json::from_str(&serialized).unwrap();

        assert_eq!(deserialized.token, envelope.token);
        assert!(deserialized.client_token.is_none());
        assert!(deserialized.origin.is_none());
        match deserialized.message {
            IpcMessage::GetCredential { domain } => {
                assert_eq!(domain, "example.com");
            }
            _ => panic!("Wrong message type"),
        }
    }

    #[test]
    fn legacy_envelope_without_new_fields_parses() {
        // Frames written by <= 0.7 clients carry only token + message.
        let legacy = r#"{"token":"tok","message":"CheckVault"}"#;
        let parsed: IpcEnvelope = serde_json::from_str(legacy).unwrap();
        assert_eq!(parsed.token, "tok");
        assert!(parsed.client_token.is_none());
        assert!(parsed.origin.is_none());
    }

    #[test]
    fn envelope_with_origin_and_client_token_round_trips() {
        let envelope = IpcEnvelope::new("tok".to_string(), IpcMessage::CheckVault)
            .with_client_token(Some("spt_abc".to_string()))
            .with_origin(Origin::NativeHost);

        let serialized = serde_json::to_string(&envelope).unwrap();
        assert!(serialized.contains("\"origin\":\"native_host\""));
        let parsed: IpcEnvelope = serde_json::from_str(&serialized).unwrap();
        assert_eq!(parsed.origin, Some(Origin::NativeHost));
        assert_eq!(parsed.client_token.as_deref(), Some("spt_abc"));
    }
}
