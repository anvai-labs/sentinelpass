//! Authentication envelope for IPC frames.

use crate::message::IpcMessage;
use serde::{Deserialize, Serialize};

/// Every IPC frame carries the daemon auth token alongside the message.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct IpcEnvelope {
    pub token: String,
    pub message: IpcMessage,
}

impl IpcEnvelope {
    pub fn new(token: String, message: IpcMessage) -> Self {
        Self { token, message }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_ipc_envelope_serialization() {
        let envelope = IpcEnvelope {
            token: "test_token_12345".to_string(),
            message: IpcMessage::GetCredential {
                domain: "example.com".to_string(),
            },
        };

        let serialized = serde_json::to_string(&envelope).unwrap();
        let deserialized: IpcEnvelope = serde_json::from_str(&serialized).unwrap();

        assert_eq!(deserialized.token, envelope.token);
        match deserialized.message {
            IpcMessage::GetCredential { domain } => {
                assert_eq!(domain, "example.com");
            }
            _ => panic!("Wrong message type"),
        }
    }
}
