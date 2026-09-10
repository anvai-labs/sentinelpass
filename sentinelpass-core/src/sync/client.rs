//! HTTP sync client for communicating with the relay server.

use crate::sync::auth::{format_auth_header, sign_request};
use crate::sync::models::{
    PullRequest, PullResponse, PushRequest, PushResponse, SyncDeviceInfo, SyncEntryBlob,
};
use crate::sync::v2::{PullRequestV2, PullResponseV2, PushRequestV2, PushResponseV2};
use crate::{PasswordManagerError, Result};
use ed25519_dalek::SigningKey;
use std::future::Future;
use std::pin::Pin;
use uuid::Uuid;

/// The v2 sync transport surface the engine consumes (ADR-006).
///
/// A trait so the engine can be driven against an in-memory relay model in
/// tests — loss/retry/duplicate/convergence evidence without HTTP — while
/// production uses [`SyncClient`].
pub trait SyncTransport: Send + Sync {
    /// Idempotent v2 push (duplicates replay their original results).
    fn push_v2<'a>(
        &'a self,
        request: &'a PushRequestV2,
    ) -> Pin<Box<dyn Future<Output = Result<PushResponseV2>> + Send + 'a>>;

    /// Paged v2 pull over the relay's vault mutation log.
    fn pull_v2<'a>(
        &'a self,
        request: &'a PullRequestV2,
    ) -> Pin<Box<dyn Future<Output = Result<PullResponseV2>> + Send + 'a>>;
}

/// HTTP client for the SentinelPass relay server.
pub struct SyncClient {
    client: reqwest::Client,
    relay_url: String,
    device_id: Uuid,
    signing_key: SigningKey,
}

impl SyncClient {
    /// Create a new sync client.
    pub fn new(relay_url: &str, device_id: Uuid, signing_key: SigningKey) -> Result<Self> {
        // Defense in depth: `init_sync` validates on store, but a config
        // written by an older build (or hand-edited) is rejected here too,
        // before any request is signed or sent.
        crate::sync::config::validate_relay_url(relay_url)?;
        let client = reqwest::Client::builder()
            .timeout(std::time::Duration::from_secs(30))
            .build()
            .map_err(|e| PasswordManagerError::Io(std::io::Error::other(e.to_string())))?;

        Ok(Self {
            client,
            relay_url: relay_url.trim_end_matches('/').to_string(),
            device_id,
            signing_key,
        })
    }

    /// Register this device with the relay.
    ///
    /// This helper is sufficient for first-device registration. Existing-vault joins on hardened
    /// relays should use `register_device_with_pairing`.
    pub async fn register_device(
        &self,
        device_name: &str,
        device_type: &str,
        public_key: &[u8],
        vault_id: &Uuid,
    ) -> Result<()> {
        self.register_device_with_pairing(
            device_name,
            device_type,
            public_key,
            vault_id,
            None,
            None,
        )
        .await
    }

    /// Register this device with the relay, optionally presenting a pairing proof for existing-vault joins.
    pub async fn register_device_with_pairing(
        &self,
        device_name: &str,
        device_type: &str,
        public_key: &[u8],
        vault_id: &Uuid,
        pairing_token: Option<&str>,
        registration_proof: Option<&[u8]>,
    ) -> Result<()> {
        let path = "/api/v1/devices/register";
        let mut body = serde_json::Map::new();
        body.insert("device_id".to_string(), serde_json::json!(self.device_id));
        body.insert("device_name".to_string(), serde_json::json!(device_name));
        body.insert("device_type".to_string(), serde_json::json!(device_type));
        body.insert(
            "public_key".to_string(),
            serde_json::json!(base64::engine::general_purpose::STANDARD.encode(public_key)),
        );
        body.insert("vault_id".to_string(), serde_json::json!(vault_id));
        if let Some(pairing_token) = pairing_token {
            body.insert(
                "pairing_token".to_string(),
                serde_json::json!(pairing_token),
            );
        }
        if let Some(registration_proof) = registration_proof {
            body.insert(
                "registration_proof".to_string(),
                serde_json::json!(
                    base64::engine::general_purpose::STANDARD.encode(registration_proof)
                ),
            );
        }
        let body_bytes = serde_json::to_vec(&body)
            .map_err(|e| PasswordManagerError::InvalidInput(e.to_string()))?;

        self.signed_post(path, &body_bytes).await?;
        Ok(())
    }

    /// Push changed entries to the relay.
    pub async fn push(&self, request: &PushRequest) -> Result<PushResponse> {
        let path = "/api/v1/sync/push";
        let body = serde_json::to_vec(request)
            .map_err(|e| PasswordManagerError::InvalidInput(e.to_string()))?;

        let response = self.signed_post(path, &body).await?;
        serde_json::from_slice(&response).map_err(|e| {
            PasswordManagerError::InvalidInput(format!("Invalid push response: {}", e))
        })
    }

    /// Pull changes from the relay since the given sequence.
    pub async fn pull(&self, request: &PullRequest) -> Result<PullResponse> {
        let path = "/api/v1/sync/pull";
        let body = serde_json::to_vec(request)
            .map_err(|e| PasswordManagerError::InvalidInput(e.to_string()))?;

        let response = self.signed_post(path, &body).await?;
        serde_json::from_slice(&response).map_err(|e| {
            PasswordManagerError::InvalidInput(format!("Invalid pull response: {}", e))
        })
    }

    /// v2 protocol (ADR-006): idempotent push with durable per-object
    /// results. Retrying the same mutations is always safe — duplicates
    /// replay their original durable results.
    pub async fn push_v2(
        &self,
        request: &crate::sync::v2::PushRequestV2,
    ) -> Result<crate::sync::v2::PushResponseV2> {
        let path = "/api/v2/sync/push";
        let body = serde_json::to_vec(request)
            .map_err(|e| PasswordManagerError::InvalidInput(e.to_string()))?;

        let response = self.signed_post(path, &body).await?;
        serde_json::from_slice(&response).map_err(|e| {
            PasswordManagerError::InvalidInput(format!("Invalid v2 push response: {}", e))
        })
    }

    /// v2 protocol: paged pull over the relay's vault mutation log.
    pub async fn pull_v2(
        &self,
        request: &crate::sync::v2::PullRequestV2,
    ) -> Result<crate::sync::v2::PullResponseV2> {
        let path = "/api/v2/sync/pull";
        let body = serde_json::to_vec(request)
            .map_err(|e| PasswordManagerError::InvalidInput(e.to_string()))?;

        let response = self.signed_post(path, &body).await?;
        serde_json::from_slice(&response).map_err(|e| {
            PasswordManagerError::InvalidInput(format!("Invalid v2 pull response: {}", e))
        })
    }

    /// Full vault push (initial sync).
    pub async fn full_push(&self, entries: &[SyncEntryBlob]) -> Result<PushResponse> {
        let path = "/api/v1/sync/full-push";
        let body = serde_json::to_vec(entries)
            .map_err(|e| PasswordManagerError::InvalidInput(e.to_string()))?;

        let response = self.signed_post(path, &body).await?;
        serde_json::from_slice(&response).map_err(|e| {
            PasswordManagerError::InvalidInput(format!("Invalid full-push response: {}", e))
        })
    }

    /// Full vault pull.
    pub async fn full_pull(&self) -> Result<Vec<SyncEntryBlob>> {
        let path = "/api/v1/sync/full-pull";
        let response = self.signed_post(path, b"").await?;
        serde_json::from_slice(&response).map_err(|e| {
            PasswordManagerError::InvalidInput(format!("Invalid full-pull response: {}", e))
        })
    }

    /// List known devices.
    pub async fn list_devices(&self) -> Result<Vec<SyncDeviceInfo>> {
        let path = "/api/v1/devices";
        let response = self.signed_get(path).await?;
        serde_json::from_slice(&response).map_err(|e| {
            PasswordManagerError::InvalidInput(format!("Invalid devices response: {}", e))
        })
    }

    /// Revoke a device.
    pub async fn revoke_device(&self, target_device_id: &Uuid) -> Result<()> {
        let path = format!("/api/v1/devices/{}/revoke", target_device_id);
        self.signed_post(&path, b"").await?;
        Ok(())
    }

    /// Upload pairing bootstrap blob.
    ///
    /// Hardened relays require `upload_bootstrap_with_proof`.
    pub async fn upload_bootstrap(
        &self,
        pairing_token: &str,
        encrypted_bootstrap: &[u8],
        pairing_salt: &[u8],
    ) -> Result<()> {
        self.upload_bootstrap_with_proof(pairing_token, encrypted_bootstrap, pairing_salt, None)
            .await
    }

    /// Upload pairing bootstrap blob with an optional registration proof (required by hardened relays).
    pub async fn upload_bootstrap_with_proof(
        &self,
        pairing_token: &str,
        encrypted_bootstrap: &[u8],
        pairing_salt: &[u8],
        registration_proof: Option<&[u8]>,
    ) -> Result<()> {
        let path = "/api/v1/pairing/bootstrap";
        let mut body = serde_json::Map::new();
        body.insert(
            "pairing_token".to_string(),
            serde_json::json!(pairing_token),
        );
        body.insert(
            "encrypted_bootstrap".to_string(),
            serde_json::json!(base64::engine::general_purpose::STANDARD.encode(encrypted_bootstrap)),
        );
        body.insert(
            "pairing_salt".to_string(),
            serde_json::json!(base64::engine::general_purpose::STANDARD.encode(pairing_salt)),
        );
        if let Some(registration_proof) = registration_proof {
            body.insert(
                "registration_proof".to_string(),
                serde_json::json!(
                    base64::engine::general_purpose::STANDARD.encode(registration_proof)
                ),
            );
        }
        let body_bytes = serde_json::to_vec(&body)
            .map_err(|e| PasswordManagerError::InvalidInput(e.to_string()))?;

        self.signed_post(path, &body_bytes).await?;
        Ok(())
    }

    /// Fetch pairing bootstrap blob (unauthenticated -- new device has no key yet).
    pub async fn fetch_bootstrap(&self, pairing_token: &str) -> Result<(Vec<u8>, Vec<u8>)> {
        let url = format!(
            "{}/api/v1/pairing/bootstrap/{}",
            self.relay_url, pairing_token
        );
        let resp = self
            .client
            .get(&url)
            .send()
            .await
            .map_err(|e| PasswordManagerError::Io(std::io::Error::other(e.to_string())))?;

        if !resp.status().is_success() {
            return Err(PasswordManagerError::InvalidInput(format!(
                "Bootstrap fetch failed: {}",
                resp.status()
            )));
        }

        let body: serde_json::Value = resp
            .json()
            .await
            .map_err(|e| PasswordManagerError::Io(std::io::Error::other(e.to_string())))?;

        let encrypted = base64::engine::general_purpose::STANDARD
            .decode(body["encrypted_bootstrap"].as_str().unwrap_or(""))
            .map_err(|e| PasswordManagerError::InvalidInput(format!("Invalid bootstrap: {}", e)))?;

        let salt = base64::engine::general_purpose::STANDARD
            .decode(body["pairing_salt"].as_str().unwrap_or(""))
            .map_err(|e| PasswordManagerError::InvalidInput(format!("Invalid salt: {}", e)))?;

        Ok((encrypted, salt))
    }

    // --- Internal helpers ---

    async fn signed_post(&self, path: &str, body: &[u8]) -> Result<Vec<u8>> {
        let timestamp = chrono::Utc::now().timestamp();
        let nonce = Uuid::new_v4().to_string();

        let signature = sign_request(&self.signing_key, "POST", path, timestamp, &nonce, body);

        let auth_header = format_auth_header(&self.device_id, timestamp, &nonce, &signature);
        let url = format!("{}{}", self.relay_url, path);

        let resp = self
            .client
            .post(&url)
            .header("Authorization", &auth_header)
            .header("Content-Type", "application/json")
            .body(body.to_vec())
            .send()
            .await
            .map_err(|e| PasswordManagerError::Io(std::io::Error::other(e.to_string())))?;

        if !resp.status().is_success() {
            let status = resp.status();
            let body = resp.text().await.unwrap_or_else(|_| "unknown".to_string());
            return Err(PasswordManagerError::InvalidInput(format!(
                "Relay error {}: {}",
                status, body
            )));
        }

        resp.bytes()
            .await
            .map(|b| b.to_vec())
            .map_err(|e| PasswordManagerError::Io(std::io::Error::other(e.to_string())))
    }

    async fn signed_get(&self, path: &str) -> Result<Vec<u8>> {
        let timestamp = chrono::Utc::now().timestamp();
        let nonce = Uuid::new_v4().to_string();

        let signature = sign_request(&self.signing_key, "GET", path, timestamp, &nonce, b"");

        let auth_header = format_auth_header(&self.device_id, timestamp, &nonce, &signature);
        let url = format!("{}{}", self.relay_url, path);

        let resp = self
            .client
            .get(&url)
            .header("Authorization", &auth_header)
            .send()
            .await
            .map_err(|e| PasswordManagerError::Io(std::io::Error::other(e.to_string())))?;

        if !resp.status().is_success() {
            let status = resp.status();
            let body = resp.text().await.unwrap_or_else(|_| "unknown".to_string());
            return Err(PasswordManagerError::InvalidInput(format!(
                "Relay error {}: {}",
                status, body
            )));
        }

        resp.bytes()
            .await
            .map(|b| b.to_vec())
            .map_err(|e| PasswordManagerError::Io(std::io::Error::other(e.to_string())))
    }
}

use base64::Engine;

impl SyncTransport for SyncClient {
    fn push_v2<'a>(
        &'a self,
        request: &'a PushRequestV2,
    ) -> Pin<Box<dyn Future<Output = Result<PushResponseV2>> + Send + 'a>> {
        Box::pin(SyncClient::push_v2(self, request))
    }

    fn pull_v2<'a>(
        &'a self,
        request: &'a PullRequestV2,
    ) -> Pin<Box<dyn Future<Output = Result<PullResponseV2>> + Send + 'a>> {
        Box::pin(SyncClient::pull_v2(self, request))
    }
}
