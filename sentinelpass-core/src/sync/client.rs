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

        // WBS-617 (SR-SYNC-007): bounded, SAFE redirects. A redirect may
        // never (a) exceed BOUNDED_REDIRECTS hops, (b) change the origin
        // (host:port — a relay must not bounce credentials to a peer), or
        // (c) downgrade https to http. Off-policy hops surface as errors
        // instead of being followed.
        let origin = Self::origin_of(relay_url)?;
        let client = reqwest::Client::builder()
            .timeout(std::time::Duration::from_secs(30))
            .redirect(reqwest::redirect::Policy::custom(
                move |attempt| match redirect_decision(
                    attempt.previous().len(),
                    attempt.url(),
                    (&origin.0, origin.1.as_deref(), origin.2),
                ) {
                    Ok(()) => attempt.follow(),
                    Err(reason) => attempt.error(reason),
                },
            ))
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
        let path = "/api/v2/devices/register";
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

    /// v2 pairing (WBS-615/616): upload the encrypted bootstrap bound to a
    /// 256-bit secret. The relay stores only Argon2id(secret).
    pub async fn upload_bootstrap_v2(
        &self,
        secret_b64: &str,
        encrypted_bootstrap: &[u8],
        registration_proof: &[u8],
    ) -> Result<()> {
        let body = serde_json::json!({
            "secret": secret_b64,
            "encrypted_bootstrap": base64::engine::general_purpose::STANDARD
                .encode(encrypted_bootstrap),
            "registration_proof": base64::engine::general_purpose::STANDARD
                .encode(registration_proof),
        });
        let body_bytes = serde_json::to_vec(&body)
            .map_err(|e| PasswordManagerError::InvalidInput(e.to_string()))?;
        self.signed_post("/api/v2/pairing/bootstrap", &body_bytes)
            .await?;
        Ok(())
    }

    /// v2 migration (WBS-624): claim the authoritative re-baseline for the
    /// origin vault. The relay mints a fresh vault; a second claim for the
    /// same origin is refused (409).
    pub async fn claim_migration(&self, origin_vault_id: &Uuid) -> Result<Uuid> {
        let body = serde_json::json!({ "origin_vault_id": origin_vault_id });
        let body_bytes = serde_json::to_vec(&body)
            .map_err(|e| PasswordManagerError::InvalidInput(e.to_string()))?;
        let response = self
            .signed_post("/api/v2/migration/claim", &body_bytes)
            .await?;
        let parsed: serde_json::Value = serde_json::from_slice(&response).map_err(|e| {
            PasswordManagerError::InvalidInput(format!("invalid claim response: {e}"))
        })?;
        let id = parsed["new_vault_id"].as_str().ok_or_else(|| {
            PasswordManagerError::InvalidInput("claim response missing new_vault_id".to_string())
        })?;
        Uuid::parse_str(id)
            .map_err(|e| PasswordManagerError::InvalidInput(format!("invalid new_vault_id: {e}")))
    }

    /// v2 pairing: retrieve (and consume) the bootstrap by proving knowledge
    /// of the secret. Returns (encrypted_bootstrap, registration_proof).
    /// Material moves in the POST body — never in a URL (WBS-616).
    pub async fn retrieve_bootstrap_v2(&self, secret_b64: &str) -> Result<(Vec<u8>, Vec<u8>)> {
        let body = serde_json::json!({ "secret": secret_b64 });
        let body_bytes = serde_json::to_vec(&body)
            .map_err(|e| PasswordManagerError::InvalidInput(e.to_string()))?;
        let response = self
            .signed_post("/api/v2/pairing/bootstrap/retrieve", &body_bytes)
            .await?;
        let parsed: serde_json::Value = serde_json::from_slice(&response).map_err(|e| {
            PasswordManagerError::InvalidInput(format!("invalid retrieve response: {e}"))
        })?;
        let encrypted = base64::engine::general_purpose::STANDARD
            .decode(parsed["encrypted_bootstrap"].as_str().unwrap_or(""))
            .map_err(|e| PasswordManagerError::InvalidInput(format!("invalid bootstrap: {e}")))?;
        let proof = base64::engine::general_purpose::STANDARD
            .decode(parsed["registration_proof"].as_str().unwrap_or(""))
            .map_err(|e| PasswordManagerError::InvalidInput(format!("invalid proof: {e}")))?;
        Ok((encrypted, proof))
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

/// Redirect bound (WBS-617): small by design — a legitimate relay never
/// bounces more than a couple of times.
const BOUNDED_REDIRECTS: usize = 3;

impl SyncClient {
    /// (scheme, host, effective port) of a relay URL — the redirect-safety
    /// origin.
    fn origin_of(
        url: &str,
    ) -> std::result::Result<(String, Option<String>, Option<u16>), PasswordManagerError> {
        let parsed = url::Url::parse(url)
            .map_err(|e| PasswordManagerError::InvalidInput(format!("invalid relay URL: {e}")))?;
        let scheme = parsed.scheme().to_string();
        let port = match (parsed.port(), scheme.as_str()) {
            (Some(p), _) => Some(p),
            (None, "https") => Some(443),
            (None, "http") => Some(80),
            _ => None,
        };
        Ok((scheme, parsed.host_str().map(|h| h.to_string()), port))
    }
}

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

/// A transport that performs no I/O — for conflict-resolution paths that
/// only run local applies (take-remote) and never touch the relay.
pub struct DetachedTransport;

/// The WBS-617 redirect decision, extracted for direct testing: Ok = follow,
/// Err = the refusal reason. Policy: bounded hops, same scheme (no TLS
/// downgrade), same host+port (no cross-origin bounce), and the target must
/// pass the transport policy.
pub(crate) fn redirect_decision(
    previous_hops: usize,
    next: &url::Url,
    origin: (&str, Option<&str>, Option<u16>),
) -> std::result::Result<(), &'static str> {
    if previous_hops >= BOUNDED_REDIRECTS {
        return Err("too many redirects");
    }
    if next.scheme() != origin.0 {
        return Err("redirect changed the URL scheme (downgrade refused)");
    }
    if next.host_str() != origin.1 || next.port_or_known_default() != origin.2 {
        return Err("redirect left the relay origin");
    }
    if crate::sync::config::validate_relay_url(next.as_str()).is_err() {
        return Err("redirect target violates transport policy");
    }
    Ok(())
}

impl SyncTransport for DetachedTransport {
    fn push_v2<'a>(
        &'a self,
        _request: &'a PushRequestV2,
    ) -> Pin<Box<dyn Future<Output = Result<PushResponseV2>> + Send + 'a>> {
        Box::pin(async {
            Err(PasswordManagerError::NotImplemented(
                "resolution path never pushes".to_string(),
            ))
        })
    }

    fn pull_v2<'a>(
        &'a self,
        _request: &'a PullRequestV2,
    ) -> Pin<Box<dyn Future<Output = Result<PullResponseV2>> + Send + 'a>> {
        Box::pin(async {
            Err(PasswordManagerError::NotImplemented(
                "resolution path never pulls".to_string(),
            ))
        })
    }
}

#[cfg(test)]
mod redirect_tests {
    use super::*;

    fn origin_of_str(url: &str) -> (String, Option<String>, Option<u16>) {
        SyncClient::origin_of(url).unwrap()
    }

    /// WBS-617: the redirect decision is bounded, same-origin, and
    /// downgrade-refusing — SR-SYNC-007's "bounded, safe redirect behavior".
    #[test]
    fn redirect_policy_refuses_cross_origin_and_downgrades() {
        let origin = origin_of_str("https://relay.example.com:8443");

        // Same-origin https hop: followed.
        assert!(redirect_decision(
            0,
            &url::Url::parse("https://relay.example.com:8443/api/v2/sync/pull").unwrap(),
            (&origin.0, origin.1.as_deref(), origin.2),
        )
        .is_ok());

        // Cross-ORIGIN hop (different host): refused.
        assert!(redirect_decision(
            0,
            &url::Url::parse("https://evil.example.com/api/v2/sync/pull").unwrap(),
            (&origin.0, origin.1.as_deref(), origin.2),
        )
        .is_err());

        // TLS DOWNGRADE hop (same host, http): refused.
        assert!(redirect_decision(
            0,
            &url::Url::parse("http://relay.example.com:8443/x").unwrap(),
            (&origin.0, origin.1.as_deref(), origin.2),
        )
        .is_err());
    }

    #[test]
    fn redirect_policy_is_bounded() {
        let origin = origin_of_str("https://relay.example.com");
        let next = url::Url::parse("https://relay.example.com/api/v2/sync/pull").unwrap();
        for hops in 0..BOUNDED_REDIRECTS {
            assert!(
                redirect_decision(hops, &next, (&origin.0, origin.1.as_deref(), origin.2)).is_ok()
            );
        }
        assert!(redirect_decision(
            BOUNDED_REDIRECTS,
            &next,
            (&origin.0, origin.1.as_deref(), origin.2),
        )
        .is_err());
    }

    #[test]
    fn origin_parses_explicit_and_default_ports() {
        let (scheme, host, port) = origin_of_str("https://relay.example.com:8443");
        assert_eq!(
            (scheme.as_str(), host.as_deref(), port),
            ("https", Some("relay.example.com"), Some(8443))
        );
        let (scheme, host, port) = origin_of_str("https://relay.example.com");
        assert_eq!(
            (scheme.as_str(), host.as_deref(), port),
            ("https", Some("relay.example.com"), Some(443))
        );
    }
}
