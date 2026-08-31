//! IPC (Inter-Process Communication) for daemon communication
//!
//! The wire protocol (message types, envelope, framing, client, token
//! management, Windows frame crypto) lives in the [`sentinelpass_protocol`]
//! crate — the stable contract external clients embed. This module keeps the
//! daemon-side surface: audit logging, the request dispatcher
//! ([`IpcServer`]), and re-exports so existing
//! `sentinelpass_core::daemon::ipc::*` paths keep working.

#[cfg(windows)]
pub use sentinelpass_protocol::{
    decrypt_windows_ipc_frame, encrypt_windows_ipc_frame, windows_named_pipe_path,
};
pub use sentinelpass_protocol::{
    default_ipc_socket_path, default_ipc_token_path, load_ipc_token, load_or_create_ipc_token,
    CredentialSummary, ExternalSecretField, IpcClient, IpcEnvelope, IpcMessage, ProtocolError,
};

use crate::{AuditEventType, AuditLogger};
use tracing::warn;

pub(super) fn log_daemon_audit(
    logger: Option<&AuditLogger>,
    event_type: AuditEventType,
    context: &str,
) {
    if let Some(lg) = logger {
        if let Err(e) = lg.log(event_type, context) {
            warn!("Failed to write daemon audit event: {}", e);
        }
    }
    // No logger → init failed at startup; that warning was already emitted then.
}

pub(super) fn log_external_secret_audit(
    logger: Option<&AuditLogger>,
    client_id: Option<&str>,
    domain: &str,
    field: Option<&str>,
    purpose: Option<&str>,
    success: bool,
    context: &str,
) {
    log_daemon_audit(
        logger,
        AuditEventType::ExternalSecretAccess {
            client_id: client_id.map(ToString::to_string),
            domain: domain.to_string(),
            field: field.map(ToString::to_string),
            purpose: purpose.map(ToString::to_string),
            success,
        },
        context,
    );
}

pub mod server;
pub use server::IpcServer;

#[cfg(test)]
mod tests {
    use super::*;
    use std::path::{Path, PathBuf};

    #[cfg(unix)]
    #[tokio::test]
    async fn daemon_ipc_external_secret_lookup_requires_victor_allowlist() {
        use crate::daemon::DaemonVault;
        use crate::{
            CredentialType, Entry, ExternalSecretAllowlist, ExternalSecretField, VaultManager,
        };
        use chrono::Utc;
        use std::sync::Arc;
        use tokio::time::{sleep, Duration};

        let suffix = uuid::Uuid::new_v4().simple().to_string();
        let short_suffix = &suffix[..12];
        let vault_path = std::env::temp_dir().join(format!("sentinelpass_ipc_{short_suffix}.db"));
        let socket_path = PathBuf::from(format!("/tmp/sp-{short_suffix}.sock"));
        let allowlist_path =
            std::env::temp_dir().join(format!("sentinelpass_ipc_allowlist_{short_suffix}.json"));
        let password = b"test_password_123!";
        let auth_token = format!("test-token-{short_suffix}");

        let vault = VaultManager::create(&vault_path, password).unwrap();
        vault
            .add_entry(&Entry {
                entry_id: None,
                title: "Anthropic API".to_string(),
                username: "anthropic".to_string(),
                password: "sk-ant-test".to_string().into(),
                url: Some("anthropic".to_string()),
                notes: None,
                credential_type: CredentialType::ApiKey,
                created_at: Utc::now(),
                modified_at: Utc::now(),
                favorite: false,
            })
            .unwrap();
        vault
            .add_entry(&Entry {
                entry_id: None,
                title: "Example Passkey".to_string(),
                username: "user@example.com".to_string(),
                password: "passkey-ref:example.com:user@example.com"
                    .to_string()
                    .into(),
                url: Some("https://example.com".to_string()),
                notes: Some("Reference only; no WebAuthn private key material".to_string()),
                credential_type: CredentialType::PasskeyReference,
                created_at: Utc::now(),
                modified_at: Utc::now(),
                favorite: false,
            })
            .unwrap();
        drop(vault);

        let mut allowlist = ExternalSecretAllowlist::default();
        allowlist
            .allow("victor", "anthropic", ExternalSecretField::Password)
            .unwrap();
        allowlist
            .allow("victor", "example.com", ExternalSecretField::Password)
            .unwrap();
        allowlist.save_to_path(&allowlist_path).unwrap();

        let daemon_vault = Arc::new(DaemonVault::new(Some(vault_path.clone()), 300).unwrap());
        daemon_vault.unlock(password).await.unwrap();

        let server = Arc::new(IpcServer::new_with_allowlist_path(
            socket_path.clone(),
            daemon_vault,
            auth_token.clone(),
            allowlist_path.clone(),
        ));
        let server_task = tokio::spawn({
            let server = server.clone();
            async move { server.run().await }
        });

        for _ in 0..50 {
            if socket_path.exists() {
                break;
            }
            assert!(
                !server_task.is_finished(),
                "IPC server task exited before creating socket"
            );
            sleep(Duration::from_millis(10)).await;
        }
        assert!(socket_path.exists(), "IPC server did not create socket");

        let client = IpcClient::new_with_token(socket_path.clone(), auth_token);
        let response = client
            .send(IpcMessage::GetExternalSecret {
                client_id: "victor".to_string(),
                domain: "anthropic".to_string(),
                field: ExternalSecretField::Password,
                purpose: Some("victor-auth".to_string()),
            })
            .await
            .unwrap();
        match response {
            IpcMessage::GetExternalSecretResponse {
                value,
                authorized: true,
                error: None,
                ..
            } => assert_eq!(value, Some("sk-ant-test".to_string())),
            other => panic!("unexpected authorized lookup response: {:?}", other),
        }

        let response = client
            .send(IpcMessage::GetExternalSecret {
                client_id: "victor".to_string(),
                domain: "anthropic".to_string(),
                field: ExternalSecretField::Username,
                purpose: Some("victor-auth".to_string()),
            })
            .await
            .unwrap();
        match response {
            IpcMessage::GetExternalSecretResponse {
                value: None,
                authorized: false,
                error: Some(error),
                ..
            } => assert!(error.contains("not authorized")),
            other => panic!("unexpected denied lookup response: {:?}", other),
        }

        let response = client
            .send(IpcMessage::GetExternalSecret {
                client_id: "victor".to_string(),
                domain: "example.com".to_string(),
                field: ExternalSecretField::Password,
                purpose: Some("victor-auth".to_string()),
            })
            .await
            .unwrap();
        match response {
            IpcMessage::GetExternalSecretResponse {
                value: None,
                authorized: true,
                error: None,
                ..
            } => {}
            other => panic!("unexpected passkey lookup response: {:?}", other),
        }

        server_task.abort();
        let _ = std::fs::remove_file(socket_path);
        let _ = std::fs::remove_file(allowlist_path);
        let _ = std::fs::remove_file(vault_path);
    }
    #[cfg(unix)]
    #[tokio::test]
    async fn daemon_ipc_client_tokens_enforce_grant_access() {
        use crate::daemon::DaemonVault;
        use crate::{
            ClientTokenStatus, CredentialType, Entry, ExternalSecretAllowlist, ExternalSecretField,
            VaultManager,
        };
        use chrono::Utc;
        use std::sync::Arc;
        use tokio::time::{sleep, Duration};

        let suffix = uuid::Uuid::new_v4().simple().to_string();
        let short_suffix = &suffix[..12];
        let vault_path = std::env::temp_dir().join(format!("sentinelpass_tok_{short_suffix}.db"));
        let socket_path = PathBuf::from(format!("/tmp/sp-tok-{short_suffix}.sock"));
        let allowlist_path =
            std::env::temp_dir().join(format!("sentinelpass_tok_allow_{short_suffix}.json"));
        let password = b"test_password_123!";
        let auth_token = format!("test-token-{short_suffix}");

        let vault = VaultManager::create(&vault_path, password).unwrap();
        vault
            .add_entry(&Entry {
                entry_id: None,
                title: "Anthropic API".to_string(),
                username: "anthropic".to_string(),
                password: "sk-ant-live".to_string().into(),
                url: Some("anthropic".to_string()),
                notes: None,
                credential_type: CredentialType::ApiKey,
                created_at: Utc::now(),
                modified_at: Utc::now(),
                favorite: false,
            })
            .unwrap();
        drop(vault);

        let mut allowlist = ExternalSecretAllowlist::default();
        allowlist
            .allow("victor", "anthropic", ExternalSecretField::Password)
            .unwrap();
        let token = allowlist.mint_client_token("victor").unwrap();
        allowlist.save_to_path(&allowlist_path).unwrap();

        let daemon_vault = Arc::new(DaemonVault::new(Some(vault_path.clone()), 300).unwrap());
        daemon_vault.unlock(password).await.unwrap();

        let server = Arc::new(IpcServer::new_with_allowlist_path(
            socket_path.clone(),
            daemon_vault,
            auth_token.clone(),
            allowlist_path.clone(),
        ));
        let server_task = tokio::spawn({
            let server = server.clone();
            async move { server.run().await }
        });
        for _ in 0..50 {
            if socket_path.exists() {
                break;
            }
            assert!(!server_task.is_finished());
            sleep(Duration::from_millis(10)).await;
        }

        async fn lookup(
            socket_path: &Path,
            auth_token: &str,
            client_token: Option<String>,
        ) -> IpcMessage {
            let client =
                IpcClient::new_with_token(socket_path.to_path_buf(), auth_token.to_string())
                    .with_context(client_token, None);
            client
                .send(IpcMessage::GetExternalSecret {
                    client_id: "victor".to_string(),
                    domain: "anthropic".to_string(),
                    field: ExternalSecretField::Password,
                    purpose: Some("token-test".to_string()),
                })
                .await
                .unwrap()
        }

        // Token-enforced client: denied without token...
        match lookup(&socket_path, &auth_token, None).await {
            IpcMessage::GetExternalSecretResponse {
                value: None,
                authorized: false,
                error: Some(err),
                ..
            } => assert!(err.contains("SENTINELPASS_CLIENT_TOKEN")),
            other => panic!("expected token denial, got {:?}", other),
        }
        // ...denied with a wrong token...
        match lookup(&socket_path, &auth_token, Some("spt_wrong".to_string())).await {
            IpcMessage::GetExternalSecretResponse {
                authorized: false, ..
            } => {}
            other => panic!("expected wrong-token denial, got {:?}", other),
        }
        // ...and allowed with the minted token.
        match lookup(&socket_path, &auth_token, Some(token.clone())).await {
            IpcMessage::GetExternalSecretResponse {
                value: Some(value),
                authorized: true,
                error: None,
                ..
            } => assert_eq!(value, "sk-ant-live"),
            other => panic!("expected token grant, got {:?}", other),
        }

        // Rotation kills the old token.
        let mut allowlist = ExternalSecretAllowlist::load_from_path(&allowlist_path).unwrap();
        assert_eq!(
            allowlist.token_status("victor"),
            ClientTokenStatus::Enforced
        );
        let rotated = allowlist.rotate_client_token("victor").unwrap();
        allowlist.save_to_path(&allowlist_path).unwrap();
        match lookup(&socket_path, &auth_token, Some(token.clone())).await {
            IpcMessage::GetExternalSecretResponse {
                authorized: false, ..
            } => {}
            other => panic!("expected old-token denial after rotation, got {:?}", other),
        }
        match lookup(&socket_path, &auth_token, Some(rotated.clone())).await {
            IpcMessage::GetExternalSecretResponse {
                value: Some(_),
                authorized: true,
                ..
            } => {}
            other => panic!("expected rotated-token grant, got {:?}", other),
        }

        // Revocation is fail-closed, even with the newest token.
        let mut allowlist = ExternalSecretAllowlist::load_from_path(&allowlist_path).unwrap();
        allowlist.revoke_client_token("victor").unwrap();
        allowlist.save_to_path(&allowlist_path).unwrap();
        match lookup(&socket_path, &auth_token, Some(rotated)).await {
            IpcMessage::GetExternalSecretResponse {
                authorized: false, ..
            } => {}
            other => panic!("expected revoked denial, got {:?}", other),
        }

        server_task.abort();
        let _ = std::fs::remove_file(socket_path);
        let _ = std::fs::remove_file(allowlist_path);
        let _ = std::fs::remove_file(vault_path);
    }
    #[cfg(unix)]
    #[tokio::test]
    async fn daemon_ipc_locked_semantics_and_save_secret() {
        use crate::daemon::DaemonVault;
        use crate::{
            ClientTokenStatus, ExternalSecretAllowlist, ExternalSecretField, VaultManager,
        };
        use std::sync::Arc;
        use tokio::time::{sleep, Duration};

        let suffix = uuid::Uuid::new_v4().simple().to_string();
        let short_suffix = &suffix[..12];
        let vault_path = std::env::temp_dir().join(format!("sentinelpass_lock_{short_suffix}.db"));
        let socket_path = PathBuf::from(format!("/tmp/sp-lock-{short_suffix}.sock"));
        let allowlist_path =
            std::env::temp_dir().join(format!("sentinelpass_lock_allow_{short_suffix}.json"));
        let password = b"test_password_123!";
        let auth_token = format!("test-token-{short_suffix}");

        // Create the vault so DaemonVault::new accepts the path, but leave it locked.
        let vault = VaultManager::create(&vault_path, password).unwrap();
        drop(vault);

        let mut allowlist = ExternalSecretAllowlist::default();
        allowlist
            .upsert_grant(
                "sandhi",
                "sandhi:anthropic:key",
                ExternalSecretField::Password,
                None,
                true,
            )
            .unwrap();
        allowlist
            .allow(
                "readonly",
                "sandhi:openai:key",
                ExternalSecretField::Password,
            )
            .unwrap();
        let token = allowlist.mint_client_token("sandhi").unwrap();
        allowlist.save_to_path(&allowlist_path).unwrap();

        let daemon_vault = Arc::new(DaemonVault::new(Some(vault_path.clone()), 300).unwrap());
        let server = Arc::new(IpcServer::new_with_allowlist_path(
            socket_path.clone(),
            daemon_vault.clone(),
            auth_token.clone(),
            allowlist_path.clone(),
        ));
        let server_task = tokio::spawn({
            let server = server.clone();
            async move { server.run().await }
        });
        for _ in 0..50 {
            if socket_path.exists() {
                break;
            }
            assert!(!server_task.is_finished());
            sleep(Duration::from_millis(10)).await;
        }

        let client = IpcClient::new_with_token(socket_path.clone(), auth_token.clone());

        // Locked lookup: explicit locked flag, not a silent empty result.
        match client
            .send(IpcMessage::GetExternalSecret {
                client_id: "sandhi".to_string(),
                domain: "sandhi:anthropic:key".to_string(),
                field: ExternalSecretField::Password,
                purpose: Some("lock-test".to_string()),
            })
            .await
            .unwrap()
        {
            IpcMessage::GetExternalSecretResponse {
                value: None,
                authorized: true,
                error: None,
                locked: Some(true),
            } => {}
            other => panic!("expected locked response, got {:?}", other),
        }

        // Locked SaveSecret: locked flag on the write path too.
        match client
            .send(IpcMessage::SaveSecret {
                client_id: "sandhi".to_string(),
                domain: "sandhi:anthropic:key".to_string(),
                value: "sk-ant-new".to_string(),
                purpose: Some("lock-test".to_string()),
            })
            .await
            .unwrap()
        {
            IpcMessage::SaveSecretResponse {
                success: false,
                locked: Some(true),
                ..
            } => {}
            other => panic!("expected locked save response, got {:?}", other),
        }

        // Unlock; the write grant now applies.
        daemon_vault.unlock(password).await.unwrap();
        let client = client.with_context(Some(token.clone()), None);

        // SaveSecret with a write grant creates then updates the entry.
        for expected in ["sk-ant-new", "sk-ant-rotated"] {
            match client
                .send(IpcMessage::SaveSecret {
                    client_id: "sandhi".to_string(),
                    domain: "sandhi:anthropic:key".to_string(),
                    value: expected.to_string(),
                    purpose: None,
                })
                .await
                .unwrap()
            {
                IpcMessage::SaveSecretResponse {
                    success: true,
                    error: None,
                    ..
                } => {}
                other => panic!("expected save success for {expected}, got {:?}", other),
            }
            match client
                .send(IpcMessage::GetExternalSecret {
                    client_id: "sandhi".to_string(),
                    domain: "sandhi:anthropic:key".to_string(),
                    field: ExternalSecretField::Password,
                    purpose: None,
                })
                .await
                .unwrap()
            {
                IpcMessage::GetExternalSecretResponse {
                    value: Some(value),
                    authorized: true,
                    error: None,
                    ..
                } => assert_eq!(value, expected),
                other => panic!("expected readback of {expected}, got {:?}", other),
            }
        }

        // A read-only client cannot write.
        let readonly_client = IpcClient::new_with_token(socket_path.clone(), auth_token.clone())
            .with_context(Some("readonly-token".to_string()), None);
        match readonly_client
            .send(IpcMessage::SaveSecret {
                client_id: "readonly".to_string(),
                domain: "sandhi:openai:key".to_string(),
                value: "nope".to_string(),
                purpose: None,
            })
            .await
            .unwrap()
        {
            IpcMessage::SaveSecretResponse {
                success: false,
                error: Some(err),
                ..
            } => assert!(err.contains("no write grant")),
            other => panic!("expected write denial for readonly client, got {:?}", other),
        }

        // DeleteSecret is defined but rejected.
        match client
            .send(IpcMessage::DeleteSecret {
                client_id: "sandhi".to_string(),
                domain: "sandhi:anthropic:key".to_string(),
            })
            .await
            .unwrap()
        {
            IpcMessage::DeleteSecretResponse {
                deleted: false,
                error: Some(err),
                ..
            } => assert!(err.contains("not supported")),
            other => panic!("expected delete rejection, got {:?}", other),
        }

        server_task.abort();
        let _ = std::fs::remove_file(socket_path);
        let _ = std::fs::remove_file(allowlist_path);
        let _ = std::fs::remove_file(vault_path);
        let _ = ClientTokenStatus::Legacy;
    }
}
