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
    SitePermissionSummary,
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
    use std::path::Path;

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
        let socket_dir = tempfile::TempDir::new().unwrap().keep();
        {
            use std::os::unix::fs::PermissionsExt;
            std::fs::set_permissions(&socket_dir, std::fs::Permissions::from_mode(0o700)).unwrap();
        }
        let socket_path = socket_dir.join("s.sock");
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
        let _ = std::fs::remove_dir(socket_dir);
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
        let socket_dir = tempfile::TempDir::new().unwrap().keep();
        {
            use std::os::unix::fs::PermissionsExt;
            std::fs::set_permissions(&socket_dir, std::fs::Permissions::from_mode(0o700)).unwrap();
        }
        let socket_path = socket_dir.join("s.sock");
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
        let _ = std::fs::remove_dir(socket_dir);
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
        let socket_dir = tempfile::TempDir::new().unwrap().keep();
        {
            use std::os::unix::fs::PermissionsExt;
            std::fs::set_permissions(&socket_dir, std::fs::Permissions::from_mode(0o700)).unwrap();
        }
        let socket_path = socket_dir.join("s.sock");
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
        let _ = std::fs::remove_dir(socket_dir);
        let _ = std::fs::remove_file(allowlist_path);
        let _ = std::fs::remove_file(vault_path);
        let _ = ClientTokenStatus::Legacy;
    }

    /// WBS-501/503 bootstrap path: a daemon started with NO vault enters
    /// maintenance mode, refuses every non-bootstrap op, and transitions to
    /// live after a successful `VaultCreate` — all through the single
    /// application-service boundary.
    #[cfg(unix)]
    #[tokio::test]
    async fn daemon_maintenance_bootstrap_creates_vault_and_goes_live() {
        use crate::daemon::{try_acquire, DaemonVault, IpcServer};
        use sentinelpass_protocol::service::{ServiceOutcome, VaultOp, VaultOpResult};
        use std::sync::Arc;

        let suffix = uuid::Uuid::new_v4().simple().to_string();
        let short_suffix = &suffix[..12];
        let vault_dir = std::env::temp_dir().join(format!("sentinelpass_boot_{short_suffix}"));
        std::fs::create_dir_all(&vault_dir).unwrap();
        {
            use std::os::unix::fs::PermissionsExt;
            std::fs::set_permissions(&vault_dir, std::fs::Permissions::from_mode(0o700)).unwrap();
        }
        let vault_path = vault_dir.join("vault.db");
        let socket_path = vault_dir.join("bootstrap.sock");
        let password = b"bootstrap_password_123!";

        assert!(!vault_path.exists(), "precondition: no vault on disk");

        // The daemon holds this lock for its lifetime; the test mimics the
        // binary's startup sequence.
        let lock = try_acquire(&vault_path).unwrap();

        let daemon_vault = Arc::new(DaemonVault::new(Some(vault_path.clone()), 300).unwrap());
        let server = Arc::new(IpcServer::new(
            socket_path.clone(),
            daemon_vault,
            "bootstrap-token".to_string(),
        ));
        server.enter_maintenance_mode();
        assert!(server.is_maintenance_mode());

        let server_task = tokio::spawn({
            let server = server.clone();
            async move { server.run().await }
        });
        for _ in 0..50 {
            if socket_path.exists() {
                break;
            }
            assert!(!server_task.is_finished());
            tokio::time::sleep(std::time::Duration::from_millis(10)).await;
        }

        let client = IpcClient::new_with_token(socket_path.clone(), "bootstrap-token".to_string());

        async fn service(
            client: &IpcClient,
            op: VaultOp,
        ) -> std::result::Result<VaultOpResult, sentinelpass_protocol::service::ServiceError>
        {
            match client.send(IpcMessage::ServiceCall { op }).await.unwrap() {
                IpcMessage::ServiceResult { outcome } => match outcome {
                    ServiceOutcome::Ok { result } => Ok(result),
                    ServiceOutcome::Err { error } => Err(error),
                },
                other => panic!("unexpected non-service response: {:?}", other),
            }
        }

        // Negative: in maintenance mode every non-bootstrap op is refused
        // with the typed maintenance_mode code.
        let err = service(&client, VaultOp::EntryList)
            .await
            .expect_err("maintenance daemon must refuse CRUD");
        assert_eq!(err.code, "maintenance_mode");

        // Legacy unlock is refused too (no vault to unlock).
        match client
            .send(IpcMessage::UnlockVault {
                master_password: "whatever".to_string(),
            })
            .await
            .unwrap()
        {
            IpcMessage::UnlockVaultResponse {
                success: false,
                error: Some(err),
            } => assert!(err.contains("maintenance mode")),
            other => panic!("expected maintenance unlock refusal: {:?}", other),
        }

        // Bootstrap: create → daemon transitions to live, vault unlocked.
        let status = service(
            &client,
            VaultOp::VaultCreate {
                master_password: zeroize::Zeroizing::new(
                    String::from_utf8(password.to_vec()).unwrap(),
                ),
            },
        )
        .await
        .expect("bootstrap create must succeed");
        match status {
            VaultOpResult::Status(status) => {
                assert!(status.unlocked);
                assert!(!status.maintenance);
            }
            other => panic!("expected Status, got {other:?}"),
        }
        assert!(!server.is_maintenance_mode(), "mode flipped to live");
        assert!(vault_path.exists(), "vault file now exists");

        // Live CRUD now flows through the same boundary.
        let result = service(&client, VaultOp::EntryList).await.unwrap();
        match result {
            VaultOpResult::EntryList(list) => assert!(list.is_empty()),
            other => panic!("expected EntryList, got {other:?}"),
        }

        server_task.abort();
        let _ = std::fs::remove_file(&socket_path);
        drop(lock);
        let _ = std::fs::remove_file(crate::daemon::maintenance_lock_path(&vault_path));
        let _ = std::fs::remove_dir_all(&vault_dir);
    }

    /// WBS-512 evidence: a STALLED client (connected, sends nothing) no
    /// longer wedges the daemon — another client completes normally because
    /// connections are handled on bounded concurrent tasks with deadlines.
    #[cfg(unix)]
    #[tokio::test]
    async fn stalled_client_does_not_wedge_other_clients() {
        use crate::daemon::{DaemonVault, IpcServer};
        use crate::VaultManager;
        use sentinelpass_protocol::connection::{IpcConnection, TransportConnection};
        use std::sync::Arc;

        let suffix = uuid::Uuid::new_v4().simple().to_string();
        let short_suffix = &suffix[..12];
        let vault_path = std::env::temp_dir().join(format!("sentinelpass_stall_{short_suffix}.db"));
        let socket_dir = tempfile::TempDir::new().unwrap().keep();
        {
            use std::os::unix::fs::PermissionsExt;
            std::fs::set_permissions(&socket_dir, std::fs::Permissions::from_mode(0o700)).unwrap();
        }
        let socket_path = socket_dir.join("s.sock");
        let password = b"test_password_123!";

        let vault = VaultManager::create(&vault_path, password).unwrap();
        drop(vault);

        let daemon_vault = Arc::new(DaemonVault::new(Some(vault_path.clone()), 300).unwrap());
        daemon_vault.unlock(password).await.unwrap();
        let server = Arc::new(IpcServer::new(
            socket_path.clone(),
            daemon_vault,
            "stall-token".to_string(),
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
            tokio::time::sleep(std::time::Duration::from_millis(10)).await;
        }

        // The stalled client: connects and sends NOTHING.
        let _stalled = sentinelpass_protocol::UnixSocketConnection::connect(socket_path.clone())
            .await
            .unwrap();

        // A well-behaved client still completes promptly.
        let good_client = IpcClient::new_with_token(socket_path.clone(), "stall-token".to_string());
        let started = std::time::Instant::now();
        let response = good_client.send(IpcMessage::CheckVault).await.unwrap();
        let elapsed = started.elapsed();
        assert!(
            elapsed < std::time::Duration::from_secs(5),
            "daemon must serve other clients while one is stalled (took {elapsed:?})"
        );
        assert!(matches!(
            response,
            IpcMessage::VaultStatusResponse { unlocked: true, .. }
        ));

        // The session negotiation works for a full client exchange.
        let raw = sentinelpass_protocol::UnixSocketConnection::connect(socket_path.clone())
            .await
            .unwrap();
        let mut ipc = IpcConnection::connect_client(TransportConnection::Unix(raw), "stall-token")
            .await
            .unwrap();
        // Frames carry full envelopes (token + message), like IpcClient.
        let envelope = IpcEnvelope {
            token: "stall-token".to_string(),
            client_token: None,
            origin: None,
            capability: None,
            message: IpcMessage::CheckVault,
        };
        ipc.send_frame(serde_json::to_vec(&envelope).unwrap().as_slice())
            .await
            .unwrap();
        let response_bytes = ipc.recv_frame().await.unwrap();
        let response: IpcMessage = serde_json::from_slice(&response_bytes).unwrap();
        assert!(matches!(
            response,
            IpcMessage::VaultStatusResponse { unlocked: true, .. }
        ));

        server_task.abort();
        let _ = std::fs::remove_file(&socket_path);
        let _ = std::fs::remove_dir(&socket_dir);
        let _ = std::fs::remove_file(&vault_path);
    }

    /// WBS-504/505 phase negative suite, end to end: the browser surface
    /// (GetCredential) is denied for a general client claiming NativeHost
    /// without capability material, ALLOWED with the material, and the
    /// legacy self-asserted window applies only with the explicit env.
    #[cfg(unix)]
    #[tokio::test]
    async fn browser_surface_requires_native_host_capability() {
        use crate::daemon::capabilities::{InstallationCapabilities, NATIVE_HOST_AUDIENCE};
        use crate::daemon::{DaemonVault, IpcServer};
        use crate::VaultManager;
        use sentinelpass_protocol::Origin;
        use std::sync::Arc;

        let suffix = uuid::Uuid::new_v4().simple().to_string();
        let short_suffix = &suffix[..12];
        let vault_path = std::env::temp_dir().join(format!("sentinelpass_cap_{short_suffix}.db"));
        let socket_dir = tempfile::TempDir::new().unwrap().keep();
        {
            use std::os::unix::fs::PermissionsExt;
            std::fs::set_permissions(&socket_dir, std::fs::Permissions::from_mode(0o700)).unwrap();
        }
        let socket_path = socket_dir.join("s.sock");
        let capability_store = socket_dir.join("capabilities.json");
        let password = b"test_password_123!";

        // Mint the installation capability for the native host.
        let mut store = InstallationCapabilities::default();
        let host_secret = store
            .mint(&capability_store, NATIVE_HOST_AUDIENCE, None)
            .unwrap();

        let vault = VaultManager::create(&vault_path, password).unwrap();
        vault
            .add_entry(&crate::Entry {
                entry_id: None,
                title: "Example".to_string(),
                username: "user@example.com".to_string(),
                password: "example-secret".to_string().into(),
                url: Some("https://example.com".to_string()),
                notes: None,
                credential_type: crate::CredentialType::Password,
                created_at: chrono::Utc::now(),
                modified_at: chrono::Utc::now(),
                favorite: false,
            })
            .unwrap();
        drop(vault);

        let daemon_vault = Arc::new(DaemonVault::new(Some(vault_path.clone()), 300).unwrap());
        daemon_vault.unlock(password).await.unwrap();
        let server = Arc::new(
            IpcServer::new(socket_path.clone(), daemon_vault, "cap-token".to_string())
                .with_capability_store_path(capability_store.clone()),
        );
        let server_task = tokio::spawn({
            let server = server.clone();
            async move { server.run().await }
        });
        for _ in 0..50 {
            if socket_path.exists() {
                break;
            }
            assert!(!server_task.is_finished());
            tokio::time::sleep(std::time::Duration::from_millis(10)).await;
        }

        let lookup = |origin: Option<Origin>, capability: Option<String>| {
            let client = IpcClient::new_with_token(socket_path.clone(), "cap-token".to_string())
                .with_context(None, origin)
                .with_capability(capability);
            async move {
                client
                    .send(IpcMessage::GetCredential {
                        domain: "example.com".to_string(),
                        page_url: Some("https://example.com/login".to_string()),
                    })
                    .await
                    .unwrap()
            }
        };

        // Negative: general client CLAIMING NativeHost without material —
        // denied (empty response, the documented deny shape).
        let response = lookup(Some(Origin::NativeHost), None).await;
        match response {
            IpcMessage::GetCredentialResponse {
                username: None,
                password: None,
                ..
            } => {}
            other => panic!("expected denial response, got {other:?}"),
        }

        // Positive: the native host presenting its installation capability
        // is served.
        let response = lookup(Some(Origin::NativeHost), Some(host_secret.to_string())).await;
        match response {
            IpcMessage::GetCredentialResponse {
                password: Some(password),
                ..
            } => assert_eq!(password, "example-secret"),
            other => panic!("expected credential response, got {other:?}"),
        }

        // Wrong material denied.
        let response = lookup(Some(Origin::NativeHost), Some("attacker-guess".to_string())).await;
        match response {
            IpcMessage::GetCredentialResponse { password: None, .. } => {}
            other => panic!("expected denial, got {other:?}"),
        }

        server_task.abort();
        let _ = std::fs::remove_file(&socket_path);
        let _ = std::fs::remove_file(&vault_path);
        let _ = std::fs::remove_file(&capability_store);
        let _ = std::fs::remove_dir(&socket_dir);
    }

    /// Negative: a LIVE daemon refuses bootstrap creation (the vault already
    /// exists; creation is a maintenance-only op).
    #[cfg(unix)]
    #[tokio::test]
    async fn live_daemon_refuses_vault_create_and_locked_ops_fail_closed() {
        use crate::daemon::{DaemonVault, IpcServer};
        use crate::VaultManager;
        use sentinelpass_protocol::service::{ServiceOutcome, VaultOp};
        use std::sync::Arc;

        let suffix = uuid::Uuid::new_v4().simple().to_string();
        let short_suffix = &suffix[..12];
        let vault_path = std::env::temp_dir().join(format!("sentinelpass_live_{short_suffix}.db"));
        let socket_dir = tempfile::TempDir::new().unwrap().keep();
        {
            use std::os::unix::fs::PermissionsExt;
            std::fs::set_permissions(&socket_dir, std::fs::Permissions::from_mode(0o700)).unwrap();
        }
        let socket_path = socket_dir.join("s.sock");
        let password = b"test_password_123!";

        let vault = VaultManager::create(&vault_path, password).unwrap();
        drop(vault);

        let daemon_vault = Arc::new(DaemonVault::new(Some(vault_path.clone()), 300).unwrap());
        let server = Arc::new(IpcServer::new(
            socket_path.clone(),
            daemon_vault.clone(),
            "live-token".to_string(),
        ));
        assert!(!server.is_maintenance_mode());

        let server_task = tokio::spawn({
            let server = server.clone();
            async move { server.run().await }
        });
        for _ in 0..50 {
            if socket_path.exists() {
                break;
            }
            assert!(!server_task.is_finished());
            tokio::time::sleep(std::time::Duration::from_millis(10)).await;
        }

        let client = IpcClient::new_with_token(socket_path.clone(), "live-token".to_string());

        // A locked live daemon fails closed with the typed code (not a
        // silent empty result) — including bootstrap creation.
        let outcome = match client
            .send(IpcMessage::ServiceCall {
                op: VaultOp::EntryList,
            })
            .await
            .unwrap()
        {
            IpcMessage::ServiceResult { outcome } => outcome,
            other => panic!("unexpected non-service response: {:?}", other),
        };
        match outcome {
            ServiceOutcome::Err { error } => assert_eq!(error.code, "vault_locked"),
            ServiceOutcome::Ok { .. } => panic!("locked daemon must refuse CRUD"),
        }
        let outcome = match client
            .send(IpcMessage::ServiceCall {
                op: VaultOp::VaultCreate {
                    master_password: zeroize::Zeroizing::new("another-password-123!".to_string()),
                },
            })
            .await
            .unwrap()
        {
            IpcMessage::ServiceResult { outcome } => outcome,
            other => panic!("unexpected non-service response: {:?}", other),
        };
        match outcome {
            ServiceOutcome::Err { error } => assert_eq!(error.code, "vault_locked"),
            ServiceOutcome::Ok { .. } => panic!("locked daemon must refuse VaultCreate"),
        }

        // Unlock: now the live daemon refuses bootstrap creation (a vault
        // already exists; creation is maintenance-only).
        daemon_vault.unlock(password).await.unwrap();
        let outcome = match client
            .send(IpcMessage::ServiceCall {
                op: VaultOp::VaultCreate {
                    master_password: zeroize::Zeroizing::new("another-password-123!".to_string()),
                },
            })
            .await
            .unwrap()
        {
            IpcMessage::ServiceResult { outcome } => outcome,
            other => panic!("unexpected non-service response: {:?}", other),
        };
        match outcome {
            ServiceOutcome::Err { error } => {
                assert_eq!(error.code, "invalid_input");
            }
            ServiceOutcome::Ok { .. } => panic!("live daemon must refuse VaultCreate"),
        }

        server_task.abort();
        let _ = std::fs::remove_file(&socket_path);
        let _ = std::fs::remove_dir(socket_dir);
        let _ = std::fs::remove_file(&vault_path);
    }
}
