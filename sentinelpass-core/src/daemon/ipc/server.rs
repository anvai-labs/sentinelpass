//! IPC server — handles daemon-side message dispatch.

use super::stepup;
#[cfg(windows)]
use super::windows_named_pipe_path;
use super::{
    log_daemon_audit, log_external_secret_audit, CredentialSummary, IpcEnvelope, IpcMessage,
};
use crate::daemon::service::{codes, LiveVaultService, VaultApplicationService};
#[cfg(unix)]
use crate::daemon::transport::unix::UnixSocketTransport;
#[cfg(windows)]
use crate::daemon::transport::windows::WindowsNamedPipeTransport;
use crate::daemon::transport::{TransportConfig, TransportError};
use crate::daemon::DaemonVault;
use crate::external_secret_access::{ExternalSecretAllowlist, ExternalSecretField};
use crate::{AuditEventType, AuditLogger, VaultManager};
use crate::{DatabaseError, PasswordManagerError, Result};
use sentinelpass_protocol::service::{ServiceError, ServiceOutcome, VaultOp, VaultOpResult};
use sentinelpass_protocol::{Origin, ServiceVaultStatus};
use std::path::PathBuf;
use std::sync::atomic::{AtomicBool, AtomicU8, Ordering};
use std::sync::Arc;
use subtle::ConstantTimeEq;
#[allow(unused_imports)]
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tracing::{debug, error, info, warn};
use url::Url;
use zeroize::Zeroize;

/// Daemon serving the full surface against an existing vault.
const MODE_LIVE: u8 = 0;
/// Daemon started with no vault on disk: only bootstrap/status/shutdown are
/// served until `VaultCreate` transitions to live (WBS-501/503).
const MODE_MAINTENANCE: u8 = 1;
/// WBS-512: maximum concurrently-connected IPC clients.
const MAX_CONCURRENT_CLIENTS: usize = 16;

#[allow(dead_code)]
pub struct IpcServer {
    socket_path: PathBuf,
    vault: Arc<DaemonVault>,
    auth_token: String,
    external_secret_allowlist_path: PathBuf,
    /// Shared audit logger — one instance per process, created at startup.
    /// Appends are stateless since the WBS-415 chain (chain head re-derived
    /// from the file tail under the `audit.lock` advisory lock), so this
    /// instance and the `VaultManager`'s instance — and CLI processes — all
    /// append to ONE verifiable chain.
    audit_logger: Option<Arc<AuditLogger>>,
    /// Set by the `Shutdown` IPC message; the accept loops observe it and exit.
    shutdown: Arc<AtomicBool>,
    /// Live vs maintenance bootstrap mode (WBS-501/503).
    mode: Arc<AtomicU8>,
    /// WBS-512: bounds concurrent client connections (stalled/slow clients
    /// cannot exhaust daemon tasks).
    client_limiter: Arc<tokio::sync::Semaphore>,
    /// SP-0 / ADR-013: master-password step-up state (server-held only).
    stepup: stepup::StepUpState,
    /// SP-1 / ADR-014: exact-entry service grant store path (injectable
    /// for tests; default beside the config).
    service_grants_path: std::path::PathBuf,
    /// Serializes grant-store read-modify-write cycles.
    service_grants_lock: std::sync::Mutex<()>,
    /// Strict administrative-step-up profile (SP-0): when set, every
    /// `VaultOp::requires_admin_step_up()` op needs a fresh approval and
    /// browser/external-tool write surfaces are denied outright.
    /// Enabled by `SENTINELPASS_REQUIRE_STEPUP=1` at daemon start.
    require_stepup: bool,
    /// WBS-504/505: capability store (default location; injectable for
    /// tests).
    capability_store_path: PathBuf,
    /// WBS-712: per-site autofill permission store (default location;
    /// injectable for tests).
    site_permissions_path: PathBuf,
    /// WBS-712 (adversarial review F7): serializes grant/revoke/list
    /// read-modify-write cycles so a concurrent revoke cannot be
    /// resurrected by an in-flight grant (last-writer-wins).
    site_permissions_lock: std::sync::Mutex<()>,
}

impl IpcServer {
    /// Create a new IPC server
    pub fn new(socket_path: PathBuf, vault: Arc<DaemonVault>, auth_token: String) -> Self {
        Self::new_with_allowlist_path(
            socket_path,
            vault,
            auth_token,
            ExternalSecretAllowlist::default_path(),
        )
    }

    /// Create a new IPC server with an explicit external secret allowlist path.
    pub fn new_with_allowlist_path(
        socket_path: PathBuf,
        vault: Arc<DaemonVault>,
        auth_token: String,
        external_secret_allowlist_path: PathBuf,
    ) -> Self {
        let audit_logger = match crate::platform::ensure_audit_log_dir() {
            Ok(dir) => match AuditLogger::new(dir) {
                Ok(lg) => Some(Arc::new(lg)),
                Err(e) => {
                    warn!(error_kind = ?std::any::type_name_of_val(&e), "IpcServer: audit logger unavailable — audit events will be dropped");
                    None
                }
            },
            Err(e) => {
                warn!(error_kind = ?std::any::type_name_of_val(&e), "IpcServer: audit log directory unavailable — audit events will be dropped");
                None
            }
        };
        Self {
            socket_path,
            vault,
            auth_token,
            external_secret_allowlist_path,
            audit_logger,
            shutdown: Arc::new(AtomicBool::new(false)),
            mode: Arc::new(AtomicU8::new(MODE_LIVE)),
            client_limiter: Arc::new(tokio::sync::Semaphore::new(MAX_CONCURRENT_CLIENTS)),
            stepup: stepup::StepUpState::new(),
            service_grants_path: crate::service_grants::ServiceGrantStore::default_path(),
            service_grants_lock: std::sync::Mutex::new(()),
            require_stepup: std::env::var_os("SENTINELPASS_REQUIRE_STEPUP")
                .map(|v| v == "1")
                .unwrap_or(false),
            capability_store_path: crate::daemon::capabilities::default_store_path(),
            site_permissions_path: crate::daemon::site_permissions::default_store_path(),
            site_permissions_lock: std::sync::Mutex::new(()),
        }
    }

    /// SP-0 / ADR-013: enable the strict administrative step-up profile
    /// (tests / the SENTINELPASS_REQUIRE_STEPUP deployment posture).
    pub fn with_require_stepup(mut self, require: bool) -> Self {
        self.require_stepup = require;
        self
    }

    /// SP-1 / ADR-014: inject the service grant store path (tests).
    pub fn with_service_grants_path(mut self, path: std::path::PathBuf) -> Self {
        self.service_grants_path = path;
        self
    }

    /// SP-1 / ADR-014: retrieval-only exact-entry service secret access.
    /// Typed outcomes; `not_found` is only reachable AFTER grant
    /// validation (un-granted probing gets `denied`).
    async fn service_get_secret(
        &self,
        client_id: &str,
        entry_id: i64,
        field: &str,
        token: &str,
    ) -> IpcMessage {
        let field = match field {
            "username" => crate::service_grants::ServiceField::Username,
            "password" => crate::service_grants::ServiceField::Password,
            "title" => crate::service_grants::ServiceField::Title,
            other => {
                return self.service_secret_report(
                    "denied",
                    None,
                    Some(format!(
                        "unknown field {other:?} (username, password, title)"
                    )),
                )
            }
        };
        let store = match crate::service_grants::ServiceGrantStore::load_from_path(
            &self.service_grants_path,
        ) {
            Ok(store) => store,
            Err(e) => {
                return self.service_secret_report(
                    "denied",
                    None,
                    Some(format!("grant store unavailable (fail closed): {e}")),
                )
            }
        };
        let authorized = store
            .authorize(client_id, token, entry_id, field, chrono::Utc::now())
            .is_some();
        // Review F3: service deliveries get the same audit discipline as
        // the legacy broker (client/entry/field only — never the value).
        log_daemon_audit(
            self.audit_logger.as_deref(),
            if authorized {
                crate::AuditEventType::CredentialViewed { entry_id }
            } else {
                // Denials ride the same event with the outcome in the
                // context line (no value material, ever).
                crate::AuditEventType::ExternalSecretAccess {
                    client_id: Some(client_id.to_string()),
                    domain: format!("entry:{entry_id}"),
                    field: Some(field.as_str().to_string()),
                    purpose: Some("service_get:denied".to_string()),
                    success: false,
                }
            },
            &format!(
                "SP-1 service_get {client_id} entry:{entry_id} field:{} authorized={authorized}",
                field.as_str()
            ),
        );
        if !authorized {
            return self.service_secret_report("denied", None, None);
        }
        let Some(manager) = self.vault.manager().await else {
            return self.service_secret_report("locked", None, None);
        };
        // get_entry returns Err(NotFound) for absent ids — normalize to
        // the typed not_found status.
        let fetch = tokio::task::spawn_blocking(move || manager.get_entry(entry_id)).await;
        let fetch = fetch.map(|r| {
            r.map(Some).or_else(|e| {
                if matches!(e, crate::PasswordManagerError::NotFound(_)) {
                    Ok(None)
                } else {
                    Err(e)
                }
            })
        });
        match fetch {
            Ok(Ok(Some(entry))) => {
                let value = match field {
                    crate::service_grants::ServiceField::Username => entry.username,
                    // The Entry password is Zeroizing<String>; the report
                    // rides the sealed session (same as every credential
                    // response on this socket).
                    crate::service_grants::ServiceField::Password => entry.password.to_string(),
                    crate::service_grants::ServiceField::Title => entry.title,
                };
                self.service_secret_report("authorized", Some(value), None)
            }
            Ok(Ok(None)) => self.service_secret_report("not_found", None, None),
            Ok(Err(e)) => self.service_secret_report(
                "denied",
                None,
                Some(format!("entry lookup failed: {e}")),
            ),
            Err(e) => {
                self.service_secret_report("denied", None, Some(format!("lookup task failed: {e}")))
            }
        }
    }

    fn service_secret_report(
        &self,
        status: &str,
        value: Option<String>,
        error: Option<String>,
    ) -> IpcMessage {
        IpcMessage::ServiceResult {
            outcome: ServiceOutcome::Ok {
                result: VaultOpResult::Report(serde_json::json!({
                    "status": status,
                    "value": value,
                    "error": error,
                })),
            },
        }
    }

    /// SP-1 / ADR-014: mint a grant (admin; step-up gated upstream).
    async fn service_grant_create(
        &self,
        client_id: &str,
        entry_id: i64,
        fields: Vec<String>,
        expires_at: Option<i64>,
    ) -> IpcMessage {
        let parsed: std::result::Result<Vec<crate::service_grants::ServiceField>, _> = fields
            .iter()
            .map(|f| match f.as_str() {
                "username" => Ok(crate::service_grants::ServiceField::Username),
                "password" => Ok(crate::service_grants::ServiceField::Password),
                "title" => Ok(crate::service_grants::ServiceField::Title),
                other => Err(PasswordManagerError::InvalidInput(format!(
                    "unknown field {other:?}"
                ))),
            })
            .collect();
        let fields = match parsed {
            Ok(fields) if !fields.is_empty() => fields,
            Ok(_) => {
                return self.service_secret_report(
                    "denied",
                    None,
                    Some("a grant must name at least one field".into()),
                )
            }
            Err(e) => return self.service_secret_report("denied", None, Some(e.to_string())),
        };
        // Review F5: a garbage expires_at is an input error, never a
        // silently clamped expiry.
        let expiry = expires_at.and_then(|secs| chrono::DateTime::from_timestamp(secs, 0));
        if expires_at.is_some() && expiry.is_none() {
            return self.service_secret_report(
                "denied",
                None,
                Some("expires_at out of range".into()),
            );
        }
        let _guard = self.service_grants_lock.lock().unwrap();
        let mut store = match crate::service_grants::ServiceGrantStore::load_from_path(
            &self.service_grants_path,
        ) {
            Ok(store) => store,
            Err(e) => {
                return self.service_secret_report(
                    "denied",
                    None,
                    Some(format!("grant store unavailable (fail closed): {e}")),
                )
            }
        };
        let (grant, token) = match store.mint_grant(client_id, entry_id, fields, expiry) {
            Ok(minted) => minted,
            Err(e) => return self.service_secret_report("denied", None, Some(e.to_string())),
        };
        if let Err(e) = store.save_to_path(&self.service_grants_path) {
            // Review F6: NOT published — distinct from an authz denial.
            return self.service_secret_report("store_error", None, Some(e.to_string()));
        }
        // Review F3: audit the policy mutation (no secret material).
        log_daemon_audit(
            self.audit_logger.as_deref(),
            crate::AuditEventType::CredentialModified { entry_id },
            &format!("SP-1 service_grant_created {client_id} entry:{entry_id}"),
        );
        // Token shown once, inside the sealed session (legacy-broker
        // discipline). The report is the ONLY place it appears.
        IpcMessage::ServiceResult {
            outcome: ServiceOutcome::Ok {
                result: VaultOpResult::Report(serde_json::json!({
                    "status": "created",
                    "grant_id": grant.grant_id.to_string(),
                    "client_token": *token,
                    "expires_at": grant.expires_at.map(|e| e.timestamp()),
                })),
            },
        }
    }

    /// SP-1 / ADR-014: revoke a grant (admin; step-up gated upstream).
    async fn service_grant_revoke(&self, grant_id_str: &str) -> IpcMessage {
        let Ok(grant_id) = uuid::Uuid::parse_str(grant_id_str) else {
            return self.service_secret_report("denied", None, Some("malformed grant id".into()));
        };
        let _guard = self.service_grants_lock.lock().unwrap();
        let mut store = match crate::service_grants::ServiceGrantStore::load_from_path(
            &self.service_grants_path,
        ) {
            Ok(store) => store,
            Err(e) => {
                return self.service_secret_report(
                    "denied",
                    None,
                    Some(format!("grant store unavailable (fail closed): {e}")),
                )
            }
        };
        if !store.revoke(grant_id) {
            return self.service_secret_report("not_found", None, None);
        }
        match store.save_to_path(&self.service_grants_path) {
            Ok(()) => {
                log_daemon_audit(
                    self.audit_logger.as_deref(),
                    crate::AuditEventType::CredentialModified { entry_id: 0 },
                    &format!("SP-1 service_grant_revoked {grant_id}"),
                );
                self.service_secret_report("revoked", None, None)
            }
            // Review F6: revocation NOT published — the grant is still
            // live on disk; say so distinctly.
            Err(e) => self.service_secret_report("store_error", None, Some(e.to_string())),
        }
    }

    pub fn with_capability_store_path(mut self, path: PathBuf) -> Self {
        self.capability_store_path = path;
        self
    }

    /// Override the per-site permission store path (tests / embedders).
    pub fn with_site_permissions_path(mut self, path: PathBuf) -> Self {
        self.site_permissions_path = path;
        self
    }

    /// Handle to observe (or trigger) server shutdown from outside the accept loop.
    pub fn shutdown_flag(&self) -> Arc<AtomicBool> {
        Arc::clone(&self.shutdown)
    }

    /// Put the server into maintenance/bootstrap mode: only `CheckVault`,
    /// `Shutdown`, `ServiceCall(VaultStatus)` and `ServiceCall(VaultCreate)`
    /// are served until creation succeeds and the mode flips back to live
    /// (WBS-501/503).
    pub fn enter_maintenance_mode(&self) {
        self.mode.store(MODE_MAINTENANCE, Ordering::Release);
    }

    /// Whether the server is currently in maintenance/bootstrap mode.
    pub fn is_maintenance_mode(&self) -> bool {
        self.mode.load(Ordering::Acquire) == MODE_MAINTENANCE
    }

    fn set_live_mode(&self) {
        self.mode.store(MODE_LIVE, Ordering::Release);
    }

    /// Start the IPC server (WBS-512: BOUNDED concurrent connections).
    pub async fn run(self: Arc<Self>) -> Result<()> {
        info!("Starting IPC server at {:?}", self.socket_path);

        // Remove existing socket if present
        if self.socket_path.exists() {
            std::fs::remove_file(&self.socket_path).map_err(|e| {
                PasswordManagerError::from(DatabaseError::Ipc(format!(
                    "Failed to remove socket: {}",
                    e
                )))
            })?;
        }

        #[cfg(unix)]
        {
            // Use Unix domain socket transport
            let mut transport = UnixSocketTransport::new(TransportConfig {
                unix_socket_path: Some(self.socket_path.to_string_lossy().to_string()),
                ..Default::default()
            })
            .map_err(|e| {
                PasswordManagerError::from(DatabaseError::Ipc(format!(
                    "Failed to create transport: {}",
                    e
                )))
            })?;

            transport.bind().map_err(|e| {
                PasswordManagerError::from(DatabaseError::Ipc(format!(
                    "Failed to bind transport: {}",
                    e
                )))
            })?;

            info!("IPC server listening on {:?}", self.socket_path);

            loop {
                match transport.accept().await {
                    Ok(conn) => {
                        debug!("IPC client connected");
                        // WBS-512: each connection runs on its own task,
                        // bounded by the client semaphore — a stalled or
                        // slow client can no longer wedge the daemon.
                        match self.client_limiter.clone().acquire_owned().await {
                            Ok(permit) => {
                                let server = Arc::clone(&self);
                                tokio::spawn(async move {
                                    let _permit = permit;
                                    if let Err(e) = server.run_connection(conn.into()).await {
                                        debug!(error_kind = ?std::any::type_name_of_val(&e), "IPC connection ended");
                                    }
                                });
                            }
                            Err(e) => error!("client limiter closed: {}", e),
                        }
                    }
                    Err(e) => {
                        error!("Failed to accept connection: {}", e);
                    }
                }

                if self.shutdown.load(Ordering::Acquire) {
                    info!("IPC: shutdown requested — stopping accept loop");
                    break;
                }
            }
        }

        let _ = std::fs::remove_file(&self.socket_path);

        #[cfg(windows)]
        {
            // Named pipes only: the legacy tcp:// loopback branch was
            // removed in Phase 3 (ADR-007 migration).
            // Honor an explicit \\.\pipe\ path (tests, custom deploys);
            // default to the per-user pipe name otherwise.
            let configured_pipe_path = {
                let as_str = self.socket_path.to_string_lossy().to_string();
                if as_str.starts_with(r"\\.\pipe\") {
                    Some(as_str)
                } else {
                    Some(windows_named_pipe_path())
                }
            };
            let transport = WindowsNamedPipeTransport::new(TransportConfig {
                windows_pipe_path: configured_pipe_path,
                ..Default::default()
            })
            .map_err(|e| {
                PasswordManagerError::from(DatabaseError::Ipc(format!(
                    "Failed to create transport: {}",
                    e
                )))
            })?;

            let pipe_name = transport.pipe_name().to_string();
            info!("IPC server listening on named pipe: {}", pipe_name);

            loop {
                // Create the named pipe server instance (WBS-508: explicit
                // current-user DACL, first-instance protection, remote
                // rejection).
                let pipe_server = transport.create_server().map_err(|e| {
                    PasswordManagerError::from(DatabaseError::Ipc(format!(
                        "Failed to create named pipe: {}",
                        e
                    )))
                })?;

                debug!("Named pipe created, waiting for connection");

                match pipe_server.connect().await {
                    // tokio's NamedPipeServer::connect resolves when a
                    // client has attached — the value is (), the connected
                    // pipe IS the server handle. Wrap it via the protocol
                    // connection's server-side constructor.
                    Ok(()) => {
                        debug!("IPC client connected (named pipe)");
                        let pipe_conn =
                            sentinelpass_protocol::WindowsNamedPipeConnection::from_server(
                                pipe_server,
                            );
                        match self.client_limiter.clone().acquire_owned().await {
                            Ok(permit) => {
                                let server = Arc::clone(&self);
                                tokio::spawn(async move {
                                    let _permit = permit;
                                    if let Err(e) = server.run_connection(pipe_conn.into()).await {
                                        debug!(error_kind = ?std::any::type_name_of_val(&e), "IPC connection ended");
                                    }
                                });
                            }
                            Err(e) => error!("client limiter closed: {}", e),
                        }
                    }
                    Err(e) => {
                        error!("Failed to accept named pipe connection: {}", e);
                    }
                }

                if self.shutdown.load(Ordering::Acquire) {
                    info!("IPC: shutdown requested — stopping accept loop");
                    break;
                }
            }
        }

        Ok(())
    }

    /// One negotiated client connection: session handshake (WBS-509/510),
    /// then request/response cycles until EOF — every frame read bounded by
    /// the session deadline and replay-checked (WBS-511).
    async fn run_connection(
        &self,
        conn: sentinelpass_protocol::connection::TransportConnection,
    ) -> Result<()> {
        // SP-0: random per-connection identity for step-up binding.
        let connection_id: u128 = rand::random();
        let (mut ipc, first_frame) =
            sentinelpass_protocol::connection::IpcConnection::accept_server(conn, &self.auth_token)
                .await
                .map_err(|e| {
                    PasswordManagerError::from(DatabaseError::Ipc(format!(
                        "session negotiation failed: {}",
                        e
                    )))
                })?;

        // A legacy PLAIN client's first frame is already delivered.
        if let Some(first) = first_frame {
            if let Some(response_bytes) = self.process_frame(&first, connection_id).await {
                ipc.send_frame(&response_bytes).await.map_err(|e| {
                    PasswordManagerError::from(DatabaseError::Ipc(format!(
                        "Failed to send response: {}",
                        e
                    )))
                })?;
            }
        }

        loop {
            if self.shutdown.load(Ordering::Acquire) {
                break;
            }
            let frame = match ipc.recv_frame().await {
                Ok(frame) => frame,
                Err(TransportError::Timeout) => {
                    debug!("IPC connection idle past deadline — closing");
                    break;
                }
                Err(e) => {
                    debug!(error_kind = ?std::any::type_name_of_val(&e), "IPC connection read ended");
                    break;
                }
            };
            if let Some(response_bytes) = self.process_frame(&frame, connection_id).await {
                ipc.send_frame(&response_bytes).await.map_err(|e| {
                    PasswordManagerError::from(DatabaseError::Ipc(format!(
                        "Failed to send response: {}",
                        e
                    )))
                })?;
            }
        }
        Ok(())
    }

    /// Token check + dispatch for one plaintext envelope frame. Returns the
    /// serialized response, or None when no response should be sent.
    async fn process_frame(&self, frame: &[u8], connection_id: u128) -> Option<Vec<u8>> {
        match serde_json::from_slice::<IpcEnvelope>(frame) {
            Ok(envelope) => {
                if !bool::from(envelope.token.as_bytes().ct_eq(self.auth_token.as_bytes())) {
                    warn!("Rejected IPC request with invalid token");
                    return None;
                }
                let response = self.handle_message(envelope, connection_id).await;
                match serde_json::to_vec(&response) {
                    Ok(response_bytes) => Some(response_bytes),
                    Err(e) => {
                        error!(error_kind = ?std::any::type_name_of_val(&e), "Failed to serialize response");
                        None
                    }
                }
            }
            Err(e) => {
                error!(error_kind = ?std::any::type_name_of_val(&e), "Failed to parse IPC envelope");
                None
            }
        }
    }

    /// Gate for the browser-autofill surface (GetCredential, GetTotpCode,
    /// ListDomainCredentials, SaveCredential). External tools must use
    /// GetExternalSecret / SaveSecret instead.
    ///
    /// - `NativeHost` origin: allowed.
    /// - `Cli` origin: denied — a CLI-tagged client has no business on the
    ///   autofill surface.
    /// - No origin: denied by default (legacy <= 0.7 hosts). Operators still
    ///   running a pre-0.8 native host can temporarily restore legacy
    ///   behavior with SENTINELPASS_ALLOW_LEGACY_ORIGINLESS=1; the escape
    ///   hatch exists only so upgrades are not forced and is removed in 1.0.
    fn browser_surface_allowed(&self, origin: Option<Origin>, capability: Option<&str>) -> bool {
        let capabilities = crate::daemon::capabilities::InstallationCapabilities::load_from_path(
            &self.capability_store_path,
        );
        let store = capabilities.unwrap_or_default();
        Self::browser_surface_allowed_with_store(origin, capability, &store)
    }

    /// Pure decision core (testable without the default store path).
    fn browser_surface_allowed_with_store(
        origin: Option<Origin>,
        capability: Option<&str>,
        capabilities: &crate::daemon::capabilities::InstallationCapabilities,
    ) -> bool {
        // WBS-504/505: the installation capability is the authority. The
        // origin label stays provenance-only and can never authorize.
        if capabilities.verify(
            crate::daemon::capabilities::NATIVE_HOST_AUDIENCE,
            capability,
        ) {
            return true;
        }

        // Legacy migration windows (both announced; both removed in 1.0):
        let legacy_originless = std::env::var("SENTINELPASS_ALLOW_LEGACY_ORIGINLESS")
            .map(|v| v == "1")
            .unwrap_or(false);
        let legacy_self_asserted = std::env::var("SENTINELPASS_ALLOW_SELF_ASSERTED_ORIGIN")
            .map(|v| v == "1")
            .unwrap_or(false);
        match origin {
            Some(Origin::NativeHost) if legacy_self_asserted => {
                warn!(
                    "allowed SELF-ASSERTED NativeHost origin via \
                     SENTINELPASS_ALLOW_SELF_ASSERTED_ORIGIN=1 (pre-capability host; \
                     upgrade sentinelpass-host — removed in 1.0)"
                );
                true
            }
            None if legacy_originless => {
                warn!(
                    "allowed ORIGINLESS browser-surface request via \
                     SENTINELPASS_ALLOW_LEGACY_ORIGINLESS=1 (pre-0.8 host; upgrade \
                     sentinelpass-host — removed in 1.0)"
                );
                true
            }
            _ => {
                warn!(
                    "denied browser-surface request without a valid native-host \
                     capability (audience/native-host presentation required; upgrade \
                     sentinelpass-host)"
                );
                false
            }
        }
    }

    /// WBS-711 autofill origin gate: validate the requesting page URL and
    /// return the scheme-validated host that credential delivery is BOUND
    /// to, or a denial reason.
    ///
    /// Default-deny contract (SR-CLIENT-003 / SR-EXT-002):
    /// - `https:` origins deliver, bound to the parsed host.
    /// - plain `http:` origins are REFUSED (`insecure-http`) unless the
    ///   WBS-712 per-site permission store holds an explicit
    ///   `allow_insecure` grant for the EXACT host (user action in the
    ///   popup). WBS-706's consent covered SAVE; this covers AUTOFILL
    ///   delivery.
    /// - a missing URL (pre-711 host), an unparseable value, a non-web
    ///   scheme (`file:`, `chrome-extension:`, …), or an empty host are
    ///   all REFUSED (`origin-unverified`) — fail-closed; a valid
    ///   capability does NOT bypass the scheme gate, and a missing or
    ///   unreadable permission store denies too.
    ///
    /// The returned host comes from the WHATWG parse of the URL the
    /// BROWSER reported (sender URL), never from a content-script-claimed
    /// domain string, so the vault lookup cannot be pointed at a host the
    /// page is not on.
    fn autofill_origin_decision(
        &self,
        page_url: Option<&str>,
    ) -> std::result::Result<String, &'static str> {
        // WBS-712: grants load from the store per request (mirroring the
        // capability store). A missing/unreadable store is an EMPTY store —
        // the gate stays fail-closed without it.
        let permissions = crate::daemon::site_permissions::SitePermissionStore::load_from_path(
            &self.site_permissions_path,
        )
        .unwrap_or_default();
        Self::autofill_origin_decision_with_store(page_url, &permissions)
    }

    /// Pure decision core (testable without a store path).
    fn autofill_origin_decision_with_store(
        page_url: Option<&str>,
        permissions: &crate::daemon::site_permissions::SitePermissionStore,
    ) -> std::result::Result<String, &'static str> {
        let Some(raw) = page_url.map(str::trim).filter(|v| !v.is_empty()) else {
            return Err("origin-unverified");
        };
        let parsed = Url::parse(raw).map_err(|_| "origin-unverified")?;
        let insecure = match parsed.scheme() {
            "https" => false,
            "http" => true,
            _ => return Err("origin-unverified"),
        };
        let host = parsed.host_str().map(str::trim).unwrap_or("");
        if host.is_empty() {
            return Err("origin-unverified");
        }
        let normalized =
            crate::domain::normalize_host(host).unwrap_or_else(|| host.to_ascii_lowercase());
        if insecure && !permissions.allows_insecure(&normalized) {
            return Err("insecure-http");
        }
        Ok(normalized)
    }

    /// Handle an IPC envelope (auth token was already verified by the caller).
    #[allow(dead_code)]
    /// `connection_id` (SP-0): random per-connection identity minted in
    /// `run_connection`; step-up approvals are bound to it.
    async fn handle_message(&self, envelope: IpcEnvelope, connection_id: u128) -> IpcMessage {
        // Maintenance/bootstrap gate (WBS-501/503): a daemon started with no
        // vault serves only status, bootstrap creation, and shutdown.
        if self.is_maintenance_mode() {
            return self
                .handle_maintenance_message(envelope, connection_id)
                .await;
        }

        let client_token = envelope.client_token.clone();
        // Origin is provenance labeling for the browser-surface gate below —
        // NOT authentication. The security boundary for external tools is the
        // grant + client token system.
        let origin = envelope.origin;
        match envelope.message {
            IpcMessage::GetExternalSecret {
                client_id,
                domain,
                field,
                purpose,
            } => {
                if !self.vault.is_unlocked().await {
                    return IpcMessage::GetExternalSecretResponse {
                        value: None,
                        authorized: true,
                        error: None,
                        locked: Some(true),
                    };
                }
                debug!("IPC: GetExternalSecret");

                let purpose = purpose.unwrap_or_else(|| "external-secret-access".to_string());
                let allowlist =
                    ExternalSecretAllowlist::load_from_path(&self.external_secret_allowlist_path);
                let token_ok = match &allowlist {
                    Ok(allowlist) => {
                        allowlist.verify_client_token(&client_id, client_token.as_deref())
                    }
                    Err(_) => false,
                };
                match allowlist {
                    Ok(allowlist)
                        if token_ok && allowlist.is_allowed(&client_id, &domain, field) =>
                    {
                        match self.vault.get_credential(&domain).await {
                            Ok(Some(cred)) => {
                                let value = match field {
                                    ExternalSecretField::Username => Some(cred.username),
                                    ExternalSecretField::Password => Some(cred.password),
                                    ExternalSecretField::Title => Some(cred.title),
                                };
                                log_external_secret_audit(
                                    self.audit_logger.as_deref(),
                                    Some(&client_id),
                                    &domain,
                                    Some(field.as_str()),
                                    Some(&purpose),
                                    value.is_some(),
                                    // Static context (WBS-414): client id
                                    // and purpose are user/external-tool
                                    // free text — they ride in the event
                                    // payload fields, not the plaintext
                                    // context line.
                                    "External secret access granted",
                                );
                                IpcMessage::GetExternalSecretResponse {
                                    value,
                                    authorized: true,
                                    error: None,
                                    locked: None,
                                }
                            }
                            Ok(None) => {
                                log_external_secret_audit(
                                    self.audit_logger.as_deref(),
                                    Some(&client_id),
                                    &domain,
                                    Some(field.as_str()),
                                    Some(&purpose),
                                    false,
                                    // Static context (WBS-414, see above).
                                    "External secret access found no credential",
                                );
                                IpcMessage::GetExternalSecretResponse {
                                    value: None,
                                    authorized: true,
                                    error: None,
                                    locked: None,
                                }
                            }
                            Err(e) => {
                                error!(error_kind = ?std::any::type_name_of_val(&e), "Failed to get external secret");
                                log_external_secret_audit(
                                    self.audit_logger.as_deref(),
                                    Some(&client_id),
                                    &domain,
                                    Some(field.as_str()),
                                    Some(&purpose),
                                    false,
                                    // Static context (WBS-414, see above).
                                    "External secret access failed",
                                );
                                IpcMessage::GetExternalSecretResponse {
                                    value: None,
                                    authorized: true,
                                    error: Some("Credential lookup failed".to_string()),
                                    locked: None,
                                }
                            }
                        }
                    }
                    Ok(_) => {
                        log_external_secret_audit(
                            self.audit_logger.as_deref(),
                            Some(&client_id),
                            &domain,
                            Some(field.as_str()),
                            Some(&purpose),
                            false,
                            // Static context (WBS-414, see above).
                            "External secret access denied",
                        );
                        IpcMessage::GetExternalSecretResponse {
                            value: None,
                            authorized: false,
                            error: Some(format!(
                                "Client '{}' is not authorized for {} {}: run \
                                 'sentinelpass secret allow {} --domain {} --field {}' \
                                 and set SENTINELPASS_CLIENT_TOKEN",
                                client_id,
                                domain,
                                field.as_str(),
                                client_id,
                                domain,
                                field.as_str()
                            )),
                            locked: None,
                        }
                    }
                    Err(e) => {
                        error!(error_kind = ?std::any::type_name_of_val(&e), "Failed to load external secret allowlist");
                        IpcMessage::GetExternalSecretResponse {
                            value: None,
                            authorized: false,
                            error: Some("Failed to load external secret allowlist".to_string()),
                            locked: None,
                        }
                    }
                }
            }
            IpcMessage::SaveSecret {
                client_id,
                domain,
                value,
                purpose,
            } => {
                // SP-0 / ADR-013: under the strict administrative profile,
                // unattended external-tool writes are disabled — entry
                // mutation needs an owner step-up, which this surface
                // cannot present. Fail closed with the typed code.
                if self.require_stepup {
                    return IpcMessage::SaveSecretResponse {
                        success: false,
                        locked: None,
                        error: Some(
                            "step_up_required: external-tool writes are disabled under the strict profile"
                                .to_string(),
                        ),
                    };
                }
                let purpose_label = purpose.unwrap_or_else(|| "external-secret-write".to_string());
                if !self.vault.is_unlocked().await {
                    return IpcMessage::SaveSecretResponse {
                        success: false,
                        locked: Some(true),
                        error: Some("vault is locked".to_string()),
                    };
                }

                let allowlist =
                    ExternalSecretAllowlist::load_from_path(&self.external_secret_allowlist_path);
                let authorized = match &allowlist {
                    Ok(allowlist) => {
                        allowlist.verify_client_token(&client_id, client_token.as_deref())
                            && allowlist
                                .grants_for_client(Some(&client_id))
                                .unwrap_or_default()
                                .into_iter()
                                .any(|grant| {
                                    grant.allow_write
                                        && !grant.is_expired_at(chrono::Utc::now())
                                        && grant.domain == domain
                                })
                    }
                    Err(_) => false,
                };

                if !authorized {
                    log_daemon_audit(
                        self.audit_logger.as_deref(),
                        AuditEventType::ExternalSecretWrite {
                            client_id: Some(client_id.clone()),
                            domain: domain.clone(),
                            purpose: Some(purpose_label),
                            success: false,
                        },
                        "External secret write denied",
                    );
                    return IpcMessage::SaveSecretResponse {
                        success: false,
                        locked: None,
                        error: Some(format!(
                            "Client '{}' has no write grant for '{}': run \
                             'sentinelpass secret allow {} --domain {} --field password --write' \
                             and set SENTINELPASS_CLIENT_TOKEN",
                            client_id, domain, client_id, domain
                        )),
                    };
                }

                match self.vault.save_secret_value(&domain, &value).await {
                    Ok(()) => {
                        log_daemon_audit(
                            self.audit_logger.as_deref(),
                            AuditEventType::ExternalSecretWrite {
                                client_id: Some(client_id.clone()),
                                domain: domain.clone(),
                                purpose: Some(purpose_label),
                                success: true,
                            },
                            "External secret written via daemon IPC",
                        );
                        IpcMessage::SaveSecretResponse {
                            success: true,
                            locked: None,
                            error: None,
                        }
                    }
                    Err(e) => {
                        error!(error_kind = ?std::any::type_name_of_val(&e), "Failed to save external secret");
                        IpcMessage::SaveSecretResponse {
                            success: false,
                            locked: None,
                            error: Some("Failed to save secret".to_string()),
                        }
                    }
                }
            }
            IpcMessage::DeleteSecret {
                client_id: _,
                domain,
            } => {
                // Deletion is rejected until entries carry ownership metadata
                // (schema v5): a write-grant must never be able to delete a
                // human-created login.
                debug!("IPC: DeleteSecret");
                let _ = domain;
                IpcMessage::DeleteSecretResponse {
                    deleted: false,
                    locked: None,
                    error: Some(
                        "deletion is not supported for external tools; revoke the grant instead"
                            .to_string(),
                    ),
                }
            }
            IpcMessage::GetCredential {
                domain,
                page_url,
                username,
            } => {
                debug!("IPC: GetCredential");

                if !self.browser_surface_allowed(origin, envelope.capability.as_deref()) {
                    return IpcMessage::GetCredentialResponse {
                        username: None,
                        password: None,
                        title: None,
                        locked: None,
                        denied_reason: None,
                    };
                }

                if !self.vault.is_unlocked().await {
                    return IpcMessage::GetCredentialResponse {
                        username: None,
                        password: None,
                        title: None,
                        locked: Some(true),
                        denied_reason: None,
                    };
                }

                // WBS-711: default-deny unsafe/unverifiable origins and
                // bind delivery to the scheme-validated host (never the
                // claimed domain string).
                let validated_host = match self.autofill_origin_decision(page_url.as_deref()) {
                    Ok(host) => host,
                    Err(reason) => {
                        warn!("denied autofill credential delivery");
                        log_external_secret_audit(
                            self.audit_logger.as_deref(),
                            None,
                            &domain,
                            None,
                            None,
                            false,
                            "Autofill credential delivery denied by the origin gate",
                        );
                        return IpcMessage::GetCredentialResponse {
                            username: None,
                            password: None,
                            title: None,
                            locked: None,
                            denied_reason: Some(reason.to_string()),
                        };
                    }
                };

                match self
                    .vault
                    .get_credential_for_username(&validated_host, username.as_deref())
                    .await
                {
                    Ok(Some(cred)) => {
                        log_external_secret_audit(
                            self.audit_logger.as_deref(),
                            None,
                            &domain,
                            None,
                            None,
                            true,
                            "Credential secret retrieved through daemon IPC",
                        );
                        IpcMessage::GetCredentialResponse {
                            username: Some(cred.username),
                            password: Some(cred.password),
                            title: Some(cred.title),
                            locked: None,
                            denied_reason: None,
                        }
                    }
                    Ok(None) => {
                        debug!("No credential found");
                        log_external_secret_audit(
                            self.audit_logger.as_deref(),
                            None,
                            &domain,
                            None,
                            None,
                            false,
                            "Credential secret lookup through daemon IPC returned no match",
                        );
                        IpcMessage::GetCredentialResponse {
                            username: None,
                            password: None,
                            title: None,
                            locked: None,
                            denied_reason: None,
                        }
                    }
                    Err(e) => {
                        error!(error_kind = ?std::any::type_name_of_val(&e), "Failed to get credential");
                        log_external_secret_audit(
                            self.audit_logger.as_deref(),
                            None,
                            &domain,
                            None,
                            None,
                            false,
                            "Credential secret lookup through daemon IPC failed",
                        );
                        IpcMessage::GetCredentialResponse {
                            username: None,
                            password: None,
                            title: None,
                            locked: None,
                            denied_reason: None,
                        }
                    }
                }
            }
            IpcMessage::ListDomainCredentials {
                base_domain,
                page_url,
            } => {
                debug!("IPC: ListDomainCredentials");

                if !self.browser_surface_allowed(origin, envelope.capability.as_deref()) {
                    return IpcMessage::ListDomainCredentialsResponse {
                        credentials: Vec::new(),
                        locked: None,
                        denied_reason: None,
                    };
                }

                if !self.vault.is_unlocked().await {
                    return IpcMessage::ListDomainCredentialsResponse {
                        credentials: Vec::new(),
                        locked: Some(true),
                        denied_reason: None,
                    };
                }

                // WBS-711: same origin gate as credential delivery — a
                // listing also discloses which usernames exist for a site.
                let validated_host = match self.autofill_origin_decision(page_url.as_deref()) {
                    Ok(host) => host,
                    Err(reason) => {
                        warn!("denied domain-credential listing");
                        log_external_secret_audit(
                            self.audit_logger.as_deref(),
                            None,
                            &base_domain,
                            None,
                            None,
                            false,
                            "Autofill domain listing denied by the origin gate",
                        );
                        return IpcMessage::ListDomainCredentialsResponse {
                            credentials: Vec::new(),
                            locked: None,
                            denied_reason: Some(reason.to_string()),
                        };
                    }
                };

                match self.vault.list_domain_credentials(&validated_host).await {
                    Ok(credentials) => {
                        let summaries: Vec<CredentialSummary> = credentials
                            .into_iter()
                            .map(|cred| CredentialSummary {
                                username: cred.username,
                                title: Some(cred.title),
                                domain: cred.domain,
                            })
                            .collect();
                        IpcMessage::ListDomainCredentialsResponse {
                            credentials: summaries,
                            locked: None,
                            denied_reason: None,
                        }
                    }
                    Err(e) => {
                        error!(error_kind = ?std::any::type_name_of_val(&e), "Failed to list domain credentials");
                        IpcMessage::ListDomainCredentialsResponse {
                            credentials: Vec::new(),
                            locked: None,
                            denied_reason: None,
                        }
                    }
                }
            }
            IpcMessage::GetTotpCode {
                domain,
                page_url,
                username,
            } => {
                debug!("IPC: GetTotpCode");

                if !self.browser_surface_allowed(origin, envelope.capability.as_deref()) {
                    return IpcMessage::GetTotpCodeResponse {
                        code: None,
                        seconds_remaining: None,
                        locked: None,
                        denied_reason: None,
                    };
                }

                if !self.vault.is_unlocked().await {
                    return IpcMessage::GetTotpCodeResponse {
                        code: None,
                        seconds_remaining: None,
                        locked: Some(true),
                        denied_reason: None,
                    };
                }

                // WBS-711: TOTP codes are login second factors — the same
                // scheme safety rule applies.
                let validated_host = match self.autofill_origin_decision(page_url.as_deref()) {
                    Ok(host) => host,
                    Err(reason) => {
                        warn!("denied TOTP code delivery");
                        log_external_secret_audit(
                            self.audit_logger.as_deref(),
                            None,
                            &domain,
                            None,
                            None,
                            false,
                            "Autofill TOTP delivery denied by the origin gate",
                        );
                        return IpcMessage::GetTotpCodeResponse {
                            code: None,
                            seconds_remaining: None,
                            locked: None,
                            denied_reason: Some(reason.to_string()),
                        };
                    }
                };

                match self
                    .vault
                    .get_totp_code_for_username(&validated_host, username.as_deref())
                    .await
                {
                    Ok(Some(code)) => IpcMessage::GetTotpCodeResponse {
                        code: Some(code.code),
                        seconds_remaining: Some(code.seconds_remaining),
                        locked: None,
                        denied_reason: None,
                    },
                    Ok(None) => {
                        debug!("No TOTP code found");
                        IpcMessage::GetTotpCodeResponse {
                            code: None,
                            seconds_remaining: None,
                            locked: None,
                            denied_reason: None,
                        }
                    }
                    Err(e) => {
                        error!(error_kind = ?std::any::type_name_of_val(&e), "Failed to get TOTP code");
                        IpcMessage::GetTotpCodeResponse {
                            code: None,
                            seconds_remaining: None,
                            locked: None,
                            denied_reason: None,
                        }
                    }
                }
            }
            IpcMessage::SaveCredential {
                domain,
                username,
                password,
                url,
                save_trigger: _,
            } => {
                // SP-0 / ADR-013: browser capture is entry creation; under
                // the strict profile the extension cannot present a
                // master-password step-up, so capture is disabled (the
                // owner adds entries through the step-up-capable CLI/UI).
                if self.require_stepup {
                    return IpcMessage::SaveCredentialResponse {
                        success: false,
                        locked: None,
                        error: Some(
                            "step_up_required: browser capture is disabled under the strict profile"
                                .to_string(),
                        ),
                    };
                }
                info!("IPC: SaveCredential");

                if !self.browser_surface_allowed(origin, envelope.capability.as_deref()) {
                    return IpcMessage::SaveCredentialResponse {
                        success: false,
                        error: Some(
                            "browser-surface request rejected: non-native origin".to_string(),
                        ),
                        locked: None,
                    };
                }

                if !self.vault.is_unlocked().await {
                    return IpcMessage::SaveCredentialResponse {
                        success: false,
                        error: Some("vault is locked".to_string()),
                        locked: Some(true),
                    };
                }

                match self
                    .vault
                    .save_credential(&domain, &username, &password, url.as_deref())
                    .await
                {
                    Ok(_) => {
                        info!("Credential saved successfully");
                        IpcMessage::SaveCredentialResponse {
                            success: true,
                            error: None,
                            locked: None,
                        }
                    }
                    Err(e) => {
                        error!(error_kind = ?std::any::type_name_of_val(&e), "Failed to save credential");
                        IpcMessage::SaveCredentialResponse {
                            success: false,
                            error: Some(e.to_string()),
                            locked: None,
                        }
                    }
                }
            }
            IpcMessage::GrantSitePermission {
                host,
                allow_insecure,
            } => {
                // SP-0 / ADR-013: autofill permission grants are policy
                // mutations; the strict profile denies them on the browser
                // surface (which cannot step up).
                if self.require_stepup {
                    return IpcMessage::GrantSitePermissionResponse {
                        success: false,
                        error: Some(
                            "step_up_required: site permission grants are disabled under the strict profile"
                                .to_string(),
                        ),
                    };
                }
                // WBS-712: permission management is a browser-surface op —
                // the same capability gate as the ops it authorizes. The
                // grant only ever loosens the gate for ONE exact host and
                // only for the insecure scheme the user explicitly accepted.
                if !self.browser_surface_allowed(origin, envelope.capability.as_deref()) {
                    return IpcMessage::GrantSitePermissionResponse {
                        success: false,
                        error: Some(
                            "browser-surface request rejected: non-native origin".to_string(),
                        ),
                    };
                }

                let result = if allow_insecure {
                    let mut store =
                        crate::daemon::site_permissions::SitePermissionStore::load_from_path(
                            &self.site_permissions_path,
                        )
                        .unwrap_or_default();
                    match store.grant_insecure(&self.site_permissions_path, &host) {
                        Ok(true) => {
                            info!("Site permission granted (allow_insecure) for");
                            Ok(true)
                        }
                        Ok(false) => Ok(false),
                        Err(e) => Err(e),
                    }
                } else {
                    Err(PasswordManagerError::InvalidInput(
                        "only allow_insecure grants are supported".to_string(),
                    ))
                };

                match result {
                    Ok(true) => IpcMessage::GrantSitePermissionResponse {
                        success: true,
                        error: None,
                    },
                    Ok(false) => IpcMessage::GrantSitePermissionResponse {
                        success: false,
                        error: Some("invalid host".to_string()),
                    },
                    Err(e) => {
                        error!(error_kind = ?std::any::type_name_of_val(&e), "Failed to grant site permission");
                        IpcMessage::GrantSitePermissionResponse {
                            success: false,
                            error: Some("grant failed".to_string()),
                        }
                    }
                }
            }
            IpcMessage::RevokeSitePermission { host } => {
                // SP-0 / ADR-013 (review F3): revocation is a policy
                // mutation too — handoff §3A: "Even restrictive
                // administrative revocation uses step-up under the owner's
                // current rule." The browser surface cannot step up.
                if self.require_stepup {
                    return IpcMessage::RevokeSitePermissionResponse {
                        success: false,
                        removed: false,
                        error: Some(
                            "step_up_required: site permission changes are disabled under the strict profile"
                                .to_string(),
                        ),
                    };
                }
                if !self.browser_surface_allowed(origin, envelope.capability.as_deref()) {
                    return IpcMessage::RevokeSitePermissionResponse {
                        success: false,
                        removed: false,
                        error: Some(
                            "browser-surface request rejected: non-native origin".to_string(),
                        ),
                    };
                }

                let mut store =
                    crate::daemon::site_permissions::SitePermissionStore::load_from_path(
                        &self.site_permissions_path,
                    )
                    .unwrap_or_default();
                match store.revoke(&self.site_permissions_path, &host) {
                    Ok(removed) => {
                        info!("Site permission revoked for");
                        IpcMessage::RevokeSitePermissionResponse {
                            success: true,
                            removed,
                            error: None,
                        }
                    }
                    Err(e) => {
                        error!(error_kind = ?std::any::type_name_of_val(&e), "Failed to revoke site permission");
                        IpcMessage::RevokeSitePermissionResponse {
                            success: false,
                            removed: false,
                            error: Some("revoke failed".to_string()),
                        }
                    }
                }
            }
            IpcMessage::ListSitePermissions => {
                if !self.browser_surface_allowed(origin, envelope.capability.as_deref()) {
                    return IpcMessage::ListSitePermissionsResponse {
                        permissions: Vec::new(),
                        locked: None,
                    };
                }

                let store = crate::daemon::site_permissions::SitePermissionStore::load_from_path(
                    &self.site_permissions_path,
                )
                .unwrap_or_default();
                IpcMessage::ListSitePermissionsResponse {
                    permissions: store
                        .list()
                        .into_iter()
                        .map(|p| sentinelpass_protocol::SitePermissionSummary {
                            host: p.host,
                            allow_insecure: p.allow_insecure,
                            granted_at: p.granted_at,
                        })
                        .collect(),
                    locked: None,
                }
            }
            IpcMessage::UnlockVault {
                mut master_password,
            } => {
                debug!("IPC: UnlockVault");

                let unlock_result = if self.vault.is_unlocked().await {
                    Ok(())
                } else {
                    self.vault.unlock(master_password.as_bytes()).await
                };
                master_password.zeroize();

                match unlock_result {
                    Ok(_) => IpcMessage::UnlockVaultResponse {
                        success: true,
                        error: None,
                    },
                    Err(e) => {
                        warn!(error_kind = ?std::any::type_name_of_val(&e), "Failed to unlock vault via IPC");
                        IpcMessage::UnlockVaultResponse {
                            success: false,
                            error: Some(e.to_string()),
                        }
                    }
                }
            }
            IpcMessage::UnlockVaultBiometric { prompt_reason } => {
                debug!("IPC: UnlockVaultBiometric");
                let reason =
                    prompt_reason.unwrap_or_else(|| "Unlock SentinelPass daemon".to_string());
                match self.vault.unlock_with_biometric(&reason).await {
                    Ok(_) => {
                        log_daemon_audit(
                            self.audit_logger.as_deref(),
                            AuditEventType::BiometricUnlockRequested { success: true },
                            "Daemon biometric unlock succeeded",
                        );
                        IpcMessage::UnlockVaultResponse {
                            success: true,
                            error: None,
                        }
                    }
                    Err(e) => {
                        warn!(error_kind = ?std::any::type_name_of_val(&e), "Failed biometric unlock via IPC");
                        log_daemon_audit(
                            self.audit_logger.as_deref(),
                            AuditEventType::BiometricUnlockRequested { success: false },
                            "Daemon biometric unlock failed",
                        );
                        IpcMessage::UnlockVaultResponse {
                            success: false,
                            error: Some(e.to_string()),
                        }
                    }
                }
            }
            IpcMessage::CheckVault => {
                debug!("IPC: CheckVault");
                let unlocked = self.vault.is_unlocked().await;
                // key_epoch is vault metadata, not key material, but
                // DaemonVault drops its VaultManager on lock — 0 means
                // "unknown" (vault not currently loaded), not epoch zero.
                let key_epoch = self.vault.key_epoch().await.unwrap_or(0);
                IpcMessage::VaultStatusResponse {
                    unlocked,
                    key_epoch,
                }
            }
            IpcMessage::LockVault => {
                debug!("IPC: LockVault");
                self.vault.lock().await;
                IpcMessage::VaultStatusResponse {
                    unlocked: false,
                    key_epoch: 0,
                }
            }
            IpcMessage::Shutdown => {
                info!("IPC: Shutdown requested");
                self.shutdown.store(true, Ordering::Release);
                IpcMessage::VaultStatusResponse {
                    unlocked: false,
                    key_epoch: 0,
                }
            }
            IpcMessage::SyncNow => {
                // SP-0 / ADR-013 (review F1): the bare SyncNow message must
                // honor the strict profile exactly like
                // ServiceCall(VaultOp::SyncNow) — a sync cycle APPLIES remote
                // mutations, so gating only the classified op left a crafted
                // bare-frame bypass.
                if self.require_stepup {
                    return IpcMessage::SyncNowResponse {
                        success: false,
                        pushed: 0,
                        pulled: 0,
                        error: Some(
                            "step_up_required: unattended sync is disabled under the strict profile"
                                .to_string(),
                        ),
                    };
                }
                debug!("IPC: SyncNow");
                #[cfg(feature = "sync")]
                {
                    let pending_before = self
                        .vault
                        .get_sync_status()
                        .await
                        .map(|s| s.pending_changes)
                        .unwrap_or(0);
                    match self.vault.sync_now().await {
                        Ok(status_after) => {
                            let pushed =
                                pending_before.saturating_sub(status_after.pending_changes);
                            info!("IPC: sync completed, ~{} changes pushed", pushed);
                            IpcMessage::SyncNowResponse {
                                success: true,
                                pushed,
                                pulled: 0,
                                error: None,
                            }
                        }
                        Err(e) => {
                            error!(error_kind = ?std::any::type_name_of_val(&e), "Failed to run sync");
                            IpcMessage::SyncNowResponse {
                                success: false,
                                pushed: 0,
                                pulled: 0,
                                error: Some(e.to_string()),
                            }
                        }
                    }
                }
                #[cfg(not(feature = "sync"))]
                IpcMessage::SyncNowResponse {
                    success: false,
                    pushed: 0,
                    pulled: 0,
                    error: Some("sync support is not compiled into this daemon".to_string()),
                }
            }
            IpcMessage::SyncStatus => {
                debug!("IPC: SyncStatus");
                match self.vault.get_sync_status().await {
                    Ok(status) => IpcMessage::SyncStatusResponse {
                        enabled: status.enabled,
                        device_id: status.device_id.map(|d| d.to_string()),
                        device_name: status.device_name,
                        relay_url: status.relay_url,
                        last_sync_at: status.last_sync_at,
                        pending_changes: status.pending_changes,
                    },
                    Err(e) => {
                        error!(error_kind = ?std::any::type_name_of_val(&e), "Failed to get sync status");
                        IpcMessage::SyncStatusResponse {
                            enabled: false,
                            device_id: None,
                            device_name: None,
                            relay_url: None,
                            last_sync_at: None,
                            pending_changes: 0,
                        }
                    }
                }
            }
            IpcMessage::ServiceCall {
                op,
                stepup_approval,
            } => {
                // SP-0 / ADR-013: strict profile — administrative mutations
                // require a fresh, unused, connection- and operation-bound
                // master-password approval. Fail-closed with a typed error
                // the CLI maps to an interactive password prompt.
                // Review F2 (SP-1): service-grant administration gates on a
                // step-up approval on EVERY profile — new surface, no
                // legacy clients. The general SP-0 gate below remains
                // profile-conditional for the transitional surface.
                let grant_admin = matches!(
                    &op,
                    VaultOp::ServiceGrantCreate { .. } | VaultOp::ServiceGrantRevoke { .. }
                );
                if grant_admin || (self.require_stepup && op.requires_admin_step_up()) {
                    let op_bytes = match serde_json::to_vec(&op) {
                        Ok(bytes) => bytes,
                        Err(e) => {
                            return IpcMessage::ServiceResult {
                                outcome: ServiceOutcome::Err {
                                    error: ServiceError::new(
                                        "step_up_required",
                                        format!(
                                            "cannot serialize operation for approval binding: {e}"
                                        ),
                                    ),
                                },
                            };
                        }
                    };
                    let approval = match stepup_approval {
                        Some(approval) => approval,
                        None => {
                            return IpcMessage::ServiceResult {
                                outcome: ServiceOutcome::Err {
                                    error: ServiceError::new(
                                        "step_up_required",
                                        "this operation requires a fresh master-password approval",
                                    ),
                                },
                            };
                        }
                    };
                    if let Err(denial) =
                        self.stepup
                            .take_if_valid(&approval, connection_id, &op_bytes)
                    {
                        return IpcMessage::ServiceResult {
                            outcome: ServiceOutcome::Err {
                                error: ServiceError::new(
                                    "step_up_required",
                                    format!("step-up approval denied: {denial}"),
                                ),
                            },
                        };
                    }
                    // Approval consumed (single use, burned even if the
                    // mutation below fails — ADR-013).
                }
                self.dispatch_service_call(op).await
            }
            // SP-0 / ADR-013: mint a single-use administrative approval
            // after verifying the master password through the full
            // reviewed open path. The password never unlocks anything,
            // never persists, and is dropped (zeroizing) immediately.
            IpcMessage::StepUpAuthorize {
                master_password,
                op,
            } => {
                if let Some(retry_after) = self.stepup.throttled() {
                    return IpcMessage::StepUpDenied {
                        error: "too many failed verifications".to_string(),
                        retry_after_secs: Some(retry_after),
                    };
                }
                // The vault must exist (nothing to verify against in
                // maintenance mode; VaultCreate needs no step-up).
                if self.is_maintenance_mode() {
                    return IpcMessage::StepUpDenied {
                        error: "no vault: nothing to verify against".to_string(),
                        retry_after_secs: None,
                    };
                }
                // Review F2: mutations can only dispatch against an
                // UNLOCKED manager, and running the full open() while the
                // daemon vault is locked installs the process-global
                // audit-key lease (breaking the cleared-on-lock invariant)
                // and re-runs vault maintenance sweeps against a vault the
                // operator believes is at rest. Refuse: unlock first.
                if !self.vault.is_unlocked().await {
                    return IpcMessage::StepUpDenied {
                        error: "vault is locked: unlock it before requesting step-up \
                             (administrative mutations require the unlocked vault)"
                            .to_string(),
                        retry_after_secs: None,
                    };
                }
                let op_bytes = match serde_json::to_vec(&op) {
                    Ok(bytes) => bytes,
                    Err(e) => {
                        return IpcMessage::StepUpDenied {
                            error: format!("cannot serialize operation: {e}"),
                            retry_after_secs: None,
                        };
                    }
                };
                // KDF discipline identical to unlock: blocking pool + the
                // per-vault Argon2id gate. NOTE (review F2, documented in
                // ADR-013): this runs the FULL reviewed open(), whose
                // success path re-runs (idempotent, already-completed)
                // maintenance sweeps and appends a VaultUnlocked audit
                // record; a wrong password shares the vault-wide persistent
                // lockout counter with unlock. The DaemonVault itself is
                // never unlocked by this.
                let permit = self.vault.kdf_permit().await;
                let vault_path = self.vault.vault_path().to_path_buf();
                // Zeroizing custody inside the blocking task; nothing
                // retains the password after verification.
                let password = zeroize::Zeroizing::new(master_password.into_bytes());
                let verification = tokio::task::spawn_blocking(move || {
                    let _permit = permit;
                    VaultManager::open(&vault_path, &password)
                })
                .await;
                match verification {
                    Ok(Ok(_manager)) => {
                        // Verified. The manager (and its derived keys) is
                        // dropped here on purpose.
                        self.stepup.record_success();
                        let (approval_id, expires_at_unix) =
                            self.stepup.mint(connection_id, &op_bytes);
                        IpcMessage::StepUpReceipt {
                            approval_id,
                            expires_at_unix,
                        }
                    }
                    Ok(Err(_)) => {
                        self.stepup.record_failure();
                        let retry_after = self.stepup.throttled();
                        IpcMessage::StepUpDenied {
                            error: "master password verification failed".to_string(),
                            retry_after_secs: retry_after,
                        }
                    }
                    Err(e) => IpcMessage::StepUpDenied {
                        error: format!("verification task failed: {e}"),
                        retry_after_secs: None,
                    },
                }
            }
            _ => IpcMessage::VaultStatusResponse {
                unlocked: false,
                key_epoch: 0,
            },
        }
    }

    /// Application-service dispatch (WBS-408/501): every vault operation
    /// reaches the [`VaultManager`] through the single `VaultOp` boundary.
    /// The blocking work (SQLite + crypto) runs on the blocking pool, never
    /// on the async executor; the relay-network ops (`SyncNow`) are awaited
    /// here instead because the sync engine needs an async context.
    async fn dispatch_service_call(&self, op: VaultOp) -> IpcMessage {
        // Metadata ops that are valid while LOCKED — served without a
        // manager (review finding: the UI asks biometric status before
        // unlock to decide whether to offer the button).
        // SP-1 / ADR-014: service-grant ops are served HERE (grant store
        // + step-up context live at the IPC boundary), not in the vault
        // application service. Step-up enforcement for the admin pair is
        // inherited: the ServiceCall arm already gated them via the
        // exhaustive classification (both are step-up class).
        match &op {
            VaultOp::ServiceGetSecret {
                client_id,
                entry_id,
                field,
                token,
            } => {
                return self
                    .service_get_secret(client_id, *entry_id, field, token)
                    .await
            }
            VaultOp::ServiceGrantCreate {
                client_id,
                entry_id,
                fields,
                expires_at,
            } => {
                // Review F2: the ServiceCall arm gates these two admin ops
                // on a consumed op-bound step-up approval UNCONDITIONALLY
                // (every profile) before dispatch reaches here.
                return self
                    .service_grant_create(client_id, *entry_id, fields.clone(), *expires_at)
                    .await;
            }
            VaultOp::ServiceGrantRevoke { grant_id } => {
                return self.service_grant_revoke(grant_id).await
            }
            _ => {}
        }

        if let VaultOp::BiometricStatusGet = op {
            let configured =
                VaultManager::is_biometric_unlock_enabled(self.vault.vault_path()).unwrap_or(false);
            return IpcMessage::ServiceResult {
                outcome: ServiceOutcome::from(VaultOpResult::Biometric(
                    sentinelpass_protocol::service::ServiceBiometricStatus {
                        method_name: crate::BiometricManager::get_method_name().to_string(),
                        available: crate::BiometricManager::is_available(),
                        enrolled: crate::BiometricManager::is_enrolled(),
                        configured,
                    },
                )),
            };
        }

        let outcome = match op {
            VaultOp::SyncMigrateClaim => {
                #[cfg(feature = "sync")]
                {
                    match self.vault.claim_sync_migration().await {
                        Ok(new_vault) => ServiceOutcome::from(VaultOpResult::Report(
                            serde_json::json!({ "new_vault_id": new_vault.to_string() }),
                        )),
                        Err(e) => ServiceOutcome::from(ServiceError::from(e)),
                    }
                }
                #[cfg(not(feature = "sync"))]
                {
                    ServiceOutcome::from(ServiceError::new(
                        codes::INTERNAL,
                        "sync support is not compiled into this daemon",
                    ))
                }
            }
            VaultOp::SyncNow => {
                #[cfg(feature = "sync")]
                {
                    match self.vault.sync_now().await {
                        Ok(status) => ServiceOutcome::from(VaultOpResult::SyncStatus(
                            sentinelpass_protocol::service::ServiceSyncStatus {
                                enabled: status.enabled,
                                device_id: status.device_id.map(|d| d.to_string()),
                                device_name: status.device_name,
                                relay_url: status.relay_url,
                                last_sync_at: status.last_sync_at,
                                pending_changes: status.pending_changes,
                                conflicts: status.conflict_count,
                            },
                        )),
                        Err(e) => ServiceOutcome::from(ServiceError::from(e)),
                    }
                }
                #[cfg(not(feature = "sync"))]
                {
                    ServiceOutcome::from(ServiceError::new(
                        codes::INTERNAL,
                        "sync support is not compiled into this daemon",
                    ))
                }
            }
            op => match self.vault.manager().await {
                None => ServiceOutcome::from(ServiceError::new(
                    codes::VAULT_LOCKED,
                    "vault is locked; unlock it first",
                )),
                Some(vault) => {
                    // `spawn_blocking` needs 'static: DaemonVault hands out an
                    // Arc'd manager. Serialization of vault ops comes from
                    // VaultManager's internal db mutex (review F5: the Arc
                    // clone means concurrent service tasks DO run in
                    // parallel; SQLite access — and therefore one write at a
                    // time — is serialized inside the manager).
                    let joined = tokio::task::spawn_blocking(move || {
                        LiveVaultService::new(&vault).execute(&op)
                    })
                    .await;
                    match joined {
                        Ok(Ok(result)) => ServiceOutcome::from(result),
                        Ok(Err(service_error)) => ServiceOutcome::from(service_error),
                        Err(e) => ServiceOutcome::from(ServiceError::new(
                            codes::INTERNAL,
                            format!("service task failed: {}", e),
                        )),
                    }
                }
            },
        };
        IpcMessage::ServiceResult { outcome }
    }

    /// Maintenance/bootstrap surface (WBS-501/503): no vault exists yet.
    async fn handle_maintenance_message(
        &self,
        envelope: IpcEnvelope,
        _connection_id: u128,
    ) -> IpcMessage {
        match envelope.message {
            IpcMessage::CheckVault => IpcMessage::VaultStatusResponse {
                unlocked: false,
                key_epoch: 0,
            },
            IpcMessage::Shutdown => {
                info!("IPC: Shutdown requested (maintenance mode)");
                self.shutdown.store(true, Ordering::Release);
                IpcMessage::VaultStatusResponse {
                    unlocked: false,
                    key_epoch: 0,
                }
            }
            IpcMessage::ServiceCall { op, .. } => {
                // Maintenance mode serves only VaultStatus/VaultCreate —
                // VaultCreate is bootstrap password-setting, exempt from
                // step-up by design (ADR-013).
                self.dispatch_maintenance_op(op).await
            }
            IpcMessage::UnlockVault {
                mut master_password,
            } => {
                // No vault exists; unlocking cannot succeed. Still zeroize
                // the presented password before answering.
                master_password.zeroize();
                warn!("IPC: unlock refused — daemon is in maintenance mode (no vault)");
                IpcMessage::UnlockVaultResponse {
                    success: false,
                    error: Some(
                        "daemon is in maintenance mode: no vault exists yet; create one first"
                            .to_string(),
                    ),
                }
            }
            IpcMessage::UnlockVaultBiometric { .. } => {
                warn!("IPC: biometric unlock refused — maintenance mode (no vault)");
                IpcMessage::UnlockVaultResponse {
                    success: false,
                    error: Some(
                        "daemon is in maintenance mode: no vault exists yet; create one first"
                            .to_string(),
                    ),
                }
            }
            other => {
                debug!("IPC: message refused in maintenance mode");
                let _ = other;
                IpcMessage::VaultStatusResponse {
                    unlocked: false,
                    key_epoch: 0,
                }
            }
        }
    }

    /// Bootstrap op dispatch: only `VaultStatus` and `VaultCreate`.
    async fn dispatch_maintenance_op(&self, op: VaultOp) -> IpcMessage {
        match op {
            VaultOp::VaultStatus => IpcMessage::ServiceResult {
                outcome: ServiceOutcome::from(VaultOpResult::Status(ServiceVaultStatus {
                    unlocked: false,
                    key_epoch: 0,
                    maintenance: true,
                })),
            },
            VaultOp::VaultCreate { master_password } => {
                let vault_path = self.vault.vault_path().to_path_buf();
                if vault_path.exists() {
                    return IpcMessage::ServiceResult {
                        outcome: ServiceOutcome::from(ServiceError::new(
                            codes::VAULT_EXISTS,
                            "a vault already exists at the daemon's vault path",
                        )),
                    };
                }
                info!("IPC: creating vault through maintenance bootstrap");
                // Argon2id KDF + schema creation on the blocking pool
                // (ADR-004 rev 5: KDF work never runs on the async executor)
                // with the per-vault KDF gate held (WBS-513).
                let kdf_permit = self.vault.kdf_permit().await;
                let created = tokio::task::spawn_blocking(move || {
                    let _kdf_permit = kdf_permit;
                    VaultManager::create(&vault_path, master_password.as_bytes())
                })
                .await;
                match created {
                    Ok(Ok(vault)) => {
                        let key_epoch = vault.key_epoch().unwrap_or(1);
                        log_daemon_audit(
                            self.audit_logger.as_deref(),
                            AuditEventType::VaultCreated,
                            "vault created through daemon maintenance bootstrap",
                        );
                        self.vault.unlock_with_manager(vault).await;
                        self.set_live_mode();
                        info!("IPC: vault created — daemon leaving maintenance mode");
                        IpcMessage::ServiceResult {
                            outcome: ServiceOutcome::from(VaultOpResult::Status(
                                ServiceVaultStatus {
                                    unlocked: true,
                                    key_epoch,
                                    maintenance: false,
                                },
                            )),
                        }
                    }
                    Ok(Err(e)) => {
                        warn!(error_kind = ?std::any::type_name_of_val(&e), "IPC: vault creation refused");
                        IpcMessage::ServiceResult {
                            outcome: ServiceOutcome::from(ServiceError::from(e)),
                        }
                    }
                    Err(e) => IpcMessage::ServiceResult {
                        outcome: ServiceOutcome::from(ServiceError::new(
                            codes::INTERNAL,
                            format!("vault creation task failed: {}", e),
                        )),
                    },
                }
            }
            other => {
                let _ = &other;
                IpcMessage::ServiceResult {
                    outcome: ServiceOutcome::from(ServiceError::new(
                        codes::MAINTENANCE_MODE,
                        "daemon is in maintenance mode (no vault): only status and \
                         vault creation are served",
                    )),
                }
            }
        }
    }
}

#[cfg(test)]
mod browser_surface_gate_tests {
    use super::*;
    use crate::daemon::capabilities::InstallationCapabilities;
    use sentinelpass_protocol::Origin;

    fn store_with_native_host() -> InstallationCapabilities {
        let mut store = InstallationCapabilities::default();
        store
            .capabilities
            .push(crate::daemon::capabilities::Capability {
                audience: crate::daemon::capabilities::NATIVE_HOST_AUDIENCE.to_string(),
                secret_hash: {
                    use sha2::Digest;
                    hex::encode(sha2::Sha256::digest(b"valid-host-capability-secret"))
                },
                issued_at: 0,
                expires_at: None,
                nonce: "test-nonce".to_string(),
            });
        store
    }

    /// Env is process-global: every env-touching test holds this lock for
    /// its whole body (same pattern as the pre-existing gate tests).
    static ENV_LOCK: std::sync::Mutex<()> = std::sync::Mutex::new(());

    fn set_env(key: &str, value: Option<&str>) {
        match value {
            Some(v) => std::env::set_var(key, v),
            None => std::env::remove_var(key),
        }
    }

    /// WBS-505 positive: a valid native-host capability authorizes the
    /// browser surface regardless of the (forgeable) origin label.
    #[test]
    fn valid_capability_authorizes_browser_surface() {
        set_env("SENTINELPASS_ALLOW_SELF_ASSERTED_ORIGIN", None);
        set_env("SENTINELPASS_ALLOW_LEGACY_ORIGINLESS", None);
        let store = store_with_native_host();
        assert!(IpcServer::browser_surface_allowed_with_store(
            Some(Origin::NativeHost),
            Some("valid-host-capability-secret"),
            &store,
        ));
    }

    /// WBS-505 negative (the phase gate): a GENERAL client claiming
    /// NativeHost — origin label present, capability material absent — is
    /// DENIED. Origin is provenance, never authorization.
    #[test]
    fn native_host_claim_without_capability_is_denied() {
        let _env = ENV_LOCK.lock().unwrap();
        set_env("SENTINELPASS_ALLOW_SELF_ASSERTED_ORIGIN", None);
        set_env("SENTINELPASS_ALLOW_LEGACY_ORIGINLESS", None);
        let store = store_with_native_host();

        assert!(!IpcServer::browser_surface_allowed_with_store(
            Some(Origin::NativeHost),
            None,
            &store,
        ));
        // Wrong secret material is denied too.
        assert!(!IpcServer::browser_surface_allowed_with_store(
            Some(Origin::NativeHost),
            Some("attacker-guess"),
            &store,
        ));
        // Originless with a guess is denied.
        assert!(!IpcServer::browser_surface_allowed_with_store(
            None,
            Some("attacker-guess"),
            &store,
        ));
        // A CLI-LABELED request presenting VALID material is allowed: the
        // origin label is provenance and cannot authorize OR de-authorize —
        // possession of the capability material is the authority (a
        // "CLI" label is trivially droppable by an attacker, so consulting
        // it would be security theater). What the capability model removes
        // is the AMBIENT grant: without the material, every claim fails.
        assert!(IpcServer::browser_surface_allowed_with_store(
            Some(Origin::Cli),
            Some("valid-host-capability-secret"),
            &store,
        ));
        assert!(!IpcServer::browser_surface_allowed_with_store(
            Some(Origin::Cli),
            None,
            &store,
        ));
    }

    /// The legacy self-asserted-origin window requires BOTH the exact env
    /// value and the NativeHost label; it is announced and temporary.
    #[test]
    fn legacy_self_asserted_origin_window_is_explicit_opt_in() {
        let _env = ENV_LOCK.lock().unwrap();
        let store = store_with_native_host();

        set_env("SENTINELPASS_ALLOW_SELF_ASSERTED_ORIGIN", None);
        assert!(!IpcServer::browser_surface_allowed_with_store(
            Some(Origin::NativeHost),
            None,
            &store,
        ));

        set_env("SENTINELPASS_ALLOW_SELF_ASSERTED_ORIGIN", Some("1"));
        assert!(IpcServer::browser_surface_allowed_with_store(
            Some(Origin::NativeHost),
            None,
            &store,
        ));

        // Only the exact value "1" opts in.
        set_env("SENTINELPASS_ALLOW_SELF_ASSERTED_ORIGIN", Some("yes"));
        assert!(!IpcServer::browser_surface_allowed_with_store(
            Some(Origin::NativeHost),
            None,
            &store,
        ));
        set_env("SENTINELPASS_ALLOW_SELF_ASSERTED_ORIGIN", None);

        // The OLD originless window stays independent and still denied by
        // default (env cleaned above).
        assert!(!IpcServer::browser_surface_allowed_with_store(
            None, None, &store
        ));
    }
}

/// WBS-711 — default-deny HTTP autofill: the daemon-side origin gate.
#[cfg(test)]
mod autofill_origin_gate_tests {
    use super::*;
    use crate::daemon::capabilities::{InstallationCapabilities, NATIVE_HOST_AUDIENCE};
    use crate::daemon::DaemonVault;
    use crate::{Entry, VaultManager};
    use chrono::Utc;
    use sentinelpass_protocol::{IpcEnvelope, Origin};
    use tempfile::TempDir;

    #[test]
    fn credential_diagnostics_do_not_disclose_request_values() {
        #[derive(Clone)]
        struct Capture(Arc<std::sync::Mutex<Vec<u8>>>);
        impl std::io::Write for Capture {
            fn write(&mut self, bytes: &[u8]) -> std::io::Result<usize> {
                self.0.lock().unwrap().extend_from_slice(bytes);
                Ok(bytes.len())
            }
            fn flush(&mut self) -> std::io::Result<()> {
                Ok(())
            }
        }
        let h = harness_with_vault();
        let capture = Capture(Arc::new(std::sync::Mutex::new(Vec::new())));
        let writer = capture.clone();
        let subscriber = tracing_subscriber::fmt()
            .without_time()
            .with_ansi(false)
            .with_max_level(tracing::Level::TRACE)
            .with_writer(move || writer.clone())
            .finish();
        let rt = tokio::runtime::Builder::new_current_thread()
            .enable_all()
            .build()
            .unwrap();
        tracing::subscriber::with_default(subscriber, || {
            for capability in [None, Some(h.capability.clone())] {
                let _ = handle(
                    &rt,
                    &h.server,
                    envelope(
                        IpcMessage::SaveCredential {
                            domain: "private-canary.invalid".into(),
                            username: "private-user-canary".into(),
                            password: "private-secret-canary".into(),
                            url: Some("https://private-canary.invalid".into()),
                            save_trigger: Some("private-trigger-canary".into()),
                        },
                        capability,
                    ),
                );
            }
        });
        let bytes = capture.0.lock().unwrap();
        let text = String::from_utf8_lossy(&bytes);
        assert!(!text.is_empty(), "logging capture must observe events");
        for canary in [
            "private-canary",
            "private-user",
            "private-secret",
            "private-trigger",
        ] {
            assert!(!text.contains(canary), "diagnostic log disclosed {canary}");
        }
    }

    // --- pure gate decision -------------------------------------------------

    fn empty_permissions() -> crate::daemon::site_permissions::SitePermissionStore {
        crate::daemon::site_permissions::SitePermissionStore::default()
    }

    #[test]
    fn https_origins_deliver_with_their_validated_host() {
        for (url, expected_host) in [
            ("https://example.com/login", "example.com"),
            ("https://Example.COM/login", "example.com"),
            ("https://example.com:8443/x?y=1#z", "example.com"),
            ("https://sub.example.com/deep/path", "sub.example.com"),
            ("https://user:pw@example.com/", "example.com"),
            ("https://[::1]:8443/login", "::1"),
        ] {
            let decision =
                IpcServer::autofill_origin_decision_with_store(Some(url), &empty_permissions());
            assert_eq!(
                decision.as_deref(),
                Ok(expected_host),
                "gate must validate and bind {url}"
            );
        }
    }

    #[test]
    fn http_origins_are_denied_by_default() {
        for url in [
            "http://example.com/login",
            "http://EXAMPLE.com",
            "http://127.0.0.1:8080/login",
            "http://[::1]/admin",
        ] {
            assert_eq!(
                IpcServer::autofill_origin_decision_with_store(Some(url), &empty_permissions()),
                Err("insecure-http"),
                "plain HTTP must be denied: {url}"
            );
        }
    }

    #[test]
    fn unverifiable_origins_are_denied() {
        for url in [
            None,
            Some(""),
            Some("   "),
            // No scheme at all: the daemon cannot verify transport safety.
            Some("example.com"),
            Some("//example.com/path"),
            // Non-web schemes are not autofill contexts.
            Some("ftp://example.com/pub"),
            Some("file:///etc/passwd"),
            Some("chrome-extension://abcdef/popup.html"),
            Some("about:blank"),
            // Scheme-shaped but no host.
            Some("https://"),
        ] {
            assert_eq!(
                IpcServer::autofill_origin_decision_with_store(url, &empty_permissions()),
                Err("origin-unverified"),
                "unverifiable origin must be denied: {url:?}"
            );
        }
    }

    // --- handler-level behavior over a REAL unlocked daemon vault -----------

    struct GateHarness {
        _tmp: TempDir,
        server: IpcServer,
        capability: String,
        permissions_path: std::path::PathBuf,
    }

    fn harness_with_vault() -> GateHarness {
        let tmp = TempDir::new().unwrap();
        let vault_path = tmp.path().join("vault.db");
        let password = b"test_password";

        let vault = VaultManager::create(&vault_path, password).unwrap();
        vault
            .add_entry(&Entry {
                entry_id: None,
                title: "Example".to_string(),
                username: "user@example.com".to_string(),
                password: "password-secret".to_string().into(),
                url: Some("https://example.com/login".to_string()),
                notes: None,
                credential_type: crate::CredentialType::Password,
                created_at: Utc::now(),
                modified_at: Utc::now(),
                favorite: false,
            })
            .unwrap();
        vault
            .add_entry(&Entry {
                entry_id: None,
                title: "GitHub".to_string(),
                username: "gh@example.com".to_string(),
                password: "github-secret".to_string().into(),
                url: Some("https://github.com/login".to_string()),
                notes: None,
                credential_type: crate::CredentialType::Password,
                created_at: Utc::now(),
                modified_at: Utc::now(),
                favorite: false,
            })
            .unwrap();
        drop(vault);

        let daemon_vault = DaemonVault::new(Some(vault_path.clone()), 300).unwrap();
        let rt = tokio::runtime::Runtime::new().unwrap();
        rt.block_on(async { daemon_vault.unlock(password).await })
            .unwrap();

        // Mint a native-host capability in a temp store.
        let capability_store = tmp.path().join("ipc-capabilities.json");
        let mut store = InstallationCapabilities::default();
        let capability = store
            .mint(&capability_store, NATIVE_HOST_AUDIENCE, None)
            .unwrap();

        let permissions_path = tmp.path().join("site_permissions.json");
        let server = IpcServer::new_with_allowlist_path(
            tmp.path().join("test.sock"),
            Arc::new(daemon_vault),
            "test-token".to_string(),
            tmp.path().join("allowlist.json"),
        )
        .with_capability_store_path(capability_store)
        .with_site_permissions_path(permissions_path.clone());

        GateHarness {
            _tmp: tmp,
            server,
            capability: capability.to_string(),
            permissions_path,
        }
    }

    fn envelope(message: IpcMessage, capability: Option<String>) -> IpcEnvelope {
        IpcEnvelope {
            token: "test-token".to_string(),
            client_token: None,
            origin: Some(Origin::NativeHost),
            capability,
            message,
        }
    }

    const TEST_CONNECTION: u128 = 0x5FE0_0000_0000_0000;

    /// Test-only: a Debug-safe label (IpcMessage Debug can contain secret
    /// payloads; panic messages must not embed them).
    fn variant_name(_: &IpcMessage) -> &'static str {
        "IpcMessage"
    }

    fn handle(
        rt: &tokio::runtime::Runtime,
        server: &IpcServer,
        envelope: IpcEnvelope,
    ) -> IpcMessage {
        rt.block_on(server.handle_message(envelope, TEST_CONNECTION))
    }

    /// SP-0: same, on an explicit connection identity (cross-connection
    /// denial tests).
    fn handle_on(
        rt: &tokio::runtime::Runtime,
        server: &IpcServer,
        envelope: IpcEnvelope,
        connection_id: u128,
    ) -> IpcMessage {
        rt.block_on(server.handle_message(envelope, connection_id))
    }

    #[test]
    fn https_page_delivers_the_credential() {
        let h = harness_with_vault();
        let rt = tokio::runtime::Runtime::new().unwrap();
        let response = handle(
            &rt,
            &h.server,
            envelope(
                IpcMessage::GetCredential {
                    domain: "example.com".to_string(),
                    page_url: Some("https://example.com/login".to_string()),
                    username: None,
                },
                Some(h.capability.clone()),
            ),
        );
        match response {
            IpcMessage::GetCredentialResponse {
                username,
                denied_reason,
                ..
            } => {
                assert_eq!(username.as_deref(), Some("user@example.com"));
                assert_eq!(denied_reason, None);
            }
            other => panic!("wrong response: {other:?}"),
        }
    }

    /// The lookup identity is the host parsed from the validated page URL,
    /// NOT the claimed domain: a page at https://example.com gets
    /// example.com's credential even when the request claims github.com —
    /// and never the claimed domain's stored secret.
    #[test]
    fn delivery_binds_to_the_validated_url_host_not_the_claimed_domain() {
        let h = harness_with_vault();
        let rt = tokio::runtime::Runtime::new().unwrap();
        let response = handle(
            &rt,
            &h.server,
            envelope(
                IpcMessage::GetCredential {
                    // Claimed domain has its own stored credential
                    // (gh@example.com) — the page is on example.com, so
                    // the delivery must be example.com's entry instead.
                    domain: "github.com".to_string(),
                    page_url: Some("https://example.com/login".to_string()),
                    username: None,
                },
                Some(h.capability.clone()),
            ),
        );
        match response {
            IpcMessage::GetCredentialResponse {
                username,
                password,
                title,
                denied_reason,
                ..
            } => {
                assert_eq!(denied_reason, None);
                assert_eq!(
                    username.as_deref(),
                    Some("user@example.com"),
                    "delivery must follow the URL host, not the claimed domain"
                );
                assert_eq!(password.as_deref(), Some("password-secret"));
                assert_eq!(title.as_deref(), Some("Example"));
            }
            other => panic!("wrong response: {other:?}"),
        }
    }

    #[test]
    fn http_page_is_denied_with_a_reason_even_with_a_valid_capability() {
        let h = harness_with_vault();
        let rt = tokio::runtime::Runtime::new().unwrap();
        let response = handle(
            &rt,
            &h.server,
            envelope(
                IpcMessage::GetCredential {
                    domain: "example.com".to_string(),
                    page_url: Some("http://example.com/login".to_string()),
                    username: None,
                },
                Some(h.capability.clone()),
            ),
        );
        match response {
            IpcMessage::GetCredentialResponse {
                username,
                password,
                denied_reason,
                ..
            } => {
                assert_eq!(username, None);
                assert_eq!(password, None);
                assert_eq!(denied_reason.as_deref(), Some("insecure-http"));
            }
            other => panic!("wrong response: {other:?}"),
        }
    }

    /// A missing page URL (pre-711 host) is a denial, not a bypass: the
    /// capability gate and the scheme gate are independent.
    #[test]
    fn missing_page_url_is_denied() {
        let h = harness_with_vault();
        let rt = tokio::runtime::Runtime::new().unwrap();
        for page_url in [None, Some("".to_string()), Some("not a url".to_string())] {
            let response = handle(
                &rt,
                &h.server,
                envelope(
                    IpcMessage::GetCredential {
                        domain: "example.com".to_string(),
                        page_url,
                        username: None,
                    },
                    Some(h.capability.clone()),
                ),
            );
            match response {
                IpcMessage::GetCredentialResponse {
                    username,
                    denied_reason,
                    ..
                } => {
                    assert_eq!(username, None, "no delivery without a verifiable origin");
                    assert_eq!(denied_reason.as_deref(), Some("origin-unverified"));
                }
                other => panic!("wrong response: {other:?}"),
            }
        }
    }

    #[test]
    fn listing_and_totp_are_gated_the_same_way() {
        let h = harness_with_vault();
        let rt = tokio::runtime::Runtime::new().unwrap();

        let list = handle(
            &rt,
            &h.server,
            envelope(
                IpcMessage::ListDomainCredentials {
                    base_domain: "example.com".to_string(),
                    page_url: Some("http://example.com/login".to_string()),
                },
                Some(h.capability.clone()),
            ),
        );
        match list {
            IpcMessage::ListDomainCredentialsResponse {
                credentials,
                denied_reason,
                ..
            } => {
                assert!(credentials.is_empty());
                assert_eq!(denied_reason.as_deref(), Some("insecure-http"));
            }
            other => panic!("wrong response: {other:?}"),
        }

        let totp = handle(
            &rt,
            &h.server,
            envelope(
                IpcMessage::GetTotpCode {
                    domain: "example.com".to_string(),
                    page_url: Some("http://example.com/login".to_string()),
                    username: None,
                },
                Some(h.capability.clone()),
            ),
        );
        match totp {
            IpcMessage::GetTotpCodeResponse {
                code,
                denied_reason,
                ..
            } => {
                assert_eq!(code, None);
                assert_eq!(denied_reason.as_deref(), Some("insecure-http"));
            }
            other => panic!("wrong response: {other:?}"),
        }

        // HTTPS listing passes the gate and returns the stored match.
        let list_ok = handle(
            &rt,
            &h.server,
            envelope(
                IpcMessage::ListDomainCredentials {
                    base_domain: "example.com".to_string(),
                    page_url: Some("https://example.com/login".to_string()),
                },
                Some(h.capability.clone()),
            ),
        );
        match list_ok {
            IpcMessage::ListDomainCredentialsResponse {
                credentials,
                denied_reason,
                ..
            } => {
                assert_eq!(denied_reason, None);
                assert_eq!(credentials.len(), 1);
                assert_eq!(credentials[0].username, "user@example.com");
            }
            other => panic!("wrong response: {other:?}"),
        }
    }

    /// A LOCKED vault reports locked before the origin gate is consulted
    /// (UX ordering: the user is told to unlock, then the scheme rule
    /// applies) — the combination still leaks nothing.
    #[test]
    fn locked_vault_reports_locked_before_the_origin_gate() {
        let h = harness_with_vault();
        let rt = tokio::runtime::Runtime::new().unwrap();
        rt.block_on(h.server.vault.lock());
        let response = handle(
            &rt,
            &h.server,
            envelope(
                IpcMessage::GetCredential {
                    domain: "example.com".to_string(),
                    page_url: Some("http://example.com/login".to_string()),
                    username: None,
                },
                Some(h.capability.clone()),
            ),
        );
        match response {
            IpcMessage::GetCredentialResponse { locked, .. } => {
                assert_eq!(locked, Some(true));
            }
            other => panic!("wrong response: {other:?}"),
        }
    }

    // --- WBS-712: the explicit per-site allow-list ---------------------------

    /// Grant → HTTP delivers; sibling host stays denied; revoke → denied
    /// again. The full default-deny → explicit-allow lifecycle.
    #[test]
    fn explicit_http_grant_allows_and_revocation_re_denies() {
        let h = harness_with_vault();
        let rt = tokio::runtime::Runtime::new().unwrap();

        let get = |harness: &GateHarness| {
            handle(
                &rt,
                &harness.server,
                envelope(
                    IpcMessage::GetCredential {
                        domain: "example.com".to_string(),
                        page_url: Some("http://example.com/login".to_string()),
                        username: None,
                    },
                    Some(harness.capability.clone()),
                ),
            )
        };

        // Default deny.
        match get(&h) {
            IpcMessage::GetCredentialResponse { denied_reason, .. } => {
                assert_eq!(denied_reason.as_deref(), Some("insecure-http"));
            }
            other => panic!("wrong response: {other:?}"),
        }

        // Explicit grant (popup path) flips the decision for THIS host.
        let grant = handle(
            &rt,
            &h.server,
            envelope(
                IpcMessage::GrantSitePermission {
                    host: "https://example.com/user".to_string(),
                    allow_insecure: true,
                },
                Some(h.capability.clone()),
            ),
        );
        match grant {
            IpcMessage::GrantSitePermissionResponse { success, error } => {
                assert!(success, "grant failed: {error:?}");
            }
            other => panic!("wrong response: {other:?}"),
        }

        match get(&h) {
            IpcMessage::GetCredentialResponse {
                username,
                denied_reason,
                ..
            } => {
                assert_eq!(denied_reason, None);
                assert_eq!(username.as_deref(), Some("user@example.com"));
            }
            other => panic!("wrong response: {other:?}"),
        }

        // The grant is EXACT-host: a sibling is still denied.
        let sibling = handle(
            &rt,
            &h.server,
            envelope(
                IpcMessage::GetCredential {
                    domain: "github.com".to_string(),
                    page_url: Some("http://github.com/login".to_string()),
                    username: None,
                },
                Some(h.capability.clone()),
            ),
        );
        match sibling {
            IpcMessage::GetCredentialResponse { denied_reason, .. } => {
                assert_eq!(denied_reason.as_deref(), Some("insecure-http"));
            }
            other => panic!("wrong response: {other:?}"),
        }

        // Revocation re-denies immediately.
        let revoke = handle(
            &rt,
            &h.server,
            envelope(
                IpcMessage::RevokeSitePermission {
                    host: "example.com".to_string(),
                },
                Some(h.capability.clone()),
            ),
        );
        match revoke {
            IpcMessage::RevokeSitePermissionResponse {
                success, removed, ..
            } => {
                assert!(success);
                assert!(removed);
            }
            other => panic!("wrong response: {other:?}"),
        }
        match get(&h) {
            IpcMessage::GetCredentialResponse { denied_reason, .. } => {
                assert_eq!(denied_reason.as_deref(), Some("insecure-http"));
            }
            other => panic!("wrong response: {other:?}"),
        }

        // The listing reflects the empty store.
        let list = handle(
            &rt,
            &h.server,
            envelope(IpcMessage::ListSitePermissions, Some(h.capability.clone())),
        );
        match list {
            IpcMessage::ListSitePermissionsResponse { permissions, .. } => {
                assert!(permissions.is_empty());
            }
            other => panic!("wrong response: {other:?}"),
        }
    }

    /// A username disambiguator narrows delivery to the exact account
    /// (WBS-712 popup "Pass" per row / WBS-715 chooser): the vault holds
    /// user@example.com AND gh@example.com for the SAME tab host only in
    /// the suffix-match sense, so this test uses two entries on one host.
    #[test]
    fn username_filter_selects_the_exact_account() {
        let h = harness_with_vault();
        let rt = tokio::runtime::Runtime::new().unwrap();

        // example.com has exactly one entry; asking for another username
        // must NOT return it.
        let response = handle(
            &rt,
            &h.server,
            envelope(
                IpcMessage::GetCredential {
                    domain: "example.com".to_string(),
                    page_url: Some("https://example.com/login".to_string()),
                    username: Some("nobody@example.com".to_string()),
                },
                Some(h.capability.clone()),
            ),
        );
        match response {
            IpcMessage::GetCredentialResponse { username, .. } => {
                assert_eq!(username, None, "non-matching username must not deliver");
            }
            other => panic!("wrong response: {other:?}"),
        }

        // The exact (case-insensitive) username delivers its own row.
        let response = handle(
            &rt,
            &h.server,
            envelope(
                IpcMessage::GetCredential {
                    domain: "example.com".to_string(),
                    page_url: Some("https://example.com/login".to_string()),
                    username: Some("  User@Example.COM ".to_string()),
                },
                Some(h.capability.clone()),
            ),
        );
        match response {
            IpcMessage::GetCredentialResponse {
                username,
                denied_reason,
                ..
            } => {
                assert_eq!(denied_reason, None);
                assert_eq!(username.as_deref(), Some("user@example.com"));
            }
            other => panic!("wrong response: {other:?}"),
        }
    }

    /// Permission management requires the browser-surface gate: without the
    /// native-host capability, grants are refused.
    #[test]
    fn grant_requires_browser_surface_capability() {
        let h = harness_with_vault();
        let rt = tokio::runtime::Runtime::new().unwrap();
        let response = handle(
            &rt,
            &h.server,
            envelope(
                IpcMessage::GrantSitePermission {
                    host: "example.com".to_string(),
                    allow_insecure: true,
                },
                // No capability presented.
                None,
            ),
        );
        match response {
            IpcMessage::GrantSitePermissionResponse { success, error } => {
                assert!(!success);
                assert!(error.unwrap_or_default().contains("non-native origin"));
            }
            other => panic!("wrong response: {other:?}"),
        }
        // And nothing was stored.
        let store = crate::daemon::site_permissions::SitePermissionStore::load_from_path(
            &h.permissions_path,
        )
        .unwrap();
        assert!(!store.allows_insecure("example.com"));
    }

    // ------------------------------------------------------------------
    // SP-0 / ADR-013: master-password administrative step-up
    // ------------------------------------------------------------------

    fn strict_harness() -> GateHarness {
        // One owned tempdir: the vault file must stay alive for the
        // step-up verifier's full open.
        let tmp = TempDir::new().unwrap();
        let vault_path = tmp.path().join("vault.db");
        VaultManager::create(&vault_path, b"test_password").unwrap();
        let daemon_vault = DaemonVault::new(Some(vault_path), 300).unwrap();
        let rt = tokio::runtime::Runtime::new().unwrap();
        rt.block_on(async { daemon_vault.unlock(b"test_password").await })
            .unwrap();
        let server = IpcServer::new_with_allowlist_path(
            tmp.path().join("strict.sock"),
            Arc::new(daemon_vault),
            "test-token".to_string(),
            tmp.path().join("allowlist.json"),
        )
        .with_require_stepup(true);
        GateHarness {
            _tmp: tmp,
            server,
            capability: String::new(),
            permissions_path: std::path::PathBuf::new(),
        }
    }

    fn make_add_op(title: &str) -> VaultOp {
        VaultOp::EntryAdd {
            entry: sentinelpass_protocol::service::ServiceEntry {
                entry_id: None,
                title: title.to_string(),
                username: "u".to_string(),
                password: zeroize::Zeroizing::new("p".to_string()),
                url: None,
                notes: None,
                credential_type: "password".to_string(),
                created_at: 0,
                modified_at: 0,
                favorite: false,
            },
        }
    }

    fn service_outcome(msg: IpcMessage) -> ServiceOutcome {
        match msg {
            IpcMessage::ServiceResult { outcome } => outcome,
            other => panic!("unexpected response: {}", variant_name(&other)),
        }
    }

    #[test]
    fn strict_profile_denies_mutation_without_approval() {
        let h = strict_harness();
        let rt = tokio::runtime::Runtime::new().unwrap();
        let msg = handle(
            &rt,
            &h.server,
            envelope(
                IpcMessage::ServiceCall {
                    op: make_add_op("x"),
                    stepup_approval: None,
                },
                Some(h.capability.clone()),
            ),
        );
        match service_outcome(msg) {
            ServiceOutcome::Err { error } => assert_eq!(error.code, "step_up_required"),
            ServiceOutcome::Ok { .. } => panic!("unapproved mutation must be denied"),
        }
    }

    #[test]
    fn strict_profile_allows_reads_without_step_up() {
        let h = strict_harness();
        let rt = tokio::runtime::Runtime::new().unwrap();
        for op in [VaultOp::VaultStatus, VaultOp::EntryList] {
            let msg = handle(
                &rt,
                &h.server,
                envelope(
                    IpcMessage::ServiceCall {
                        op,
                        stepup_approval: None,
                    },
                    Some(h.capability.clone()),
                ),
            );
            assert!(
                matches!(service_outcome(msg), ServiceOutcome::Ok { .. }),
                "reads must remain unattended under the strict profile"
            );
        }
    }

    #[test]
    fn step_up_allows_exactly_one_mutation() {
        let h = strict_harness();
        let rt = tokio::runtime::Runtime::new().unwrap();
        let op = make_add_op("stepped");
        // Authorize with the correct master password for THIS op.
        let receipt = handle(
            &rt,
            &h.server,
            envelope(
                IpcMessage::StepUpAuthorize {
                    master_password: "test_password".to_string(),
                    op: op.clone(),
                },
                None,
            ),
        );
        let IpcMessage::StepUpReceipt { approval_id, .. } = receipt else {
            panic!("expected receipt")
        };
        // The approved mutation succeeds...
        let msg = handle(
            &rt,
            &h.server,
            envelope(
                IpcMessage::ServiceCall {
                    op: op.clone(),
                    stepup_approval: Some(approval_id.clone()),
                },
                Some(h.capability.clone()),
            ),
        );
        match service_outcome(msg) {
            ServiceOutcome::Ok { .. } => {}
            ServiceOutcome::Err { error } => panic!("approved mutation failed: {error}"),
        }
        // ...exactly once. Replay is denied.
        let replay = handle(
            &rt,
            &h.server,
            envelope(
                IpcMessage::ServiceCall {
                    op,
                    stepup_approval: Some(approval_id),
                },
                Some(h.capability.clone()),
            ),
        );
        match service_outcome(replay) {
            ServiceOutcome::Err { error } => {
                assert_eq!(error.code, "step_up_required");
                assert!(error.message.contains("unknown, already used"));
            }
            ServiceOutcome::Ok { .. } => panic!("approval replay must be denied"),
        }
    }

    #[test]
    fn step_up_wrong_password_denied_then_throttled() {
        let h = strict_harness();
        let rt = tokio::runtime::Runtime::new().unwrap();
        let op = VaultOp::EntryList;
        let deny = |msg: IpcMessage| match msg {
            IpcMessage::StepUpDenied { error, .. } => error,
            other => panic!("expected denial, got {}", variant_name(&other)),
        };
        for _ in 0..5 {
            let err = deny(handle(
                &rt,
                &h.server,
                envelope(
                    IpcMessage::StepUpAuthorize {
                        master_password: "wrong-password".to_string(),
                        op: op.clone(),
                    },
                    None,
                ),
            ));
            assert!(err.contains("verification failed"));
        }
        // The 6th attempt is throttled before touching the KDF.
        match handle(
            &rt,
            &h.server,
            envelope(
                IpcMessage::StepUpAuthorize {
                    master_password: "test_password".to_string(),
                    op,
                },
                None,
            ),
        ) {
            IpcMessage::StepUpDenied {
                error,
                retry_after_secs: Some(wait),
            } => {
                assert!(error.contains("too many failed"));
                assert!(wait >= 1);
            }
            IpcMessage::StepUpReceipt { .. } => panic!("must be throttled after 5 failures"),
            other => panic!("unexpected: {}", variant_name(&other)),
        }
    }

    #[test]
    fn step_up_approval_binds_to_the_exact_operation() {
        let h = strict_harness();
        let rt = tokio::runtime::Runtime::new().unwrap();
        let authorized = make_add_op("a");
        let substituted = make_add_op("SWAPPED");
        let IpcMessage::StepUpReceipt { approval_id, .. } = handle(
            &rt,
            &h.server,
            envelope(
                IpcMessage::StepUpAuthorize {
                    master_password: "test_password".to_string(),
                    op: authorized,
                },
                None,
            ),
        ) else {
            panic!("expected receipt")
        };
        let msg = handle(
            &rt,
            &h.server,
            envelope(
                IpcMessage::ServiceCall {
                    op: substituted,
                    stepup_approval: Some(approval_id),
                },
                Some(h.capability.clone()),
            ),
        );
        match service_outcome(msg) {
            ServiceOutcome::Err { error } => {
                assert_eq!(error.code, "step_up_required");
                assert!(error
                    .message
                    .contains("does not match this exact operation"));
            }
            ServiceOutcome::Ok { .. } => panic!("swapped target must be denied"),
        }
    }

    #[test]
    fn step_up_approval_is_connection_bound() {
        let h = strict_harness();
        let rt = tokio::runtime::Runtime::new().unwrap();
        let op = make_add_op("c");
        let IpcMessage::StepUpReceipt { approval_id, .. } = handle(
            &rt,
            &h.server,
            envelope(
                IpcMessage::StepUpAuthorize {
                    master_password: "test_password".to_string(),
                    op: op.clone(),
                },
                None,
            ),
        ) else {
            panic!("expected receipt")
        };
        // A different connection cannot use it...
        let msg = handle_on(
            &rt,
            &h.server,
            envelope(
                IpcMessage::ServiceCall {
                    op: op.clone(),
                    stepup_approval: Some(approval_id.clone()),
                },
                Some(h.capability.clone()),
            ),
            TEST_CONNECTION + 1,
        );
        match service_outcome(msg) {
            ServiceOutcome::Err { error } => {
                assert!(error.message.contains("different connection"))
            }
            ServiceOutcome::Ok { .. } => panic!("cross-connection approval must be denied"),
        }
        // ...but the minting connection still can.
        let ok = handle(
            &rt,
            &h.server,
            envelope(
                IpcMessage::ServiceCall {
                    op,
                    stepup_approval: Some(approval_id),
                },
                Some(h.capability.clone()),
            ),
        );
        assert!(matches!(service_outcome(ok), ServiceOutcome::Ok { .. }));
    }

    #[test]
    fn strict_profile_denies_browser_and_tool_write_surfaces() {
        let h = strict_harness();
        let rt = tokio::runtime::Runtime::new().unwrap();
        match handle(
            &rt,
            &h.server,
            envelope(
                IpcMessage::SaveCredential {
                    domain: "example.com".into(),
                    username: "u".into(),
                    password: "p".into(),
                    url: Some("https://example.com".into()),
                    save_trigger: None,
                },
                Some(h.capability.clone()),
            ),
        ) {
            IpcMessage::SaveCredentialResponse {
                success: false,
                error,
                ..
            } => {
                assert!(error.unwrap().contains("step_up_required"))
            }
            other => panic!("unexpected: {}", variant_name(&other)),
        }
        match handle(
            &rt,
            &h.server,
            envelope(
                IpcMessage::SaveSecret {
                    client_id: "tool".into(),
                    domain: "example.com".into(),
                    value: "v".into(),
                    purpose: None,
                },
                None,
            ),
        ) {
            IpcMessage::SaveSecretResponse {
                success: false,
                error,
                ..
            } => {
                assert!(error.unwrap().contains("step_up_required"))
            }
            other => panic!("unexpected: {}", variant_name(&other)),
        }
    }

    #[test]
    fn legacy_profile_keeps_unattended_mutations() {
        // Strict OFF (the desktop default until UI support): behavior is
        // unchanged — the regression guard for the rollout gate.
        let h = harness_with_vault();
        let rt = tokio::runtime::Runtime::new().unwrap();
        let msg = handle(
            &rt,
            &h.server,
            envelope(
                IpcMessage::ServiceCall {
                    op: make_add_op("legacy"),
                    stepup_approval: None,
                },
                Some(h.capability.clone()),
            ),
        );
        assert!(
            matches!(service_outcome(msg), ServiceOutcome::Ok { .. }),
            "strict-off must keep pre-SP-0 behavior"
        );
    }

    // ------------------------------------------------------------------
    // SP-0 adversarial review remediation tests (F1/F2a/F3/F9)
    // ------------------------------------------------------------------

    #[test]
    fn strict_profile_denies_bare_sync_now_message() {
        // Review F1: the bare IpcMessage::SyncNow (not the VaultOp) was an
        // ungated alias that applied remote mutations unattended.
        let h = strict_harness();
        let rt = tokio::runtime::Runtime::new().unwrap();
        match handle(&rt, &h.server, envelope(IpcMessage::SyncNow, None)) {
            IpcMessage::SyncNowResponse {
                success: false,
                error: Some(error),
                ..
            } => assert!(error.contains("step_up_required")),
            other => panic!("unexpected: {}", variant_name(&other)),
        }
    }

    #[test]
    fn strict_profile_denies_site_permission_revocation() {
        // Review F3: revocation is a policy mutation on a surface that
        // cannot step up.
        let h = strict_harness();
        let rt = tokio::runtime::Runtime::new().unwrap();
        match handle(
            &rt,
            &h.server,
            envelope(
                IpcMessage::RevokeSitePermission {
                    host: "example.com".into(),
                },
                Some(h.capability.clone()),
            ),
        ) {
            IpcMessage::RevokeSitePermissionResponse {
                success: false,
                error: Some(error),
                ..
            } => assert!(error.contains("step_up_required")),
            other => panic!("unexpected: {}", variant_name(&other)),
        }
    }

    #[test]
    fn strict_profile_denies_site_permission_grant() {
        // Reviewer-requested coverage: the GRANT direction's strict denial
        // (revocation already had one; the code existed since the base
        // commit — this pins it).
        let h = strict_harness();
        let rt = tokio::runtime::Runtime::new().unwrap();
        match handle(
            &rt,
            &h.server,
            envelope(
                IpcMessage::GrantSitePermission {
                    host: "example.com".into(),
                    allow_insecure: true,
                },
                Some(h.capability.clone()),
            ),
        ) {
            IpcMessage::GrantSitePermissionResponse {
                success: false,
                error: Some(error),
            } => assert!(error.contains("step_up_required")),
            other => panic!("unexpected: {}", variant_name(&other)),
        }
    }

    #[test]
    fn step_up_is_refused_while_vault_locked() {
        // Review F2: the full open() against a locked daemon vault would
        // install the process-global audit-key lease (breaking
        // cleared-on-lock) and run maintenance sweeps on a vault at rest.
        // Refused: unlock first.
        let tmp = TempDir::new().unwrap();
        let vault_path = tmp.path().join("vault.db");
        VaultManager::create(&vault_path, b"test_password").unwrap();
        // DaemonVault stays LOCKED (no unlock call).
        let daemon_vault = DaemonVault::new(Some(vault_path), 300).unwrap();
        let server = IpcServer::new_with_allowlist_path(
            tmp.path().join("locked.sock"),
            Arc::new(daemon_vault),
            "test-token".to_string(),
            tmp.path().join("allowlist.json"),
        )
        .with_require_stepup(true);
        let rt = tokio::runtime::Runtime::new().unwrap();
        match handle(
            &rt,
            &server,
            envelope(
                IpcMessage::StepUpAuthorize {
                    master_password: "test_password".to_string(),
                    op: VaultOp::EntryList,
                },
                None,
            ),
        ) {
            IpcMessage::StepUpDenied { error, .. } => {
                assert!(error.contains("locked"), "unexpected denial: {error}")
            }
            IpcMessage::StepUpReceipt { .. } => {
                panic!("step-up must be refused while the vault is locked")
            }
            other => panic!("unexpected: {}", variant_name(&other)),
        }
    }

    // ------------------------------------------------------------------
    // SP-1 / ADR-014: exact-entry service grants
    // ------------------------------------------------------------------

    fn sp1_harness() -> (GateHarness, std::path::PathBuf) {
        let tmp = TempDir::new().unwrap();
        let vault_path = tmp.path().join("vault.db");
        let password = b"test_password";
        let vm = VaultManager::create(&vault_path, password).unwrap();
        let _entry_id = vm
            .add_entry(&Entry {
                entry_id: None,
                title: "Svc".to_string(),
                username: "svc-user".to_string(),
                password: "svc-secret".to_string().into(),
                url: Some("https://svc.example".to_string()),
                notes: None,
                credential_type: crate::CredentialType::Password,
                created_at: Utc::now(),
                modified_at: Utc::now(),
                favorite: false,
            })
            .unwrap();
        drop(vm);
        let daemon_vault = DaemonVault::new(Some(vault_path), 300).unwrap();
        let rt = tokio::runtime::Runtime::new().unwrap();
        rt.block_on(async { daemon_vault.unlock(password).await })
            .unwrap();
        let grants = tmp.path().join("service-grants.json");
        let server = IpcServer::new_with_allowlist_path(
            tmp.path().join("sp1.sock"),
            Arc::new(daemon_vault),
            "test-token".to_string(),
            tmp.path().join("allowlist.json"),
        )
        .with_service_grants_path(grants.clone());
        (
            GateHarness {
                _tmp: tmp,
                server,
                capability: String::new(),
                permissions_path: std::path::PathBuf::new(),
            },
            grants,
        )
    }

    fn report_value(msg: IpcMessage) -> serde_json::Value {
        match msg {
            IpcMessage::ServiceResult {
                outcome:
                    ServiceOutcome::Ok {
                        result: VaultOpResult::Report(value),
                    },
            } => value,
            IpcMessage::ServiceResult {
                outcome: ServiceOutcome::Err { error },
            } => panic!("service error: {error}"),
            other => panic!("unexpected: {}", variant_name(&other)),
        }
    }

    #[test]
    fn service_grant_lifecycle_end_to_end() {
        let (h, _grants) = sp1_harness();
        let rt = tokio::runtime::Runtime::new().unwrap();

        // 1. Mint — grant administration needs a step-up on EVERY profile
        //    (review F2). First prove the unapproved call is denied, then
        //    approve and retry.
        let create_op = VaultOp::ServiceGrantCreate {
            client_id: "sandesha-svc".into(),
            entry_id: 1,
            fields: vec!["password".into()],
            expires_at: None,
        };
        let unapproved = handle(
            &rt,
            &h.server,
            envelope(
                IpcMessage::ServiceCall {
                    op: create_op.clone(),
                    stepup_approval: None,
                },
                None,
            ),
        );
        match unapproved {
            IpcMessage::ServiceResult {
                outcome: ServiceOutcome::Err { error },
            } => assert_eq!(error.code, "step_up_required"),
            other => panic!(
                "unapproved grant create must be step-up denied: {}",
                variant_name(&other)
            ),
        }
        let IpcMessage::StepUpReceipt { approval_id, .. } = handle(
            &rt,
            &h.server,
            envelope(
                IpcMessage::StepUpAuthorize {
                    master_password: "test_password".to_string(),
                    op: create_op.clone(),
                },
                None,
            ),
        ) else {
            panic!("expected step-up receipt")
        };
        let created = handle(
            &rt,
            &h.server,
            envelope(
                IpcMessage::ServiceCall {
                    op: create_op,
                    stepup_approval: Some(approval_id),
                },
                None,
            ),
        );
        let create_report = report_value(created);
        assert_eq!(create_report["status"], "created");
        let token = create_report["client_token"].as_str().unwrap().to_string();
        let grant_id = create_report["grant_id"]
            .as_str()
            .unwrap_or_default()
            .to_string();
        assert!(!grant_id.is_empty(), "mint report must carry grant_id");

        // 2. Retrieve: exact entry + field + token -> the value.
        let got = handle(
            &rt,
            &h.server,
            envelope(
                IpcMessage::ServiceCall {
                    op: VaultOp::ServiceGetSecret {
                        client_id: "sandesha-svc".into(),
                        entry_id: 1,
                        field: "password".into(),
                        token: token.clone(),
                    },
                    stepup_approval: None,
                },
                None,
            ),
        );
        let report = report_value(got);
        assert_eq!(report["status"], "authorized");
        assert_eq!(report["value"].as_str(), Some("svc-secret"));

        // 3. Un-granted probing: wrong entry id -> denied (never
        //    not_found before grant validation).
        let probe = handle(
            &rt,
            &h.server,
            envelope(
                IpcMessage::ServiceCall {
                    op: VaultOp::ServiceGetSecret {
                        client_id: "sandesha-svc".into(),
                        entry_id: 99,
                        field: "password".into(),
                        token: token.clone(),
                    },
                    stepup_approval: None,
                },
                None,
            ),
        );
        assert_eq!(report_value(probe)["status"], "denied");

        // 4. Revoke (admin op — step-up), then retrieval is denied.
        let revoke_op = VaultOp::ServiceGrantRevoke { grant_id };
        let IpcMessage::StepUpReceipt {
            approval_id: revoke_approval,
            ..
        } = handle(
            &rt,
            &h.server,
            envelope(
                IpcMessage::StepUpAuthorize {
                    master_password: "test_password".to_string(),
                    op: revoke_op.clone(),
                },
                None,
            ),
        )
        else {
            panic!("expected step-up receipt for revoke")
        };
        let revoked = handle(
            &rt,
            &h.server,
            envelope(
                IpcMessage::ServiceCall {
                    op: revoke_op,
                    stepup_approval: Some(revoke_approval),
                },
                None,
            ),
        );
        assert_eq!(report_value(revoked)["status"], "revoked");
        let after = handle(
            &rt,
            &h.server,
            envelope(
                IpcMessage::ServiceCall {
                    op: VaultOp::ServiceGetSecret {
                        client_id: "sandesha-svc".into(),
                        entry_id: 1,
                        field: "password".into(),
                        token,
                    },
                    stepup_approval: None,
                },
                None,
            ),
        );
        assert_eq!(report_value(after)["status"], "denied");
    }

    #[test]
    fn grant_admin_ops_are_step_up_class() {
        // SP-1 admin ops join the SP-0 classification (exhaustive match
        // forces this; pinned here for the spec).
        use sentinelpass_protocol::VaultOp as O;
        assert!(O::ServiceGrantCreate {
            client_id: "x".into(),
            entry_id: 1,
            fields: vec![],
            expires_at: None,
        }
        .requires_admin_step_up());
        assert!(O::ServiceGrantRevoke {
            grant_id: "g".into()
        }
        .requires_admin_step_up());
        assert!(!O::ServiceGetSecret {
            client_id: "x".into(),
            entry_id: 1,
            field: "password".into(),
            token: "t".into(),
        }
        .requires_admin_step_up());
    }

    #[test]
    fn tampered_grant_store_fails_closed() {
        let (h, grants) = sp1_harness();
        std::fs::write(&grants, b"{\"grants\": {}, \"evil\": 1}").unwrap();
        let rt = tokio::runtime::Runtime::new().unwrap();
        let got = handle(
            &rt,
            &h.server,
            envelope(
                IpcMessage::ServiceCall {
                    op: VaultOp::ServiceGetSecret {
                        client_id: "x".into(),
                        entry_id: 1,
                        field: "password".into(),
                        token: "sps_anything".into(),
                    },
                    stepup_approval: None,
                },
                None,
            ),
        );
        let report = report_value(got);
        assert_eq!(
            report["status"], "denied",
            "tampered store must fail closed, got: {report}"
        );
    }
}
