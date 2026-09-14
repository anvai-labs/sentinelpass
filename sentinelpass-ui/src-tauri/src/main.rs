// Prevents additional console window on Windows in release builds
#![cfg_attr(not(debug_assertions), windows_subsystem = "windows")]

use sentinelpass_core::daemon::service::{
    entity_from_wire, entry_from_wire, entry_summary_from_wire, entry_to_wire, LiveVaultService,
    VaultApplicationService,
};
use sentinelpass_core::daemon::{default_ipc_socket_path, IpcClient, IpcMessage};
use sentinelpass_core::{
    parse_otpauth_uri, Entity, Entry, EntrySummary, RegistryOverview, TotpAlgorithm, VaultManager,
};
use sentinelpass_protocol::service::{ServiceError, VaultOp, VaultOpResult};
use serde::{Deserialize, Serialize};
use std::path::PathBuf;
use std::process::{Child, Command, Stdio};
use std::sync::{Arc, Mutex, OnceLock};
use tauri::{Manager, State};

mod clipboard_secret;

// Application state
struct AppState {
    /// Compatibility window ONLY (ADR-007 migration): with
    /// SENTINELPASS_ALLOW_DIRECT_VAULT=1 the UI keeps a direct manager.
    /// IPC-only mode (default) never populates this.
    vault_manager: Arc<Mutex<Option<VaultManager>>>,
    daemon_process: Arc<Mutex<Option<Child>>>,
    clipboard_tracker: Arc<Mutex<clipboard_secret::ClipboardSecretTracker>>,
    /// Held while the compat direct manager is live (stage-3 review F1):
    /// the UI's direct mode is lock-guarded exactly like the CLI's — a live
    /// daemon owns the vault and direct mode refuses.
    direct_lock: Arc<Mutex<Option<sentinelpass_core::daemon::MaintenanceLockGuard>>>,
}

/// FLAGGED direct-vault compatibility mode (ADR-007 migration window;
/// removed in 1.0). Not silent: announced wherever it takes effect, and the
/// exclusive maintenance lock is held for the direct manager's lifetime.
fn direct_vault_mode() -> bool {
    std::env::var("SENTINELPASS_ALLOW_DIRECT_VAULT")
        .map(|v| v == "1")
        .unwrap_or(false)
}

/// Announce compat direct mode (stage-3 review F1: never silent).
fn announce_direct_mode() {
    eprintln!(
        "WARNING: SENTINELPASS_ALLOW_DIRECT_VAULT=1 — DIRECT vault access \
         (compatibility window): this app opens and writes the vault itself, \
         bypassing daemon authority (ADR-007). Temporary and announced on every use."
    );
}

/// Take and hold the exclusive maintenance lock for the direct manager's
/// lifetime; refuses (fail-closed) while a daemon owns the vault.
fn acquire_ui_direct_lock(state: &AppState) -> Result<(), String> {
    let mut slot = state.direct_lock.lock().unwrap();
    if slot.is_some() {
        return Ok(());
    }
    let guard =
        sentinelpass_core::daemon::try_acquire(&sentinelpass_core::get_default_vault_path())
            .map_err(|e| format!("Direct mode refused: {} (a daemon owns the vault)", e))?;
    *slot = Some(guard);
    Ok(())
}

/// Execute one application-service op (WBS-502): through the daemon by
/// default; through the compatibility local manager when direct mode is on
/// and a manager is loaded.
async fn service_call(state: &AppState, op: VaultOp) -> Result<VaultOpResult, String> {
    if direct_vault_mode() {
        let guard = state.vault_manager.lock().unwrap();
        if let Some(vault) = guard.as_ref() {
            let service = LiveVaultService::new(vault);
            return service
                .execute(&op)
                .map_err(|e: ServiceError| format!("[{}] {}", e.code, e.message));
        }
        // No local manager: fall through to the daemon path.
    }

    ensure_daemon_running(state).await?;
    let client = IpcClient::new(default_ipc_socket_path())
        .map_err(|e| format!("Daemon unavailable: {}", e))?;
    client
        .call_service(op)
        .await
        .map_err(|e| format!("Failed to communicate with daemon: {}", e))
}

/// Map a wire entry summary to the core type for the frontend.
fn to_entry_summary(result: VaultOpResult) -> Result<Vec<EntrySummary>, String> {
    match result {
        VaultOpResult::EntryList(list) => list
            .iter()
            .map(entry_summary_from_wire)
            .collect::<Result<Vec<_>, _>>()
            .map_err(|e| e.to_string()),
        other => Err(format!("unexpected daemon response: {other:?}")),
    }
}

static RESOURCE_DIR: OnceLock<PathBuf> = OnceLock::new();

#[derive(Serialize, Deserialize)]
pub struct DaemonStatus {
    available: bool,
    unlocked: bool,
    message: Option<String>,
}

fn daemon_binary_name() -> &'static str {
    if cfg!(windows) {
        "sentinelpass-daemon.exe"
    } else {
        "sentinelpass-daemon"
    }
}

fn host_binary_name() -> &'static str {
    if cfg!(windows) {
        "sentinelpass-host.exe"
    } else {
        "sentinelpass-host"
    }
}

fn resolve_host_binary_path() -> PathBuf {
    let binary_name = host_binary_name();
    let mut candidates = Vec::new();

    if let Ok(explicit_path) = std::env::var("SENTINELPASS_HOST_PATH") {
        let trimmed = explicit_path.trim();
        if !trimmed.is_empty() {
            candidates.push(PathBuf::from(trimmed));
        }
    }

    if let Some(resource_dir) = RESOURCE_DIR.get() {
        candidates.push(
            resource_dir
                .join("src-tauri")
                .join("resources")
                .join("bin")
                .join(binary_name),
        );
        candidates.push(resource_dir.join("bin").join(binary_name));
        candidates.push(resource_dir.join(binary_name));
    }

    if let Ok(current_exe) = std::env::current_exe() {
        if let Some(exe_dir) = current_exe.parent() {
            candidates.push(exe_dir.join(binary_name));
            candidates.push(exe_dir.join("resources").join("bin").join(binary_name));
            candidates.push(
                exe_dir
                    .join("..")
                    .join("Resources")
                    .join("bin")
                    .join(binary_name),
            );
        }
    }

    for candidate in candidates {
        if candidate.exists() {
            return candidate;
        }
    }

    PathBuf::from(binary_name)
}

fn resolve_daemon_binary_path() -> std::path::PathBuf {
    let binary_name = daemon_binary_name();
    let mut candidates = Vec::new();

    if let Ok(explicit_path) = std::env::var("SENTINELPASS_DAEMON_PATH") {
        let trimmed = explicit_path.trim();
        if !trimmed.is_empty() {
            candidates.push(PathBuf::from(trimmed));
        }
    }

    if let Some(resource_dir) = RESOURCE_DIR.get() {
        candidates.push(
            resource_dir
                .join("src-tauri")
                .join("resources")
                .join("bin")
                .join(binary_name),
        );
        candidates.push(resource_dir.join("bin").join(binary_name));
        candidates.push(resource_dir.join(binary_name));
    }

    if let Ok(current_exe) = std::env::current_exe() {
        if let Some(exe_dir) = current_exe.parent() {
            candidates.push(exe_dir.join(binary_name));
            candidates.push(exe_dir.join("resources").join("bin").join(binary_name));
            candidates.push(
                exe_dir
                    .join("..")
                    .join("Resources")
                    .join("bin")
                    .join(binary_name),
            );
        }
    }

    for candidate in candidates {
        if candidate.exists() {
            return candidate;
        }
    }

    std::path::PathBuf::from(binary_name)
}

fn spawn_daemon_process() -> std::result::Result<Child, String> {
    let daemon_binary = resolve_daemon_binary_path();
    unlock_debug_log(&format!(
        "spawn_daemon_process: starting {} --start-locked",
        daemon_binary.display()
    ));

    let mut command = Command::new(&daemon_binary);
    command
        .arg("--start-locked")
        .stdin(Stdio::null())
        .stdout(Stdio::null())
        .stderr(Stdio::null());

    #[cfg(windows)]
    {
        use std::os::windows::process::CommandExt;
        const CREATE_NO_WINDOW: u32 = 0x0800_0000;
        command.creation_flags(CREATE_NO_WINDOW);
    }

    command
        .spawn()
        .map_err(|error| format!("Failed to start {}: {}", daemon_binary.display(), error))
}

fn reap_managed_daemon_if_exited(state: &AppState) {
    let mut daemon_process = state.daemon_process.lock().unwrap();
    if let Some(child) = daemon_process.as_mut() {
        match child.try_wait() {
            Ok(Some(status)) => {
                unlock_debug_log(&format!(
                    "reap_managed_daemon_if_exited: daemon exited with status {}",
                    status
                ));
                *daemon_process = None;
            }
            Ok(None) => {}
            Err(error) => {
                unlock_debug_log(&format!(
                    "reap_managed_daemon_if_exited: failed to poll daemon status: {}",
                    error
                ));
                *daemon_process = None;
            }
        }
    }
}

async fn wait_for_daemon_ready(timeout: std::time::Duration) -> std::result::Result<(), String> {
    let deadline = tokio::time::Instant::now() + timeout;

    loop {
        match send_daemon_message(IpcMessage::CheckVault).await {
            Ok(IpcMessage::VaultStatusResponse { .. }) => {
                unlock_debug_log("wait_for_daemon_ready: daemon IPC ready");
                return Ok(());
            }
            Ok(other) => {
                unlock_debug_log(&format!(
                    "wait_for_daemon_ready: unexpected IPC response: {:?}",
                    other
                ));
            }
            Err(error) => {
                unlock_debug_log(&format!(
                    "wait_for_daemon_ready: daemon not ready yet: {}",
                    error
                ));
            }
        }

        if tokio::time::Instant::now() >= deadline {
            return Err("Daemon started but IPC did not become ready in time".to_string());
        }

        tokio::time::sleep(std::time::Duration::from_millis(150)).await;
    }
}

async fn ensure_daemon_running(state: &AppState) -> std::result::Result<(), String> {
    if matches!(
        send_daemon_message(IpcMessage::CheckVault).await,
        Ok(IpcMessage::VaultStatusResponse { .. })
    ) {
        return Ok(());
    }

    reap_managed_daemon_if_exited(state);

    let should_spawn = {
        let daemon_process = state.daemon_process.lock().unwrap();
        daemon_process.is_none()
    };

    if should_spawn {
        let child = spawn_daemon_process()?;
        let pid = child.id();
        {
            let mut daemon_process = state.daemon_process.lock().unwrap();
            *daemon_process = Some(child);
        }
        unlock_debug_log(&format!(
            "ensure_daemon_running: started managed daemon process pid={}",
            pid
        ));
    } else {
        unlock_debug_log("ensure_daemon_running: managed daemon already running");
    }

    wait_for_daemon_ready(std::time::Duration::from_secs(5)).await
}

fn stop_managed_daemon(state: &AppState) {
    let mut daemon_process = state.daemon_process.lock().unwrap();
    if let Some(child) = daemon_process.as_mut() {
        unlock_debug_log("stop_managed_daemon: stopping managed daemon process");
        let _ = child.kill();
        let _ = child.wait();
    }
    *daemon_process = None;
}

async fn send_daemon_message(message: IpcMessage) -> std::result::Result<IpcMessage, String> {
    unlock_debug_log("send_daemon_message: preparing IPC client");
    let socket_path = default_ipc_socket_path();
    let ipc_client =
        IpcClient::new(socket_path).map_err(|e| format!("Daemon unavailable: {}", e))?;
    let response = ipc_client
        .send(message)
        .await
        .map_err(|e| format!("Failed to communicate with daemon: {}", e))?;
    // WBS-708: never serialize the full response — IpcMessage variants carry
    // plaintext credentials, and this string went to a debug log file.
    unlock_debug_log("send_daemon_message: response received");
    Ok(response)
}

async fn unlock_daemon_with_password(master_password: &str) -> std::result::Result<(), String> {
    unlock_debug_log("unlock_daemon_with_password: requesting daemon unlock");
    let response = send_daemon_message(IpcMessage::UnlockVault {
        master_password: master_password.to_string(),
    })
    .await?;

    match response {
        IpcMessage::UnlockVaultResponse { success, error: _ } if success => Ok(()),
        IpcMessage::UnlockVaultResponse {
            success: false,
            error,
        } => Err(error.unwrap_or_else(|| "Daemon unlock failed".to_string())),
        IpcMessage::VaultStatusResponse { unlocked, .. } if unlocked => Ok(()),
        IpcMessage::VaultStatusResponse {
            unlocked: false, ..
        } => Err("Daemon remains locked".to_string()),
        _ => Err("Unexpected daemon response while unlocking".to_string()),
    }
}

async fn unlock_daemon_with_biometric(prompt_reason: &str) -> std::result::Result<(), String> {
    unlock_debug_log("unlock_daemon_with_biometric: requesting daemon biometric unlock");
    let response = send_daemon_message(IpcMessage::UnlockVaultBiometric {
        prompt_reason: Some(prompt_reason.to_string()),
    })
    .await?;

    match response {
        IpcMessage::UnlockVaultResponse { success, error: _ } if success => Ok(()),
        IpcMessage::UnlockVaultResponse {
            success: false,
            error,
        } => Err(error.unwrap_or_else(|| "Daemon biometric unlock failed".to_string())),
        IpcMessage::VaultStatusResponse { unlocked, .. } if unlocked => Ok(()),
        IpcMessage::VaultStatusResponse {
            unlocked: false, ..
        } => Err("Daemon remains locked".to_string()),
        _ => Err("Unexpected daemon response while unlocking with biometric".to_string()),
    }
}

async fn fetch_daemon_status() -> DaemonStatus {
    unlock_debug_log("fetch_daemon_status: querying daemon lock state");
    match send_daemon_message(IpcMessage::CheckVault).await {
        Ok(IpcMessage::VaultStatusResponse { unlocked, .. }) => DaemonStatus {
            available: true,
            unlocked,
            message: None,
        },
        Ok(_) => DaemonStatus {
            available: true,
            unlocked: false,
            message: Some("Unexpected daemon response".to_string()),
        },
        Err(error) => DaemonStatus {
            available: false,
            unlocked: false,
            message: Some(error),
        },
    }
}

/// Unlock-flow debug logger (WBS-708).
///
/// Debug builds only: gated by `SENTINELPASS_DEBUG_UNLOCK=1` it appends the
/// unlock lifecycle (paths, PIDs, IPC status) to `ui_unlock_debug.log` in the
/// config directory. Release builds compile this to a no-op — the log file is
/// never created, the env var is never read, and no unlock-flow instrumentation
/// ships (this file also has a redaction rule at the `send_daemon_message`
/// call site: IPC responses are never serialized into the log, since
/// `IpcMessage` variants can carry plaintext credentials).
#[cfg(debug_assertions)]
fn unlock_debug_log(message: &str) {
    use std::io::Write as _;
    use std::time::{SystemTime, UNIX_EPOCH};

    if std::env::var("SENTINELPASS_DEBUG_UNLOCK").unwrap_or_default() != "1" {
        return;
    }

    let ts = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(0);
    let line = format!("[{}] {}\n", ts, message);

    eprintln!("[SentinelPass UI Debug] {}", message);

    if let Ok(config_dir) = sentinelpass_core::ensure_config_dir() {
        let path = config_dir.join("ui_unlock_debug.log");
        if let Ok(mut file) = std::fs::OpenOptions::new()
            .create(true)
            .append(true)
            .open(path)
        {
            let _ = file.write_all(line.as_bytes());
            return;
        }
    }

    // Fallback path so debug logs are still available even if config directory writes fail.
    if let Ok(temp_dir) = std::env::var("TEMP") {
        let fallback = std::path::PathBuf::from(temp_dir).join("sentinelpass_ui_unlock_debug.log");
        if let Ok(mut file) = std::fs::OpenOptions::new()
            .create(true)
            .append(true)
            .open(fallback)
        {
            let _ = file.write_all(line.as_bytes());
        }
    }
}

/// Release stub: unlock-flow debug instrumentation does not ship (WBS-708).
#[cfg(not(debug_assertions))]
fn unlock_debug_log(_message: &str) {}

// Stable Chrome extension ID derived from the RSA public key in
// browser-extension/chrome/manifest.json.  Keep these in sync.
const CHROME_EXTENSION_ID: &str = "nophfgfiiohedlodfeepjoioljbhggdd";
const NATIVE_HOST_NAME: &str = "com.passwordmanager.host";
const FIREFOX_EXTENSION_ID: &str = "sentinelpass@localhost";

/// Directories where Chrome/Chromium/Firefox look for native messaging host
/// manifests on the current platform.
fn native_messaging_dirs() -> Vec<(&'static str, PathBuf)> {
    let mut dirs = Vec::new();

    #[cfg(target_os = "macos")]
    {
        if let Some(home) = dirs::home_dir() {
            let lib = home.join("Library").join("Application Support");
            dirs.push((
                "chrome",
                lib.join("Google")
                    .join("Chrome")
                    .join("NativeMessagingHosts"),
            ));
            dirs.push((
                "chromium",
                lib.join("Chromium").join("NativeMessagingHosts"),
            ));
            dirs.push(("firefox", lib.join("Mozilla").join("NativeMessagingHosts")));
        }
    }

    #[cfg(all(unix, not(target_os = "macos")))]
    {
        if let Some(home) = dirs::home_dir() {
            dirs.push((
                "chrome",
                home.join(".config")
                    .join("google-chrome")
                    .join("NativeMessagingHosts"),
            ));
            dirs.push((
                "chromium",
                home.join(".config")
                    .join("chromium")
                    .join("NativeMessagingHosts"),
            ));
            dirs.push((
                "firefox",
                home.join(".mozilla").join("native-messaging-hosts"),
            ));
        }
    }

    #[cfg(target_os = "windows")]
    {
        // On Windows the manifest is written to %LOCALAPPDATA%\SentinelPass\ and
        // a registry key points to the file.  We use "chrome" / "firefox" labels
        // so the caller can branch on the browser type.
        if let Ok(local) = std::env::var("LOCALAPPDATA") {
            let base = PathBuf::from(local).join("SentinelPass");
            dirs.push(("chrome", base.clone()));
            dirs.push(("firefox", base));
        }
    }

    dirs
}

fn build_chrome_manifest(host_path: &std::path::Path) -> String {
    serde_json::json!({
        "name": NATIVE_HOST_NAME,
        "description": "SentinelPass Native Messaging Host",
        "path": host_path.to_string_lossy(),
        "type": "stdio",
        "allowed_origins": [
            format!("chrome-extension://{}/", CHROME_EXTENSION_ID)
        ]
    })
    .to_string()
}

fn build_firefox_manifest(host_path: &std::path::Path) -> String {
    serde_json::json!({
        "name": NATIVE_HOST_NAME,
        "description": "SentinelPass Native Messaging Host",
        "path": host_path.to_string_lossy(),
        "type": "stdio",
        "allowed_extensions": [FIREFOX_EXTENSION_ID]
    })
    .to_string()
}

fn write_manifest(dir: &std::path::Path, filename: &str, contents: &str) -> Result<(), String> {
    std::fs::create_dir_all(dir)
        .map_err(|e| format!("Failed to create dir {}: {}", dir.display(), e))?;
    let path = dir.join(filename);
    std::fs::write(&path, contents)
        .map_err(|e| format!("Failed to write {}: {}", path.display(), e))?;
    unlock_debug_log(&format!("write_manifest: wrote {}", path.display()));
    Ok(())
}

/// Idempotent — safe to call on every launch.  Writes native messaging host
/// manifests (and on Windows, registry entries) for Chrome, Chromium, and
/// Firefox so the browser extension can locate `sentinelpass-host`.
fn ensure_native_host_registered() -> Result<(), String> {
    let host_path = resolve_host_binary_path();
    let host_path = if host_path.exists() {
        std::fs::canonicalize(&host_path).unwrap_or(host_path)
    } else {
        host_path
    };

    unlock_debug_log(&format!(
        "ensure_native_host_registered: host binary = {}",
        host_path.display()
    ));

    let manifest_name = format!("{}.json", NATIVE_HOST_NAME);
    let chrome_manifest = build_chrome_manifest(&host_path);
    let firefox_manifest = build_firefox_manifest(&host_path);

    let mut errors = Vec::new();

    for (browser, dir) in native_messaging_dirs() {
        let result = if browser == "firefox" {
            // On non-Windows platforms Firefox uses the same directory layout.
            // On Windows the manifest file gets a different name so we can
            // write both Chrome and Firefox manifests into the same folder.
            #[cfg(target_os = "windows")]
            {
                let ff_name = format!("{}.firefox.json", NATIVE_HOST_NAME);
                write_manifest(&dir, &ff_name, &firefox_manifest)
            }
            #[cfg(not(target_os = "windows"))]
            {
                write_manifest(&dir, &manifest_name, &firefox_manifest)
            }
        } else {
            write_manifest(&dir, &manifest_name, &chrome_manifest)
        };

        if let Err(e) = result {
            errors.push(e);
        }
    }

    // Windows: create registry entries pointing to the manifest files.
    #[cfg(target_os = "windows")]
    {
        if let Ok(local) = std::env::var("LOCALAPPDATA") {
            let base = PathBuf::from(&local).join("SentinelPass");
            let chrome_json = base.join(&manifest_name);
            let ff_json = base.join(format!("{}.firefox.json", NATIVE_HOST_NAME));

            let reg_entries = [
                (
                    format!(
                        r"HKCU\Software\Google\Chrome\NativeMessagingHosts\{}",
                        NATIVE_HOST_NAME
                    ),
                    chrome_json.to_string_lossy().to_string(),
                ),
                (
                    format!(
                        r"HKCU\Software\Chromium\NativeMessagingHosts\{}",
                        NATIVE_HOST_NAME
                    ),
                    chrome_json.to_string_lossy().to_string(),
                ),
                (
                    format!(
                        r"HKCU\Software\Mozilla\NativeMessagingHosts\{}",
                        NATIVE_HOST_NAME
                    ),
                    ff_json.to_string_lossy().to_string(),
                ),
            ];

            for (key, value) in &reg_entries {
                let status = Command::new("reg")
                    .args(["add", key, "/ve", "/t", "REG_SZ", "/d", value, "/f"])
                    .stdout(Stdio::null())
                    .stderr(Stdio::null())
                    .status();
                match status {
                    Ok(s) if s.success() => {
                        unlock_debug_log(&format!(
                            "ensure_native_host_registered: registry set {}",
                            key
                        ));
                    }
                    Ok(s) => {
                        errors.push(format!("reg add {} exited with {}", key, s));
                    }
                    Err(e) => {
                        errors.push(format!("reg add {} failed: {}", key, e));
                    }
                }
            }
        }
    }

    if errors.is_empty() {
        unlock_debug_log("ensure_native_host_registered: all manifests written successfully");
        Ok(())
    } else {
        let combined = errors.join("; ");
        unlock_debug_log(&format!(
            "ensure_native_host_registered: partial failures: {}",
            combined
        ));
        Err(combined)
    }
}

// Command: Create vault (WBS-502): through the daemon's maintenance
// bootstrap (VaultCreate) by default; direct with the exclusive lock in
// FLAGGED compat mode (stage-2 review F2 closure).
#[tauri::command]
async fn create_vault(
    master_password: String,
    state: State<'_, AppState>,
) -> Result<String, String> {
    let vault_path = sentinelpass_core::get_default_vault_path();

    // Check if vault already exists
    if vault_path.exists() {
        return Err("Vault already exists".to_string());
    }

    // Ensure data directory exists
    sentinelpass_core::ensure_data_dir()
        .map_err(|e| format!("Failed to create data directory: {}", e))?;

    if direct_vault_mode() {
        // Compatibility window: exclusive, lock-guarded local creation.
        announce_direct_mode();
        acquire_ui_direct_lock(&state)?;
        let vault = VaultManager::create(&vault_path, master_password.as_bytes())
            .map_err(|e| format!("Failed to create vault: {}", e))?;
        *state.vault_manager.lock().unwrap() = Some(vault);
        return Ok("Vault created successfully".to_string());
    }

    // Daemon authority: the daemon (maintenance mode when no vault exists)
    // creates the vault and transitions to live with it unlocked.
    ensure_daemon_running(&state).await?;
    let result = service_call(
        &state,
        VaultOp::VaultCreate {
            master_password: master_password.into(),
        },
    )
    .await?;
    match result {
        VaultOpResult::Status(status) if status.unlocked => {
            unlock_debug_log("create_vault: daemon bootstrap create success");
            Ok("Vault created successfully".to_string())
        }
        other => Err(format!("Unexpected daemon response: {other:?}")),
    }
}

// Command: Unlock vault (WBS-502): unlock the DAEMON — it owns the only
// live DEK. Local open only in FLAGGED compat mode.
#[tauri::command]
async fn unlock_vault(
    master_password: String,
    state: State<'_, AppState>,
) -> Result<String, String> {
    unlock_debug_log("unlock_vault: command called");
    let vault_path = sentinelpass_core::get_default_vault_path();
    unlock_debug_log(&format!(
        "unlock_vault: vault_path={} exists={}",
        vault_path.display(),
        vault_path.exists()
    ));

    if !vault_path.exists() {
        return Err("No vault found".to_string());
    }

    if direct_vault_mode() {
        // Compatibility window: old local-open behavior + best-effort daemon.
        announce_direct_mode();
        acquire_ui_direct_lock(&state)?;
        return match VaultManager::open(&vault_path, master_password.as_bytes()) {
            Ok(vault) => {
                *state.vault_manager.lock().unwrap() = Some(vault);
                match ensure_daemon_running(&state).await {
                    Ok(_) => match unlock_daemon_with_password(&master_password).await {
                        Ok(_) => Ok("Vault unlocked successfully".to_string()),
                        Err(error) => Ok(format!(
                            "Vault unlocked in app, but daemon unlock failed: {}. \
                             Browser integration will stay locked until daemon is unlocked.",
                            error
                        )),
                    },
                    Err(error) => Ok(format!(
                        "Vault unlocked in app, but daemon is unavailable: {}. \
                         Browser integration will stay unavailable until daemon starts.",
                        error
                    )),
                }
            }
            Err(sentinelpass_core::PasswordManagerError::LockedOut(remaining_seconds)) => {
                Err(format!(
                    "Vault is temporarily locked after failed attempts. Try again in {} seconds.",
                    remaining_seconds
                ))
            }
            Err(e) => Err(format!("Failed to unlock vault: {}", e)),
        };
    }

    // Daemon authority: ensure the daemon is up (it may be locked), then ask
    // it to unlock. The daemon's open() enforces the lockout policy.
    ensure_daemon_running(&state).await?;
    // Stage-3 review F4: an already-unlocked daemon accepts any password —
    // surface that honestly instead of a false validation success.
    if let Ok(IpcMessage::VaultStatusResponse { unlocked: true, .. }) =
        send_daemon_message(IpcMessage::CheckVault).await
    {
        return Ok("Daemon was already unlocked; the password was not verified.".to_string());
    }
    match unlock_daemon_with_password(&master_password).await {
        Ok(_) => {
            unlock_debug_log("unlock_vault: daemon unlock success");
            Ok("Vault unlocked successfully".to_string())
        }
        Err(error) => {
            unlock_debug_log(&format!("unlock_vault: daemon unlock failed: {}", error));
            if error.contains("locked out") || error.contains("failed attempts") {
                Err(error)
            } else {
                Err(format!("Failed to unlock vault: {}", error))
            }
        }
    }
}

// Command: Unlock vault via biometric authentication
#[tauri::command]
async fn unlock_vault_biometric(state: State<'_, AppState>) -> Result<String, String> {
    unlock_debug_log("unlock_vault_biometric: command called");
    let vault_path = sentinelpass_core::get_default_vault_path();

    if !vault_path.exists() {
        return Err("No vault found".to_string());
    }

    if direct_vault_mode() {
        // Compatibility window: local biometric open + best-effort daemon.
        announce_direct_mode();
        acquire_ui_direct_lock(&state)?;
        return match VaultManager::open_with_biometric(&vault_path, "Unlock SentinelPass vault") {
            Ok(vault) => {
                *state.vault_manager.lock().unwrap() = Some(vault);
                match ensure_daemon_running(&state).await {
                    Ok(_) => {
                        match unlock_daemon_with_biometric("Unlock SentinelPass daemon").await {
                            Ok(_) => Ok("Vault unlocked successfully via biometric authentication"
                                .to_string()),
                            Err(error) => Ok(format!(
                                "Vault unlocked in app, but daemon unlock failed: {}. \
                                 Browser integration may still require unlock.",
                                error
                            )),
                        }
                    }
                    Err(error) => Ok(format!(
                        "Vault unlocked in app, but daemon is unavailable: {}. \
                         Browser integration may remain unavailable.",
                        error
                    )),
                }
            }
            Err(e) => Err(format!("Failed biometric unlock: {}", e)),
        };
    }

    // Daemon authority: the platform biometric prompt runs in the daemon,
    // which owns the platform wrapper slot.
    ensure_daemon_running(&state).await?;
    match unlock_daemon_with_biometric("Unlock SentinelPass vault").await {
        Ok(_) => {
            unlock_debug_log("unlock_vault_biometric: daemon biometric unlock success");
            Ok("Vault unlocked successfully via biometric authentication".to_string())
        }
        Err(error) => Err(format!("Failed biometric unlock: {}", error)),
    }
}

// Command: Get biometric capability/configuration status. The service op is
// valid while the daemon is LOCKED; the local metadata read is only a
// daemon-unavailable fallback (read-only, no DEK).
#[tauri::command]
async fn biometric_status(state: State<'_, AppState>) -> Result<BiometricStatus, String> {
    match service_call(&state, VaultOp::BiometricStatusGet).await {
        Ok(VaultOpResult::Biometric(status)) => Ok(BiometricStatus {
            method_name: status.method_name,
            available: status.available,
            enrolled: status.enrolled,
            configured: status.configured,
        }),
        Ok(other) => Err(format!("unexpected daemon response: {other:?}")),
        Err(_) => {
            let vault_path = sentinelpass_core::get_default_vault_path();
            let configured = if vault_path.exists() {
                VaultManager::is_biometric_unlock_enabled(&vault_path).map_err(|e| e.to_string())?
            } else {
                false
            };
            Ok(BiometricStatus {
                method_name: sentinelpass_core::BiometricManager::get_method_name().to_string(),
                available: sentinelpass_core::BiometricManager::is_available(),
                enrolled: sentinelpass_core::BiometricManager::is_enrolled(),
                configured,
            })
        }
    }
}

// Command: Enable biometric unlock for this vault (WBS-502: via service op;
// the daemon validates the password against its unlocked manager).
#[tauri::command]
async fn enable_biometric_unlock(
    master_password: String,
    state: State<'_, AppState>,
) -> Result<String, String> {
    if master_password.is_empty() {
        return Err("Master password cannot be empty".to_string());
    }

    let vault_path = sentinelpass_core::get_default_vault_path();
    if !vault_path.exists() {
        return Err("No vault found".to_string());
    }

    service_call(
        &state,
        VaultOp::BiometricEnable {
            master_password: master_password.into(),
        },
    )
    .await?;
    Ok("Biometric unlock enabled".to_string())
}

// Command: Disable biometric unlock for this vault
#[tauri::command]
async fn disable_biometric_unlock(state: State<'_, AppState>) -> Result<String, String> {
    service_call(&state, VaultOp::BiometricDisable).await?;
    Ok("Biometric unlock disabled".to_string())
}

// Command: Lock vault
#[tauri::command]
async fn lock_vault(state: State<'_, AppState>) -> Result<(), String> {
    {
        let mut vault_manager = state.vault_manager.lock().unwrap();
        if let Some(ref mut vault) = *vault_manager {
            vault.lock();
        }
        *vault_manager = None;
    }
    // Release the compat direct-mode lock with the manager (stage-3 F1).
    *state.direct_lock.lock().unwrap() = None;

    if let Err(error) = send_daemon_message(IpcMessage::LockVault).await {
        eprintln!("SentinelPass UI: failed to lock daemon via IPC: {}", error);
    }

    Ok(())
}

// Command: Check if vault is unlocked (WBS-502: the daemon's state IS the
// unlock state; the local compat manager counts only in direct mode).
#[tauri::command]
async fn is_unlocked(state: State<'_, AppState>) -> Result<bool, String> {
    if direct_vault_mode() && state.vault_manager.lock().unwrap().is_some() {
        return Ok(true);
    }
    match send_daemon_message(IpcMessage::CheckVault).await {
        Ok(IpcMessage::VaultStatusResponse { unlocked, .. }) => Ok(unlocked),
        _ => Ok(false),
    }
}

// Command: Check daemon availability/unlock state for browser integration.
#[tauri::command]
async fn daemon_status(state: State<'_, AppState>) -> Result<DaemonStatus, String> {
    if let Err(error) = ensure_daemon_running(&state).await {
        unlock_debug_log(&format!("daemon_status: daemon unavailable: {}", error));
        return Ok(DaemonStatus {
            available: false,
            unlocked: false,
            message: Some(error),
        });
    }

    Ok(fetch_daemon_status().await)
}

// Command: List entries (WBS-502: service op through the daemon)
#[tauri::command]
async fn list_entries(state: State<'_, AppState>) -> Result<Vec<EntrySummary>, String> {
    let result = service_call(&state, VaultOp::EntryList).await?;
    to_entry_summary(result)
}

// Command: Get entry
#[tauri::command]
async fn get_entry(entry_id: i64, state: State<'_, AppState>) -> Result<Entry, String> {
    match service_call(&state, VaultOp::EntryGet { entry_id }).await? {
        VaultOpResult::Entry(entry) => entry_from_wire(&entry).map_err(|e| e.to_string()),
        other => Err(format!("unexpected daemon response: {other:?}")),
    }
}

// Command: Add entry
#[tauri::command]
async fn add_entry(entry: Entry, state: State<'_, AppState>) -> Result<i64, String> {
    let wire = entry_to_wire(&entry).map_err(|e| e.to_string())?;
    match service_call(&state, VaultOp::EntryAdd { entry: wire }).await? {
        VaultOpResult::EntryId(entry_id) => Ok(entry_id),
        other => Err(format!("unexpected daemon response: {other:?}")),
    }
}

// Command: Update entry
#[tauri::command]
async fn update_entry(
    entry_id: i64,
    entry: Entry,
    state: State<'_, AppState>,
) -> Result<(), String> {
    let mut wire = entry_to_wire(&entry).map_err(|e| e.to_string())?;
    wire.entry_id = Some(entry_id);
    service_call(
        &state,
        VaultOp::EntryUpdate {
            entry_id,
            entry: wire,
        },
    )
    .await?;
    Ok(())
}

// Command: Delete entry
#[tauri::command]
async fn delete_entry(entry_id: i64, state: State<'_, AppState>) -> Result<(), String> {
    service_call(&state, VaultOp::EntryDelete { entry_id }).await?;
    Ok(())
}

// Command: Registry posture overview (ADR-001 P2). `include_strength=false`
// is a cheap, no-decrypt pass (used for the header badge count);
// `include_strength=true` decrypts every eligible secret for strength
// scoring (used when the dashboard panel is actually opened). The daemon
// performs the backfill sweep before reading posture (WBS-502).
#[tauri::command]
async fn get_registry_overview(
    include_strength: bool,
    state: State<'_, AppState>,
) -> Result<RegistryOverview, String> {
    let result = service_call(&state, VaultOp::RegistryOverview { include_strength }).await?;
    match result {
        VaultOpResult::Report(value) => serde_json::from_value(value)
            .map_err(|e| format!("failed to decode registry overview: {}", e)),
        other => Err(format!("unexpected daemon response: {other:?}")),
    }
}

// Command: List registered entities
#[tauri::command]
async fn list_entities(state: State<'_, AppState>) -> Result<Vec<Entity>, String> {
    match service_call(&state, VaultOp::EntityList).await? {
        VaultOpResult::EntityList(entities) => entities
            .iter()
            .map(entity_from_wire)
            .collect::<Result<Vec<_>, _>>()
            .map_err(|e| e.to_string()),
        other => Err(format!("unexpected daemon response: {other:?}")),
    }
}

// Command: Generate password
#[tauri::command]
async fn generate_password(length: usize, include_symbols: bool) -> String {
    use sentinelpass_core::crypto::{generate_password, PasswordGeneratorConfig};

    let config = PasswordGeneratorConfig {
        length,
        include_lowercase: true,
        include_uppercase: true,
        include_digits: true,
        include_symbols,
        exclude_ambiguous: true,
    };

    generate_password(&config).unwrap_or_else(|_| "Password generation failed".to_string())
}

// Command: Check password strength
#[tauri::command]
async fn check_password_strength(password: String) -> Result<PasswordAnalysis, String> {
    use sentinelpass_core::crypto::analyze_password;

    let analysis = analyze_password(&password).map_err(|e| e.to_string())?;
    Ok(PasswordAnalysis {
        strength: analysis.strength.as_str().to_string(),
        score: analysis.strength.score(),
        entropy_bits: analysis.entropy_bits,
        crack_time_human: analysis.crack_time_human(),
        warnings: analysis.warnings,
        suggestions: analysis.suggestions,
        has_lowercase: analysis.has_lowercase,
        has_uppercase: analysis.has_uppercase,
        has_digits: analysis.has_digits,
        has_symbols: analysis.has_symbols,
    })
}

// Command: Check if TOTP is configured for an entry
#[tauri::command]
async fn has_totp(entry_id: i64, state: State<'_, AppState>) -> Result<bool, String> {
    match service_call(&state, VaultOp::TotpMetadata { entry_id }).await? {
        VaultOpResult::TotpMetadata(meta) => Ok(meta.is_some()),
        other => Err(format!("unexpected daemon response: {other:?}")),
    }
}

// Command: Get current TOTP code for an entry
#[tauri::command]
async fn get_totp_code(
    entry_id: i64,
    state: State<'_, AppState>,
) -> Result<TotpCodeResponse, String> {
    match service_call(&state, VaultOp::TotpCode { entry_id }).await? {
        VaultOpResult::TotpCode {
            code,
            seconds_remaining,
        } => Ok(TotpCodeResponse {
            code,
            seconds_remaining,
        }),
        other => Err(format!("unexpected daemon response: {other:?}")),
    }
}

// Command: Get TOTP metadata for an entry
#[tauri::command]
async fn get_totp_metadata(
    entry_id: i64,
    state: State<'_, AppState>,
) -> Result<Option<TotpMetadataResponse>, String> {
    match service_call(&state, VaultOp::TotpMetadata { entry_id }).await? {
        VaultOpResult::TotpMetadata(meta) => Ok(meta.map(|m| TotpMetadataResponse {
            algorithm: m.algorithm,
            digits: m.digits,
            period: m.period,
            issuer: m.issuer,
            account_name: m.account_name,
        })),
        other => Err(format!("unexpected daemon response: {other:?}")),
    }
}

// Command: Add or update TOTP configuration for an entry
#[tauri::command]
#[allow(clippy::too_many_arguments)]
async fn set_totp(
    entry_id: i64,
    secret: Option<String>,
    otpauth_uri: Option<String>,
    algorithm: Option<String>,
    digits: Option<u8>,
    period: Option<u32>,
    issuer: Option<String>,
    account_name: Option<String>,
    state: State<'_, AppState>,
) -> Result<String, String> {
    let parsed = if let Some(uri) = otpauth_uri.as_ref().filter(|v| !v.trim().is_empty()) {
        Some(parse_otpauth_uri(uri).map_err(|e| e.to_string())?)
    } else {
        None
    };

    let secret_value = secret
        .as_ref()
        .filter(|v| !v.trim().is_empty())
        .cloned()
        .or_else(|| parsed.as_ref().map(|p| p.secret_base32.clone()))
        .ok_or("TOTP secret is required (or provide otpauth URI)")?;

    let algorithm_value = if let Some(raw) = algorithm.as_ref().filter(|v| !v.trim().is_empty()) {
        raw.parse::<TotpAlgorithm>().map_err(|e| e.to_string())?
    } else {
        parsed
            .as_ref()
            .map(|p| p.algorithm)
            .unwrap_or(TotpAlgorithm::Sha1)
    };

    let digits_value = digits
        .or_else(|| parsed.as_ref().map(|p| p.digits))
        .unwrap_or(6);
    let period_value = period
        .or_else(|| parsed.as_ref().map(|p| p.period))
        .unwrap_or(30);
    let issuer_value = issuer.or_else(|| parsed.as_ref().and_then(|p| p.issuer.clone()));
    let account_value =
        account_name.or_else(|| parsed.as_ref().and_then(|p| p.account_name.clone()));

    service_call(
        &state,
        VaultOp::TotpAdd {
            entry_id,
            secret: secret_value.into(),
            algorithm: Some(algorithm_value.to_string()),
            digits: Some(digits_value),
            period: Some(period_value),
            issuer: issuer_value,
            account_name: account_value,
        },
    )
    .await?;

    Ok("TOTP saved".to_string())
}

// Command: Remove TOTP configuration from an entry
#[tauri::command]
async fn remove_totp(entry_id: i64, state: State<'_, AppState>) -> Result<String, String> {
    service_call(&state, VaultOp::TotpRemove { entry_id }).await?;
    Ok("TOTP removed".to_string())
}

// Command: Re-register native messaging host manifests
#[tauri::command]
async fn register_native_host() -> Result<String, String> {
    ensure_native_host_registered()?;
    Ok("Native messaging host registered for all browsers".to_string())
}

// Command: Open browser extensions/add-ons page
#[tauri::command]
async fn open_browser_extensions_page(browser: String) -> Result<(), String> {
    match browser.to_lowercase().as_str() {
        "chrome" | "chromium" => {
            #[cfg(target_os = "macos")]
            {
                Command::new("open")
                    .arg("-a")
                    .arg("Google Chrome")
                    .arg("chrome://extensions")
                    .spawn()
                    .map_err(|e| format!("Failed to open Chrome extensions page: {}", e))?;
            }
            #[cfg(target_os = "windows")]
            {
                // Try common Chrome install locations
                let chrome_paths = [
                    r"C:\Program Files\Google\Chrome\Application\chrome.exe",
                    r"C:\Program Files (x86)\Google\Chrome\Application\chrome.exe",
                ];
                let mut launched = false;
                for path in &chrome_paths {
                    if std::path::Path::new(path).exists() {
                        Command::new(path)
                            .arg("chrome://extensions")
                            .spawn()
                            .map_err(|e| format!("Failed to open Chrome extensions page: {}", e))?;
                        launched = true;
                        break;
                    }
                }
                if !launched {
                    return Err("Chrome not found at expected locations".to_string());
                }
            }
            #[cfg(all(unix, not(target_os = "macos")))]
            {
                let browsers = [
                    "google-chrome",
                    "google-chrome-stable",
                    "chromium-browser",
                    "chromium",
                ];
                let mut launched = false;
                for bin in &browsers {
                    if Command::new(bin).arg("chrome://extensions").spawn().is_ok() {
                        launched = true;
                        break;
                    }
                }
                if !launched {
                    return Err("Chrome/Chromium not found".to_string());
                }
            }
        }
        "firefox" => {
            #[cfg(target_os = "macos")]
            {
                Command::new("open")
                    .arg("-a")
                    .arg("Firefox")
                    .arg("about:addons")
                    .spawn()
                    .map_err(|e| format!("Failed to open Firefox add-ons page: {}", e))?;
            }
            #[cfg(target_os = "windows")]
            {
                let firefox_paths = [
                    r"C:\Program Files\Mozilla Firefox\firefox.exe",
                    r"C:\Program Files (x86)\Mozilla Firefox\firefox.exe",
                ];
                let mut launched = false;
                for path in &firefox_paths {
                    if std::path::Path::new(path).exists() {
                        Command::new(path)
                            .arg("about:addons")
                            .spawn()
                            .map_err(|e| format!("Failed to open Firefox add-ons page: {}", e))?;
                        launched = true;
                        break;
                    }
                }
                if !launched {
                    return Err("Firefox not found at expected locations".to_string());
                }
            }
            #[cfg(all(unix, not(target_os = "macos")))]
            {
                Command::new("firefox")
                    .arg("about:addons")
                    .spawn()
                    .map_err(|e| format!("Failed to open Firefox add-ons page: {}", e))?;
            }
        }
        _ => return Err(format!("Unknown browser: {}", browser)),
    }

    Ok(())
}

fn normalize_url_for_launch(url: &str) -> Result<String, String> {
    let trimmed = url.trim();
    if trimmed.is_empty() {
        return Err("URL is required".to_string());
    }
    if trimmed.chars().any(char::is_whitespace) {
        return Err("URL must not contain spaces".to_string());
    }

    let candidate = if trimmed.starts_with("http://") || trimmed.starts_with("https://") {
        trimmed.to_string()
    } else {
        format!("https://{}", trimmed)
    };

    if !(candidate.starts_with("http://") || candidate.starts_with("https://")) {
        return Err("Only http/https URLs are supported".to_string());
    }

    Ok(candidate)
}

// Command: Open entry URL in system default browser.
#[tauri::command]
async fn open_entry_url(url: String) -> Result<(), String> {
    let normalized = normalize_url_for_launch(&url)?;

    #[cfg(target_os = "windows")]
    {
        Command::new("explorer")
            .arg(&normalized)
            .spawn()
            .map_err(|e| format!("Failed to open URL in default browser: {}", e))?;
    }

    #[cfg(target_os = "macos")]
    {
        Command::new("open")
            .arg(&normalized)
            .spawn()
            .map_err(|e| format!("Failed to open URL in default browser: {}", e))?;
    }

    #[cfg(all(unix, not(target_os = "macos")))]
    {
        Command::new("xdg-open")
            .arg(&normalized)
            .spawn()
            .map_err(|e| format!("Failed to open URL in default browser: {}", e))?;
    }

    Ok(())
}

// Command: Copy a secret to the native clipboard (WBS-709).
//
// The write goes through arboard with platform sensitive-markers so
// clipboard history / cloud sync skip the value where the OS supports it.
// Only the SHA-256 digest is retained (never the plaintext) so expiry and
// app-exit can clear the clipboard only if it still holds this secret.
#[tauri::command]
fn copy_secret_to_clipboard(secret: String, state: State<'_, AppState>) -> Result<(), String> {
    if secret.is_empty() {
        return Err("Nothing to copy".to_string());
    }

    clipboard_secret::write_secret_to_clipboard(&secret)?;
    state
        .clipboard_tracker
        .lock()
        .unwrap()
        .register(secret.as_bytes());

    // Best-effort zeroization of the deserialized command argument.
    let mut secret = secret;
    use zeroize::Zeroize as _;
    secret.zeroize();

    Ok(())
}

/// Clear the clipboard iff it still holds the registered secret; drop the
/// registration either way. Returns whether the clipboard was cleared.
fn expire_registered_clipboard(state: &AppState) -> bool {
    let current = clipboard_secret::read_clipboard_text();
    let mut tracker = state.clipboard_tracker.lock().unwrap();
    let ours = tracker.matches_clipboard(current.as_deref());
    tracker.clear_registration();
    if ours {
        // The secret belongs to us and its expiry elapsed (or the app is
        // exiting): remove it from the native clipboard.
        return clipboard_secret::clear_clipboard().is_ok();
    }
    false
}

// Command: expiry tick from the UI timer (WBS-709). Clears the clipboard
// when it still holds the most recent secret copied by this app.
#[tauri::command]
fn expire_clipboard_secret(state: State<'_, AppState>) -> Result<bool, String> {
    Ok(expire_registered_clipboard(&state))
}

#[derive(Serialize, Deserialize)]
pub struct PasswordAnalysis {
    strength: String,
    score: u8,
    entropy_bits: f64,
    crack_time_human: String,
    warnings: Vec<String>,
    suggestions: Vec<String>,
    has_lowercase: bool,
    has_uppercase: bool,
    has_digits: bool,
    has_symbols: bool,
}

#[derive(Serialize, Deserialize)]
pub struct BiometricStatus {
    method_name: String,
    available: bool,
    enrolled: bool,
    configured: bool,
}

#[derive(Serialize, Deserialize)]
pub struct TotpCodeResponse {
    code: String,
    seconds_remaining: u32,
}

#[derive(Serialize, Deserialize)]
pub struct TotpMetadataResponse {
    algorithm: String,
    digits: u8,
    period: u32,
    issuer: Option<String>,
    account_name: Option<String>,
}

fn main() {
    unlock_debug_log("startup: sentinelpass-ui main() entered");
    let app = tauri::Builder::default()
        .plugin(tauri_plugin_dialog::init())
        .manage(AppState {
            vault_manager: Arc::new(Mutex::new(None)),
            daemon_process: Arc::new(Mutex::new(None)),
            clipboard_tracker: Arc::new(
                Mutex::new(clipboard_secret::ClipboardSecretTracker::new()),
            ),
            direct_lock: Arc::new(Mutex::new(None)),
        })
        .setup(|app| {
            if let Ok(resource_dir) = app.path().resource_dir() {
                let _ = RESOURCE_DIR.set(resource_dir.clone());
                unlock_debug_log(&format!("setup: resource_dir={}", resource_dir.display()));
            }

            // Auto-register native messaging host manifests so the browser
            // extension can locate sentinelpass-host without manual install.
            if let Err(e) = ensure_native_host_registered() {
                unlock_debug_log(&format!("setup: native host registration failed: {}", e));
            }

            let app_handle = app.handle().clone();
            tauri::async_runtime::spawn(async move {
                let state = app_handle.state::<AppState>();
                if let Err(error) = ensure_daemon_running(&state).await {
                    unlock_debug_log(&format!(
                        "setup: failed to start managed daemon automatically: {}",
                        error
                    ));
                } else {
                    unlock_debug_log("setup: managed daemon is ready");
                }
            });
            Ok(())
        })
        .invoke_handler(tauri::generate_handler![
            create_vault,
            unlock_vault,
            unlock_vault_biometric,
            lock_vault,
            is_unlocked,
            daemon_status,
            biometric_status,
            enable_biometric_unlock,
            disable_biometric_unlock,
            list_entries,
            get_entry,
            add_entry,
            update_entry,
            delete_entry,
            get_registry_overview,
            list_entities,
            generate_password,
            check_password_strength,
            has_totp,
            get_totp_code,
            get_totp_metadata,
            set_totp,
            remove_totp,
            open_entry_url,
            register_native_host,
            open_browser_extensions_page,
            copy_secret_to_clipboard,
            expire_clipboard_secret,
        ])
        .build(tauri::generate_context!())
        .expect("error while building tauri application");

    app.run(|app_handle, event| {
        if matches!(event, tauri::RunEvent::Exit) {
            let state = app_handle.state::<AppState>();
            // WBS-709 clear-on-exit: if a copied secret is still pending on
            // the system clipboard, remove it before the process goes away.
            expire_registered_clipboard(&state);
            stop_managed_daemon(&state);
        }
    });
}
