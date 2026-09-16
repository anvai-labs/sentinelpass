use anyhow::Result;
use rpassword::prompt_password;
use sentinelpass_core::daemon::{
    default_ipc_socket_path, load_or_create_ipc_token, try_acquire, DaemonVault, IpcServer,
};
use sentinelpass_core::VaultManager;
use std::io::IsTerminal;
use std::path::{Path, PathBuf};
use std::sync::Arc;
use tokio::signal;
use tracing::{error, info, Level};
use tracing_appender::non_blocking::WorkerGuard;
use tracing_subscriber::FmtSubscriber;
use zeroize::Zeroize;

const VERSION: &str = env!("CARGO_PKG_VERSION");
const DEFAULT_INACTIVITY_TIMEOUT: u64 = 300; // 5 minutes

/// File name prefix of the daemon's service-mode log (a date suffix is
/// appended by the daily roller).
const LOG_FILE_NAME: &str = "sentinelpass-daemon.log";
/// Marker appended by the startup size guard when an outgrown log is
/// renamed aside (`<name>.oversized-<unix_ts>`).
const OVERSIZED_MARKER: &str = ".oversized-";
/// Service-mode logs above this size are renamed aside at startup. Daily
/// rotation bounds one day's file, but a single runaway day (or a legacy
/// unbounded file carried over from the launchd capture) could otherwise
/// grow without limit.
const MAX_ACTIVE_LOG_BYTES: u64 = 10 * 1024 * 1024; // 10 MB

struct GlobalVault {
    vault: Arc<DaemonVault>,
    _master_password: Vec<u8>, // Stored for potential re-unlock, zeroized on drop
}

impl Drop for GlobalVault {
    fn drop(&mut self) {
        self._master_password.zeroize();
    }
}

/// True when the daemon runs in a service context (launchd, systemd, a
/// scheduled task): stdout is not a terminal. Interactive `cargo run` keeps
/// stdout logging.
fn is_service_context() -> bool {
    !std::io::stdout().is_terminal()
}

/// If `log_path` exists and outgrew [`MAX_ACTIVE_LOG_BYTES`], rename it aside
/// once (`<name>.oversized-<unix_ts>`) so the log starts small again.
///
/// Returns the archive path when a rotation happened, `None` when the file
/// is missing, not a regular file, or still within the cap. IO errors
/// propagate; callers treat rotation as best-effort.
fn rotate_oversized_log(log_path: &Path) -> std::io::Result<Option<PathBuf>> {
    let meta = match std::fs::metadata(log_path) {
        Ok(meta) => meta,
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => return Ok(None),
        Err(e) => return Err(e),
    };
    if !meta.is_file() || meta.len() <= MAX_ACTIVE_LOG_BYTES {
        return Ok(None);
    }
    let file_name = log_path
        .file_name()
        .map(|n| n.to_string_lossy().to_string())
        .unwrap_or_else(|| LOG_FILE_NAME.to_string());
    let unix_ts = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(0);
    let archived = log_path.with_file_name(format!("{file_name}{OVERSIZED_MARKER}{unix_ts}"));
    std::fs::rename(log_path, &archived)?;
    Ok(Some(archived))
}

/// Sweep the logs directory before the appender attaches, renaming any
/// outgrown roller file aside. This covers the ACTIVE (today's) file and
/// also sweeps earlier daily files that outgrew the cap, without any date
/// arithmetic: daily files are named `<LOG_FILE_NAME>.<date>` and archived
/// files carry [`OVERSIZED_MARKER`], so a prefix + marker check separates
/// the two. Best-effort — a failed sweep only loses the size bound for this
/// run, never the daemon start. The launcher's stderr capture (launchd
/// StandardOutPath, journal) receives the notes.
fn sweep_oversized_logs(logs_dir: &Path) {
    let Ok(entries) = std::fs::read_dir(logs_dir) else {
        return;
    };
    for entry in entries.flatten() {
        let name = entry.file_name();
        let Some(name) = name.to_str() else { continue };
        if !name.starts_with(LOG_FILE_NAME) || name.contains(OVERSIZED_MARKER) {
            continue;
        }
        match rotate_oversized_log(&entry.path()) {
            Ok(Some(archived)) => {
                eprintln!(
                    "rotated oversized log {} -> {}",
                    entry.path().display(),
                    archived.display()
                );
            }
            Ok(None) => {}
            Err(e) => {
                eprintln!(
                    "warning: could not rotate oversized log {}: {}",
                    entry.path().display(),
                    e
                );
            }
        }
    }
}

/// Attach the global tracing subscriber.
///
/// Service context logs to a DAILY-ROTATING file under the platform data
/// dir's `logs/` subdir — the unbounded launchd-captured `daemon.log` gap
/// closes because the switch happens before the first tracing line, so the
/// launcher capture only ever holds early panics. The returned
/// [`WorkerGuard`] must be held by main for the process lifetime so the
/// non-blocking worker thread flushes buffered lines on shutdown (`None`
/// when logging stayed on stdout).
fn init_logging() -> Result<Option<WorkerGuard>> {
    let builder = FmtSubscriber::builder().with_max_level(Level::INFO);

    if !is_service_context() {
        // Interactive terminal: keep the historical stdout behavior exactly.
        tracing::subscriber::set_global_default(builder.finish())?;
        return Ok(None);
    }

    let logs_dir = sentinelpass_core::platform::get_data_dir().join("logs");
    sentinelpass_core::platform::create_private_dir(&logs_dir).map_err(|e| {
        anyhow::anyhow!(
            "Failed to create log directory {}: {}",
            logs_dir.display(),
            e
        )
    })?;

    sweep_oversized_logs(&logs_dir);

    let (writer, guard) =
        tracing_appender::non_blocking(tracing_appender::rolling::daily(&logs_dir, LOG_FILE_NAME));
    // No ANSI escapes in file logs.
    tracing::subscriber::set_global_default(builder.with_ansi(false).with_writer(writer).finish())?;
    Ok(Some(guard))
}

#[tokio::main]
async fn main() -> Result<()> {
    // Initialize logging. The returned guard MUST live to the end of main:
    // dropping it stops the non-blocking worker before final flushes.
    let _log_guard = init_logging()?;

    info!("Starting SentinelPass Daemon v{}", VERSION);
    let args: Vec<String> = std::env::args().skip(1).collect();
    let use_biometric = args.iter().any(|arg| arg == "--biometric");
    let start_locked = args.iter().any(|arg| arg == "--start-locked");

    if use_biometric && start_locked {
        return Err(anyhow::anyhow!(
            "Invalid flags: --biometric and --start-locked cannot be used together"
        ));
    }

    // WBS-501/503: the daemon is the sole live DEK owner. It takes the
    // exclusive advisory lock beside the vault and holds it for its entire
    // lifetime — a second daemon, or any offline maintenance process, refuses
    // coexistence instead of racing this one on the vault files.
    let vault_path = sentinelpass_core::get_default_vault_path();
    if let Some(parent) = vault_path.parent() {
        if !parent.exists() {
            sentinelpass_core::platform::create_private_dir(parent)
                .map_err(|e| anyhow::anyhow!("Failed to create data directory: {}", e))?;
        }
    }
    let _maintenance_lock = match try_acquire(&vault_path) {
        Ok(guard) => guard,
        Err(e) => {
            error!("Refusing to start: {}", e);
            // Non-zero exit: a refusal must never look like a clean start to
            // supervisors waiting on the process (review F4).
            std::process::exit(1);
        }
    };

    let maintenance_mode = !vault_path.exists();

    // WBS-505: provision the native-host installation capability on every
    // start (mint-once; the host presents the 0600 secret file and the
    // daemon verifies it for browser-surface operations).
    if let Err(e) = sentinelpass_core::daemon::site_permissions::ensure_store_file(
        &sentinelpass_core::daemon::site_permissions::default_store_path(),
    ) {
        tracing::warn!("site permission store unavailable: {}", e);
    }
    if let Err(e) = sentinelpass_core::daemon::ensure_native_host_capability() {
        error!("Native-host capability provisioning failed: {}", e);
        // Non-zero exit: a refusal must never look like a clean start
        // (stage-6 review F2, matching the lock-refusal rule).
        std::process::exit(1);
    }

    // Create DaemonVault (works for the bootstrap case: the path is only
    // touched once a vault exists — maintenance mode serves creation).
    let vault = DaemonVault::new(Some(vault_path.clone()), DEFAULT_INACTIVITY_TIMEOUT)?;

    let master_password_bytes = if maintenance_mode {
        info!(
            "No vault found at {:?} — entering maintenance mode; \
             create a vault through the application-service IPC (VaultCreate)",
            vault_path
        );
        Vec::new()
    } else if start_locked {
        info!("Starting daemon in locked mode; waiting for IPC unlock");
        Vec::new()
    } else if use_biometric {
        info!("Using biometric unlock flow");
        let opened_vault =
            VaultManager::open_with_biometric(&vault_path, "Unlock SentinelPass daemon")
                .map_err(|e| anyhow::anyhow!("Failed biometric unlock: {}", e))?;
        vault.unlock_with_manager(opened_vault).await;
        info!("Vault unlocked successfully");
        Vec::new()
    } else {
        let master_password = prompt_password("Enter master password to unlock vault: ")?;
        let master_password_bytes = master_password.as_bytes().to_vec();
        if let Err(e) = vault.unlock(&master_password_bytes).await {
            return Err(anyhow::anyhow!("Failed to unlock vault: {}", e));
        }
        info!("Vault unlocked successfully");
        master_password_bytes
    };

    // Wrap vault in Arc for sharing with IPC server
    let vault_arc = Arc::new(vault);

    // Store vault state globally for IPC access
    let global_vault = GlobalVault {
        vault: vault_arc.clone(),
        _master_password: master_password_bytes,
    };

    // Start IPC server
    let ipc_socket_path = default_ipc_socket_path();
    let ipc_token = load_or_create_ipc_token()
        .map_err(|e| anyhow::anyhow!("Failed to load/create IPC token: {}", e))?;
    let ipc_server = IpcServer::new(ipc_socket_path.clone(), vault_arc, ipc_token);
    if maintenance_mode {
        ipc_server.enter_maintenance_mode();
    }

    // Spawn IPC server in background (WBS-512: run takes Arc<Self> so it
    // can spawn bounded per-connection tasks).
    let ipc_server = Arc::new(ipc_server);
    let ipc_handle = tokio::spawn(async move {
        info!("IPC server starting at {:?}", ipc_socket_path);
        if let Err(e) = ipc_server.run().await {
            error!("IPC server error: {}", e);
        }
    });

    if maintenance_mode {
        info!("Daemon ready in maintenance mode (no vault). Press Ctrl+C to exit.");
    } else {
        info!("Daemon ready. Press Ctrl+C to exit.");
        info!(
            "Auto-lock enabled after {} seconds of inactivity",
            DEFAULT_INACTIVITY_TIMEOUT
        );
    }

    // Wait for shutdown signal
    signal::ctrl_c().await?;
    info!("Received shutdown signal");

    // Abort IPC server task
    ipc_handle.abort();

    // Lock vault before exiting
    info!("Locking vault...");
    global_vault.vault.lock().await;

    // Vault and master_password are dropped here, which zeros the password.
    // Dropping the maintenance lock releases the advisory lock last, after
    // the vault state is gone.

    Ok(())
}

#[cfg(test)]
mod log_rotation_tests {
    use super::*;

    #[test]
    fn missing_log_file_is_a_no_op() {
        let dir = tempfile::TempDir::new().unwrap();
        let log_path = dir.path().join(LOG_FILE_NAME);

        assert!(matches!(rotate_oversized_log(&log_path), Ok(None)));
        assert!(!log_path.exists());
    }

    #[test]
    fn log_within_cap_is_left_in_place() {
        let dir = tempfile::TempDir::new().unwrap();
        let log_path = dir.path().join(LOG_FILE_NAME);
        std::fs::write(&log_path, vec![0u8; 4096]).unwrap();

        assert!(matches!(rotate_oversized_log(&log_path), Ok(None)));
        assert!(log_path.exists(), "within-cap log must not be moved");
        assert_eq!(std::fs::read_dir(dir.path()).unwrap().count(), 1);
    }

    #[test]
    fn log_at_cap_boundary_is_not_rotated() {
        let dir = tempfile::TempDir::new().unwrap();
        let log_path = dir.path().join(LOG_FILE_NAME);
        std::fs::write(&log_path, vec![0u8; MAX_ACTIVE_LOG_BYTES as usize]).unwrap();

        assert!(matches!(rotate_oversized_log(&log_path), Ok(None)));
        assert!(log_path.exists());
    }

    #[test]
    fn oversized_log_is_renamed_aside_with_marker_and_timestamp() {
        let dir = tempfile::TempDir::new().unwrap();
        let log_path = dir.path().join(LOG_FILE_NAME);
        std::fs::write(&log_path, vec![0u8; MAX_ACTIVE_LOG_BYTES as usize + 1]).unwrap();

        let archived = rotate_oversized_log(&log_path)
            .expect("rotation must not fail")
            .expect("oversized log must be rotated");

        assert!(!log_path.exists(), "active log must be moved aside");
        assert!(archived.is_file());
        let name = archived.file_name().unwrap().to_str().unwrap();
        assert!(
            name.starts_with(LOG_FILE_NAME),
            "archived name keeps the log prefix: {name}"
        );
        assert!(
            name.contains(OVERSIZED_MARKER),
            "archived name carries the oversized marker: {name}"
        );
        assert!(
            name.rsplit(OVERSIZED_MARKER)
                .next()
                .unwrap()
                .parse::<u64>()
                .is_ok(),
            "archived name ends in a unix timestamp: {name}"
        );
        assert_eq!(
            std::fs::metadata(&archived).unwrap().len(),
            MAX_ACTIVE_LOG_BYTES + 1,
            "rotation must not lose content"
        );
    }

    #[test]
    fn sweep_rotates_oversized_daily_files_but_skips_archived_and_foreign_files() {
        let dir = tempfile::TempDir::new().unwrap();
        let logs_dir = dir.path().join("logs");
        std::fs::create_dir(&logs_dir).unwrap();

        // Oversized daily file (today's active or an old runaway): rotated.
        let oversized = logs_dir.join(format!("{LOG_FILE_NAME}.2026-09-16"));
        std::fs::write(&oversized, vec![0u8; MAX_ACTIVE_LOG_BYTES as usize + 1]).unwrap();
        // Already-archived file: left alone.
        let archived = logs_dir.join(format!("{LOG_FILE_NAME}{OVERSIZED_MARKER}123"));
        std::fs::write(&archived, vec![0u8; MAX_ACTIVE_LOG_BYTES as usize + 1]).unwrap();
        // Unrelated file: left alone.
        let foreign = logs_dir.join("vault.db");
        std::fs::write(&foreign, vec![0u8; MAX_ACTIVE_LOG_BYTES as usize + 1]).unwrap();
        // Small daily file: left alone.
        let small = logs_dir.join(format!("{LOG_FILE_NAME}.2026-09-15"));
        std::fs::write(&small, b"tiny").unwrap();

        sweep_oversized_logs(&logs_dir);

        assert!(!oversized.exists(), "oversized daily file must be swept");
        assert_eq!(
            std::fs::read_dir(&logs_dir).unwrap().count(),
            4,
            "sweep must add exactly one archive, touching nothing else"
        );
        assert!(
            archived.exists(),
            "already-archived file must not be renamed again"
        );
        assert!(foreign.exists(), "foreign files must be untouched");
        assert!(small.exists(), "within-cap daily file must be untouched");
    }
}
