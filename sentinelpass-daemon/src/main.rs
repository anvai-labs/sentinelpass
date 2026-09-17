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
/// Retention bound for the roller's old daily files: the sweep keeps only
/// the newest [`KEEP_DAILY_LOGS`] `<LOG_FILE_NAME>.<date>` files. This is a
/// privacy bound, not just disk hygiene — service logs carry domain-bearing
/// INFO lines (autofill lookups) plus the vault path, so unbounded daily
/// files accumulate a per-domain history on disk.
const KEEP_DAILY_LOGS: usize = 14;
/// Retention bound for the [`OVERSIZED_MARKER`] archives: the sweep keeps
/// only the 3 most recent. Archives are rare runaway-day captures; a deeper
/// history has no diagnostic value against the same privacy cost.
const KEEP_ARCHIVED_LOGS: usize = 3;

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

/// Compute the retention deletion plan for `logs_dir`: daily roller files
/// beyond the `keep_daily` newest and oversized archives beyond the
/// `keep_archived` newest, oldest first. Read-only — [`prune_retention`]
/// executes the plan.
///
/// Classification and ordering are name-based with no date parsing: daily
/// files are `<LOG_FILE_NAME>.<date>` (ISO dates, so lexicographic order is
/// chronological) and archives order by the unix-ts after
/// [`OVERSIZED_MARKER`] (fixed-width epoch seconds, so textual order is
/// numeric). Today's active file is the newest daily file and is never
/// planned for deletion regardless of `keep_daily` — the roller holds it
/// open. The bare legacy name (`sentinelpass-daemon.log`, no suffix) and
/// anything without the log prefix are likewise out of bounds.
fn retention_deletion_plan(
    logs_dir: &Path,
    keep_daily: usize,
    keep_archived: usize,
) -> std::io::Result<Vec<PathBuf>> {
    let mut daily: Vec<String> = Vec::new();
    let mut archived: Vec<String> = Vec::new();
    for entry in std::fs::read_dir(logs_dir)? {
        let entry = entry?;
        let file_name = entry.file_name();
        let Some(name) = file_name.to_str() else {
            continue;
        };
        let Some(suffix) = name.strip_prefix(LOG_FILE_NAME) else {
            continue;
        };
        if suffix.contains(OVERSIZED_MARKER) {
            archived.push(name.to_string());
        } else if suffix.starts_with('.') {
            daily.push(name.to_string());
        }
        // The bare prefix (no suffix) is an active or legacy capture file —
        // never a deletion candidate.
    }
    daily.sort();
    // Newest archive = largest unix-ts. An unparsable suffix sorts as the
    // newest: deletion is irreversible, so an unexpected name is kept, not
    // dropped.
    archived.sort_by_key(|name| {
        name.rsplit(OVERSIZED_MARKER)
            .next()
            .and_then(|ts| ts.parse::<u64>().ok())
            .unwrap_or(u64::MAX)
    });
    // The newest daily file is today's, held open by the roller — floor the
    // effective keep at 1 so it can never be planned for deletion, whatever
    // `keep_daily` the caller passes. For `keep_daily >= 1` this is a no-op
    // (the newest sorts into the kept set anyway).
    let daily_cut = daily.len().saturating_sub(keep_daily.max(1));
    let archived_cut = archived.len().saturating_sub(keep_archived);
    let mut plan: Vec<PathBuf> = daily[..daily_cut]
        .iter()
        .map(|n| logs_dir.join(n))
        .collect();
    plan.extend(archived[..archived_cut].iter().map(|n| logs_dir.join(n)));
    Ok(plan)
}

/// Execute a retention prune over `logs_dir`, returning the number of files
/// actually deleted. Individual failures (a file locked by an antivirus or
/// indexer on Windows, say) do not strand the rest of the plan; the first
/// failure is reported after every planned deletion was attempted.
fn prune_retention(
    logs_dir: &Path,
    keep_daily: usize,
    keep_archived: usize,
) -> std::io::Result<usize> {
    let plan = retention_deletion_plan(logs_dir, keep_daily, keep_archived)?;
    let mut deleted = 0;
    let mut first_error = None;
    for path in &plan {
        match std::fs::remove_file(path) {
            Ok(()) => deleted += 1,
            Err(e) => {
                first_error.get_or_insert(e);
            }
        }
    }
    match first_error {
        Some(e) => Err(e),
        None => Ok(deleted),
    }
}

/// Sweep the logs directory before the appender attaches: rename any
/// outgrown roller file aside, then apply the retention caps. The size
/// guard covers the ACTIVE (today's) file and also sweeps earlier daily
/// files that outgrew the cap, without any date arithmetic: daily files are
/// named `<LOG_FILE_NAME>.<date>` and archived files carry
/// [`OVERSIZED_MARKER`], so a prefix + marker check separates the two.
/// Retention ([`prune_retention`] with [`KEEP_DAILY_LOGS`] /
/// [`KEEP_ARCHIVED_LOGS`]) then deletes old daily files and oversized
/// archives past the caps — a privacy bound on the domain-bearing INFO
/// history on disk, not just disk hygiene. It runs after the size guard so
/// freshly rotated archives count as new. Best-effort — a failed sweep only
/// loses the size bound / retention for this run, never the daemon start.
/// The launcher's stderr capture (launchd StandardOutPath, journal)
/// receives the notes.
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
    match prune_retention(logs_dir, KEEP_DAILY_LOGS, KEEP_ARCHIVED_LOGS) {
        Ok(0) => {}
        Ok(n) => eprintln!("pruned {n} old daemon log file(s) past retention"),
        Err(e) => eprintln!("warning: could not prune old daemon logs: {e}"),
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
    // Tighten the data dir itself first: on fresh service installs this runs
    // before any other hardening step, and create_private_dir only tightens
    // the leaf — the parent would otherwise be born 0755 via umask (review
    // F2), tripping loose-parent warnings on every subsequent vault open.
    sentinelpass_core::platform::create_private_dir(&sentinelpass_core::platform::get_data_dir())
        .map_err(|e| {
        anyhow::anyhow!(
            "Failed to harden data directory {}: {}",
            sentinelpass_core::platform::get_data_dir().display(),
            e
        )
    })?;
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
            // Flush the non-blocking log worker before exit: process::exit
            // skips destructors, so the WorkerGuard would never flush and
            // this refusal line could be lost from the rotated log (the
            // crash-loop diagnostic exactly when it is needed).
            drop(_log_guard);
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
        // Flush before exit — same WorkerGuard rationale as the
        // lock-refusal path above (review F1).
        drop(_log_guard);
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

#[cfg(test)]
mod log_retention_tests {
    use super::*;

    /// File names in `dir`, sorted, classified as (daily, archived) the way
    /// the retention planner classifies them.
    fn classify_logs(logs_dir: &Path) -> (Vec<String>, Vec<String>) {
        let mut daily = Vec::new();
        let mut archived = Vec::new();
        for entry in std::fs::read_dir(logs_dir).unwrap().flatten() {
            let name = entry.file_name().to_string_lossy().to_string();
            if !name.starts_with(LOG_FILE_NAME) {
                continue;
            }
            if name.contains(OVERSIZED_MARKER) {
                archived.push(name);
            } else if name != LOG_FILE_NAME {
                daily.push(name);
            }
        }
        daily.sort();
        archived.sort();
        (daily, archived)
    }

    #[test]
    fn prunes_past_retention_caps_keeping_the_newest_files() {
        let dir = tempfile::TempDir::new().unwrap();
        let logs_dir = dir.path().join("logs");
        std::fs::create_dir(&logs_dir).unwrap();

        // 20 daily files (zero-padded dates sort chronologically) + 5
        // archives with growing unix-ts suffixes, plus a bare legacy log
        // and a foreign file that must both ride along untouched.
        for day in 1..=20u32 {
            let daily = logs_dir.join(format!("{LOG_FILE_NAME}.2026-08-{day:02}"));
            std::fs::write(daily, b"daily").unwrap();
        }
        for i in 0..5u64 {
            let ts = 1_758_000_000 + 100 * i;
            let archived = logs_dir.join(format!("{LOG_FILE_NAME}{OVERSIZED_MARKER}{ts}"));
            std::fs::write(archived, b"archived").unwrap();
        }
        std::fs::write(logs_dir.join(LOG_FILE_NAME), b"active").unwrap();
        std::fs::write(logs_dir.join("vault.db"), b"foreign").unwrap();

        let deleted = prune_retention(&logs_dir, KEEP_DAILY_LOGS, KEEP_ARCHIVED_LOGS)
            .expect("retention prune must not fail");
        assert_eq!(
            deleted, 8,
            "six old dailies and two old archives must be pruned"
        );

        let (daily, archived) = classify_logs(&logs_dir);
        assert_eq!(daily.len(), KEEP_DAILY_LOGS, "exactly the cap survives");
        assert_eq!(
            daily.first().unwrap(),
            &format!("{LOG_FILE_NAME}.2026-08-07"),
            "the OLDEST survivors start right after the pruned range"
        );
        assert_eq!(
            daily.last().unwrap(),
            &format!("{LOG_FILE_NAME}.2026-08-20"),
            "the newest daily file always survives"
        );
        assert_eq!(
            archived.len(),
            KEEP_ARCHIVED_LOGS,
            "exactly the archive cap survives"
        );
        let kept_ts: Vec<u64> = archived
            .iter()
            .map(|n| n.rsplit(OVERSIZED_MARKER).next().unwrap().parse().unwrap())
            .collect();
        assert_eq!(
            kept_ts,
            vec![1_758_000_200, 1_758_000_300, 1_758_000_400],
            "the NEWEST archives survive, oldest pruned first"
        );
        assert!(
            logs_dir.join(LOG_FILE_NAME).exists(),
            "the bare active log must never be pruned"
        );
        assert!(
            logs_dir.join("vault.db").exists(),
            "foreign files must never be pruned"
        );
    }

    #[test]
    fn below_retention_caps_nothing_is_deleted() {
        let dir = tempfile::TempDir::new().unwrap();
        let logs_dir = dir.path().join("logs");
        std::fs::create_dir(&logs_dir).unwrap();

        for day in 1..=5u32 {
            let daily = logs_dir.join(format!("{LOG_FILE_NAME}.2026-09-{day:02}"));
            std::fs::write(daily, b"daily").unwrap();
        }
        for ts in [1_758_000_000u64, 1_758_000_100] {
            let archived = logs_dir.join(format!("{LOG_FILE_NAME}{OVERSIZED_MARKER}{ts}"));
            std::fs::write(archived, b"archived").unwrap();
        }

        let plan = retention_deletion_plan(&logs_dir, KEEP_DAILY_LOGS, KEEP_ARCHIVED_LOGS)
            .expect("planning must not fail");
        assert!(
            plan.is_empty(),
            "below the caps the plan is empty: {plan:?}"
        );

        let deleted = prune_retention(&logs_dir, KEEP_DAILY_LOGS, KEEP_ARCHIVED_LOGS)
            .expect("retention prune must not fail");
        assert_eq!(deleted, 0, "below the caps nothing is deleted");
        assert_eq!(
            std::fs::read_dir(&logs_dir).unwrap().count(),
            7,
            "directory must be untouched"
        );
    }

    #[test]
    fn retention_never_deletes_the_active_or_bare_log_file() {
        let dir = tempfile::TempDir::new().unwrap();
        let logs_dir = dir.path().join("logs");
        std::fs::create_dir(&logs_dir).unwrap();

        // Even at keep_daily = 0 the newest daily (today's, held open by the
        // roller) and the bare legacy name must survive.
        for day in 14..=16u32 {
            let daily = logs_dir.join(format!("{LOG_FILE_NAME}.2026-09-{day}"));
            std::fs::write(daily, b"daily").unwrap();
        }
        std::fs::write(logs_dir.join(LOG_FILE_NAME), b"active").unwrap();
        let archived = logs_dir.join(format!("{LOG_FILE_NAME}{OVERSIZED_MARKER}123"));
        std::fs::write(&archived, b"archived").unwrap();
        let foreign = logs_dir.join("vault.db");
        std::fs::write(&foreign, b"foreign").unwrap();

        let deleted = prune_retention(&logs_dir, 0, 0).expect("retention prune must not fail");

        assert_eq!(
            deleted, 3,
            "the two older dailies plus the archive go; the newest daily is protected even at keep_daily = 0"
        );
        assert!(
            logs_dir
                .join(format!("{LOG_FILE_NAME}.2026-09-16"))
                .exists(),
            "today's active file is by definition the newest and is never pruned"
        );
        assert!(
            logs_dir.join(LOG_FILE_NAME).exists(),
            "the bare active log (no date suffix) is never pruned"
        );
        assert!(foreign.exists(), "foreign files are never pruned");
        assert!(!archived.exists(), "archives have no active protection");
    }

    #[test]
    fn archive_files_do_not_confuse_daily_pruning() {
        let dir = tempfile::TempDir::new().unwrap();
        let logs_dir = dir.path().join("logs");
        std::fs::create_dir(&logs_dir).unwrap();

        // 16 small dailies (one past the cap) + 2 archives, one of which
        // carries BOTH a date and the oversized marker — it must count as an
        // archive, never as a daily, and vice versa for the daily count.
        for day in 1..=16u32 {
            let daily = logs_dir.join(format!("{LOG_FILE_NAME}.2026-09-{day:02}"));
            std::fs::write(daily, b"daily").unwrap();
        }
        let dated_archive = logs_dir.join(format!(
            "{LOG_FILE_NAME}.2026-09-10{OVERSIZED_MARKER}1758000000"
        ));
        std::fs::write(&dated_archive, b"archived").unwrap();
        let plain_archive = logs_dir.join(format!("{LOG_FILE_NAME}{OVERSIZED_MARKER}1758000100"));
        std::fs::write(&plain_archive, b"archived").unwrap();

        let plan = retention_deletion_plan(&logs_dir, KEEP_DAILY_LOGS, KEEP_ARCHIVED_LOGS)
            .expect("planning must not fail");
        let mut planned: Vec<String> = plan
            .iter()
            .map(|p| p.file_name().unwrap().to_string_lossy().to_string())
            .collect();
        planned.sort();
        assert_eq!(
            planned,
            vec![
                format!("{LOG_FILE_NAME}.2026-09-01"),
                format!("{LOG_FILE_NAME}.2026-09-02"),
            ],
            "only the two oldest dailies are planned; archives stay out of the daily count"
        );

        prune_retention(&logs_dir, KEEP_DAILY_LOGS, KEEP_ARCHIVED_LOGS)
            .expect("prune must not fail");
        let (daily, archived) = classify_logs(&logs_dir);
        assert_eq!(daily.len(), KEEP_DAILY_LOGS);
        assert_eq!(
            archived.len(),
            2,
            "both archives survive: 2 is within the archive cap"
        );
    }

    #[test]
    fn sweep_applies_retention_after_the_size_guard() {
        let dir = tempfile::TempDir::new().unwrap();
        let logs_dir = dir.path().join("logs");
        std::fs::create_dir(&logs_dir).unwrap();

        // 15 within-cap dailies + today's oversized file: the size guard
        // rotates today's aside (fresh archive), then retention prunes the
        // roller files back to the cap. The pre-existing archive plus the
        // fresh one stay under the archive cap.
        for day in 1..=15u32 {
            let daily = logs_dir.join(format!("{LOG_FILE_NAME}.2026-09-{day:02}"));
            std::fs::write(daily, b"tiny").unwrap();
        }
        let oversized = logs_dir.join(format!("{LOG_FILE_NAME}.2026-09-16"));
        std::fs::write(&oversized, vec![0u8; MAX_ACTIVE_LOG_BYTES as usize + 1]).unwrap();
        let old_archive = logs_dir.join(format!("{LOG_FILE_NAME}{OVERSIZED_MARKER}100"));
        std::fs::write(&old_archive, b"archived").unwrap();

        sweep_oversized_logs(&logs_dir);

        let (daily, archived) = classify_logs(&logs_dir);
        assert_eq!(
            daily.len(),
            KEEP_DAILY_LOGS,
            "the sweep must leave exactly the retention cap of daily files"
        );
        assert!(
            !logs_dir
                .join(format!("{LOG_FILE_NAME}.2026-09-01"))
                .exists(),
            "the oldest daily file is pruned"
        );
        assert_eq!(
            archived.len(),
            2,
            "the fresh oversized archive joins the old one, under the cap"
        );
    }
}
