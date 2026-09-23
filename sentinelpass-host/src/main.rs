use anyhow::Result;
use sentinelpass_core::daemon::NativeMessagingHost;
use tracing::{error, info};
use tracing_subscriber::FmtSubscriber;

const VERSION: &str = env!("CARGO_PKG_VERSION");

fn main() -> Result<()> {
    sentinelpass_core::platform::disable_core_dumps()?;
    // Initialize logging to stderr (native messaging uses stdout)
    let subscriber = FmtSubscriber::builder()
        .with_writer(std::io::stderr)
        .finish();

    tracing::subscriber::set_global_default(subscriber).expect("setting default subscriber failed");

    info!("Starting SentinelPass Native Messaging Host v{}", VERSION);

    // Run the native messaging host
    let mut host = NativeMessagingHost::new();

    match host.run() {
        Ok(()) => {
            info!("Native messaging host completed successfully");
            Ok(())
        }
        Err(e) => {
            error!(error_kind = ?std::any::type_name_of_val(&e), "Native messaging host error");
            anyhow::bail!(
                "Native messaging host failed; request values are omitted from diagnostics"
            )
        }
    }
}
