//! Model one mobile application's persistent base directory, with disposable
//! vault fixtures beneath it. Core's base-dir override is process-wide and
//! set once, so its lifetime must exceed every individual vault fixture.
use std::path::PathBuf;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::OnceLock;

pub fn vault_dir() -> PathBuf {
    static APP_BASE: OnceLock<PathBuf> = OnceLock::new();
    static NEXT: AtomicU64 = AtomicU64::new(0);
    let base = APP_BASE.get_or_init(|| {
        let stamp = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .expect("clock after epoch")
            .as_nanos();
        let base =
            std::env::temp_dir().join(format!("sp_mobile_test_app_{}_{stamp}", std::process::id()));
        sentinelpass_core::platform::create_private_dir(&base).expect("create app base");
        sentinelpass_core::platform::set_base_dir(base.clone());
        base
    });
    let dir = base.join(format!("vault_{}", NEXT.fetch_add(1, Ordering::Relaxed)));
    sentinelpass_core::platform::create_private_dir(&dir).expect("create vault fixture");
    dir
}
