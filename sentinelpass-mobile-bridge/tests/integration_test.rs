//! WBS-806: lifecycle / invalid-handle integration tests.
//!
//! These exercise the real exported C ABI (`sp_*` symbols via
//! `sentinelpass_mobile_bridge::*`) end-to-end against real vault files:
//! vault lifecycle, entry lifecycle, lock/unlock, TOTP/generator surfaces,
//! and every invalid-handle path (double destroy, use-after-destroy,
//! unknown handles). The FFI functions are the contract Swift consumes;
//! the JNI contract is pinned separately by `jni_contract.rs`.

use std::ffi::{CStr, CString};
use std::os::raw::c_char;
use std::path::PathBuf;
use std::sync::atomic::{AtomicU32, Ordering};

use sentinelpass_mobile_bridge::{
    sp_biometric_has_key, sp_bridge_info, sp_entry_add, sp_entry_delete, sp_entry_get_by_id,
    sp_entry_list_all, sp_entry_search, sp_entry_update, sp_password_check_strength,
    sp_password_generate, sp_string_free, sp_sync_get_status, sp_totp_generate_code,
    sp_vault_destroy, sp_vault_init, sp_vault_is_unlocked, sp_vault_lock, BridgeInfo, Entry,
    EntrySummary, ErrorCode, PasswordAnalysis, SyncStatus, TotpCode, VaultHandle,
};

static TEST_SEQ: AtomicU32 = AtomicU32::new(0);

fn cstr(s: &str) -> CString {
    CString::new(s).expect("test strings contain no NUL")
}

/// A live vault in a fresh temp dir. Destroy + cleanup on drop so parallel
/// tests cannot leak registry entries or temp files.
struct TestVault {
    dir: PathBuf,
    handle: VaultHandle,
}

impl TestVault {
    fn create() -> Self {
        let dir = std::env::temp_dir().join(format!(
            "sp_integration_{}_{}",
            std::process::id(),
            TEST_SEQ.fetch_add(1, Ordering::SeqCst)
        ));
        std::fs::create_dir_all(&dir).expect("create temp dir");
        let vault_path = dir.join("vault.db");
        let mut handle: VaultHandle = 0;
        let code = unsafe {
            sp_vault_init(
                cstr(vault_path.to_str().unwrap()).as_ptr(),
                cstr(MASTER).as_ptr(),
                &mut handle,
            )
        };
        assert_eq!(code, ErrorCode::Success, "vault create must succeed");
        Self { dir, handle }
    }

    fn add_entry(&self, title: &str) -> String {
        let mut id_ptr: *const c_char = std::ptr::null();
        let code = unsafe {
            sp_entry_add(
                self.handle,
                cstr(title).as_ptr(),
                cstr("user@example.com").as_ptr(),
                cstr("hunter2secret").as_ptr(),
                cstr("https://example.com").as_ptr(),
                std::ptr::null(), // notes optional
                &mut id_ptr,
            )
        };
        assert_eq!(code, ErrorCode::Success, "entry add must succeed");
        let id = unsafe { CStr::from_ptr(id_ptr) }
            .to_string_lossy()
            .into_owned();
        unsafe { sp_string_free(id_ptr) };
        id
    }
}

impl Drop for TestVault {
    fn drop(&mut self) {
        unsafe { sp_vault_destroy(self.handle) };
        let _ = std::fs::remove_dir_all(&self.dir);
    }
}

const MASTER: &str = "integration-master-password";

#[test]
fn vault_lifecycle_create_unlock_lock_destroy() {
    let v = TestVault::create();

    let mut unlocked = false;
    let code = unsafe { sp_vault_is_unlocked(v.handle, &mut unlocked) };
    assert_eq!(code, ErrorCode::Success);
    assert!(unlocked, "fresh vault must be unlocked");

    assert_eq!(unsafe { sp_vault_lock(v.handle) }, ErrorCode::Success);
    let code = unsafe { sp_vault_is_unlocked(v.handle, &mut unlocked) };
    assert_eq!(code, ErrorCode::Success);
    assert!(!unlocked, "vault must be locked after sp_vault_lock");
}

#[test]
fn double_destroy_and_use_after_destroy_are_refused() {
    let dir = std::env::temp_dir().join(format!(
        "sp_integration_{}_{}",
        std::process::id(),
        TEST_SEQ.fetch_add(1, Ordering::SeqCst)
    ));
    std::fs::create_dir_all(&dir).expect("create temp dir");
    let mut handle: VaultHandle = 0;
    let code = unsafe {
        sp_vault_init(
            cstr(dir.join("vault.db").to_str().unwrap()).as_ptr(),
            cstr(MASTER).as_ptr(),
            &mut handle,
        )
    };
    assert_eq!(code, ErrorCode::Success);

    assert_eq!(unsafe { sp_vault_destroy(handle) }, ErrorCode::Success);
    // Double destroy: refused, not a silent success.
    assert_eq!(unsafe { sp_vault_destroy(handle) }, ErrorCode::InvalidParam);
    // Use-after-destroy: refused on every op that takes a handle.
    let mut unlocked = true;
    assert_eq!(
        unsafe { sp_vault_is_unlocked(handle, &mut unlocked) },
        ErrorCode::InvalidParam
    );
    assert_eq!(unsafe { sp_vault_lock(handle) }, ErrorCode::InvalidParam);
    let mut out: *const EntrySummary = std::ptr::null();
    let mut count: usize = 0;
    assert_eq!(
        unsafe { sp_entry_list_all(handle, &mut out, &mut count) },
        ErrorCode::InvalidParam
    );
    let _ = std::fs::remove_dir_all(dir);
}

#[test]
fn unknown_handle_and_null_out_params_are_refused() {
    // A handle that was never issued must be refused everywhere.
    let bogus: VaultHandle = u64::MAX - 7;
    let mut unlocked = true;
    assert_eq!(
        unsafe { sp_vault_is_unlocked(bogus, &mut unlocked) },
        ErrorCode::InvalidParam
    );
    assert_eq!(unsafe { sp_vault_lock(bogus) }, ErrorCode::InvalidParam);
    assert_eq!(unsafe { sp_vault_destroy(bogus) }, ErrorCode::InvalidParam);

    // Null out-params are InvalidParam, never a write-through-null.
    assert_eq!(
        unsafe { sp_vault_is_unlocked(bogus, std::ptr::null_mut()) },
        ErrorCode::InvalidParam
    );
    assert_eq!(
        unsafe { sp_bridge_info(std::ptr::null_mut()) },
        ErrorCode::InvalidParam
    );
}

#[test]
fn vault_reopen_requires_master_password() {
    let dir = std::env::temp_dir().join(format!(
        "sp_integration_{}_{}",
        std::process::id(),
        TEST_SEQ.fetch_add(1, Ordering::SeqCst)
    ));
    std::fs::create_dir_all(&dir).expect("create temp dir");
    let path = dir.join("vault.db");

    let mut handle: VaultHandle = 0;
    assert_eq!(
        unsafe {
            sp_vault_init(
                cstr(path.to_str().unwrap()).as_ptr(),
                cstr(MASTER).as_ptr(),
                &mut handle,
            )
        },
        ErrorCode::Success
    );
    unsafe { sp_vault_destroy(handle) };

    // Wrong password: refused. The honest surface is `Crypto` — the wrapped
    // key fails AES-GCM authentication — because core does not yet
    // distinguish a dedicated InvalidMasterPassword variant (the
    // ErrorCode::InvalidPassword ABI value exists for when it does).
    let mut bad: VaultHandle = 0;
    assert_eq!(
        unsafe {
            sp_vault_init(
                cstr(path.to_str().unwrap()).as_ptr(),
                cstr("wrong-password").as_ptr(),
                &mut bad,
            )
        },
        ErrorCode::Crypto
    );
    // Correct password: reopens unlocked.
    let mut good: VaultHandle = 0;
    assert_eq!(
        unsafe {
            sp_vault_init(
                cstr(path.to_str().unwrap()).as_ptr(),
                cstr(MASTER).as_ptr(),
                &mut good,
            )
        },
        ErrorCode::Success
    );
    let mut unlocked = false;
    unsafe { sp_vault_is_unlocked(good, &mut unlocked) };
    assert!(unlocked, "reopened vault must be unlocked");
    unsafe { sp_vault_destroy(good) };
    let _ = std::fs::remove_dir_all(dir);
}

#[test]
fn entry_lifecycle_add_get_update_search_delete() {
    let v = TestVault::create();
    let id = v.add_entry("alpha");

    // Get by ID round-trips all fields.
    let mut entry = Entry {
        id: std::ptr::null(),
        title: std::ptr::null(),
        username: std::ptr::null(),
        password: std::ptr::null(),
        url: std::ptr::null(),
        notes: std::ptr::null(),
        created_at: 0,
        modified_at: 0,
        favorite: false,
    };
    assert_eq!(
        unsafe { sp_entry_get_by_id(v.handle, cstr(&id).as_ptr(), &mut entry) },
        ErrorCode::Success
    );
    assert_eq!(
        unsafe { CStr::from_ptr(entry.title) }.to_string_lossy(),
        "alpha"
    );
    assert_eq!(
        unsafe { CStr::from_ptr(entry.password) }.to_string_lossy(),
        "hunter2secret"
    );

    // ATOMIC update (WBS-807): only the title changes; nulls leave the rest
    // untouched; the entry id is preserved (no delete-then-add churn).
    assert_eq!(
        unsafe {
            sp_entry_update(
                v.handle,
                cstr(&id).as_ptr(),
                cstr("alpha-renamed").as_ptr(),
                std::ptr::null(),
                std::ptr::null(),
                std::ptr::null(),
                std::ptr::null(),
            )
        },
        ErrorCode::Success
    );
    assert_eq!(
        unsafe { sp_entry_get_by_id(v.handle, cstr(&id).as_ptr(), &mut entry) },
        ErrorCode::Success
    );
    assert_eq!(
        unsafe { CStr::from_ptr(entry.title) }.to_string_lossy(),
        "alpha-renamed"
    );
    assert_eq!(
        unsafe { CStr::from_ptr(entry.password) }.to_string_lossy(),
        "hunter2secret",
        "null password must be unchanged"
    );
    assert_eq!(
        unsafe { CStr::from_ptr(entry.id) }.to_string_lossy(),
        id,
        "atomic update must preserve entry identity"
    );

    // List sees it; search finds it by title.
    let mut list: *const EntrySummary = std::ptr::null();
    let mut count: usize = 0;
    assert_eq!(
        unsafe { sp_entry_list_all(v.handle, &mut list, &mut count) },
        ErrorCode::Success
    );
    assert_eq!(count, 1);
    unsafe { sentinelpass_mobile_bridge::sp_entry_list_free(list as *mut EntrySummary, count) };

    let mut list: *const EntrySummary = std::ptr::null();
    let mut count: usize = 0;
    assert_eq!(
        unsafe { sp_entry_search(v.handle, cstr("alpha").as_ptr(), &mut list, &mut count) },
        ErrorCode::Success
    );
    assert_eq!(count, 1);
    unsafe { sentinelpass_mobile_bridge::sp_entry_list_free(list as *mut EntrySummary, count) };

    // Delete removes it; subsequent get is NotFound.
    assert_eq!(
        unsafe { sp_entry_delete(v.handle, cstr(&id).as_ptr()) },
        ErrorCode::Success
    );
    assert_eq!(
        unsafe { sp_entry_get_by_id(v.handle, cstr(&id).as_ptr(), &mut entry) },
        ErrorCode::NotFound
    );
}

#[test]
fn entry_ops_on_invalid_ids_and_handles_fail_cleanly() {
    let v = TestVault::create();
    let mut entry = Entry {
        id: std::ptr::null(),
        title: std::ptr::null(),
        username: std::ptr::null(),
        password: std::ptr::null(),
        url: std::ptr::null(),
        notes: std::ptr::null(),
        created_at: 0,
        modified_at: 0,
        favorite: false,
    };
    // Non-numeric ID: InvalidParam, not a panic.
    assert_eq!(
        unsafe { sp_entry_get_by_id(v.handle, cstr("not-a-number").as_ptr(), &mut entry) },
        ErrorCode::InvalidParam
    );
    // Missing ID: NotFound.
    assert_eq!(
        unsafe { sp_entry_get_by_id(v.handle, cstr("999999").as_ptr(), &mut entry) },
        ErrorCode::NotFound
    );
    // Null out-struct.
    assert_eq!(
        unsafe { sp_entry_get_by_id(v.handle, cstr("1").as_ptr(), std::ptr::null_mut()) },
        ErrorCode::InvalidParam
    );
}

#[test]
fn generator_and_strength_surfaces_validate_inputs() {
    let mut pw: *const c_char = std::ptr::null();
    // Out of the documented 8..=128 range: refused.
    assert_eq!(
        unsafe { sp_password_generate(4, false, &mut pw) },
        ErrorCode::InvalidParam
    );
    assert_eq!(
        unsafe { sp_password_generate(129, false, &mut pw) },
        ErrorCode::InvalidParam
    );
    assert_eq!(
        unsafe { sp_password_generate(32, true, &mut pw) },
        ErrorCode::Success
    );
    let generated = unsafe { CStr::from_ptr(pw) }.to_string_lossy().into_owned();
    assert_eq!(generated.len(), 32);
    unsafe { sp_string_free(pw) };

    let mut analysis = PasswordAnalysis {
        score: 0,
        entropy_bits: 0.0,
        crack_time_seconds: 0.0,
        length: 0,
        has_lower: false,
        has_upper: false,
        has_digit: false,
        has_symbol: false,
    };
    assert_eq!(
        unsafe { sp_password_check_strength(cstr("Tr0ub4dor&3longer!").as_ptr(), &mut analysis) },
        ErrorCode::Success
    );
    assert!(analysis.length == 18);
    assert!(analysis.has_upper && analysis.has_digit && analysis.has_symbol);
    // Null out-param refused.
    assert_eq!(
        unsafe { sp_password_check_strength(cstr("x").as_ptr(), std::ptr::null_mut()) },
        ErrorCode::InvalidParam
    );
}

#[test]
fn totp_and_sync_surfaces_report_expected_states() {
    let v = TestVault::create();
    let id = v.add_entry("no-totp");

    let mut code_out = TotpCode {
        code: std::ptr::null(),
        seconds_remaining: 0,
    };
    // Entries without a TOTP secret must error, not panic.
    let code = unsafe { sp_totp_generate_code(v.handle, cstr(&id).as_ptr(), &mut code_out) };
    assert_ne!(code, ErrorCode::Success);

    let mut status = SyncStatus {
        enabled: false,
        last_sync_at: 0,
        pending_changes: 0,
        device_id: std::ptr::null(),
    };
    assert_eq!(
        unsafe { sp_sync_get_status(v.handle, &mut status) },
        ErrorCode::Success
    );
    assert!(
        !status.enabled,
        "sync must default to disabled until relay sync v2 is wired (ADR-006/ADR-009)"
    );
    unsafe { sp_string_free(status.device_id) };

    let mut has_key = true;
    assert_eq!(
        unsafe { sp_biometric_has_key(v.handle, &mut has_key) },
        ErrorCode::Success
    );
    assert!(!has_key, "fresh vault must have no biometric key");
}

#[test]
fn abi_negotiation_is_available_and_stable() {
    let mut info = BridgeInfo {
        abi_version: 0,
        min_supported_abi_version: 0,
        feature_flags: 0,
        reserved: 0,
    };
    assert_eq!(unsafe { sp_bridge_info(&mut info) }, ErrorCode::Success);
    assert!(info.abi_version >= 1);
    assert!(info.min_supported_abi_version >= 1);
    assert_eq!(info.reserved, 0);
}
