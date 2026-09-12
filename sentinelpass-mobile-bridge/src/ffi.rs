// FFI exports for iOS (C ABI)
//
// These functions are exported with C linkage and can be called from
// Swift or Objective-C using standard platform interop.

use crate::bridge;
use crate::error::ErrorCode;
use std::alloc;
use std::ffi::{CStr, CString};
use std::os::raw::{c_char, c_int, c_uint};
use std::ptr;

/// Vault handle type (opaque u64)
pub type VaultHandle = u64;

/// FFI-safe entry representation
#[repr(C)]
pub struct Entry {
    pub id: *const c_char,
    pub title: *const c_char,
    pub username: *const c_char,
    pub password: *const c_char,
    pub url: *const c_char,
    pub notes: *const c_char,
    pub created_at: i64,
    pub modified_at: i64,
    pub favorite: bool,
}

/// FFI-safe entry summary (for list views)
#[repr(C)]
pub struct EntrySummary {
    pub id: *const c_char,
    pub title: *const c_char,
    pub username: *const c_char,
    pub favorite: bool,
}

/// FFI-safe TOTP code representation
#[repr(C)]
pub struct TotpCode {
    pub code: *const c_char,
    pub seconds_remaining: u32,
}

/// FFI-safe password analysis result
#[repr(C)]
pub struct PasswordAnalysis {
    pub score: c_int, // 0-5 (0=very weak, 5=very strong)
    pub entropy_bits: f64,
    pub crack_time_seconds: f64,
    pub length: c_uint,
    pub has_lower: bool,
    pub has_upper: bool,
    pub has_digit: bool,
    pub has_symbol: bool,
}

/// Convert a Rust string to a C string
/// Returns a pointer that must be freed with sp_string_free
fn string_to_c(s: &str) -> *const c_char {
    match CString::new(s) {
        Ok(c_string) => c_string.into_raw(),
        Err(_) => ptr::null(),
    }
}

/// Convert a C string to a Rust string
fn c_to_string(ptr: *const c_char) -> Result<String, ErrorCode> {
    if ptr.is_null() {
        return Err(ErrorCode::InvalidParam);
    }

    unsafe {
        CStr::from_ptr(ptr)
            .to_str()
            .map(|s| s.to_owned())
            .map_err(|_| ErrorCode::InvalidParam)
    }
}

/// Convert BridgeResult to error code
fn result_to_code<T>(result: Result<T, crate::error::BridgeError>) -> ErrorCode {
    match result {
        Ok(_) => ErrorCode::Success,
        Err(e) => e.to_error_code(),
    }
}

// ============================================================================
// Vault Management
// ============================================================================

/// Initialize or unlock a vault
#[no_mangle]
pub unsafe extern "C" fn sp_vault_init(
    vault_path: *const c_char,
    master_password: *const c_char,
    out_handle: *mut VaultHandle,
) -> ErrorCode {
    let path = match c_to_string(vault_path) {
        Ok(p) => p,
        Err(_) => return ErrorCode::InvalidParam,
    };

    let password = match c_to_string(master_password) {
        Ok(p) => p,
        Err(_) => return ErrorCode::InvalidParam,
    };

    if out_handle.is_null() {
        return ErrorCode::InvalidParam;
    }

    match bridge::bridge_vault_init(&path, &password) {
        Ok(handle) => {
            *out_handle = handle;
            ErrorCode::Success
        }
        Err(e) => e.to_error_code(),
    }
}

/// Destroy a vault
#[no_mangle]
pub unsafe extern "C" fn sp_vault_destroy(handle: VaultHandle) -> ErrorCode {
    result_to_code(bridge::bridge_vault_destroy(handle))
}

/// Check if vault is unlocked
#[no_mangle]
pub unsafe extern "C" fn sp_vault_is_unlocked(
    handle: VaultHandle,
    out_unlocked: *mut bool,
) -> ErrorCode {
    if out_unlocked.is_null() {
        return ErrorCode::InvalidParam;
    }

    match bridge::bridge_vault_is_unlocked(handle) {
        Ok(unlocked) => {
            *out_unlocked = unlocked;
            ErrorCode::Success
        }
        Err(e) => e.to_error_code(),
    }
}

/// Lock the vault
#[no_mangle]
pub unsafe extern "C" fn sp_vault_lock(handle: VaultHandle) -> ErrorCode {
    result_to_code(bridge::bridge_vault_lock(handle))
}

// ============================================================================
// Entry Management
// ============================================================================

/// Add a new entry
#[no_mangle]
pub unsafe extern "C" fn sp_entry_add(
    handle: VaultHandle,
    title: *const c_char,
    username: *const c_char,
    password: *const c_char,
    url: *const c_char,
    notes: *const c_char,
    out_entry_id: *mut *const c_char,
) -> ErrorCode {
    if out_entry_id.is_null() {
        return ErrorCode::InvalidParam;
    }

    let title_str = match c_to_string(title) {
        Ok(s) => s,
        Err(_) => return ErrorCode::InvalidParam,
    };
    let username_str = match c_to_string(username) {
        Ok(s) => s,
        Err(_) => return ErrorCode::InvalidParam,
    };
    let password_str = match c_to_string(password) {
        Ok(s) => s,
        Err(_) => return ErrorCode::InvalidParam,
    };

    // Convert optional strings, handling null pointers
    let url_str = if url.is_null() {
        String::new()
    } else {
        match c_to_string(url) {
            Ok(s) => s,
            Err(_) => return ErrorCode::InvalidParam,
        }
    };
    let notes_str = if notes.is_null() {
        String::new()
    } else {
        match c_to_string(notes) {
            Ok(s) => s,
            Err(_) => return ErrorCode::InvalidParam,
        }
    };

    match bridge::bridge_entry_add(
        handle,
        &title_str,
        &username_str,
        &password_str,
        &url_str,
        &notes_str,
    ) {
        Ok(entry_id) => {
            *out_entry_id = string_to_c(&entry_id);
            ErrorCode::Success
        }
        Err(e) => e.to_error_code(),
    }
}

/// Get entry by ID
#[no_mangle]
pub unsafe extern "C" fn sp_entry_get_by_id(
    handle: VaultHandle,
    entry_id: *const c_char,
    out_entry: *mut Entry,
) -> ErrorCode {
    if out_entry.is_null() {
        return ErrorCode::InvalidParam;
    }

    let id_str = match c_to_string(entry_id) {
        Ok(s) => s,
        Err(_) => return ErrorCode::InvalidParam,
    };

    match bridge::bridge_entry_get(handle, &id_str) {
        Ok(entry) => {
            *out_entry = Entry {
                id: string_to_c(&entry.entry_id.map(|id| id.to_string()).unwrap_or_default()),
                title: string_to_c(&entry.title),
                username: string_to_c(&entry.username),
                password: string_to_c(&entry.password),
                url: string_to_c(entry.url.as_deref().unwrap_or("")),
                notes: string_to_c(entry.notes.as_deref().unwrap_or("")),
                created_at: entry.created_at.timestamp(),
                modified_at: entry.modified_at.timestamp(),
                favorite: entry.favorite,
            };
            ErrorCode::Success
        }
        Err(e) => e.to_error_code(),
    }
}

/// List all entries
#[no_mangle]
pub unsafe extern "C" fn sp_entry_list_all(
    handle: VaultHandle,
    out_entries: *mut *const EntrySummary,
    out_count: *mut usize,
) -> ErrorCode {
    if out_entries.is_null() || out_count.is_null() {
        return ErrorCode::InvalidParam;
    }

    match bridge::bridge_entry_list(handle) {
        Ok(summaries) => {
            let count = summaries.len();
            *out_count = count;

            if count == 0 {
                *out_entries = ptr::null();
                return ErrorCode::Success;
            }

            let layout = alloc::Layout::array::<EntrySummary>(count).unwrap();
            let entries_ptr = alloc::alloc(layout) as *mut EntrySummary;

            for (i, summary) in summaries.into_iter().enumerate() {
                let entry_ptr = entries_ptr.add(i);
                *entry_ptr = EntrySummary {
                    id: string_to_c(&summary.entry_id.to_string()),
                    title: string_to_c(&summary.title),
                    username: string_to_c(&summary.username),
                    favorite: summary.favorite,
                };
            }

            *out_entries = entries_ptr as *const EntrySummary;
            ErrorCode::Success
        }
        Err(e) => e.to_error_code(),
    }
}

/// Delete entry
#[no_mangle]
pub unsafe extern "C" fn sp_entry_delete(
    handle: VaultHandle,
    entry_id: *const c_char,
) -> ErrorCode {
    let id_str = match c_to_string(entry_id) {
        Ok(s) => s,
        Err(_) => return ErrorCode::InvalidParam,
    };
    result_to_code(bridge::bridge_entry_delete(handle, &id_str))
}

/// Search entries
#[no_mangle]
pub unsafe extern "C" fn sp_entry_search(
    handle: VaultHandle,
    query: *const c_char,
    out_entries: *mut *const EntrySummary,
    out_count: *mut usize,
) -> ErrorCode {
    if out_entries.is_null() || out_count.is_null() {
        return ErrorCode::InvalidParam;
    }

    let query_str = match c_to_string(query) {
        Ok(s) => s,
        Err(_) => return ErrorCode::InvalidParam,
    };

    match bridge::bridge_entry_search(handle, &query_str) {
        Ok(summaries) => {
            let count = summaries.len();
            *out_count = count;

            if count == 0 {
                *out_entries = ptr::null();
                return ErrorCode::Success;
            }

            let layout = alloc::Layout::array::<EntrySummary>(count).unwrap();
            let entries_ptr = alloc::alloc(layout) as *mut EntrySummary;

            for (i, summary) in summaries.into_iter().enumerate() {
                let entry_ptr = entries_ptr.add(i);
                *entry_ptr = EntrySummary {
                    id: string_to_c(&summary.entry_id.to_string()),
                    title: string_to_c(&summary.title),
                    username: string_to_c(&summary.username),
                    favorite: summary.favorite,
                };
            }

            *out_entries = entries_ptr as *const EntrySummary;
            ErrorCode::Success
        }
        Err(e) => e.to_error_code(),
    }
}

// ============================================================================
// TOTP
// ============================================================================

/// Generate TOTP code
#[no_mangle]
pub unsafe extern "C" fn sp_totp_generate_code(
    handle: VaultHandle,
    entry_id: *const c_char,
    out_code: *mut TotpCode,
) -> ErrorCode {
    if out_code.is_null() {
        return ErrorCode::InvalidParam;
    }

    let id_str = match c_to_string(entry_id) {
        Ok(s) => s,
        Err(_) => return ErrorCode::InvalidParam,
    };

    match bridge::bridge_totp_generate_code(handle, &id_str) {
        Ok(totp_info) => {
            *out_code = TotpCode {
                code: string_to_c(&totp_info.code),
                seconds_remaining: totp_info.seconds_remaining,
            };
            ErrorCode::Success
        }
        Err(e) => e.to_error_code(),
    }
}

// ============================================================================
// Password Generation
// ============================================================================

/// Generate password
#[no_mangle]
pub unsafe extern "C" fn sp_password_generate(
    length: usize,
    include_symbols: bool,
    out_password: *mut *const c_char,
) -> ErrorCode {
    if out_password.is_null() {
        return ErrorCode::InvalidParam;
    }

    if !(8..=128).contains(&length) {
        return ErrorCode::InvalidParam;
    }

    match bridge::bridge_password_generate(length, include_symbols) {
        Ok(password) => {
            *out_password = string_to_c(&password);
            ErrorCode::Success
        }
        Err(e) => e.to_error_code(),
    }
}

/// Check password strength
#[no_mangle]
pub unsafe extern "C" fn sp_password_check_strength(
    password: *const c_char,
    out_analysis: *mut PasswordAnalysis,
) -> ErrorCode {
    if out_analysis.is_null() {
        return ErrorCode::InvalidParam;
    }

    let password_str = match c_to_string(password) {
        Ok(s) => s,
        Err(_) => return ErrorCode::InvalidParam,
    };

    match bridge::bridge_password_check_strength(&password_str) {
        Ok(analysis) => {
            *out_analysis = PasswordAnalysis {
                score: analysis.strength.score() as c_int,
                entropy_bits: analysis.entropy_bits,
                crack_time_seconds: analysis.crack_time_seconds,
                length: analysis.length as c_uint,
                has_lower: analysis.has_lowercase,
                has_upper: analysis.has_uppercase,
                has_digit: analysis.has_digits,
                has_symbol: analysis.has_symbols,
            };
            ErrorCode::Success
        }
        Err(e) => e.to_error_code(),
    }
}

// ============================================================================
// Biometric
// ============================================================================

#[no_mangle]
pub unsafe extern "C" fn sp_biometric_set_key(
    handle: VaultHandle,
    key_data: *const u8,
    key_data_len: usize,
) -> ErrorCode {
    if key_data.is_null() || key_data_len == 0 {
        return ErrorCode::InvalidParam;
    }

    let slice = std::slice::from_raw_parts(key_data, key_data_len);
    result_to_code(bridge::bridge_biometric_set_key(handle, slice))
}

#[no_mangle]
pub unsafe extern "C" fn sp_biometric_has_key(
    handle: VaultHandle,
    out_has_key: *mut bool,
) -> ErrorCode {
    if out_has_key.is_null() {
        return ErrorCode::InvalidParam;
    }

    match bridge::bridge_biometric_has_key(handle) {
        Ok(has_key) => {
            *out_has_key = has_key;
            ErrorCode::Success
        }
        Err(e) => e.to_error_code(),
    }
}

#[no_mangle]
pub unsafe extern "C" fn sp_biometric_remove_key(handle: VaultHandle) -> ErrorCode {
    result_to_code(bridge::bridge_biometric_remove_key(handle))
}

#[no_mangle]
pub unsafe extern "C" fn sp_biometric_unlock(handle: VaultHandle) -> ErrorCode {
    result_to_code(bridge::bridge_biometric_unlock(handle))
}

// ============================================================================
// Sync Operations
// ============================================================================

/// FFI-safe sync status representation
#[repr(C)]
pub struct SyncStatus {
    pub enabled: bool,
    pub last_sync_at: i64,
    pub pending_changes: u64,
    pub device_id: *const c_char,
}

/// FFI-safe sync result representation
#[repr(C)]
pub struct SyncResult {
    pub success: bool,
    pub pushed: u64,
    pub pulled: u64,
    pub error_message: *const c_char,
}

/// Get sync status
#[no_mangle]
pub unsafe extern "C" fn sp_sync_get_status(
    handle: VaultHandle,
    out_status: *mut SyncStatus,
) -> ErrorCode {
    if out_status.is_null() {
        return ErrorCode::InvalidParam;
    }

    match bridge::bridge_sync_get_status(handle) {
        Ok(status) => {
            let device_id_str = status.device_id.unwrap_or_default();
            *out_status = SyncStatus {
                enabled: status.enabled,
                last_sync_at: status.last_sync_at.unwrap_or(0),
                pending_changes: status.pending_changes,
                device_id: string_to_c(&device_id_str),
            };
            ErrorCode::Success
        }
        Err(e) => e.to_error_code(),
    }
}

/// Collect entries pending sync (returns JSON bytes)
#[no_mangle]
pub unsafe extern "C" fn sp_sync_collect_pending(
    handle: VaultHandle,
    out_bytes: *mut *const u8,
    out_len: *mut usize,
) -> ErrorCode {
    if out_bytes.is_null() || out_len.is_null() {
        return ErrorCode::InvalidParam;
    }

    match bridge::bridge_sync_collect_pending(handle) {
        Ok(bytes) => {
            *out_len = bytes.len();
            *out_bytes = bytes.leak().as_ptr();
            ErrorCode::Success
        }
        Err(e) => e.to_error_code(),
    }
}

/// Apply downloaded entries (entries_json is JSON string)
#[no_mangle]
pub unsafe extern "C" fn sp_sync_apply_entries(
    handle: VaultHandle,
    entries_json: *const u8,
    entries_len: usize,
    out_applied: *mut u64,
) -> ErrorCode {
    if entries_json.is_null() || entries_len == 0 || out_applied.is_null() {
        return ErrorCode::InvalidParam;
    }

    let slice = std::slice::from_raw_parts(entries_json, entries_len);
    match bridge::bridge_sync_apply_entries(handle, slice) {
        Ok(applied) => {
            *out_applied = applied;
            ErrorCode::Success
        }
        Err(e) => e.to_error_code(),
    }
}

/// Prepare entries for CloudKit upload (returns JSON bytes of CloudKit records)
#[no_mangle]
pub unsafe extern "C" fn sp_sync_prepare_cloudkit(
    handle: VaultHandle,
    device_id: *const c_char,
    out_bytes: *mut *const u8,
    out_len: *mut usize,
) -> ErrorCode {
    if out_bytes.is_null() || out_len.is_null() {
        return ErrorCode::InvalidParam;
    }

    let device_id_str = match c_to_string(device_id) {
        Ok(s) => s,
        Err(_) => return ErrorCode::InvalidParam,
    };

    match bridge::bridge_sync_prepare_cloudkit(handle, &device_id_str) {
        Ok(bytes) => {
            *out_len = bytes.len();
            *out_bytes = bytes.leak().as_ptr();
            ErrorCode::Success
        }
        Err(e) => e.to_error_code(),
    }
}

/// Prepare entries for Google Drive upload (returns JSON bytes of Drive files)
#[no_mangle]
pub unsafe extern "C" fn sp_sync_prepare_drive(
    handle: VaultHandle,
    device_id: *const c_char,
    out_bytes: *mut *const u8,
    out_len: *mut usize,
) -> ErrorCode {
    if out_bytes.is_null() || out_len.is_null() {
        return ErrorCode::InvalidParam;
    }

    let device_id_str = match c_to_string(device_id) {
        Ok(s) => s,
        Err(_) => return ErrorCode::InvalidParam,
    };

    match bridge::bridge_sync_prepare_drive(handle, &device_id_str) {
        Ok(bytes) => {
            *out_len = bytes.len();
            *out_bytes = bytes.leak().as_ptr();
            ErrorCode::Success
        }
        Err(e) => e.to_error_code(),
    }
}

// ============================================================================
// Memory Management
// ============================================================================

#[no_mangle]
pub unsafe extern "C" fn sp_string_free(ptr: *const c_char) {
    if !ptr.is_null() {
        let _ = CString::from_raw(ptr as *mut c_char);
    }
}

#[no_mangle]
pub unsafe extern "C" fn sp_bytes_free(ptr: *const u8, len: usize) {
    if !ptr.is_null() && len > 0 {
        let layout = alloc::Layout::from_size_align_unchecked(len, 1);
        alloc::dealloc(ptr as *mut u8, layout);
    }
}

// ============================================================================
// ABI contract tests (WBS-801)
// ============================================================================
//
// The cbindgen-generated header (`include/sentinelpass_bridge.h`, produced by
// build.rs from cbindgen.toml) is the single C ABI contract consumed by Swift.
// These tests pin the header to the real export surface so the contract can
// never drift silently; CI additionally regenerates the header and fails on
// any diff.

#[cfg(test)]
mod abi_contract_tests {
    use std::fs;
    use std::path::PathBuf;

    fn header_text() -> String {
        let path = PathBuf::from(env!("CARGO_MANIFEST_DIR"))
            .join("include")
            .join("sentinelpass_bridge.h");
        fs::read_to_string(&path).unwrap_or_else(|e| {
            panic!(
                "generated header missing at {:?}: {} (build.rs writes it on every build)",
                path, e
            )
        })
    }

    /// Extract the names of all `extern "C" fn` exports defined in this file.
    fn ffi_export_names() -> Vec<String> {
        let src = fs::read_to_string(PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("src/ffi.rs"))
            .expect("ffi.rs source readable");
        let mut names = Vec::new();
        for line in src.lines() {
            if let Some(idx) = line.find("extern \"C\" fn ") {
                let rest = &line[idx + "extern \"C\" fn ".len()..];
                let name: String = rest
                    .chars()
                    .take_while(|c| c.is_alphanumeric() || *c == '_')
                    .collect();
                if !name.is_empty() {
                    names.push(name);
                }
            }
        }
        names.sort();
        names.dedup();
        names
    }

    /// The declared C ABI contract: every function exported to Swift. Must be
    /// kept in lockstep with cbindgen.toml `[export] include`.
    const DECLARED_C_ABI: &[&str] = &[
        "sp_biometric_has_key",
        "sp_biometric_remove_key",
        "sp_biometric_set_key",
        "sp_biometric_unlock",
        "sp_bytes_free",
        "sp_entry_add",
        "sp_entry_delete",
        "sp_entry_get_by_id",
        "sp_entry_list_all",
        "sp_entry_search",
        "sp_password_check_strength",
        "sp_password_generate",
        "sp_string_free",
        "sp_sync_apply_entries",
        "sp_sync_collect_pending",
        "sp_sync_get_status",
        // Removed under WBS-807 (ADR-009 rev 2: relay-only mobile sync).
        "sp_sync_prepare_cloudkit",
        "sp_sync_prepare_drive",
        "sp_totp_generate_code",
        "sp_vault_destroy",
        "sp_vault_init",
        "sp_vault_is_unlocked",
        "sp_vault_lock",
    ];

    #[test]
    fn declared_abi_matches_ffi_surface() {
        let mut declared: Vec<String> = DECLARED_C_ABI.iter().map(|s| s.to_string()).collect();
        declared.sort();
        assert_eq!(
            ffi_export_names(),
            declared,
            "src/ffi.rs exports and the declared C ABI contract (DECLARED_C_ABI / cbindgen.toml) diverged; update both together"
        );
    }

    #[test]
    fn header_declares_every_export() {
        let header = header_text();
        for name in ffi_export_names() {
            assert!(
                header.contains(&format!("{}(", name)),
                "generated header does not declare exported symbol `{}` — the C ABI contract drifted; rebuild to regenerate include/sentinelpass_bridge.h and commit it",
                name
            );
        }
    }

    #[test]
    fn header_declares_sp_error_code() {
        let header = header_text();
        assert!(
            header.contains("SPErrorCode_InvalidParam"),
            "generated header must declare the SPErrorCode enum"
        );
        assert!(
            header.contains("} SPErrorCode;"),
            "generated header must declare the SPErrorCode enum type"
        );
    }
}
