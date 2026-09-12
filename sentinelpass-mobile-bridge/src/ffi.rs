// FFI exports for iOS (C ABI)
//
// These functions are exported with C linkage and can be called from
// Swift or Objective-C using standard platform interop.
//
// # Ownership contract (WBS-804 — the single proven ownership rule set)
//
// Every rule applies uniformly; there are no exceptions buried in individual
// functions:
//
// 1. IN-STRINGS (`const char *`, `const uint8_t *`): borrowed. The caller
//    keeps them valid for the duration of the call; the bridge never frees
//    them and never retains them past the call.
// 2. OUT-STRINGS (`const char **`): allocated by the bridge with the Rust
//    allocator (`CString::into_raw`). The caller MUST release each one with
//    `sp_string_free`, exactly once. A null out-string on `Success` means
//    the field is absent (optional field semantics), not a failure.
// 3. OUT-BYTE-BUFFERS (`const uint8_t **` + `uintptr_t *`): allocated by the
//    bridge with `alloc` under `Layout::array::<u8>(len)`. The caller MUST
//    release with `sp_bytes_free(ptr, len)` using the SAME `len` that was
//    output. `sp_bytes_free` is valid only on buffers produced by the
//    bridge — never on buffers the caller allocated.
// 4. OUT-STRUCTS (`SPEntry`, `SPTotpCode`, `SPBridgeInfo`, `SyncStatus`):
//    written by the callee into caller-provided storage. String members
//    inside them follow rule 2 (`sp_string_free`); `SPTotpCode.code` and
//    `SyncStatus.device_id` each own one string.
// 5. STRUCT ARRAYS (`SPEntrySummary *` + count): allocated by the bridge.
//    The caller MUST release with `sp_entry_list_free(ptr, count)`, which
//    frees every element's strings and the backing array. Do not free the
//    array or its strings individually.
// 6. SINGLE OUT-ENTRIES (`SPEntry` written by `sp_entry_get_by_id`): the
//    caller MUST release with `sp_entry_free(entry)`, which frees all six
//    string members.
// 7. HANDLES (`SPVaultHandle`): created by `sp_vault_init`, destroyed by
//    `sp_vault_destroy`. Use-after-destroy and double-destroy return
//    `InvalidParam` (WBS-806 tests enforce this); destroying a handle also
//    zeroizes any registered biometric key material (WBS-804).
// 8. PANIC CONTAINMENT: no Rust panic ever unwinds across this boundary
//    (WBS-805 `catch_unwind` on every exported function); a contained panic
//    surfaces as the documented error code, never as an abort in the host
//    process.
//
// The generated header (cbindgen) carries the same rules per function via
// doc comments; `include/sentinelpass_bridge.h` is the contract Swift sees.

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

/// Copy `bytes` into a caller-freeable allocation.
///
/// Ownership (WBS-804 rule 3): the returned buffer is allocated with `alloc`
/// under `Layout::array::<u8>(len)`, so `sp_bytes_free(ptr, bytes.len())`
/// deallocates with the EXACT layout used here — no `Vec::leak`/layout
/// mismatch. Returns null on allocation failure.
fn bytes_to_c_buffer(bytes: &[u8]) -> *const u8 {
    if bytes.is_empty() {
        return ptr::null();
    }
    let layout = match alloc::Layout::array::<u8>(bytes.len()) {
        Ok(l) => l,
        Err(_) => return ptr::null(),
    };
    unsafe {
        let dst = alloc::alloc(layout);
        if dst.is_null() {
            return ptr::null();
        }
        ptr::copy_nonoverlapping(bytes.as_ptr(), dst, bytes.len());
        dst as *const u8
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
// ABI / Feature Negotiation (WBS-803)
// ============================================================================

/// ABI/feature description reported to consumers (WBS-803).
#[repr(C)]
pub struct BridgeInfo {
    pub abi_version: u32,
    pub min_supported_abi_version: u32,
    pub feature_flags: u32,
    /// Must be zero; reserved for future growth so the struct can gain
    /// fields without breaking consumers that zero-initialize it.
    pub reserved: u32,
}

/// Report this build's ABI version and feature flags.
///
/// Ownership: `out_info` is written by the callee; no allocation is
/// performed and nothing needs freeing.
#[no_mangle]
pub unsafe extern "C" fn sp_bridge_info(out_info: *mut BridgeInfo) -> ErrorCode {
    if out_info.is_null() {
        return ErrorCode::InvalidParam;
    }
    let info = crate::abi::abi_info();
    *out_info = BridgeInfo {
        abi_version: info.abi_version,
        min_supported_abi_version: info.min_supported_abi_version,
        feature_flags: info.feature_flags,
        reserved: 0,
    };
    ErrorCode::Success
}

/// Negotiate a consumer's ABI version against this build (WBS-803).
///
/// `client_abi_version` is the ABI the caller was built against. On success
/// (`Success`) the versions are compatible and `out_info` describes this
/// build; the caller must feature-test `feature_flags` before using optional
/// capabilities. On `AbiUnsupported` the caller MUST refuse to operate; the
/// header contract is versioned as one unit, so an unsupported consumer
/// cannot assume any other symbol's signature. `out_info` (if non-null) is
/// filled even on failure so the caller can report the mismatch.
#[no_mangle]
pub unsafe extern "C" fn sp_bridge_negotiate(
    client_abi_version: u32,
    out_info: *mut BridgeInfo,
) -> ErrorCode {
    if out_info.is_null() {
        return ErrorCode::InvalidParam;
    }
    match crate::abi::negotiate(client_abi_version) {
        Ok(info) => {
            *out_info = BridgeInfo {
                abi_version: info.abi_version,
                min_supported_abi_version: info.min_supported_abi_version,
                feature_flags: info.feature_flags,
                reserved: 0,
            };
            ErrorCode::Success
        }
        Err(e) => {
            let info = crate::abi::abi_info();
            *out_info = BridgeInfo {
                abi_version: info.abi_version,
                min_supported_abi_version: info.min_supported_abi_version,
                feature_flags: info.feature_flags,
                reserved: 0,
            };
            e.to_error_code()
        }
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

            let layout = match alloc::Layout::array::<EntrySummary>(count) {
                Ok(l) => l,
                Err(_) => return ErrorCode::OutOfMemory,
            };
            let entries_ptr = alloc::alloc(layout) as *mut EntrySummary;
            if entries_ptr.is_null() {
                return ErrorCode::OutOfMemory;
            }

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

            let layout = match alloc::Layout::array::<EntrySummary>(count) {
                Ok(l) => l,
                Err(_) => return ErrorCode::OutOfMemory,
            };
            let entries_ptr = alloc::alloc(layout) as *mut EntrySummary;
            if entries_ptr.is_null() {
                return ErrorCode::OutOfMemory;
            }

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
            let buf = bytes_to_c_buffer(&bytes);
            if buf.is_null() && !bytes.is_empty() {
                return ErrorCode::OutOfMemory;
            }
            *out_len = bytes.len();
            *out_bytes = buf;
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
            let buf = bytes_to_c_buffer(&bytes);
            if buf.is_null() && !bytes.is_empty() {
                return ErrorCode::OutOfMemory;
            }
            *out_len = bytes.len();
            *out_bytes = buf;
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
            let buf = bytes_to_c_buffer(&bytes);
            if buf.is_null() && !bytes.is_empty() {
                return ErrorCode::OutOfMemory;
            }
            *out_len = bytes.len();
            *out_bytes = buf;
            ErrorCode::Success
        }
        Err(e) => e.to_error_code(),
    }
}

// ============================================================================
// Memory Management (WBS-804: single proven ownership contract)
// ============================================================================

/// Free a string returned by the bridge (out-strings, `SPTotpCode.code`,
/// `SyncStatus.device_id`). Safe on null. Must be called exactly once per
/// bridge-allocated string; never on strings the caller allocated.
#[no_mangle]
pub unsafe extern "C" fn sp_string_free(ptr: *const c_char) {
    if !ptr.is_null() {
        drop(CString::from_raw(ptr as *mut c_char));
    }
}

/// Free a byte buffer returned by the bridge, using the same `len` that the
/// producing call output. The buffer is deallocated with the exact layout
/// used at allocation (`Layout::array::<u8>(len)`); passing a different
/// `len` is a caller bug. Never call this on buffers the caller allocated.
#[no_mangle]
pub unsafe extern "C" fn sp_bytes_free(ptr: *const u8, len: usize) {
    if !ptr.is_null() && len > 0 {
        if let Ok(layout) = alloc::Layout::array::<u8>(len) {
            alloc::dealloc(ptr as *mut u8, layout);
        }
    }
}

/// Free one `SPEntry` returned by `sp_entry_get_by_id`, releasing all six
/// string members. The struct storage itself is caller-provided and is NOT
/// freed here. Safe on null.
#[no_mangle]
pub unsafe extern "C" fn sp_entry_free(entry: *mut Entry) {
    if entry.is_null() {
        return;
    }
    let e = &mut *entry;
    for s in [e.id, e.title, e.username, e.password, e.url, e.notes] {
        if !s.is_null() {
            drop(CString::from_raw(s as *mut c_char));
        }
    }
}

/// Free an `SPEntrySummary` array returned by `sp_entry_list_all` /
/// `sp_entry_search`, releasing every element's strings and the backing
/// array (allocated under `Layout::array::<EntrySummary>(count)`). Safe on
/// null or `count == 0`.
#[no_mangle]
pub unsafe extern "C" fn sp_entry_list_free(entries: *mut EntrySummary, count: usize) {
    if entries.is_null() || count == 0 {
        return;
    }
    for i in 0..count {
        let s = &*entries.add(i);
        for p in [s.id, s.title, s.username] {
            if !p.is_null() {
                drop(CString::from_raw(p as *mut c_char));
            }
        }
    }
    if let Ok(layout) = alloc::Layout::array::<EntrySummary>(count) {
        alloc::dealloc(entries as *mut u8, layout);
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
    use super::{sp_bridge_info, sp_bridge_negotiate, BridgeInfo, ErrorCode};
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
        "sp_bridge_info",
        "sp_bridge_negotiate",
        "sp_entry_free",
        "sp_entry_list_free",
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

    #[test]
    fn sp_bridge_info_reports_abi_and_flags() {
        let mut info = BridgeInfo {
            abi_version: 0,
            min_supported_abi_version: 0,
            feature_flags: 0,
            reserved: 1,
        };
        let code = unsafe { sp_bridge_info(&mut info) };
        assert_eq!(code, ErrorCode::Success);
        assert_eq!(info.abi_version, crate::abi::ABI_VERSION);
        assert_eq!(
            info.min_supported_abi_version,
            crate::abi::MIN_SUPPORTED_ABI_VERSION
        );
        assert_eq!(info.reserved, 0, "reserved must be zeroed by the callee");
    }

    #[test]
    fn sp_bridge_info_rejects_null() {
        let code = unsafe { sp_bridge_info(std::ptr::null_mut()) };
        assert_eq!(code, ErrorCode::InvalidParam);
    }

    #[test]
    fn sp_bridge_negotiate_round_trip() {
        let mut info = BridgeInfo {
            abi_version: 0,
            min_supported_abi_version: 0,
            feature_flags: 0,
            reserved: 0,
        };
        let code = unsafe { sp_bridge_negotiate(crate::abi::ABI_VERSION, &mut info) };
        assert_eq!(code, ErrorCode::Success);
        assert_eq!(info.abi_version, crate::abi::ABI_VERSION);
    }

    #[test]
    fn sp_bridge_negotiate_rejects_mismatch_but_reports_info() {
        let mut info = BridgeInfo {
            abi_version: 0,
            min_supported_abi_version: 0,
            feature_flags: 0,
            reserved: 0,
        };
        let code = unsafe { sp_bridge_negotiate(crate::abi::ABI_VERSION + 1, &mut info) };
        assert_eq!(code, ErrorCode::AbiUnsupported);
        assert_eq!(
            info.abi_version,
            crate::abi::ABI_VERSION,
            "out_info must describe this build even on refusal"
        );
    }

    #[test]
    fn sp_bridge_negotiate_rejects_null() {
        let code = unsafe { sp_bridge_negotiate(crate::abi::ABI_VERSION, std::ptr::null_mut()) };
        assert_eq!(code, ErrorCode::InvalidParam);
    }
}

/// WBS-804 ownership round-trips: every bridge allocation has exactly one
/// sanctioned release path, exercised end-to-end here against a real vault.
#[cfg(test)]
mod ownership_tests {
    use super::*;
    use std::ffi::CString;
    use std::sync::atomic::{AtomicU32, Ordering};

    static TEST_SEQ: AtomicU32 = AtomicU32::new(0);

    fn cstr(s: &str) -> CString {
        CString::new(s).expect("test strings contain no NUL")
    }

    /// Create a fresh unlocked temp vault and return (dir, handle).
    fn temp_vault() -> (std::path::PathBuf, VaultHandle) {
        let dir = std::env::temp_dir().join(format!(
            "sp_ffi_ownership_{}_{}",
            std::process::id(),
            TEST_SEQ.fetch_add(1, Ordering::SeqCst)
        ));
        std::fs::create_dir_all(&dir).expect("create temp dir");
        let vault_path = dir.join("vault.db");
        let mut handle: VaultHandle = 0;
        let code = unsafe {
            sp_vault_init(
                cstr(vault_path.to_str().unwrap()).as_ptr(),
                cstr("test-master-password").as_ptr(),
                &mut handle,
            )
        };
        assert_eq!(code, ErrorCode::Success, "temp vault init must succeed");
        (dir, handle)
    }

    fn add_entry(handle: VaultHandle, title: &str) -> String {
        let mut id_ptr: *const c_char = std::ptr::null();
        let code = unsafe {
            sp_entry_add(
                handle,
                cstr(title).as_ptr(),
                cstr("user").as_ptr(),
                cstr("secret-password").as_ptr(),
                cstr("https://example.com").as_ptr(),
                cstr("notes").as_ptr(),
                &mut id_ptr,
            )
        };
        assert_eq!(code, ErrorCode::Success);
        let id = unsafe { CStr::from_ptr(id_ptr) }
            .to_string_lossy()
            .into_owned();
        unsafe { sp_string_free(id_ptr) };
        id
    }

    #[test]
    fn entry_get_roundtrip_then_sp_entry_free() {
        let (dir, handle) = temp_vault();
        let id = add_entry(handle, "roundtrip");

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
        let code = unsafe { sp_entry_get_by_id(handle, cstr(&id).as_ptr(), &mut entry) };
        assert_eq!(code, ErrorCode::Success);

        // Borrowed view of the out-strings BEFORE freeing.
        let title = unsafe { CStr::from_ptr(entry.title) }
            .to_string_lossy()
            .into_owned();
        let password = unsafe { CStr::from_ptr(entry.password) }
            .to_string_lossy()
            .into_owned();
        assert_eq!(title, "roundtrip");
        assert_eq!(password, "secret-password");
        assert_eq!(unsafe { CStr::from_ptr(entry.id) }.to_string_lossy(), id);

        // The single sanctioned release path for an SPEntry.
        unsafe { sp_entry_free(&mut entry) };
        assert!(
            bridge::bridge_vault_destroy(handle).is_ok(),
            "destroy must succeed"
        );
        let _ = std::fs::remove_dir_all(dir);
    }

    #[test]
    fn entry_list_roundtrip_then_sp_entry_list_free() {
        let (dir, handle) = temp_vault();
        add_entry(handle, "alpha");
        add_entry(handle, "beta");

        let mut list: *const EntrySummary = std::ptr::null();
        let mut count: usize = 0;
        let code = unsafe { sp_entry_list_all(handle, &mut list, &mut count) };
        assert_eq!(code, ErrorCode::Success);
        assert_eq!(count, 2);

        let first_title = unsafe { CStr::from_ptr((*list).title) }
            .to_string_lossy()
            .into_owned();
        assert!(first_title == "alpha" || first_title == "beta");

        // The single sanctioned release path for a summary array.
        unsafe { sp_entry_list_free(list as *mut EntrySummary, count) };
        assert!(
            bridge::bridge_vault_destroy(handle).is_ok(),
            "destroy must succeed"
        );
        let _ = std::fs::remove_dir_all(dir);
    }

    #[test]
    fn byte_buffer_roundtrip_then_sp_bytes_free() {
        let (dir, handle) = temp_vault();
        add_entry(handle, "buffered");

        let mut buf: *const u8 = std::ptr::null();
        let mut len: usize = 0;
        let code = unsafe { sp_sync_collect_pending(handle, &mut buf, &mut len) };
        assert_eq!(code, ErrorCode::Success);
        assert!(!buf.is_null());
        assert!(len > 0);

        // Buffer content must be readable up to len (caller side).
        let slice = unsafe { std::slice::from_raw_parts(buf, len) };
        assert!(!slice.is_empty());

        // The single sanctioned release path, with the SAME len.
        unsafe { sp_bytes_free(buf, len) };
        assert!(
            bridge::bridge_vault_destroy(handle).is_ok(),
            "destroy must succeed"
        );
        let _ = std::fs::remove_dir_all(dir);
    }

    #[test]
    fn string_free_null_safe_and_destroy_clears_registered_keys() {
        // sp_string_free/sp_entry_free are safe on null.
        unsafe { sp_string_free(std::ptr::null()) };
        unsafe { sp_entry_free(std::ptr::null_mut()) };
        unsafe { sp_entry_list_free(std::ptr::null_mut(), 0) };
        unsafe { sp_bytes_free(std::ptr::null(), 0) };

        // Destroy removes the registry entry (use-after-destroy fails) and
        // drops the zeroizing biometric buffer with it.
        let (dir, handle) = temp_vault();
        bridge::bridge_biometric_set_key(handle, &[1u8, 2, 3, 4]).expect("set key");
        assert!(
            bridge::bridge_biometric_has_key(handle).unwrap_or(false),
            "biometric key must be set"
        );
        assert!(
            bridge::bridge_vault_destroy(handle).is_ok(),
            "destroy must succeed"
        );
        assert!(
            !bridge::bridge_biometric_has_key(handle).unwrap_or(true),
            "biometric key must be gone after destroy (zeroized on drop)"
        );
        assert!(
            bridge::bridge_vault_is_unlocked(handle).is_err(),
            "handle invalid after destroy"
        );
        assert!(
            bridge::bridge_vault_destroy(handle).is_err(),
            "double destroy must be refused"
        );
        let _ = std::fs::remove_dir_all(dir);
    }
}
