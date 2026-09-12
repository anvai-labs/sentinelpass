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
//    `sp_string_free`, exactly once. NULL out-strings: for OPTIONAL fields
//    (`SPEntry.url`/`notes`, `SyncStatus.device_id`) NULL on `Success` means
//    the field is absent. REQUIRED strings (`id`, `title`, `username`,
//    `password`, `SPTotpCode.code`, generated passwords, entry ids) are
//    never NULL on `Success` — bridge inputs arrive as C strings, which
//    cannot contain interior NUL, so the NUL case is unreachable defense.
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
///
/// Currently unused (the WBS-807 placeholder removal left no byte-buffer
/// producer) but retained as the ONLY sanctioned producer shape for future
/// buffer exports (authenticated backup, WBS-827) so the ownership contract
/// stays single-proven.
#[allow(dead_code)]
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

/// WBS-805 panic containment: no Rust panic may unwind across the C ABI
/// boundary (unwinding into Swift/ObjC is undefined behavior). Every exported
/// function body runs inside this wrapper; a contained panic is logged and
/// surfaces as [`ErrorCode::Panic`]. Out-params written before the panic must
/// be treated as undefined by the caller (see the ownership contract, rule 8).
fn catch_panic<F>(op: F) -> ErrorCode
where
    F: FnOnce() -> ErrorCode,
{
    match std::panic::catch_unwind(std::panic::AssertUnwindSafe(op)) {
        Ok(code) => code,
        Err(payload) => {
            let detail = payload
                .downcast_ref::<&str>()
                .copied()
                .or_else(|| payload.downcast_ref::<String>().map(|s| s.as_str()))
                .unwrap_or("<non-string panic payload>");
            tracing::error!(target: "mobile_bridge", "contained panic at C ABI boundary: {detail}");
            ErrorCode::Panic
        }
    }
}

/// Void-returning variant of [`catch_panic`] for the memory-management
/// exports (frees report nothing; a contained panic there is logged and the
/// free is treated as not having happened — callers must not retry frees).
fn catch_panic_void<F>(op: F)
where
    F: FnOnce(),
{
    let _ = catch_panic(move || {
        op();
        ErrorCode::Success
    });
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
    catch_panic(|| {
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
    })
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
    catch_panic(|| {
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
    })
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
    catch_panic(|| {
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
    })
}

/// Destroy a vault
#[no_mangle]
pub unsafe extern "C" fn sp_vault_destroy(handle: VaultHandle) -> ErrorCode {
    catch_panic(|| result_to_code(bridge::bridge_vault_destroy(handle)))
}

/// Check if vault is unlocked
#[no_mangle]
pub unsafe extern "C" fn sp_vault_is_unlocked(
    handle: VaultHandle,
    out_unlocked: *mut bool,
) -> ErrorCode {
    catch_panic(|| {
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
    })
}

/// Lock the vault
#[no_mangle]
pub unsafe extern "C" fn sp_vault_lock(handle: VaultHandle) -> ErrorCode {
    catch_panic(|| result_to_code(bridge::bridge_vault_lock(handle)))
}

// ============================================================================
// Entry Management
// ============================================================================

/// Add a new entry.
///
/// Ownership (WBS-804 rule 2): on `Success` the caller MUST release
/// `*out_entry_id` with `sp_string_free`.
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
    catch_panic(|| {
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
    })
}

/// Get entry by ID.
///
/// Ownership (WBS-804 rule 6): on `Success` the caller MUST release the
/// strings with `sp_entry_free(&mut entry)`. `url`/`notes` are NULL when the
/// entry has no such field (rule 2); `id`/`title`/`username`/`password` are
/// never NULL on `Success`.
#[no_mangle]
pub unsafe extern "C" fn sp_entry_get_by_id(
    handle: VaultHandle,
    entry_id: *const c_char,
    out_entry: *mut Entry,
) -> ErrorCode {
    catch_panic(|| {
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
                    // Rule 2: absent optional fields are NULL, not "".
                    url: entry.url.as_deref().map(string_to_c).unwrap_or(ptr::null()),
                    notes: entry
                        .notes
                        .as_deref()
                        .map(string_to_c)
                        .unwrap_or(ptr::null()),
                    created_at: entry.created_at.timestamp(),
                    modified_at: entry.modified_at.timestamp(),
                    favorite: entry.favorite,
                };
                ErrorCode::Success
            }
            Err(e) => e.to_error_code(),
        }
    })
}

/// Update an existing entry (WBS-807: ATOMIC update).
///
/// A null argument means "leave this field unchanged"; a non-null empty
/// string clears `url`/`notes`. One call, one transaction — the caller never
/// needs delete-then-add (which would lose history and race concurrent
/// readers).
#[no_mangle]
pub unsafe extern "C" fn sp_entry_update(
    handle: VaultHandle,
    entry_id: *const c_char,
    title: *const c_char,
    username: *const c_char,
    password: *const c_char,
    url: *const c_char,
    notes: *const c_char,
) -> ErrorCode {
    catch_panic(|| {
        let id_str = match c_to_string(entry_id) {
            Ok(s) => s,
            Err(_) => return ErrorCode::InvalidParam,
        };

        // null = unchanged; present = set (empty clears url/notes).
        let opt = |p: *const c_char| -> Result<Option<String>, ErrorCode> {
            if p.is_null() {
                Ok(None)
            } else {
                c_to_string(p).map(Some)
            }
        };

        let title_opt = match opt(title) {
            Ok(v) => v,
            Err(c) => return c,
        };
        let username_opt = match opt(username) {
            Ok(v) => v,
            Err(c) => return c,
        };
        let password_opt = match opt(password) {
            Ok(v) => v,
            Err(c) => return c,
        };
        let url_opt = match opt(url) {
            Ok(v) => v,
            Err(c) => return c,
        };
        let notes_opt = match opt(notes) {
            Ok(v) => v,
            Err(c) => return c,
        };

        result_to_code(bridge::bridge_entry_update(
            handle,
            &id_str,
            title_opt.as_deref(),
            username_opt.as_deref(),
            password_opt.as_deref(),
            url_opt.as_deref(),
            notes_opt.as_deref(),
        ))
    })
}

/// List all entries.
///
/// Ownership (WBS-804 rule 5): on `Success` the caller MUST release the
/// array with `sp_entry_list_free(*out_entries, *out_count)`.
#[no_mangle]
pub unsafe extern "C" fn sp_entry_list_all(
    handle: VaultHandle,
    out_entries: *mut *const EntrySummary,
    out_count: *mut usize,
) -> ErrorCode {
    catch_panic(|| {
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
    })
}

/// Delete entry
#[no_mangle]
pub unsafe extern "C" fn sp_entry_delete(
    handle: VaultHandle,
    entry_id: *const c_char,
) -> ErrorCode {
    catch_panic(|| {
        let id_str = match c_to_string(entry_id) {
            Ok(s) => s,
            Err(_) => return ErrorCode::InvalidParam,
        };
        result_to_code(bridge::bridge_entry_delete(handle, &id_str))
    })
}

/// Search entries.
///
/// Ownership (WBS-804 rule 5): on `Success` the caller MUST release the
/// array with `sp_entry_list_free(*out_entries, *out_count)`.
#[no_mangle]
pub unsafe extern "C" fn sp_entry_search(
    handle: VaultHandle,
    query: *const c_char,
    out_entries: *mut *const EntrySummary,
    out_count: *mut usize,
) -> ErrorCode {
    catch_panic(|| {
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
    })
}

// ============================================================================
// TOTP
// ============================================================================

/// Generate TOTP code.
///
/// Ownership (WBS-804 rule 4): on `Success` the caller MUST release
/// `out_code.code` with `sp_string_free`.
#[no_mangle]
pub unsafe extern "C" fn sp_totp_generate_code(
    handle: VaultHandle,
    entry_id: *const c_char,
    out_code: *mut TotpCode,
) -> ErrorCode {
    catch_panic(|| {
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
    })
}

// ============================================================================
// Password Generation
// ============================================================================

/// Generate a password (8..=128 chars).
///
/// Ownership (WBS-804 rule 2): on `Success` the caller MUST release
/// `*out_password` with `sp_string_free`.
#[no_mangle]
pub unsafe extern "C" fn sp_password_generate(
    length: usize,
    include_symbols: bool,
    out_password: *mut *const c_char,
) -> ErrorCode {
    catch_panic(|| {
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
    })
}

/// Check password strength.
///
/// Ownership: `out_analysis` is plain data written by the callee; nothing to
/// free (WBS-804 rule 4).
#[no_mangle]
pub unsafe extern "C" fn sp_password_check_strength(
    password: *const c_char,
    out_analysis: *mut PasswordAnalysis,
) -> ErrorCode {
    catch_panic(|| {
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
    })
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

/// Get sync status.
///
/// Ownership (WBS-804 rule 4): on `Success` the caller MUST release
/// `out_status.device_id` with `sp_string_free` (NULL when no device is
/// registered — rule 2). Sync stays disabled until the mobile relay sync v2
/// surface is wired (ADR-006/ADR-009; the CloudKit/Drive placeholders were
/// removed under WBS-807).
#[no_mangle]
pub unsafe extern "C" fn sp_sync_get_status(
    handle: VaultHandle,
    out_status: *mut SyncStatus,
) -> ErrorCode {
    catch_panic(|| {
        if out_status.is_null() {
            return ErrorCode::InvalidParam;
        }

        match bridge::bridge_sync_get_status(handle) {
            Ok(status) => {
                *out_status = SyncStatus {
                    enabled: status.enabled,
                    last_sync_at: status.last_sync_at.unwrap_or(0),
                    pending_changes: status.pending_changes,
                    // Rule 2: absent device_id is NULL, not "".
                    device_id: status
                        .device_id
                        .as_deref()
                        .map(string_to_c)
                        .unwrap_or(ptr::null()),
                };
                ErrorCode::Success
            }
            Err(e) => e.to_error_code(),
        }
    })
}

// ============================================================================
// Platform slot (WBS-812/821): auth-bound Keystore/Keychain DEK wrap
// ============================================================================

/// Draw a fresh 32-byte challenge (hex) for the platform's auth-bound key to
/// sign. Ownership rule 2: release `out_hex` with `sp_string_free`.
#[no_mangle]
pub unsafe extern "C" fn sp_slot_challenge(out_hex: *mut *const c_char) -> ErrorCode {
    catch_panic(|| {
        if out_hex.is_null() {
            return ErrorCode::InvalidParam;
        }
        match crate::slot::bridge_slot_challenge() {
            Ok(hex) => {
                *out_hex = string_to_c(&hex);
                ErrorCode::Success
            }
            Err(e) => e.to_error_code(),
        }
    })
}

/// Seal the vault DEK under the platform signature (ENABLE).
///
/// `challenge`/`sig_a`/`sig_b` are hex strings from the host platform: the
/// challenge the auth-bound key signed and TWO byte-identical signatures
/// (deterministic scheme). `binding` is the caller-stable vault identity.
/// Ownership rule 2: on `Success` release `out_blob` (the NON-SECRET
/// at-rest blob JSON) with `sp_string_free`.
#[no_mangle]
pub unsafe extern "C" fn sp_slot_seal(
    handle: VaultHandle,
    challenge: *const c_char,
    sig_a: *const c_char,
    sig_b: *const c_char,
    binding: *const c_char,
    out_blob: *mut *const c_char,
) -> ErrorCode {
    catch_panic(|| {
        if out_blob.is_null() {
            return ErrorCode::InvalidParam;
        }
        let challenge_s = match c_to_string(challenge) {
            Ok(s) => s,
            Err(_) => return ErrorCode::InvalidParam,
        };
        let sig_a_s = match c_to_string(sig_a) {
            Ok(s) => s,
            Err(_) => return ErrorCode::InvalidParam,
        };
        let sig_b_s = match c_to_string(sig_b) {
            Ok(s) => s,
            Err(_) => return ErrorCode::InvalidParam,
        };
        let binding_s = match c_to_string(binding) {
            Ok(s) => s,
            Err(_) => return ErrorCode::InvalidParam,
        };

        match crate::slot::bridge_slot_seal(handle, &challenge_s, &sig_a_s, &sig_b_s, &binding_s) {
            Ok(blob) => {
                *out_blob = string_to_c(&blob);
                ErrorCode::Success
            }
            Err(e) => e.to_error_code(),
        }
    })
}

/// Release the DEK from the slot blob with a fresh platform signature over
/// the blob's challenge and OPEN the vault (UNLOCK). Fails closed on any
/// mismatch. Ownership rule 7: the returned handle must be destroyed.
#[no_mangle]
pub unsafe extern "C" fn sp_slot_unlock(
    vault_path: *const c_char,
    blob_json: *const c_char,
    sig: *const c_char,
    binding: *const c_char,
    out_handle: *mut VaultHandle,
) -> ErrorCode {
    catch_panic(|| {
        if out_handle.is_null() {
            return ErrorCode::InvalidParam;
        }
        let path_s = match c_to_string(vault_path) {
            Ok(s) => s,
            Err(_) => return ErrorCode::InvalidParam,
        };
        let blob_s = match c_to_string(blob_json) {
            Ok(s) => s,
            Err(_) => return ErrorCode::InvalidParam,
        };
        let sig_s = match c_to_string(sig) {
            Ok(s) => s,
            Err(_) => return ErrorCode::InvalidParam,
        };
        let binding_s = match c_to_string(binding) {
            Ok(s) => s,
            Err(_) => return ErrorCode::InvalidParam,
        };

        match crate::slot::bridge_slot_unlock(&path_s, &blob_s, &sig_s, &binding_s) {
            Ok(handle) => {
                *out_handle = handle;
                ErrorCode::Success
            }
            Err(e) => e.to_error_code(),
        }
    })
}

/// Preflight: whether `blob_json` is a recognized v1 slot blob. No key
/// material involved; `out_has` is written on `Success`.
#[no_mangle]
pub unsafe extern "C" fn sp_slot_has_blob(
    blob_json: *const c_char,
    out_has: *mut bool,
) -> ErrorCode {
    catch_panic(|| {
        if out_has.is_null() {
            return ErrorCode::InvalidParam;
        }
        let blob_s = match c_to_string(blob_json) {
            Ok(s) => s,
            Err(_) => return ErrorCode::InvalidParam,
        };
        *out_has = crate::slot::bridge_slot_has_blob(&blob_s);
        ErrorCode::Success
    })
}

/// iOS Keychain pattern (WBS-821, `biometric.rs mod macos` analog): Swift
/// reads the DEK from the `kSecAccessControlBiometryCurrentSet`-gated
/// Keychain item (the OS-gated release IS the authorization) and passes the
/// 32 bytes here to open the vault. `dek` is BORROWED (rule 1: never
/// retained; the caller zeroizes its copy). Ownership rule 7 on the
/// returned handle.
#[no_mangle]
pub unsafe extern "C" fn sp_slot_open_with_dek(
    vault_path: *const c_char,
    dek: *const u8,
    dek_len: usize,
    source: *const c_char,
    out_handle: *mut VaultHandle,
) -> ErrorCode {
    catch_panic(|| {
        if out_handle.is_null() || dek.is_null() {
            return ErrorCode::InvalidParam;
        }
        let path_s = match c_to_string(vault_path) {
            Ok(s) => s,
            Err(_) => return ErrorCode::InvalidParam,
        };
        let source_s = match c_to_string(source) {
            Ok(s) => s,
            Err(_) => return ErrorCode::InvalidParam,
        };
        let dek_slice = std::slice::from_raw_parts(dek, dek_len);

        match crate::slot::bridge_slot_open_with_dek(&path_s, dek_slice, &source_s) {
            Ok(handle) => {
                *out_handle = handle;
                ErrorCode::Success
            }
            Err(e) => e.to_error_code(),
        }
    })
}

// ============================================================================
// Memory Management (WBS-804: single proven ownership contract)
// ============================================================================

/// Free a string returned by the bridge (out-strings, `SPTotpCode.code`,
/// `SyncStatus.device_id`). Safe on null. Must be called exactly once per
/// bridge-allocated string; never on strings the caller allocated.
#[no_mangle]
pub unsafe extern "C" fn sp_string_free(ptr: *const c_char) {
    catch_panic_void(|| {
        if !ptr.is_null() {
            drop(CString::from_raw(ptr as *mut c_char));
        }
    })
}

/// Free a byte buffer returned by the bridge, using the same `len` that the
/// producing call output. The buffer is deallocated with the exact layout
/// used at allocation (`Layout::array::<u8>(len)`); passing a different
/// `len` is a caller bug. Never call this on buffers the caller allocated.
#[no_mangle]
pub unsafe extern "C" fn sp_bytes_free(ptr: *const u8, len: usize) {
    catch_panic_void(|| {
        if !ptr.is_null() && len > 0 {
            if let Ok(layout) = alloc::Layout::array::<u8>(len) {
                alloc::dealloc(ptr as *mut u8, layout);
            }
        }
    })
}

/// Free one `SPEntry` returned by `sp_entry_get_by_id`, releasing all six
/// string members. The struct storage itself is caller-provided and is NOT
/// freed here. Safe on null.
#[no_mangle]
pub unsafe extern "C" fn sp_entry_free(entry: *mut Entry) {
    catch_panic_void(|| {
        if entry.is_null() {
            return;
        }
        let e = &mut *entry;
        for s in [e.id, e.title, e.username, e.password, e.url, e.notes] {
            if !s.is_null() {
                drop(CString::from_raw(s as *mut c_char));
            }
        }
    })
}

/// Free an `SPEntrySummary` array returned by `sp_entry_list_all` /
/// `sp_entry_search`, releasing every element's strings and the backing
/// array (allocated under `Layout::array::<EntrySummary>(count)`). Safe on
/// null or `count == 0`.
#[no_mangle]
pub unsafe extern "C" fn sp_entry_list_free(entries: *mut EntrySummary, count: usize) {
    catch_panic_void(|| {
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
    })
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
        "sp_bridge_info",
        "sp_bridge_negotiate",
        "sp_entry_free",
        "sp_entry_list_free",
        "sp_bytes_free",
        "sp_entry_add",
        "sp_entry_delete",
        "sp_entry_get_by_id",
        "sp_entry_list_all",
        "sp_entry_search",
        "sp_entry_update",
        "sp_password_check_strength",
        "sp_password_generate",
        "sp_string_free",
        "sp_sync_get_status",
        "sp_slot_challenge",
        "sp_slot_has_blob",
        "sp_slot_open_with_dek",
        "sp_slot_seal",
        "sp_slot_unlock",
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

    /// WBS-805: every C ABI export body must run inside `catch_panic` —
    /// a panic must never unwind into Swift/ObjC (UB). Parsed from source so
    /// a new export cannot skip containment.
    #[test]
    fn every_c_export_is_panic_contained() {
        let src = fs::read_to_string(PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("src/ffi.rs"))
            .expect("ffi.rs source readable");
        let export_region = src.split("#[cfg(test)]").next().expect("export region");
        let needle = "pub unsafe extern \"C\" fn ";
        let mut checked = 0usize;
        let mut rest = export_region;
        while let Some(pos) = rest.find(needle) {
            let after = &rest[pos + needle.len()..];
            let name: String = after
                .chars()
                .take_while(|c| c.is_alphanumeric() || *c == '_')
                .collect();
            let brace = after.find('{').expect("export body brace");
            let first_stmt = after[brace + 1..].trim_start();
            assert!(
                first_stmt.starts_with("catch_panic"),
                "export `{name}` is not panic-contained (body must open with catch_panic/catch_panic_void)"
            );
            checked += 1;
            rest = after;
        }
        assert!(
            checked >= 24,
            "parsed {checked} exports — parser desynced from ffi.rs"
        );
    }

    #[test]
    fn catch_panic_contains_panics_and_passes_values_through() {
        assert_eq!(
            super::catch_panic(|| ErrorCode::Success),
            ErrorCode::Success
        );
        assert_eq!(
            super::catch_panic(|| panic!("synthetic boundary panic")),
            ErrorCode::Panic
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
    fn sp_bytes_free_releases_bridge_shaped_buffers() {
        // No current export produces out-byte-buffers (WBS-807 removed the
        // placeholder sync paths), so exercise the sanctioned release path
        // against a buffer allocated exactly the way `bytes_to_c_buffer`
        // (the only sanctioned producer shape, retained for WBS-827 backup)
        // allocates: alloc under Layout::array::<u8>(len).
        let len = 37usize;
        let layout = alloc::Layout::array::<u8>(len).unwrap();
        let buf = unsafe {
            let dst = alloc::alloc(layout);
            assert!(!dst.is_null());
            std::ptr::write_bytes(dst, 0xAB, len);
            dst as *const u8
        };
        let slice = unsafe { std::slice::from_raw_parts(buf, len) };
        assert_eq!(slice[0], 0xAB);
        // The single sanctioned release path, with the SAME len.
        unsafe { sp_bytes_free(buf, len) };
    }

    #[test]
    fn sp_entry_update_atomic_partial_fields() {
        let (dir, handle) = temp_vault();
        let id = add_entry(handle, "before");

        // Update ONLY the title; null = unchanged elsewhere.
        let code = unsafe {
            sp_entry_update(
                handle,
                cstr(&id).as_ptr(),
                cstr("after").as_ptr(),
                std::ptr::null(),
                std::ptr::null(),
                std::ptr::null(),
                std::ptr::null(),
            )
        };
        assert_eq!(code, ErrorCode::Success);

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
        unsafe { sp_entry_free(&mut entry) };
        assert_eq!(
            unsafe { sp_entry_get_by_id(handle, cstr(&id).as_ptr(), &mut entry) },
            ErrorCode::Success
        );
        assert_eq!(
            unsafe { CStr::from_ptr(entry.title) }.to_string_lossy(),
            "after"
        );
        assert_eq!(
            unsafe { CStr::from_ptr(entry.password) }.to_string_lossy(),
            "secret-password",
            "null password must be unchanged"
        );
        assert_eq!(
            unsafe { CStr::from_ptr(entry.username) }.to_string_lossy(),
            "user",
            "null username must be unchanged"
        );

        // Same entry id preserved (no delete-then-add identity churn).
        assert_eq!(unsafe { CStr::from_ptr(entry.id) }.to_string_lossy(), id);

        assert!(bridge::bridge_vault_destroy(handle).is_ok());
        let _ = std::fs::remove_dir_all(dir);
    }

    #[test]
    fn string_free_null_safe_and_destroy_clears_registered_keys() {
        // sp_string_free/sp_entry_free are safe on null.
        unsafe { sp_string_free(std::ptr::null()) };
        unsafe { sp_entry_free(std::ptr::null_mut()) };
        unsafe { sp_entry_list_free(std::ptr::null_mut(), 0) };
        unsafe { sp_bytes_free(std::ptr::null(), 0) };

        // Destroy removes the registry entry (use-after-destroy fails).
        // WBS-812/821: the in-process biometric key map is GONE — platform
        // slots keep no key material in this process (the zeroizing-destroy
        // property now holds vacuously and structurally).
        let (dir, handle) = temp_vault();
        assert!(
            bridge::bridge_vault_destroy(handle).is_ok(),
            "destroy must succeed"
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
