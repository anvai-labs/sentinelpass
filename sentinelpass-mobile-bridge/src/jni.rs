// JNI exports for Android (WBS-802: one class/package/signature contract)
//
// The JNI contract is owned by the Kotlin facade
// `android/SentinelPass/app/src/main/java/com/sentinelpass/VaultBridge.kt`:
// every `external fun` declared there resolves to exactly one exported
// `Java_com_sentinelpass_VaultBridge_<name>` symbol here, with matching
// arity and argument types. This contract is pinned by
// `tests/jni_contract.rs` (declaration parity) and, on CI, by the
// all-ABI symbol check over the built `.so` (WBS-811).
//
// All Kotlin declarations are instance methods of `com.sentinelpass.
// VaultBridge`, so the second JNI parameter is the receiver (`this`).
// Return-shape conventions (consumed by VaultBridge.kt, do not change
// without updating both sides):
// - `nativeGetEntry` / `nativeListEntries` / `nativeSearchEntries` return
//   JSON matching the Kotlin `Entry` / `EntrySummary` models.
// - `nativeGenerateTotp` returns `"<code>,<seconds_remaining>"`.
// - `nativeCheckStrength` returns `"<score>,<description>"`.

#![allow(unused_variables)]

#[cfg(feature = "jni")]
use crate::bridge;
#[cfg(feature = "jni")]
use crate::error::ErrorCode;
#[cfg(feature = "jni")]
use jni::objects::{JObject, JString};
#[cfg(feature = "jni")]
use jni::sys::{jboolean, jint, jlong, jstring};
#[cfg(feature = "jni")]
use jni::JNIEnv;
#[cfg(feature = "jni")]
use serde::Serialize;

/// Wire model mirroring the Kotlin `Entry` data class (VaultBridge.kt).
/// Field names and types are the JSON contract; serde renames here are
/// what Kotlin's `@Serializable Entry` decodes.
#[cfg(feature = "jni")]
#[derive(Serialize)]
struct EntryWire<'a> {
    id: Option<String>,
    title: &'a str,
    username: &'a str,
    password: &'a str,
    url: Option<&'a str>,
    notes: Option<&'a str>,
    #[serde(rename = "createdAt")]
    created_at: Option<String>,
    #[serde(rename = "modifiedAt")]
    modified_at: Option<String>,
    favorite: bool,
}

/// Wire model mirroring the Kotlin `EntrySummary` data class.
#[cfg(feature = "jni")]
#[derive(Serialize)]
struct EntrySummaryWire<'a> {
    id: String,
    title: &'a str,
    username: &'a str,
    favorite: bool,
}

/// Convert JNI string to Rust string
#[cfg(feature = "jni")]
fn jstring_to_string(env: &mut JNIEnv, jstr: JString) -> Result<String, ErrorCode> {
    env.get_string(&jstr)
        .map(|s| s.into())
        .map_err(|_| ErrorCode::InvalidParam)
}

/// Convert Rust string to JNI string
#[cfg(feature = "jni")]
fn string_to_jstring(env: &mut JNIEnv, s: &str) -> Result<jstring, ErrorCode> {
    env.new_string(s)
        .map(|j| j.into_raw())
        .map_err(|_| ErrorCode::OutOfMemory)
}

/// Convert Result to error code
#[cfg(feature = "jni")]
fn result_to_code<T>(result: Result<T, crate::error::BridgeError>) -> jint {
    match result {
        Ok(_) => ErrorCode::Success as jint,
        Err(e) => e.to_error_code() as jint,
    }
}

/// WBS-805 panic containment: a Rust panic unwinding through an
/// `extern "system"` JNI frame aborts the host process. Every JNI export body
/// runs inside this wrapper; a contained panic is logged and surfaces as the
/// caller-side failure convention (0 / null / `ErrorCode::Unknown`) — never
/// as an abort. Out-params written before the panic must be treated as
/// undefined by the caller.
fn catch_jni<T>(default: T, op: impl FnOnce() -> T) -> T {
    match std::panic::catch_unwind(std::panic::AssertUnwindSafe(op)) {
        Ok(v) => v,
        Err(payload) => {
            let detail = payload
                .downcast_ref::<&str>()
                .copied()
                .or_else(|| payload.downcast_ref::<String>().map(|s| s.as_str()))
                .unwrap_or("<non-string panic payload>");
            tracing::error!(target: "mobile_bridge", "contained panic at JNI boundary: {detail}");
            default
        }
    }
}

// ============================================================================
// ABI Negotiation - JNI (WBS-803)
// ============================================================================

/// ABI contract version of this build. VaultBridge.kt handshakes in its init
/// block and refuses to operate on a mismatch (fail closed).
#[no_mangle]
#[cfg(feature = "jni")]
pub extern "system" fn Java_com_sentinelpass_VaultBridge_nativeAbiVersion(
    env: JNIEnv,
    this: JObject,
) -> jint {
    catch_jni(ErrorCode::Unknown as jint, || {
        crate::abi::ABI_VERSION as jint
    })
}

// ============================================================================
// Vault Management - JNI
// ============================================================================

/// Create a new vault or unlock an existing one. Returns the vault handle
/// (non-zero) on success, 0 on failure.
#[no_mangle]
#[cfg(feature = "jni")]
pub extern "system" fn Java_com_sentinelpass_VaultBridge_nativeInit(
    mut env: JNIEnv,
    this: JObject,
    vault_path: JString,
    master_password: JString,
) -> jlong {
    catch_jni(0, || {
        let path = match jstring_to_string(&mut env, vault_path) {
            Ok(p) => p,
            Err(_) => return 0,
        };

        let password = match jstring_to_string(&mut env, master_password) {
            Ok(p) => p,
            Err(_) => return 0,
        };

        match bridge::bridge_vault_init(&path, &password) {
            Ok(handle) => handle as jlong,
            Err(_) => 0,
        }
    })
}

/// Destroy the vault handle. Deterministic: safe to call once per handle;
/// a second call reports InvalidParam (Kotlin guards with handle != 0).
#[no_mangle]
#[cfg(feature = "jni")]
pub extern "system" fn Java_com_sentinelpass_VaultBridge_nativeDestroy(
    mut env: JNIEnv,
    this: JObject,
    handle: jlong,
) {
    catch_jni((), || {
        let _ = bridge::bridge_vault_destroy(handle as u64);
    })
}

#[no_mangle]
#[cfg(feature = "jni")]
pub extern "system" fn Java_com_sentinelpass_VaultBridge_nativeIsUnlocked(
    mut env: JNIEnv,
    this: JObject,
    handle: jlong,
) -> jboolean {
    catch_jni(0, || {
        match bridge::bridge_vault_is_unlocked(handle as u64) {
            Ok(true) => 1,
            Ok(false) | Err(_) => 0,
        }
    })
}

#[no_mangle]
#[cfg(feature = "jni")]
pub extern "system" fn Java_com_sentinelpass_VaultBridge_nativeLock(
    mut env: JNIEnv,
    this: JObject,
    handle: jlong,
) -> jint {
    catch_jni(ErrorCode::Unknown as jint, || {
        result_to_code(bridge::bridge_vault_lock(handle as u64))
    })
}

// ============================================================================
// Entry Management - JNI
// ============================================================================

#[no_mangle]
#[cfg(feature = "jni")]
pub extern "system" fn Java_com_sentinelpass_VaultBridge_nativeAddEntry(
    mut env: JNIEnv,
    this: JObject,
    handle: jlong,
    title: JString,
    username: JString,
    password: JString,
    url: JString,
    notes: JString,
) -> jstring {
    catch_jni(std::ptr::null_mut(), || {
        let title_str = match jstring_to_string(&mut env, title) {
            Ok(s) => s,
            Err(_) => return std::ptr::null_mut(),
        };
        let username_str = match jstring_to_string(&mut env, username) {
            Ok(s) => s,
            Err(_) => return std::ptr::null_mut(),
        };
        let password_str = match jstring_to_string(&mut env, password) {
            Ok(s) => s,
            Err(_) => return std::ptr::null_mut(),
        };
        let url_str = match jstring_to_string(&mut env, url) {
            Ok(s) => s,
            Err(_) => return std::ptr::null_mut(),
        };
        let notes_str = match jstring_to_string(&mut env, notes) {
            Ok(s) => s,
            Err(_) => return std::ptr::null_mut(),
        };

        match bridge::bridge_entry_add(
            handle as u64,
            &title_str,
            &username_str,
            &password_str,
            &url_str,
            &notes_str,
        ) {
            Ok(entry_id) => string_to_jstring(&mut env, &entry_id).unwrap_or(std::ptr::null_mut()),
            Err(_) => std::ptr::null_mut(),
        }
    })
}

/// Get an entry as JSON matching the Kotlin `Entry` model (or null).
#[no_mangle]
#[cfg(feature = "jni")]
pub extern "system" fn Java_com_sentinelpass_VaultBridge_nativeGetEntry(
    mut env: JNIEnv,
    this: JObject,
    handle: jlong,
    entry_id: JString,
) -> jstring {
    catch_jni(std::ptr::null_mut(), || {
        let id_str = match jstring_to_string(&mut env, entry_id) {
            Ok(s) => s,
            Err(_) => return std::ptr::null_mut(),
        };

        match bridge::bridge_entry_get(handle as u64, &id_str) {
            Ok(entry) => {
                let wire = EntryWire {
                    id: entry.entry_id.map(|v| v.to_string()),
                    title: &entry.title,
                    username: &entry.username,
                    password: &entry.password,
                    url: entry.url.as_deref(),
                    notes: entry.notes.as_deref(),
                    created_at: Some(entry.created_at.to_rfc3339()),
                    modified_at: Some(entry.modified_at.to_rfc3339()),
                    favorite: entry.favorite,
                };
                match serde_json::to_string(&wire) {
                    Ok(json) => string_to_jstring(&mut env, &json).unwrap_or(std::ptr::null_mut()),
                    Err(_) => std::ptr::null_mut(),
                }
            }
            Err(_) => std::ptr::null_mut(),
        }
    })
}

/// List entries as a JSON array of Kotlin `EntrySummary` (or null).
#[no_mangle]
#[cfg(feature = "jni")]
pub extern "system" fn Java_com_sentinelpass_VaultBridge_nativeListEntries(
    mut env: JNIEnv,
    this: JObject,
    handle: jlong,
) -> jstring {
    catch_jni(std::ptr::null_mut(), || {
        match bridge::bridge_entry_list(handle as u64) {
            Ok(summaries) => {
                let wire: Vec<EntrySummaryWire<'_>> = summaries
                    .iter()
                    .map(|s| EntrySummaryWire {
                        id: s.entry_id.to_string(),
                        title: &s.title,
                        username: &s.username,
                        favorite: s.favorite,
                    })
                    .collect();
                match serde_json::to_string(&wire) {
                    Ok(json) => string_to_jstring(&mut env, &json).unwrap_or(std::ptr::null_mut()),
                    Err(_) => std::ptr::null_mut(),
                }
            }
            Err(_) => std::ptr::null_mut(),
        }
    })
}

/// Search entries as a JSON array of Kotlin `EntrySummary` (or null).
#[no_mangle]
#[cfg(feature = "jni")]
pub extern "system" fn Java_com_sentinelpass_VaultBridge_nativeSearchEntries(
    mut env: JNIEnv,
    this: JObject,
    handle: jlong,
    query: JString,
) -> jstring {
    catch_jni(std::ptr::null_mut(), || {
        let query_str = match jstring_to_string(&mut env, query) {
            Ok(s) => s,
            Err(_) => return std::ptr::null_mut(),
        };

        match bridge::bridge_entry_search(handle as u64, &query_str) {
            Ok(summaries) => {
                let wire: Vec<EntrySummaryWire<'_>> = summaries
                    .iter()
                    .map(|s| EntrySummaryWire {
                        id: s.entry_id.to_string(),
                        title: &s.title,
                        username: &s.username,
                        favorite: s.favorite,
                    })
                    .collect();
                match serde_json::to_string(&wire) {
                    Ok(json) => string_to_jstring(&mut env, &json).unwrap_or(std::ptr::null_mut()),
                    Err(_) => std::ptr::null_mut(),
                }
            }
            Err(_) => std::ptr::null_mut(),
        }
    })
}

#[no_mangle]
#[cfg(feature = "jni")]
pub extern "system" fn Java_com_sentinelpass_VaultBridge_nativeDeleteEntry(
    mut env: JNIEnv,
    this: JObject,
    handle: jlong,
    entry_id: JString,
) -> jint {
    catch_jni(ErrorCode::Unknown as jint, || {
        let id_str = match jstring_to_string(&mut env, entry_id) {
            Ok(s) => s,
            Err(_) => return ErrorCode::InvalidParam as jint,
        };

        result_to_code(bridge::bridge_entry_delete(handle as u64, &id_str))
    })
}

// ============================================================================
// TOTP - JNI
// ============================================================================

/// Returns `"<code>,<seconds_remaining>"` — the format VaultBridge.kt parses.
#[no_mangle]
#[cfg(feature = "jni")]
pub extern "system" fn Java_com_sentinelpass_VaultBridge_nativeGenerateTotp(
    mut env: JNIEnv,
    this: JObject,
    handle: jlong,
    entry_id: JString,
) -> jstring {
    catch_jni(std::ptr::null_mut(), || {
        let id_str = match jstring_to_string(&mut env, entry_id) {
            Ok(s) => s,
            Err(_) => return std::ptr::null_mut(),
        };

        match bridge::bridge_totp_generate_code(handle as u64, &id_str) {
            Ok(totp_info) => {
                let formatted = format!("{},{}", totp_info.code, totp_info.seconds_remaining);
                string_to_jstring(&mut env, &formatted).unwrap_or(std::ptr::null_mut())
            }
            Err(_) => std::ptr::null_mut(),
        }
    })
}

// ============================================================================
// Password Generation - JNI
// ============================================================================

#[no_mangle]
#[cfg(feature = "jni")]
pub extern "system" fn Java_com_sentinelpass_VaultBridge_nativeGeneratePassword(
    mut env: JNIEnv,
    this: JObject,
    handle: jlong,
    length: jint,
    include_symbols: jboolean,
) -> jstring {
    catch_jni(std::ptr::null_mut(), || {
        let length = length as usize;
        let symbols = include_symbols != 0;

        match bridge::bridge_password_generate(length, symbols) {
            Ok(password) => string_to_jstring(&mut env, &password).unwrap_or(std::ptr::null_mut()),
            Err(_) => std::ptr::null_mut(),
        }
    })
}

/// Returns `"<score>,<description>"` — the format VaultBridge.kt parses.
#[no_mangle]
#[cfg(feature = "jni")]
pub extern "system" fn Java_com_sentinelpass_VaultBridge_nativeCheckStrength(
    mut env: JNIEnv,
    this: JObject,
    handle: jlong,
    password: JString,
) -> jstring {
    catch_jni(std::ptr::null_mut(), || {
        let password_str = match jstring_to_string(&mut env, password) {
            Ok(s) => s,
            Err(_) => return std::ptr::null_mut(),
        };

        match bridge::bridge_password_check_strength(&password_str) {
            Ok(analysis) => {
                let result = format!(
                    "{},{}",
                    analysis.strength.score(),
                    analysis.strength.as_str()
                );
                string_to_jstring(&mut env, &result).unwrap_or(std::ptr::null_mut())
            }
            Err(_) => std::ptr::null_mut(),
        }
    })
}

// ============================================================================
// Biometric - JNI
// ============================================================================
//
// WBS-802 trims the JNI surface to exactly the Kotlin-declared natives.
// The platform-keystore-bound biometric slot (WBS-812) introduces new,
// symmetrically declared natives in Stage M2.

#[no_mangle]
#[cfg(feature = "jni")]
pub extern "system" fn Java_com_sentinelpass_VaultBridge_nativeBiometricHasKey(
    mut env: JNIEnv,
    this: JObject,
    handle: jlong,
) -> jboolean {
    catch_jni(0, || {
        match bridge::bridge_biometric_has_key(handle as u64) {
            Ok(true) => 1,
            Ok(false) | Err(_) => 0,
        }
    })
}

#[no_mangle]
#[cfg(feature = "jni")]
pub extern "system" fn Java_com_sentinelpass_VaultBridge_nativeBiometricRemoveKey(
    mut env: JNIEnv,
    this: JObject,
    handle: jlong,
) -> jint {
    catch_jni(ErrorCode::Unknown as jint, || {
        result_to_code(bridge::bridge_biometric_remove_key(handle as u64))
    })
}

#[no_mangle]
#[cfg(feature = "jni")]
pub extern "system" fn Java_com_sentinelpass_VaultBridge_nativeBiometricUnlock(
    mut env: JNIEnv,
    this: JObject,
    handle: jlong,
) -> jint {
    catch_jni(ErrorCode::Unknown as jint, || {
        result_to_code(bridge::bridge_biometric_unlock(handle as u64))
    })
}

#[cfg(all(test, feature = "jni"))]
mod wire_tests {
    use super::*;

    /// The JSON wire keys must match the Kotlin `@Serializable Entry` /
    /// `EntrySummary` models exactly (VaultBridge.kt decodes these names).
    #[test]
    fn entry_wire_keys_match_kotlin_model() {
        let entry = EntryWire {
            id: Some("42".to_string()),
            title: "t",
            username: "u",
            password: "p",
            url: Some("https://x"),
            notes: None,
            created_at: Some("2026-01-01T00:00:00+00:00".to_string()),
            modified_at: Some("2026-01-01T00:00:00+00:00".to_string()),
            favorite: true,
        };
        let json: serde_json::Value =
            serde_json::from_str(&serde_json::to_string(&entry).unwrap()).unwrap();
        for key in [
            "id",
            "title",
            "username",
            "password",
            "url",
            "notes",
            "createdAt",
            "modifiedAt",
            "favorite",
        ] {
            assert!(
                json.get(key).is_some(),
                "EntryWire JSON is missing key `{key}` required by the Kotlin model"
            );
        }
        assert_eq!(json["id"], "42");
        assert_eq!(json["favorite"], true);
    }

    #[test]
    fn summary_wire_keys_match_kotlin_model() {
        let summary = EntrySummaryWire {
            id: "7".to_string(),
            title: "t",
            username: "u",
            favorite: false,
        };
        let json: serde_json::Value =
            serde_json::from_str(&serde_json::to_string(&summary).unwrap()).unwrap();
        for key in ["id", "title", "username", "favorite"] {
            assert!(
                json.get(key).is_some(),
                "EntrySummaryWire JSON is missing key `{key}` required by the Kotlin model"
            );
        }
    }
}
