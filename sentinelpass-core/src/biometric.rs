//! Biometric authentication support (Windows Hello, Touch ID)

use crate::crypto::DataEncryptionKey;
use crate::DatabaseError;
use crate::{PasswordManagerError, Result};
use std::path::Path;
#[cfg(windows)]
use zeroize::Zeroize;

use serde::{Deserialize, Serialize};

/// Message used by every platform-unsupported stub. Matched BY REFERENCE
/// (see biometric_ops/slot_ops tolerant clears) — never reword without
/// updating those matches; the const exists so prose drift cannot silently
/// break the platform-unsupported exception (review finding).
pub const UNSUPPORTED_PLATFORM_MSG: &str =
    "Biometric key storage is not supported on this platform";

#[cfg(any(windows, target_os = "macos"))]
const BIOMETRIC_SERVICE_NAME: &str = "sentinelpass.biometric";

/// Platform storage policy used for biometric vault DEK protection.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum BiometricProtectionPolicy {
    /// macOS Keychain item protected with `biometryCurrentSet`.
    MacosBiometryCurrentSet,
    /// Windows Hello-gated OS key storage.
    WindowsHelloUserPresence,
}

impl BiometricProtectionPolicy {
    /// Return the strongest policy supported by the current platform.
    pub fn current_platform() -> Result<Self> {
        #[cfg(target_os = "macos")]
        return Ok(Self::MacosBiometryCurrentSet);

        #[cfg(windows)]
        return Ok(Self::WindowsHelloUserPresence);

        #[cfg(not(any(windows, target_os = "macos")))]
        return Err(PasswordManagerError::NotFound(
            UNSUPPORTED_PLATFORM_MSG.to_string(),
        ));
    }

    /// Whether the stored secret becomes unusable after biometric enrollment changes.
    pub fn invalidates_on_biometric_enrollment_change(self) -> bool {
        matches!(self, Self::MacosBiometryCurrentSet)
    }
}

/// Result of a biometric operation
#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum BiometricResult {
    /// User successfully authenticated
    Success,
    /// User cancelled the operation
    Cancelled,
    /// Biometric hardware not available
    NotAvailable,
    /// Biometric operation failed
    Failed(String),
    /// Biometric not enrolled
    NotEnrolled,
}

/// Biometric authentication manager
pub struct BiometricManager;

impl BiometricManager {
    /// Check if biometric authentication is available on this system
    pub fn is_available() -> bool {
        #[cfg(windows)]
        return self::windows::is_hello_available();

        #[cfg(target_os = "macos")]
        return self::macos::is_touch_id_available();

        #[cfg(not(any(windows, target_os = "macos")))]
        return false;
    }

    /// Check if biometric authentication is enrolled
    pub fn is_enrolled() -> bool {
        #[cfg(windows)]
        return self::windows::is_hello_enrolled();

        #[cfg(target_os = "macos")]
        return self::macos::is_touch_id_enrolled();

        #[cfg(not(any(windows, target_os = "macos")))]
        return false;
    }

    /// Prompt for biometric authentication
    /// Returns BiometricResult::Success if authenticated successfully
    pub fn authenticate(_reason: &str) -> BiometricResult {
        #[cfg(windows)]
        return self::windows::authenticate_with_hello(_reason);

        #[cfg(target_os = "macos")]
        return self::macos::authenticate_with_touch_id(_reason);

        #[cfg(not(any(windows, target_os = "macos")))]
        return BiometricResult::NotAvailable;
    }

    /// Get a human-readable name for the biometric method on this platform
    pub fn get_method_name() -> &'static str {
        #[cfg(windows)]
        return "Windows Hello";

        #[cfg(target_os = "macos")]
        return "Touch ID";

        #[cfg(not(any(windows, target_os = "macos")))]
        return "Biometric Authentication";
    }

    /// Generate a deterministic keychain reference for a vault path.
    pub fn biometric_ref_for_vault(vault_path: &Path) -> String {
        use sha2::{Digest, Sha256};

        let mut hasher = Sha256::new();
        hasher.update(vault_path.to_string_lossy().as_bytes());
        format!("vault-{}", hex::encode(hasher.finalize()))
    }

    #[cfg(any(windows, test))]
    fn encode_vault_dek(dek: &DataEncryptionKey) -> String {
        use base64::Engine;

        base64::engine::general_purpose::STANDARD.encode(dek.as_bytes())
    }

    #[cfg(any(windows, test))]
    fn decode_vault_dek(encoded: &str) -> Result<DataEncryptionKey> {
        use base64::Engine;

        let decoded = base64::engine::general_purpose::STANDARD
            .decode(encoded.as_bytes())
            .map_err(|e| {
                PasswordManagerError::from(DatabaseError::Keyring(format!(
                    "Stored biometric keyring secret is invalid: {}",
                    e
                )))
            })?;

        Self::decode_vault_dek_bytes(decoded)
    }

    #[cfg(any(windows, target_os = "macos", test))]
    fn decode_vault_dek_bytes(decoded: Vec<u8>) -> Result<DataEncryptionKey> {
        let key_bytes: [u8; 32] = decoded.try_into().map_err(|bytes: Vec<u8>| {
            PasswordManagerError::from(DatabaseError::Keyring(format!(
                "Stored biometric keyring secret has invalid length: expected 32 bytes, got {}",
                bytes.len()
            )))
        })?;

        Ok(DataEncryptionKey::from_bytes(&mut { key_bytes }))
    }

    /// Store the vault DEK in an OS-protected key store for biometric unlock.
    pub fn store_vault_dek(vault_path: &Path, dek: &DataEncryptionKey) -> Result<String> {
        if dek.as_bytes().is_empty() {
            return Err(PasswordManagerError::InvalidInput(
                "Vault DEK cannot be empty".to_string(),
            ));
        }

        #[cfg(target_os = "macos")]
        {
            self::macos::store_vault_dek(vault_path, dek)
        }

        #[cfg(windows)]
        {
            let biometric_ref = Self::biometric_ref_for_vault(vault_path);
            let entry =
                keyring::Entry::new(BIOMETRIC_SERVICE_NAME, &biometric_ref).map_err(|e| {
                    PasswordManagerError::from(DatabaseError::Keyring(format!(
                        "Failed to initialize keyring entry: {}",
                        e
                    )))
                })?;

            // Store base64 to keep storage UTF-8 safe across keychain backends.
            let mut encoded = Self::encode_vault_dek(dek);
            let set_result = entry.set_password(&encoded).map_err(|e| {
                PasswordManagerError::from(DatabaseError::Keyring(format!(
                    "Failed to store biometric keyring secret: {}",
                    e
                )))
            });
            encoded.zeroize();
            set_result?;

            Ok(biometric_ref)
        }

        #[cfg(not(any(windows, target_os = "macos")))]
        {
            let _ = (vault_path, dek);
            Err(PasswordManagerError::NotFound(
                UNSUPPORTED_PLATFORM_MSG.to_string(),
            ))
        }
    }

    /// Load a previously stored vault DEK from the OS key store.
    pub fn load_vault_dek(biometric_ref: &str) -> Result<DataEncryptionKey> {
        #[cfg(target_os = "macos")]
        {
            self::macos::load_vault_dek(biometric_ref, "Unlock SentinelPass vault with Touch ID")
        }

        #[cfg(windows)]
        {
            let entry =
                keyring::Entry::new(BIOMETRIC_SERVICE_NAME, biometric_ref).map_err(|e| {
                    PasswordManagerError::from(DatabaseError::Keyring(format!(
                        "Failed to initialize keyring entry: {}",
                        e
                    )))
                })?;

            let mut encoded = entry.get_password().map_err(|e| {
                PasswordManagerError::NotFound(format!(
                    "Biometric keyring secret is unavailable: {}",
                    e
                ))
            })?;

            let dek = Self::decode_vault_dek(&encoded)?;
            encoded.zeroize();

            Ok(dek)
        }

        #[cfg(not(any(windows, target_os = "macos")))]
        {
            let _ = biometric_ref;
            Err(PasswordManagerError::NotFound(
                UNSUPPORTED_PLATFORM_MSG.to_string(),
            ))
        }
    }

    /// Authenticate and load a previously stored vault DEK from the OS key store.
    pub fn authenticate_and_load_vault_dek(
        biometric_ref: &str,
        reason: &str,
    ) -> Result<DataEncryptionKey> {
        #[cfg(target_os = "macos")]
        {
            self::macos::load_vault_dek(biometric_ref, reason)
        }

        #[cfg(not(target_os = "macos"))]
        {
            Self::require_authentication(reason)?;
            Self::load_vault_dek(biometric_ref)
        }
    }

    #[cfg(not(target_os = "macos"))]
    fn require_authentication(reason: &str) -> Result<()> {
        match Self::authenticate(reason) {
            BiometricResult::Success => Ok(()),
            BiometricResult::Cancelled => Err(PasswordManagerError::InvalidInput(
                "Biometric authentication was cancelled".to_string(),
            )),
            BiometricResult::NotAvailable => Err(PasswordManagerError::NotFound(format!(
                "{} is not available on this system",
                Self::get_method_name()
            ))),
            BiometricResult::NotEnrolled => Err(PasswordManagerError::NotFound(format!(
                "{} is not enrolled on this system",
                Self::get_method_name()
            ))),
            BiometricResult::Failed(err) => Err(PasswordManagerError::from(DatabaseError::Other(
                format!("Biometric authentication failed: {}", err),
            ))),
        }
    }

    /// Remove a stored biometric vault DEK secret.
    pub fn clear_vault_dek(biometric_ref: &str) -> Result<()> {
        #[cfg(target_os = "macos")]
        {
            self::macos::clear_vault_dek(biometric_ref)
        }

        #[cfg(windows)]
        {
            let entry =
                keyring::Entry::new(BIOMETRIC_SERVICE_NAME, biometric_ref).map_err(|e| {
                    PasswordManagerError::from(DatabaseError::Keyring(format!(
                        "Failed to initialize keyring entry: {}",
                        e
                    )))
                })?;

            if let Err(e) = entry.delete_password() {
                let msg = e.to_string();
                let lowered = msg.to_ascii_lowercase();
                if lowered.contains("no entry")
                    || lowered.contains("not found")
                    || lowered.contains("missing")
                {
                    return Ok(());
                }
                return Err(PasswordManagerError::from(DatabaseError::Keyring(format!(
                    "Failed to clear biometric keyring secret: {}",
                    e
                ))));
            }

            Ok(())
        }

        #[cfg(not(any(windows, target_os = "macos")))]
        {
            let _ = biometric_ref;
            Err(PasswordManagerError::NotFound(
                UNSUPPORTED_PLATFORM_MSG.to_string(),
            ))
        }
    }
}

/// Windows-specific implementation using Windows Hello
#[cfg(windows)]
mod windows {
    use super::BiometricResult;
    use windows::{
        core::HSTRING,
        Security::Credentials::UI::{
            UserConsentVerificationResult, UserConsentVerifier, UserConsentVerifierAvailability,
        },
        Win32::{
            Foundation::RPC_E_CHANGED_MODE,
            System::Com::{CoInitializeEx, COINIT_APARTMENTTHREADED},
        },
    };

    fn ensure_com_initialized() {
        // SAFETY: CoInitializeEx initializes COM for the current thread and accepts a null reserved pointer.
        let hr = unsafe { CoInitializeEx(None, COINIT_APARTMENTTHREADED) };
        if hr.is_err() && hr != RPC_E_CHANGED_MODE {
            // Best-effort initialization only; Windows Hello calls may still succeed if COM/WinRT is initialized.
        }
    }

    fn check_availability() -> windows::core::Result<UserConsentVerifierAvailability> {
        ensure_com_initialized();
        UserConsentVerifier::CheckAvailabilityAsync()?.get()
    }

    pub fn is_hello_available() -> bool {
        matches!(
            check_availability(),
            Ok(UserConsentVerifierAvailability::Available)
        )
    }

    pub fn is_hello_enrolled() -> bool {
        matches!(
            check_availability(),
            Ok(UserConsentVerifierAvailability::Available)
        )
    }

    pub fn authenticate_with_hello(reason: &str) -> BiometricResult {
        let availability = match check_availability() {
            Ok(value) => value,
            Err(e) => {
                return BiometricResult::Failed(format!(
                    "Windows Hello availability check failed: {}",
                    e
                ))
            }
        };

        match availability {
            UserConsentVerifierAvailability::Available => {}
            UserConsentVerifierAvailability::NotConfiguredForUser => {
                return BiometricResult::NotEnrolled;
            }
            UserConsentVerifierAvailability::DisabledByPolicy
            | UserConsentVerifierAvailability::DeviceNotPresent => {
                return BiometricResult::NotAvailable;
            }
            UserConsentVerifierAvailability::DeviceBusy => {
                return BiometricResult::Failed(
                    "Windows Hello device is currently busy".to_string(),
                );
            }
            _ => {
                return BiometricResult::Failed(format!(
                    "Unhandled Windows Hello availability state: {:?}",
                    availability
                ))
            }
        }

        ensure_com_initialized();
        let prompt = HSTRING::from(reason);
        let result = match UserConsentVerifier::RequestVerificationAsync(&prompt) {
            Ok(op) => match op.get() {
                Ok(value) => value,
                Err(e) => {
                    return BiometricResult::Failed(format!(
                        "Windows Hello verification failed: {}",
                        e
                    ))
                }
            },
            Err(e) => {
                return BiometricResult::Failed(format!(
                    "Windows Hello request creation failed: {}",
                    e
                ))
            }
        };

        match result {
            UserConsentVerificationResult::Verified => BiometricResult::Success,
            UserConsentVerificationResult::Canceled => BiometricResult::Cancelled,
            UserConsentVerificationResult::NotConfiguredForUser => BiometricResult::NotEnrolled,
            UserConsentVerificationResult::DisabledByPolicy
            | UserConsentVerificationResult::DeviceNotPresent => BiometricResult::NotAvailable,
            UserConsentVerificationResult::DeviceBusy => {
                BiometricResult::Failed("Windows Hello device is busy".to_string())
            }
            UserConsentVerificationResult::RetriesExhausted => {
                BiometricResult::Failed("Biometric retries exhausted".to_string())
            }
            _ => BiometricResult::Failed(format!(
                "Unhandled Windows Hello verification result: {:?}",
                result
            )),
        }
    }
}

/// macOS-specific implementation using Touch ID
#[cfg(target_os = "macos")]
#[allow(unexpected_cfgs)]
mod macos {
    use super::{BiometricManager, BiometricResult, BIOMETRIC_SERVICE_NAME};
    use crate::{DatabaseError, PasswordManagerError, Result};
    use block::ConcreteBlock;
    use cocoa::base::{id, nil, BOOL, YES};
    use cocoa::foundation::NSString;
    use core_foundation::base::{
        kCFAllocatorDefault, CFGetTypeID, CFRelease, CFType, CFTypeRef, TCFType,
    };
    use core_foundation::boolean::CFBoolean;
    use core_foundation::data::{CFData, CFDataRef};
    use core_foundation::dictionary::CFDictionary;
    use core_foundation::string::{CFString, CFStringRef};
    use objc::{msg_send, runtime::Class, sel, sel_impl};
    use security_framework_sys::access_control::{
        kSecAccessControlBiometryCurrentSet, kSecAttrAccessibleWhenPasscodeSetThisDeviceOnly,
        SecAccessControlCreateWithFlags,
    };
    use security_framework_sys::base::{errSecItemNotFound, errSecSuccess};
    use security_framework_sys::item::{
        kSecAttrAccessControl, kSecAttrAccount, kSecAttrService, kSecClass,
        kSecClassGenericPassword, kSecReturnData, kSecValueData,
    };
    use security_framework_sys::keychain_item::{SecItemAdd, SecItemCopyMatching, SecItemDelete};
    use std::path::Path;
    use std::ptr;
    use std::sync::mpsc;
    use std::time::Duration;

    extern "C" {
        static kSecUseOperationPrompt: CFStringRef;
    }

    const LAPOLICY_DEVICE_OWNER_AUTHENTICATION_WITH_BIOMETRICS: i64 = 1;

    const LA_ERROR_AUTHENTICATION_FAILED: i64 = -1;
    const LA_ERROR_USER_CANCEL: i64 = -2;
    const LA_ERROR_SYSTEM_CANCEL: i64 = -4;
    const LA_ERROR_PASSCODE_NOT_SET: i64 = -5;
    const LA_ERROR_BIOMETRY_NOT_AVAILABLE: i64 = -6;
    const LA_ERROR_BIOMETRY_NOT_ENROLLED: i64 = -7;
    const LA_ERROR_BIOMETRY_LOCKOUT: i64 = -8;

    fn keychain_error(action: &str, status: i32) -> PasswordManagerError {
        PasswordManagerError::from(DatabaseError::Keyring(format!(
            "Failed to {} biometric keychain secret (status {})",
            action, status
        )))
    }

    fn sec_status(action: &str, status: i32) -> Result<()> {
        if status == errSecSuccess {
            Ok(())
        } else {
            Err(keychain_error(action, status))
        }
    }

    fn sec_class() -> CFString {
        // SAFETY: Security.framework returns immortal CFString constants.
        unsafe { CFString::wrap_under_get_rule(kSecClass) }
    }

    fn sec_class_generic_password() -> CFString {
        // SAFETY: Security.framework returns immortal CFString constants.
        unsafe { CFString::wrap_under_get_rule(kSecClassGenericPassword) }
    }

    fn sec_attr_service() -> CFString {
        // SAFETY: Security.framework returns immortal CFString constants.
        unsafe { CFString::wrap_under_get_rule(kSecAttrService) }
    }

    fn sec_attr_account() -> CFString {
        // SAFETY: Security.framework returns immortal CFString constants.
        unsafe { CFString::wrap_under_get_rule(kSecAttrAccount) }
    }

    fn sec_attr_access_control() -> CFString {
        // SAFETY: Security.framework returns immortal CFString constants.
        unsafe { CFString::wrap_under_get_rule(kSecAttrAccessControl) }
    }

    fn sec_value_data() -> CFString {
        // SAFETY: Security.framework returns immortal CFString constants.
        unsafe { CFString::wrap_under_get_rule(kSecValueData) }
    }

    fn sec_return_data() -> CFString {
        // SAFETY: Security.framework returns immortal CFString constants.
        unsafe { CFString::wrap_under_get_rule(kSecReturnData) }
    }

    fn sec_operation_prompt() -> CFString {
        // SAFETY: Security.framework returns immortal CFString constants.
        unsafe { CFString::wrap_under_get_rule(kSecUseOperationPrompt) }
    }

    fn base_query(biometric_ref: &str) -> Vec<(CFString, CFType)> {
        vec![
            (sec_class(), sec_class_generic_password().into_CFType()),
            (
                sec_attr_service(),
                CFString::from(BIOMETRIC_SERVICE_NAME).into_CFType(),
            ),
            (
                sec_attr_account(),
                CFString::from(biometric_ref).into_CFType(),
            ),
        ]
    }

    fn biometry_current_set_access_control() -> Result<CFType> {
        // SAFETY: The protection constant and flags are defined by Security.framework.
        let access_control = unsafe {
            SecAccessControlCreateWithFlags(
                kCFAllocatorDefault,
                kSecAttrAccessibleWhenPasscodeSetThisDeviceOnly as CFTypeRef,
                kSecAccessControlBiometryCurrentSet,
                ptr::null_mut(),
            )
        };
        if access_control.is_null() {
            return Err(PasswordManagerError::from(DatabaseError::Keyring(
                "Failed to create biometric keychain access control".to_string(),
            )));
        }

        // SAFETY: `SecAccessControlCreateWithFlags` follows Create Rule ownership.
        Ok(unsafe { CFType::wrap_under_create_rule(access_control as CFTypeRef) })
    }

    fn add_query(biometric_ref: &str, dek: &[u8]) -> Result<CFDictionary<CFString, CFType>> {
        let mut query = base_query(biometric_ref);
        query.push((
            sec_attr_access_control(),
            biometry_current_set_access_control()?,
        ));
        query.push((sec_value_data(), CFData::from_buffer(dek).into_CFType()));
        Ok(CFDictionary::from_CFType_pairs(&query))
    }

    fn load_query(biometric_ref: &str, reason: &str) -> CFDictionary<CFString, CFType> {
        let mut query = base_query(biometric_ref);
        query.push((sec_return_data(), CFBoolean::from(true).into_CFType()));
        query.push((sec_operation_prompt(), CFString::from(reason).into_CFType()));
        CFDictionary::from_CFType_pairs(&query)
    }

    fn delete_query(biometric_ref: &str) -> CFDictionary<CFString, CFType> {
        CFDictionary::from_CFType_pairs(&base_query(biometric_ref))
    }

    pub fn store_vault_dek(
        vault_path: &Path,
        dek: &crate::crypto::DataEncryptionKey,
    ) -> Result<String> {
        let biometric_ref = BiometricManager::biometric_ref_for_vault(vault_path);
        clear_vault_dek(&biometric_ref)?;

        let query = add_query(&biometric_ref, dek.as_bytes())?;
        // SAFETY: `query` is a well-formed SecItemAdd dictionary.
        sec_status("store", unsafe {
            SecItemAdd(query.as_concrete_TypeRef(), ptr::null_mut())
        })?;

        Ok(biometric_ref)
    }

    pub fn load_vault_dek(
        biometric_ref: &str,
        reason: &str,
    ) -> Result<crate::crypto::DataEncryptionKey> {
        let query = load_query(biometric_ref, reason);
        let mut item: CFTypeRef = ptr::null();
        // SAFETY: `query` is a well-formed SecItemCopyMatching dictionary and `item` is an out pointer.
        let status = unsafe { SecItemCopyMatching(query.as_concrete_TypeRef(), &mut item) };
        if status == errSecItemNotFound {
            return Err(PasswordManagerError::NotFound(
                "Biometric keychain secret is unavailable".to_string(),
            ));
        }
        sec_status("load", status)?;

        if item.is_null() {
            return Err(keychain_error("load", status));
        }

        // SAFETY: `item` is returned by a Copy operation and must be released on all paths.
        let data = unsafe {
            if CFGetTypeID(item) != CFData::type_id() {
                CFRelease(item);
                return Err(PasswordManagerError::from(DatabaseError::Keyring(
                    "Stored biometric keychain secret has unexpected type".to_string(),
                )));
            }
            CFData::wrap_under_create_rule(item as CFDataRef)
        };

        BiometricManager::decode_vault_dek_bytes(data.bytes().to_vec())
    }

    pub fn clear_vault_dek(biometric_ref: &str) -> Result<()> {
        let query = delete_query(biometric_ref);
        // SAFETY: `query` is a well-formed SecItemDelete dictionary.
        let status = unsafe { SecItemDelete(query.as_concrete_TypeRef()) };
        if status == errSecItemNotFound {
            return Ok(());
        }
        sec_status("clear", status)
    }

    fn la_error_code(error: id) -> Option<i64> {
        if error == nil {
            return None;
        }

        // SAFETY: `error` is an NSError-compatible Objective-C object from LocalAuthentication.
        let code: i64 = unsafe { msg_send![error, code] };
        Some(code)
    }

    fn can_evaluate_policy() -> std::result::Result<(), i64> {
        // SAFETY: Objective-C calls target LocalAuthentication API on macOS.
        unsafe {
            let Some(context_class) = Class::get("LAContext") else {
                return Err(LA_ERROR_BIOMETRY_NOT_AVAILABLE);
            };
            let context: id = msg_send![context_class, new];
            if context == nil {
                return Err(LA_ERROR_BIOMETRY_NOT_AVAILABLE);
            }

            let mut error: id = nil;
            let can_eval: BOOL = msg_send![
                context,
                canEvaluatePolicy: LAPOLICY_DEVICE_OWNER_AUTHENTICATION_WITH_BIOMETRICS
                error: &mut error
            ];
            let _: () = msg_send![context, release];

            if can_eval == YES {
                Ok(())
            } else {
                Err(la_error_code(error).unwrap_or(LA_ERROR_AUTHENTICATION_FAILED))
            }
        }
    }

    fn map_preflight_error(code: i64) -> BiometricResult {
        match code {
            LA_ERROR_BIOMETRY_NOT_ENROLLED => BiometricResult::NotEnrolled,
            LA_ERROR_BIOMETRY_NOT_AVAILABLE | LA_ERROR_PASSCODE_NOT_SET => {
                BiometricResult::NotAvailable
            }
            LA_ERROR_BIOMETRY_LOCKOUT => BiometricResult::Failed(
                "Touch ID is locked. Use your device passcode to re-enable it.".to_string(),
            ),
            _ => BiometricResult::Failed(format!("Touch ID preflight failed (code {})", code)),
        }
    }

    fn map_auth_error(error: id) -> BiometricResult {
        let code = la_error_code(error).unwrap_or(LA_ERROR_AUTHENTICATION_FAILED);
        match code {
            LA_ERROR_USER_CANCEL | LA_ERROR_SYSTEM_CANCEL => BiometricResult::Cancelled,
            LA_ERROR_BIOMETRY_NOT_ENROLLED => BiometricResult::NotEnrolled,
            LA_ERROR_BIOMETRY_NOT_AVAILABLE | LA_ERROR_PASSCODE_NOT_SET => {
                BiometricResult::NotAvailable
            }
            LA_ERROR_BIOMETRY_LOCKOUT => BiometricResult::Failed(
                "Touch ID is locked. Use your device passcode to re-enable it.".to_string(),
            ),
            LA_ERROR_AUTHENTICATION_FAILED => {
                BiometricResult::Failed("Touch ID authentication failed".to_string())
            }
            _ => BiometricResult::Failed(format!("Touch ID authentication failed (code {})", code)),
        }
    }

    pub fn is_touch_id_available() -> bool {
        match can_evaluate_policy() {
            Ok(()) => true,
            Err(code) => matches!(
                code,
                LA_ERROR_BIOMETRY_NOT_ENROLLED | LA_ERROR_BIOMETRY_LOCKOUT
            ),
        }
    }

    pub fn is_touch_id_enrolled() -> bool {
        match can_evaluate_policy() {
            Ok(()) => true,
            Err(code) => matches!(code, LA_ERROR_BIOMETRY_LOCKOUT),
        }
    }

    pub fn authenticate_with_touch_id(reason: &str) -> BiometricResult {
        if let Err(code) = can_evaluate_policy() {
            return map_preflight_error(code);
        }

        // SAFETY: Objective-C calls target LocalAuthentication API on macOS.
        unsafe {
            let Some(context_class) = Class::get("LAContext") else {
                return BiometricResult::NotAvailable;
            };
            let context: id = msg_send![context_class, new];
            if context == nil {
                return BiometricResult::NotAvailable;
            }

            let reason_ns = NSString::alloc(nil).init_str(reason);
            let (sender, receiver) = mpsc::channel::<BiometricResult>();

            let reply = ConcreteBlock::new(move |success: BOOL, error: id| {
                let result = if success == YES {
                    BiometricResult::Success
                } else {
                    map_auth_error(error)
                };
                let _ = sender.send(result);
            })
            .copy();

            let _: () = msg_send![
                context,
                evaluatePolicy: LAPOLICY_DEVICE_OWNER_AUTHENTICATION_WITH_BIOMETRICS
                localizedReason: reason_ns
                reply: &*reply
            ];

            let result = receiver
                .recv_timeout(Duration::from_secs(45))
                .unwrap_or_else(|_| {
                    BiometricResult::Failed("Timed out waiting for Touch ID response".to_string())
                });

            let _: () = msg_send![context, release];
            let _: () = msg_send![reason_ns, release];

            result
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_biometric_method_name() {
        let _name = BiometricManager::get_method_name();
        #[cfg(windows)]
        assert_eq!(_name, "Windows Hello");
        #[cfg(target_os = "macos")]
        assert_eq!(_name, "Touch ID");
    }

    #[test]
    fn test_is_available() {
        // This test will pass on supported platforms
        let _ = BiometricManager::is_available();
    }

    #[test]
    fn test_is_enrolled() {
        // This test will pass on supported platforms
        let _ = BiometricManager::is_enrolled();
    }

    #[test]
    fn test_current_biometric_policy_is_platform_native() {
        let policy = BiometricProtectionPolicy::current_platform();

        #[cfg(target_os = "macos")]
        {
            let policy = policy.unwrap();
            assert_eq!(policy, BiometricProtectionPolicy::MacosBiometryCurrentSet);
            assert!(policy.invalidates_on_biometric_enrollment_change());
        }

        #[cfg(windows)]
        {
            let policy = policy.unwrap();
            assert_eq!(policy, BiometricProtectionPolicy::WindowsHelloUserPresence);
            assert!(!policy.invalidates_on_biometric_enrollment_change());
        }

        #[cfg(not(any(windows, target_os = "macos")))]
        assert!(policy.is_err());
    }

    #[test]
    fn test_vault_dek_encoding_roundtrip() {
        let dek = DataEncryptionKey::new().unwrap();
        let encoded = BiometricManager::encode_vault_dek(&dek);
        let decoded = BiometricManager::decode_vault_dek(&encoded).unwrap();

        assert_eq!(decoded.as_bytes(), dek.as_bytes());
    }

    #[test]
    fn test_vault_dek_raw_bytes_roundtrip() {
        let dek = DataEncryptionKey::new().unwrap();
        let decoded = BiometricManager::decode_vault_dek_bytes(dek.as_bytes().to_vec()).unwrap();

        assert_eq!(decoded.as_bytes(), dek.as_bytes());
    }

    #[test]
    fn test_vault_dek_decode_rejects_legacy_master_password_length() {
        use base64::Engine;

        let legacy_encoded = base64::engine::general_purpose::STANDARD.encode(b"master-password");
        let err = match BiometricManager::decode_vault_dek(&legacy_encoded) {
            Ok(_) => panic!("legacy master-password-sized secret should not decode as a DEK"),
            Err(err) => err,
        };

        assert!(err.to_string().contains("invalid length"));
    }
}
