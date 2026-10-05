//! Windows context diagnostics and disabled legacy native-autofill entry points.
//!
//! A foreground window/title is not a verified origin or authorization to release
//! a credential. The unshipped direct-vault clipboard/input prototype is retired;
//! browser autofill continues through the daemon and native messaging host.

use super::{native_autofill_unavailable, AutoFillResult, CredentialMatch};
use crate::{PasswordManagerError, Result};
use windows::Win32::Foundation::HWND;
use windows::Win32::UI::WindowsAndMessaging::{GetForegroundWindow, GetWindowTextW, IsWindow};

const TITLE_CAPACITY: usize = 512;

/// Read diagnostic context only. `domain` is always `None`.
pub fn get_context() -> Result<AutoFillContext> {
    // SAFETY: GetForegroundWindow takes no pointers and does not transfer ownership.
    context_for_window(unsafe { GetForegroundWindow() })
}

fn context_for_window(hwnd: HWND) -> Result<AutoFillContext> {
    // SAFETY: Win32 validates opaque handles; no Rust pointer is dereferenced here.
    if hwnd.is_invalid() || !unsafe { IsWindow(Some(hwnd)) }.as_bool() {
        return Err(PasswordManagerError::InvalidInput(
            "No valid window for diagnostic context".into(),
        ));
    }
    let mut buffer = [0u16; TITLE_CAPACITY];
    // SAFETY: the generated binding supplies the buffer pointer AND its length
    // with the correct Win32 ABI. Titles may be empty or truncated; they never
    // become an authority/domain assertion. The API handles a disappearing HWND.
    // KNOWN AMBIGUITY (review nit 2, deliberately tolerated): GetWindowTextW
    // returns 0 both for an empty title and for API failure, and Win32 leaves
    // the last-error value STALE on success paths — so the two cannot be
    // reliably distinguished and an API failure yields Ok(""). Acceptable
    // here: the title is diagnostics/provenance only and never an authority
    // assertion (a wrong-empty title cannot widen any decision).
    let length = unsafe { GetWindowTextW(hwnd, &mut buffer) };
    let length = usize::try_from(length)
        .ok()
        .filter(|length| *length < buffer.len())
        .ok_or_else(|| PasswordManagerError::InvalidInput("Invalid window title length".into()))?;
    Ok(AutoFillContext {
        window_handle: hwnd,
        window_title: String::from_utf16_lossy(&buffer[..length]),
        domain: None,
    })
}

/// Disabled: requires daemon authority, explicit consent and a bound destination.
pub fn autofill_via_clipboard(
    _credential: &CredentialMatch,
    _vault_manager: &crate::vault::VaultManager,
) -> Result<AutoFillResult> {
    Err(native_autofill_unavailable())
}

/// Disabled: never decrypts a credential or injects input into a foreground window.
pub fn autofill_via_input(
    _credential: &CredentialMatch,
    _vault_manager: &crate::vault::VaultManager,
) -> Result<AutoFillResult> {
    Err(native_autofill_unavailable())
}

/// Disabled along with the legacy native credential-delivery path.
pub fn register_hotkey(_modifiers: u32, _vk: u32) -> Result<()> {
    Err(native_autofill_unavailable())
}

/// Untrusted diagnostic context. Never use the title/handle as credential authority.
pub struct AutoFillContext {
    pub window_handle: HWND,
    pub window_title: String,
    /// Always `None`: window titles cannot establish a verified web origin.
    pub domain: Option<String>,
}

#[cfg(test)]
mod tests {
    use super::*;
    use windows::core::{w, PCWSTR};
    use windows::Win32::UI::WindowsAndMessaging::{
        CreateWindowExW, DestroyWindow, WINDOW_EX_STYLE, WINDOW_STYLE,
    };

    struct TestWindow(HWND);

    impl TestWindow {
        fn new(title: &str) -> Self {
            let title: Vec<u16> = title.encode_utf16().chain(Some(0)).collect();
            // SAFETY: STATIC is a system class; both strings remain alive through
            // the call. This is an invisible, test-owned window: never foreground,
            // never shown, and never a clipboard owner or input recipient.
            Self(unsafe {
                CreateWindowExW(
                    WINDOW_EX_STYLE::default(),
                    w!("STATIC"),
                    PCWSTR(title.as_ptr()),
                    WINDOW_STYLE::default(),
                    0,
                    0,
                    1,
                    1,
                    None,
                    None,
                    None,
                    None,
                )
                .expect("create hidden synthetic window")
            })
        }
    }

    impl Drop for TestWindow {
        fn drop(&mut self) {
            // SAFETY: the window is owned by this guard and destroyed on its thread.
            let _ = unsafe { DestroyWindow(self.0) };
        }
    }

    #[test]
    fn native_title_binding_reads_unicode_but_never_asserts_an_origin() {
        for title in [
            "",
            "example.invalid - Google Chrome",
            "https://example.invalid/login",
            "नमस्ते 🔐 — synthetic",
        ] {
            let window = TestWindow::new(title);
            let context = context_for_window(window.0).unwrap();
            assert_eq!(context.window_title, title);
            assert_eq!(context.domain, None);
        }
    }

    #[test]
    fn long_native_title_is_bounded_and_null_handle_rejected() {
        let window = TestWindow::new(&"x".repeat(TITLE_CAPACITY * 4));
        let context = context_for_window(window.0).unwrap();
        assert_eq!(context.window_title.len(), TITLE_CAPACITY - 1);
        assert!(context.domain.is_none());
        assert!(context_for_window(HWND::default()).is_err());
    }

    #[test]
    fn native_delivery_denies_before_vault_access_or_os_side_effects() {
        let vault = super::super::tests::unavailable_vault();
        for id in ["1", "not-an-id"] {
            let credential = super::super::tests::synthetic_match(id);
            for result in [
                autofill_via_clipboard(&credential, &vault),
                autofill_via_input(&credential, &vault),
            ] {
                assert!(matches!(
                    result,
                    Err(PasswordManagerError::NotImplemented(_))
                ));
            }
        }
        assert!(matches!(
            register_hotkey(6, 0x74),
            Err(PasswordManagerError::NotImplemented(_))
        ));
    }
}
