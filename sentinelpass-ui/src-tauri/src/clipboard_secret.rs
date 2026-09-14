//! Native expiring/sensitive clipboard support (WBS-709).
//!
//! Secrets the UI copies are written straight to the OS clipboard from Rust
//! via `arboard`, marked as sensitive where the platform offers it (macOS
//! writes the `org.nspasteboard.ConcealedType` marker; Windows sets the
//! `ExcludeClipboardContentFromMonitorProcessing` /
//! `CanUploadToCloudClipboard` exclusions so clipboard history and cloud
//! sync skip the value), and registered in a tracker that keeps ONLY a
//! SHA-256 digest of the secret — never the plaintext.
//!
//! The digest lets the expiry timer (invoked by the frontend 30 seconds
//! after each copy — see `sentinelpass-ui/clipboard.ts`) and the app-exit
//! hook tell "the clipboard still holds our secret" apart from "the user
//! copied something else afterwards", so the auto-clear never wipes
//! unrelated user content and can run without any plaintext copy living in
//! Rust state.

use sha2::{Digest, Sha256};
use subtle::ConstantTimeEq;

/// SHA-256 of `input`. The tracker compares digests, not secrets.
pub fn secret_digest(input: &[u8]) -> [u8; 32] {
    let mut hasher = Sha256::new();
    hasher.update(input);
    hasher.finalize().into()
}

/// Tracks the most recent secret this app placed on the system clipboard
/// without storing the secret itself (WBS-709).
///
/// Note on digest precision: for LOW-ENTROPY secrets (e.g. a 6-digit TOTP
/// code) a SHA-256 digest is brute-forceable if process memory is later
/// disclosed. That is acceptable here — the plaintext lived in the same
/// process memory — and is the price of letting expiry/exit clear the
/// clipboard without retaining the secret itself.
#[derive(Default)]
pub struct ClipboardSecretTracker {
    pending_digest: Option<[u8; 32]>,
}

impl ClipboardSecretTracker {
    pub fn new() -> Self {
        Self::default()
    }

    /// Record the digest of the secret that was just written to the
    /// clipboard. Any previously registered secret is superseded: only the
    /// most recent copy is ever auto-cleared.
    pub fn register(&mut self, secret: &[u8]) {
        self.pending_digest = Some(secret_digest(secret));
    }

    /// Drop the registration (expiry handled, user replaced the clipboard,
    /// or nothing was pending).
    pub fn clear_registration(&mut self) {
        self.pending_digest = None;
    }

    /// Constant-time "does the clipboard's current content hash to the
    /// registered digest?". Empty/unreadable clipboards never match.
    pub fn matches_clipboard(&self, current_clipboard: Option<&str>) -> bool {
        match (self.pending_digest, current_clipboard) {
            (Some(expected), Some(current)) => {
                expected
                    .ct_eq(&secret_digest(current.as_bytes()))
                    .unwrap_u8()
                    == 1
            }
            _ => false,
        }
    }
}

/// Write `text` to the system clipboard with platform sensitive-markers.
fn set_sensitive(clipboard: &mut arboard::Clipboard, text: &str) -> Result<(), arboard::Error> {
    #[cfg(target_os = "macos")]
    {
        use arboard::SetExtApple as _;
        clipboard
            .set()
            .exclude_from_history()
            .text(text.to_string())
    }
    #[cfg(target_os = "windows")]
    {
        use arboard::SetExtWindows as _;
        clipboard
            .set()
            .exclude_from_monitoring()
            .exclude_from_cloud()
            .exclude_from_history()
            .text(text.to_string())
    }
    #[cfg(all(unix, not(target_os = "macos")))]
    {
        // No sensitive-marker convention; plain text. (Without `wait()` the
        // value also disappears on X11 when this process exits, which for a
        // secret is the desired direction.)
        clipboard.set().text(text.to_string())
    }
}

/// Write a secret to the native clipboard, marked sensitive where the
/// platform supports it (WBS-709).
pub fn write_secret_to_clipboard(text: &str) -> Result<(), String> {
    let mut clipboard =
        arboard::Clipboard::new().map_err(|e| format!("Clipboard unavailable: {}", e))?;
    set_sensitive(&mut clipboard, text).map_err(|e| format!("Clipboard write failed: {}", e))
}

/// Read the current clipboard text, or `None` if it is empty, non-text, or
/// the clipboard cannot be opened right now.
pub fn read_clipboard_text() -> Option<String> {
    let mut clipboard = arboard::Clipboard::new().ok()?;
    clipboard.get_text().ok()
}

/// Clear the system clipboard.
///
/// Races: `expire_registered_clipboard` reads the clipboard before deciding
/// to clear, so another process overwriting the clipboard inside that
/// millisecond window could have its content cleared by our expiry. This
/// window is inherent to match-then-clear designs (the same trade-off every
/// password manager's auto-clear makes) and is bounded to content written
/// between the read and the clear; in-process ordering is strict because
/// all clipboard commands run on the main thread.
pub fn clear_clipboard() -> Result<(), String> {
    let mut clipboard =
        arboard::Clipboard::new().map_err(|e| format!("Clipboard unavailable: {}", e))?;
    clipboard
        .clear()
        .map_err(|e| format!("Clipboard clear failed: {}", e))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn digest_is_stable_and_binds_content() {
        let a = secret_digest(b"secret-value");
        let b = secret_digest(b"secret-value");
        let c = secret_digest(b"secret-value2");
        assert_eq!(a, b, "same input must hash identically");
        assert_ne!(a, c, "different input must hash differently");
        assert_ne!(a, [0u8; 32], "digest must not be all-zero for real input");
    }

    #[test]
    fn registered_secret_matches_identical_clipboard_content() {
        let mut tracker = ClipboardSecretTracker::new();
        assert!(!tracker.matches_clipboard(Some("secret-value")));

        tracker.register(b"secret-value");
        assert!(tracker.matches_clipboard(Some("secret-value")));
        assert!(
            tracker.matches_clipboard(Some("secret-value")),
            "matching must be repeatable (no consumption on compare)"
        );
    }

    #[test]
    fn replaced_clipboard_content_does_not_match() {
        let mut tracker = ClipboardSecretTracker::new();
        tracker.register(b"secret-value");
        assert!(!tracker.matches_clipboard(Some("user copied something else")));
        assert!(!tracker.matches_clipboard(Some("")));
    }

    #[test]
    fn empty_or_unreadable_clipboard_never_matches() {
        let mut tracker = ClipboardSecretTracker::new();
        tracker.register(b"secret-value");
        assert!(!tracker.matches_clipboard(None));
    }

    #[test]
    fn clear_registration_drops_the_pending_secret() {
        let mut tracker = ClipboardSecretTracker::new();
        tracker.register(b"secret-value");
        tracker.clear_registration();
        assert!(!tracker.matches_clipboard(Some("secret-value")));
    }

    #[test]
    fn re_registration_supersedes_the_previous_secret() {
        let mut tracker = ClipboardSecretTracker::new();
        tracker.register(b"first-secret");
        tracker.register(b"second-secret");
        assert!(!tracker.matches_clipboard(Some("first-secret")));
        assert!(tracker.matches_clipboard(Some("second-secret")));
    }
}
