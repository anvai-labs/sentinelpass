/**
 * SentinelPass Desktop UI — clipboard secret controller (WBS-709).
 *
 * Secret copies go through the backend (`copy_secret_to_clipboard`), which
 * writes to the native clipboard with platform sensitive-markers and
 * registers only a SHA-256 digest. This module owns the single expiry
 * timer: 30 seconds after each copy it asks the backend to clear the
 * clipboard IF it still holds that secret (clear-on-expiry), and the
 * backend repeats the same check on app exit (clear-on-exit hook).
 */
/** How long a copied secret may stay on the clipboard before expiry. */
export const CLIPBOARD_EXPIRY_MS = 30_000;
export const defaultClipboardTimers = {
    set: (fn, ms) => setTimeout(fn, ms),
    clear: (handle) => clearTimeout(handle)
};
/**
 * Build the app's clipboard controller. `onExpiry` fires after the timer
 * runs with whether the clipboard was actually cleared (used for the
 * "Clipboard cleared" toast).
 */
export function createClipboardManager(invoke, timers = defaultClipboardTimers, onExpiry) {
    let expiryHandle = null;
    function cancelExpiry() {
        if (expiryHandle !== null) {
            timers.clear(expiryHandle);
            expiryHandle = null;
        }
    }
    async function clearIfStillOurs() {
        try {
            return (await invoke('expire_clipboard_secret')) === true;
        }
        catch {
            // Backend unreachable — nothing safe to do from the UI side.
            return false;
        }
    }
    return {
        async copySecret(text) {
            if (!text) {
                return false;
            }
            await invoke('copy_secret_to_clipboard', { secret: text });
            // Only the most recent copy is pending: re-arm (not stack) the
            // timer, mirroring the backend's single-digest tracker.
            cancelExpiry();
            expiryHandle = timers.set(() => {
                expiryHandle = null;
                void clearIfStillOurs().then((cleared) => {
                    if (onExpiry) {
                        onExpiry(cleared);
                    }
                });
            }, CLIPBOARD_EXPIRY_MS);
            return true;
        },
        async expireNow() {
            cancelExpiry();
            return clearIfStillOurs();
        },
        cancelExpiry,
        hasPendingExpiry() {
            return expiryHandle !== null;
        }
    };
}
