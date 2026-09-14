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

/** The subset of the Tauri invoke bridge this module needs. */
export type ClipboardInvoker = (cmd: string, args?: Record<string, unknown>) => Promise<unknown>;

/** Injectable timer pair so tests can drive expiry without real time. */
export interface ClipboardTimers {
    set(fn: () => void, ms: number): unknown;
    clear(handle: unknown): void;
}

export const defaultClipboardTimers: ClipboardTimers = {
    set: (fn, ms) => setTimeout(fn, ms),
    clear: (handle) => clearTimeout(handle as ReturnType<typeof setTimeout>)
};

export interface ClipboardManager {
    /**
     * Copy a secret to the native clipboard and (re)arm the expiry timer.
     * Resolves to `true` on success; a no-op resolving `false` for empty
     * input. Rejects with the backend error when the write fails.
     */
    copySecret(text: string): Promise<boolean>;
    /**
     * Cancel the pending timer and clear the clipboard immediately if it
     * still holds the registered secret. Resolves to whether it was cleared.
     */
    expireNow(): Promise<boolean>;
    /** Cancel the pending expiry timer without clearing anything. */
    cancelExpiry(): void;
    /** Whether a copy is still waiting for its expiry tick. */
    hasPendingExpiry(): boolean;
}

/**
 * Build the app's clipboard controller. `onExpiry` fires after the timer
 * runs with whether the clipboard was actually cleared (used for the
 * "Clipboard cleared" toast).
 */
export function createClipboardManager(
    invoke: ClipboardInvoker,
    timers: ClipboardTimers = defaultClipboardTimers,
    onExpiry?: (cleared: boolean) => void
): ClipboardManager {
    let expiryHandle: unknown = null;

    function cancelExpiry(): void {
        if (expiryHandle !== null) {
            timers.clear(expiryHandle);
            expiryHandle = null;
        }
    }

    async function clearIfStillOurs(): Promise<boolean> {
        try {
            return (await invoke('expire_clipboard_secret')) === true;
        } catch {
            // Backend unreachable — nothing safe to do from the UI side.
            return false;
        }
    }

    return {
        async copySecret(text: string): Promise<boolean> {
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

        async expireNow(): Promise<boolean> {
            cancelExpiry();
            return clearIfStillOurs();
        },

        cancelExpiry,

        hasPendingExpiry(): boolean {
            return expiryHandle !== null;
        }
    };
}
