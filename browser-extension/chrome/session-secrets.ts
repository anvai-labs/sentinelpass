/**
 * Extension session-secret registry (WBS-716, TD-CLIENT-07).
 *
 * Single source of truth for WHICH `chrome.storage.session` keys carry
 * secret material, how long each may live, and when an entry counts as
 * expired. The background worker uses this module to
 *
 *  - stamp `expiresAt` on every secret entry it writes (bounded lifetime —
 *    no long-lived plaintext in session storage),
 *  - sweep expired entries from a `chrome.alarms` tick (service workers
 *    cannot rely on timers), and
 *  - purge everything on an explicit vault lock or browser-session end
 *    (session storage itself dies with the browser session).
 *
 * Content scripts NEVER hold session-secret material: since WBS-716 they
 * hand captured submissions to the background (`capture_pending_login`) and
 * only ASK whether a pending login should be resumed (`resume_pending_login`)
 * — plaintext never round-trips back to a page context.
 *
 * This module is pure (no `chrome.*` calls) so the policy is unit-testable.
 */

/** Session-storage key holding one pending login submission. */
export const PENDING_CREDENTIAL_KEY = 'pendingCredential';

/** Prefix for per-notification pending save payloads. */
export const PENDING_SAVE_PREFIX = 'pendingSaveCredential:';

/** Prefix for inline-prompt payloads held by the background (WBS-716 review
 * fix F1: the content script's inline prompt references one of these by id
 * and NEVER receives the password itself). */
export const PENDING_INLINE_PREFIX = 'pendingInlinePrompt:';

/** Session-storage key holding a locked-vault save retry. */
export const PENDING_UNLOCK_RETRY_KEY = 'pendingUnlockRetry';

/** How long a captured pending login may live (the 2FA-page window). */
export const PENDING_CREDENTIAL_TTL_MS = 30_000;

/** How long a per-notification save payload may live. */
export const PENDING_SAVE_TTL_MS = 10 * 60_000;

/** How long a locked-vault save retry may live. */
export const PENDING_UNLOCK_RETRY_TTL_MS = 2 * 60_000;

/**
 * True when `key` is a session-storage key whose value contains secret
 * material (usernames and/or passwords in plaintext).
 */
export function isSessionSecretKey(key: string): boolean {
  return (
    key === PENDING_CREDENTIAL_KEY ||
    key === PENDING_UNLOCK_RETRY_KEY ||
    key.startsWith(PENDING_SAVE_PREFIX) ||
    key.startsWith(PENDING_INLINE_PREFIX)
  );
}

/**
 * The bounded lifetime for a session-secret key, in milliseconds.
 * Unknown keys return null (not secret material — never swept by policy).
 */
export function sessionSecretTtlMs(key: string): number | null {
  if (key === PENDING_CREDENTIAL_KEY) {
    return PENDING_CREDENTIAL_TTL_MS;
  }
  if (key.startsWith(PENDING_SAVE_PREFIX) || key.startsWith(PENDING_INLINE_PREFIX)) {
    return PENDING_SAVE_TTL_MS;
  }
  if (key === PENDING_UNLOCK_RETRY_KEY) {
    return PENDING_UNLOCK_RETRY_TTL_MS;
  }
  return null;
}

/**
 * The `expiresAt` stamp for a fresh entry of `key` written at `now`.
 * Null for keys that are not session secrets (caller should not store
 * those under this policy, but must not stamp them either).
 */
export function sessionSecretExpiry(key: string, now: number): number | null {
  const ttl = sessionSecretTtlMs(key);
  return ttl === null ? null : now + ttl;
}

/**
 * Whether the entry stored under `key` is expired at `now`.
 *
 * Fail-closed: a missing/forged/never-stamped `expiresAt` on a key that is
 * SUPPOSED to be stamped counts as expired (swept) — an entry must not
 * escape its bounded lifetime by losing its stamp. Unknown (non-secret)
 * keys are never "expired" by this predicate.
 */
export function isSessionSecretExpired(
  key: string,
  value: unknown,
  now: number
): boolean {
  if (!isSessionSecretKey(key)) {
    return false;
  }
  const expiresAt =
    value && typeof value === 'object' && !Array.isArray(value)
      ? (value as { expiresAt?: unknown }).expiresAt
      : undefined;
  return typeof expiresAt !== 'number' || !Number.isFinite(expiresAt) || expiresAt <= now;
}

/**
 * Which of `keys` hold expired secret entries at `now` (the sweep list).
 */
export function expiredSessionSecretKeys(
  keys: string[],
  lookup: (key: string) => unknown,
  now: number
): string[] {
  return keys.filter((key) => isSessionSecretExpired(key, lookup(key), now));
}
