/**
 * Debug logging utility for the browser extension.
 *
 * In production builds, sensitive information (URLs, hostnames, password lengths,
 * credential flow events) is not logged to protect user privacy and reduce
 * information leakage through support logs or browser console inspection.
 *
 * Debug mode can be enabled via:
 * 1. Loading as unpacked extension (auto-detected)
 * 2. Setting chrome-extension logging level to verbose in chrome://extensions
 * 3. Manually enabling via chrome.storage.local for support diagnostics
 */

// Auto-detect development mode: unpacked extensions are in development
// Production extensions from the web store will have a different install type
let debugMode = false;

// Initialize debug mode detection
function initDebugMode(): void {
  if (typeof chrome !== 'undefined' && chrome.management) {
    chrome.management.getSelf((info) => {
      // Unpacked extensions are development builds
      if (info.installType === 'development') {
        debugMode = true;
      }
    });
  }

  // Check storage for user-enabled debug mode (for support diagnostics)
  if (typeof chrome !== 'undefined' && chrome.storage) {
    chrome.storage.local.get(['debugModeEnabled'], (result) => {
      if (result.debugModeEnabled === true) {
        debugMode = true;
      }
    });
  }
}

// Initialize on load
initDebugMode();

/**
 * Set debug mode on or off (persists to chrome.storage).
 */
function setDebugMode(enabled: boolean): void {
  debugMode = enabled;
  if (typeof chrome !== 'undefined' && chrome.storage) {
    chrome.storage.local.set({ debugModeEnabled: enabled });
  }
}

/**
 * Check if debug mode is enabled.
 */
export function isDebugEnabled(): boolean {
  return debugMode;
}

/**
 * Log a debug message. Only logs in debug mode.
 * Sensitive information should never be logged through this in production.
 */
export function debugLog(...args: unknown[]): void {
  if (debugMode) {
    console.log('[SentinelPass Debug]', ...args);
  }
}

/**
 * Log an info message. Always logged, but with reduced verbosity.
 * Use for non-sensitive operational messages only.
 */
export function infoLog(message: string, ...args: unknown[]): void {
  console.log(`[SentinelPass] ${message}`, ...args);
}

/**
 * Log a warning. Always logged.
 * Use for error conditions and important notices.
 */
export function warnLog(message: string, ...args: unknown[]): void {
  console.warn(`[SentinelPass] ${message}`, ...args);
}

/**
 * Log an error. Always logged.
 * Use for critical failures and exceptions.
 */
export function errorLog(message: string, ...args: unknown[]): void {
  console.error(`[SentinelPass] ${message}`, ...args);
}

/**
 * Sanitize URL for logging - removes sensitive parts like query strings and fragments.
 * In production, returns only the origin (protocol + host) to avoid logging specific pages.
 */
export function sanitizeUrl(url: string): string {
  if (debugMode) {
    return url; // Full URL in debug mode
  }

  try {
    const urlObj = new URL(url);
    return urlObj.origin; // Only protocol + host in production
  } catch {
    return '(invalid URL)';
  }
}

/**
 * Sanitize hostname for logging - returns a generic indicator in production.
 */
export function sanitizeHostname(hostname: string): string {
  if (debugMode) {
    return hostname; // Full hostname in debug mode
  }
  return '(hostname)'; // Generic indicator in production
}

/**
 * Sanitize password length for logging - returns whether password is empty/weak/strong
 * rather than exact length.
 */
export function sanitizePasswordLength(password: string): string {
  if (debugMode) {
    return password.length.toString(); // Exact length in debug mode
  }

  if (!password) {
    return 'empty';
  } else if (password.length < 8) {
    return 'short (<8 chars)';
  } else if (password.length < 12) {
    return 'medium (8-11 chars)';
  } else {
    return 'long (12+ chars)';
  }
}
