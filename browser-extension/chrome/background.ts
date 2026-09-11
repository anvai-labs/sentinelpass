// Background service worker for Password Manager Extension
import {
  autofillPageUrlForDaemon,
  classifyCredentialUrlSecurity,
  domainMatchesPolicy,
  normalizeCredentialUrl,
  normalizeDomainForPolicy,
  normalizeUsername,
  isUsernameMatchOrUnknown,
} from './save-heuristics.js';
import { debugLog, infoLog, warnLog, errorLog } from './logger.js';
import {
  PENDING_CREDENTIAL_KEY,
  PENDING_CREDENTIAL_TTL_MS,
  PENDING_INLINE_PREFIX,
  PENDING_SAVE_PREFIX,
  PENDING_SAVE_TTL_MS,
  isSessionSecretExpired,
  isSessionSecretKey,
  sessionSecretExpiry
} from './session-secrets.js';

// Native messaging host configuration
const HOST_NAME = 'com.passwordmanager.host';
const NOTIFICATION_ICON_URL = chrome.runtime.getURL('icon128.png');

infoLog('Background service worker loaded');
debugLog('Host name:', HOST_NAME);
debugLog('Extension ID:', chrome.runtime.id);

// ========================================
// Helper Functions
// ========================================

const SENSITIVE_LOG_KEYS = new Set(['password', 'secret', 'token', 'passphrase', 'totp_code']);
const NEVER_SAVE_DOMAINS_KEY = 'neverSaveDomains';
const SAVE_NOTIFICATION_DEDUP_WINDOW_MS = 4000;
const PENDING_UNLOCK_RETRY_KEY = 'pendingUnlockRetry';
const VAULT_LOCKED_NOTIFICATION_PREFIX = 'vault-locked-';
const recentSaveNotificationRequests = new Map();
const handledSaveNotifications = new Set();

// Rate limiting for message handlers
const MESSAGE_RATE_LIMIT_MAX = 30;
const MESSAGE_RATE_LIMIT_WINDOW_MS = 5000;
const messageRateTracker = new Map<number, number[]>();

function isMessageRateLimited(tabId: number): boolean {
  const now = Date.now();
  const timestamps = messageRateTracker.get(tabId) || [];
  const recent = timestamps.filter(t => now - t < MESSAGE_RATE_LIMIT_WINDOW_MS);
  recent.push(now);
  messageRateTracker.set(tabId, recent);
  return recent.length > MESSAGE_RATE_LIMIT_MAX;
}

// Periodic cleanup of stale rate-limit entries
setInterval(() => {
  const now = Date.now();
  for (const [tabId, timestamps] of messageRateTracker) {
    const recent = timestamps.filter(t => now - t < MESSAGE_RATE_LIMIT_WINDOW_MS);
    if (recent.length === 0) {
      messageRateTracker.delete(tabId);
    } else {
      messageRateTracker.set(tabId, recent);
    }
  }
}, 60000);
let lastVaultLockedNotificationAt = 0;
const ALLOWED_WEB_PROTOCOLS = new Set(['http:', 'https:']);

function generateRequestId() {
  if (globalThis.crypto?.randomUUID) {
    return globalThis.crypto.randomUUID();
  }
  return `req-${Date.now()}-${Math.random().toString(16).slice(2, 10)}`;
}

// Returns true when the message was sent from this extension's own popup,
// options page, or ANY of our own extension pages (they may be opened in a
// tab — popup-as-tab is a supported pattern and site-access management
// depends on it) rather than from a content script embedded in a web page.
// Messages from our own pages are already authenticated (same extension ID,
// and sender.url reflects the actual sending frame — a web page can never
// present an extension-page URL), so domain-context checks are skipped.
function isPopupSender(sender): boolean {
  if (!sender.tab) {
    return true;
  }
  const ownBaseUrl = chrome.runtime.getURL('');
  return typeof sender.url === 'string' && sender.url.startsWith(ownBaseUrl);
}

// WBS-711 review fix F2: content-script payloads never supply stored or
// validated URLs — the browser-provided frame URL is authoritative for
// anything the daemon parses (page_url) or stores (canonical save URL).
// Popup senders keep their own values (they save arbitrary entries by
// design and have no meaningful frame URL).
function withSenderProvenance(data, sender) {
  if (isPopupSender(sender) || !sender?.url) {
    return data;
  }
  return { ...data, url: sender.url, submitted_url: sender.url };
}

function normalizeHostForSenderValidation(value) {
  if (!value || typeof value !== 'string') {
    return null;
  }

  const trimmed = value.trim();
  if (!trimmed) {
    return null;
  }

  if (trimmed.includes('://')) {
    try {
      const parsed = new URL(trimmed);
      if (!ALLOWED_WEB_PROTOCOLS.has(parsed.protocol)) {
        return null;
      }
      const host = parsed.hostname.trim().replace(/^\.+|\.+$/g, '').toLowerCase();
      return host || null;
    } catch (_error) {
      return null;
    }
  }

  const host = trimmed.replace(/^\.+|\.+$/g, '').toLowerCase();
  return host || null;
}

function collectSenderHosts(sender) {
  const hosts = [];
  const frameHost = normalizeHostForSenderValidation(sender?.url);
  const tabHost = normalizeHostForSenderValidation(sender?.tab?.url);

  if (frameHost) {
    hosts.push(frameHost);
  }
  if (tabHost && !hosts.includes(tabHost)) {
    hosts.push(tabHost);
  }

  return hosts;
}

function validateSenderDomainContext(sender, claimedDomainOrUrl, requestType) {
  const claimedHost = normalizeHostForSenderValidation(claimedDomainOrUrl);
  if (!claimedHost) {
    return {
      ok: false,
      error: `Missing or invalid domain context for ${requestType}`
    };
  }

  const frameHost = normalizeHostForSenderValidation(sender?.url);
  const tabHost = normalizeHostForSenderValidation(sender?.tab?.url);
  const isSubframe = typeof sender?.frameId === 'number' && sender.frameId > 0;
  if (isSubframe && frameHost && tabHost && frameHost !== tabHost) {
    return {
      ok: false,
      error: `Cross-origin iframe sender blocked for ${requestType} (frame=${frameHost}, tab=${tabHost})`
    };
  }

  const senderHosts = collectSenderHosts(sender);
  if (senderHosts.length === 0) {
    return {
      ok: false,
      error: `Missing sender URL context for ${requestType}`
    };
  }

  if (!senderHosts.includes(claimedHost)) {
    return {
      ok: false,
      error: `Sender URL host mismatch for ${requestType} (claimed=${claimedHost}, sender=${senderHosts.join(',')})`
    };
  }

  return {
    ok: true,
    claimedHost,
    senderHosts
  };
}

async function isCredentialUnchanged(data) {
  if (!data?.domain || typeof data?.password !== 'string' || !data.password) {
    return false;
  }

  try {
    const response = await handleGetCredential(
      data.domain,
      generateRequestId(),
      // Browser-provided URL (the dispatch layer overwrites payload URLs
      // with sender.url — review F2); a delivery denial here only means
      // the unchanged-check cannot run (fail-safe: the save proceeds as a
      // duplicate upsert).
      data?.submitted_url || data?.url || null,
      undefined
    );
    if (!response?.success || !response?.data?.password) {
      return false;
    }

    const existingPassword = response.data.password;
    if (existingPassword !== data.password) {
      return false;
    }

    const submittedUsername = normalizeUsername(data.username);
    const existingUsername = normalizeUsername(response.data.username);
    const inputMethod = typeof data?.input_method === 'string'
      ? data.input_method
      : 'manual_or_unknown';

    if (isUsernameMatchOrUnknown(submittedUsername, existingUsername)) {
      return true;
    }

    if (inputMethod === 'autofill_reuse') {
      // Autofill provided this value in the same tab; password match is enough to treat as unchanged.
      return true;
    }

    return false;
  } catch (error) {
    console.error('[SentinelPass Background] Failed unchanged-credential check:', error);
    return false;
  }
}

function redactForLog(value) {
  if (!value || typeof value !== 'object') {
    return value;
  }

  if (Array.isArray(value)) {
    return value.map(redactForLog);
  }

  const redacted = {};
  for (const [key, item] of Object.entries(value)) {
    if (SENSITIVE_LOG_KEYS.has(key.toLowerCase())) {
      redacted[key] = '[REDACTED]';
    } else if (item && typeof item === 'object') {
      redacted[key] = redactForLog(item);
    } else {
      redacted[key] = item;
    }
  }

  return redacted;
}

function createNotification(notificationId, options) {
  return new Promise((resolve, reject) => {
    const payload = {
      type: 'basic',
      iconUrl: NOTIFICATION_ICON_URL,
      ...options
    };

    chrome.notifications.create(notificationId, payload, (createdId) => {
      if (chrome.runtime.lastError) {
        reject(new Error(chrome.runtime.lastError.message));
        return;
      }
      resolve(createdId);
    });
  });
}

function sessionGet(keys) {
  return new Promise((resolve) => {
    chrome.storage.session.get(keys, (result) => {
      if (chrome.runtime.lastError) {
        console.error('[SentinelPass Background] Session get failed:', chrome.runtime.lastError.message);
        resolve({});
        return;
      }
      resolve(result || {});
    });
  });
}

function sessionSet(items) {
  return new Promise<void>((resolve) => {
    chrome.storage.session.set(items, () => {
      if (chrome.runtime.lastError) {
        console.error('[SentinelPass Background] Session set failed:', chrome.runtime.lastError.message);
      }
      resolve();
    });
  });
}

function sessionRemove(keys) {
  return new Promise<void>((resolve) => {
    chrome.storage.session.remove(keys, () => {
      if (chrome.runtime.lastError) {
        console.error('[SentinelPass Background] Session remove failed:', chrome.runtime.lastError.message);
      }
      resolve();
    });
  });
}

// ── WBS-716 session-secret hygiene ──────────────────────────────────────────

const PURGE_SESSION_SECRETS_ALARM = 'purge-session-secrets';

// One alarm tick per minute: sweep expired session-secret entries, and
// clear everything if the vault was locked OUTSIDE this extension (daemon
// auto-lock, CLI, UI — native messaging has no push channel, review F5).
function sweepExpiredSessionSecrets() {
  void (async () => {
    const all = await sessionGet(null);
    const keys = Object.keys(all || {});
    const expired = keys.filter((key) => isSessionSecretExpired(key, all[key], Date.now()));
    if (expired.length > 0) {
      debugLog('[SentinelPass Background] Sweeping expired session secrets:', expired.length);
      await sessionRemove(expired);
    }

    if (Object.keys(all || {}).some((key) => isSessionSecretKey(key))) {
      try {
        const status = await handleCheckVaultStatus();
        if (status.success && !status.unlocked) {
          debugLog('[SentinelPass Background] Vault locked externally; purging pending secrets');
          await purgeAllSessionSecrets();
          await broadcastScrubSecrets();
        }
      } catch (error) {
        debugLog('[SentinelPass Background] Locked-state check failed:', error);
      }
    }
  })();
}

if (chrome.alarms) {
  chrome.alarms.create(PURGE_SESSION_SECRETS_ALARM, { periodInMinutes: 1 });
  chrome.alarms.onAlarm.addListener((alarm) => {
    if (alarm.name === PURGE_SESSION_SECRETS_ALARM) {
      sweepExpiredSessionSecrets();
    }
  });
}

// Purge EVERY session-secret entry (vault lock / explicit scrub).
async function purgeAllSessionSecrets() {
  const all = await sessionGet(null);
  const secretKeys = Object.keys(all || {}).filter((key) => isSessionSecretKey(key));
  if (secretKeys.length > 0) {
    debugLog('[SentinelPass Background] Purging session secrets on lock:', secretKeys.length);
    await sessionRemove(secretKeys);
  }
}

// Tell every content script to drop in-memory autofill context.
async function broadcastScrubSecrets() {
  try {
    const tabs = await chrome.tabs.query({});
    for (const tab of tabs) {
      if (typeof tab.id === 'number') {
        chrome.tabs.sendMessage(tab.id, { type: 'scrub_secrets' }, () => {
          // Content scripts may not be present — swallow the expected error.
          void chrome.runtime.lastError;
        });
      }
    }
  } catch (error) {
    debugLog('[SentinelPass Background] Scrub broadcast failed:', error);
  }
}

function isVaultLockedError(errorMessage) {
  return typeof errorMessage === 'string' && errorMessage.toLowerCase().includes('vault is locked');
}

async function queuePendingSaveRetry(data) {
  const pending = {
    action: 'save_credential',
    data: {
      username: data?.username,
      password: data?.password,
      domain: data?.domain,
      url: data?.url || null,
      submitted_url: data?.submitted_url || null,
      save_trigger: data?.save_trigger || 'unknown'
    },
    createdAt: Date.now(),
    // WBS-716: bounded retry lifetime, stamped via the shared registry.
    expiresAt: sessionSecretExpiry(PENDING_UNLOCK_RETRY_KEY, Date.now())
  };
  await sessionSet({ [PENDING_UNLOCK_RETRY_KEY]: pending });
}

async function notifyVaultLockedAndQueueRetry(data) {
  await queuePendingSaveRetry(data);

  const now = Date.now();
  if ((now - lastVaultLockedNotificationAt) < 1500) {
    return;
  }
  lastVaultLockedNotificationAt = now;

  await createNotification(`${VAULT_LOCKED_NOTIFICATION_PREFIX}${now}`, {
    title: 'SentinelPass Vault Locked',
    message: 'Unlock SentinelPass app, then click Retry save.',
    buttons: [
      { title: 'Retry save' }
    ],
    requireInteraction: true,
    silent: false
  });
}

async function retryPendingSaveAfterUnlock() {
  const pending = (await sessionGet([PENDING_UNLOCK_RETRY_KEY]))[PENDING_UNLOCK_RETRY_KEY];
  if (!pending || pending.action !== 'save_credential') {
    await createNotification(`save-retry-none-${Date.now()}`, {
      title: 'SentinelPass',
      message: 'No pending save request to retry.',
      requireInteraction: false
    });
    return;
  }

  if (!pending.expiresAt || Date.now() > pending.expiresAt) {
    await sessionRemove([PENDING_UNLOCK_RETRY_KEY]);
    await createNotification(`save-retry-expired-${Date.now()}`, {
      title: 'SentinelPass',
      message: 'Pending save request expired. Submit the login form again to save.',
      requireInteraction: false
    });
    return;
  }

  const status = await handleCheckVaultStatus();
  if (!status.success || !status.unlocked) {
    await createNotification(`${VAULT_LOCKED_NOTIFICATION_PREFIX}${Date.now()}`, {
      title: 'SentinelPass Vault Locked',
      message: 'Vault is still locked. Unlock SentinelPass app, then retry.',
      buttons: [
        { title: 'Retry save' }
      ],
      requireInteraction: true,
      silent: false
    });
    return;
  }

  const retryResult = await handleSaveCredential({
    ...pending.data,
    save_trigger: 'locked_retry_button'
  });

  if (retryResult.success) {
    await sessionRemove([PENDING_UNLOCK_RETRY_KEY]);
    await createNotification(`save-success-${Date.now()}`, {
      title: 'SentinelPass',
      message: retryResult.insecure_http
        ? 'Password saved, but this site used unencrypted HTTP'
        : 'Password saved successfully!',
      requireInteraction: false
    });
    return;
  }

  await createNotification(`save-error-${Date.now()}`, {
    title: 'SentinelPass Error',
    message: `Failed to save password: ${retryResult.error || 'Unknown error'}`,
    requireInteraction: false
  });
}

function buildSaveNotificationDedupKey(data) {
  const domain = normalizeDomainForPolicy(data?.domain || data?.url || '') || 'unknown';
  const username = typeof data?.username === 'string' ? data.username.trim().toLowerCase() : '';
  const url = typeof data?.url === 'string' ? data.url.split('#')[0] : '';
  const passwordLength = typeof data?.password === 'string' ? data.password.length : 0;
  return `${domain}|${username}|${url}|len:${passwordLength}`;
}

function isDuplicateSaveNotification(data) {
  const now = Date.now();
  const dedupKey = buildSaveNotificationDedupKey(data);

  for (const [key, timestamp] of recentSaveNotificationRequests.entries()) {
    if (now - timestamp > SAVE_NOTIFICATION_DEDUP_WINDOW_MS) {
      recentSaveNotificationRequests.delete(key);
    }
  }

  const previousTimestamp = recentSaveNotificationRequests.get(dedupKey);
  recentSaveNotificationRequests.set(dedupKey, now);

  return previousTimestamp !== undefined && (now - previousTimestamp) < SAVE_NOTIFICATION_DEDUP_WINDOW_MS;
}

function requestInlineSavePrompt(tabId, data) {
  if (!tabId) {
    return Promise.resolve(false);
  }

  // WBS-716 review fix F1: the FULL payload (including the password) stays
  // in the background under a one-time prompt id; the content script's
  // inline prompt receives only display fields and confirms by id. The
  // held entry is TTL-stamped and swept like every other session secret.
  const promptId = generateRequestId();
  const storageKey = `${PENDING_INLINE_PREFIX}${promptId}`;
  void sessionSet({
    [storageKey]: {
      ...data,
      expiresAt: sessionSecretExpiry(storageKey, Date.now())
    }
  });

  return new Promise((resolve) => {
    chrome.tabs.sendMessage(tabId, {
      type: 'show_inline_save_prompt',
      data: {
        username: data?.username || '',
        domain: data?.domain || '',
        url: data?.url || '',
        submitted_url: data?.submitted_url || '',
        request_source: data?.request_source || 'inline_prompt',
        insecure_http: data?.insecure_http === true,
        isPasswordChange: data?.isPasswordChange === true,
        promptId
      }
    }, (response) => {
      if (chrome.runtime.lastError) {
        console.error('[SentinelPass Background] Failed sending inline save prompt message:', chrome.runtime.lastError.message);
        // The prompt never appeared — drop the held payload immediately.
        void sessionRemove([storageKey]);
        resolve(false);
        return;
      }

      resolve(response?.success === true);
    });
  });
}

function getNeverSaveDomains() {
  return new Promise((resolve) => {
    chrome.storage.local.get([NEVER_SAVE_DOMAINS_KEY], (result) => {
      if (chrome.runtime.lastError) {
        console.error('[SentinelPass Background] Failed reading never-save domains:', chrome.runtime.lastError.message);
        resolve({});
        return;
      }
      resolve(result[NEVER_SAVE_DOMAINS_KEY] || {});
    });
  });
}

function setNeverSaveDomains(domains) {
  return new Promise<void>((resolve, reject) => {
    chrome.storage.local.set({ [NEVER_SAVE_DOMAINS_KEY]: domains }, () => {
      if (chrome.runtime.lastError) {
        reject(new Error(chrome.runtime.lastError.message));
      } else {
        resolve();
      }
    });
  });
}

async function shouldSuppressSavePrompt(domainOrUrl) {
  const normalized = normalizeDomainForPolicy(domainOrUrl);
  if (!normalized) {
    return false;
  }

  const domains = await getNeverSaveDomains();
  return Object.keys(domains).some((policyDomain) =>
    domainMatchesPolicy(normalized, policyDomain)
  );
}

async function addNeverSaveDomain(domainOrUrl) {
  const normalized = normalizeDomainForPolicy(domainOrUrl);
  if (!normalized) {
    return false;
  }

  const domains = await getNeverSaveDomains();
  domains[normalized] = { createdAt: Date.now() };
  await setNeverSaveDomains(domains);
  return true;
}

// Handle get_credential request
async function handleGetCredential(domain, requestId, pageUrl, username) {
  debugLog('[SentinelPass Background] handleGetCredential called for domain:', domain);

  try {
    const response = await chrome.runtime.sendNativeMessage(HOST_NAME, {
      type: 'get_credential',
      domain: domain,
      request_id: requestId,
      // WBS-711: browser-provided page URL; the daemon scheme-validates it
      // and default-denies unsafe origins.
      page_url: pageUrl || undefined,
      // WBS-712/715: exact-username disambiguator (popup per-row Pass).
      username: username || undefined
    });

    debugLog('[SentinelPass Background] Got credential response from native host:', redactForLog(response));
    return response;
  } catch (error) {
    console.error('[SentinelPass Background] Error getting credential:', error);
    return {
      success: false,
      error: error.message
    };
  }
}

// Handle list_domain_credentials request
async function handleListDomainCredentials(domain, requestId, pageUrl) {
  debugLog('[SentinelPass Background] handleListDomainCredentials called for base domain:', domain);

  try {
    const response = await chrome.runtime.sendNativeMessage(HOST_NAME, {
      type: 'list_domain_credentials',
      domain: domain,
      request_id: requestId,
      page_url: pageUrl || undefined
    });

    debugLog('[SentinelPass Background] Got domain credentials response from native host:', response?.credentials?.length || 0, 'credentials');
    return response;
  } catch (error) {
    console.error('[SentinelPass Background] Error listing domain credentials:', error);
    return {
      success: false,
      error: error.message,
      credentials: []
    };
  }
}

// Handle get_totp_code request
async function handleGetTotpCode(domain, requestId, pageUrl, username) {
  debugLog('[SentinelPass Background] handleGetTotpCode called for domain:', domain);

  try {
    const response = await chrome.runtime.sendNativeMessage(HOST_NAME, {
      type: 'get_totp_code',
      domain: domain,
      request_id: requestId,
      page_url: pageUrl || undefined,
      // Review F4: bound to the SAME account whose password was filled.
      username: username || undefined
    });

    debugLog('[SentinelPass Background] Got TOTP response from native host:', redactForLog(response));
    return response;
  } catch (error) {
    console.error('[SentinelPass Background] Error getting TOTP code:', error);
    return {
      success: false,
      error: error.message
    };
  }
}

// Handle save_credential request
async function handleSaveCredential(data) {
  debugLog('[SentinelPass Background] handleSaveCredential called');
  debugLog('[SentinelPass Background] Save request payload:', redactForLog(data));

  try {
    if (await isCredentialUnchanged(data)) {
      debugLog('[SentinelPass Background] Credential unchanged; skipping save write');
      await sessionRemove([PENDING_UNLOCK_RETRY_KEY]);
      return { success: true, unchanged: true };
    }

    // Send to native host for saving
    debugLog('[SentinelPass Background] Sending save request to native host...');
    const canonicalUrl = normalizeCredentialUrl(data?.submitted_url || data?.url, data?.domain);
    debugLog('[SentinelPass Background] Canonical URL selected for save:', canonicalUrl);

    const response = await chrome.runtime.sendNativeMessage(HOST_NAME, {
      type: 'save_credential',
      domain: data.domain,
      data: {
        username: data.username,
        password: data.password,
        title: data.domain || data.url || 'Unknown', // Backward compatibility
        url: canonicalUrl
      },
      // Provenance of the save (extension-computed; the daemon logs it).
      save_trigger: typeof data.save_trigger === 'string' ? data.save_trigger : undefined
    });

    debugLog('[SentinelPass Background] Native host response:', redactForLog(response));

    if (response && response.success) {
      debugLog('[SentinelPass Background] Credential saved successfully');
      await sessionRemove([PENDING_UNLOCK_RETRY_KEY]);
      // WBS-706: let callers warn when the saved credential's canonical URL
      // is plain HTTP (content script toasts, popup notification).
      const savedInsecureHttp = classifyCredentialUrlSecurity(canonicalUrl) === 'insecure';
      if (savedInsecureHttp) {
        warnLog('[SentinelPass Background] Credential saved for a plain-HTTP origin:', canonicalUrl);
      }
      return { success: true, insecure_http: savedInsecureHttp };
    } else {
      console.error('[SentinelPass Background] Failed to save credential:', redactForLog(response));
      const errorMessage = response?.error
        || (response?.unlocked === false ? 'Vault is locked. Please unlock SentinelPass daemon and try again.' : null)
        || 'Unknown error';

      if (isVaultLockedError(errorMessage)) {
        try {
          await notifyVaultLockedAndQueueRetry(data);
        } catch (lockedFlowError) {
          console.error('[SentinelPass Background] Failed preparing locked-vault retry flow:', lockedFlowError);
        }
      }

      return {
        success: false,
        error: errorMessage,
        code: isVaultLockedError(errorMessage) ? 'vault_locked' : 'save_failed'
      };
    }
  } catch (error) {
    console.error('[SentinelPass Background] Error in handleSaveCredential:', error);
    const message = String(error?.message || error || '');
    if (message.includes('Access to the specified native messaging host is forbidden')) {
      console.error('[SentinelPass Background] Native host permission denied for extension ID:', chrome.runtime.id);
      console.error('[SentinelPass Background] Update native host manifest allowed_origins to include:', `chrome-extension://${chrome.runtime.id}/`);
    }
    // Create a notification to inform the user about the error
    await createNotification('save-error-' + Date.now(), {
      title: 'SentinelPass Error',
      message: message.includes('forbidden')
        ? 'Native host permission denied. Re-register extension ID in native host manifest.'
        : 'Failed to save password. Ensure daemon is running and vault is unlocked.',
      requireInteraction: false
    });
    return {
      success: false,
      error: error.message,
      code: message.includes('forbidden') ? 'native_host_forbidden' : 'native_host_error'
    };
  }
}

// Handle check_credential_exists request
async function handleCheckCredentialExists(domain, pageUrl) {
  debugLog('[SentinelPass Background] handleCheckCredentialExists called for domain:', domain);

  try {
    const response = await chrome.runtime.sendNativeMessage(HOST_NAME, {
      type: 'check_credential_exists',
      domain: domain,
      page_url: pageUrl || undefined
    });

    debugLog('[SentinelPass Background] Credential exists check result:', redactForLog(response));
    return response.exists || false;
  } catch (error) {
    console.error('[SentinelPass Background] Error checking credential exists:', error);
    return false;
  }
}

// Handle check_vault_status request
async function handleCheckVaultStatus() {
  debugLog('[SentinelPass Background] handleCheckVaultStatus called');

  try {
    const response = await chrome.runtime.sendNativeMessage(HOST_NAME, {
      type: 'check_vault_status'
    });

    debugLog('[SentinelPass Background] Vault status:', redactForLog(response));
    return {
      success: response?.success === true,
      unlocked: response?.unlocked === true
    };
  } catch (error) {
    console.error('[SentinelPass Background] Error checking vault status:', error);
    return {
      success: false,
      unlocked: false,
      error: error.message
    };
  }
}

// Handle lock_vault request
async function handleLockVault() {
  debugLog('[SentinelPass Background] handleLockVault called');

  try {
    const response = await chrome.runtime.sendNativeMessage(HOST_NAME, {
      type: 'lock_vault'
    });

    return {
      success: response?.success === true,
      unlocked: response?.unlocked === true
    };
  } catch (error) {
    console.error('[SentinelPass Background] Error locking vault:', error);
    return {
      success: false,
      unlocked: true,
      error: error.message
    };
  }
}

// ── WBS-712 per-site autofill permissions (popup-only surface) ──────────────

// Handle grant_site_permission request (popup settings view). The daemon
// normalizes the host and stores an EXACT-host grant; https never needs one.
async function handleGrantSitePermission(host, allowInsecure) {
  debugLog('[SentinelPass Background] handleGrantSitePermission for host:', host);
  if (!host || typeof host !== 'string') {
    return { success: false, error: 'Missing host' };
  }
  try {
    const response = await chrome.runtime.sendNativeMessage(HOST_NAME, {
      type: 'grant_site_permission',
      domain: host,
      allow_insecure: allowInsecure === true
    });
    return { success: response?.success === true, error: response?.error || null };
  } catch (error) {
    console.error('[SentinelPass Background] Error granting site permission:', error);
    return { success: false, error: error.message };
  }
}

// Handle revoke_site_permission request (popup settings view).
async function handleRevokeSitePermission(host) {
  debugLog('[SentinelPass Background] handleRevokeSitePermission for host:', host);
  if (!host || typeof host !== 'string') {
    return { success: false, error: 'Missing host' };
  }
  try {
    const response = await chrome.runtime.sendNativeMessage(HOST_NAME, {
      type: 'revoke_site_permission',
      domain: host
    });
    return { success: response?.success === true, error: response?.error || null };
  } catch (error) {
    console.error('[SentinelPass Background] Error revoking site permission:', error);
    return { success: false, error: error.message };
  }
}

// Handle list_site_permissions request (popup settings view).
async function handleListSitePermissions() {
  try {
    const response = await chrome.runtime.sendNativeMessage(HOST_NAME, {
      type: 'list_site_permissions'
    });
    return { success: response?.success === true, permissions: response?.site_permissions || [] };
  } catch (error) {
    console.error('[SentinelPass Background] Error listing site permissions:', error);
    return { success: false, permissions: [], error: error.message };
  }
}

// Handle save notification request from content script
async function handleSaveNotification(data, sender) {
  debugLog('[SentinelPass Background] ========== HANDLE SAVE NOTIFICATION ==========');
  debugLog('[SentinelPass Background] Notification payload:', redactForLog(data));

  try {
    const validation = validateSenderDomainContext(
      sender,
      data?.domain || data?.url || '',
      'request_save_notification'
    );
    if (!validation.ok) {
      throw new Error(validation.error);
    }

    const requestSource = typeof data?.request_source === 'string' ? data.request_source : 'unknown';
    debugLog('[SentinelPass Background] Save request source:', requestSource);

    const suppressPrompt = await shouldSuppressSavePrompt(data?.domain || data?.url || '');
    if (suppressPrompt) {
      debugLog('[SentinelPass Background] Skipping save notification due to never-save policy');
      return true;
    }

    // WBS-706 (HTTP warn half): flag plain-HTTP submissions so both the
    // notification and the inline prompt warn before the user consents to a
    // save. Classification is a structured URL-API parse, not string matching.
    const insecureHttp = classifyCredentialUrlSecurity(data?.submitted_url || data?.url || '') === 'insecure';
    if (insecureHttp) {
      warnLog('[SentinelPass Background] Save request originates from a plain-HTTP page:', data?.domain || data?.url);
    }

    if (await isCredentialUnchanged(data)) {
      debugLog('[SentinelPass Background] Skipping save notification because credential is unchanged');
      return true;
    }

    if (isDuplicateSaveNotification(data)) {
      debugLog('[SentinelPass Background] Skipping duplicate save notification request');
      return true;
    }

    const shouldUseInlineFirst = requestSource === 'pending-login-check';
    if (shouldUseInlineFirst) {
      // Inline-first is safe on post-navigation pages where the tab is stable.
      const inlinePromptShown = await requestInlineSavePrompt(sender?.tab?.id, data);
      if (inlinePromptShown) {
        debugLog('[SentinelPass Background] Inline save prompt shown');
        debugLog('[SentinelPass Background] Awaiting explicit user action before any save');
        return true;
      }
    } else {
      debugLog('[SentinelPass Background] Using persistent notification path for source:', requestSource);
    }

    // Create notification to ask user to save
    const notificationId = 'save-password-' + Date.now();
    const storageKey = `pendingSaveCredential:${notificationId}`;

    // Store credential data keyed to notification ID for button click handling.
    // Do this before creating the notification to avoid races on very fast clicks.
    // The insecure-HTTP flag rides along so the save prompt / toast can warn.
    // WBS-716: bounded lifetime — swept by the alarm even if the notification
    // is never acted on.
    const pendingData = {
      ...data,
      insecure_http: insecureHttp,
      _sender_tab_id: sender?.tab?.id ?? null,
      expiresAt: sessionSecretExpiry(storageKey, Date.now())
    };
    chrome.storage.session.set({ [storageKey]: pendingData }, () => {
      if (chrome.runtime.lastError) {
        console.error('[SentinelPass Background] Failed to store pending save credential:', chrome.runtime.lastError.message);
      } else {
        debugLog('[SentinelPass Background] Stored pending save credential for notification:', notificationId);
      }
    });

    let createdId = null;
    const isPasswordChange = data?.isPasswordChange === true;
    try {
      createdId = await createNotification(notificationId, {
        title: isPasswordChange ? 'SentinelPass - Update Password?' : 'SentinelPass - Save Password?',
        message: insecureHttp
          ? `${isPasswordChange ? 'Update' : 'Save'} the password for ${data.domain}? WARNING: this page used an unencrypted (HTTP) connection.`
          : `Do you want to ${isPasswordChange ? 'update' : 'save'} the password for ${data.domain}?`,
        buttons: [
          { title: insecureHttp ? 'Save anyway' : (isPasswordChange ? 'Update' : 'Save') },
          { title: 'Never for this site' }
        ],
        requireInteraction: true,
        silent: false
      });
    } catch (notificationError) {
      console.error('[SentinelPass Background] Notification creation failed, attempting inline fallback:', notificationError);
      const inlinePromptShown = await requestInlineSavePrompt(sender?.tab?.id, data);
      if (inlinePromptShown) {
        chrome.storage.session.remove(storageKey);
        debugLog('[SentinelPass Background] Inline save prompt shown as fallback');
        return true;
      }
      chrome.storage.session.remove(storageKey);
      throw notificationError;
    }

    debugLog('[SentinelPass Background] ========== SAVE NOTIFICATION CREATED ==========');
    debugLog('[SentinelPass Background] Notification ID:', createdId || notificationId);
    return true;
  } catch (error) {
    console.error('[SentinelPass Background] ========== ERROR IN HANDLE SAVE NOTIFICATION ==========');
    console.error('[SentinelPass Background] Error:', error);
    throw error;
  }
}

// ========================================
// Event Listeners
// ========================================

// Listen for messages from content scripts
chrome.runtime.onMessage.addListener((request, sender, sendResponse) => {
  // Validate sender is from this extension
  if (sender.id !== chrome.runtime.id) { return; }

  // Rate limit per tab
  const tabId = sender.tab?.id ?? -1;
  if (isMessageRateLimited(tabId)) {
    warnLog('Rate limited messages from tab ' + tabId);
    sendResponse({ success: false, error: 'Rate limited' });
    return true;
  }

  debugLog('[SentinelPass Background] Received message:', request.type);
  debugLog('[SentinelPass Background] Request details:', redactForLog(request));

  if (request.type === 'get_credential') {
    debugLog('[SentinelPass Background] Handling get_credential for domain:', request.domain);
    if (!isPopupSender(sender)) {
      const validation = validateSenderDomainContext(sender, request.domain, 'get_credential');
      if (!validation.ok) {
        console.warn('[SentinelPass Background] Blocked get_credential:', validation.error);
        sendResponse({ success: false, error: validation.error });
        return true;
      }
    }
    const pageUrl = autofillPageUrlForDaemon(
      request.page_url,
      sender.url,
      isPopupSender(sender)
    );
    const username = typeof request.username === 'string' ? request.username : undefined;
    handleGetCredential(request.domain, request.request_id, pageUrl, username)
          .then(response => {
            debugLog('[SentinelPass Background] Get credential response:', redactForLog(response));
            sendResponse(response);
          })
          .catch(error => {
            console.error('[SentinelPass Background] Get credential error:', error);
            sendResponse({
              success: false,
              error: error.message
            });
          });
        return true; // Keep message channel open for async response
      }

  if (request.type === 'list_domain_credentials') {
    debugLog('[SentinelPass Background] Handling list_domain_credentials for base domain:', request.domain);
    if (!isPopupSender(sender)) {
      const validation = validateSenderDomainContext(sender, request.domain, 'list_domain_credentials');
      if (!validation.ok) {
        console.warn('[SentinelPass Background] Blocked list_domain_credentials:', validation.error);
        sendResponse({ success: false, error: validation.error, data: [] });
        return true;
      }
    }
    const pageUrl = autofillPageUrlForDaemon(
      request.page_url,
      sender.url,
      isPopupSender(sender)
    );
    handleListDomainCredentials(request.domain, request.request_id, pageUrl)
          .then(response => {
            debugLog('[SentinelPass Background] List domain credentials response:', response?.data?.length || 0, 'credentials');
            sendResponse(response);
          })
          .catch(error => {
            console.error('[SentinelPass Background] List domain credentials error:', error);
            sendResponse({
              success: false,
              error: error.message,
              data: []
            });
          });
        return true;
  }

  if (request.type === 'get_totp_code') {
    debugLog('[SentinelPass Background] Handling get_totp_code for domain:', request.domain);
    const validation = validateSenderDomainContext(sender, request.domain, 'get_totp_code');
    if (!validation.ok) {
      console.warn('[SentinelPass Background] Blocked get_totp_code:', validation.error);
      sendResponse({ success: false, error: validation.error });
      return true;
    }
    const pageUrl = autofillPageUrlForDaemon(
      request.page_url,
      sender.url,
      isPopupSender(sender)
    );
    const totpUsername = typeof request.username === 'string' ? request.username : undefined;
    handleGetTotpCode(request.domain, request.request_id, pageUrl, totpUsername)
          .then(response => {
            debugLog('[SentinelPass Background] Get TOTP response:', redactForLog(response));
            sendResponse(response);
          })
          .catch(error => {
            console.error('[SentinelPass Background] Get TOTP error:', error);
            sendResponse({
              success: false,
              error: error.message
            });
          });
        return true;
      }

  if (request.type === 'save_credential') {
    debugLog('[SentinelPass Background] Handling save_credential');
    debugLog('[SentinelPass Background] Domain:', request.data?.domain);
    debugLog('[SentinelPass Background] URL:', request.data?.url);
    debugLog('[SentinelPass Background] Save trigger:', request.data?.save_trigger || 'unknown');
    if (!isPopupSender(sender)) {
      const validation = validateSenderDomainContext(
        sender,
        request.data?.domain || request.data?.url || '',
        'save_credential'
      );
      if (!validation.ok) {
        console.warn('[SentinelPass Background] Blocked save_credential:', validation.error);
        sendResponse({ success: false, error: validation.error, code: 'sender_domain_mismatch' });
        return true;
      }
    }
    handleSaveCredential(withSenderProvenance(request.data, sender))
          .then(response => {
            debugLog('[SentinelPass Background] Save credential response:', redactForLog(response));
            sendResponse(response);
          })
          .catch(error => {
            console.error('[SentinelPass Background] Save credential error:', error);
            sendResponse({
              success: false,
              error: error.message
            });
          });
        return true;
      }

  if (request.type === 'check_credential_exists') {
    debugLog('[SentinelPass Background] Handling check_credential_exists for domain:', request.domain);
    if (!isPopupSender(sender)) {
      const validation = validateSenderDomainContext(sender, request.domain, 'check_credential_exists');
      if (!validation.ok) {
        console.warn('[SentinelPass Background] Blocked check_credential_exists:', validation.error);
        sendResponse({ success: false, exists: false, error: validation.error });
        return true;
      }
    }
    const pageUrl = autofillPageUrlForDaemon(
      request.page_url,
      sender.url,
      isPopupSender(sender)
    );
    handleCheckCredentialExists(request.domain, pageUrl)
          .then(exists => {
              debugLog('[SentinelPass Background] Credential exists:', exists);
              sendResponse({ exists: exists });
          })
          .catch(error => {
            console.error('[SentinelPass Background] Check credential exists error:', error);
            sendResponse({
              success: false,
              error: error.message
            });
          });
        return true;
      }

  if (request.type === 'check_vault_status') {
    debugLog('[SentinelPass Background] Handling check_vault_status');
    handleCheckVaultStatus()
          .then(statusResponse => {
              debugLog('[SentinelPass Background] Vault status:', redactForLog(statusResponse));
              sendResponse(statusResponse);
          })
          .catch(error => {
            console.error('[SentinelPass Background] Check vault status error:', error);
            sendResponse({
              success: false,
              unlocked: false,
              error: error.message
            });
          });
        return true;
      }

  if (request.type === 'lock_vault') {
    debugLog('[SentinelPass Background] Handling lock_vault');
    handleLockVault()
          .then(response => {
            debugLog('[SentinelPass Background] Lock vault response:', redactForLog(response));
            // WBS-716: a lock clears every pending plaintext payload and
            // asks content scripts to drop their in-memory autofill context.
            if (response?.success && response?.unlocked === false) {
              void purgeAllSessionSecrets().then(() => broadcastScrubSecrets());
            }
            sendResponse(response);
          })
          .catch(error => {
            console.error('[SentinelPass Background] Lock vault error:', error);
            sendResponse({
              success: false,
              unlocked: true,
              error: error.message
            });
          });
        return true;
      }

  if (request.type === 'inline_save_confirm') {
    // WBS-716 review fix F1: the inline prompt confirms by one-time id;
    // the password never travels to (or from) the content script.
    const promptId = typeof request.promptId === 'string' ? request.promptId : '';
    if (!promptId) {
      sendResponse({ success: false, error: 'Missing prompt id' });
      return true;
    }
    void (async () => {
      const storageKey = `${PENDING_INLINE_PREFIX}${promptId}`;
      const stored = await sessionGet([storageKey]);
      const payload = stored?.[storageKey];
      if (!payload || isSessionSecretExpired(storageKey, payload, Date.now())) {
        await sessionRemove([storageKey]);
        sendResponse({ success: false, error: 'Save prompt expired' });
        return;
      }
      try {
        const result = await handleSaveCredential({
          ...payload,
          save_trigger: 'inline_prompt_confirm'
        });
        sendResponse(result);
      } finally {
        await sessionRemove([storageKey]);
      }
    })();
    return true;
  }

  if (request.type === 'capture_pending_login') {
    // WBS-716: the content script hands the captured submission over; the
    // plaintext now lives ONLY in the (trusted) background worker's session
    // storage, stamped with the bounded 2FA-page TTL.
    const validation = validateSenderDomainContext(
      sender,
      request.data?.domain || request.data?.url || '',
      'capture_pending_login'
    );
    if (!validation.ok) {
      console.warn('[SentinelPass Background] Blocked capture_pending_login:', validation.error);
      sendResponse({ captured: false, error: validation.error });
      return true;
    }
    const stamped = {
      ...withSenderProvenance(request.data, sender),
      expiresAt: sessionSecretExpiry(PENDING_CREDENTIAL_KEY, Date.now())
    };
    void sessionSet({ [PENDING_CREDENTIAL_KEY]: stamped }).then(() => {
      sendResponse({ captured: true });
    });
    return true;
  }

  if (request.type === 'resume_pending_login') {
    // WBS-716: the content script only ASKS; validation, host matching, and
    // the payload never leave the background worker.
    void (async () => {
      const hostname = typeof request.hostname === 'string' ? request.hostname : '';
      if (!hostname) {
        sendResponse({ resumed: false });
        return;
      }
      const stored = await sessionGet([PENDING_CREDENTIAL_KEY]);
      const pending = stored?.[PENDING_CREDENTIAL_KEY];
      if (!pending) {
        sendResponse({ resumed: false });
        return;
      }
      const fresh =
        !isSessionSecretExpired(PENDING_CREDENTIAL_KEY, pending, Date.now()) &&
        typeof pending.timestamp === 'number' &&
        Date.now() - pending.timestamp < PENDING_CREDENTIAL_TTL_MS;
      const sameSite =
        typeof pending.domain === 'string' &&
        pending.domain === hostname &&
        pending.url !== request.href;
      if (!fresh || !sameSite) {
        if (!fresh) {
          debugLog('[SentinelPass Background] Pending login expired; clearing');
          await sessionRemove([PENDING_CREDENTIAL_KEY]);
        }
        sendResponse({ resumed: false });
        return;
      }
      try {
        // Preserve the inline-first UX for the 2FA-page resume path.
        const shown = await handleSaveNotification(
          { ...pending, request_source: 'pending-login-check' },
          sender
        );
        sendResponse({ resumed: shown === true });
      } finally {
        await sessionRemove([PENDING_CREDENTIAL_KEY]);
      }
    })();
    return true;
  }

  if (request.type === 'grant_site_permission') {
    // WBS-712: permission management is popup-only — a content script (and
    // therefore any page) must not be able to move the permission store.
    if (!isPopupSender(sender)) {
      console.warn('[SentinelPass Background] Blocked grant_site_permission from non-popup sender');
      sendResponse({ success: false, error: 'permission changes are popup-only' });
      return true;
    }
    handleGrantSitePermission(request.host, request.allow_insecure)
      .then(response => sendResponse(response));
    return true;
  }

  if (request.type === 'revoke_site_permission') {
    if (!isPopupSender(sender)) {
      console.warn('[SentinelPass Background] Blocked revoke_site_permission from non-popup sender');
      sendResponse({ success: false, error: 'permission changes are popup-only' });
      return true;
    }
    handleRevokeSitePermission(request.host)
      .then(response => sendResponse(response));
    return true;
  }

  if (request.type === 'list_site_permissions') {
    if (!isPopupSender(sender)) {
      console.warn('[SentinelPass Background] Blocked list_site_permissions from non-popup sender');
      sendResponse({ success: false, permissions: [], error: 'permission changes are popup-only' });
      return true;
    }
    handleListSitePermissions()
      .then(response => sendResponse(response));
    return true;
  }

  if (request.type === 'save_prompt_outcome') {
    const outcome = request.data?.outcome || 'unknown';
    const domain = request.data?.domain || 'unknown';
    const source = request.data?.source || 'unknown';
    const promptId = request.data?.promptId || 'n/a';
    debugLog('[SentinelPass Background] SAVE_PROMPT_OUTCOME', {
      outcome: outcome,
      source: source,
      domain: domain,
      promptId: promptId
    });
    if (outcome.startsWith('no_save_')) {
      debugLog(` NO_SAVE: ${outcome} (${domain})`);
    } else if (outcome === 'save_clicked') {
      debugLog(` SAVE_INTENT_CONFIRMED: ${domain}`);
    }
    sendResponse({ success: true });
    return true;
  }

  if (request.type === 'request_save_notification') {
    debugLog('[SentinelPass Background] Handling request_save_notification');
    handleSaveNotification(withSenderProvenance(request.data, sender), sender)
          .then(result => {
              debugLog('[SentinelPass Background] Save notification result:', result);
              sendResponse({ success: result });
          })
          .catch(error => {
            console.error('[SentinelPass Background] Save notification error:', error);
            sendResponse({
              success: false,
              error: error.message
            });
          });
        return true;
      }
});

// Handle keyboard shortcut for autofill
chrome.commands.onCommand.addListener((command) => {
  if (command === 'autofill') {
    chrome.tabs.query({ active: true, currentWindow: true }, (tabs) => {
      if (tabs[0]) {
        chrome.tabs.sendMessage(tabs[0].id, {
          type: 'trigger_autofill'
        });
      }
    });
  }
});

// Handle notification button clicks
chrome.notifications.onButtonClicked.addListener((notificationId, buttonIndex) => {
  debugLog('[SentinelPass Background] ========== NOTIFICATION BUTTON CLICKED ==========');
  debugLog('[SentinelPass Background] Notification ID:', notificationId);
  debugLog('[SentinelPass Background] Button Index:', buttonIndex);

  if (notificationId.startsWith(VAULT_LOCKED_NOTIFICATION_PREFIX)) {
    chrome.notifications.clear(notificationId);
    if (buttonIndex === 0) {
      void retryPendingSaveAfterUnlock();
    }
    return;
  }

  // Check if this is a save password notification
  if (notificationId.startsWith('save-password-')) {
    handledSaveNotifications.add(notificationId);
    const storageKey = `pendingSaveCredential:${notificationId}`;
    void (async () => {
      const result = await sessionGet([storageKey]);
      if (!result || !result[storageKey]) {
        return;
      }

      const data = result[storageKey];

      if (buttonIndex === 0) {
        // Save button clicked
        debugLog(` SAVE_INTENT_CONFIRMED: ${data.domain || 'unknown'} (notification_button)`);
        debugLog('[SentinelPass Background] Save button clicked, saving credential...');
        debugLog('[SentinelPass Background] Domain:', data.domain);

        const saveResult = await handleSaveCredential({
          username: data.username,
          password: data.password,
          domain: data.domain,
          url: data.url || null,
          submitted_url: data.submitted_url || data.url || null,
          save_trigger: 'notification_button'
        });

        if (saveResult.success) {
          if (saveResult.unchanged) {
            debugLog('[SentinelPass Background] Credential already up to date');
          } else {
            debugLog('[SentinelPass Background] Credential saved successfully!');
          }
          await createNotification('save-success-' + Date.now(), {
            title: 'SentinelPass',
            message: saveResult.insecure_http
              ? 'Password saved, but this site used unencrypted HTTP'
              : saveResult.unchanged
                ? 'Password already up to date.'
                : 'Password saved successfully!',
            requireInteraction: false
          });
        } else {
          console.error('[SentinelPass Background] Failed to save credential from notification path:', saveResult.error);
          if (saveResult.code !== 'vault_locked') {
            await createNotification('save-error-' + Date.now(), {
              title: 'SentinelPass Error',
              message: `Failed to save password: ${saveResult.error || 'Unknown error'}`,
              requireInteraction: false
            });
          }
        }
      } else {
        // Never button clicked
        debugLog(` NO_SAVE: no_save_never_for_site (${data.domain || 'unknown'})`);
        debugLog('[SentinelPass Background] Never for this site clicked');
        try {
          const stored = await addNeverSaveDomain(data.domain || data.url || '');
          if (stored) {
            debugLog('[SentinelPass Background] Added never-save policy for domain:', data.domain);
            await createNotification('never-save-' + Date.now(), {
              title: 'SentinelPass',
              message: `Will no longer prompt to save for ${data.domain || 'this site'}`,
              requireInteraction: false
            });
          }
        } catch (error) {
          console.error('[SentinelPass Background] Failed to persist policy or notify user:', error);
        }
      }

      // Clear the pending credential
      await sessionRemove([storageKey]);
    })().catch((error) => {
      console.error('[SentinelPass Background] Error handling notification button click:', error);
    });
  }
});

// Handle notification closed (clicked X or dismissed)
chrome.notifications.onClosed.addListener((notificationId) => {
  debugLog('[SentinelPass Background] Notification closed:', notificationId);

  // Clean up any pending data for this specific save prompt
  if (notificationId.startsWith('save-password-')) {
    const storageKey = `pendingSaveCredential:${notificationId}`;
    if (handledSaveNotifications.has(notificationId)) {
      handledSaveNotifications.delete(notificationId);
      chrome.storage.session.remove(storageKey);
      return;
    }

    chrome.storage.session.get([storageKey], (result) => {
      const pending = result ? (result[storageKey] as Record<string, unknown> | undefined) : null;
      const domain = (pending?.domain as string) || 'unknown';
      const tabId = Number.isInteger(pending?._sender_tab_id) ? (pending._sender_tab_id as number) : null;

      if (tabId !== null) {
        void requestInlineSavePrompt(tabId, pending).then((inlineShown) => {
          if (inlineShown) {
            debugLog(` Reopened inline save prompt after notification close (${domain})`);
          } else {
            debugLog(` NO_SAVE: no_save_notification_closed (${domain})`);
          }
          chrome.storage.session.remove(storageKey);
        });
        return;
      }

      debugLog(` NO_SAVE: no_save_notification_closed (${domain})`);
      chrome.storage.session.remove(storageKey);
    });
  }
});

console.log('Password Manager background service worker initialized');
