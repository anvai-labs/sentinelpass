// Content script for password field detection and autofill

import { debugLog, infoLog, warnLog, errorLog, sanitizeUrl, sanitizeHostname, sanitizePasswordLength } from './logger';

function escapeHtml(str: string): string {
  const div = document.createElement('div');
  div.appendChild(document.createTextNode(str));
  return div.innerHTML;
}

function createLockIcon(width: number, height: number): SVGSVGElement {
  const ns = 'http://www.w3.org/2000/svg';
  const svg = document.createElementNS(ns, 'svg');
  svg.setAttribute('width', String(width));
  svg.setAttribute('height', String(height));
  svg.setAttribute('viewBox', '0 0 24 24');
  svg.setAttribute('fill', 'currentColor');
  const path = document.createElementNS(ns, 'path');
  path.setAttribute('d', 'M12 17c1.1 0 2-.9 2-2s-.9-2-2-2-2 .9-2 2 .9 2 2 2zm6-9h-1V6c0-2.76-2.24-5-5-5S7 3.24 7 6v2H6c-1.1 0-2 .9-2 2v10c0 1.1.9 2 2 2h12c1.1 0 2-.9 2-2V10c0-1.1-.9-2-2-2zM9 6c0-1.66 1.34-3 3-3s3 1.34 3 3v2H9V6zm9 14H6V10h12v10zm-6-3c1.1 0 2-.9 2-2s-.9-2-2-2-2 .9-2 2 .9 2 2 2z');
  svg.appendChild(path);
  return svg;
}

infoLog('Content script loaded');
debugLog('Current URL:', sanitizeUrl(window.location.href));
debugLog('Hostname:', sanitizeHostname(window.location.hostname));

// Configuration
const AUTOFILL_BUTTON_CLASS = 'pm-autofill-button';
const AUTOFILL_BUTTON_STYLE = `
  position: absolute;
  right: 8px;
  top: 50%;
  transform: translateY(-50%);
  background: #1a73e8;
  color: white;
  border: none;
  border-radius: 4px;
  padding: 4px 8px;
  cursor: pointer;
  font-size: 14px;
  z-index: 9999;
  display: flex;
  align-items: center;
  gap: 4px;
  box-shadow: 0 2px 4px rgba(0,0,0,0.2);
`;

const AUTOFILL_BUTTON_HOVER_STYLE = `
  background: #1557b0;
`;

const SENSITIVE_LOG_KEYS = new Set(['password', 'secret', 'token', 'passphrase']);
const NEVER_SAVE_DOMAINS_KEY = 'neverSaveDomains';
const SAVE_NOTIFICATION_REQUEST_DEDUP_WINDOW_MS = 4000;
const AUTOFILL_SUBMISSION_WINDOW_MS = 10 * 60 * 1000;
const recentSaveNotificationRequests = new Map();
let lastAutofillContext = null;

function normalizeUsernameValue(value) {
  return typeof value === 'string' ? value.trim().toLowerCase() : '';
}

function detectInputMethod(username, password, domain) {
  if (!lastAutofillContext || typeof password !== 'string' || !password) {
    return 'manual_or_unknown';
  }

  const ageMs = Date.now() - lastAutofillContext.timestamp;
  if (ageMs < 0 || ageMs > AUTOFILL_SUBMISSION_WINDOW_MS) {
    return 'manual_or_unknown';
  }

  const sameDomain = lastAutofillContext.domain === domain;
  const samePassword = lastAutofillContext.password === password;
  if (!sameDomain || !samePassword) {
    return 'manual_or_unknown';
  }

  const currentUser = normalizeUsernameValue(username);
  const autofillUser = normalizeUsernameValue(lastAutofillContext.username);
  const usernameCompatible = !autofillUser || !currentUser || autofillUser === currentUser;

  return usernameCompatible ? 'autofill_reuse' : 'manual_or_unknown';
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

function normalizeDomainForPolicy(value) {
  if (!value || typeof value !== 'string') {
    return null;
  }

  let normalized = value.trim().toLowerCase();
  if (!normalized) {
    return null;
  }

  if (normalized.startsWith('http://') || normalized.startsWith('https://')) {
    try {
      normalized = new URL(normalized).hostname.toLowerCase();
    } catch (_error) {
      // Keep original value if URL parsing fails.
    }
  }

  normalized = normalized.replace(/^\.+|\.+$/g, '');
  if (normalized.startsWith('www.')) {
    normalized = normalized.slice(4);
  }

  return normalized || null;
}

function domainMatchesPolicy(domain, policyDomain) {
  return domain === policyDomain || domain.endsWith(`.${policyDomain}`);
}

function getNeverSaveDomains() {
  return new Promise((resolve) => {
    chrome.storage.local.get([NEVER_SAVE_DOMAINS_KEY], (result) => {
      if (chrome.runtime.lastError) {
        errorLog('Failed reading never-save domains:', chrome.runtime.lastError?.message);
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

function buildSaveNotificationRequestKey(data) {
  const domain = normalizeDomainForPolicy(data?.domain || data?.url || '') || 'unknown';
  const username = typeof data?.username === 'string' ? data.username.trim().toLowerCase() : '';
  const url = typeof data?.url === 'string' ? data.url.split('#')[0] : '';
  const passwordLength = typeof data?.password === 'string' ? data.password.length : 0;
  return `${domain}|${username}|${url}|len:${passwordLength}`;
}

function isDuplicateSaveNotificationRequest(data) {
  const now = Date.now();
  const dedupKey = buildSaveNotificationRequestKey(data);

  for (const [key, timestamp] of recentSaveNotificationRequests.entries()) {
    if (now - timestamp > SAVE_NOTIFICATION_REQUEST_DEDUP_WINDOW_MS) {
      recentSaveNotificationRequests.delete(key);
    }
  }

  const previousTimestamp = recentSaveNotificationRequests.get(dedupKey);
  recentSaveNotificationRequests.set(dedupKey, now);

  return previousTimestamp !== undefined && (now - previousTimestamp) < SAVE_NOTIFICATION_REQUEST_DEDUP_WINDOW_MS;
}

function requestPersistentSaveNotification(data, sourceLabel, onComplete = null) {
  const payload = {
    ...data,
    request_source: data?.request_source || sourceLabel
  };

  if (isDuplicateSaveNotificationRequest(data)) {
    debugLog('Skipping duplicate save notification request from', sourceLabel);
    if (typeof onComplete === 'function') {
      onComplete({ success: true, deduped: true });
    }
    return;
  }

  debugLog('Requesting persistent save notification from', sourceLabel);
  chrome.runtime.sendMessage({
    type: 'request_save_notification',
    data: payload
  }, (response) => {
    if (chrome.runtime.lastError) {
      errorLog('Message error:', chrome.runtime.lastError.message);
    } else {
      debugLog('Save notification response:', redactForLog(response));
    }

    if (typeof onComplete === 'function') {
      onComplete(response);
    }
  });
}

function reportSavePromptOutcome(outcome, data = {}) {
  const payload = {
    type: 'save_prompt_outcome',
    data: {
      source: 'inline_prompt',
      outcome,
      timestamp: Date.now(),
      ...data
    }
  };

  try {
    chrome.runtime.sendMessage(payload, (response) => {
      if (chrome.runtime.lastError) {
        errorLog('Failed to report save prompt outcome:', chrome.runtime.lastError.message);
        return;
      }
      debugLog('Save prompt outcome reported:', redactForLog(payload.data), redactForLog(response));
    });
  } catch (error) {
    errorLog('Exception while reporting save prompt outcome:', error.message);
  }
}

// Track form submissions to detect new passwords
const trackedForms = new WeakSet();
const submittedCredentials = new Map(); // Track credentials per form

// Wait for DOM to be ready
if (document.readyState === 'loading') {
  document.addEventListener('DOMContentLoaded', init);
} else {
  init();
}

function init() {
  infoLog('Extension initializing...');

  // Observe DOM changes for dynamically added forms
  observeDOMChanges();

  // Scan for password fields immediately
  detectAndInjectButtons();

  // Track form submissions for password saving
  trackFormSubmissions();

  // Check for pending credentials from previous page
  checkPendingCredentials();

  // Listen for messages from background script
  chrome.runtime.onMessage.addListener((request, sender, sendResponse) => {
    // Validate sender is from this extension
    if (sender.id !== chrome.runtime.id) { return; }

    debugLog('Received message:', request.type);
    if (request.type === 'trigger_autofill') {
      performAutofill();
    }
    if (request.type === 'fill_credentials') {
      fillCredentials(request.username, request.password);
    }
    if (request.type === 'show_inline_save_prompt') {
      const payload = request.data || {};
      const username = payload.username || '';
      const password = payload.password || '';
      const domain = payload.domain || window.location.hostname;
      const sourceUrl = payload.submitted_url || payload.url || window.location.href;

      if (!password) {
        sendResponse({ success: false, error: 'Missing password for inline save prompt' });
        return false;
      }

      infoLog('Showing inline save prompt fallback');
      showSavePrompt(username, domain, password, sourceUrl);
      sendResponse({ success: true });
      return true;
    }
  });

  infoLog('Initialization complete');
}

// Check if there's a pending credential from a previous page login
function checkPendingCredentials() {
  // Check if we're in a valid context (not an iframe/blank page)
  if (window.location.protocol === 'about:' || window.location.protocol === 'data:') {
    debugLog('Skipping pending credentials check in restricted context');
    return;
  }

  // Check if we're in an iframe
  if (window.self !== window.top) {
    debugLog('Skipping pending credentials check in iframe');
    return;
  }

  try {
    chrome.storage.session.get(['pendingCredential'], (result) => {
      if (chrome.runtime.lastError) {
        errorLog('Storage access error:', chrome.runtime.lastError.message);
        return;
      }

      if (result && result.pendingCredential) {
        const pending = result.pendingCredential;
        const age = Date.now() - pending.timestamp;

        debugLog('Found pending login, age:', age, 'ms');
        debugLog('Pending domain (sanitized):', sanitizeHostname(pending.domain));
        debugLog('Current domain (sanitized):', sanitizeHostname(window.location.hostname));

        // Only show prompt if less than 30 seconds old and on a different page
        if (age < 30000 && window.location.hostname === pending.domain && window.location.href !== pending.url) {
          void (async () => {
            if (await shouldSuppressSavePrompt(pending.domain || pending.url || '')) {
              debugLog('Skipping pending save notification due to never-save policy');
              chrome.storage.session.remove('pendingCredential');
              return;
            }

            infoLog('Successful login detected, showing save notification...');

            // Request notification
            debugLog('[SentinelPass] ========== SENDING NOTIFICATION FROM 2FA PAGE ==========');
            requestPersistentSaveNotification(pending, 'pending-login-check', () => {
              // Clear the pending login regardless of callback result.
              chrome.storage.session.remove('pendingCredential');
            });
          })();
        } else if (age >= 30000) {
          debugLog('[SentinelPass] Clearing stale pending login');
          chrome.storage.session.remove('pendingCredential');
        }
      }
    });
  } catch (error) {
    debugLog('[SentinelPass] Error checking pending credentials:', error.message);
  }
}

// Track form submissions to detect new/changed passwords
function trackFormSubmissions() {
  debugLog('[SentinelPass] Setting up form submission tracking...');

  // Listen for form submissions
  document.addEventListener('submit', (e) => {
    const form = e.target;
    if (!form) {
      debugLog('[SentinelPass] Form submission: no form target');
      return;
    }

    debugLog('[SentinelPass] Form submission detected!');
    debugLog('[SentinelPass] Form action:', form.action);
    debugLog('[SentinelPass] Form ID:', form.id);

    const passwordField = form.querySelector('input[type="password"]');
    if (!passwordField) {
      debugLog('[SentinelPass] No password field found in form');
      return;
    }

    if (!passwordField.value) {
      debugLog('[SentinelPass] Password field is empty');
      return;
    }

    debugLog('[SentinelPass] Password field has value length:', passwordField.value.length);

    // Find username field
    const usernameField = findUsernameField(passwordField);
    const username = usernameField ? usernameField.value : '';
    debugLog('[SentinelPass] Username field found:', !!usernameField);

    // Detect if this is a new password or password change
    const domain = window.location.hostname;
    const isNewPassword = isNewPasswordForm(form, passwordField);
    debugLog('[SentinelPass] Is new password form:', isNewPassword);

    // Store credentials in session storage (persists across navigation)
    const inputMethod = detectInputMethod(username, passwordField.value, domain);
    const submissionData = {
      username: username,
      password: passwordField.value,
      domain: domain,
      url: window.location.href,
      submitted_url: window.location.href,
      timestamp: Date.now(),
      input_method: inputMethod,
      isNewPassword: isNewPassword
    };

    debugLog('[SentinelPass] Submission input method:', inputMethod);

    chrome.storage.session.set({ 'pendingCredential': submissionData }, () => {
      debugLog('[SentinelPass] Stored credentials in session storage');
    });

    // Show save prompt immediately for new password forms
    if (isNewPassword) {
      debugLog('[SentinelPass] Scheduling save prompt in 500ms...');
      setTimeout(() => {
        showSavePrompt(username, domain, passwordField.value, submissionData.url);
      }, 500);
    } else {
      // For login forms, send to background for persistent notification
      // This survives page navigation
      void (async () => {
        if (await shouldSuppressSavePrompt(domain)) {
          debugLog('[SentinelPass] Suppressing login save notification due to never-save policy');
          return;
        }

        debugLog('[SentinelPass] Login form submitted, requesting persistent notification...');
        requestPersistentSaveNotification(submissionData, 'form-submit');
      })();
    }
  }, true);

  // Also listen for button clicks in forms (for JavaScript-based submissions)
  document.addEventListener('click', (e) => {
    const button = e.target.closest('button[type="submit"], input[type="submit"], button:not([type])');
    if (!button) return;

    const form = button.form;
    if (!form) return;

    const passwordField = form.querySelector('input[type="password"]');
    if (!passwordField || !passwordField.value) return;

    debugLog('[SentinelPass] Submit button clicked in form with password field');

    // Get credentials IMMEDIATELY - no delays
    const usernameField = findUsernameField(passwordField);
    const domain = window.location.hostname;

    const submittedUsername = usernameField ? usernameField.value : '';
    const inputMethod = detectInputMethod(submittedUsername, passwordField.value, domain);
    const submissionData = {
      username: submittedUsername,
      password: passwordField.value,
      domain: domain,
      url: window.location.href,
      submitted_url: window.location.href,
      timestamp: Date.now(),
      input_method: inputMethod,
      isNewPassword: isNewPasswordForm(form, passwordField)
    };

    debugLog('[SentinelPass] Submission input method:', inputMethod);

    debugLog('[SentinelPass] Button click - capturing credentials immediately');
    debugLog('[SentinelPass] Domain:', submissionData.domain);

    // Store in session storage
    try {
      chrome.storage.session.set({ 'pendingCredential': submissionData }, () => {
        if (chrome.runtime.lastError) {
          debugLog('[SentinelPass] Storage error:', chrome.runtime.lastError.message);
        } else {
          debugLog('[SentinelPass] Stored credentials from button click');
        }
      });
    } catch (error) {
      debugLog('[SentinelPass] Storage exception:', error.message);
    }
    // Request notification IMMEDIATELY - no delays
    if (!submissionData.isNewPassword) {
      void (async () => {
        if (await shouldSuppressSavePrompt(submissionData.domain || submissionData.url || '')) {
          debugLog('[SentinelPass] Suppressing button-click save notification due to never-save policy');
          return;
        }

        debugLog('[SentinelPass] Requesting save notification from button click');
        requestPersistentSaveNotification(submissionData, 'submit-button-click');
      })();
    }
  }, true);
}

// Detect if form is for new account creation
function isNewPasswordForm(form, passwordField) {
  debugLog('[SentinelPass] Checking if new password form...');

  // Check for common registration indicators
  const formText = form.textContent.toLowerCase();
  const formId = (form.id || '').toLowerCase();
  const formAction = (form.action || '').toLowerCase();

  debugLog('[SentinelPass] Form text sample:', formText.substring(0, 200));
  debugLog('[SentinelPass] Form ID:', formId);
  debugLog('[SentinelPass] Form action:', formAction);

  // Indicators of new account creation
  const newAccountIndicators = [
    'register', 'signup', 'sign-up', 'sign up', 'create account',
    'new account', 'join', 'get started', 'create password'
  ];

  const hasNewAccountIndicator = newAccountIndicators.some(indicator =>
    formText.includes(indicator) ||
    formId.includes(indicator) ||
    formAction.includes(indicator)
  );

  debugLog('[SentinelPass] Has new account indicator:', hasNewAccountIndicator);

  // Check if password confirmation field exists (common in registration)
  const passwordFields = form.querySelectorAll('input[type="password"]');
  const hasPasswordConfirm = passwordFields.length > 1;

  debugLog('[SentinelPass] Password fields count:', passwordFields.length);
  debugLog('[SentinelPass] Has password confirm:', hasPasswordConfirm);

  // Check if current password field is empty (might be password change)
  const isNewPassword = hasNewAccountIndicator || hasPasswordConfirm;

  debugLog('[SentinelPass] Is new password:', isNewPassword);
  return isNewPassword;
}

// Show prompt to save credentials
function showSavePrompt(username, domain, password, sourceUrl = window.location.href) {
  void (async () => {
    if (await shouldSuppressSavePrompt(domain)) {
      debugLog('[SentinelPass] Suppressing save prompt due to never-save policy');
      reportSavePromptOutcome('no_save_suppressed_policy', {
        domain: domain,
        url: sourceUrl
      });
      return;
    }

    debugLog('[SentinelPass] showSavePrompt called!');
    debugLog('[SentinelPass] Domain:', domain);
    debugLog('[SentinelPass] Password length:', password.length);

  const promptId = `inline-${Date.now()}-${Math.random().toString(16).slice(2, 8)}`;
  let outcomeReported = false;
  const reportOnce = (outcome, extra = {}) => {
    if (outcomeReported) {
      return;
    }
    outcomeReported = true;
    reportSavePromptOutcome(outcome, {
      promptId: promptId,
      domain: domain,
      url: sourceUrl,
      ...extra
    });
  };
  const onBeforeUnload = () => {
    reportOnce('no_save_page_unload');
  };
  window.addEventListener('beforeunload', onBeforeUnload, { once: true });

  // Remove existing prompt if any
  const existingPrompt = document.querySelector('.pm-save-prompt');
  if (existingPrompt) {
    debugLog('[SentinelPass] Removing existing prompt');
    reportSavePromptOutcome('no_save_prompt_replaced', {
      domain: domain,
      url: sourceUrl
    });
    existingPrompt.remove();
  }

  debugLog('[SentinelPass] Creating save prompt element...');
  const prompt = document.createElement('div');
  prompt.className = 'pm-save-prompt';

  const content = document.createElement('div');
  content.className = 'pm-prompt-content';

  // Header
  const header = document.createElement('div');
  header.className = 'pm-prompt-header';
  header.appendChild(createLockIcon(20, 20));

  const title = document.createElement('span');
  title.className = 'pm-prompt-title';
  title.textContent = 'Save Password?';
  header.appendChild(title);

  const closeBtn = document.createElement('button');
  closeBtn.type = 'button';
  closeBtn.className = 'pm-prompt-close';
  closeBtn.textContent = '\u00d7';
  header.appendChild(closeBtn);

  // Body
  const body = document.createElement('div');
  body.className = 'pm-prompt-body';

  const domainP = document.createElement('p');
  domainP.textContent = 'SentinelPass detected a new password for ';
  const domainStrong = document.createElement('strong');
  domainStrong.textContent = domain;
  domainP.appendChild(domainStrong);
  body.appendChild(domainP);

  if (username) {
    const userP = document.createElement('p');
    userP.textContent = 'Username: ';
    const userStrong = document.createElement('strong');
    userStrong.textContent = username;
    userP.appendChild(userStrong);
    body.appendChild(userP);
  }

  const actions = document.createElement('div');
  actions.className = 'pm-prompt-actions';

  const saveBtn = document.createElement('button');
  saveBtn.type = 'button';
  saveBtn.className = 'pm-prompt-btn pm-prompt-btn-save';
  saveBtn.textContent = 'Save';

  const neverBtn = document.createElement('button');
  neverBtn.type = 'button';
  neverBtn.className = 'pm-prompt-btn pm-prompt-btn-never';
  neverBtn.textContent = 'Never for this site';

  const notNowBtn = document.createElement('button');
  notNowBtn.type = 'button';
  notNowBtn.className = 'pm-prompt-btn pm-prompt-btn-notnow';
  notNowBtn.textContent = 'Not now';

  actions.appendChild(saveBtn);
  actions.appendChild(neverBtn);
  actions.appendChild(notNowBtn);
  body.appendChild(actions);

  content.appendChild(header);
  content.appendChild(body);
  prompt.appendChild(content);

  prompt.style.cssText = `
    position: fixed;
    top: 20px;
    right: 20px;
    width: 400px;
    max-width: calc(100vw - 40px);
    background: white;
    border-radius: 8px;
    box-shadow: 0 4px 20px rgba(0,0,0,0.3);
    z-index: 999999;
    font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, sans-serif;
    animation: pmSlideIn 0.3s ease-out;
  `;

  // Add styles for the prompt
  const style = document.createElement('style');
  style.textContent = `
    @keyframes pmSlideIn {
      from { transform: translateY(-20px); opacity: 0; }
      to { transform: translateY(0); opacity: 1; }
    }
    .pm-prompt-content {
      padding: 16px;
    }
    .pm-prompt-header {
      display: flex;
      align-items: center;
      gap: 8px;
      margin-bottom: 12px;
      padding-bottom: 12px;
      border-bottom: 1px solid #e0e0e0;
    }
    .pm-prompt-title {
      font-weight: 600;
      font-size: 16px;
      flex: 1;
    }
    .pm-prompt-close {
      background: none;
      border: none;
      font-size: 20px;
      cursor: pointer;
      padding: 0;
      color: #666;
    }
    .pm-prompt-body p {
      margin: 0 0 8px 0;
      font-size: 14px;
      color: #333;
    }
    .pm-prompt-actions {
      display: flex;
      gap: 8px;
      margin-top: 16px;
    }
    .pm-prompt-btn {
      padding: 8px 16px;
      border-radius: 4px;
      border: none;
      cursor: pointer;
      font-size: 14px;
      font-weight: 500;
    }
    .pm-prompt-btn-save {
      background: #1a73e8;
      color: white;
    }
    .pm-prompt-btn-save:hover {
      background: #1557b0;
    }
    .pm-prompt-btn-never {
      background: #f1f3f4;
      color: #5f6368;
    }
    .pm-prompt-btn-never:hover {
      background: #e8eaed;
    }
    .pm-prompt-btn-notnow {
      background: transparent;
      color: #5f6368;
    }
    .pm-prompt-btn-notnow:hover {
      background: #f1f3f4;
    }
  `;

  document.head.appendChild(style);
  document.body.appendChild(prompt);

  debugLog('[SentinelPass] Save prompt appended to DOM');
  reportSavePromptOutcome('prompt_shown', {
    promptId: promptId,
    domain: domain,
    url: sourceUrl
  });

  // Add event listeners
  closeBtn.addEventListener('click', () => {
    debugLog('[SentinelPass] Prompt close button clicked');
    window.removeEventListener('beforeunload', onBeforeUnload);
    reportOnce('no_save_closed', {
      usernamePresent: Boolean(username)
    });
    prompt.remove();
  });

  saveBtn.addEventListener('click', () => {
    debugLog('[SentinelPass] Save button clicked!');
    window.removeEventListener('beforeunload', onBeforeUnload);
    reportOnce('save_clicked', {
      usernamePresent: Boolean(username)
    });
    saveCredentials(username, password, domain, sourceUrl);
    prompt.remove();
  });

  neverBtn.addEventListener('click', () => {
    debugLog('[SentinelPass] Never button clicked');
    window.removeEventListener('beforeunload', onBeforeUnload);
    reportOnce('no_save_never_for_site');
    void addNeverSaveDomain(domain)
      .then((stored) => {
        if (stored) {
          showNotification(`Will no longer prompt for ${domain}`, 'info');
        }
      })
      .catch((error) => {
        console.error('[SentinelPass] Failed to store never-save policy:', error);
      });
    prompt.remove();
  });

  notNowBtn.addEventListener('click', () => {
    debugLog('[SentinelPass] Not now button clicked');
    window.removeEventListener('beforeunload', onBeforeUnload);
    reportOnce('no_save_not_now');
    prompt.remove();
  });

  debugLog('[SentinelPass] Event listeners attached to save prompt');

    // Auto-dismiss after 30 seconds
    setTimeout(() => {
      if (prompt.parentNode) {
        window.removeEventListener('beforeunload', onBeforeUnload);
        reportOnce('no_save_timeout');
        prompt.style.animation = 'pmSlideOut 0.3s ease-out';
        setTimeout(() => prompt.remove(), 300);
      }
    }, 30000);
  })();
}

// Save credentials to vault via native messaging
async function saveCredentials(username, password, domain, sourceUrl = window.location.href) {
  debugLog('[SentinelPass] saveCredentials called');
  debugLog('[SentinelPass] Sending message to background script...');

  try {
    const response = await chrome.runtime.sendMessage({
      type: 'save_credential',
      data: {
        username: username,
        password: password,
        domain: domain,
        url: sourceUrl || window.location.href,
        submitted_url: sourceUrl || window.location.href,
        save_trigger: 'inline_prompt_button'
      }
    });

    debugLog('[SentinelPass] Received response from background:', redactForLog(response));

    if (response.success) {
      if (response.unchanged) {
        debugLog('[SentinelPass] Credential unchanged, skipping duplicate save');
        showNotification('Password already up to date', 'info');
      } else {
        debugLog('[SentinelPass] Password saved successfully!');
        showNotification('Password saved successfully!', 'success');
      }
    } else {
      console.error('[SentinelPass] Failed to save:', response.error);
      if (response.code === 'vault_locked') {
        showNotification('Vault locked. Unlock SentinelPass app, then click Retry save in the browser notification.', 'warning');
      } else {
        showNotification('Failed to save: ' + (response.error || 'Unknown error'), 'error');
      }
    }
  } catch (error) {
    console.error('[SentinelPass] Save credentials failed:', error);
    showNotification('Failed to save password', 'error');
  }
}

// Observe DOM for changes
function observeDOMChanges() {
  const observer = new MutationObserver((mutations) => {
    for (const mutation of mutations) {
      if (mutation.addedNodes.length > 0) {
        detectAndInjectButtons();
        break;
      }
    }
  });

  observer.observe(document.body, {
    childList: true,
    subtree: true
  });
}

// Detect password fields and inject autofill buttons
function detectAndInjectButtons() {
  const passwordFields = document.querySelectorAll('input[type="password"]');
  debugLog('[SentinelPass] Password fields detected:', passwordFields.length);

  passwordFields.forEach((field, index) => {
    debugLog('[SentinelPass] Processing password field', index);

    // Skip if button already exists
    if (field.parentElement.querySelector(`.${AUTOFILL_BUTTON_CLASS}`)) {
      debugLog('[SentinelPass] Button already exists for field', index);
      return;
    }

    // Make parent relative for absolute positioning
    const parent = field.parentElement;
    const computedStyle = window.getComputedStyle(parent);
    if (computedStyle.position === 'static') {
      parent.style.position = 'relative';
    }

    debugLog('[SentinelPass] Injecting autofill button for field', index);
    injectAutofillButton(field, parent);

    // NEW: Monitor password field for changes to capture credentials
    monitorPasswordField(field);
  });
}

// Monitor password field and store credentials as user types
function monitorPasswordField(passwordField) {
  debugLog('[SentinelPass] monitorPasswordField called');

  const form = passwordField.form;
  if (!form) {
    debugLog('[SentinelPass] No form found for password field');
    return;
  }

  debugLog('[SentinelPass] Form found:', form.action || form.id || 'unnamed');

  // Get the form's submit button to monitor clicks
  const submitButton = form.querySelector('button[type="submit"], input[type="submit"], button:not([type])');
  if (!submitButton) {
    debugLog('[SentinelPass] No submit button found');
    return;
  }

  debugLog('[SentinelPass] Submit button found, setting up mousedown listener');
  debugLog('[SentinelPass] Submit button text:', submitButton.textContent || submitButton.value);

  // Use mousedown on submit button (fires before click and before navigation)
  submitButton.addEventListener('mousedown', (e) => {
    debugLog('[SentinelPass] Mousedown fired!');

    if (!passwordField.value) {
      debugLog('Password field is empty, skipping');
      return;
    }

    debugLog('Submit button mousedown - capturing credentials');
    debugLog('Password value length:', sanitizePasswordLength(passwordField.value));

    const usernameField = findUsernameField(passwordField);
    const domain = window.location.hostname;

    const submittedUsername = usernameField ? usernameField.value : '';
    const inputMethod = detectInputMethod(submittedUsername, passwordField.value, domain);
    const submissionData = {
      username: submittedUsername,
      password: passwordField.value,
      domain: domain,
      url: window.location.href,
      submitted_url: window.location.href,
      timestamp: Date.now(),
      input_method: inputMethod,
      isNewPassword: isNewPasswordForm(form, passwordField)
    };

    debugLog('[SentinelPass] Captured credentials on mousedown');
    debugLog('[SentinelPass] Domain:', domain);
    debugLog('[SentinelPass] Username detected:', Boolean(submissionData.username));
    debugLog('[SentinelPass] Submission input method:', inputMethod);

    // Store in session storage (cleared when browser closes — no plaintext on disk)
    chrome.storage.session.set({ 'pendingCredential': submissionData }, () => {
      if (chrome.runtime.lastError) {
        debugLog('[SentinelPass] Storage error:', chrome.runtime.lastError.message);
      } else {
        debugLog('[SentinelPass] Credentials stored in session storage');
      }
    });

    // Request notification immediately
    if (!submissionData.isNewPassword) {
      void (async () => {
        if (await shouldSuppressSavePrompt(submissionData.domain || submissionData.url || '')) {
          debugLog('[SentinelPass] Suppressing mousedown save notification due to never-save policy');
          return;
        }

        debugLog('[SentinelPass] ========== REQUESTING SAVE NOTIFICATION ==========');
        debugLog('[SentinelPass] Message type: request_save_notification');
        debugLog('[SentinelPass] Message data:', redactForLog(submissionData));

        requestPersistentSaveNotification(submissionData, 'submit-button-mousedown');
      })();
    }
  }, { once: false, capture: true });

  debugLog('[SentinelPass] Mousedown listener attached');
}

// Inject autofill button next to password field
function injectAutofillButton(passwordField, parent) {
  const button = document.createElement('button');
  button.className = AUTOFILL_BUTTON_CLASS;
  button.appendChild(createLockIcon(16, 16));
  button.setAttribute('type', 'button');
  button.setAttribute('aria-label', 'Fill password from Password Manager');

  // Apply styles
  button.style.cssText = AUTOFILL_BUTTON_STYLE;

  // Hover effect
  button.addEventListener('mouseenter', () => {
    button.style.cssText = AUTOFILL_BUTTON_STYLE + AUTOFILL_BUTTON_HOVER_STYLE;
  });
  button.addEventListener('mouseleave', () => {
    button.style.cssText = AUTOFILL_BUTTON_STYLE;
  });

  // Click handler
  button.addEventListener('click', (e) => {
    e.preventDefault();
    e.stopPropagation();
    requestAutofill(passwordField);
  });

  // Hide when password field is not focused
  passwordField.addEventListener('focus', () => {
    button.style.display = 'flex';
  });
  passwordField.addEventListener('blur', () => {
    // Delay hiding to allow button click
    setTimeout(() => {
      if (document.activeElement !== button) {
        button.style.display = 'none';
      }
    }, 200);
  });

  // Initially hide
  button.style.display = 'none';

  parent.appendChild(button);
}

// Request credentials from background script
async function requestAutofill(passwordField) {
  const domain = window.location.hostname;
  const requestId = generateUUID();

  debugLog('[SentinelPass] Requesting autofill for domain:', domain);

  try {
    const response = await chrome.runtime.sendMessage({
      type: 'get_credential',
      domain: domain,
      request_id: requestId
    });

    debugLog('[SentinelPass] Autofill response:', redactForLog(response));

    if (response.success && response.data) {
      fillCredentials(response.data.username, response.data.password);

      let statusMessage = 'Password filled successfully!';
      const totpResponse = await requestTotpCode(domain, requestId);
      if (totpResponse?.success && totpResponse.totp_code) {
        const didFillTotp = fillTotpCode(totpResponse.totp_code);
        if (didFillTotp) {
          statusMessage = 'Password and verification code filled!';
        }
      }

      // Show success indicator
      showNotification(statusMessage, 'success');
    } else {
      debugLog('[SentinelPass] No credentials found for', domain);
      showNotification('No credentials found for this site', 'info');
    }
  } catch (error) {
    console.error('[SentinelPass] Autofill failed:', error);
    showNotification('Failed to autofill password', 'error');
  }
}

// Request current TOTP code from background script.
async function requestTotpCode(domain, requestId) {
  try {
    const response = await chrome.runtime.sendMessage({
      type: 'get_totp_code',
      domain: domain,
      request_id: requestId
    });

    debugLog('[SentinelPass] TOTP response:', redactForLog(response));
    return response;
  } catch (error) {
    debugLog('[SentinelPass] TOTP request failed:', error);
    return null;
  }
}

// Fill credentials into form fields
function fillCredentials(username, password) {
  const passwordField = document.querySelector('input[type="password"]');
  if (!passwordField) return;

  const contextTimestamp = Date.now();
  lastAutofillContext = {
    username: username || '',
    password: password || '',
    domain: window.location.hostname,
    timestamp: contextTimestamp
  };
  debugLog('[SentinelPass] Updated autofill context for submit tracking');

  // Clear plaintext credentials from memory after the submission window expires
  setTimeout(() => {
    if (lastAutofillContext && lastAutofillContext.timestamp === contextTimestamp) {
      lastAutofillContext = null;
    }
  }, AUTOFILL_SUBMISSION_WINDOW_MS);

  // Fill password
  passwordField.value = password;
  passwordField.dispatchEvent(new Event('input', { bubbles: true }));
  passwordField.dispatchEvent(new Event('change', { bubbles: true }));

  // Try to find username field
  const usernameField = findUsernameField(passwordField);
  if (usernameField && username) {
    usernameField.value = username;
    usernameField.dispatchEvent(new Event('input', { bubbles: true }));
    usernameField.dispatchEvent(new Event('change', { bubbles: true }));
  }
}

// Find likely TOTP/OTP field on page.
function findTotpField() {
  const exactSelectors = [
    'input[autocomplete="one-time-code"]',
    'input[name*="otp" i]',
    'input[id*="otp" i]',
    'input[name*="totp" i]',
    'input[id*="totp" i]',
    'input[name*="verification" i]',
    'input[id*="verification" i]'
  ];

  for (const selector of exactSelectors) {
    const field = document.querySelector(selector);
    if (field && !field.disabled && !field.readOnly) {
      return field;
    }
  }

  const allInputs = document.querySelectorAll<HTMLInputElement>('input[type="text"], input[type="tel"], input[type="number"], input:not([type])');
  for (const input of allInputs) {
    if (input.disabled || input.readOnly) {
      continue;
    }
    const signal = [
      input.name || '',
      input.id || '',
      input.placeholder || '',
      input.autocomplete || '',
      input.getAttribute('aria-label') || ''
    ].join(' ');
    if (/otp|totp|2fa|one.?time|verification|authenticator|security.?code|auth.?code/i.test(signal)) {
      return input;
    }
  }

  return null;
}

// Fill TOTP code if a matching field is available.
function fillTotpCode(code) {
  const field = findTotpField();
  if (!field || !code) {
    return false;
  }

  field.value = code;
  field.dispatchEvent(new Event('input', { bubbles: true }));
  field.dispatchEvent(new Event('change', { bubbles: true }));
  return true;
}

// Find username field based on password field location
function findUsernameField(passwordField) {
  const form = passwordField.form;

  if (form) {
    // Try to find username in same form
    let usernameField = form.querySelector('input[type="text"], input[type="email"]');

    // Look for input with "username", "email", "user" in name/id
    const inputs = form.querySelectorAll('input[type="text"], input[type="email"]');
    for (const input of inputs) {
      const attr = input.name + input.id + input.placeholder + input.autocomplete;
      if (/user|email|login/i.test(attr)) {
        usernameField = input;
        break;
      }
    }

    return usernameField;
  }

  // Try to find input before password field
  let prev = passwordField.previousElementSibling;
  while (prev) {
    if (prev.tagName === 'INPUT' && (prev.type === 'text' || prev.type === 'email')) {
      return prev;
    }
    prev = prev.previousElementSibling;
  }

  return null;
}

// Perform autofill from keyboard shortcut
function performAutofill() {
  const passwordField = document.querySelector('input[type="password"]');
  if (passwordField) {
    requestAutofill(passwordField);
  } else {
    showNotification('No password field found on this page', 'info');
  }
}

// Show notification to user
function showNotification(message, type = 'info') {
  const notification = document.createElement('div');
  notification.textContent = message;
  notification.style.cssText = `
    position: fixed;
    top: 20px;
    right: 20px;
    padding: 12px 20px;
    background: ${type === 'success' ? '#34a853' : type === 'error' ? '#ea4335' : '#1a73e8'};
    color: white;
    border-radius: 4px;
    box-shadow: 0 4px 6px rgba(0,0,0,0.2);
    z-index: 100000;
    font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, sans-serif;
    font-size: 14px;
    animation: slideIn 0.3s ease-out;
  `;

  document.body.appendChild(notification);

  setTimeout(() => {
    notification.style.animation = 'slideOut 0.3s ease-out';
    setTimeout(() => notification.remove(), 300);
  }, 3000);
}

// Generate UUID
function generateUUID() {
  return 'xxxxxxxx-xxxx-4xxx-yxxx-xxxxxxxxxxxx'.replace(/[xy]/g, function(c) {
    const r = Math.random() * 16 | 0;
    const v = c === 'x' ? r : (r & 0x3 | 0x8);
    return v.toString(16);
  });
}

// Add CSS animations
const style = document.createElement('style');
style.textContent = `
  @keyframes slideIn {
    from {
      transform: translateX(100%);
      opacity: 0;
    }
    to {
      transform: translateX(0);
      opacity: 1;
    }
  }

  @keyframes slideOut {
    from {
      transform: translateX(0);
      opacity: 1;
    }
    to {
      transform: translateX(100%);
      opacity: 0;
    }
  }

  .${AUTOFILL_BUTTON_CLASS}:hover {
    background: #1557b0 !important;
  }
`;
document.head.appendChild(style);

console.log('Password Manager content script initialized');
