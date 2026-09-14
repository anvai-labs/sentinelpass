(() => {
  // browser-extension/chrome/logger.js
  var debugMode = false;
  function initDebugMode() {
    if (typeof chrome !== "undefined" && chrome.management) {
      chrome.management.getSelf((info) => {
        if (info.installType === "development") {
          debugMode = true;
        }
      });
    }
    if (typeof chrome !== "undefined" && chrome.storage) {
      chrome.storage.local.get(["debugModeEnabled"], (result) => {
        if (result.debugModeEnabled === true) {
          debugMode = true;
        }
      });
    }
  }
  initDebugMode();
  function debugLog(...args) {
    if (debugMode) {
      console.log("[SentinelPass Debug]", ...args);
    }
  }
  function infoLog(message, ...args) {
    console.log(`[SentinelPass] ${message}`, ...args);
  }
  function errorLog(message, ...args) {
    console.error(`[SentinelPass] ${message}`, ...args);
  }
  function sanitizeUrl(url) {
    if (debugMode) {
      return url;
    }
    try {
      const urlObj = new URL(url);
      return urlObj.origin;
    } catch {
      return "(invalid URL)";
    }
  }
  function sanitizeHostname(hostname) {
    if (debugMode) {
      return hostname;
    }
    return "(hostname)";
  }
  function sanitizePasswordLength(password) {
    if (debugMode) {
      return password.length.toString();
    }
    if (!password) {
      return "empty";
    } else if (password.length < 8) {
      return "short (<8 chars)";
    } else if (password.length < 12) {
      return "medium (8-11 chars)";
    } else {
      return "long (12+ chars)";
    }
  }

  // browser-extension/chrome/save-heuristics.js
  function hasSchemePrefix(value) {
    return /^[a-zA-Z][a-zA-Z0-9+.-]*:/.test(value);
  }
  var HOST_PORT_ONLY = /^[a-zA-Z0-9.-]+:[0-9]{1,5}$/;
  function hostFromParsedUrl(parsed) {
    const host = parsed.hostname.replace(/^\[|\]$/g, "").replace(/^\.+|\.+$/g, "").toLowerCase();
    return host || null;
  }
  function stripPolicyWwwSuffix(host) {
    const withoutWww = host.startsWith("www.") ? host.slice(4) : host;
    return withoutWww || null;
  }
  function normalizeDomainForPolicy(value) {
    if (!value || typeof value !== "string") {
      return null;
    }
    const trimmed = value.trim();
    if (!trimmed) {
      return null;
    }
    if (hasSchemePrefix(trimmed)) {
      try {
        const host = hostFromParsedUrl(new URL(trimmed));
        if (host) {
          return stripPolicyWwwSuffix(host);
        }
      } catch {
      }
      if (HOST_PORT_ONLY.test(trimmed)) {
        try {
          const host = hostFromParsedUrl(new URL(`https://${trimmed}`));
          return host ? stripPolicyWwwSuffix(host) : null;
        } catch {
          return null;
        }
      }
      return null;
    }
    try {
      const host = hostFromParsedUrl(new URL(`https://${trimmed}`));
      if (!host) {
        return null;
      }
      return stripPolicyWwwSuffix(host);
    } catch {
      return null;
    }
  }
  function classifyCredentialUrlSecurity(rawUrl) {
    if (!rawUrl || typeof rawUrl !== "string") {
      return "unknown";
    }
    const trimmed = rawUrl.trim();
    if (!trimmed) {
      return "unknown";
    }
    try {
      const parsed = new URL(trimmed);
      if (parsed.protocol === "https:") {
        return "secure";
      }
      if (parsed.protocol === "http:") {
        return "insecure";
      }
      return "unknown";
    } catch {
      return "unknown";
    }
  }
  function domainMatchesPolicy(domain, policyDomain) {
    const normalizedDomain = domain.replace(/^\[|\]$/g, "");
    const normalizedPolicy = policyDomain.replace(/^\[|\]$/g, "");
    return normalizedDomain === normalizedPolicy || normalizedDomain.endsWith(`.${normalizedPolicy}`);
  }

  // browser-extension/chrome/field-semantics.js
  function autocompleteTokens(descriptor) {
    return (descriptor.autocomplete || "").split(/\s+/).map((token) => token.toLowerCase()).filter(Boolean);
  }
  function hint(descriptor) {
    return [descriptor.name, descriptor.id, descriptor.placeholder].filter((part) => typeof part === "string").join(" ").toLowerCase();
  }
  function classifyInputField(descriptor) {
    const tokens = autocompleteTokens(descriptor);
    for (const token of tokens) {
      if (token === "username" || token === "email" || token === "login") {
        return "username";
      }
      if (token === "current-password") {
        return "current-password";
      }
      if (token === "new-password") {
        return "new-password";
      }
      if (token === "one-time-code") {
        return "one-time-code";
      }
    }
    if ((descriptor.type || "").toLowerCase() === "password") {
      return "current-password";
    }
    if ((descriptor.type || "").toLowerCase() === "email" || /user|email|login/.test(hint(descriptor))) {
      return "username";
    }
    return "other";
  }
  function isAutofillablePasswordField(descriptor) {
    const role = classifyInputField(descriptor);
    const type = (descriptor.type || "").toLowerCase();
    return type === "password" && role === "current-password";
  }
  function classifyPasswordForm(fields) {
    const newPasswords = fields.filter((f) => classifyInputField(f) === "new-password");
    if (newPasswords.length === 0) {
      return "login";
    }
    const filledCurrent = fields.some((f) => classifyInputField(f) === "current-password" && f.hasValue);
    return filledCurrent ? "password-change" : "new-account";
  }

  // browser-extension/chrome/credential-choice.js
  function decideCredentialChoice(candidates, requestedUsername) {
    if (candidates.length === 0) {
      return { action: "none" };
    }
    if (requestedUsername) {
      const wanted = requestedUsername.trim().toLowerCase();
      const match = candidates.find((candidate) => candidate.username.trim().toLowerCase() === wanted);
      if (match) {
        return { action: "fill", username: match.username };
      }
    }
    if (candidates.length === 1) {
      return { action: "fill", username: candidates[0].username };
    }
    return {
      action: "choose",
      candidates: candidates.map((candidate) => ({
        username: candidate.username,
        title: candidate.title
      }))
    };
  }

  // browser-extension/chrome/content.ts
  function createLockIcon(width, height) {
    const ns = "http://www.w3.org/2000/svg";
    const svg = document.createElementNS(ns, "svg");
    svg.setAttribute("width", String(width));
    svg.setAttribute("height", String(height));
    svg.setAttribute("viewBox", "0 0 24 24");
    svg.setAttribute("fill", "currentColor");
    const path = document.createElementNS(ns, "path");
    path.setAttribute("d", "M12 17c1.1 0 2-.9 2-2s-.9-2-2-2-2 .9-2 2 .9 2 2 2zm6-9h-1V6c0-2.76-2.24-5-5-5S7 3.24 7 6v2H6c-1.1 0-2 .9-2 2v10c0 1.1.9 2 2 2h12c1.1 0 2-.9 2-2V10c0-1.1-.9-2-2-2zM9 6c0-1.66 1.34-3 3-3s3 1.34 3 3v2H9V6zm9 14H6V10h12v10zm-6-3c1.1 0 2-.9 2-2s-.9-2-2-2-2 .9-2 2 .9 2 2 2z");
    svg.appendChild(path);
    return svg;
  }
  infoLog("Content script loaded");
  debugLog("Current URL:", sanitizeUrl(window.location.href));
  debugLog("Hostname:", sanitizeHostname(window.location.hostname));
  var AUTOFILL_BUTTON_CLASS = "pm-autofill-button";
  var AUTOFILL_BUTTON_STYLE = `
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
  var AUTOFILL_BUTTON_HOVER_STYLE = `
  background: #1557b0;
`;
  var SENSITIVE_LOG_KEYS = /* @__PURE__ */ new Set(["password", "secret", "token", "passphrase"]);
  var NEVER_SAVE_DOMAINS_KEY = "neverSaveDomains";
  var SAVE_NOTIFICATION_REQUEST_DEDUP_WINDOW_MS = 4e3;
  var AUTOFILL_SUBMISSION_WINDOW_MS = 10 * 60 * 1e3;
  var mousedownInstrumentedForms = /* @__PURE__ */ new WeakSet();
  var recentSaveNotificationRequests = /* @__PURE__ */ new Map();
  var lastAutofillContext = null;
  function normalizeUsernameValue(value) {
    return typeof value === "string" ? value.trim().toLowerCase() : "";
  }
  function detectInputMethod(username, password, domain) {
    if (!lastAutofillContext || typeof password !== "string" || !password) {
      return "manual_or_unknown";
    }
    const ageMs = Date.now() - lastAutofillContext.timestamp;
    if (ageMs < 0 || ageMs > AUTOFILL_SUBMISSION_WINDOW_MS) {
      return "manual_or_unknown";
    }
    const sameDomain = lastAutofillContext.domain === domain;
    const samePassword = lastAutofillContext.password === password;
    if (!sameDomain || !samePassword) {
      return "manual_or_unknown";
    }
    const currentUser = normalizeUsernameValue(username);
    const autofillUser = normalizeUsernameValue(lastAutofillContext.username);
    const usernameCompatible = !autofillUser || !currentUser || autofillUser === currentUser;
    return usernameCompatible ? "autofill_reuse" : "manual_or_unknown";
  }
  function redactForLog(value) {
    if (!value || typeof value !== "object") {
      return value;
    }
    if (Array.isArray(value)) {
      return value.map(redactForLog);
    }
    const redacted = {};
    for (const [key, item] of Object.entries(value)) {
      if (SENSITIVE_LOG_KEYS.has(key.toLowerCase())) {
        redacted[key] = "[REDACTED]";
      } else if (item && typeof item === "object") {
        redacted[key] = redactForLog(item);
      } else {
        redacted[key] = item;
      }
    }
    return redacted;
  }
  function getNeverSaveDomains() {
    return new Promise((resolve) => {
      chrome.storage.local.get([NEVER_SAVE_DOMAINS_KEY], (result) => {
        if (chrome.runtime.lastError) {
          errorLog("Failed reading never-save domains:", chrome.runtime.lastError?.message);
          resolve({});
          return;
        }
        resolve(result[NEVER_SAVE_DOMAINS_KEY] || {});
      });
    });
  }
  function setNeverSaveDomains(domains) {
    return new Promise((resolve, reject) => {
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
    return Object.keys(domains).some(
      (policyDomain) => domainMatchesPolicy(normalized, policyDomain)
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
    const domain = normalizeDomainForPolicy(data?.domain || data?.url || "") || "unknown";
    const username = typeof data?.username === "string" ? data.username.trim().toLowerCase() : "";
    const url = typeof data?.url === "string" ? data.url.split("#")[0] : "";
    const passwordLength = typeof data?.password === "string" ? data.password.length : 0;
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
    return previousTimestamp !== void 0 && now - previousTimestamp < SAVE_NOTIFICATION_REQUEST_DEDUP_WINDOW_MS;
  }
  function requestPersistentSaveNotification(data, sourceLabel, onComplete = null) {
    const payload = {
      ...data,
      request_source: data?.request_source || sourceLabel
    };
    if (isDuplicateSaveNotificationRequest(data)) {
      debugLog("Skipping duplicate save notification request from", sourceLabel);
      if (typeof onComplete === "function") {
        onComplete({ success: true, deduped: true });
      }
      return;
    }
    debugLog("Requesting persistent save notification from", sourceLabel);
    chrome.runtime.sendMessage({
      type: "request_save_notification",
      data: payload
    }, (response) => {
      if (chrome.runtime.lastError) {
        errorLog("Message error:", chrome.runtime.lastError.message);
      } else {
        debugLog("Save notification response:", redactForLog(response));
      }
      if (typeof onComplete === "function") {
        onComplete(response);
      }
    });
  }
  function reportSavePromptOutcome(outcome, data = {}) {
    const payload = {
      type: "save_prompt_outcome",
      data: {
        source: "inline_prompt",
        outcome,
        timestamp: Date.now(),
        ...data
      }
    };
    try {
      chrome.runtime.sendMessage(payload, (response) => {
        if (chrome.runtime.lastError) {
          errorLog("Failed to report save prompt outcome:", chrome.runtime.lastError.message);
          return;
        }
        debugLog("Save prompt outcome reported:", redactForLog(payload.data), redactForLog(response));
      });
    } catch (error) {
      errorLog("Exception while reporting save prompt outcome:", error.message);
    }
  }
  if (document.readyState === "loading") {
    document.addEventListener("DOMContentLoaded", init);
  } else {
    init();
  }
  function init() {
    infoLog("Extension initializing...");
    try {
      initSteps();
    } catch (error) {
      console.error("[SentinelPass] Extension initialization failed:", error);
    }
  }
  function initSteps() {
    observeDOMChanges();
    detectAndInjectButtons();
    trackFormSubmissions();
    resumePendingLogin();
    window.addEventListener("pagehide", () => {
      lastAutofillContext = null;
    });
    chrome.runtime.onMessage.addListener((request, sender, sendResponse) => {
      if (sender.id !== chrome.runtime.id) {
        return;
      }
      debugLog("Received message:", request.type);
      if (request.type === "trigger_autofill") {
        performAutofill();
      }
      if (request.type === "scrub_secrets") {
        debugLog("Scrubbing in-memory autofill context (vault lock)");
        lastAutofillContext = null;
      }
      if (request.type === "show_inline_save_prompt") {
        const payload = request.data || {};
        const username = payload.username || "";
        const domain = payload.domain || window.location.hostname;
        const sourceUrl = payload.submitted_url || payload.url || window.location.href;
        const promptId = typeof payload.promptId === "string" ? payload.promptId : "";
        if (!promptId) {
          sendResponse({ success: false, error: "Missing prompt id for inline save prompt" });
          return false;
        }
        infoLog("Showing inline save prompt fallback (background-held payload)");
        showSavePrompt(username, domain, null, sourceUrl, promptId, payload.isPasswordChange === true);
        sendResponse({ success: true });
        return true;
      }
    });
    infoLog("Initialization complete");
  }
  function resumePendingLogin() {
    if (window.location.protocol === "about:" || window.location.protocol === "data:") {
      debugLog("Skipping pending credentials check in restricted context");
      return;
    }
    if (window.self !== window.top) {
      debugLog("Skipping pending credentials check in iframe");
      return;
    }
    try {
      chrome.runtime.sendMessage({
        type: "resume_pending_login",
        hostname: window.location.hostname,
        href: window.location.href
      }, (response) => {
        if (chrome.runtime.lastError) {
          debugLog("Resume pending login failed:", chrome.runtime.lastError.message);
          return;
        }
        if (response && response.resumed) {
          infoLog("Successful login detected, save notification shown by background");
        }
      });
    } catch (error) {
      debugLog("[SentinelPass] Error resuming pending login:", error.message);
    }
  }
  function capturePendingLogin(submissionData) {
    try {
      chrome.runtime.sendMessage({
        type: "capture_pending_login",
        data: submissionData
      }, (response) => {
        if (chrome.runtime.lastError) {
          debugLog("Pending login capture failed:", chrome.runtime.lastError.message);
        } else if (response && response.captured) {
          debugLog("[SentinelPass] Pending login captured by background");
        }
      });
    } catch (error) {
      debugLog("[SentinelPass] Pending login capture exception:", error.message);
    }
  }
  function trackFormSubmissions() {
    debugLog("[SentinelPass] Setting up form submission tracking...");
    document.addEventListener("submit", (e) => {
      const form = e.target instanceof HTMLFormElement ? e.target : null;
      if (!form) {
        debugLog("[SentinelPass] Form submission: no form target");
        return;
      }
      debugLog("[SentinelPass] Form submission detected!");
      debugLog("[SentinelPass] Form action:", form.action);
      debugLog("[SentinelPass] Form ID:", form.id);
      const passwordField = selectCaptureTarget(form);
      if (!passwordField) {
        debugLog("[SentinelPass] No password field found in form");
        return;
      }
      if (!passwordField.value) {
        debugLog("[SentinelPass] Password field is empty");
        return;
      }
      debugLog("[SentinelPass] Password field has value length:", passwordField.value.length);
      const usernameField = findUsernameField(passwordField);
      const username = usernameField ? usernameField.value : "";
      debugLog("[SentinelPass] Username field found:", !!usernameField);
      const domain = window.location.hostname;
      const isNewPassword = isNewPasswordForm(form, passwordField);
      const isPasswordChange = isNewPassword && isPasswordChangeForm(form);
      debugLog("[SentinelPass] Is new password form:", isNewPassword);
      debugLog("[SentinelPass] Is password change form:", isPasswordChange);
      const inputMethod = detectInputMethod(username, passwordField.value, domain);
      const submissionData = {
        username,
        password: passwordField.value,
        domain,
        url: window.location.href,
        submitted_url: window.location.href,
        timestamp: Date.now(),
        input_method: inputMethod,
        isNewPassword,
        isPasswordChange
      };
      debugLog("[SentinelPass] Submission input method:", inputMethod);
      capturePendingLogin(submissionData);
      if (isNewPassword) {
        debugLog("[SentinelPass] Scheduling save prompt in 500ms...");
        setTimeout(() => {
          showSavePrompt(username, domain, passwordField.value, submissionData.url, null, isPasswordChange);
        }, 500);
      } else {
        void (async () => {
          if (await shouldSuppressSavePrompt(domain)) {
            debugLog("[SentinelPass] Suppressing login save notification due to never-save policy");
            return;
          }
          debugLog("[SentinelPass] Login form submitted, requesting persistent notification...");
          requestPersistentSaveNotification(submissionData, "form-submit");
        })();
      }
    }, true);
    document.addEventListener("click", (e) => {
      if (!(e.target instanceof Element)) return;
      const button = e.target.closest('button[type="submit"], input[type="submit"], button:not([type])');
      if (!(button instanceof HTMLButtonElement || button instanceof HTMLInputElement)) return;
      const form = button.form;
      if (!form) return;
      const passwordField = selectCaptureTarget(form);
      if (!passwordField || !passwordField.value) return;
      debugLog("[SentinelPass] Submit button clicked in form with password field");
      const usernameField = findUsernameField(passwordField);
      const domain = window.location.hostname;
      const submittedUsername = usernameField ? usernameField.value : "";
      const inputMethod = detectInputMethod(submittedUsername, passwordField.value, domain);
      const isNewPassword = isNewPasswordForm(form, passwordField);
      const submissionData = {
        username: submittedUsername,
        password: passwordField.value,
        domain,
        url: window.location.href,
        submitted_url: window.location.href,
        timestamp: Date.now(),
        input_method: inputMethod,
        isNewPassword,
        isPasswordChange: isNewPassword && isPasswordChangeForm(form)
      };
      debugLog("[SentinelPass] Submission input method:", inputMethod);
      debugLog("[SentinelPass] Button click - capturing credentials immediately");
      debugLog("[SentinelPass] Domain:", submissionData.domain);
      capturePendingLogin(submissionData);
      if (!submissionData.isNewPassword) {
        void (async () => {
          if (await shouldSuppressSavePrompt(submissionData.domain || submissionData.url || "")) {
            debugLog("[SentinelPass] Suppressing button-click save notification due to never-save policy");
            return;
          }
          debugLog("[SentinelPass] Requesting save notification from button click");
          requestPersistentSaveNotification(submissionData, "submit-button-click");
        })();
      }
    }, true);
  }
  function selectCaptureTarget(form) {
    const fields = Array.from(
      form.querySelectorAll('input[type="password"]')
    );
    if (fields.length === 0) {
      return null;
    }
    const described = fields.map((field) => ({
      ...describeField(field),
      hasValue: Boolean(field.value)
    }));
    const kind = classifyPasswordForm(described);
    if (kind === "login") {
      return fields.find((field, index) => described[index].hasValue) || fields[0];
    }
    const newPasswords = fields.filter(
      (field, index) => classifyInputField(described[index]) === "new-password" || kind === "new-account"
    );
    const pool = newPasswords.length > 0 ? newPasswords : fields;
    for (let i = pool.length - 1; i >= 0; i -= 1) {
      if (pool[i].value) {
        return pool[i];
      }
    }
    return pool[pool.length - 1];
  }
  function isNewPasswordForm(form, passwordField) {
    debugLog("[SentinelPass] Checking if new password form...");
    const described = [];
    for (const field of form.querySelectorAll('input[type="password"]')) {
      const input = field;
      described.push({
        autocomplete: input.getAttribute("autocomplete") || "",
        type: input.type,
        name: input.name || "",
        id: input.id || "",
        placeholder: input.getAttribute("placeholder") || "",
        hasValue: Boolean(input.value)
      });
    }
    const kind = classifyPasswordForm(described);
    debugLog("[SentinelPass] Password form kind (autocomplete signal):", kind);
    if (kind !== "login") {
      return true;
    }
    const formText = form.textContent.toLowerCase();
    const formId = (form.id || "").toLowerCase();
    const formAction = (form.action || "").toLowerCase();
    const newAccountIndicators = [
      "register",
      "signup",
      "sign-up",
      "sign up",
      "create account",
      "new account",
      "join",
      "get started",
      "create password"
    ];
    const hasNewAccountIndicator = newAccountIndicators.some(
      (indicator) => formText.includes(indicator) || formId.includes(indicator) || formAction.includes(indicator)
    );
    debugLog("[SentinelPass] Has new account indicator (text fallback):", hasNewAccountIndicator);
    return hasNewAccountIndicator;
  }
  function isPasswordChangeForm(form) {
    const described = [];
    for (const field of form.querySelectorAll('input[type="password"]')) {
      const input = field;
      described.push({
        autocomplete: input.getAttribute("autocomplete") || "",
        type: input.type,
        name: input.name || "",
        id: input.id || "",
        placeholder: input.getAttribute("placeholder") || "",
        hasValue: Boolean(input.value)
      });
    }
    return classifyPasswordForm(described) === "password-change";
  }
  function showSavePrompt(username, domain, password, sourceUrl = window.location.href, promptId = null, isPasswordChange = false) {
    void (async () => {
      if (await shouldSuppressSavePrompt(domain)) {
        debugLog("[SentinelPass] Suppressing save prompt due to never-save policy");
        reportSavePromptOutcome("no_save_suppressed_policy", {
          domain,
          url: sourceUrl
        });
        return;
      }
      debugLog("[SentinelPass] showSavePrompt called!");
      debugLog("[SentinelPass] Domain:", domain);
      debugLog("[SentinelPass] Password length:", password.length);
      const promptId2 = `inline-${Date.now()}-${Math.random().toString(16).slice(2, 8)}`;
      const insecurePage = window.location.protocol === "http:" || classifyCredentialUrlSecurity(sourceUrl) === "insecure";
      let outcomeReported = false;
      const reportOnce = (outcome, extra = {}) => {
        if (outcomeReported) {
          return;
        }
        outcomeReported = true;
        reportSavePromptOutcome(outcome, {
          promptId: promptId2,
          domain,
          url: sourceUrl,
          ...extra
        });
      };
      const onBeforeUnload = () => {
        reportOnce("no_save_page_unload");
      };
      window.addEventListener("beforeunload", onBeforeUnload, { once: true });
      const existingPrompt = document.querySelector(".pm-save-prompt");
      if (existingPrompt) {
        debugLog("[SentinelPass] Removing existing prompt");
        reportSavePromptOutcome("no_save_prompt_replaced", {
          domain,
          url: sourceUrl
        });
        existingPrompt.remove();
      }
      debugLog("[SentinelPass] Creating save prompt element...");
      const prompt = document.createElement("div");
      prompt.className = "pm-save-prompt";
      const content = document.createElement("div");
      content.className = "pm-prompt-content";
      const header = document.createElement("div");
      header.className = "pm-prompt-header";
      header.appendChild(createLockIcon(20, 20));
      const title = document.createElement("span");
      title.className = "pm-prompt-title";
      title.textContent = isPasswordChange ? "Update Password?" : "Save Password?";
      header.appendChild(title);
      const closeBtn = document.createElement("button");
      closeBtn.type = "button";
      closeBtn.className = "pm-prompt-close";
      closeBtn.textContent = "\xD7";
      header.appendChild(closeBtn);
      const body = document.createElement("div");
      body.className = "pm-prompt-body";
      const domainP = document.createElement("p");
      domainP.textContent = isPasswordChange ? "SentinelPass detected a password change for " : "SentinelPass detected a new password for ";
      const domainStrong = document.createElement("strong");
      domainStrong.textContent = domain;
      domainP.appendChild(domainStrong);
      body.appendChild(domainP);
      if (username) {
        const userP = document.createElement("p");
        userP.textContent = "Username: ";
        const userStrong = document.createElement("strong");
        userStrong.textContent = username;
        userP.appendChild(userStrong);
        body.appendChild(userP);
      }
      if (insecurePage) {
        const warnP = document.createElement("p");
        warnP.className = "pm-prompt-warning";
        warnP.textContent = "This page uses an unencrypted connection (HTTP). The password could be visible to network attackers.";
        body.appendChild(warnP);
      }
      const actions = document.createElement("div");
      actions.className = "pm-prompt-actions";
      const saveBtn = document.createElement("button");
      saveBtn.type = "button";
      saveBtn.className = "pm-prompt-btn pm-prompt-btn-save";
      saveBtn.textContent = (isPasswordChange ? "Update" : "Save") + (insecurePage ? " anyway" : "");
      const neverBtn = document.createElement("button");
      neverBtn.type = "button";
      neverBtn.className = "pm-prompt-btn pm-prompt-btn-never";
      neverBtn.textContent = "Never for this site";
      const notNowBtn = document.createElement("button");
      notNowBtn.type = "button";
      notNowBtn.className = "pm-prompt-btn pm-prompt-btn-notnow";
      notNowBtn.textContent = "Not now";
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
      const style2 = document.createElement("style");
      style2.textContent = `
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
    .pm-prompt-warning {
      padding: 8px 10px;
      border-radius: 4px;
      background: #fef7e0;
      border: 1px solid #f9ab00;
      color: #8a5a00 !important;
      font-weight: 500;
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
      document.head.appendChild(style2);
      document.body.appendChild(prompt);
      debugLog("[SentinelPass] Save prompt appended to DOM");
      reportSavePromptOutcome("prompt_shown", {
        promptId: promptId2,
        domain,
        url: sourceUrl
      });
      closeBtn.addEventListener("click", () => {
        debugLog("[SentinelPass] Prompt close button clicked");
        window.removeEventListener("beforeunload", onBeforeUnload);
        reportOnce("no_save_closed", {
          usernamePresent: Boolean(username)
        });
        prompt.remove();
      });
      saveBtn.addEventListener("click", (event) => {
        if (!event.isTrusted) {
          return;
        }
        debugLog("[SentinelPass] Save button clicked!");
        window.removeEventListener("beforeunload", onBeforeUnload);
        reportOnce("save_clicked", {
          usernamePresent: Boolean(username)
        });
        if (promptId2) {
          void confirmInlineSave(promptId2);
        } else if (password) {
          saveCredentials(username, password, domain, sourceUrl, isPasswordChange);
        }
        prompt.remove();
      });
      neverBtn.addEventListener("click", (event) => {
        if (!event.isTrusted) {
          return;
        }
        debugLog("[SentinelPass] Never button clicked");
        window.removeEventListener("beforeunload", onBeforeUnload);
        reportOnce("no_save_never_for_site");
        void addNeverSaveDomain(domain).then((stored) => {
          if (stored) {
            showNotification(`Will no longer prompt for ${domain}`, "info");
          }
        }).catch((error) => {
          console.error("[SentinelPass] Failed to store never-save policy:", error);
        });
        prompt.remove();
      });
      notNowBtn.addEventListener("click", (event) => {
        if (!event.isTrusted) {
          return;
        }
        debugLog("[SentinelPass] Not now button clicked");
        window.removeEventListener("beforeunload", onBeforeUnload);
        reportOnce("no_save_not_now");
        prompt.remove();
      });
      debugLog("[SentinelPass] Event listeners attached to save prompt");
      setTimeout(() => {
        if (prompt.parentNode) {
          window.removeEventListener("beforeunload", onBeforeUnload);
          reportOnce("no_save_timeout");
          prompt.style.animation = "pmSlideOut 0.3s ease-out";
          setTimeout(() => prompt.remove(), 300);
        }
      }, 3e4);
    })();
  }
  async function confirmInlineSave(promptId) {
    try {
      const response = await chrome.runtime.sendMessage({
        type: "inline_save_confirm",
        promptId
      });
      if (response?.success) {
        if (response.unchanged) {
          showNotification("Password already up to date", "info");
        } else if (response.insecure_http) {
          showNotification("Password saved, but this site used unencrypted HTTP", "warning");
        } else {
          showNotification("Password saved successfully!", "success");
        }
      } else if (response?.code === "vault_locked") {
        showNotification("Vault locked. Unlock SentinelPass app, then submit the login again.", "warning");
      } else {
        console.error("[SentinelPass] Inline save confirm failed:", response?.error);
        showNotification("Failed to save: " + (response?.error || "Unknown error"), "error");
      }
    } catch (error) {
      console.error("[SentinelPass] Inline save confirm error:", error);
      showNotification("Failed to save password", "error");
    }
  }
  async function saveCredentials(username, password, domain, sourceUrl = window.location.href, isPasswordChange = false) {
    debugLog("[SentinelPass] saveCredentials called");
    debugLog("[SentinelPass] Sending message to background script...");
    try {
      const response = await chrome.runtime.sendMessage({
        type: "save_credential",
        data: {
          username,
          password,
          domain,
          url: sourceUrl || window.location.href,
          submitted_url: sourceUrl || window.location.href,
          save_trigger: isPasswordChange ? "password_change" : "inline_prompt_button"
        }
      });
      debugLog("[SentinelPass] Received response from background:", redactForLog(response));
      if (response.success) {
        if (response.unchanged) {
          debugLog("[SentinelPass] Credential unchanged, skipping duplicate save");
          showNotification("Password already up to date", "info");
        } else if (response.insecure_http) {
          debugLog("[SentinelPass] Password saved for a plain-HTTP origin");
          showNotification("Password saved, but this site used unencrypted HTTP", "warning");
        } else {
          debugLog("[SentinelPass] Password saved successfully!");
          showNotification("Password saved successfully!", "success");
        }
      } else {
        console.error("[SentinelPass] Failed to save:", response.error);
        if (response.code === "vault_locked") {
          showNotification("Vault locked. Unlock SentinelPass app, then click Retry save in the browser notification.", "warning");
        } else {
          showNotification("Failed to save: " + (response.error || "Unknown error"), "error");
        }
      }
    } catch (error) {
      console.error("[SentinelPass] Save credentials failed:", error);
      showNotification("Failed to save password", "error");
    }
  }
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
  function detectAndInjectButtons() {
    const passwordFields = document.querySelectorAll('input[type="password"]');
    debugLog("[SentinelPass] Password fields detected:", passwordFields.length);
    passwordFields.forEach((field, index) => {
      debugLog("[SentinelPass] Processing password field", index);
      if (field.parentElement.querySelector(`.${AUTOFILL_BUTTON_CLASS}`)) {
        debugLog("[SentinelPass] Button already exists for field", index);
        return;
      }
      const parent = field.parentElement;
      const computedStyle = window.getComputedStyle(parent);
      if (computedStyle.position === "static") {
        parent.style.position = "relative";
      }
      debugLog("[SentinelPass] Injecting autofill button for field", index);
      injectAutofillButton(field, parent);
      monitorPasswordField(field);
    });
  }
  function monitorPasswordField(passwordField) {
    debugLog("[SentinelPass] monitorPasswordField called");
    const form = passwordField.form;
    if (!form) {
      debugLog("[SentinelPass] No form found for password field");
      return;
    }
    if (mousedownInstrumentedForms.has(form)) {
      return;
    }
    mousedownInstrumentedForms.add(form);
    debugLog("[SentinelPass] Form found:", form.action || form.id || "unnamed");
    const submitButton = form.querySelector('button[type="submit"], input[type="submit"], button:not([type])');
    if (!submitButton) {
      debugLog("[SentinelPass] No submit button found");
      return;
    }
    debugLog("[SentinelPass] Submit button found, setting up mousedown listener");
    submitButton.addEventListener("mousedown", (e) => {
      debugLog("[SentinelPass] Mousedown fired!");
      const passwordField2 = selectCaptureTarget(form);
      if (!passwordField2 || !passwordField2.value) {
        debugLog("Password field is empty, skipping");
        return;
      }
      debugLog("Submit button mousedown - capturing credentials");
      debugLog("Password value length:", sanitizePasswordLength(passwordField2.value));
      const usernameField = findUsernameField(passwordField2);
      const domain = window.location.hostname;
      const submittedUsername = usernameField ? usernameField.value : "";
      const inputMethod = detectInputMethod(submittedUsername, passwordField2.value, domain);
      const isNewPassword = isNewPasswordForm(form, passwordField2);
      const submissionData = {
        username: submittedUsername,
        password: passwordField2.value,
        domain,
        url: window.location.href,
        submitted_url: window.location.href,
        timestamp: Date.now(),
        input_method: inputMethod,
        isNewPassword,
        isPasswordChange: isNewPassword && isPasswordChangeForm(form)
      };
      debugLog("[SentinelPass] Captured credentials on mousedown");
      debugLog("[SentinelPass] Domain:", domain);
      debugLog("[SentinelPass] Username detected:", Boolean(submissionData.username));
      debugLog("[SentinelPass] Submission input method:", inputMethod);
      capturePendingLogin(submissionData);
      if (!submissionData.isNewPassword) {
        void (async () => {
          if (await shouldSuppressSavePrompt(submissionData.domain || submissionData.url || "")) {
            debugLog("[SentinelPass] Suppressing mousedown save notification due to never-save policy");
            return;
          }
          debugLog("[SentinelPass] ========== REQUESTING SAVE NOTIFICATION ==========");
          debugLog("[SentinelPass] Message type: request_save_notification");
          debugLog("[SentinelPass] Message data:", redactForLog(submissionData));
          requestPersistentSaveNotification(submissionData, "submit-button-mousedown");
        })();
      }
    }, { once: false, capture: true });
    debugLog("[SentinelPass] Mousedown listener attached");
  }
  function injectAutofillButton(passwordField, parent) {
    const button = document.createElement("button");
    button.className = AUTOFILL_BUTTON_CLASS;
    button.appendChild(createLockIcon(16, 16));
    button.setAttribute("type", "button");
    button.setAttribute("aria-label", "Fill password from Password Manager");
    button.style.cssText = AUTOFILL_BUTTON_STYLE;
    button.addEventListener("mouseenter", () => {
      button.style.cssText = AUTOFILL_BUTTON_STYLE + AUTOFILL_BUTTON_HOVER_STYLE;
    });
    button.addEventListener("mouseleave", () => {
      button.style.cssText = AUTOFILL_BUTTON_STYLE;
    });
    button.addEventListener("click", (e) => {
      if (!e.isTrusted) {
        return;
      }
      e.preventDefault();
      e.stopPropagation();
      requestAutofill(passwordField);
    });
    passwordField.addEventListener("focus", () => {
      button.style.display = "flex";
    });
    passwordField.addEventListener("blur", () => {
      setTimeout(() => {
        if (document.activeElement !== button) {
          button.style.display = "none";
        }
      }, 200);
    });
    button.style.display = "none";
    parent.appendChild(button);
  }
  function describeField(field) {
    return {
      autocomplete: field.getAttribute("autocomplete") || "",
      type: field.type,
      name: field.name || "",
      id: field.id || "",
      placeholder: field.getAttribute("placeholder") || ""
    };
  }
  function isRenderedField(field) {
    if (field.disabled || field.readOnly) {
      return false;
    }
    const rect = field.getBoundingClientRect();
    return rect.width > 0 && rect.height > 0;
  }
  function newPasswordFillAllowed(form) {
    const fields = Array.from(
      form.querySelectorAll('input[type="password"]')
    );
    if (fields.length <= 1) {
      return true;
    }
    const described = fields.map((field) => ({
      ...describeField(field),
      hasValue: Boolean(field.value)
    }));
    return classifyPasswordForm(described) === "login";
  }
  function bindAutofillTarget(requestedField) {
    const candidates = Array.from(document.querySelectorAll('input[type="password"]'));
    const visible = (field) => isRenderedField(field) && isAutofillablePasswordField(describeField(field));
    if (requestedField && requestedField.isConnected && requestedField.type === "password") {
      const described = describeField(requestedField);
      if (isAutofillablePasswordField(described)) {
        return requestedField;
      }
      if (classifyInputField(described) === "new-password" && requestedField.form && newPasswordFillAllowed(requestedField.form)) {
        return requestedField;
      }
      return null;
    }
    return candidates.find((field) => visible(field) && isAutofillablePasswordField(describeField(field))) || null;
  }
  async function fetchAndFillFor(domain, requestId, username, targetField) {
    const response = await chrome.runtime.sendMessage({
      type: "get_credential",
      domain,
      request_id: requestId,
      username
    });
    debugLog("[SentinelPass] Autofill response:", redactForLog(response));
    if (typeof response?.error === "string" && response.error.startsWith("autofill denied:")) {
      debugLog("[SentinelPass] Autofill denied by daemon origin policy:", response.error);
      if (response.error.includes("insecure-http")) {
        showNotification("Autofill is disabled on unencrypted HTTP sites", "warning");
      } else {
        showNotification("Autofill is not available for this page", "warning");
      }
      return;
    }
    if (!(response.success && response.data)) {
      debugLog("[SentinelPass] No credential delivered for", domain);
      showNotification("No credentials found for this site", "info");
      return;
    }
    const target = bindAutofillTarget(targetField);
    if (!target) {
      showNotification(
        "No fillable password field (new-password fields are not autofilled)",
        "warning"
      );
      return;
    }
    fillCredentials(response.data.username, response.data.password, target);
    let statusMessage = "Password filled successfully!";
    const totpResponse = await requestTotpCode(domain, requestId, username);
    if (totpResponse?.success && totpResponse.totp_code) {
      const didFillTotp = fillTotpCode(totpResponse.totp_code);
      if (didFillTotp) {
        statusMessage = "Password and verification code filled!";
      }
    }
    showNotification(statusMessage, "success");
  }
  function showCredentialChooser(candidates, onPick) {
    document.querySelector(".pm-credential-chooser-host")?.remove();
    const host = document.createElement("div");
    host.className = "pm-credential-chooser-host";
    host.style.cssText = `
    position: fixed;
    top: 20px;
    right: 20px;
    width: 320px;
    max-width: calc(100vw - 40px);
    z-index: 2147483647;
    all: initial;
  `;
    const shadow = host.attachShadow({ mode: "closed" });
    const overlay = document.createElement("div");
    overlay.style.cssText = `
    background: white;
    border-radius: 8px;
    box-shadow: 0 4px 20px rgba(0,0,0,0.3);
    font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, sans-serif;
    padding: 12px;
  `;
    shadow.appendChild(overlay);
    const close = () => {
      host.remove();
      document.removeEventListener("keydown", onKey, true);
    };
    const title = document.createElement("div");
    title.textContent = "Choose an account";
    title.style.cssText = "font-weight:600; font-size:14px; margin-bottom:8px; color:#202124;";
    overlay.appendChild(title);
    const trustedPick = (event, username) => {
      if (!event.isTrusted) {
        debugLog("[SentinelPass] Refusing untrusted chooser event");
        return;
      }
      close();
      onPick(username);
    };
    for (const candidate of candidates) {
      const row = document.createElement("button");
      row.type = "button";
      row.textContent = candidate.title && candidate.title !== candidate.username ? `${candidate.username} \u2014 ${candidate.title}` : candidate.username;
      row.style.cssText = `
      display:block; width:100%; text-align:left; margin:4px 0;
      padding:8px 10px; border:1px solid #e0e0e0; border-radius:6px;
      background:#f8f9fa; cursor:pointer; font-size:13px; color:#202124;
    `;
      row.addEventListener("click", (event) => trustedPick(event, candidate.username));
      overlay.appendChild(row);
    }
    const cancel = document.createElement("button");
    cancel.type = "button";
    cancel.textContent = "Cancel";
    cancel.style.cssText = "margin-top:6px; background:none; border:none; color:#5f6368; cursor:pointer; font-size:12px;";
    cancel.addEventListener("click", (event) => {
      if (!event.isTrusted) {
        return;
      }
      close();
    });
    overlay.appendChild(cancel);
    const onKey = (event) => {
      if (event.isTrusted && event.key === "Escape") {
        close();
      }
    };
    document.addEventListener("keydown", onKey, true);
    document.body.appendChild(host);
  }
  async function requestAutofill(passwordField) {
    const domain = window.location.hostname;
    const requestId = generateUUID();
    debugLog("[SentinelPass] Requesting autofill for domain:", domain);
    try {
      const listing = await chrome.runtime.sendMessage({
        type: "list_domain_credentials",
        domain,
        request_id: requestId
      });
      if (typeof listing?.error === "string" && listing.error.startsWith("autofill denied:")) {
        debugLog("[SentinelPass] Autofill denied by daemon origin policy:", listing.error);
        if (listing.error.includes("insecure-http")) {
          showNotification("Autofill is disabled on unencrypted HTTP sites", "warning");
        } else {
          showNotification("Autofill is not available for this page", "warning");
        }
        return;
      }
      const candidates = (listing?.credentials || []).map((entry) => ({
        username: entry.username,
        title: entry.title || ""
      }));
      const decision = decideCredentialChoice(candidates);
      if (decision.action === "none") {
        debugLog("[SentinelPass] No credentials found for", domain);
        showNotification("No credentials found for this site", "info");
        return;
      }
      if (decision.action === "fill") {
        await fetchAndFillFor(domain, requestId, decision.username, passwordField);
        return;
      }
      showCredentialChooser(decision.candidates, (username) => {
        void fetchAndFillFor(domain, generateUUID(), username, passwordField);
      });
    } catch (error) {
      console.error("[SentinelPass] Autofill failed:", error);
      showNotification("Failed to autofill password", "error");
    }
  }
  async function requestTotpCode(domain, requestId, username) {
    try {
      const response = await chrome.runtime.sendMessage({
        type: "get_totp_code",
        domain,
        request_id: requestId,
        username
      });
      debugLog("[SentinelPass] TOTP response:", redactForLog(response));
      return response;
    } catch (error) {
      debugLog("[SentinelPass] TOTP request failed:", error);
      return null;
    }
  }
  function fillCredentials(username, password, targetField = null) {
    const passwordField = targetField || document.querySelector('input[type="password"]');
    if (!passwordField) return;
    const contextTimestamp = Date.now();
    lastAutofillContext = {
      username: username || "",
      password: password || "",
      domain: window.location.hostname,
      timestamp: contextTimestamp
    };
    debugLog("[SentinelPass] Updated autofill context for submit tracking");
    setTimeout(() => {
      if (lastAutofillContext && lastAutofillContext.timestamp === contextTimestamp) {
        lastAutofillContext = null;
      }
    }, AUTOFILL_SUBMISSION_WINDOW_MS);
    passwordField.value = password;
    passwordField.dispatchEvent(new Event("input", { bubbles: true }));
    passwordField.dispatchEvent(new Event("change", { bubbles: true }));
    const usernameField = findUsernameField(passwordField);
    if (usernameField && username) {
      usernameField.value = username;
      usernameField.dispatchEvent(new Event("input", { bubbles: true }));
      usernameField.dispatchEvent(new Event("change", { bubbles: true }));
    }
  }
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
    const allInputs = document.querySelectorAll('input[type="text"], input[type="tel"], input[type="number"], input:not([type])');
    for (const input of allInputs) {
      if (input.disabled || input.readOnly) {
        continue;
      }
      const signal = [
        input.name || "",
        input.id || "",
        input.placeholder || "",
        input.autocomplete || "",
        input.getAttribute("aria-label") || ""
      ].join(" ");
      if (/otp|totp|2fa|one.?time|verification|authenticator|security.?code|auth.?code/i.test(signal)) {
        return input;
      }
    }
    return null;
  }
  function fillTotpCode(code) {
    const field = findTotpField();
    if (!field || !code) {
      return false;
    }
    field.value = code;
    field.dispatchEvent(new Event("input", { bubbles: true }));
    field.dispatchEvent(new Event("change", { bubbles: true }));
    return true;
  }
  function findUsernameField(passwordField) {
    const form = passwordField.form;
    const isUsernameLike = (input) => {
      if (input.type !== "text" && input.type !== "email") {
        return false;
      }
      return classifyInputField({
        autocomplete: input.getAttribute("autocomplete") || "",
        type: input.type,
        name: input.name || "",
        id: input.id || "",
        placeholder: input.getAttribute("placeholder") || ""
      }) === "username";
    };
    if (form) {
      const inputs = Array.from(form.querySelectorAll("input"));
      return inputs.find(isUsernameLike) || null;
    }
    let prev = passwordField.previousElementSibling;
    while (prev) {
      if (prev.tagName === "INPUT" && isUsernameLike(prev)) {
        return prev;
      }
      prev = prev.previousElementSibling;
    }
    return null;
  }
  function performAutofill() {
    const target = bindAutofillTarget(null);
    if (target) {
      requestAutofill(target);
    } else {
      showNotification("No password field found on this page", "info");
    }
  }
  function showNotification(message, type = "info") {
    const notification = document.createElement("div");
    notification.textContent = message;
    notification.style.cssText = `
    position: fixed;
    top: 20px;
    right: 20px;
    padding: 12px 20px;
    background: ${type === "success" ? "#34a853" : type === "error" ? "#ea4335" : type === "warning" ? "#f9ab00" : "#1a73e8"};
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
      notification.style.animation = "slideOut 0.3s ease-out";
      setTimeout(() => notification.remove(), 300);
    }, 3e3);
  }
  function generateUUID() {
    return "xxxxxxxx-xxxx-4xxx-yxxx-xxxxxxxxxxxx".replace(/[xy]/g, function(c) {
      const r = Math.random() * 16 | 0;
      const v = c === "x" ? r : r & 3 | 8;
      return v.toString(16);
    });
  }
  var style = document.createElement("style");
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
  console.log("Password Manager content script initialized");
})();
