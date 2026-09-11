// Popup script for SentinelPass extension

const CLIPBOARD_CLEAR_TIMEOUT_MS = 10_000;

interface CredentialItem {
  username: string;
  title: string;
  domain: string;
}

let currentDomain = '';
let currentTabUrl = '';
let allCredentials: CredentialItem[] = [];

document.addEventListener('DOMContentLoaded', async () => {
  const [tab] = await chrome.tabs.query({ active: true, currentWindow: true });
  try {
    currentDomain = tab.url ? new URL(tab.url).hostname : '';
  } catch {
    currentDomain = '';
  }
  // Browser-provided URL of the active tab — forwarded as `page_url` so the
  // daemon can scheme-validate autofill delivery (WBS-711).
  currentTabUrl = typeof tab?.url === 'string' ? tab.url : '';

  setupEventListeners();
  checkVaultStatus();
});

function setupEventListeners() {
  document.getElementById('lockBtn')!.addEventListener('click', lockVault);
  document.getElementById('settingsBtn')!.addEventListener('click', openSettings);

  const search = document.getElementById('searchInput') as HTMLInputElement;
  search.addEventListener('input', () => handleSearch(search.value.trim()));

  document.getElementById('addCredentialBtn')!.addEventListener('click', showAddView);
  document.getElementById('addForm')!.addEventListener('submit', handleAddSubmit);
  document.getElementById('addCancelBtn')!.addEventListener('click', () => {
    (document.getElementById('addForm') as HTMLFormElement).reset();
    showUnlockedView();
  });

  document.getElementById('settingsBackBtn')!.addEventListener('click', showUnlockedView);

  // WBS-712 site access controls
  document.getElementById('siteAccessToggle')!.addEventListener('click', toggleSiteAccess);
  document.getElementById('httpAllowBtn')!.addEventListener('click', allowHttpForSite);
}

// ── Vault status ──────────────────────────────────────────────────────────────

async function checkVaultStatus() {
  showLoading();
  try {
    const response = await chrome.runtime.sendMessage({ type: 'check_vault_status' });
    if (response.unlocked) {
      showUnlockedView();
      await loadCredentials();
    } else {
      showLockedView();
    }
  } catch {
    showLockedView();
  }
}

// ── Credential loading and search ─────────────────────────────────────────────

async function loadCredentials() {
  if (!currentDomain) {
    renderCredentials([]);
    return;
  }
  try {
    const response = await chrome.runtime.sendMessage({
      type: 'list_domain_credentials',
      domain: currentDomain,
      request_id: generateUUID(),
      page_url: currentTabUrl,
    });
    const raw: any[] = response?.credentials ?? [];
    allCredentials = raw.map(c => ({
      username: c.username ?? '',
      title: c.title ?? currentDomain,
      domain: c.url ?? currentDomain,
    }));
  } catch {
    allCredentials = [];
  }

  // Clear the search box on every fresh load
  (document.getElementById('searchInput') as HTMLInputElement).value = '';
  renderCredentials(allCredentials);
}

function handleSearch(query: string) {
  if (!query) {
    renderCredentials(allCredentials);
    return;
  }
  const q = query.toLowerCase();
  renderCredentials(
    allCredentials.filter(
      c => c.username.toLowerCase().includes(q) || c.title.toLowerCase().includes(q)
    )
  );
}

function renderCredentials(credentials: CredentialItem[]) {
  const list = document.getElementById('credentialsList')!;
  list.textContent = '';

  if (credentials.length === 0) {
    const empty = document.createElement('div');
    empty.className = 'empty-state';
    const p = document.createElement('p');
    p.textContent = 'No credentials found for ';
    const strong = document.createElement('strong');
    strong.textContent = currentDomain || 'this site';
    p.appendChild(strong);
    empty.appendChild(p);
    list.appendChild(empty);
    return;
  }

  for (const cred of credentials) {
    const item = document.createElement('div');
    item.className = 'credential-item';

    const info = document.createElement('div');
    info.className = 'credential-info';

    const usernameDiv = document.createElement('div');
    usernameDiv.className = 'credential-username';
    usernameDiv.textContent = cred.username;

    const titleDiv = document.createElement('div');
    titleDiv.className = 'credential-domain';
    titleDiv.textContent = cred.title !== currentDomain ? cred.title : cred.domain;

    info.appendChild(usernameDiv);
    info.appendChild(titleDiv);

    const actions = document.createElement('div');
    actions.className = 'credential-actions';

    const copyUserBtn = document.createElement('button');
    copyUserBtn.className = 'btn-copy';
    copyUserBtn.textContent = 'User';
    copyUserBtn.title = 'Copy username';
    copyUserBtn.addEventListener('click', () => copyText(cred.username, 'Username copied'));

    const copyPassBtn = document.createElement('button');
    copyPassBtn.className = 'btn-copy';
    copyPassBtn.textContent = 'Pass';
    copyPassBtn.title = 'Copy password';
    copyPassBtn.addEventListener('click', () => fetchAndCopyPassword(cred.domain));

    actions.appendChild(copyUserBtn);
    actions.appendChild(copyPassBtn);
    item.appendChild(info);
    item.appendChild(actions);
    list.appendChild(item);
  }
}

// Fetch a credential's password at copy-time to avoid holding it in memory.
async function fetchAndCopyPassword(domain: string) {
  try {
    const response = await chrome.runtime.sendMessage({
      type: 'get_credential',
      domain,
      request_id: generateUUID(),
      page_url: currentTabUrl,
    });
    if (response?.success && response.data?.password) {
      await copyText(response.data.password, 'Password copied');
    } else {
      showNotification('Could not retrieve password', 'error');
    }
  } catch {
    showNotification('Failed to copy password', 'error');
  }
}

// ── Add credential form ───────────────────────────────────────────────────────

function showAddView() {
  hideAllViews();
  document.getElementById('addView')!.classList.remove('hidden');
  const urlInput = document.getElementById('addUrl') as HTMLInputElement;
  if (currentDomain) urlInput.value = `https://${currentDomain}`;
  (document.getElementById('addTitle') as HTMLInputElement).focus();
}

async function handleAddSubmit(e: Event) {
  e.preventDefault();

  const title = (document.getElementById('addTitle') as HTMLInputElement).value.trim();
  const username = (document.getElementById('addUsername') as HTMLInputElement).value.trim();
  const password = (document.getElementById('addPassword') as HTMLInputElement).value;
  const url = (document.getElementById('addUrl') as HTMLInputElement).value.trim();

  if (!title || !username || !password) {
    showNotification('Title, username, and password are required', 'error');
    return;
  }

  const saveBtn = document.getElementById('addSaveBtn') as HTMLButtonElement;
  saveBtn.disabled = true;
  saveBtn.textContent = 'Saving…';

  try {
    const response = await chrome.runtime.sendMessage({
      type: 'save_credential',
      data: {
        domain: currentDomain,
        username,
        password,
        title,
        url: url || (currentDomain ? `https://${currentDomain}` : ''),
      },
    });

    if (response?.success) {
      // WBS-706: warn when the saved credential's origin is plain HTTP.
      showNotification(
        response?.insecure_http
          ? 'Credential saved, but this site used unencrypted HTTP'
          : 'Credential saved'
      );
      (document.getElementById('addForm') as HTMLFormElement).reset();
      showUnlockedView();
      await loadCredentials();
    } else {
      showNotification(response?.error ?? 'Failed to save credential', 'error');
    }
  } catch {
    showNotification('Failed to save credential', 'error');
  } finally {
    saveBtn.disabled = false;
    saveBtn.textContent = 'Save';
  }
}

// ── Settings ──────────────────────────────────────────────────────────────────

function openSettings() {
  hideAllViews();
  document.getElementById('settingsView')!.classList.remove('hidden');

  // Populate dynamic fields
  const manifest = chrome.runtime.getManifest();
  const versionEl = document.getElementById('settingsVersion');
  if (versionEl) versionEl.textContent = `v${manifest.version}`;

  void refreshSiteAccess();
}

// ── WBS-712 site access ───────────────────────────────────────────────────────

// The browser permission pattern for the active tab (http/https only).
function currentOriginPattern(): string | null {
  if (!currentTabUrl) return null;
  try {
    const parsed = new URL(currentTabUrl);
    if (parsed.protocol !== 'http:' && parsed.protocol !== 'https:') return null;
    return `${parsed.origin}/*`;
  } catch {
    return null;
  }
}

async function hasBrowserOriginAccess(pattern: string): Promise<boolean> {
  return new Promise((resolve) => {
    chrome.permissions.contains({ origins: [pattern] }, (granted) => {
      if (chrome.runtime.lastError) {
        resolve(false);
        return;
      }
      resolve(granted === true);
    });
  });
}

async function requestBrowserOriginAccess(pattern: string, grant: boolean): Promise<boolean> {
  return new Promise((resolve) => {
    const done = (result: unknown) => {
      if (chrome.runtime.lastError) {
        showNotification(chrome.runtime.lastError.message, 'error');
        resolve(false);
        return;
      }
      resolve(result === true);
    };
    if (grant) {
      chrome.permissions.request({ origins: [pattern] }, (result) => done(result));
    } else {
      chrome.permissions.remove({ origins: [pattern] }, (result) => done(result));
    }
  });
}

function renderSiteGrants(
  grants: Array<{ host: string; allow_insecure: boolean }>
) {
  const container = document.getElementById('siteGrants')!;
  container.textContent = '';
  for (const grant of grants) {
    const row = document.createElement('div');
    row.className = 'site-grant';
    const label = document.createElement('span');
    label.textContent = grant.host;
    const revokeBtn = document.createElement('button');
    revokeBtn.className = 'btn btn-secondary';
    revokeBtn.textContent = 'Revoke';
    revokeBtn.addEventListener('click', () => void revokeGrant(grant.host));
    row.appendChild(label);
    row.appendChild(revokeBtn);
    container.appendChild(row);
  }
}

async function refreshSiteAccess() {
  const originEl = document.getElementById('siteAccessOrigin');
  const toggleBtn = document.getElementById('siteAccessToggle') as HTMLButtonElement | null;
  const httpBtn = document.getElementById('httpAllowBtn') as HTMLButtonElement | null;
  const pattern = currentOriginPattern();

  if (originEl) {
    originEl.textContent = pattern ? currentDomain || 'This site' : 'This site (no web page)';
  }

  // HTTP autofill grants stored daemon-side.
  try {
    const response = await chrome.runtime.sendMessage({ type: 'list_site_permissions' });
    renderSiteGrants(response?.permissions ?? []);
    if (httpBtn) {
      const grantedForSite =
        currentDomain &&
        (response?.permissions ?? []).some((p: { host: string }) => p.host === currentDomain);
      httpBtn.textContent = grantedForSite ? 'Revoke' : 'Allow';
    }
  } catch {
    renderSiteGrants([]);
  }

  if (!toggleBtn) return;
  if (!pattern) {
    toggleBtn.disabled = true;
    toggleBtn.textContent = 'N/A';
    return;
  }
  toggleBtn.disabled = false;
  const granted = await hasBrowserOriginAccess(pattern);
  toggleBtn.textContent = granted ? 'Remove access' : 'Enable';
}

async function toggleSiteAccess() {
  const pattern = currentOriginPattern();
  if (!pattern) return;
  const granted = await hasBrowserOriginAccess(pattern);
  // chrome.permissions.request needs a user gesture — the button click.
  const applied = await requestBrowserOriginAccess(pattern, !granted);
  if (applied) {
    showNotification(granted ? 'Site access removed' : 'Site access enabled');
    await refreshSiteAccess();
  }
}

async function allowHttpForSite() {
  if (!currentDomain) return;
  const httpBtn = document.getElementById('httpAllowBtn') as HTMLButtonElement | null;
  const isRevoke = httpBtn?.textContent === 'Revoke';
  const response = await chrome.runtime.sendMessage({
    type: isRevoke ? 'revoke_site_permission' : 'grant_site_permission',
    host: currentDomain,
    allow_insecure: true,
  });
  if (response?.success) {
    showNotification(isRevoke ? 'HTTP autofill disabled for this site' : 'HTTP autofill allowed for this site (not recommended)', isRevoke ? 'success' : 'error');
    await refreshSiteAccess();
  } else {
    showNotification(response?.error ?? 'Permission change failed', 'error');
  }
}

async function revokeGrant(host: string) {
  const response = await chrome.runtime.sendMessage({
    type: 'revoke_site_permission',
    host,
  });
  if (response?.success) {
    showNotification(`Permission revoked for ${host}`);
    await refreshSiteAccess();
  } else {
    showNotification(response?.error ?? 'Revoke failed', 'error');
  }
}

// ── Lock vault ────────────────────────────────────────────────────────────────

async function lockVault() {
  try {
    const response = await chrome.runtime.sendMessage({ type: 'lock_vault' });
    if (response?.success && response.unlocked === false) {
      showLockedView();
      showNotification('Vault locked');
    } else {
      showNotification(response?.error ?? 'Failed to lock vault', 'error');
    }
  } catch {
    showNotification('Failed to lock vault', 'error');
  }
}

// ── Clipboard ─────────────────────────────────────────────────────────────────

async function copyText(text: string, successMsg: string) {
  try {
    await navigator.clipboard.writeText(text);
    showNotification(successMsg);
    setTimeout(async () => {
      try { await navigator.clipboard.writeText(''); } catch { /* ignore */ }
    }, CLIPBOARD_CLEAR_TIMEOUT_MS);
  } catch {
    showNotification('Failed to copy', 'error');
  }
}

// ── View management ───────────────────────────────────────────────────────────

function showLockedView() {
  hideAllViews();
  document.getElementById('lockedView')!.classList.remove('hidden');
  updateVaultStatus(false);
}

function showUnlockedView() {
  hideAllViews();
  document.getElementById('unlockedView')!.classList.remove('hidden');
  updateVaultStatus(true);
}

function showLoading() {
  hideAllViews();
  document.getElementById('loadingView')!.classList.remove('hidden');
}

function hideAllViews() {
  document.querySelectorAll('.view').forEach(v => v.classList.add('hidden'));
}

function updateVaultStatus(unlocked: boolean) {
  const indicator = document.getElementById('vaultStatus')!;
  const dot = indicator.querySelector('.status-dot')!;
  const text = indicator.querySelector('.status-text')!;
  if (unlocked) {
    dot.classList.add('unlocked');
    dot.classList.remove('locked');
    text.textContent = 'Unlocked';
  } else {
    dot.classList.add('locked');
    dot.classList.remove('unlocked');
    text.textContent = 'Locked';
  }
}

// ── Notifications ─────────────────────────────────────────────────────────────

function showNotification(message: string, type: 'success' | 'error' | 'info' = 'success') {
  const n = document.createElement('div');
  n.className = `notification notification-${type}`;
  n.textContent = message;
  document.body.appendChild(n);
  setTimeout(() => n.classList.add('show'), 10);
  setTimeout(() => {
    n.classList.remove('show');
    setTimeout(() => n.remove(), 300);
  }, 3000);
}

// ── Utilities ─────────────────────────────────────────────────────────────────

function generateUUID(): string {
  return 'xxxxxxxx-xxxx-4xxx-yxxx-xxxxxxxxxxxx'.replace(/[xy]/g, c => {
    const r = (Math.random() * 16) | 0;
    return (c === 'x' ? r : (r & 0x3) | 0x8).toString(16);
  });
}
