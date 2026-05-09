// Popup script for SentinelPass extension

const CLIPBOARD_CLEAR_TIMEOUT_MS = 10_000;

interface CredentialItem {
  username: string;
  title: string;
  domain: string;
}

let currentDomain = '';
let allCredentials: CredentialItem[] = [];

document.addEventListener('DOMContentLoaded', async () => {
  const [tab] = await chrome.tabs.query({ active: true, currentWindow: true });
  try {
    currentDomain = tab.url ? new URL(tab.url).hostname : '';
  } catch {
    currentDomain = '';
  }

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
      showNotification('Credential saved');
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
