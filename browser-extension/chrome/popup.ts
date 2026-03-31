// Popup script for Password Manager extension

let currentDomain = '';
const UNAVAILABLE_FEATURE_MESSAGE = 'This feature is not available in the current preview build.';
const CLIPBOARD_CLEAR_TIMEOUT_MS = 10000;

// Store credentials in memory only — never expose in DOM attributes
const credentialStore = new Map<string, { username: string; password: string }>();
let credentialIdCounter = 0;

document.addEventListener('DOMContentLoaded', async () => {
  // Get current tab
  const [tab] = await chrome.tabs.query({ active: true, currentWindow: true });
  currentDomain = new URL(tab.url).hostname;

  // Initialize popup
  setupEventListeners();
  applyUnavailableFeatureState();
  checkVaultStatus();
});

function setupEventListeners() {
  document.getElementById('lockBtn').addEventListener('click', lockVault);
  document.getElementById('settingsBtn').addEventListener('click', openSettings);
}

function applyUnavailableFeatureState() {
  const searchInput = document.getElementById('searchInput');
  if (searchInput) {
    searchInput.disabled = true;
    searchInput.title = UNAVAILABLE_FEATURE_MESSAGE;
    searchInput.classList.add('feature-disabled');
  }

  const addButton = document.getElementById('addCredentialBtn');
  if (addButton) {
    addButton.disabled = true;
    addButton.title = UNAVAILABLE_FEATURE_MESSAGE;
    addButton.classList.add('feature-disabled');
  }
}

async function checkVaultStatus() {
  showLoading();

  try {
    const response = await chrome.runtime.sendMessage({
      type: 'check_vault_status'
    });

    if (response.unlocked) {
      showUnlockedView();
      loadCredentials();
    } else {
      showLockedView();
    }
  } catch (error) {
    console.error('Failed to check vault status:', error);
    showLockedView();
  }
}

async function loadCredentials() {
  try {
    const response = await chrome.runtime.sendMessage({
      type: 'get_credential',
      domain: currentDomain,
      request_id: generateUUID()
    });

    const credentialsList = document.getElementById('credentialsList');
    credentialsList.textContent = '';

    if (response.success && response.data) {
      // Store credentials in memory — never expose in DOM
      const credId = 'cred-' + (++credentialIdCounter);
      credentialStore.set(credId, {
        username: response.data.username,
        password: response.data.password
      });

      const item = document.createElement('div');
      item.className = 'credential-item';

      const info = document.createElement('div');
      info.className = 'credential-info';

      const usernameDiv = document.createElement('div');
      usernameDiv.className = 'credential-username';
      usernameDiv.textContent = response.data.username;

      const domainDiv = document.createElement('div');
      domainDiv.className = 'credential-domain';
      domainDiv.textContent = currentDomain;

      info.appendChild(usernameDiv);
      info.appendChild(domainDiv);

      const copyBtn = document.createElement('button');
      copyBtn.className = 'btn-copy';
      copyBtn.textContent = 'Copy';
      copyBtn.dataset.credId = credId;
      copyBtn.addEventListener('click', () => {
        const cred = credentialStore.get(credId);
        if (cred) {
          copyToClipboard(cred.username, cred.password);
        }
      });

      item.appendChild(info);
      item.appendChild(copyBtn);
      credentialsList.appendChild(item);
    } else {
      const emptyState = document.createElement('div');
      emptyState.className = 'empty-state';

      const p = document.createElement('p');
      p.textContent = 'No credentials found for ';
      const strong = document.createElement('strong');
      strong.textContent = currentDomain;
      p.appendChild(strong);

      const addBtn = document.createElement('button');
      addBtn.id = 'addCredentialBtn';
      addBtn.className = 'btn btn-primary feature-disabled';
      addBtn.disabled = true;
      addBtn.title = UNAVAILABLE_FEATURE_MESSAGE;
      addBtn.textContent = 'Add Credential (Coming Soon)';

      emptyState.appendChild(p);
      emptyState.appendChild(addBtn);
      credentialsList.appendChild(emptyState);
    }
  } catch (error) {
    console.error('Failed to load credentials:', error);
    const credentialsList = document.getElementById('credentialsList');
    credentialsList.textContent = '';
    const errorDiv = document.createElement('div');
    errorDiv.className = 'error-state';
    const p = document.createElement('p');
    p.textContent = 'Failed to load credentials';
    errorDiv.appendChild(p);
    credentialsList.appendChild(errorDiv);
  }
}

function showLockedView() {
  hideAllViews();
  document.getElementById('lockedView').classList.remove('hidden');
  updateVaultStatus(false);
}

function showUnlockedView() {
  hideAllViews();
  document.getElementById('unlockedView').classList.remove('hidden');
  updateVaultStatus(true);
}

function showLoading() {
  hideAllViews();
  document.getElementById('loadingView').classList.remove('hidden');
}

function hideAllViews() {
  document.querySelectorAll('.view').forEach(view => {
    view.classList.add('hidden');
  });
}

function updateVaultStatus(unlocked) {
  const statusIndicator = document.getElementById('vaultStatus');
  const dot = statusIndicator.querySelector('.status-dot');
  const text = statusIndicator.querySelector('.status-text');

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

async function lockVault() {
  try {
    const response = await chrome.runtime.sendMessage({
      type: 'lock_vault'
    });

    if (response && response.success && response.unlocked === false) {
      showLockedView();
      showNotification('Vault locked');
    } else {
      showNotification(response?.error || 'Failed to lock vault', 'error');
    }
  } catch (error) {
    console.error('Failed to lock vault:', error);
    showNotification('Failed to lock vault', 'error');
  }
}

function openSettings() {
  showNotification(UNAVAILABLE_FEATURE_MESSAGE, 'info');
}

async function copyToClipboard(username, password) {
  try {
    await navigator.clipboard.writeText(password);
    showNotification('Password copied to clipboard');

    // Auto-clear clipboard after timeout
    setTimeout(async () => {
      try {
        await navigator.clipboard.writeText('');
      } catch {
        // Clipboard write may fail if focus changed
      }
    }, CLIPBOARD_CLEAR_TIMEOUT_MS);
  } catch (error) {
    console.error('Failed to copy:', error);
    showNotification('Failed to copy password', 'error');
  }
}

function showNotification(message, type = 'success') {
  const notification = document.createElement('div');
  notification.className = `notification notification-${type}`;
  notification.textContent = message;
  document.body.appendChild(notification);

  setTimeout(() => {
    notification.classList.add('show');
  }, 10);

  setTimeout(() => {
    notification.classList.remove('show');
    setTimeout(() => notification.remove(), 300);
  }, 3000);
}

function generateUUID() {
  return 'xxxxxxxx-xxxx-4xxx-yxxx-xxxxxxxxxxxx'.replace(/[xy]/g, function(c) {
    const r = Math.random() * 16 | 0;
    const v = c === 'x' ? r : (r & 0x3 | 0x8);
    return v.toString(16);
  });
}
