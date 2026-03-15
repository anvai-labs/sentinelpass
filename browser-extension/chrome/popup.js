// Popup script for Password Manager extension
let currentDomain = '';
const UNAVAILABLE_FEATURE_MESSAGE = 'This feature is not available in the current preview build.';
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

        // Check if native messaging is not available
        if (response && response.error) {
            showNativeMessagingNotAvailable();
            return;
        }

        if (response.unlocked) {
            showUnlockedView();
            loadCredentials();
        }
        else {
            showLockedView();
        }
    }
    catch (error) {
        console.error('Failed to check vault status:', error);
        showNativeMessagingNotAvailable();
    }
}

function showNativeMessagingNotAvailable() {
    hideAllViews();
    const credentialsList = document.getElementById('credentialsList');
    const lockedView = document.getElementById('lockedView');

    // Update vault status to show error
    const statusElement = document.getElementById('vaultStatus');
    statusElement.querySelector('.status-text').textContent = 'Native Host Not Found';
    statusElement.classList.add('status-error');

    // Show locked view with error message
    lockedView.classList.remove('hidden');
    const lockedMessage = lockedView.querySelector('.locked-message');
    lockedMessage.innerHTML = `
        <svg width="64" height="64" viewBox="0 0 24 24" fill="currentColor" style="color: #dc2626;">
          <path d="M12 2C6.48 2 2 6.48 2 12s4.48 10 10 10 10-4.48 10-10S17.52 2 12 2zm1 15h-2v-2h2v2zm0-4h-2V7h2v6z"/>
        </svg>
        <p style="color: #dc2626; font-weight: 600;">Native Host Not Found</p>
        <p class="hint">SentinelPass requires the desktop application to be installed.</p>
        <div style="margin-top: 16px; text-align: left; max-width: 320px;">
          <p style="font-size: 13px; margin-bottom: 8px;"><strong>Installation Steps:</strong></p>
          <ol style="font-size: 13px; padding-left: 20px; line-height: 1.5;">
            <li>Download the desktop application from <a href="https://github.com/vjsingh1984/sentinelpass/releases" target="_blank" style="color: #2563eb;">GitHub Releases</a></li>
            <li>Install and run the application</li>
            <li>Initialize your vault: <code style="background: #f3f4f6; padding: 2px 6px; border-radius: 4px;">sentinelpass init</code></li>
            <li>Reload this extension</li>
          </ol>
        </div>
        <button id="openInstallationGuide" style="margin-top: 12px; font-size: 13px; padding: 8px 16px;">View Full Installation Guide</button>
      `;

    // Add event listener for installation guide button
    const guideBtn = document.getElementById('openInstallationGuide');
    if (guideBtn) {
        guideBtn.addEventListener('click', () => {
            chrome.tabs.create({ url: 'https://github.com/vjsingh1984/sentinelpass/blob/main/browser-extension/chrome/INSTALLATION.md' });
        });
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
        if (response.success && response.data) {
            credentialsList.innerHTML = `
        <div class="credential-item">
          <div class="credential-info">
            <div class="credential-username">${escapeHtml(response.data.username)}</div>
            <div class="credential-domain">${escapeHtml(currentDomain)}</div>
          </div>
          <button class="btn-copy" data-username="${escapeHtml(response.data.username)}" data-password="${escapeHtml(response.data.password)}">
            Copy
          </button>
        </div>
      `;
            // Add copy button listeners
            credentialsList.querySelector('.btn-copy').addEventListener('click', (e) => {
                const username = e.target.dataset.username;
                const password = e.target.dataset.password;
                copyToClipboard(username, password);
            });
        }
        else {
            credentialsList.innerHTML = `
        <div class="empty-state">
          <p>No credentials found for <strong>${escapeHtml(currentDomain)}</strong></p>
          <button id="addCredentialBtn" class="btn btn-primary feature-disabled" disabled title="${escapeHtml(UNAVAILABLE_FEATURE_MESSAGE)}">Add Credential (Coming Soon)</button>
        </div>
      `;
        }
    }
    catch (error) {
        console.error('Failed to load credentials:', error);
        document.getElementById('credentialsList').innerHTML = `
      <div class="error-state">
        <p>Failed to load credentials</p>
      </div>
    `;
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
    }
    else {
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
        }
        else {
            showNotification(response?.error || 'Failed to lock vault', 'error');
        }
    }
    catch (error) {
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
        // Auto-clear after 30 seconds
        setTimeout(async () => {
            try {
                const current = await navigator.clipboard.readText();
                if (current === password) {
                    await navigator.clipboard.writeText('');
                }
            }
            catch (e) {
                // Clipboard read may fail if focus changed
            }
        }, 30000);
    }
    catch (error) {
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
function escapeHtml(text) {
    const div = document.createElement('div');
    div.textContent = text;
    return div.innerHTML;
}
function generateUUID() {
    return 'xxxxxxxx-xxxx-4xxx-yxxx-xxxxxxxxxxxx'.replace(/[xy]/g, function (c) {
        const r = Math.random() * 16 | 0;
        const v = c === 'x' ? r : (r & 0x3 | 0x8);
        return v.toString(16);
    });
}
