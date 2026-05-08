/**
 * SentinelPass Desktop UI — main application module.
 *
 * This file drives the Tauri frontend and is responsible for:
 *
 * 1. **Lifecycle & initialisation** — Tauri API detection, DOM-ready
 *    bootstrapping, event-listener wiring, and periodic refresh timers.
 *
 * 2. **Vault lifecycle** — vault create/unlock/lock flows, biometric
 *    settings, daemon health monitoring, password generation, URL
 *    handling, and search/filter orchestration.
 *
 * Entry CRUD, TOTP management, and utility helpers have been extracted
 * into dedicated modules (`entries.ts`, `totp.ts`, `utils.ts`) with
 * shared state managed by `state.ts`.
 */
import { normalizeLaunchUrl } from './url-utils.js';
import { initTauriAPI, invoke, confirm, setCurrentEntry, setCurrentTotpMetadata, setCurrentFilter, vaultScreen, searchInput } from './state.js';
import { showToast, togglePasswordVisibility, copyToClipboard } from './utils.js';
import { setTotpButtonState, closeTotpModal, copyTotpForEntry, openTotpModal, saveTotpForEntry, removeTotpForEntry } from './totp.js';
import { loadEntries, createNewEntry, saveEntry, deleteEntry, refreshEntriesNow, backgroundRefreshEntries, applyEntryFilters, handleCredentialTypeChanged } from './entries.js';
// ──────────────────────────────────────────────────────────────────────────────
// Local State (not shared across modules)
// ──────────────────────────────────────────────────────────────────────────────
let isCreateVault = false;
let biometricStatus = null;
let daemonStatus = null;
// DOM Elements (welcome-screen-only, not needed by other modules)
const welcomeScreen = document.getElementById('welcome-screen');
const vaultActions = document.getElementById('vault-actions');
const passwordForm = document.getElementById('password-form');
const masterPasswordInput = document.getElementById('master-password');
const confirmPasswordInput = document.getElementById('confirm-password');
const confirmPasswordGroup = document.getElementById('confirm-password-group');
const formTitle = document.getElementById('form-title');
const submitPasswordBtn = document.getElementById('submit-password');
const strengthMeter = document.getElementById('strength-meter');
const strengthFill = document.getElementById('strength-fill');
const strengthText = document.getElementById('strength-text');
const daemonStatusIndicator = document.getElementById('daemon-status-indicator');
// ──────────────────────────────────────────────────────────────────────────────
// Lifecycle & Initialisation
// ──────────────────────────────────────────────────────────────────────────────
/**
 * Bootstrap the application after the Tauri API is available.
 *
 * Wires DOM event listeners, checks whether the vault is already unlocked,
 * refreshes biometric and daemon status, and starts periodic background
 * refresh timers (daemon health every 15 s, entries every 10 s).
 */
async function init() {
    setupEventListeners();
    await checkVaultUnlocked();
    await refreshBiometricStatus();
    await refreshDaemonStatus();
    setInterval(() => {
        void refreshDaemonStatus();
    }, 15000);
    setInterval(() => {
        void backgroundRefreshEntries();
    }, 10000);
    window.addEventListener('focus', () => {
        void backgroundRefreshEntries();
    });
    document.addEventListener('visibilitychange', () => {
        if (document.visibilityState === 'visible') {
            void backgroundRefreshEntries();
        }
    });
}
/**
 * Register all DOM event handlers for the welcome screen, vault screen,
 * entry detail pane, TOTP modal, filter buttons, and keyboard shortcuts.
 */
function setupEventListeners() {
    console.log('Setting up event listeners...');
    // Welcome Screen
    const createBtn = document.getElementById('create-vault-btn');
    const unlockBtn = document.getElementById('unlock-vault-btn');
    const unlockBiometricBtn = document.getElementById('unlock-biometric-btn');
    const settingsBtn = document.getElementById('settings-btn');
    console.log('Create vault button:', createBtn);
    console.log('Unlock vault button:', unlockBtn);
    if (createBtn) {
        createBtn.addEventListener('click', (e) => {
            console.log('Create vault button clicked!');
            showCreateVault();
        });
    }
    else {
        console.error('Create vault button not found!');
    }
    if (unlockBtn) {
        unlockBtn.addEventListener('click', (e) => {
            console.log('Unlock vault button clicked!');
            showUnlockVault();
        });
    }
    if (unlockBiometricBtn) {
        unlockBiometricBtn.addEventListener('click', unlockVaultWithBiometric);
    }
    document.getElementById('cancel-password').addEventListener('click', () => hidePasswordForm());
    passwordForm.addEventListener('submit', handlePasswordSubmit);
    masterPasswordInput.addEventListener('input', handlePasswordInput);
    // Vault Screen
    document.getElementById('lock-btn').addEventListener('click', lockVault);
    document.getElementById('add-entry-btn').addEventListener('click', createNewEntry);
    document.getElementById('refresh-entries-btn').addEventListener('click', refreshEntriesNow);
    document.getElementById('open-url-btn').addEventListener('click', openEntryUrl);
    if (settingsBtn) {
        settingsBtn.addEventListener('click', handleSettings);
    }
    searchInput.addEventListener('input', handleSearch);
    document.getElementById('detail-url').addEventListener('input', updateUrlOpenButtonState);
    document.getElementById('detail-credential-type')?.addEventListener('change', handleCredentialTypeChanged);
    // Filter buttons
    document.querySelectorAll('.filter-btn').forEach(btn => {
        btn.addEventListener('click', (e) => handleFilter(e.target.dataset.filter));
    });
    // Entry Detail
    document.getElementById('save-entry').addEventListener('click', saveEntry);
    document.getElementById('delete-entry').addEventListener('click', deleteEntry);
    document.getElementById('detail-favorite').addEventListener('click', toggleFavorite);
    document.getElementById('toggle-detail-password').addEventListener('click', () => togglePasswordVisibility('detail-password'));
    document.getElementById('generate-password-btn').addEventListener('click', generatePasswordForEntry);
    document.getElementById('copy-username').addEventListener('click', () => copyToClipboard(document.getElementById('detail-username').value, 'Username'));
    document.getElementById('copy-password').addEventListener('click', () => copyToClipboard(document.getElementById('detail-password').value, getDetailSecretLabel()));
    document.getElementById('copy-totp').addEventListener('click', copyTotpForEntry);
    document.getElementById('configure-totp').addEventListener('click', openTotpModal);
    document.getElementById('remove-totp').addEventListener('click', removeTotpForEntry);
    document.getElementById('totp-form').addEventListener('submit', saveTotpForEntry);
    document.getElementById('cancel-totp').addEventListener('click', closeTotpModal);
    const totpModal = document.getElementById('totp-modal');
    if (totpModal) {
        totpModal.addEventListener('click', (event) => {
            if (event.target === totpModal) {
                closeTotpModal();
            }
        });
    }
    // Browser Extensions modal
    const extensionsBtn = document.getElementById('extensions-btn');
    if (extensionsBtn) {
        extensionsBtn.addEventListener('click', openExtensionModal);
    }
    document.getElementById('close-extension-modal')?.addEventListener('click', closeExtensionModal);
    document.getElementById('reregister-native-host')?.addEventListener('click', reregisterNativeHost);
    document.getElementById('open-chrome-extensions')?.addEventListener('click', () => openBrowserExtensionsPage('chrome'));
    document.getElementById('open-firefox-extensions')?.addEventListener('click', () => openBrowserExtensionsPage('firefox'));
    const extensionModal = document.getElementById('extension-modal');
    if (extensionModal) {
        extensionModal.addEventListener('click', (event) => {
            if (event.target === extensionModal)
                closeExtensionModal();
        });
    }
    // Toggle password visibility in welcome screen
    document.getElementById('toggle-password').addEventListener('click', () => togglePasswordVisibility('master-password'));
    updateUrlOpenButtonState();
}
/**
 * Check whether the vault is already unlocked (e.g. from a previous session)
 * and, if so, transition directly to the vault screen.
 */
async function checkVaultUnlocked() {
    try {
        const unlocked = await invoke('is_unlocked');
        if (unlocked) {
            showVaultScreen();
            loadEntries();
        }
    }
    catch (error) {
        console.error('Error checking vault status:', error);
    }
}
// ──────────────────────────────────────────────────────────────────────────────
// Biometric & Daemon Status
// ──────────────────────────────────────────────────────────────────────────────
/**
 * Query the backend for biometric availability, enrollment, and configuration,
 * then update the biometric unlock button accordingly.
 *
 * @returns The biometric status object, or `null` on error.
 */
async function refreshBiometricStatus() {
    try {
        biometricStatus = await invoke('biometric_status');
    }
    catch (error) {
        console.error('Error checking biometric status:', error);
        biometricStatus = null;
    }
    updateBiometricButton();
    return biometricStatus;
}
/**
 * Query the backend for the browser-integration daemon's health and update the
 * status banner.
 *
 * @returns The daemon status object (`{ available, unlocked, message }`).
 */
async function refreshDaemonStatus() {
    try {
        daemonStatus = await invoke('daemon_status');
    }
    catch (error) {
        daemonStatus = {
            available: false,
            unlocked: false,
            message: String(error)
        };
    }
    updateDaemonStatusBanner();
    return daemonStatus;
}
/**
 * Show or hide the daemon-status banner based on the current `daemonStatus`.
 *
 * Hidden when the daemon is available and unlocked; shows a warning when the
 * daemon vault is locked, or an error when the daemon is unreachable.
 */
function updateDaemonStatusBanner() {
    if (!daemonStatusIndicator)
        return;
    if (!daemonStatus || (daemonStatus.available && daemonStatus.unlocked)) {
        daemonStatusIndicator.classList.add('hidden');
        daemonStatusIndicator.textContent = '';
        daemonStatusIndicator.classList.remove('warning', 'error');
        return;
    }
    let message = '';
    let type = 'warning';
    if (!daemonStatus.available) {
        type = 'error';
        message = daemonStatus.message
            ? `Browser integration daemon is unavailable (${daemonStatus.message}). SentinelPass will retry automatically.`
            : 'Browser integration daemon is unavailable. SentinelPass will retry automatically.';
    }
    else {
        message = 'Daemon is running but vault is locked. Unlock SentinelPass to re-enable browser autofill and save.';
    }
    daemonStatusIndicator.textContent = message;
    daemonStatusIndicator.classList.remove('hidden');
    daemonStatusIndicator.classList.remove('warning', 'error');
    daemonStatusIndicator.classList.add(type);
}
/**
 * Update the biometric unlock button's visibility and label based on the
 * current `biometricStatus` (available, enrolled, configured).
 */
function updateBiometricButton() {
    const button = document.getElementById('unlock-biometric-btn');
    const label = document.getElementById('unlock-biometric-label');
    if (!button || !label)
        return;
    const methodName = biometricStatus?.method_name ||
        biometricStatus?.methodName ||
        'Biometric';
    label.textContent = `Unlock with ${methodName}`;
    const canUseBiometricUnlock = Boolean(biometricStatus?.available &&
        biometricStatus?.enrolled &&
        biometricStatus?.configured);
    button.classList.toggle('hidden', !canUseBiometricUnlock);
}
// ──────────────────────────────────────────────────────────────────────────────
// Vault Creation / Unlock / Lock
// ──────────────────────────────────────────────────────────────────────────────
/** Switch the welcome screen to the "create new vault" password form. */
function showCreateVault() {
    isCreateVault = true;
    vaultActions.classList.add('hidden');
    passwordForm.classList.remove('hidden');
    confirmPasswordGroup.classList.remove('hidden');
    formTitle.textContent = 'Create New Vault';
    submitPasswordBtn.textContent = 'Create Vault';
    masterPasswordInput.focus();
}
/** Switch the welcome screen to the "unlock existing vault" password form. */
function showUnlockVault() {
    isCreateVault = false;
    vaultActions.classList.add('hidden');
    passwordForm.classList.remove('hidden');
    confirmPasswordGroup.classList.add('hidden');
    formTitle.textContent = 'Unlock Vault';
    submitPasswordBtn.textContent = 'Unlock';
    masterPasswordInput.focus();
}
/** Hide the password form, clear its inputs, and restore the welcome actions. */
function hidePasswordForm() {
    passwordForm.classList.add('hidden');
    confirmPasswordGroup.classList.add('hidden');
    vaultActions.classList.remove('hidden');
    masterPasswordInput.value = '';
    confirmPasswordInput.value = '';
    strengthMeter.classList.add('hidden');
}
/**
 * Handle keystrokes in the master-password input by running real-time
 * password-strength analysis via the backend.
 *
 * @param e - The `input` event from the password field.
 */
async function handlePasswordInput(e) {
    const password = e.target.value;
    if (password.length > 0) {
        strengthMeter.classList.remove('hidden');
        const analysis = await invoke('check_password_strength', { password });
        updateStrengthMeter(analysis);
    }
    else {
        strengthMeter.classList.add('hidden');
    }
}
/**
 * Render the password-strength meter bar and label from an analysis result.
 *
 * @param analysis - Backend strength result with `strength`, `score`,
 *   `entropy_bits`, and `crack_time_human` fields.
 */
function updateStrengthMeter(analysis) {
    const { strength, score, entropy_bits, crack_time_human } = analysis;
    strengthFill.style.width = `${(score / 5) * 100}%`;
    // Color based on strength
    const colors = {
        'Very Weak': '#ef4444',
        'Weak': '#f59e0b',
        'Fair': '#f59e0b',
        'Strong': '#10b981',
        'Very Strong': '#059669'
    };
    strengthFill.style.backgroundColor = colors[strength] || '#6366f1';
    strengthText.textContent = `${strength} (${entropy_bits.toFixed(1)} bits) - ${crack_time_human}`;
}
/**
 * Handle the password-form submit for both vault creation and unlock flows.
 *
 * On creation, validates that both password fields match before invoking
 * `create_vault`. On unlock, invokes `unlock_vault` and transitions to the
 * vault screen on success.
 *
 * @param e - The form `submit` event (default is prevented).
 */
async function handlePasswordSubmit(e) {
    e.preventDefault();
    const password = masterPasswordInput.value;
    console.log('[SentinelPass UI] handlePasswordSubmit called', { isCreateVault });
    if (isCreateVault) {
        const confirmPassword = confirmPasswordInput.value;
        if (password !== confirmPassword) {
            showToast('Passwords do not match', 'error');
            return;
        }
        try {
            await invoke('create_vault', { masterPassword: password });
            showToast('Vault created successfully!', 'success');
            showVaultScreen();
            await refreshBiometricStatus();
            await refreshDaemonStatus();
        }
        catch (error) {
            showToast(error, 'error');
        }
    }
    else {
        try {
            console.log('[SentinelPass UI] Attempting unlock_vault invoke...');
            const unlockMessage = await invoke('unlock_vault', { masterPassword: password });
            console.log('[SentinelPass UI] unlock_vault response:', unlockMessage);
            const unlockType = typeof unlockMessage === 'string' && unlockMessage.includes('daemon unlock failed')
                ? 'warning'
                : 'success';
            showToast(unlockMessage || 'Vault unlocked successfully!', unlockType);
            showVaultScreen();
            loadEntries();
            await refreshBiometricStatus();
            const status = await refreshDaemonStatus();
            console.log('[SentinelPass UI] daemon_status after unlock:', status);
        }
        catch (error) {
            console.error('[SentinelPass UI] unlock_vault error:', error);
            showToast(error, 'error');
        }
    }
}
/**
 * Unlock the vault using platform biometric authentication (Touch ID /
 * Windows Hello) and transition to the vault screen on success.
 */
async function unlockVaultWithBiometric() {
    try {
        console.log('[SentinelPass UI] Attempting unlock_vault_biometric invoke...');
        const unlockMessage = await invoke('unlock_vault_biometric');
        console.log('[SentinelPass UI] unlock_vault_biometric response:', unlockMessage);
        const unlockType = typeof unlockMessage === 'string' && unlockMessage.includes('daemon biometric unlock failed')
            ? 'warning'
            : 'success';
        showToast(unlockMessage || 'Vault unlocked with biometric authentication!', unlockType);
        showVaultScreen();
        loadEntries();
        await refreshBiometricStatus();
        const status = await refreshDaemonStatus();
        console.log('[SentinelPass UI] daemon_status after biometric unlock:', status);
    }
    catch (error) {
        console.error('[SentinelPass UI] unlock_vault_biometric error:', error);
        showToast(error, 'error');
    }
}
/**
 * Open the biometric settings flow.
 *
 * Checks availability and enrollment, then either offers to disable (if
 * already configured) or enable biometric unlock.  Enabling requires the
 * user to re-enter their master password via a secure modal.
 */
async function handleSettings() {
    const status = await refreshBiometricStatus();
    if (!status) {
        showToast('Unable to load biometric settings', 'error');
        return;
    }
    const methodName = status.method_name || status.methodName || 'Biometric';
    if (!status.available) {
        showToast(`${methodName} is not available on this device`, 'warning');
        return;
    }
    if (!status.enrolled) {
        showToast(`${methodName} is not enrolled on this device`, 'warning');
        return;
    }
    if (status.configured) {
        const shouldDisable = await confirm(`Disable ${methodName} unlock for this vault?`, {
            title: 'Biometric Settings',
            kind: 'warning'
        });
        if (!shouldDisable)
            return;
        try {
            await invoke('disable_biometric_unlock');
            showToast(`${methodName} unlock disabled`, 'success');
            await refreshBiometricStatus();
        }
        catch (error) {
            showToast(error, 'error');
        }
        return;
    }
    const shouldEnable = await confirm(`Enable ${methodName} unlock for this vault? You will verify your identity during setup.`, {
        title: 'Biometric Settings',
        kind: 'info'
    });
    if (!shouldEnable)
        return;
    let masterPassword = await requestMasterPasswordForBiometric(methodName);
    if (masterPassword === null) {
        return;
    }
    try {
        await invoke('enable_biometric_unlock', { masterPassword });
        showToast(`${methodName} unlock enabled`, 'success');
        await refreshBiometricStatus();
    }
    catch (error) {
        showToast(error, 'error');
    }
    finally {
        masterPassword = '';
    }
}
/**
 * Lock the vault, clear all in-memory state (entries, TOTP metadata),
 * return to the welcome screen, and refresh biometric/daemon status.
 */
async function lockVault() {
    try {
        await invoke('lock_vault');
        hidePasswordForm();
        welcomeScreen.classList.remove('hidden');
        vaultScreen.classList.add('hidden');
        setCurrentEntry(null);
        setCurrentTotpMetadata(null);
        setTotpButtonState(false, false);
        closeTotpModal();
        await refreshBiometricStatus();
        await refreshDaemonStatus();
        showToast('Vault locked', 'success');
    }
    catch (error) {
        showToast(error, 'error');
    }
}
/** Hide the welcome screen and show the main vault screen. */
function showVaultScreen() {
    welcomeScreen.classList.add('hidden');
    vaultScreen.classList.remove('hidden');
    hidePasswordForm();
}
// ──────────────────────────────────────────────────────────────────────────────
// Search & Filter
// ──────────────────────────────────────────────────────────────────────────────
/**
 * Handle input events on the search field by re-applying entry filters.
 *
 * @param e - The `input` event from the search field.
 */
function handleSearch(e) {
    applyEntryFilters();
}
/**
 * Switch the active entry filter and refresh the displayed list.
 *
 * @param filter - The filter key (`"all"` or `"favorites"`).
 */
function handleFilter(filter) {
    setCurrentFilter(filter);
    // Update active button
    document.querySelectorAll('.filter-btn').forEach(btn => {
        btn.classList.toggle('active', btn.dataset.filter === filter);
    });
    if (filter === 'all') {
        applyEntryFilters();
    }
    else if (filter === 'favorites') {
        applyEntryFilters();
    }
}
// ──────────────────────────────────────────────────────────────────────────────
// Password Generation
// ──────────────────────────────────────────────────────────────────────────────
/**
 * Generate a strong random password via the backend and fill it into the
 * detail-pane password field.
 */
async function generatePasswordForEntry() {
    try {
        const password = await invoke('generate_password', {
            length: 16,
            includeSymbols: true
        });
        document.getElementById('detail-password').value = password;
        showToast(`${getDetailSecretLabel()} generated!`, 'success');
    }
    catch (error) {
        showToast(error, 'error');
    }
}
function getDetailSecretLabel() {
    const typeSelect = document.getElementById('detail-credential-type');
    return typeSelect?.value === 'api_key' ? 'API key' : 'Password';
}
// ──────────────────────────────────────────────────────────────────────────────
// URL Handling
// ──────────────────────────────────────────────────────────────────────────────
/**
 * Enable or disable the "open URL" button based on whether the URL input
 * contains a non-empty value.
 */
function updateUrlOpenButtonState() {
    const urlInput = document.getElementById('detail-url');
    const openButton = document.getElementById('open-url-btn');
    if (!urlInput || !openButton) {
        return;
    }
    const hasValue = urlInput.value.trim().length > 0;
    openButton.disabled = !hasValue;
    openButton.title = hasValue
        ? 'Open URL in default browser'
        : 'Enter URL to open';
}
/**
 * Normalise the current entry's URL and open it in the user's default
 * system browser via the Tauri shell plugin.
 */
async function openEntryUrl() {
    const urlInput = document.getElementById('detail-url');
    if (!urlInput) {
        showToast('URL field unavailable', 'error');
        return;
    }
    const rawUrl = urlInput.value;
    if (!rawUrl.trim()) {
        showToast('Enter a URL first', 'warning');
        urlInput.focus();
        return;
    }
    try {
        const normalized = normalizeLaunchUrl(rawUrl);
        await invoke('open_entry_url', { url: normalized });
        showToast('Opened in default browser', 'success');
    }
    catch (error) {
        const message = error?.message || String(error);
        showToast(message, 'error');
    }
}
/** Toggle the favourite CSS class on the detail-pane favourite button. */
function toggleFavorite() {
    document.getElementById('detail-favorite').classList.toggle('active');
}
// ──────────────────────────────────────────────────────────────────────────────
// Browser Extensions Modal
// ──────────────────────────────────────────────────────────────────────────────
/** Open the browser extensions modal and check native host status. */
async function openExtensionModal() {
    const modal = document.getElementById('extension-modal');
    if (!modal)
        return;
    modal.classList.remove('hidden');
    modal.setAttribute('aria-hidden', 'false');
    // Check native host status
    const dot = document.getElementById('native-host-dot');
    const statusText = document.getElementById('native-host-status');
    if (dot && statusText) {
        try {
            await invoke('register_native_host');
            dot.classList.remove('error');
            dot.classList.add('success');
            statusText.textContent = 'Registered';
        }
        catch {
            dot.classList.remove('success');
            dot.classList.add('error');
            statusText.textContent = 'Not registered';
        }
    }
}
/** Close the browser extensions modal. */
function closeExtensionModal() {
    const modal = document.getElementById('extension-modal');
    if (!modal)
        return;
    modal.classList.add('hidden');
    modal.setAttribute('aria-hidden', 'true');
}
/** Re-register native messaging host manifests and update the status indicator. */
async function reregisterNativeHost() {
    try {
        await invoke('register_native_host');
        const dot = document.getElementById('native-host-dot');
        const statusText = document.getElementById('native-host-status');
        if (dot) {
            dot.classList.remove('error');
            dot.classList.add('success');
        }
        if (statusText) {
            statusText.textContent = 'Registered';
        }
        showToast('Native host re-registered successfully', 'success');
    }
    catch (error) {
        const dot = document.getElementById('native-host-dot');
        const statusText = document.getElementById('native-host-status');
        if (dot) {
            dot.classList.remove('success');
            dot.classList.add('error');
        }
        if (statusText) {
            statusText.textContent = 'Registration failed';
        }
        showToast(error, 'error');
    }
}
/** Open the browser's extensions management page. */
async function openBrowserExtensionsPage(browser) {
    try {
        await invoke('open_browser_extensions_page', { browser });
        showToast(`Opened ${browser} extensions page`, 'success');
    }
    catch (error) {
        showToast(error, 'error');
    }
}
// ──────────────────────────────────────────────────────────────────────────────
// Biometric Password Prompt
// ──────────────────────────────────────────────────────────────────────────────
/**
 * Show a secure modal prompting the user to re-enter their master password
 * (required for enabling or disabling biometric unlock).
 *
 * Returns a promise that resolves with the entered password, or `null` if
 * the user cancels (via button, overlay click, or Escape key).
 *
 * @param methodName - The biometric method name to display (e.g. "Touch ID").
 * @returns The master password string, or `null` if cancelled.
 */
async function requestMasterPasswordForBiometric(methodName) {
    const modal = document.getElementById('secure-password-modal');
    const title = document.getElementById('secure-password-title');
    const description = document.getElementById('secure-password-description');
    const form = document.getElementById('secure-password-form');
    const input = document.getElementById('secure-master-password');
    const cancelButton = document.getElementById('cancel-secure-password');
    const toggleButton = document.getElementById('toggle-secure-master-password');
    if (!modal || !title || !description || !form || !input || !cancelButton || !toggleButton) {
        showToast('Secure password prompt is unavailable', 'error');
        return null;
    }
    title.textContent = `Enable ${methodName} Unlock`;
    description.textContent = `Enter your master password to enable ${methodName} unlock for this vault.`;
    input.value = '';
    input.type = 'password';
    modal.classList.remove('hidden');
    modal.setAttribute('aria-hidden', 'false');
    await new Promise(resolve => setTimeout(resolve, 0));
    input.focus();
    return new Promise(resolve => {
        let finished = false;
        const cleanup = () => {
            form.removeEventListener('submit', onSubmit);
            cancelButton.removeEventListener('click', onCancel);
            toggleButton.removeEventListener('click', onToggleVisibility);
            modal.removeEventListener('click', onOverlayClick);
            document.removeEventListener('keydown', onEscape);
            input.value = '';
            input.type = 'password';
            modal.classList.add('hidden');
            modal.setAttribute('aria-hidden', 'true');
        };
        const finish = value => {
            if (finished)
                return;
            finished = true;
            cleanup();
            resolve(value);
        };
        const onSubmit = event => {
            event.preventDefault();
            const value = input.value;
            if (!value) {
                showToast('Master password is required', 'warning');
                input.focus();
                return;
            }
            finish(value);
        };
        const onCancel = () => finish(null);
        const onToggleVisibility = () => togglePasswordVisibility('secure-master-password');
        const onOverlayClick = event => {
            if (event.target === modal) {
                finish(null);
            }
        };
        const onEscape = event => {
            if (event.key === 'Escape') {
                event.preventDefault();
                finish(null);
            }
        };
        form.addEventListener('submit', onSubmit);
        cancelButton.addEventListener('click', onCancel);
        toggleButton.addEventListener('click', onToggleVisibility);
        modal.addEventListener('click', onOverlayClick);
        document.addEventListener('keydown', onEscape);
    });
}
// ──────────────────────────────────────────────────────────────────────────────
// Entry Point
// ──────────────────────────────────────────────────────────────────────────────
// Initialize on load - wait for DOM and Tauri
if (document.readyState === 'loading') {
    document.addEventListener('DOMContentLoaded', initializeApp);
}
else {
    initializeApp();
}
/**
 * Application entry point invoked after the DOM is ready.
 *
 * Binds the Tauri API and, if available, kicks off the main {@link init}
 * sequence.
 */
function initializeApp() {
    // Wait for Tauri to be available
    if (!initTauriAPI()) {
        console.error('Tauri API not available');
        return;
    }
    console.log('Tauri API loaded, initializing app...');
    init();
}
