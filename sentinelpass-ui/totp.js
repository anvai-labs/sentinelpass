/**
 * SentinelPass Desktop UI — TOTP management.
 *
 * Handles TOTP configuration, code copying, and removal for vault entries.
 * All backend calls go through the Tauri `invoke` bridge.
 */
import { invoke, confirm, currentEntry, currentTotpMetadata, setCurrentTotpMetadata } from './state.js';
import { appClipboard, showToast } from './utils.js';
/**
 * Normalise raw TOTP metadata from the backend into a consistent shape.
 *
 * @param metadata - The raw metadata object (may use snake_case or camelCase keys).
 * @returns A normalised object with `algorithm`, `digits`, `period`, `issuer`,
 *   and `accountName`, or `null` if no metadata was provided.
 */
export function normalizeTotpMetadata(metadata) {
    if (!metadata)
        return null;
    return {
        algorithm: String(metadata.algorithm || 'sha1').toLowerCase(),
        digits: Number(metadata.digits || 6),
        period: Number(metadata.period || 30),
        issuer: metadata.issuer || '',
        accountName: metadata.account_name || metadata.accountName || ''
    };
}
/**
 * Enable or disable the TOTP copy, configure, and remove buttons.
 *
 * @param hasSelection - Whether an entry is currently selected.
 * @param configured - Whether the selected entry has TOTP configured.
 */
export function setTotpButtonState(hasSelection, configured) {
    const copyButton = document.getElementById('copy-totp');
    const configureButton = document.getElementById('configure-totp');
    const removeButton = document.getElementById('remove-totp');
    if (!copyButton || !configureButton || !removeButton)
        return;
    const canCopyOrRemove = hasSelection && configured;
    copyButton.disabled = !canCopyOrRemove;
    copyButton.title = canCopyOrRemove ? 'Copy TOTP code' : 'No TOTP configured';
    configureButton.disabled = !hasSelection;
    configureButton.title = hasSelection
        ? (configured ? 'Update TOTP' : 'Configure TOTP')
        : 'Select a saved entry first';
    removeButton.disabled = !canCopyOrRemove;
    removeButton.title = canCopyOrRemove ? 'Remove TOTP' : 'No TOTP configured';
}
/**
 * Query the backend for TOTP metadata on the given entry and update the
 * TOTP button states (copy, configure, remove) accordingly.
 *
 * @param entryId - The entry ID to check, or falsy to reset TOTP state.
 */
export async function updateTotpAvailability(entryId) {
    if (!entryId) {
        setCurrentTotpMetadata(null);
        setTotpButtonState(false, false);
        return;
    }
    try {
        const metadata = await invoke('get_totp_metadata', { entryId });
        setCurrentTotpMetadata(normalizeTotpMetadata(metadata));
        setTotpButtonState(true, Boolean(currentTotpMetadata));
    }
    catch (error) {
        console.error('Error checking TOTP status:', error);
        setCurrentTotpMetadata(null);
        setTotpButtonState(true, false);
    }
}
/**
 * Open the TOTP configuration modal, pre-populated with existing metadata
 * if the entry already has TOTP configured.
 */
export function openTotpModal() {
    if (!currentEntry?.entry_id) {
        showToast('Save the entry before configuring TOTP', 'warning');
        return;
    }
    const modal = document.getElementById('totp-modal');
    const title = document.getElementById('totp-modal-title');
    const uriInput = document.getElementById('totp-otpauth-uri');
    const secretInput = document.getElementById('totp-secret');
    const algorithmInput = document.getElementById('totp-algorithm');
    const digitsInput = document.getElementById('totp-digits');
    const periodInput = document.getElementById('totp-period');
    const issuerInput = document.getElementById('totp-issuer');
    const accountInput = document.getElementById('totp-account-name');
    if (!modal || !uriInput || !secretInput || !algorithmInput || !digitsInput || !periodInput || !issuerInput || !accountInput) {
        showToast('TOTP modal unavailable', 'error');
        return;
    }
    const metadata = currentTotpMetadata || {
        algorithm: 'sha1',
        digits: 6,
        period: 30,
        issuer: '',
        accountName: ''
    };
    title.textContent = currentTotpMetadata ? 'Update TOTP' : 'Configure TOTP';
    uriInput.value = '';
    secretInput.value = '';
    algorithmInput.value = metadata.algorithm;
    digitsInput.value = String(metadata.digits);
    periodInput.value = String(metadata.period);
    issuerInput.value = metadata.issuer;
    accountInput.value = metadata.accountName;
    modal.classList.remove('hidden');
    modal.setAttribute('aria-hidden', 'false');
    secretInput.focus();
}
/** Close the TOTP configuration modal and clear its secret inputs. */
export function closeTotpModal() {
    const modal = document.getElementById('totp-modal');
    if (!modal)
        return;
    const uriInput = document.getElementById('totp-otpauth-uri');
    const secretInput = document.getElementById('totp-secret');
    if (uriInput)
        uriInput.value = '';
    if (secretInput)
        secretInput.value = '';
    modal.classList.add('hidden');
    modal.setAttribute('aria-hidden', 'true');
}
/**
 * Copy the current entry's TOTP code to the clipboard, showing the number
 * of seconds remaining before the code rotates. The copy is a WBS-709
 * secret copy: sensitive-marked natively and auto-cleared after 30 seconds
 * (or on app exit) like every other clipboard secret.
 */
export async function copyTotpForEntry() {
    if (!currentEntry?.entry_id) {
        showToast('Select an entry first', 'warning');
        return;
    }
    try {
        const response = await invoke('get_totp_code', { entryId: currentEntry.entry_id });
        const code = response.code;
        const secondsRemaining = response.seconds_remaining ?? response.secondsRemaining;
        await appClipboard.copySecret(code);
        showToast(`TOTP copied (${secondsRemaining}s remaining)`, 'success');
    }
    catch (error) {
        showToast(error, 'error');
        await updateTotpAvailability(currentEntry.entry_id);
    }
}
/**
 * Persist TOTP configuration from the modal form via the backend.
 *
 * Accepts either an `otpauth://` URI or a raw base32 secret, along with
 * optional algorithm, digits, period, issuer, and account name overrides.
 *
 * @param event - The form `submit` event (default is prevented).
 */
export async function saveTotpForEntry(event) {
    event.preventDefault();
    if (!currentEntry?.entry_id) {
        showToast('Save the entry before configuring TOTP', 'warning');
        return;
    }
    const uri = document.getElementById('totp-otpauth-uri').value.trim();
    const secret = document.getElementById('totp-secret').value.trim();
    const algorithm = document.getElementById('totp-algorithm').value;
    const digits = Number(document.getElementById('totp-digits').value);
    const period = Number(document.getElementById('totp-period').value);
    const issuer = document.getElementById('totp-issuer').value.trim();
    const accountName = document.getElementById('totp-account-name').value.trim();
    if (!uri && !secret) {
        showToast('Provide otpauth URI or base32 secret', 'warning');
        return;
    }
    try {
        await invoke('set_totp', {
            entryId: currentEntry.entry_id,
            secret: secret || null,
            otpauthUri: uri || null,
            algorithm,
            digits,
            period,
            issuer: issuer || null,
            accountName: accountName || null
        });
        closeTotpModal();
        await updateTotpAvailability(currentEntry.entry_id);
        showToast('TOTP configuration saved', 'success');
    }
    catch (error) {
        showToast(error, 'error');
    }
}
/**
 * Remove TOTP configuration for the currently-selected entry after user
 * confirmation.
 */
export async function removeTotpForEntry() {
    if (!currentEntry?.entry_id) {
        showToast('Select an entry first', 'warning');
        return;
    }
    if (!currentTotpMetadata) {
        showToast('No TOTP configured for this entry', 'warning');
        return;
    }
    const confirmed = await confirm('Remove TOTP configuration for this entry?', {
        title: 'Remove TOTP',
        kind: 'warning'
    });
    if (!confirmed)
        return;
    try {
        await invoke('remove_totp', { entryId: currentEntry.entry_id });
        setCurrentTotpMetadata(null);
        setTotpButtonState(true, false);
        showToast('TOTP removed', 'success');
    }
    catch (error) {
        showToast(error, 'error');
    }
}
