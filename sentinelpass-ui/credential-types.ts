export const PASSWORD_CREDENTIAL_TYPE = 'password';
export const API_KEY_CREDENTIAL_TYPE = 'api_key';
export const PASSKEY_REFERENCE_TYPE = 'passkey_reference';

export type CredentialType =
    | typeof PASSWORD_CREDENTIAL_TYPE
    | typeof API_KEY_CREDENTIAL_TYPE
    | typeof PASSKEY_REFERENCE_TYPE;

export type VaultEntryLike = {
    credential_type?: string | null;
    username?: string | null;
    password?: string | null;
    url?: string | null;
};

export type PasskeyReferenceMetadata = {
    relyingPartyId: string | null;
    accountLabel: string | null;
    platform: string | null;
    credentialIdHint: string | null;
    syncSource: string | null;
};

export type CredentialTypeUiState = {
    credentialType: CredentialType;
    typeOptions: Array<{ value: CredentialType; label: string }>;
    typeSelectDisabled: boolean;
    typeSelectTitle: string;
    usernameLabel: string;
    secretLabel: string;
    secretPlaceholder: string;
    secretGroupHidden: boolean;
    passkeyPanelHidden: boolean;
    passkeyFieldsHidden: boolean;
    secretActionsDisabled: boolean;
    totpAllowed: boolean;
    passkeyMetadata: PasskeyReferenceMetadata | null;
};

function optionalString(value: unknown): string | null {
    return typeof value === 'string' && value.trim() ? value.trim() : null;
}

export function credentialTypeForEntry(entry: VaultEntryLike | null | undefined): CredentialType {
    switch (entry?.credential_type) {
        case API_KEY_CREDENTIAL_TYPE:
            return API_KEY_CREDENTIAL_TYPE;
        case PASSKEY_REFERENCE_TYPE:
            return PASSKEY_REFERENCE_TYPE;
        default:
            return PASSWORD_CREDENTIAL_TYPE;
    }
}

export function isPasskeyReferenceEntry(entry: VaultEntryLike | null | undefined): boolean {
    return credentialTypeForEntry(entry) === PASSKEY_REFERENCE_TYPE;
}

export function credentialTypeLabel(credentialType: string | null | undefined): string {
    switch (credentialType) {
        case API_KEY_CREDENTIAL_TYPE:
            return 'API key';
        case PASSKEY_REFERENCE_TYPE:
            return 'Passkey';
        default:
            return 'Password';
    }
}

export function secretLabelForType(credentialType: string | null | undefined): string {
    return credentialType === API_KEY_CREDENTIAL_TYPE ? 'API key' : 'Password';
}

export function parsePasskeyReferenceMetadata(
    entry: VaultEntryLike | null | undefined
): PasskeyReferenceMetadata | null {
    if (!isPasskeyReferenceEntry(entry)) {
        return null;
    }

    try {
        const metadata = JSON.parse(entry?.password || '{}');
        if (metadata?.kind !== PASSKEY_REFERENCE_TYPE) {
            return null;
        }

        return {
            relyingPartyId: optionalString(metadata.relying_party_id) || optionalString(entry?.url),
            accountLabel: optionalString(metadata.account_label) || optionalString(entry?.username),
            platform: optionalString(metadata.platform),
            credentialIdHint: optionalString(metadata.credential_id_hint),
            syncSource: optionalString(metadata.sync_source)
        };
    } catch (_) {
        return {
            relyingPartyId: optionalString(entry?.url),
            accountLabel: optionalString(entry?.username),
            platform: null,
            credentialIdHint: null,
            syncSource: null
        };
    }
}

export function credentialTypeUiState(
    entry: VaultEntryLike | null | undefined,
    isNewEntry?: boolean
): CredentialTypeUiState {
    const credentialType = credentialTypeForEntry(entry);
    const isPasskey = credentialType === PASSKEY_REFERENCE_TYPE;
    // New entries (no saved entry behind the form) may pick any type,
    // including a passkey reference; existing entries cannot be CONVERTED
    // into or out of the passkey-reference type.
    const isNew = isNewEntry === true || entry == null;
    const typeOptions: CredentialTypeUiState['typeOptions'] = [
        { value: PASSWORD_CREDENTIAL_TYPE, label: 'Password' },
        { value: API_KEY_CREDENTIAL_TYPE, label: 'API key' }
    ];

    if (isPasskey || isNew) {
        typeOptions.push({ value: PASSKEY_REFERENCE_TYPE, label: 'Passkey reference' });
    }

    return {
        credentialType,
        typeOptions,
        typeSelectDisabled: isPasskey && !isNew,
        typeSelectTitle: isPasskey && !isNew
            ? 'Passkey references are metadata-only and cannot be converted into password entries'
            : 'Credential type',
        usernameLabel: isPasskey
            ? 'Account label'
            : credentialType === API_KEY_CREDENTIAL_TYPE
                ? 'Key owner / label (optional)'
                : 'Username',
        secretLabel: secretLabelForType(credentialType),
        secretPlaceholder: credentialType === API_KEY_CREDENTIAL_TYPE ? 'API key' : 'Password',
        secretGroupHidden: isPasskey,
        passkeyPanelHidden: !isPasskey,
        // The typed inputs (RP ID, platform, hints) only render while
        // CREATING a passkey reference; saved references are displayed
        // read-only from the stored metadata.
        passkeyFieldsHidden: !(isPasskey && isNew),
        secretActionsDisabled: isPasskey,
        totpAllowed: !isPasskey,
        passkeyMetadata: parsePasskeyReferenceMetadata(entry)
    };
}

/**
 * Build the canonical metadata-only passkey reference payload stored in the
 * entry secret field. Mirrors `sentinelpass-core`'s
 * `PasskeyReferenceMetadata::to_reference_json` byte-for-byte (the daemon
 * validates this shape on add/update).
 *
 * @throws {Error} When a required field (relying party ID, account label,
 *   platform) is blank.
 */
export function buildPasskeyReferenceJson({
    relyingPartyId,
    accountLabel,
    platform,
    credentialIdHint,
    syncSource
}: {
    relyingPartyId: string | null | undefined;
    accountLabel: string | null | undefined;
    platform: string | null | undefined;
    credentialIdHint: string | null | undefined;
    syncSource: string | null | undefined;
}): string {
    const trimmedRp = (relyingPartyId || '').trim();
    const trimmedAccount = (accountLabel || '').trim();
    const trimmedPlatform = (platform || '').trim();
    if (!trimmedRp) {
        throw new Error('Relying party ID is required');
    }
    if (!trimmedAccount) {
        throw new Error('Account label is required');
    }
    if (!trimmedPlatform) {
        throw new Error('Platform is required');
    }

    return JSON.stringify({
        kind: PASSKEY_REFERENCE_TYPE,
        relying_party_id: trimmedRp,
        account_label: trimmedAccount,
        platform: trimmedPlatform,
        credential_id_hint: optionalString(credentialIdHint),
        sync_source: optionalString(syncSource),
        metadata_only: true
    });
}

export function buildEntrySaveDraft({
    currentEntry,
    selectedCredentialType,
    formPassword
}: {
    currentEntry?: VaultEntryLike | null;
    selectedCredentialType?: string | null;
    formPassword: string;
}): { credentialType: CredentialType; password: string | null | undefined } {
    const currentType = credentialTypeForEntry(currentEntry);
    const credentialType = currentType === PASSKEY_REFERENCE_TYPE
        ? PASSKEY_REFERENCE_TYPE
        : selectedCredentialType === PASSKEY_REFERENCE_TYPE && !currentEntry
            ? PASSKEY_REFERENCE_TYPE
            : selectedCredentialType === API_KEY_CREDENTIAL_TYPE
                ? API_KEY_CREDENTIAL_TYPE
                : PASSWORD_CREDENTIAL_TYPE;

    return {
        credentialType,
        // Existing passkey references keep their stored payload; NEW ones
        // receive the caller-built metadata-only JSON via `formPassword`.
        password: credentialType === PASSKEY_REFERENCE_TYPE && currentEntry
            ? currentEntry.password
            : formPassword
    };
}

export type EntryDraftInput = {
    credentialType: CredentialType;
    title: string | null | undefined;
    username: string | null | undefined;
    password: string | null | undefined;
    /** Required when creating a passkey-reference draft. */
    relyingPartyId?: string | null | undefined;
};

/**
 * Per-type required-field validation for the entry form. v0.13: the
 * username is optional for API-key entries (stored as `""` = absent);
 * password and passkey entries still require one. Returns the first
 * error message, or null when the draft is valid.
 */
export function entryDraftValidationError({
    credentialType,
    title,
    username,
    password,
    relyingPartyId
}: EntryDraftInput): string | null {
    if (!title || !title.trim()) {
        return 'Title is required';
    }
    if (credentialType !== API_KEY_CREDENTIAL_TYPE && (!username || !username.trim())) {
        return credentialType === PASSKEY_REFERENCE_TYPE ? 'Account label is required' : 'Username is required';
    }
    if (credentialType === PASSKEY_REFERENCE_TYPE && (!relyingPartyId || !relyingPartyId.trim())) {
        return 'Relying party ID is required';
    }
    if (!password || !password.trim()) {
        return `${secretLabelForType(credentialType)} is required`;
    }
    return null;
}
