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
    entry: VaultEntryLike | null | undefined
): CredentialTypeUiState {
    const credentialType = credentialTypeForEntry(entry);
    const isPasskey = credentialType === PASSKEY_REFERENCE_TYPE;
    const typeOptions: CredentialTypeUiState['typeOptions'] = [
        { value: PASSWORD_CREDENTIAL_TYPE, label: 'Password' },
        { value: API_KEY_CREDENTIAL_TYPE, label: 'API key' }
    ];

    if (isPasskey) {
        typeOptions.push({ value: PASSKEY_REFERENCE_TYPE, label: 'Passkey reference' });
    }

    return {
        credentialType,
        typeOptions,
        typeSelectDisabled: isPasskey,
        typeSelectTitle: isPasskey
            ? 'Passkey references are metadata-only and cannot be converted into password entries'
            : 'Credential type',
        usernameLabel: isPasskey ? 'Account label' : 'Username',
        secretLabel: secretLabelForType(credentialType),
        secretPlaceholder: credentialType === API_KEY_CREDENTIAL_TYPE ? 'API key' : 'Password',
        secretGroupHidden: isPasskey,
        passkeyPanelHidden: !isPasskey,
        secretActionsDisabled: isPasskey,
        totpAllowed: !isPasskey,
        passkeyMetadata: parsePasskeyReferenceMetadata(entry)
    };
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
        : selectedCredentialType === API_KEY_CREDENTIAL_TYPE
            ? API_KEY_CREDENTIAL_TYPE
            : PASSWORD_CREDENTIAL_TYPE;

    return {
        credentialType,
        password: credentialType === PASSKEY_REFERENCE_TYPE ? currentEntry?.password : formPassword
    };
}
