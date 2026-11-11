import { describe, expect, it } from 'vitest';
import {
  API_KEY_CREDENTIAL_TYPE,
  PASSKEY_REFERENCE_TYPE,
  PASSWORD_CREDENTIAL_TYPE,
  buildEntrySaveDraft,
  buildPasskeyReferenceJson,
  credentialTypeForEntry,
  credentialTypeLabel,
  credentialTypeUiState,
  entryDraftValidationError,
  isPasskeyReferenceEntry,
  parsePasskeyReferenceMetadata,
  secretLabelForType
} from '../../sentinelpass-ui/credential-types.ts';

describe('desktop credential type contract', () => {
  const passkeyMetadataJson = JSON.stringify({
    kind: PASSKEY_REFERENCE_TYPE,
    relying_party_id: 'github.com',
    account_label: 'dev@example.com',
    platform: 'icloud-keychain',
    credential_id_hint: 'cred-123',
    sync_source: 'apple'
  });

  it('defaults missing and unsupported credential types to password', () => {
    expect(credentialTypeForEntry(null)).toBe(PASSWORD_CREDENTIAL_TYPE);
    expect(credentialTypeForEntry({})).toBe(PASSWORD_CREDENTIAL_TYPE);
    expect(credentialTypeForEntry({ credential_type: 'totp' })).toBe(PASSWORD_CREDENTIAL_TYPE);
  });

  it('recognizes supported credential types explicitly', () => {
    expect(credentialTypeForEntry({ credential_type: API_KEY_CREDENTIAL_TYPE })).toBe(API_KEY_CREDENTIAL_TYPE);
    expect(credentialTypeForEntry({ credential_type: PASSKEY_REFERENCE_TYPE })).toBe(PASSKEY_REFERENCE_TYPE);
    expect(isPasskeyReferenceEntry({ credential_type: PASSKEY_REFERENCE_TYPE })).toBe(true);
    expect(isPasskeyReferenceEntry({ credential_type: API_KEY_CREDENTIAL_TYPE })).toBe(false);
  });

  it('uses user-facing labels for list badges and secret fields', () => {
    expect(credentialTypeLabel(PASSWORD_CREDENTIAL_TYPE)).toBe('Password');
    expect(credentialTypeLabel(API_KEY_CREDENTIAL_TYPE)).toBe('API key');
    expect(credentialTypeLabel(PASSKEY_REFERENCE_TYPE)).toBe('Passkey');
    expect(credentialTypeLabel('unknown')).toBe('Password');

    expect(secretLabelForType(PASSWORD_CREDENTIAL_TYPE)).toBe('Password');
    expect(secretLabelForType(API_KEY_CREDENTIAL_TYPE)).toBe('API key');
    expect(secretLabelForType(PASSKEY_REFERENCE_TYPE)).toBe('Password');
  });

  it('builds editable password UI state with only password and API-key type options', () => {
    const state = credentialTypeUiState({ credential_type: PASSWORD_CREDENTIAL_TYPE });

    expect(state).toMatchObject({
      credentialType: PASSWORD_CREDENTIAL_TYPE,
      typeSelectDisabled: false,
      usernameLabel: 'Username',
      secretLabel: 'Password',
      secretPlaceholder: 'Password',
      secretGroupHidden: false,
      passkeyPanelHidden: true,
      secretActionsDisabled: false,
      totpAllowed: true,
      passkeyMetadata: null
    });
    expect(state.typeOptions.map(option => option.value)).toEqual([
      PASSWORD_CREDENTIAL_TYPE,
      API_KEY_CREDENTIAL_TYPE
    ]);
  });

  it('builds editable API-key UI state with API-key secret copy/generate wording', () => {
    const state = credentialTypeUiState({ credential_type: API_KEY_CREDENTIAL_TYPE });

    expect(state).toMatchObject({
      credentialType: API_KEY_CREDENTIAL_TYPE,
      typeSelectDisabled: false,
      usernameLabel: 'Key owner / label (optional)',
      secretLabel: 'API key',
      secretPlaceholder: 'API key',
      secretGroupHidden: false,
      passkeyPanelHidden: true,
      secretActionsDisabled: false,
      totpAllowed: true,
      passkeyMetadata: null
    });
  });

  it('builds metadata-only passkey UI state that hides copyable secret controls', () => {
    const state = credentialTypeUiState({
      credential_type: PASSKEY_REFERENCE_TYPE,
      username: 'fallback@example.com',
      url: 'fallback.example',
      password: passkeyMetadataJson
    });

    expect(state).toMatchObject({
      credentialType: PASSKEY_REFERENCE_TYPE,
      typeSelectDisabled: true,
      usernameLabel: 'Account label',
      secretGroupHidden: true,
      passkeyPanelHidden: false,
      secretActionsDisabled: true,
      totpAllowed: false
    });
    expect(state.typeOptions.map(option => option.value)).toEqual([
      PASSWORD_CREDENTIAL_TYPE,
      API_KEY_CREDENTIAL_TYPE,
      PASSKEY_REFERENCE_TYPE
    ]);
    expect(state.passkeyMetadata).toEqual({
      relyingPartyId: 'github.com',
      accountLabel: 'dev@example.com',
      platform: 'icloud-keychain',
      credentialIdHint: 'cred-123',
      syncSource: 'apple'
    });
  });

  it('parses passkey metadata only when the entry type and JSON kind agree', () => {
    expect(parsePasskeyReferenceMetadata({
      credential_type: PASSKEY_REFERENCE_TYPE,
      username: 'dev@example.com',
      url: 'github.com',
      password: passkeyMetadataJson
    })).toEqual({
      relyingPartyId: 'github.com',
      accountLabel: 'dev@example.com',
      platform: 'icloud-keychain',
      credentialIdHint: 'cred-123',
      syncSource: 'apple'
    });

    expect(parsePasskeyReferenceMetadata({
      credential_type: PASSKEY_REFERENCE_TYPE,
      username: 'dev@example.com',
      url: 'github.com',
      password: '{"kind":"password"}'
    })).toBeNull();
    expect(parsePasskeyReferenceMetadata({
      credential_type: PASSWORD_CREDENTIAL_TYPE,
      password: passkeyMetadataJson
    })).toBeNull();
  });

  it('falls back to entry account and relying-party hints when passkey JSON is malformed', () => {
    expect(parsePasskeyReferenceMetadata({
      credential_type: PASSKEY_REFERENCE_TYPE,
      username: 'dev@example.com',
      url: 'github.com',
      password: '{not-json'
    })).toEqual({
      relyingPartyId: 'github.com',
      accountLabel: 'dev@example.com',
      platform: null,
      credentialIdHint: null,
      syncSource: null
    });
  });

  it('builds save drafts for new password and API-key entries from form state', () => {
    expect(buildEntrySaveDraft({
      currentEntry: null,
      selectedCredentialType: PASSWORD_CREDENTIAL_TYPE,
      formPassword: 'pw-123'
    })).toEqual({
      credentialType: PASSWORD_CREDENTIAL_TYPE,
      password: 'pw-123'
    });

    expect(buildEntrySaveDraft({
      currentEntry: null,
      selectedCredentialType: API_KEY_CREDENTIAL_TYPE,
      formPassword: 'sk-test'
    })).toEqual({
      credentialType: API_KEY_CREDENTIAL_TYPE,
      password: 'sk-test'
    });
  });

  it('preserves passkey metadata on save and ignores type-selector or form-secret changes', () => {
    expect(buildEntrySaveDraft({
      currentEntry: {
        credential_type: PASSKEY_REFERENCE_TYPE,
        password: passkeyMetadataJson
      },
      selectedCredentialType: API_KEY_CREDENTIAL_TYPE,
      formPassword: 'accidental-secret-edit'
    })).toEqual({
      credentialType: PASSKEY_REFERENCE_TYPE,
      password: passkeyMetadataJson
    });
  });

  it('falls back to password when a non-passkey entry has an unsupported selected type', () => {
    expect(buildEntrySaveDraft({
      currentEntry: { credential_type: PASSWORD_CREDENTIAL_TYPE, password: 'old' },
      selectedCredentialType: 'passkey_reference',
      formPassword: 'new'
    })).toEqual({
      credentialType: PASSWORD_CREDENTIAL_TYPE,
      password: 'new'
    });
  });
});

describe('entry draft validation (v0.13 username-optional API keys)', () => {
  it('requires a username for password entries', () => {
    expect(entryDraftValidationError({
      credentialType: PASSWORD_CREDENTIAL_TYPE,
      title: 'Bank',
      username: '',
      password: 'pw'
    })).toBe('Username is required');
    expect(entryDraftValidationError({
      credentialType: PASSWORD_CREDENTIAL_TYPE,
      title: 'Bank',
      username: '   ',
      password: 'pw'
    })).toBe('Username is required');
    expect(entryDraftValidationError({
      credentialType: PASSWORD_CREDENTIAL_TYPE,
      title: 'Bank',
      username: undefined,
      password: 'pw'
    })).toBe('Username is required');
  });

  it('allows an empty username for API-key entries', () => {
    expect(entryDraftValidationError({
      credentialType: API_KEY_CREDENTIAL_TYPE,
      title: 'Stripe API',
      username: '',
      password: 'sk-test-51fe'
    })).toBeNull();
    expect(entryDraftValidationError({
      credentialType: API_KEY_CREDENTIAL_TYPE,
      title: 'Stripe API',
      username: '   ',
      password: 'sk-test-51fe'
    })).toBeNull();
    expect(entryDraftValidationError({
      credentialType: API_KEY_CREDENTIAL_TYPE,
      title: 'Stripe API',
      username: undefined,
      password: 'sk-test-51fe'
    })).toBeNull();
    expect(entryDraftValidationError({
      credentialType: API_KEY_CREDENTIAL_TYPE,
      title: 'Stripe API',
      username: 'ops-team',
      password: 'sk-test-51fe'
    })).toBeNull();
  });

  it('still validates title and secret for every type', () => {
    expect(entryDraftValidationError({
      credentialType: API_KEY_CREDENTIAL_TYPE,
      title: '',
      username: '',
      password: 'sk-test-51fe'
    })).toBe('Title is required');
    expect(entryDraftValidationError({
      credentialType: API_KEY_CREDENTIAL_TYPE,
      title: 'Stripe API',
      username: '',
      password: '   '
    })).toBe('API key is required');
    expect(entryDraftValidationError({
      credentialType: PASSWORD_CREDENTIAL_TYPE,
      title: 'Bank',
      username: 'user@example.com',
      password: null
    })).toBe('Password is required');
  });

  it('requires a username (account label) for passkey reference entries', () => {
    expect(entryDraftValidationError({
      credentialType: PASSKEY_REFERENCE_TYPE,
      title: 'GitHub',
      username: '',
      password: '{"kind":"passkey_reference"}'
    })).toBe('Account label is required');
  });

  it('accepts whitespace-padded but non-empty values', () => {
    expect(entryDraftValidationError({
      credentialType: PASSWORD_CREDENTIAL_TYPE,
      title: '  Bank  ',
      username: ' user@example.com ',
      password: 'pw'
    })).toBeNull();
  });
});

describe('creating passkey references from the UI', () => {
  const RP_ID_INPUT = 'example.com';

  it('offers the passkey-reference type when creating a new entry', () => {
    const state = credentialTypeUiState(null, true);

    expect(state.typeOptions.map(option => option.value)).toEqual([
      PASSWORD_CREDENTIAL_TYPE,
      API_KEY_CREDENTIAL_TYPE,
      PASSKEY_REFERENCE_TYPE
    ]);
    expect(state.typeSelectDisabled).toBe(false);
  });

  it('does not offer passkey conversion when editing an existing password entry', () => {
    const state = credentialTypeUiState({ credential_type: PASSWORD_CREDENTIAL_TYPE }, false);

    expect(state.typeOptions.map(option => option.value)).toEqual([
      PASSWORD_CREDENTIAL_TYPE,
      API_KEY_CREDENTIAL_TYPE
    ]);
  });

  it('shows the passkey edit fields only for a NEW passkey entry', () => {
    expect(credentialTypeUiState({ credential_type: PASSKEY_REFERENCE_TYPE }, false).passkeyFieldsHidden).toBe(true);
    expect(credentialTypeUiState(null, true).passkeyFieldsHidden).toBe(true);
    // New entry with the passkey type already selected in the dropdown:
    expect(credentialTypeUiState({ credential_type: PASSKEY_REFERENCE_TYPE }, true).passkeyFieldsHidden).toBe(false);
  });

  it('keeps the type dropdown enabled for a new passkey entry', () => {
    expect(credentialTypeUiState({ credential_type: PASSKEY_REFERENCE_TYPE }, true).typeSelectDisabled).toBe(false);
  });

  it('builds canonical metadata-only reference JSON', () => {
    const parsed = JSON.parse(buildPasskeyReferenceJson({
      relyingPartyId: ' example.com ',
      accountLabel: 'alice@example.com',
      platform: 'icloud-keychain',
      credentialIdHint: ' hint ',
      syncSource: null
    }));

    expect(parsed).toEqual({
      kind: PASSKEY_REFERENCE_TYPE,
      relying_party_id: 'example.com',
      account_label: 'alice@example.com',
      platform: 'icloud-keychain',
      credential_id_hint: 'hint',
      sync_source: null,
      metadata_only: true
    });
  });

  it('rejects blank required fields when building reference JSON', () => {
    expect(() => buildPasskeyReferenceJson({
      relyingPartyId: '  ',
      accountLabel: 'a',
      platform: 'p',
      credentialIdHint: null,
      syncSource: null
    })).toThrow();
    expect(() => buildPasskeyReferenceJson({
      relyingPartyId: 'x.com',
      accountLabel: '',
      platform: 'p',
      credentialIdHint: null,
      syncSource: null
    })).toThrow();
    expect(() => buildPasskeyReferenceJson({
      relyingPartyId: 'x.com',
      accountLabel: 'a',
      platform: ' ',
      credentialIdHint: null,
      syncSource: null
    })).toThrow();
  });

  it('keeps an existing passkey payload when saving an existing entry', () => {
    const entry = {
      credential_type: PASSKEY_REFERENCE_TYPE,
      password: '{"kind":"passkey_reference","relying_party_id":"github.com","metadata_only":true}'
    };
    const draft = buildEntrySaveDraft({
      currentEntry: entry,
      selectedCredentialType: PASSKEY_REFERENCE_TYPE,
      formPassword: '{"tampered":true}'
    });

    expect(draft.credentialType).toBe(PASSKEY_REFERENCE_TYPE);
    expect(draft.password).toBe(
      '{"kind":"passkey_reference","relying_party_id":"github.com","metadata_only":true}'
    );
  });

  it('uses the caller-built payload when saving a NEW passkey entry', () => {
    const draft = buildEntrySaveDraft({
      currentEntry: null,
      selectedCredentialType: PASSKEY_REFERENCE_TYPE,
      formPassword: '{"kind":"passkey_reference","metadata_only":true}'
    });

    expect(draft.credentialType).toBe(PASSKEY_REFERENCE_TYPE);
    expect(draft.password).toBe('{"kind":"passkey_reference","metadata_only":true}');
  });

  it('validates the relying party ID for passkey drafts', () => {
    expect(entryDraftValidationError({
      credentialType: PASSKEY_REFERENCE_TYPE,
      title: 'Passkey reference: example.com',
      username: 'alice@example.com',
      password: '{"kind":"passkey_reference","metadata_only":true}',
      relyingPartyId: null
    })).toBe('Relying party ID is required');

    expect(entryDraftValidationError({
      credentialType: PASSKEY_REFERENCE_TYPE,
      title: 'Passkey reference: example.com',
      username: 'alice@example.com',
      password: '{"kind":"passkey_reference","metadata_only":true}',
      relyingPartyId: RP_ID_INPUT
    })).toBeNull();
  });
});
