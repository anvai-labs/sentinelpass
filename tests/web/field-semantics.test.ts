import { describe, expect, it } from 'vitest';
import {
  classifyInputField,
  classifyPasswordForm,
  isAutofillablePasswordField,
  isNewPasswordField,
  isUsernameField
} from '../../browser-extension/chrome/field-semantics.ts';

describe('field semantics (WBS-714)', () => {
  it('honors the autocomplete attribute as the primary signal', () => {
    expect(classifyInputField({ autocomplete: 'username' })).toBe('username');
    expect(classifyInputField({ autocomplete: 'email', type: 'text' })).toBe('username');
    expect(classifyInputField({ autocomplete: 'current-password' })).toBe('current-password');
    expect(classifyInputField({ autocomplete: 'new-password' })).toBe('new-password');
    expect(classifyInputField({ autocomplete: 'one-time-code' })).toBe('one-time-code');
  });

  it('falls back to type and text hints without autocomplete', () => {
    expect(classifyInputField({ type: 'password' })).toBe('current-password');
    expect(classifyInputField({ type: 'email' })).toBe('username');
    expect(classifyInputField({ name: 'login_email', type: 'text' })).toBe('username');
    expect(classifyInputField({ type: 'text', name: 'search' })).toBe('other');
  });

  it('never classifies a text field as a password field', () => {
    expect(isAutofillablePasswordField({ type: 'text', name: 'password' })).toBe(false);
    expect(isAutofillablePasswordField({ type: 'password' })).toBe(true);
    expect(isAutofillablePasswordField({ type: 'password', autocomplete: 'new-password' })).toBe(
      false
    );
    expect(isNewPasswordField({ type: 'password', autocomplete: 'new-password' })).toBe(true);
  });

  it('prefers autocomplete=username over ambiguous text hints', () => {
    expect(isUsernameField({ autocomplete: 'username', name: 'search' })).toBe(true);
    expect(isUsernameField({ type: 'text', name: 'search' })).toBe(false);
  });

  it('classifies login forms', () => {
    expect(
      classifyPasswordForm([{ type: 'password', hasValue: true }])
    ).toBe('login');
    expect(
      classifyPasswordForm([{ type: 'password', hasValue: false }])
    ).toBe('login');
  });

  it('recognizes password-change pairs (existing + new)', () => {
    expect(
      classifyPasswordForm([
        { type: 'password', autocomplete: 'current-password', hasValue: true },
        { type: 'password', autocomplete: 'new-password', hasValue: false },
        { type: 'password', autocomplete: 'new-password', hasValue: false }
      ])
    ).toBe('password-change');
  });

  it('treats new-password fields without a filled current as new-account', () => {
    expect(
      classifyPasswordForm([
        { type: 'password', autocomplete: 'new-password', hasValue: false },
        { type: 'password', autocomplete: 'new-password', hasValue: true }
      ])
    ).toBe('new-account');
    expect(
      classifyPasswordForm([
        { type: 'password', autocomplete: 'current-password', hasValue: false },
        { type: 'password', autocomplete: 'new-password', hasValue: false }
      ])
    ).toBe('new-account');
  });

  it('recognizes change forms by signal-rich heuristics only as login when no new-password exists', () => {
    // Two plain password fields with no attributes: no positive signal —
    // classified login (the pre-714 heuristic would guess; the semantic
    // rule requires the page's own statement).
    expect(
      classifyPasswordForm([
        { type: 'password', hasValue: true },
        { type: 'password', hasValue: false }
      ])
    ).toBe('login');
  });
});
