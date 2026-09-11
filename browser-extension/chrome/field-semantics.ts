/**
 * Field semantics + form classification (WBS-714, TD-CLIENT-06).
 *
 * The `autocomplete` attribute is the page's OWN statement of what a field
 * is; honoring it is what makes form/field binding (WBS-713) and the
 * save-prompt semantics (update vs. new) deterministic instead of
 * heuristic-first. Positive semantics are honored (`new-password`,
 * `current-password`, `username`, `email`, `one-time-code`); `autocomplete
 * = "off"` is deliberately IGNORED for password fields (browser-standard
 * behavior — the user, not the site, decides whether to save).
 *
 * Pure module: callers pass plain descriptor objects (no DOM types), so
 * the classification policy is unit-testable.
 */

export type FieldRole =
  | 'username'
  | 'current-password'
  | 'new-password'
  | 'one-time-code'
  | 'other';

/** Plain shape of one input as observed from the DOM. */
export interface InputDescriptor {
  autocomplete?: string;
  type?: string;
  name?: string;
  id?: string;
  placeholder?: string;
}

/** Lowercased autocomplete token list for a descriptor. */
function autocompleteTokens(descriptor: InputDescriptor): string[] {
  return (descriptor.autocomplete || '')
    .split(/\s+/)
    .map((token) => token.toLowerCase())
    .filter(Boolean);
}

function hint(descriptor: InputDescriptor): string {
  return [descriptor.name, descriptor.id, descriptor.placeholder]
    .filter((part): part is string => typeof part === 'string')
    .join(' ')
    .toLowerCase();
}

/**
 * Classify one input by its semantics. The autocomplete attribute wins;
 * `type` and name/id/placeholder hints only break ties.
 */
export function classifyInputField(descriptor: InputDescriptor): FieldRole {
  const tokens = autocompleteTokens(descriptor);
  for (const token of tokens) {
    if (token === 'username' || token === 'email' || token === 'login') {
      return 'username';
    }
    if (token === 'current-password') {
      return 'current-password';
    }
    if (token === 'new-password') {
      return 'new-password';
    }
    if (token === 'one-time-code') {
      return 'one-time-code';
    }
  }

  if ((descriptor.type || '').toLowerCase() === 'password') {
    return 'current-password';
  }

  if (
    (descriptor.type || '').toLowerCase() === 'email' ||
    /user|email|login/.test(hint(descriptor))
  ) {
    return 'username';
  }

  return 'other';
}

export function isUsernameField(descriptor: InputDescriptor): boolean {
  return classifyInputField(descriptor) === 'username';
}

/** A password field the AUTOFILL delivery may target (login semantics). */
export function isAutofillablePasswordField(descriptor: InputDescriptor): boolean {
  const role = classifyInputField(descriptor);
  const type = (descriptor.type || '').toLowerCase();
  return type === 'password' && role === 'current-password';
}

/** A password field that must NOT be silently autofilled (set/change). */
export function isNewPasswordField(descriptor: InputDescriptor): boolean {
  return classifyInputField(descriptor) === 'new-password';
}

/**
 * What kind of form a set of password fields describes, using the page's
 * own autocomplete signals first (WBS-714: password-change pairs are
 * recognized, not guessed from surrounding text alone).
 *
 * - `password-change`: an existing (non-empty) current-password field
 *   paired with at least one new-password field — the user is CHANGING a
 *   password on an authenticated page.
 * - `new-account`: any new-password field without that existing pairing
 *   (registration/reset flows).
 * - `login`: everything else.
 */
export type FormPasswordKind = 'login' | 'new-account' | 'password-change';

export interface PasswordFieldDescriptor extends InputDescriptor {
  hasValue: boolean;
}

export function classifyPasswordForm(
  fields: PasswordFieldDescriptor[]
): FormPasswordKind {
  const newPasswords = fields.filter((f) => classifyInputField(f) === 'new-password');
  if (newPasswords.length === 0) {
    return 'login';
  }
  const filledCurrent = fields.some(
    (f) => classifyInputField(f) === 'current-password' && f.hasValue
  );
  return filledCurrent ? 'password-change' : 'new-account';
}
