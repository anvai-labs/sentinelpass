import { describe, expect, it } from 'vitest';
import { decideCredentialChoice } from '../../browser-extension/chrome/credential-choice.ts';

describe('credential choice policy (WBS-715)', () => {
  it('reports none for zero candidates', () => {
    expect(decideCredentialChoice([])).toEqual({ action: 'none' });
  });

  it('fills directly when exactly one credential matches', () => {
    expect(decideCredentialChoice([{ username: 'user@example.com' }])).toEqual({
      action: 'fill',
      username: 'user@example.com'
    });
  });

  it('requires an explicit chooser for multiple matches — never first-match', () => {
    const decision = decideCredentialChoice([
      { username: 'a@example.com', title: 'Work' },
      { username: 'b@example.com' }
    ]);
    expect(decision.action).toBe('choose');
    if (decision.action === 'choose') {
      expect(decision.candidates.map((c) => c.username)).toEqual([
        'a@example.com',
        'b@example.com'
      ]);
      expect(decision.candidates[0].title).toBe('Work');
    }
  });

  it('fills the user-picked username from the chooser', () => {
    const decision = decideCredentialChoice(
      [{ username: 'a@example.com' }, { username: 'b@example.com' }],
      'B@Example.com'
    );
    expect(decision).toEqual({ action: 'fill', username: 'b@example.com' });
  });

  it('never falls back to first-match when a picked username is unknown', () => {
    const decision = decideCredentialChoice(
      [{ username: 'a@example.com' }, { username: 'b@example.com' }],
      'evil@example.com'
    );
    expect(decision.action).toBe('choose');
  });
});
