import { describe, expect, it } from 'vitest';
import { readRepoFile } from './ui-source';

/**
 * 2026-11-04 daemon-wedge regression (UI half).
 *
 * The desktop unlock form had no re-entrancy guard: the submit control
 * stayed enabled and the password input stayed populated across the
 * multi-second Argon2id await, so Enter key-repeat / double-press fired a
 * second `unlock_vault`. That second request queued on the daemon's KDF
 * gate and ran a second concurrent `VaultManager::open`, wedging the
 * daemon's IPC listener (see the matching Rust regression tests in
 * sentinelpass-core vault_state / ipc::server). The guard covers BOTH
 * branches of the submit handler (unlock and first-run vault creation —
 * adversarial review F5).
 *
 * `app.ts` is not importable under this suite's node environment (no
 * DOM), so this gate anchors on the source — the same convention as
 * tauri-capabilities.test.ts. If the guard is refactored away, this
 * fails the web_tdd CI job instead of shipping the wedge back.
 */

const source = readRepoFile('sentinelpass-ui', 'app.ts');

describe('password form re-entrancy guard (daemon wedge regression)', () => {
  it('guards the submit handler with an in-flight flag covering both branches', () => {
    expect(source, 'handlePasswordSubmit must carry an in-flight guard').toMatch(
      /passwordSubmitInFlight/,
    );
    expect(source, 'the guard must be a re-entry check at handler scope').toMatch(
      /if\s*\(\s*passwordSubmitInFlight\s*\)\s*\{\s*return;/,
    );
    expect(
      source,
      'the guard must wrap the whole handler (create + unlock), not one branch',
    ).toMatch(/passwordSubmitInFlight\s*=\s*true;\s*\n\s*submitPasswordBtn\.disabled\s*=\s*true;/);
  });

  it('disables the submit control while a submit is in flight', () => {
    expect(source).toMatch(/submitPasswordBtn\.disabled\s*=\s*true/);
  });

  it('re-enables the submit control when the operation fails', () => {
    expect(source, 'a failed submit must restore the form for retry').toMatch(
      /submitPasswordBtn\.disabled\s*=\s*false/,
    );
    expect(source, 'the in-flight flag must clear on all paths (finally)').toMatch(
      /passwordSubmitInFlight\s*=\s*false/,
    );
  });
});
