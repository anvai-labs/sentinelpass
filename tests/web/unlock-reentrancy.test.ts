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
 * sentinelpass-core vault_state / ipc::server).
 *
 * `app.ts` is not importable under this suite's node environment (no
 * DOM), so this gate anchors on the source — the same convention as
 * tauri-capabilities.test.ts. If the guard is refactored away, this
 * fails the web_tdd CI job instead of shipping the wedge back.
 */

const source = readRepoFile('sentinelpass-ui', 'app.ts');

describe('unlock form re-entrancy guard (daemon wedge regression)', () => {
  it('guards the unlock submit handler with an in-flight flag', () => {
    expect(source, 'handlePasswordSubmit must carry an in-flight guard').toMatch(
      /unlockInFlight/,
    );
    expect(source, 'the guard must be a re-entry check at handler scope').toMatch(
      /if\s*\(\s*unlockInFlight\s*\)/,
    );
  });

  it('disables the submit control while an unlock is in flight', () => {
    expect(source).toMatch(/submitPasswordBtn\.disabled\s*=\s*true/);
  });

  it('re-enables the submit control when the unlock fails', () => {
    expect(source, 'a failed unlock must restore the form for retry').toMatch(
      /submitPasswordBtn\.disabled\s*=\s*false/,
    );
    expect(source, 'the in-flight flag must clear on the failure path').toMatch(
      /unlockInFlight\s*=\s*false/,
    );
  });
});
