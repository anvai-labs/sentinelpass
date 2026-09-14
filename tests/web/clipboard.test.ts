import { afterEach, beforeEach, describe, expect, it, vi } from 'vitest';
import {
  CLIPBOARD_EXPIRY_MS,
  createClipboardManager,
  type ClipboardInvoker,
  type ClipboardTimers
} from '../../sentinelpass-ui/clipboard.ts';

describe('clipboard secret controller (WBS-709)', () => {
  let timers: ClipboardTimers;
  let fired: Array<{ fn: () => void; ms: number }>;

  beforeEach(() => {
    fired = [];
    timers = {
      set: (fn, ms) => {
        fired.push({ fn, ms });
        return fired.length; // handle
      },
      clear: (handle) => {
        const idx = (handle as number) - 1;
        if (fired[idx]) {
          fired[idx] = { fn: () => {}, ms: -1 }; // mark cancelled
        }
      }
    };
  });

  afterEach(() => {
    vi.restoreAllMocks();
  });

  function latestTimer(): { fn: () => void; ms: number; cancelled: boolean } | null {
    const last = fired[fired.length - 1];
    if (!last) return null;
    return { ...last, cancelled: last.ms === -1 };
  }

  function invokeLog(invoke: ClipboardInvoker): Array<{ cmd: string; args?: Record<string, unknown> }> {
    return (invoke as unknown as { __log: Array<{ cmd: string; args?: Record<string, unknown> }> }).__log;
  }

  function recordingInvoke(response: unknown = true): ClipboardInvoker {
    const log: Array<{ cmd: string; args?: Record<string, unknown> }> = [];
    const fn = (async (cmd: string, args?: Record<string, unknown>) => {
      log.push({ cmd, args });
      return response;
    }) as ClipboardInvoker;
    (fn as unknown as { __log: typeof log }).__log = log;
    return fn;
  }

  it('routes secret copies through the native backend command', async () => {
    const invoke = recordingInvoke();
    const manager = createClipboardManager(invoke, timers);
    await expect(manager.copySecret('hunter2')).resolves.toBe(true);
    expect(invokeLog(invoke)).toEqual([
      { cmd: 'copy_secret_to_clipboard', args: { secret: 'hunter2' } }
    ]);
  });

  it('arms a single 30s expiry after each copy', async () => {
    const invoke = recordingInvoke();
    const manager = createClipboardManager(invoke, timers);
    await manager.copySecret('secret-a');
    expect(manager.hasPendingExpiry()).toBe(true);
    // The 30-second value is the security policy — pin the literal so a
    // silent constant drift cannot ship (the constant is asserted against
    // the literal too, so a rename alone cannot dodge this).
    expect(CLIPBOARD_EXPIRY_MS).toBe(30_000);
    expect(latestTimer()?.ms).toBe(30_000);
    expect(latestTimer()?.cancelled).toBe(false);
    expect(fired).toHaveLength(1);
  });

  it('re-arms instead of stacking timers when secrets are copied repeatedly', async () => {
    const invoke = recordingInvoke();
    const manager = createClipboardManager(invoke, timers);
    await manager.copySecret('secret-a');
    const firstHandle = fired[0];
    await manager.copySecret('secret-b');
    expect(fired).toHaveLength(2, 'second copy must schedule exactly one new timer');
    expect(latestTimer()?.fn).not.toBe(firstHandle.fn);
    expect(manager.hasPendingExpiry()).toBe(true);
    // Only the latest secret is pending expiry — the first timer must have
    // been cancelled.
    const expiredFirst = fired.filter((t) => t.ms === -1);
    expect(expiredFirst).toHaveLength(1);
  });

  it('expiry tick asks the backend to clear and reports the result', async () => {
    const invoke = recordingInvoke(true);
    const onExpiry = vi.fn();
    const manager = createClipboardManager(invoke, timers, onExpiry);
    await manager.copySecret('secret-a');
    latestTimer()!.fn();
    await vi.waitFor(() => expect(onExpiry).toHaveBeenCalledWith(true));
    expect(invokeLog(invoke)).toHaveLength(2);
    expect(invokeLog(invoke)[1].cmd).toBe('expire_clipboard_secret');
    expect(manager.hasPendingExpiry()).toBe(false);
  });

  it('onExpiry receives false when the backend did not clear', async () => {
    const invoke = recordingInvoke(false);
    const onExpiry = vi.fn();
    const manager = createClipboardManager(invoke, timers, onExpiry);
    await manager.copySecret('secret-a');
    latestTimer()!.fn();
    await vi.waitFor(() => expect(onExpiry).toHaveBeenCalledWith(false));
  });

  it('expireNow cancels the timer and clears immediately', async () => {
    const invoke = recordingInvoke(true);
    const manager = createClipboardManager(invoke, timers);
    await manager.copySecret('secret-a');
    await expect(manager.expireNow()).resolves.toBe(true);
    expect(manager.hasPendingExpiry()).toBe(false);
    const cmds = invokeLog(invoke).map((e) => e.cmd);
    expect(cmds).toEqual(['copy_secret_to_clipboard', 'expire_clipboard_secret']);
    expect(fired.filter((t) => t.ms === -1)).toHaveLength(1, 'the pending timer was cancelled');
  });

  it('empty secrets are rejected without touching the backend', async () => {
    const invoke = recordingInvoke();
    const manager = createClipboardManager(invoke, timers);
    await expect(manager.copySecret('')).resolves.toBe(false);
    expect(invokeLog(invoke)).toEqual([]);
    expect(manager.hasPendingExpiry()).toBe(false);
  });

  it('backend write failures propagate to the caller and arm nothing', async () => {
    const invoke = (async () => {
      throw new Error('Clipboard unavailable');
    }) as ClipboardInvoker;
    const manager = createClipboardManager(invoke, timers);
    await expect(manager.copySecret('secret-a')).rejects.toThrow('Clipboard unavailable');
    expect(manager.hasPendingExpiry()).toBe(false);
  });

  it('expiry survives backend errors without throwing', async () => {
    const log: Array<{ cmd: string }> = [];
    const invoke = (async (cmd: string) => {
      log.push({ cmd });
      if (cmd === 'expire_clipboard_secret') {
        throw new Error('backend gone');
      }
      return true;
    }) as ClipboardInvoker;
    const onExpiry = vi.fn();
    const manager = createClipboardManager(invoke, timers, onExpiry);
    await manager.copySecret('secret-a');
    latestTimer()!.fn();
    await vi.waitFor(() => expect(onExpiry).toHaveBeenCalledWith(false));
  });

  it('cancelExpiry drops the pending timer without clearing', async () => {
    const invoke = recordingInvoke();
    const manager = createClipboardManager(invoke, timers);
    await manager.copySecret('secret-a');
    manager.cancelExpiry();
    expect(manager.hasPendingExpiry()).toBe(false);
    expect(invokeLog(invoke)).toHaveLength(1, 'no expire call may be made');
  });
});
