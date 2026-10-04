import { describe, expect, it, vi } from 'vitest';
import { abortable, withDeadline } from '../src/deadline';

describe('provider cancellation', () => {
  it('stops waiting when a provider ignores cancellation', async () => {
    const controller = new AbortController();
    const pending = abortable(new Promise<never>(() => {}), controller.signal);
    const rejected = expect(pending).rejects.toThrow('canceled');
    controller.abort(new Error('canceled'));
    await rejected;
  });

  it('observes late provider rejection after cancellation and removes the listener', async () => {
    const controller = new AbortController();
    const remove = vi.spyOn(controller.signal, 'removeEventListener');
    let rejectProvider!: (reason: unknown) => void;
    const pending = abortable(
      new Promise<never>((_, reject) => {
        rejectProvider = reject;
      }),
      controller.signal,
    );
    const rejected = expect(pending).rejects.toThrow('canceled');
    controller.abort(new Error('canceled'));
    await rejected;
    rejectProvider(new Error('late provider error'));
    await Promise.resolve();
    expect(remove).toHaveBeenCalledWith('abort', expect.any(Function));
  });

  it('rejects an already canceled operation even if its result is available', async () => {
    await expect(
      abortable(Promise.resolve('stale'), AbortSignal.abort(new Error('expired'))),
    ).rejects.toThrow('expired');
  });

  it('clears a completed deadline without aborting the provider afterward', async () => {
    vi.useFakeTimers();
    try {
      let providerSignal!: AbortSignal;
      await expect(
        withDeadline(new AbortController().signal, 1000, async (signal) => {
          providerSignal = signal;
          return 'done';
        }),
      ).resolves.toBe('done');
      expect(vi.getTimerCount()).toBe(0);
      await vi.advanceTimersByTimeAsync(1000);
      expect(providerSignal.aborted).toBe(false);
    } finally {
      vi.useRealTimers();
    }
  });
});
