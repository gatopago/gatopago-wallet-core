import { afterEach, describe, expect, it, vi } from 'vitest';
import { withDeadline } from '../src/deadline';

afterEach(() => {
  vi.useRealTimers();
  vi.restoreAllMocks();
});
describe('request-local deadline disposal', () => {
  it('clears the timer and parent listener after success', async () => {
    vi.useFakeTimers();
    const parent = new AbortController(),
      remove = vi.spyOn(parent.signal, 'removeEventListener');
    expect(await withDeadline(parent.signal, 5000, async () => 'done')).toBe('done');
    expect(vi.getTimerCount()).toBe(0);
    expect(remove).toHaveBeenCalledTimes(1);
  });
  it('clears the timer after a rejected operation', async () => {
    vi.useFakeTimers();
    await expect(
      withDeadline(new AbortController().signal, 5000, async () => {
        throw new Error('Synthetic RPC error');
      }),
    ).rejects.toThrow('Synthetic RPC error');
    expect(vi.getTimerCount()).toBe(0);
  });
  it('does not begin an already-aborted operation', async () => {
    vi.useFakeTimers();
    const action = vi.fn(async () => 1);
    await expect(withDeadline(AbortSignal.abort(), 5000, action)).rejects.toThrow();
    expect(action).not.toHaveBeenCalled();
    expect(vi.getTimerCount()).toBe(0);
  });
  it('propagates parent cancellation and disposes the deadline', async () => {
    vi.useFakeTimers();
    const parent = new AbortController();
    const pending = withDeadline(
      parent.signal,
      5000,
      (signal) =>
        new Promise((_resolve, reject) => {
          signal.addEventListener('abort', () => reject(signal.reason), { once: true });
        }),
    );
    const assertion = expect(pending).rejects.toMatchObject({ name: 'AbortError' });
    parent.abort();
    await assertion;
    expect(vi.getTimerCount()).toBe(0);
  });
  it('still terminates a slow cooperative RPC at its original deadline', async () => {
    vi.useFakeTimers();
    const pending = withDeadline(
      new AbortController().signal,
      5000,
      (signal) =>
        new Promise((_resolve, reject) => {
          signal.addEventListener('abort', () => reject(signal.reason), { once: true });
        }),
    );
    const assertion = expect(pending).rejects.toMatchObject({ name: 'TimeoutError' });
    await vi.advanceTimersByTimeAsync(5000);
    await assertion;
    expect(vi.getTimerCount()).toBe(0);
  });
  it('does not accept a result returned after cancellation was ignored', async () => {
    vi.useFakeTimers();
    const parent = new AbortController();
    await expect(
      withDeadline(parent.signal, 5000, async () => {
        parent.abort();
        return 'late';
      }),
    ).rejects.toThrow();
    expect(vi.getTimerCount()).toBe(0);
  });
  it('allows repeated fast operations without accumulating timeout resources', async () => {
    vi.useFakeTimers();
    const parent = new AbortController();
    for (let i = 0; i < 10_010; i++) await withDeadline(parent.signal, 5000, async () => i);
    expect(vi.getTimerCount()).toBe(0);
  });
});
