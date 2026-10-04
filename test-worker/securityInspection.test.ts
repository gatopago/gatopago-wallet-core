import { afterEach, describe, expect, it, vi } from 'vitest';
import { inspectWalletSecurity } from '../src/chainInspection';
import { securityInspectionScenario } from '@gatopago/test-fixtures/v3-security-inspection';

const endpoints = ['https://first.example.test', 'https://second.example.test'] as const;
function mockProviders(
  first = securityInspectionScenario(),
  second = securityInspectionScenario(),
) {
  const mock = vi.fn(async (url: RequestInfo | URL, init?: RequestInit) => {
    const body = JSON.parse(String(init?.body)) as {
      id: number;
      method: string;
      params?: readonly unknown[];
    };
    const fixture = String(url).startsWith(endpoints[0]) ? first : second;
    return Response.json({ jsonrpc: '2.0', id: body.id, result: await fixture.request(body) });
  });
  vi.stubGlobal('fetch', mock);
  return { first, second, mock };
}
afterEach(() => {
  vi.restoreAllMocks();
  vi.unstubAllGlobals();
  vi.useRealTimers();
});

describe('Bounded independent current-security observations', () => {
  it('requires both full results, with no shared-state cache or spend permission', async () => {
    const t = mockProviders();
    const result = await inspectWalletSecurity(
      t.first.input,
      endpoints,
      new AbortController().signal,
    );
    expect(result).toMatchObject({
      providers_agree: true,
      spend_readiness: 'not_assessed',
      security: { phase: 'active_policy' },
    });
    expect(t.mock).toHaveBeenCalledTimes(32);
    await inspectWalletSecurity(t.first.input, endpoints, new AbortController().signal);
    expect(t.mock).toHaveBeenCalledTimes(64);
  });
  it.each(['adminNonce', 'spendNonce'] as const)(
    'rejects provider disagreement about %s',
    async (key) => {
      const t = mockProviders();
      t.second.security[key] += 1n;
      await expect(
        inspectWalletSecurity(t.first.input, endpoints, new AbortController().signal),
      ).rejects.toThrow('SECURITY_OBSERVATIONS_DISAGREE');
      expect(t.mock).toHaveBeenCalledTimes(32);
    },
  );
  it('does not prefer an active result over a frozen result', async () => {
    const t = mockProviders();
    t.second.security.flags = 3n;
    await expect(
      inspectWalletSecurity(t.first.input, endpoints, new AbortController().signal),
    ).rejects.toThrow('SECURITY_OBSERVATIONS_DISAGREE');
  });
  it.each([
    { urls: [] },
    { urls: [endpoints[0]] },
    { urls: [endpoints[0], endpoints[0] + '/another-key'] },
    { urls: [...endpoints, 'https://third.example.test'] },
    { urls: [endpoints[0], 'http://second.example.test'] },
  ])(
    'rejects invalid or accidentally duplicated RPC configuration %# before I/O',
    async ({ urls }) => {
      const t = mockProviders();
      await expect(
        inspectWalletSecurity(t.first.input, urls, new AbortController().signal),
      ).rejects.toThrow();
      expect(t.mock).not.toHaveBeenCalled();
    },
  );
  it('waits for the sibling provider even when the other rejects, with redacted diagnostics', async () => {
    const t = mockProviders();
    t.first.request.mockRejectedValue(new Error('private rpc credential'));
    await expect(
      inspectWalletSecurity(t.first.input, endpoints, new AbortController().signal),
    ).rejects.toThrow('RPC_UNAVAILABLE');
    expect(t.second.request).toHaveBeenCalledTimes(16);
  });
  it('does not issue I/O for a pre-cancelled observation', async () => {
    const t = mockProviders(),
      abort = new AbortController();
    abort.abort();
    await expect(inspectWalletSecurity(t.first.input, endpoints, abort.signal)).rejects.toThrow();
    expect(t.mock).not.toHaveBeenCalled();
  });
  it('aborts stalled providers at the per-call timeout and drains both requests', async () => {
    const t = mockProviders();
    let cancelled = 0;
    t.mock.mockImplementation(
      (_url, init) =>
        new Promise((_resolve, reject) => {
          init?.signal?.addEventListener(
            'abort',
            () => {
              cancelled++;
              reject(new Error('request cancelled'));
            },
            { once: true },
          );
        }),
    );
    const check = expect(
      inspectWalletSecurity(t.first.input, endpoints, new AbortController().signal),
    ).rejects.toThrow('RPC_UNAVAILABLE');
    await check;
    expect(cancelled).toBe(2);
  }, 15000);
});
