import { afterEach, describe, expect, it, vi } from 'vitest';
import { toHex } from 'viem';
import { creationInspectionScenario } from '@gatopago/test-fixtures/v3-creation-inspection';
import { createInspectionClient, inspectWalletCreationProfile } from '../src/chainInspection';
import { inspectionRpc } from '../src/inspectionRpc';
import { requireFreshCreationDeployment } from '../src/runtime/finality';
import { configureWalletNetworks } from '../src/runtime/config';
import { runtimeFixture } from './runtime.fixture';
import { rpcReply, type RpcRead } from './rpc.fixture';

afterEach(() => {
  vi.restoreAllMocks();
  vi.unstubAllGlobals();
  vi.useRealTimers();
});
const endpoint = 'https://rpc.example.test/private-fixture-key';
const options = { retryCount: 0, dedupe: false } as const;
const block = {
  method: 'eth_getBlockByNumber',
  params: ['0x64', false] as [`0x${string}`, boolean],
} as const;
const client = (signal = new AbortController().signal) =>
  createInspectionClient(endpoint, signal, true);

describe('bounded inspection JSON-RPC batches', () => {
  it('sends independent reads in one HTTP request and correlates reversed response IDs', async () => {
    const fetch = vi.fn(async (_url, init) => {
      const rows = JSON.parse(String(init.body)) as RpcRead[];
      return Response.json(
        rows
          .map((row) => ({
            jsonrpc: '2.0',
            id: row.id,
            result: row.method === 'eth_chainId' ? '0x1' : { hash: 'synthetic' },
          }))
          .reverse(),
      );
    });
    vi.stubGlobal('fetch', fetch);
    const rpc = client();
    expect(
      await Promise.all([
        rpc.request({ method: 'eth_chainId' }, options),
        rpc.request(block, options),
      ]),
    ).toEqual(['0x1', { hash: 'synthetic' }]);
    expect(fetch).toHaveBeenCalledTimes(1);
  });

  it('deduplicates only pending identical reads; closing checks and later invocations are fresh', async () => {
    const fetch = vi.fn(async (_url, init) => rpcReply(init, async () => ({ hash: 'fresh' })));
    vi.stubGlobal('fetch', fetch);
    const rpc = client();
    await Promise.all([rpc.request(block, options), rpc.request(block, options)]);
    expect(fetch).toHaveBeenCalledTimes(1);
    await rpc.request(block, options);
    await client().request(block, options);
    expect(fetch).toHaveBeenCalledTimes(3);
  });

  it('does not combine or reuse observations from different providers', async () => {
    const fetch = vi.fn(async (url, init) => rpcReply(init, async () => String(url)));
    vi.stubGlobal('fetch', fetch);
    const other = createInspectionClient(
      'https://independent.example.test/',
      new AbortController().signal,
      true,
    );
    const results = await Promise.all([
      client().request(block, options),
      other.request(block, options),
    ]);
    expect(new Set(results).size).toBe(2);
    expect(fetch).toHaveBeenCalledTimes(2);
  });

  it.each([
    'missing',
    'duplicate',
    'foreign-id',
    'error',
    'both',
    'version',
    'single-envelope',
  ] as const)('rejects the entire %s batch without retrying or falling back', async (fault) => {
    const fetch = vi.fn(async (_url, init) => {
      const requests = JSON.parse(String(init.body)) as RpcRead[];
      const rows: object[] = requests.map((row) => ({ jsonrpc: '2.0', id: row.id, result: '0x1' }));
      if (fault === 'missing') rows.pop();
      if (fault === 'duplicate') rows[1] = rows[0];
      if (fault === 'foreign-id') rows[1] = { jsonrpc: '2.0', id: 99, result: '0x1' };
      if (fault === 'error')
        rows[1] = {
          jsonrpc: '2.0',
          id: requests[1].id,
          error: { message: 'private-provider-key' },
        };
      if (fault === 'both') rows[1] = { ...rows[1], error: {} };
      if (fault === 'version') rows[1] = { ...rows[1], jsonrpc: '1.0' };
      return Response.json(fault === 'single-envelope' ? rows[0] : rows);
    });
    vi.stubGlobal('fetch', fetch);
    const rpc = client();
    const settled = await Promise.allSettled([
      rpc.request({ method: 'eth_chainId' }, options),
      rpc.request(block, options),
    ]);
    expect(settled.every((row) => row.status === 'rejected')).toBe(true);
    expect(JSON.stringify(settled)).not.toContain('private-provider-key');
    expect(fetch).toHaveBeenCalledTimes(1);
  });

  it('sends no queued request after cancellation and refuses write methods', async () => {
    const fetch = vi.fn();
    vi.stubGlobal('fetch', fetch);
    const abort = new AbortController();
    const rpc = inspectionRpc(endpoint, abort.signal, true);
    const reading = rpc.request({ method: 'eth_chainId' });
    abort.abort();
    await expect(reading).rejects.toThrow();
    await expect(
      inspectionRpc(endpoint, new AbortController().signal, true).request({
        method: 'eth_sendRawTransaction',
      }),
    ).rejects.toThrow('read-only');
    expect(fetch).not.toHaveBeenCalled();
  });

  it('snapshots delayed parameters and caps a batch at 32 unique requests', async () => {
    const fetch = vi.fn(async (_url, init) => rpcReply(init, async (read) => read.params));
    vi.stubGlobal('fetch', fetch);
    const rpc = inspectionRpc(endpoint, new AbortController().signal, true);
    const params = ['0x64', false];
    const first = rpc.request({ method: 'eth_getBlockByNumber', params });
    params[0] = 'latest';
    expect(await first).toEqual(['0x64', false]);
    const reads = Array.from({ length: 33 }, (_, i) =>
      rpc.request({ method: 'eth_getBlockByNumber', params: [toHex(i), false] }),
    );
    const settled = await Promise.allSettled(reads);
    expect(settled.filter((row) => row.status === 'rejected')).toHaveLength(1);
    expect(fetch).toHaveBeenCalledTimes(2);
    expect(JSON.parse(String(fetch.mock.calls[1][1].body))).toHaveLength(32);
  });

  it('cancels an oversized batched response without falling back to individual requests', async () => {
    let cancelled = false;
    const fetch = vi.fn(
      async () =>
        new Response(
          new ReadableStream<Uint8Array>({
            start(controller) {
              controller.enqueue(new Uint8Array(524_289));
            },
            cancel() {
              cancelled = true;
            },
          }),
        ),
    );
    vi.stubGlobal('fetch', fetch);
    const rpc = client();
    const result = await Promise.allSettled([
      rpc.request({ method: 'eth_chainId' }, options),
      rpc.request(block, options),
    ]);
    expect(result.every((row) => row.status === 'rejected')).toBe(true);
    expect(cancelled).toBe(true);
    expect(fetch).toHaveBeenCalledTimes(1);
  });
});

describe('creation preflight Free-plan HTTP budget', () => {
  function fixture() {
    const inspection = creationInspectionScenario();
    const now = Math.floor(Date.now() / 1000);
    const settings = runtimeFixture({
      document: inspection.input.document,
      digest: inspection.input.expectedDigest,
    });
    const [network] = configureWalletNetworks(
      settings.catalog,
      settings.environment,
      settings.bindings,
    );
    const read = async (request: RpcRead) => {
      if (request.method !== 'eth_getBlockByNumber') return inspection.request(request);
      if (request.params[0] === '0x0')
        return { number: '0x0', hash: inspection.state.genesis, timestamp: '0x0' };
      return {
        number: request.params[0] === 'latest' ? '0x65' : '0x64',
        hash: inspection.state.blockHash,
        timestamp: toHex(now - 20),
      };
    };
    const fetch = vi.fn(async (_url, init) => rpcReply(init, read));
    vi.stubGlobal('fetch', fetch);
    return { inspection, network, read, fetch };
  }

  it('performs the same full two-provider preflight with 22 HTTP requests instead of 76', async () => {
    const f = fixture();
    await requireFreshCreationDeployment(f.network, new AbortController().signal);
    expect(f.fetch).toHaveBeenCalledTimes(22);
    for (const url of f.network.providers.map((provider) => provider.url)) {
      expect(f.fetch.mock.calls.filter(([value]) => value === url)).toHaveLength(11);
    }
    expect(
      f.inspection.request.mock.calls.filter(([request]) => request.method === 'eth_getCode'),
    ).toHaveLength(14);
    expect(
      f.inspection.request.mock.calls.filter(([request]) => request.method === 'eth_call'),
    ).toHaveLength(36);
  });

  it('still refuses disagreement between the providers', async () => {
    const f = fixture();
    f.fetch.mockImplementation(async (url, init) =>
      rpcReply(init, async (request) => {
        const result = await f.read(request);
        return String(url).includes('observer-b') &&
          request.method === 'eth_getBlockByNumber' &&
          request.params[0] !== '0x0'
          ? { ...(result as object), hash: `0x${'aa'.repeat(32)}` }
          : result;
      }),
    );
    await expect(
      requireFreshCreationDeployment(f.network, new AbortController().signal),
    ).rejects.toThrow('RUNTIME_FINALITY_UNAVAILABLE');
  });

  it('rechecks the checkpoint after the getters instead of trusting the initial batch', async () => {
    const f = fixture();
    f.fetch.mockImplementation(async (_url, init) =>
      rpcReply(init, async (request) => {
        const result = await f.read(request);
        if (request.method === 'eth_call') f.inspection.state.blockHash = `0x${'ee'.repeat(32)}`;
        return result;
      }),
    );
    await expect(
      inspectWalletCreationProfile(f.inspection.input, endpoint, new AbortController().signal),
    ).rejects.toMatchObject({ code: 'CHECKPOINT_MISMATCH' });
    expect(f.fetch).toHaveBeenCalledTimes(6);
  });
});
