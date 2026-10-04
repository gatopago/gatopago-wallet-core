import { afterEach, describe, expect, it, vi } from 'vitest';
import { inspectFinalizedWalletSecurity } from '../src/finalizedSecurityInspection';
import { finalizedSecurityScenario } from '@gatopago/test-fixtures/v3-security-inspection';
import { fixtureHash } from '@gatopago/test-fixtures/v3-inspection';
import { finalityPin, finalityPolicyFixture } from '@gatopago/test-fixtures/v3-finality';

afterEach(() => {
  vi.restoreAllMocks();
  vi.unstubAllGlobals();
});
function scenario() {
  const first = finalizedSecurityScenario();
  const clock = vi.spyOn(Date, 'now').mockReturnValue(first.now * 1000);
  const second = finalizedSecurityScenario(first.now);
  const fetch = vi.fn(async (url: RequestInfo | URL, init?: RequestInit) => {
    init?.signal?.throwIfAborted();
    const body = JSON.parse(String(init?.body)) as {
      id: number;
      method: string;
      params?: readonly unknown[];
    };
    const provider = String(url).includes('first.') ? first : second;
    return Response.json({ jsonrpc: '2.0', id: body.id, result: await provider.request(body) });
  });
  vi.stubGlobal('fetch', fetch);
  return {
    ...first,
    first,
    second,
    clock,
    fetch,
    run: (signal = new AbortController().signal) =>
      inspectFinalizedWalletSecurity(first.input, signal),
  };
}

describe('recent finalized security → authenticated account inspection', () => {
  it('reads the common checkpoint, not the original receipt, and revalidates finality afterwards', async () => {
    const f = scenario(),
      result = await f.run();
    expect(result).toMatchObject({
      finality: 'finalized',
      providers_agree: true,
      spend_readiness: 'not_assessed',
      checkpoint: f.input.checkpoint,
      security: { phase: 'active_policy' },
      security_expires_at: f.source.expires_at,
      finality_evidence: { status: 'finalized', target: f.source.checkpoint },
    });
    expect(f.fetch).toHaveBeenCalledTimes(48);
    for (const [request] of f.first.request.mock.calls)
      if (request.method === 'eth_call' || request.method === 'eth_getCode') {
        expect(request.params?.[1]).toEqual({
          blockHash: f.source.checkpoint!.block_hash,
          requireCanonical: true,
        });
      }
    expect(result).not.toHaveProperty('receive_enabled', true);
  });
  it('cannot extend the original evidence TTL with the closing assessment', async () => {
    const f = scenario();
    Object.assign(f.source, { assessed_at: f.now - 20, expires_at: f.now + 10 });
    expect(await f.run()).toMatchObject({
      security_expires_at: f.now + 10,
      finality_evidence: { expires_at: f.now + 30 },
    });
  });
  it.each([
    { expires_at: 0 },
    { expires_at: 1 },
    { assessed_at: Number.MAX_SAFE_INTEGER },
    { policy_sha256: fixtureHash('e') },
    { mechanism: 'ethereum_finalized' },
    { network_id: 'eip155:1' },
    { genesis_hash: fixtureHash('f') },
    { checkpoint: null },
  ])('rejects invalid, stale or mismatched source evidence before RPC (%#)', async (patch) => {
    const f = scenario();
    Object.assign(f.source, patch);
    await expect(f.run()).rejects.toThrow();
    expect(f.fetch).not.toHaveBeenCalled();
  });
  it.each(['pending', 'stale', 'disagreement', 'reorg_detected', 'unavailable'] as const)(
    'never upgrades %s source evidence to usable security',
    async (status) => {
      const f = scenario();
      Object.assign(
        f.source,
        status === 'pending'
          ? {
              status,
              target: {
                block_number: '101',
                block_hash: fixtureHash('c'),
                block_timestamp: String(f.now),
              },
            }
          : { status, checkpoint: null, expires_at: f.source.assessed_at },
      );
      await expect(f.run()).rejects.toThrow();
      expect(f.fetch).not.toHaveBeenCalled();
    },
  );
  it('rejects an overlong source TTL even though the generic shape permits 60 seconds', async () => {
    const f = scenario();
    Object.assign(f.source, { expires_at: f.now + 60 });
    await expect(f.run()).rejects.toThrow('SECURITY_FINALITY_UNUSABLE');
    expect(f.fetch).not.toHaveBeenCalled();
  });
  it('rejects source evidence assessed before the pinned policy became valid', async () => {
    const f = scenario();
    const policy = finalityPolicyFixture(f.source, f.now);
    policy.valid_from = f.now - 5;
    Object.assign(f.pin, finalityPin(policy));
    // Still within TTL: this must fail because assessment predates this policy,
    // not because the evidence itself has already expired.
    Object.assign(f.source, {
      policy_sha256: f.pin.digest,
      assessed_at: f.now - 10,
      expires_at: f.now + 20,
    });
    await expect(f.run()).rejects.toThrow('SECURITY_FINALITY_UNUSABLE');
    expect(f.fetch).not.toHaveBeenCalled();
  });
  it.each([-3601, 6])('rejects an aged/future common checkpoint (%i seconds)', async (offset) => {
    const f = scenario();
    Object.assign(f.source, {
      target: { ...f.source.checkpoint, block_timestamp: String(f.now + offset) },
      checkpoint: { ...f.source.checkpoint, block_timestamp: String(f.now + offset) },
    });
    await expect(f.run()).rejects.toThrow('SECURITY_FINALITY_UNUSABLE');
    expect(f.fetch).not.toHaveBeenCalled();
  });
  it('rejects source expiry during account reads before starting the finality stage', async () => {
    const f = scenario(),
      original = f.first.request.getMockImplementation()!;
    f.first.request.mockImplementation(async (request) => {
      const value = await original(request);
      f.clock.mockReturnValue(f.source.expires_at * 1000);
      return value;
    });
    await expect(f.run()).rejects.toThrow('SECURITY_FINALITY_UNUSABLE');
    expect(f.first.request.mock.calls.some(([r]) => r.params?.[0] === 'finalized')).toBe(false);
  });
  it('does not prefer usable account state when a finality RPC fails', async () => {
    const f = scenario(),
      original = f.first.request.getMockImplementation()!;
    f.first.request.mockImplementation(async (request) => {
      if (request.params?.[0] === 'finalized') throw new Error('private-provider-token');
      return original(request);
    });
    await expect(f.run()).rejects.toThrow('SECURITY_FINALITY_UNUSABLE');
    expect(f.second.request.mock.calls.some(([r]) => r.params?.[0] === 'latest')).toBe(true);
  });
  it('rejects a checkpoint that both providers replace after security reads', async () => {
    const f = scenario();
    for (const provider of [f.first, f.second]) {
      const original = provider.request.getMockImplementation()!;
      provider.request.mockImplementation(async (request) => {
        if (request.params?.[0] === 'finalized') provider.chain.finalizedHash = fixtureHash('d');
        return original(request);
      });
    }
    await expect(f.run()).rejects.toThrow('SECURITY_FINALITY_UNUSABLE');
  });
  it('does not renew source evidence that expires during closing finality reads', async () => {
    const f = scenario(),
      original = f.first.request.getMockImplementation()!;
    f.first.request.mockImplementation(async (request) => {
      const value = await original(request);
      if (request.params?.[0] === 'finalized') f.clock.mockReturnValue(f.source.expires_at * 1000);
      return value;
    });
    await expect(f.run()).rejects.toThrow('SECURITY_FINALITY_UNUSABLE');
  });
  it('pins configuration across asynchronous reads and does not keep it in global state', async () => {
    const f = scenario(),
      operation = f.run();
    Object.assign(f.source, { expires_at: 0, checkpoint: null });
    Object.assign(f.input, {
      expectedDigest: fixtureHash('e'),
      rpcUrls: ['https://other.example.test'],
    });
    expect(await operation).toMatchObject({
      finality: 'finalized',
      checkpoint: f.first.input.checkpoint,
    });
    await expect(f.run()).rejects.toThrow();
  });
  it('preserves not-deployed without inventing a policy or readiness', async () => {
    const f = scenario();
    f.first.state.deployed = false;
    f.second.state.deployed = false;
    const result = await f.run();
    expect(result).toMatchObject({ status: 'not_deployed', spend_readiness: 'not_assessed' });
    expect(result).not.toHaveProperty('security');
  });
  it('rejects pre-cancellation before RPC', async () => {
    const f = scenario(),
      abort = new AbortController();
    abort.abort();
    await expect(f.run(abort.signal)).rejects.toThrow();
    expect(f.fetch).not.toHaveBeenCalled();
  });
  it('rejects altered finality policy bytes instead of treating source shape as admission', async () => {
    const f = scenario();
    Object.assign(f.pin, { document: f.pin.document + ' ' });
    await expect(f.run()).rejects.toThrow('Finality policy pin mismatch');
    expect(f.fetch).not.toHaveBeenCalled();
  });
});
