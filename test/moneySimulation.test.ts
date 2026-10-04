import { afterEach, describe, expect, it, vi } from 'vitest';
import { formatUserOperationRequest } from 'viem/account-abstraction';
import { readMoneyReview, writeMoneyReview } from '@gatopago/shared/v3/money-review-record';
import { simulateMoneyOperation } from '../src/money/moneySimulation';
import { createMoneyFixture } from './money.fixture';

afterEach(() => {
  vi.unstubAllGlobals();
  vi.restoreAllMocks();
});
async function fixture(fault = '') {
  const f = createMoneyFixture(),
    signed = writeMoneyReview({
      ...f.review,
      approved_at: f.now,
      proofs: [
        { signerIndex: 0, kind: 'webauthn', assertion: f.keys.assertion(f.candidate.digest) },
      ],
    });
  const record = await readMoneyReview(signed.json, signed.digest),
    clock = vi.spyOn(Date, 'now').mockReturnValue((f.now + 1) * 1000);
  const methods: string[] = [];
  vi.stubGlobal(
    'fetch',
    vi.fn(async (_url: RequestInfo | URL, init?: RequestInit) => {
      const call = JSON.parse(String(init?.body));
      methods.push(call.method);
      expect(init?.redirect).toBe('manual');
      expect(init?.signal).toBeDefined();
      let result;
      if (call.method === 'eth_chainId') result = fault === 'chain' ? '0x1' : '0x66eee';
      else if (call.method === 'eth_supportedEntryPoints')
        result = fault === 'entrypoint' ? [] : [record.candidate.plan.entryPoint];
      else if (call.method === 'eth_estimateUserOperationGas') {
        expect(call.params).toEqual([
          formatUserOperationRequest(record.operation),
          record.candidate.plan.entryPoint,
        ]);
        result = {
          verificationGasLimit: fault === 'gas' ? '0x65' : '0x64',
          callGasLimit: '0x64',
          preVerificationGas: '0x64',
          ...(fault === 'paymaster' ? { paymasterPostOpGasLimit: '0x1' } : {}),
        };
        if (fault === 'expired') clock.mockReturnValue(record.candidate.plan.validUntil * 1000);
        if (fault === 'clock-back') clock.mockReturnValue((f.now - 1) * 1000);
      } else throw new Error('Simulation must never send');
      return Response.json({ jsonrpc: '2.0', id: call.id, result });
    }),
  );
  return {
    f,
    record,
    methods,
    run: (signal = new AbortController().signal) =>
      simulateMoneyOperation(
        record,
        { kind: 'bundler', url: 'https://bundler.example/rpc' },
        signal,
      ),
  };
}
describe('Monetary simulation preserves the approved operation', () => {
  it('uses the exact signed calls and gas caps; grants no delivery authority', async () => {
    const s = await fixture(),
      original = structuredClone(s.record.operation);
    expect(await s.run()).toMatchObject({
      userop_hash: s.record.candidate.userOpHash,
      consent_digest: s.record.candidate.digest,
      gas: { verificationGasLimit: '100', callGasLimit: '100', preVerificationGas: '100' },
      observed_at: s.f.now + 1,
      expires_at: s.f.now + 6,
      send_enabled: false,
    });
    expect(s.record.operation).toEqual(original);
    expect(s.methods).toEqual([
      'eth_chainId',
      'eth_supportedEntryPoints',
      'eth_estimateUserOperationGas',
    ]);
  });
  it.each(['chain', 'entrypoint', 'gas', 'paymaster', 'expired', 'clock-back'])(
    'rejects %s without sending or increasing limits',
    async (fault) => {
      const s = await fixture(fault);
      await expect(s.run()).rejects.toThrow();
      expect(s.methods).not.toContain('eth_sendUserOperation');
    },
  );
  it('cancels before contacting a provider', async () => {
    const s = await fixture();
    await expect(s.run(AbortSignal.abort())).rejects.toThrow();
    expect(s.methods).toEqual([]);
  });
});
