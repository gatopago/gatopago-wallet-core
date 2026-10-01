import { afterEach, describe, expect, it, vi } from 'vitest';
import { formatUserOperationRequest } from 'viem/account-abstraction';
import { authorizeTransferOperation } from '@gatopago/shared/v3/transfer-authorization';
import { readTransferReview, writeTransferReview } from '@gatopago/shared/v3/transfer-review-record';
import { simulateTransferOperation } from '../src/transfers/transferSimulation';
import { transferFixture } from '@gatopago/test-fixtures/v3-transfer';

afterEach(() => { vi.unstubAllGlobals(); vi.restoreAllMocks(); });
async function fixture(fault = '') {
  const f = transferFixture(), signed = await authorizeTransferOperation(f.request, f.context, f.approval, await f.proofs(), () => f.now + 1);
  const saved = writeTransferReview(signed.consent_review), record = await readTransferReview(saved.json, saved.digest);
  const clock = vi.spyOn(Date, 'now').mockReturnValue((f.now + 2) * 1000);
  const requests: { method: string; params: unknown[] }[] = [];
  const fetcher = vi.fn(async (_url: RequestInfo | URL, init?: RequestInit) => {
    const call: { id: number; method: string; params: unknown[] } = JSON.parse(String(init?.body)); requests.push(call);
    expect(init?.redirect).toBe('manual'); expect(init?.signal).toBeDefined();
    if (fault === 'http') return new Response(null, { status: 503 });
    if (fault === 'oversized') return new Response(' '.repeat(16_385));
    let result: unknown;
    if (call.method === 'eth_chainId') result = fault === 'chain' ? '0x1' : '0x14a34';
    else if (call.method === 'eth_supportedEntryPoints') result = fault === 'entrypoint' ? [] : [record.candidate.plan.entryPoint];
    else if (call.method === 'eth_estimateUserOperationGas') {
      expect(call.params).toEqual([formatUserOperationRequest(record.operation), record.candidate.plan.entryPoint]);
      result = { verificationGasLimit: fault === 'gas' ? '0x65' : '0x64', callGasLimit: fault === 'zero' ? '0x0' : '0x64',
        preVerificationGas: fault === 'malformed' ? '100' : '0x64',
        ...(fault === 'paymaster' ? { paymasterPostOpGasLimit: '0x1' } : {}) };
      if (fault === 'expired') clock.mockReturnValue(record.candidate.plan.validUntil * 1000);
      if (fault === 'clock-back') clock.mockReturnValue(f.now * 1000);
    } else throw new Error('Unexpected method: simulation must not send');
    return Response.json({ jsonrpc: '2.0', id: fault === 'id' ? call.id + 1 : call.id, result,
      ...(fault === 'rpc-error' ? { error: { code: -32500, message: 'rejected' } } : {}) });
  });
  vi.stubGlobal('fetch', fetcher);
  return { f, record, requests, fetcher, run: (signal = new AbortController().signal) => simulateTransferOperation(record, { kind: 'bundler', url: 'https://bundler.example/rpc' }, signal) };
}

describe('Signed transfer bundler simulation, without delivery authority', () => {
  it('submits exact bytes and returns a bounded observation, never a send', async () => {
    const f = await fixture(), before = structuredClone(f.record.operation), result = await f.run();
    expect(result).toMatchObject({ userop_hash: f.record.candidate.userOpHash, consent_digest: f.record.candidate.digest,
      gas: { verificationGasLimit: '100', callGasLimit: '100', preVerificationGas: '100' }, send_enabled: false,
      observed_at: f.f.now + 2, expires_at: f.f.now + 7 });
    expect(result.operation_sha256).toMatch(/^0x[0-9a-f]{64}$/);
    expect(f.record.operation).toEqual(before);
    expect(f.requests.map(r => r.method)).toEqual(['eth_chainId', 'eth_supportedEntryPoints', 'eth_estimateUserOperationGas']);
  });
  it.each(['chain', 'entrypoint', 'gas', 'zero', 'malformed', 'paymaster', 'expired', 'clock-back', 'http', 'oversized', 'id', 'rpc-error'])(
    'rejects %s without retrying or sending', async fault => {
      const f = await fixture(fault);
      await expect(f.run()).rejects.toThrow();
      expect(f.requests.length).toBeLessThanOrEqual(3);
      expect(f.requests.some(r => r.method === 'eth_sendUserOperation')).toBe(false);
    });
  it('rejects cancellation before any RPC', async () => {
    const f = await fixture(), controller = new AbortController(); controller.abort();
    await expect(f.run(controller.signal)).rejects.toThrow(); expect(f.fetcher).not.toHaveBeenCalled();
  });
});
