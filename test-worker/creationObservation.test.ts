import { afterEach, describe, expect, it, vi } from 'vitest';
import { encodeAbiParameters } from 'viem';
import { reconcileCreationObservation } from '../src/creation/creationObservation';
import { creationReceiptScenario } from '@gatopago/test-fixtures/v3-creation-receipt';
import { fixtureHash } from '@gatopago/test-fixtures/v3-inspection';

type Rpc = { id: number; method: string; params: readonly unknown[] };
function scenario() {
	const f = creationReceiptScenario();
	const configuration = { profileDocument: f.input.document, transport: { kind: 'bundler' as const, url: 'https://bundler.invalid/' }, providers: [
		{ operatorId: 'provider_a', url: 'https://observer-a.invalid/' }, { operatorId: 'provider_b', url: 'https://observer-b.invalid/' },
	] };
	const calls: { url: string; request: Rpc }[] = [];
	const hint = vi.fn((): unknown => ({ userOpHash: f.signed.userOpHash, success: false, actualGasCost: '0xffff', receipt: f.receipt }));
	const reply = vi.fn(async (_url: string, request: Rpc): Promise<unknown> => f.request(request));
	const envelope = vi.fn((id: number, result: unknown) => Response.json({ jsonrpc: '2.0', id, result }));
	const fetch = vi.spyOn(globalThis, 'fetch').mockImplementation(async (url, init) => {
		init?.signal?.throwIfAborted();
		if (typeof init?.body !== 'string') throw new Error('Expected RPC body');
		const request: Rpc = JSON.parse(init.body);
		expect(init.redirect).toBe('manual'); expect(init.signal).toBeInstanceOf(AbortSignal);
		calls.push({ url: String(url), request });
		if (String(url) === 'https://bundler.invalid/') {
			expect(request.method).toBe('eth_getUserOperationReceipt'); expect(request.params).toEqual([f.signed.userOpHash]);
			return envelope(request.id, hint());
		}
		if (!['https://observer-a.invalid/', 'https://observer-b.invalid/'].includes(String(url))) throw new Error('Unexpected observer destination');
		return envelope(request.id, await reply(String(url), request));
	});
	const run = (known = false, signal = new AbortController().signal) => reconcileCreationObservation(f.signed, configuration, signal, known ? f.transactionHash : undefined);
	return { ...f, configuration, calls, fetch, hint, reply, envelope, run };
}
afterEach(() => { vi.restoreAllMocks(); });

describe('bounded independent observation in Workers', () => {
	it('ignores bundler success/fees and requires two complete execution-RPC observations', async () => {
		const f = scenario();
		expect(await f.run()).toMatchObject({ status: 'observed', finality: 'not_assessed', account_readiness: 'not_assessed',
			provider_ids: ['provider_a', 'provider_b'], observation: { outcome: 'creation_succeeded', actual_gas_cost: '12345' } });
		expect(f.calls.filter((call) => call.url === 'https://observer-a.invalid/')).toHaveLength(33);
		expect(f.calls.filter((call) => call.url === 'https://observer-b.invalid/')).toHaveLength(33);
		expect(f.hint).toHaveBeenCalledTimes(1);
		expect(f.calls.some((call) => call.request.method.startsWith('eth_send'))).toBe(false);
	});
	it('can verify a known transaction without a reachable bundler', async () => {
		const f = scenario(); f.hint.mockImplementation(() => { throw new Error('Provider disappeared'); });
		expect(await f.run(true)).toMatchObject({ status: 'observed' }); expect(f.hint).not.toHaveBeenCalled();
	});
	it('does not treat a missing hint as failure, expiry, permission to resend or account readiness', async () => {
		const f = scenario(); f.hint.mockReturnValue(null);
		expect(await f.run()).toEqual({ status: 'not_observed', transaction_hash: null, finality: 'not_assessed',
			account_readiness: 'not_assessed', provider_ids: ['provider_a', 'provider_b'] });
		expect(f.reply).not.toHaveBeenCalled();
	});
	it('rejects a hint for a different operation before consulting execution RPCs', async () => {
		const f = scenario(); f.hint.mockReturnValue({ userOpHash: fixtureHash('9'), receipt: f.receipt });
		expect(await f.run()).toMatchObject({ status: 'unavailable' }); expect(f.reply).not.toHaveBeenCalled();
	});
	it('does not turn two missing receipts into a new send', async () => {
		const f = scenario(); f.state.missing = true;
		expect(await f.run()).toMatchObject({ status: 'not_observed', transaction_hash: f.transactionHash });
		expect(f.reply).toHaveBeenCalledTimes(2);
	});
	it.each(['missing', 'fee', 'block'] as const)('fails closed when observers disagree on %s', async (fault) => {
		const f = scenario(), valid = f.reply.getMockImplementation()!;
		f.reply.mockImplementation(async (url, request) => {
			if (url === 'https://observer-b.invalid/' && request.method === 'eth_getTransactionReceipt') {
				if (fault === 'missing') return null;
				if (fault === 'block') return { ...f.receipt, blockHash: fixtureHash('9') };
				const logs = f.receipt.logs.map((log) => ({ ...log }));
				logs[4].data = encodeAbiParameters([{ type: 'uint256' }, { type: 'bool' }, { type: 'uint256' }, { type: 'uint256' }], [0n, true, 12346n, 123n]);
				return { ...f.receipt, logs };
			}
			return valid(url, request);
		});
		expect(await f.run()).toMatchObject({ status: fault === 'block' ? 'unavailable' : 'disagreement' });
	});
	it('awaits both observers and returns no provider secrets or old success if one fails', async () => {
		const f = scenario(); await f.run(); f.calls.length = 0;
		const valid = f.reply.getMockImplementation()!;
		f.reply.mockImplementation(async (url, request) => {
			if (url === 'https://observer-b.invalid/') throw new Error('https://secret.invalid/api-key');
			return valid(url, request);
		});
		const result = await f.run(); expect(result).toMatchObject({ status: 'unavailable' });
		expect(JSON.stringify(result)).not.toMatch(/secret|api-key|observation/);
		expect(f.calls.filter((call) => call.url === 'https://observer-a.invalid/')).toHaveLength(33);
	});
	it.each(['operator', 'hostname', 'count', 'url', 'pin'] as const)('rejects invalid %s configuration before any network I/O', async (fault) => {
		const f = scenario();
		if (fault === 'operator') f.configuration.providers[1].operatorId = f.configuration.providers[0].operatorId;
		if (fault === 'hostname') f.configuration.providers[1].url = f.configuration.providers[0].url + 'another-path';
		if (fault === 'count') f.configuration.providers.pop();
		if (fault === 'url') f.configuration.providers[0].url = 'http://observer-a.invalid/';
		if (fault === 'pin') f.configuration.profileDocument = '{}';
		await expect(f.run()).rejects.toThrow(); expect(f.fetch).not.toHaveBeenCalled();
	});
	it.each(['id', 'error', 'size'] as const)('bounds and validates the hint %s', async (fault) => {
		const f = scenario();
		f.envelope.mockImplementation((id, result) => {
			if (fault === 'size') return new Response('x'.repeat(262_145));
			if (fault === 'error') return Response.json({ jsonrpc: '2.0', id, result, error: { message: 'sensitive upstream failure' } });
			return Response.json({ jsonrpc: '2.0', id: id + 1, result });
		});
		expect(await f.run()).toMatchObject({ status: 'unavailable' }); expect(f.reply).not.toHaveBeenCalled();
	});
	it('cancellation has no external effect and never returns prior success', async () => {
		const f = scenario(), controller = new AbortController(); controller.abort();
		expect(await f.run(false, controller.signal)).toMatchObject({ status: 'unavailable' }); expect(f.fetch).not.toHaveBeenCalled();
	});
	it('detaches provider configuration before the first await', async () => {
		const f = scenario(), pending = f.run();
		f.configuration.providers[0].url = 'https://untrusted.invalid/'; f.configuration.providers[1].operatorId = 'different';
		f.configuration.profileDocument = '{}';
		expect(await pending).toMatchObject({ status: 'observed', provider_ids: ['provider_a', 'provider_b'] });
	});
});
