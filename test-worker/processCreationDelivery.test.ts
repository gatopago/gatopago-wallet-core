import { env } from 'cloudflare:workers';
import { applyD1Migrations } from 'cloudflare:test';
import { afterEach, beforeAll, beforeEach, describe, expect, it, vi } from 'vitest';
import { toHex, keccak256, parseTransaction, type Hex } from 'viem';
import { privateKeyToAccount } from 'viem/accounts';
import type { OperationTransport } from '../src/execution/operationTransport';
import { formatUserOperationRequest } from 'viem/account-abstraction';
import { CreationDeliveryRepository } from '../src/creation/creationDelivery';
import { processCreationDelivery } from '../src/creation/processCreationDelivery';
import { creationInspectionScenario } from '@gatopago/test-fixtures/v3-creation-inspection';
import { fixtureAddress, fixtureHash } from '@gatopago/test-fixtures/v3-inspection';
import { cleanCreationDelivery, creationGas, deliveryNow, deliveryOutbox, seedCreationDelivery } from './creationDelivery.fixture';
import { rpcReply } from '../test/rpc.fixture';

type Rpc = { jsonrpc: string; id: number; method: string; params: readonly unknown[] };
async function scenario() {
	const inspection = creationInspectionScenario();
	const f = await seedCreationDelivery(undefined, { document: inspection.input.document, digest: inspection.input.expectedDigest });
	const configuration = { ...f.configuration, networks: [{ ...f.configuration.profiles[0],
		checkpoint: { ...inspection.input.checkpoint }, rpcUrl: 'https://inspection.invalid/', transport: { kind: 'bundler' as const, url: 'https://bundler.invalid/' } }] };
	const calls: { url: string; request: Rpc }[] = [];
	const bundler = vi.fn(async (request: Rpc): Promise<unknown> => {
		if (request.method === 'eth_chainId') return toHex(f.signed.prepared.chainId);
		if (request.method === 'eth_supportedEntryPoints') return [f.signed.prepared.message.entryPoint];
		if (request.method === 'eth_estimateUserOperationGas') return { verificationGasLimit: toHex(creationGas().verificationGasLimit),
			callGasLimit: toHex(creationGas().callGasLimit), preVerificationGas: toHex(creationGas().preVerificationGas) };
		if (request.method === 'eth_sendUserOperation') return f.signed.userOpHash;
		throw new Error('Unexpected bundler method');
	});
	const envelope = vi.fn((request: Rpc, result: unknown) => Response.json({ jsonrpc: '2.0', id: request.id, result }));
	const fetch = vi.spyOn(globalThis, 'fetch').mockImplementation(async (url, init) => {
		init?.signal?.throwIfAborted();
		if (typeof init?.body !== 'string') throw new Error('Expected RPC body');
		if (String(url) === 'https://inspection.invalid/') return rpcReply(init, async request => {
			calls.push({ url: String(url), request: { ...request, jsonrpc: '2.0' } });
			return inspection.request(request);
		});
		const request: Rpc = JSON.parse(init.body);
		calls.push({ url: String(url), request });
		expect(init.method).toBe('POST'); expect(init.redirect).toBe('manual'); expect(init.signal).toBeInstanceOf(AbortSignal);
		if (String(url) === 'https://bundler.invalid/') return envelope(request, await bundler(request));
		throw new Error('Unexpected network destination');
	});
	const run = (signal = new AbortController().signal) => processCreationDelivery(env.WALLET_DB, f.id, configuration, signal);
	const sends = () => calls.filter(({ request }) => request.method === 'eth_sendUserOperation');
	return { ...f, inspection, configuration, calls, bundler, envelope, fetch, run, sends };
}
beforeAll(async () => { await applyD1Migrations(env.WALLET_DB, env.V3_TEST_MIGRATIONS); });
beforeEach(async () => { vi.spyOn(Date, 'now').mockReturnValue(deliveryNow() * 1000); await cleanCreationDelivery(); });
afterEach(async () => { vi.restoreAllMocks(); await cleanCreationDelivery(); });

describe('exact first UserOperation transport with D1 send boundary', () => {
	it('inspects original composition and sends exactly once across eight parallel deliveries', async () => {
		const f = await scenario();
		const results = await Promise.all(Array.from({ length: 8 }, () => f.run()));
		expect(results.filter((result) => result === 'accepted')).toHaveLength(1);
		expect(results.filter((result) => result === 'idle')).toHaveLength(7);
		expect(f.inspection.request).toHaveBeenCalledTimes(29);
		expect(f.bundler).toHaveBeenCalledTimes(4);
		expect(f.sends()).toHaveLength(1);
		const exact = [formatUserOperationRequest(f.signed.operation), f.signed.prepared.message.entryPoint];
		expect(f.sends()[0].request.params).toEqual(exact);
		expect(f.calls.find(({ request }) => request.method === 'eth_estimateUserOperationGas')?.request.params).toEqual(exact);
		expect(await f.operations.read(f.id)).toMatchObject({ delivery_state: 'accepted', deployment_assessment: 'not_assessed', receive_enabled: false, spend_enabled: false });
		expect(await f.run()).toBe('idle'); expect(f.sends()).toHaveLength(1);
	});
	it('delivers creation through the Worker relayer after the same durable grant', async () => {
    const f = await scenario(), key = `0x${'23'.repeat(32)}` as Hex, operator = privateKeyToAccount(key).address;
    const transport: OperationTransport = { kind: 'self', url: 'https://relay-a.invalid/',
      providers: [{ operatorId: 'relay-a', url: 'https://relay-a.invalid/' }, { operatorId: 'relay-b', url: 'https://relay-b.invalid/' }],
      policy: { networkId: `eip155:${f.signed.prepared.chainId}`, operator, maxGas: 3000000n,
        maxFeePerGas: 1000000000n, maxPriorityFeePerGas: 0n, maxExecutionFee: 3000000000000000n } };
    const original = f.fetch.getMockImplementation()!, sent: Hex[] = [];
    f.fetch.mockImplementation(async (url, init) => {
      if (String(url) === 'https://inspection.invalid/') return original(url, init);
      const request = JSON.parse(String(init?.body));
      let result;
      switch (request.method) {
        case 'eth_chainId': result = toHex(f.signed.prepared.chainId); break;
        case 'eth_getTransactionCount': result = '0x0'; break;
        case 'eth_getCode': result = '0x'; break;
        case 'eth_getBalance': result = '0xde0b6b3a7640000'; break;
        case 'eth_estimateGas': result = '0x186a0'; break;
        case 'eth_sendRawTransaction':
          expect(await deliveryOutbox(f.id)).toMatchObject({ state: 'sending' });
          sent.push(request.params[0]); result = keccak256(request.params[0]); break;
        default: throw new Error('Unexpected relayer method');
      }
      return Response.json({ jsonrpc: '2.0', id: request.id, result });
    });
    const config = { ...f.configuration, relayerKey: key, networks: [{ ...f.configuration.networks[0], transport }] };
    expect(await processCreationDelivery(env.WALLET_DB, f.id, config, new AbortController().signal)).toBe('accepted');
    expect(sent).toHaveLength(1); expect(f.bundler).not.toHaveBeenCalled();
    expect(parseTransaction(sent[0]).to?.toLowerCase()).toBe(f.signed.prepared.message.entryPoint.toLowerCase());
    expect(await f.operations.read(f.id)).toMatchObject({ delivery_state: 'accepted', receive_enabled: false, spend_enabled: false });
  });
	it('never reaches a bundler when original factory/implementation composition is different', async () => {
		const f = await scenario();
		f.inspection.state.codes.set(f.inspection.profile.deployment.components.implementation.address, '0x6000');
		expect(await f.run()).toBe('deferred'); expect(f.bundler).not.toHaveBeenCalled();
		expect(await deliveryOutbox(f.id)).toMatchObject({ state: 'pending', lease_token: null, send_started_at: null });
	});
	it.each(['chain', 'entrypoint', 'gas', 'sponsor', 'quantity'] as const)('rejects %s preflight without editing or broadcasting the signed operation', async (fault) => {
		const f = await scenario(), valid = f.bundler.getMockImplementation()!;
		f.bundler.mockImplementation(async (request) => {
			if (fault === 'chain' && request.method === 'eth_chainId') return '0x1';
			if (fault === 'entrypoint' && request.method === 'eth_supportedEntryPoints') return [fixtureAddress('f')];
			const result = await valid(request);
			if (request.method === 'eth_estimateUserOperationGas') {
				const estimate = { verificationGasLimit: '0x1', callGasLimit: '0x1', preVerificationGas: '0x1' };
				if (fault === 'gas') return { ...estimate, callGasLimit: toHex(creationGas().callGasLimit + 1n) };
				if (fault === 'sponsor') return { ...estimate, paymasterPostOpGasLimit: '0x1' };
				if (fault === 'quantity') return { ...estimate, callGasLimit: '0x01' };
			}
			return result;
		});
		expect(await f.run()).toBe('deferred'); expect(f.sends()).toHaveLength(0);
		expect((await f.operations.read(f.id)).signed).toEqual(f.signed);
		expect((await deliveryOutbox(f.id))?.send_started_at).toBeNull();
	});
	it.each(['id', 'version', 'error', 'size', 'status'] as const)('bounds and validates the %s of a preflight response', async (fault) => {
		const f = await scenario();
		f.envelope.mockImplementation((request, result) => {
			if (fault === 'status') return new Response('unavailable', { status: 503 });
			if (fault === 'size') return Response.json({ jsonrpc: '2.0', id: request.id, result: 'x'.repeat(16_384) });
			if (fault === 'error') return Response.json({ jsonrpc: '2.0', id: request.id, result, error: { message: 'sensitive upstream error' } });
			return Response.json({ jsonrpc: fault === 'version' ? '1.0' : '2.0', id: request.id + (fault === 'id' ? 1 : 0), result });
		});
		expect(await f.run()).toBe('deferred'); expect(f.sends()).toHaveLength(0);
		expect((await deliveryOutbox(f.id))?.state).toBe('pending');
	});
	it.each(['connection', 'hash', 'envelope', 'http', 'size'] as const)('marks an ambiguous %s send result uncertain and does not rebroadcast on replay', async (fault) => {
		const f = await scenario(), valid = f.bundler.getMockImplementation()!, defaultEnvelope = f.envelope.getMockImplementation()!;
		f.bundler.mockImplementation(async (request) => {
			if (request.method === 'eth_sendUserOperation') {
				expect((await deliveryOutbox(f.id))?.state).toBe('sending');
				if (fault === 'connection') throw new Error('connection reset after accepting operation');
				if (fault === 'hash') return fixtureHash('9');
			}
			return valid(request);
		});
		f.envelope.mockImplementation((request, result) => {
			if (request.method === 'eth_sendUserOperation') {
				if (fault === 'envelope') return Response.json({ jsonrpc: '2.0', id: request.id + 1, result });
				if (fault === 'http') return new Response('unknown', { status: 502 });
				if (fault === 'size') return new Response('x'.repeat(16_385));
			}
			return defaultEnvelope(request, result);
		});
		expect(await f.run()).toBe('uncertain'); expect(f.sends()).toHaveLength(1);
		expect(await deliveryOutbox(f.id)).toMatchObject({ state: 'uncertain', lease_token: null });
		expect(await f.run()).toBe('idle'); expect(f.sends()).toHaveLength(1);
	});
	it('a revocation during simulation prevents the external effect', async () => {
		const f = await scenario(), valid = f.bundler.getMockImplementation()!;
		f.bundler.mockImplementation(async (request) => {
			if (request.method === 'eth_estimateUserOperationGas') {
				await env.WALLET_DB.prepare('UPDATE users SET auth_not_before = ? WHERE id = ?').bind(f.principal.authTime + 1, f.session.user_id).run();
			}
			return valid(request);
		});
		expect(await f.run()).toBe('lease_lost'); expect(f.sends()).toHaveLength(0);
		expect((await deliveryOutbox(f.id))?.send_started_at).toBeNull();
	});
	it('cancellation before claim does no I/O and cancellation in preflight sends nothing', async () => {
		const f = await scenario(), controller = new AbortController(); controller.abort();
		await expect(f.run(controller.signal)).rejects.toThrow(); expect(f.fetch).not.toHaveBeenCalled();
		expect((await deliveryOutbox(f.id))?.attempt_count).toBe(0);
		const second = new AbortController(), valid = f.bundler.getMockImplementation()!;
		f.bundler.mockImplementation(async (request) => { second.abort(); return valid(request); });
		expect(await f.run(second.signal)).toBe('deferred'); expect(f.sends()).toHaveLength(0);
	});
	it('uses a detached configuration throughout a request rather than shared mutable endpoints', async () => {
		const f = await scenario(), pending = f.run();
		f.configuration.networks[0].rpcUrl = 'https://unexpected.invalid/';
		f.configuration.networks[0].transport.url = 'https://unexpected.invalid/';
		f.configuration.networks[0].checkpoint.block_hash = fixtureHash('9');
		f.configuration.scope.origin = 'https://unexpected.invalid';
		expect(await pending).toBe('accepted');
		expect(f.calls.every(({ url }) => url === 'https://inspection.invalid/' || url === 'https://bundler.invalid/')).toBe(true);
	});
	it('keeps a lost D1 acknowledgement uncertain even when the provider returned the right hash', async () => {
		const f = await scenario(), valid = f.bundler.getMockImplementation()!;
		f.bundler.mockImplementation(async (request) => {
			if (request.method === 'eth_sendUserOperation') await env.WALLET_DB.prepare(`CREATE TRIGGER delivery_fail_transition
				BEFORE UPDATE ON account_creation_outbox WHEN NEW.state = 'accepted'
				BEGIN SELECT RAISE(ABORT, 'synthetic acknowledgement failure'); END`).run();
			return valid(request);
		});
		expect(await f.run()).toBe('uncertain'); expect(f.sends()).toHaveLength(1);
		expect((await deliveryOutbox(f.id))?.state).toBe('uncertain');
		expect(await f.run()).toBe('idle');
	});
	it('recovers a persisted sending marker after worker termination without an external retry', async () => {
		const f = await scenario(), repository = new CreationDeliveryRepository(env.WALLET_DB, f.configuration);
		const lease = await repository.claim(f.id); if (!lease) throw new Error('Expected lease');
		await repository.beginSend(lease);
		vi.spyOn(Date, 'now').mockReturnValue(lease.until * 1000);
		expect(await f.run()).toBe('idle'); expect(f.fetch).not.toHaveBeenCalled();
		expect((await deliveryOutbox(f.id))?.state).toBe('uncertain');
	});
	it.each(['eth_chainId', 'eth_sendUserOperation'] as const)('cancels a stalled %s response body and preserves the correct side of the send boundary', async (method) => {
		const f = await scenario(), controller = new AbortController(), original = f.envelope.getMockImplementation()!;
		let cancelled = false;
		f.envelope.mockImplementation((request, result) => {
			if (request.method !== method) return original(request, result);
			const body = new ReadableStream<Uint8Array>({
				start(stream) { stream.enqueue(new TextEncoder().encode('{"jsonrpc":"2.0",')); },
				cancel() { cancelled = true; },
			});
			setTimeout(() => controller.abort(), 10);
			return new Response(body);
		});
		expect(await f.run(controller.signal)).toBe(method === 'eth_chainId' ? 'deferred' : 'uncertain');
		expect(cancelled).toBe(true);
		expect(f.sends()).toHaveLength(method === 'eth_chainId' ? 0 : 1);
		expect((await deliveryOutbox(f.id))?.state).toBe(method === 'eth_chainId' ? 'pending' : 'uncertain');
	});
	it.each(['IGNORE', 'ABORT'] as const)('never broadcasts when persisting the send boundary returns %s', async (failure) => {
		const f = await scenario();
		// These are fixed test literals, not SQL built from user data.
		const action = failure === 'IGNORE' ? 'RAISE(IGNORE)' : "RAISE(ABORT, 'synthetic send-marker failure')";
		await env.WALLET_DB.prepare(`CREATE TRIGGER delivery_fail_transition BEFORE UPDATE ON account_creation_outbox
			WHEN NEW.state = 'sending' BEGIN SELECT ${action}; END`).run();
		if (failure === 'IGNORE') expect(await f.run()).toBe('lease_lost');
		else await expect(f.run()).rejects.toThrow();
		expect(f.sends()).toHaveLength(0);
		expect((await deliveryOutbox(f.id))?.send_started_at).toBeNull();
	});
});
