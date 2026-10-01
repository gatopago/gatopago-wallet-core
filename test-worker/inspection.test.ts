import { afterEach, describe, expect, it, vi } from 'vitest';
import { createInspectionClient, inspectWalletCreationProfile, inspectWalletDeployment } from '../src/chainInspection';
import { inspectionScenario } from '@gatopago/test-fixtures/v3-inspection';
import { creationInspectionScenario } from '@gatopago/test-fixtures/v3-creation-inspection';
import { initializationFixture } from '@gatopago/test-fixtures/v3-initialization';
import { prepareInitialization } from '@gatopago/shared/v3/initialization';
import { authorizeCreationOperation, prepareCreationOperation } from '@gatopago/shared/v3/creation-operation';
import { getUserOperationHash } from 'viem/account-abstraction';

afterEach(() => { vi.restoreAllMocks(); vi.unstubAllGlobals(); });
const endpoint = 'https://rpc.example.test/private-fixture-key';
const freshSignal = () => new AbortController().signal;

describe('V3 original creation composition in workerd', () => {
	it('verifies the two P-256 proofs and packs the first UserOperation inside workerd without I/O', () => {
		const fetchMock = vi.fn(); vi.stubGlobal('fetch', fetchMock);
		const f = initializationFixture();
		const terms = { verificationGasLimit: 2_000_000n, callGasLimit: 100_000n, preVerificationGas: 150_000n,
			maxFeePerGas: 1_000_000_000n, maxPriorityFeePerGas: 1_000_000_000n, maximumGasCharge: 2_250_000_000_000_000n };
		const initial = f.assertion(prepareInitialization(f.input).digest);
		const candidate = prepareCreationOperation(f.input, initial, terms, f.input.validAfter);
		const signed = authorizeCreationOperation(f.input, initial, terms, f.assertion(candidate.digest), f.input.validAfter);
		expect(signed.packed.initCode.startsWith(candidate.prepared.message.factory)).toBe(true);
		expect(signed.userOpHash).toBe(getUserOperationHash({ chainId: Number(candidate.prepared.chainId),
			entryPointAddress: candidate.plan.entryPoint, entryPointVersion: '0.9', userOperation: signed.operation }));
		expect(signed.prepared.policy.mode).toBe('active');
		expect(fetchMock).not.toHaveBeenCalled();
	});
	it('checks all code and immutables with request-local HTTP ids and the same canonical block', async () => {
		const test = creationInspectionScenario();
		const ids: number[] = [];
		const fetchMock = vi.fn(async (_url: RequestInfo | URL, init?: RequestInit) => {
			const body = JSON.parse(String(init?.body)) as { id: number; method: string; params?: readonly unknown[] };
			ids.push(body.id);
			expect(init?.redirect).toBe('manual');
			expect(init?.signal).toBeInstanceOf(AbortSignal);
			if (body.method === 'eth_getCode' || body.method === 'eth_call') {
				expect(body.params?.[1]).toEqual({ blockHash: test.input.checkpoint.block_hash, requireCanonical: true });
			}
			return Response.json({ jsonrpc: '2.0', id: body.id, result: await test.request(body) });
		});
		vi.stubGlobal('fetch', fetchMock);
		expect(await inspectWalletCreationProfile(test.input, endpoint, freshSignal())).toMatchObject({
			status: 'composition_matches', network_admitted: false,
		});
		expect(ids).toEqual(Array.from({ length: 29 }, (_, i) => i + 1));
	});
	it('does not reuse a successful inspection when the provider fails later', async () => {
		const test = creationInspectionScenario();
		const fetchMock = vi.fn(async (_url: RequestInfo | URL, init?: RequestInit) => {
			const body = JSON.parse(String(init?.body)) as { id: number; method: string; params?: readonly unknown[] };
			return Response.json({ jsonrpc: '2.0', id: body.id, result: await test.request(body) });
		});
		vi.stubGlobal('fetch', fetchMock);
		await inspectWalletCreationProfile(test.input, endpoint, freshSignal());
		fetchMock.mockImplementationOnce(async () => Response.json({ jsonrpc: '2.0', id: 1,
			error: { message: 'private upstream diagnostics must not escape' } }));
		await expect(inspectWalletCreationProfile(test.input, endpoint, freshSignal())).rejects.toMatchObject({ message: 'RPC_UNAVAILABLE' });
		expect(fetchMock).toHaveBeenCalledTimes(30);
	});
	it('releases an unfinished body when creation inspection is cancelled', async () => {
		let cancelled = false;
		const abort = new AbortController();
		let started!: () => void;
		const ready = new Promise<void>((resolve) => { started = resolve; });
		const fetchMock = vi.fn(async () => {
			started();
			return new Response(new ReadableStream<Uint8Array>({ cancel() { cancelled = true; } }));
		});
		vi.stubGlobal('fetch', fetchMock);
		const test = creationInspectionScenario();
		const operation = expect(inspectWalletCreationProfile(test.input, endpoint, abort.signal)).rejects.toThrow('RPC_UNAVAILABLE');
		await ready; abort.abort(); await operation;
		expect(cancelled).toBe(true);
		expect(fetchMock).toHaveBeenCalledTimes(1);
	});
});

describe('V3 inspection in workerd with bounded HTTP RPC', () => {
	it('runs the complete pinned inspection through the real viem/HTTP adapter', async () => {
		const test = inspectionScenario();
		const ids: number[] = [];
		const fetchMock = vi.fn(async (_url: RequestInfo | URL, init?: RequestInit) => {
			const body = JSON.parse(String(init?.body)) as { id: number; method: string; params?: readonly unknown[] };
			ids.push(body.id);
			expect(init?.redirect).toBe('manual');
			expect(init?.signal).toBeInstanceOf(AbortSignal);
			return Response.json({ jsonrpc: '2.0', id: body.id, result: await test.request(body) });
		});
		vi.stubGlobal('fetch', fetchMock);
		const result = await inspectWalletDeployment(test.input, endpoint, freshSignal());
		expect(result).toMatchObject({ status: 'recognized', security_version: '2', spend_readiness: 'not_assessed' });
		expect(ids).toEqual(Array.from({ length: ids.length }, (_, i) => i + 1));
		expect(fetchMock).toHaveBeenCalledTimes(13);
	});
	it('keeps concurrent request clients and sequences independent', async () => {
		const first = inspectionScenario(), second = inspectionScenario();
		second.state.observation.securityVersion = 3n;
		const starts: string[] = [];
		vi.stubGlobal('fetch', vi.fn(async (url: RequestInfo | URL, init?: RequestInit) => {
			const body = JSON.parse(String(init?.body)) as { id: number; method: string; params?: readonly unknown[] };
			const selected = String(url).endsWith('/first') ? first : second;
			if (body.id === 1) starts.push(String(url));
			return Response.json({ jsonrpc: '2.0', id: body.id, result: await selected.request(body) });
		}));
		const outcomes = await Promise.all([
			inspectWalletDeployment(first.input, endpoint + '/first', freshSignal()),
			inspectWalletDeployment(second.input, endpoint + '/second', freshSignal()),
		]);
		expect(outcomes).toMatchObject([{ security_version: '2' }, { security_version: '3' }]);
		expect(starts).toHaveLength(2);
	});
	it('rejects non-HTTPS, userinfo and fragment configuration without network access', () => {
		const fetchMock = vi.fn(); vi.stubGlobal('fetch', fetchMock);
		for (const url of ['http://rpc.example', 'file:///tmp/rpc', 'https://user:pass@rpc.example', 'https://rpc.example#secret']) {
			expect(() => createInspectionClient(url, freshSignal())).toThrow();
		}
		expect(fetchMock).not.toHaveBeenCalled();
	});
	it('refuses write methods before fetch', async () => {
		const fetchMock = vi.fn(); vi.stubGlobal('fetch', fetchMock);
		const client = createInspectionClient(endpoint, freshSignal());
		await expect(client.request({ method: 'eth_sendRawTransaction', params: ['0x'] })).rejects.toThrow('read-only');
		expect(fetchMock).not.toHaveBeenCalled();
	});
	it.each([
		{ jsonrpc: '2.0', id: 2, result: '0x14a34' },
		{ jsonrpc: '1.0', id: 1, result: '0x14a34' },
		{ jsonrpc: '2.0', id: 1, error: { message: 'https://rpc.example?secret=x' } },
		{ jsonrpc: '2.0', id: 1, result: '0x14a34', error: {} },
		null,
	])('rejects invalid envelopes with sanitized errors and no retries: %j', async (envelope) => {
		const test = inspectionScenario();
		const mock = vi.fn(async () => Response.json(envelope)); vi.stubGlobal('fetch', mock);
		await expect(inspectWalletDeployment(test.input, endpoint, freshSignal())).rejects.toThrow('RPC_UNAVAILABLE');
		expect(mock).toHaveBeenCalledTimes(1);
	});
	it.each([true, false])('cancels excessive bodies (Content-Length present: %s)', async (declaredLength) => {
		const test = inspectionScenario(); let cancelled = false;
		vi.stubGlobal('fetch', vi.fn(async () => new Response(new ReadableStream<Uint8Array>({
			start(controller) { controller.enqueue(new Uint8Array(131_073)); },
			cancel() { cancelled = true; },
		}), { headers: declaredLength ? { 'Content-Length': '131073' } : {} })));
		await expect(inspectWalletDeployment(test.input, endpoint, freshSignal())).rejects.toThrow('RPC_UNAVAILABLE');
		expect(cancelled).toBe(true);
	});
	it('releases a non-success response and never logs or propagates its diagnostics', async () => {
		let cancelled = false;
		vi.stubGlobal('fetch', vi.fn(async () => new Response(new ReadableStream({ cancel() { cancelled = true; } }), { status: 503 })));
		const test = inspectionScenario();
		await expect(inspectWalletDeployment(test.input, endpoint, freshSignal())).rejects.toMatchObject({ message: 'RPC_UNAVAILABLE' });
		expect(cancelled).toBe(true);
	});
	it('aborts a response that never finishes instead of leaving its reader alive', async () => {
		const abort = new AbortController(); let cancelled = false;
		let started!: () => void;
		const ready = new Promise<void>((resolve) => { started = resolve; });
		vi.stubGlobal('fetch', vi.fn(async () => {
			started();
			return new Response(new ReadableStream<Uint8Array>({ cancel() { cancelled = true; } }));
		}));
		const test = inspectionScenario();
		const operation = expect(inspectWalletDeployment(test.input, endpoint, abort.signal)).rejects.toThrow('RPC_UNAVAILABLE');
		await ready;
		abort.abort();
		await operation;
		expect(cancelled).toBe(true);
	});
	it('does no I/O for an already cancelled request', async () => {
		const fetchMock = vi.fn(); vi.stubGlobal('fetch', fetchMock);
		const abort = new AbortController(); abort.abort();
		const test = inspectionScenario();
		await expect(inspectWalletDeployment(test.input, endpoint, abort.signal)).rejects.toThrow('RPC_UNAVAILABLE');
		expect(fetchMock).not.toHaveBeenCalled();
	});
});
