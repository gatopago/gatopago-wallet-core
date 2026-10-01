import { afterEach, beforeEach, describe, expect, it, vi } from 'vitest';
import { createPublicClient, custom, toHex } from 'viem';
import { assessCheckpointFinality, assertFinalityAssessment, loadPinnedFinalityPolicy } from '@gatopago/shared/v3/finality';
import { finalityPin, finalityPolicyFixture } from '@gatopago/test-fixtures/v3-finality';
import { fixtureHash } from '@gatopago/test-fixtures/v3-inspection';

const now = 1_800_000_000;
beforeEach(() => { vi.spyOn(Date, 'now').mockReturnValue(now * 1000); });
afterEach(() => { vi.restoreAllMocks(); });
function scenario() {
	const network = { network_id: 'eip155:84532' as const, genesis_hash: fixtureHash('7') };
	const b = (number: number) => ({ number: toHex(number), hash: number === 0 ? network.genesis_hash : toHex(number + 256, { size: 32 }),
		timestamp: toHex(number === 0 ? 0 : now - (120 - number)) });
	const target = { ...network, block_hash: b(100).hash, block_number: '100', block_timestamp: String(now - 20) };
	const states = [{ latest: 120, finalized: 110 }, { latest: 120, finalized: 110 }];
	const reply = vi.fn(async (index: number, call: { method: string; params?: readonly unknown[] }): Promise<unknown> => {
		if (call.method === 'eth_chainId') return toHex(84532);
		if (call.method !== 'eth_getBlockByNumber' || call.params?.[1] !== false) throw new Error('Unexpected finality RPC');
		const tag = String(call.params[0]);
		return b(tag === 'latest' ? states[index].latest : tag === 'finalized' ? states[index].finalized : Number(BigInt(tag)));
	});
	const clients = states.map((_state, index) => createPublicClient({ cacheTime: 0,
		transport: custom({ request: (call) => reply(index, call) }, { retryCount: 0 }) }));
	const policy = finalityPolicyFixture(network, now);
	const run = (signal = new AbortController().signal) => assessCheckpointFinality(clients, target, finalityPin(policy), signal);
	return { network, target, states, reply, clients, policy, run, b };
}

describe('V3 consensus-specific pinned finality evidence', () => {
	it.each(['ethereum_finalized', 'arbitrum_l1_data_finalized', 'op_stack_l1_data_finalized', 'avalanche_accepted'])(
		'records %s semantics without conflating data finality with withdrawal or spend readiness', async (mechanism) => {
			const f = scenario(); f.policy.mechanism = mechanism;
			expect(await f.run()).toMatchObject({ status: 'finalized', mechanism, policy_sha256: finalityPin(f.policy).digest,
				checkpoint: { block_number: '110' }, assessed_at: now, expires_at: now + 30 });
			expect(f.reply).toHaveBeenCalledTimes(16);
			expect(f.reply.mock.calls.every(([, call]) => ['eth_chainId', 'eth_getBlockByNumber'].includes(call.method))).toBe(true);
		});
	it('chooses the common finalized height when legitimate nodes are differently advanced', async () => {
		const f = scenario(); f.states[1].finalized = 109;
		expect(await f.run()).toMatchObject({ status: 'finalized', checkpoint: { block_number: '109' } });
	});
	it('keeps a mined receipt pending while only the latest/safe portion of the chain contains it', async () => {
		const f = scenario(); f.states[0].finalized = 99;
		expect(await f.run()).toMatchObject({ status: 'pending', checkpoint: { block_number: '99' } });
	});
	it('accepts equality only with the exact target hash and timestamp', async () => {
		const f = scenario(); f.states.forEach((s) => { s.finalized = 100; });
		expect(await f.run()).toMatchObject({ status: 'finalized', checkpoint: { block_hash: f.target.block_hash } });
	});
	it('does not walk millions of ancestors to confirm an old receipt', async () => {
		const f = scenario(); f.target.block_number = '1'; f.target.block_hash = f.b(1).hash; f.target.block_timestamp = String(now - 119);
		expect(await f.run()).toMatchObject({ status: 'finalized' }); expect(f.reply).toHaveBeenCalledTimes(16);
	});
	it.each(['latest_age', 'finalized_age', 'future', 'clock_rollback', 'expires_during_io'] as const)('rejects %s evidence', async (fault) => {
		const f = scenario(), valid = f.reply.getMockImplementation()!;
		if (fault === 'latest_age') f.policy.max_latest_age_seconds = 1;
		if (fault === 'finalized_age') f.policy.max_finalized_age_seconds = 1;
		f.reply.mockImplementation(async (index, call) => {
			const result = await valid(index, call);
			if (fault === 'latest_age') vi.spyOn(Date, 'now').mockReturnValue((now + 2) * 1000);
			if (fault === 'clock_rollback') vi.spyOn(Date, 'now').mockReturnValue((now - 1) * 1000);
			if (fault === 'expires_during_io') vi.spyOn(Date, 'now').mockReturnValue((now + 86400) * 1000);
			if (fault === 'future' && call.params?.[0] === 'latest') return { ...f.b(120), timestamp: toHex(now + 6) };
			return result;
		});
		const result = await f.run(); expect(result).toMatchObject({ status: 'stale', checkpoint: null });
		expect(result.expires_at).toBe(result.assessed_at);
	});
	it.each(['before_validity', 'expired'] as const)('does not query under a policy that is %s', async (fault) => {
		const f = scenario(); if (fault === 'expired') f.policy.valid_until = now; else f.policy.valid_from = now + 1;
		expect(await f.run()).toMatchObject({ status: 'stale' }); expect(f.reply).not.toHaveBeenCalled();
	});
	it('bounds evidence validity by the policy expiry', async () => {
		const f = scenario(); f.policy.valid_until = now + 1;
		expect(await f.run()).toMatchObject({ status: 'finalized', expires_at: now + 1 });
	});
	it.each(['chain', 'genesis', 'null', 'quantity', 'height', 'finalized_above_latest'] as const)('fails closed on %s RPC data', async (fault) => {
		const f = scenario(), valid = f.reply.getMockImplementation()!;
		if (fault === 'finalized_above_latest') f.states[0].finalized = 121;
		f.reply.mockImplementation(async (index, call) => {
			if (index === 0) {
				if (fault === 'chain' && call.method === 'eth_chainId') return '0x1';
				if (fault === 'genesis' && call.params?.[0] === '0x0') return { ...f.b(0), hash: fixtureHash('9') };
				if (call.params?.[0] === 'finalized') {
					if (fault === 'null') return null;
					if (fault === 'quantity') return { ...f.b(110), number: '0x06e' };
					if (fault === 'height') return { ...f.b(110), number: -1 };
				}
			}
			return valid(index, call);
		});
		expect(await f.run()).toMatchObject({ status: 'unavailable', checkpoint: null });
	});
	it('detects disagreement at the common finalized checkpoint', async () => {
		const f = scenario(), valid = f.reply.getMockImplementation()!; f.states[1].finalized = 111;
		f.reply.mockImplementation(async (index, call) => index === 1 && call.params?.[0] === toHex(110)
			? { ...f.b(110), hash: fixtureHash('9') } : valid(index, call));
		expect(await f.run()).toMatchObject({ status: 'disagreement', checkpoint: null });
	});
	it.each(['target', 'anchor', 'regression', 'finalized_hash'] as const)('detects changed %s and never promotes it', async (fault) => {
		const f = scenario(), valid = f.reply.getMockImplementation()!; let finalizedReads = 0;
		f.reply.mockImplementation(async (index, call) => {
			if (index === 0) {
				if ((fault === 'target' && call.params?.[0] === toHex(100)) || (fault === 'anchor' && call.params?.[0] === toHex(110))) {
					return { ...f.b(Number(BigInt(String(call.params[0])))), hash: fixtureHash('9') };
				}
				if (call.params?.[0] === 'finalized' && ++finalizedReads === 2) {
					if (fault === 'regression') return f.b(109);
					if (fault === 'finalized_hash') return { ...f.b(110), hash: fixtureHash('9') };
				}
			}
			return valid(index, call);
		});
		expect(await f.run()).toMatchObject({ status: 'reorg_detected', checkpoint: null });
	});
	it('never falls back to latest/depth if finalized is unsupported and awaits sibling reads', async () => {
		const f = scenario(), valid = f.reply.getMockImplementation()!; const completed: string[] = [];
		f.reply.mockImplementation(async (index, call) => {
			if (index === 0 && call.params?.[0] === 'finalized') throw new Error('private RPC token');
			const result = await valid(index, call); completed.push(`${index}:${String(call.params?.[0])}`); return result;
		});
		const result = await f.run(); expect(result).toMatchObject({ status: 'unavailable' });
		expect(completed).toHaveLength(6); expect(f.reply).toHaveBeenCalledTimes(7);
		expect(JSON.stringify(result)).not.toMatch(/private|token/);
	});
	it('cancels without network I/O', async () => {
		const f = scenario(), c = new AbortController(); c.abort();
		expect(await f.run(c.signal)).toMatchObject({ status: 'unavailable' }); expect(f.reply).not.toHaveBeenCalled();
	});
	it.each(['pin', 'network', 'genesis', 'mechanism', 'extra', 'ttl', 'negative', 'fraction', 'providers'] as const)(
		'rejects invalid %s configuration before RPC', async (fault) => {
			const f = scenario(), pin = finalityPin(f.policy);
			if (fault === 'pin') pin.document += ' ';
			if (fault === 'network') f.target.network_id = 'eip155:1' as typeof f.target.network_id;
			if (fault === 'genesis') f.target.genesis_hash = fixtureHash('8');
			if (fault === 'mechanism') Object.assign(pin, finalityPin({ ...f.policy, mechanism: 'latest' }));
			if (fault === 'extra') Object.assign(pin, finalityPin({ ...f.policy, ...{ rpc_url: 'https://untrusted.invalid/' } }));
			if (fault === 'ttl') Object.assign(pin, finalityPin({ ...f.policy, evidence_ttl_seconds: 3600 }));
			if (fault === 'negative') Object.assign(pin, finalityPin({ ...f.policy, max_clock_skew_seconds: -1 }));
			if (fault === 'fraction') Object.assign(pin, finalityPin({ ...f.policy, max_latest_age_seconds: 1.5 }));
			if (fault === 'providers') f.clients.pop();
			await expect(assessCheckpointFinality(f.clients, f.target, pin, new AbortController().signal)).rejects.toThrow();
			expect(f.reply).not.toHaveBeenCalled();
		});
	it('detaches the policy, target and client list before the first await', async () => {
		const f = scenario(), pin = finalityPin(f.policy), pending = assessCheckpointFinality(f.clients, f.target, pin, new AbortController().signal);
		pin.document = '{}'; f.target.block_hash = fixtureHash('8'); f.clients.pop();
		expect(await pending).toMatchObject({ status: 'finalized' });
	});
	it('loads exact policy fields and immutable configuration', () => {
		const f = scenario(), p = loadPinnedFinalityPolicy(finalityPin(f.policy), f.network);
		expect(Object.isFrozen(p)).toBe(true); expect(p).toEqual(f.policy);
	});
	it.each(['target', 'checkpoint', 'expiry', 'status', 'status_type', 'extra'] as const)('rejects malformed stored %s evidence', async (fault) => {
		const f = scenario(), value = JSON.parse(JSON.stringify(await f.run()));
		if (fault === 'target') value.target.block_hash = fixtureHash('8');
		if (fault === 'checkpoint') value.checkpoint.block_number = '99';
		if (fault === 'expiry') value.expires_at = now + 61;
		if (fault === 'status') value.status = 'stale';
		if (fault === 'status_type') { value.status = ['unavailable']; value.checkpoint = null; value.expires_at = now; }
		if (fault === 'extra') value.provider_url = 'https://secret.invalid/';
		expect(() => assertFinalityAssessment(value, f.target)).toThrow();
	});
});
