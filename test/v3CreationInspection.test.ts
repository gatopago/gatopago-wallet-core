import { describe, expect, it } from 'vitest';
import { inspectCreationDeployment } from '@gatopago/shared/v3/creation-inspection';
import { creationInspectionScenario } from '@gatopago/test-fixtures/v3-creation-inspection';
import { fixtureHash } from '@gatopago/test-fixtures/v3-inspection';

describe('Original creation composition inspection', () => {
	it('pins all code/getter reads to one canonical block without authorizing a network', async () => {
		const t = creationInspectionScenario();
		expect(await inspectCreationDeployment(t.client, t.input)).toEqual({ status: 'composition_matches', network_id: 'eip155:84532',
			profile_sha256: t.input.expectedDigest, checkpoint: t.input.checkpoint, network_admitted: false });
		expect(t.request).toHaveBeenCalledTimes(29);
		for (const [call] of t.request.mock.calls) {
			if (call.method === 'eth_call' || call.method === 'eth_getCode') expect(call.params?.[1]).toEqual({ blockHash: t.input.checkpoint.block_hash, requireCanonical: true });
		}
	});
	it('rejects each mismatching role before invoking any getter on unrecognized code', async () => {
		for (const role of creationInspectionScenario().state.codes.keys()) {
			const t = creationInspectionScenario(); t.state.codes.set(role, '0x6000');
			await expect(inspectCreationDeployment(t.client, t.input)).rejects.toMatchObject({ code: 'UNEXPECTED_CODE' });
			expect(t.request.mock.calls.some(([call]) => call.method === 'eth_call')).toBe(false);
		}
	});
	it('checks every immutable/getter rather than trusting one factory address', async () => {
		for (const key of creationInspectionScenario().state.getters.keys()) {
			const t = creationInspectionScenario(); t.state.getters.set(key, fixtureHash('e'));
			await expect(inspectCreationDeployment(t.client, t.input)).rejects.toMatchObject({ code: 'COMPOSITION_MISMATCH' });
		}
	});
	it.each(['chain', 'genesis', 'checkpoint'])('refuses an inconsistent %s', async (part) => {
		const t = creationInspectionScenario();
		if (part === 'chain') t.state.chainId = '0x1'; else if (part === 'genesis') t.state.genesis = fixtureHash('e'); else t.state.blockHash = fixtureHash('e');
		await expect(inspectCreationDeployment(t.client, t.input)).rejects.toMatchObject({ code: part === 'chain' ? 'CHAIN_MISMATCH' : 'CHECKPOINT_MISMATCH' });
	});
	it('rechecks the canonical checkpoint after the last state read', async () => {
		const t = creationInspectionScenario(), original = t.request.getMockImplementation()!;
		t.request.mockImplementation(async (call) => {
			if (t.request.mock.calls.length === 29) t.state.blockHash = fixtureHash('e');
			return original(call);
		});
		await expect(inspectCreationDeployment(t.client, t.input)).rejects.toMatchObject({ code: 'CHECKPOINT_MISMATCH' });
	});
	it('bad pins or predeployment checkpoints fail before I/O', async () => {
		const t = creationInspectionScenario();
		await expect(inspectCreationDeployment(t.client, { ...t.input, expectedDigest: fixtureHash('e') })).rejects.toThrow('pin');
		await expect(inspectCreationDeployment(t.client, { ...t.input, checkpoint: { ...t.input.checkpoint, block_number: '1' } })).rejects.toThrow('predates');
		expect(t.request).not.toHaveBeenCalled();
	});
	it('never falls back to latest or the preceding successful observation after RPC fails', async () => {
		const t = creationInspectionScenario();
		await inspectCreationDeployment(t.client, t.input); t.request.mockClear();
		t.request.mockRejectedValue(new Error('https://rpc.example?secret=not-for-output'));
		await expect(inspectCreationDeployment(t.client, t.input)).rejects.toMatchObject({ code: 'RPC_UNAVAILABLE', message: 'RPC_UNAVAILABLE' });
		expect(t.request).toHaveBeenCalledTimes(1);
	});
	it('does not adopt a caller mutation of the checkpoint across asynchronous reads', async () => {
		const t = creationInspectionScenario(), checkpoint = { ...t.input.checkpoint };
		const result = inspectCreationDeployment(t.client, { ...t.input, checkpoint });
		checkpoint.block_hash = fixtureHash('e'); checkpoint.block_number = '200';
		expect((await result).checkpoint).toEqual(t.input.checkpoint);
	});
	it.each([{ label: 'odd length', runtime: '0x0' }, { label: 'different code', runtime: '0x00' },
		{ label: 'oversized', runtime: '0x' + '00'.repeat(24577) }])('rejects $label runtime bytes', async ({ runtime }) => {
		const t = creationInspectionScenario(), original = t.request.getMockImplementation()!;
		t.request.mockImplementation(async (call) => call.method === 'eth_getCode' ? runtime : original(call));
		await expect(inspectCreationDeployment(t.client, t.input)).rejects.toThrow();
	});
});
