import { describe, expect, it } from 'vitest';
import { encodeAbiParameters, zeroHash } from 'viem';
import { observeCreationReceipt, verifyCreationReceipt } from '@gatopago/shared/v3/creation-receipt';
import { creationReceiptScenario } from '@gatopago/test-fixtures/v3-creation-receipt';
import { fixtureAddress, fixtureHash } from '@gatopago/test-fixtures/v3-inspection';

describe('first UserOperation receipt evidence', () => {
	it('binds five events and gas to the exact grant, without claiming finality or backup', () => {
		const f = creationReceiptScenario();
		expect(verifyCreationReceipt(f.signed, f.transactionHash, f.receipt)).toMatchObject({ outcome: 'creation_succeeded',
			user_op_hash: f.signed.userOpHash, actual_gas_cost: '12345', actual_gas_used: '123', block_number: '100',
			finality: 'not_assessed', account_readiness: 'not_assessed', log_indexes: { initialized: '3', created: '4', deployed: '5', completed: '7', operation: '8' } });
	});
	it('recognizes an operation execution revert inside a successful bundle transaction', () => {
		const f = creationReceiptScenario();
		f.receipt.logs[4].data = encodeAbiParameters([{ type: 'uint256' }, { type: 'bool' }, { type: 'uint256' }, { type: 'uint256' }], [0n, false, 12345n, 123n]);
		f.receipt.logs.splice(3, 1);
		expect(verifyCreationReceipt(f.signed, f.transactionHash, f.receipt)).toMatchObject({ outcome: 'execution_reverted', actual_gas_cost: '12345',
			log_indexes: { completed: null }, account_readiness: 'not_assessed' });
	});
	it.each([0, 1, 2, 3, 4])('requires event %s for successful creation', (index) => {
		const f = creationReceiptScenario(); f.receipt.logs.splice(index, 1);
		expect(() => verifyCreationReceipt(f.signed, f.transactionHash, f.receipt)).toThrow();
	});
	it.each([0, 1, 2, 3, 4])('rejects event %s emitted by an unrelated contract', (index) => {
		const f = creationReceiptScenario(); f.receipt.logs[index].address = fixtureAddress('f');
		expect(() => verifyCreationReceipt(f.signed, f.transactionHash, f.receipt)).toThrow();
	});
	it.each(['nonce', 'charge', 'gas', 'success'] as const)('rejects incorrect operation %s', (fault) => {
		const f = creationReceiptScenario();
		f.receipt.logs[4].data = encodeAbiParameters([{ type: 'uint256' }, { type: 'bool' }, { type: 'uint256' }, { type: 'uint256' }],
			[fault === 'nonce' ? 1n : 0n, fault !== 'success', fault === 'charge' ? f.signed.maximumEntryPointCharge + 1n : 12345n, fault === 'gas' ? 0n : 123n]);
		expect(() => verifyCreationReceipt(f.signed, f.transactionHash, f.receipt)).toThrow();
	});
	it.each(['removed', 'block', 'transaction', 'txindex', 'order', 'duplicate', 'topics', 'data'] as const)('rejects %s corruption in receipt logs', (fault) => {
		const f = creationReceiptScenario(), log = f.receipt.logs[4];
		if (fault === 'removed') log.removed = true;
		if (fault === 'block') log.blockHash = fixtureHash('9');
		if (fault === 'transaction') log.transactionHash = fixtureHash('9');
		if (fault === 'txindex') log.transactionIndex = '0x1';
		if (fault === 'order') log.logIndex = '0x1';
		if (fault === 'duplicate') f.receipt.logs.push({ ...log, logIndex: '0x9' });
		if (fault === 'topics') f.receipt.logs[3].topics.push(zeroHash);
		if (fault === 'data') log.data = `${log.data}00`;
		expect(() => verifyCreationReceipt(f.signed, f.transactionHash, f.receipt)).toThrow();
	});
	it('rejects a reverted transaction, absent receipt or a different operation/transaction', () => {
		const f = creationReceiptScenario();
		for (const raw of [null, { ...f.receipt, status: '0x0' }, { ...f.receipt, transactionHash: fixtureHash('9') }]) {
			expect(() => verifyCreationReceipt(f.signed, f.transactionHash, raw)).toThrow();
		}
		f.receipt.logs[4].topics[1] = fixtureHash('9');
		expect(() => verifyCreationReceipt(f.signed, f.transactionHash, f.receipt)).toThrow();
	});
	it('allows unrelated bundle logs without counting their fees as this operation\'s charge', () => {
		const f = creationReceiptScenario();
		f.receipt.logs.push({ ...f.receipt.logs[4], topics: [f.receipt.logs[4].topics[0], fixtureHash('9'), ...f.receipt.logs[4].topics.slice(2)], logIndex: '0x9' });
		expect(verifyCreationReceipt(f.signed, f.transactionHash, f.receipt).actual_gas_cost).toBe('12345');
	});
	it('observes canonical code and receipt at one block with no latest fallback', async () => {
		const f = creationReceiptScenario();
		expect(await observeCreationReceipt(f.client, f.signed, f.transactionHash, f.input.document)).toMatchObject({ outcome: 'creation_succeeded', block_timestamp: f.state.timestamp.toString() });
		expect(f.request).toHaveBeenCalledTimes(33);
		for (const [call] of f.request.mock.calls) {
			if (call.method === 'eth_call' || call.method === 'eth_getCode') expect(call.params?.[1]).toEqual({ blockHash: f.receipt.blockHash, requireCanonical: true });
		}
	});
	it('keeps a missing receipt unknown rather than declaring failure or permission to retry', async () => {
		const f = creationReceiptScenario(); f.state.missing = true;
		expect(await observeCreationReceipt(f.client, f.signed, f.transactionHash, f.input.document)).toBeNull();
		expect(f.request).toHaveBeenCalledTimes(1);
	});
	it('refuses an original profile with the wrong pin before consulting an RPC', async () => {
		const f = creationReceiptScenario();
		await expect(observeCreationReceipt(f.client, f.signed, f.transactionHash, '{}')).rejects.toThrow();
		expect(f.request).not.toHaveBeenCalled();
	});
	it.each(['code', 'time', 'reorg'] as const)('refuses a changed %s and does not reuse an earlier observation', async (fault) => {
		const f = creationReceiptScenario();
		await observeCreationReceipt(f.client, f.signed, f.transactionHash, f.input.document);
		if (fault === 'code') f.state.proxyCode = '0x6000';
		if (fault === 'time') f.state.timestamp = BigInt(f.input.validUntil + 1);
		if (fault === 'reorg') f.inspection.state.blockHash = fixtureHash('9');
		await expect(observeCreationReceipt(f.client, f.signed, f.transactionHash, f.input.document)).rejects.toThrow();
	});
	it('detects a canonical block change after its final code read', async () => {
		const f = creationReceiptScenario(), original = f.request.getMockImplementation()!;
		f.request.mockImplementation(async (call) => {
			const result = await original(call);
			if (call.method === 'eth_getCode' && call.params?.[0] === f.signed.operation.sender) f.inspection.state.blockHash = fixtureHash('9');
			return result;
		});
		await expect(observeCreationReceipt(f.client, f.signed, f.transactionHash, f.input.document)).rejects.toMatchObject({ code: 'CREATION_BLOCK_CHANGED' });
	});
	it('preserves the original JSON formatting throughout composition inspection', async () => {
		const f = creationReceiptScenario(true);
		expect(await observeCreationReceipt(f.client, f.signed, f.transactionHash, f.input.document)).toMatchObject({ outcome: 'creation_succeeded' });
		f.request.mockClear();
		const normalized = JSON.stringify(JSON.parse(f.input.document));
		await expect(observeCreationReceipt(f.client, f.signed, f.transactionHash, normalized)).rejects.toThrow();
		expect(f.request).not.toHaveBeenCalled();
	});
});
