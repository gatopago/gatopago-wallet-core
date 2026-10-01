import { describe, expect, it } from 'vitest';
import { decodeFunctionData, zeroAddress } from 'viem';
import { getUserOperationHash } from 'viem/account-abstraction';
import { authorizeCreationOperation, prepareCreationOperation, type CreationGasTerms } from '@gatopago/shared/v3/creation-operation';
import { executionAbi } from '@gatopago/shared/v3/execution';
import { prepareInitialization } from '@gatopago/shared/v3/initialization';
import { initializationFixture } from '@gatopago/test-fixtures/v3-initialization';

// Deliberately generous local budgets, NOT ERC-7562 admission or network gas estimates.
const terms: CreationGasTerms = { verificationGasLimit: 2_000_000n, callGasLimit: 100_000n, preVerificationGas: 150_000n,
	maxFeePerGas: 1_000_000_000n, maxPriorityFeePerGas: 1_000_000_000n, maximumGasCharge: 2_250_000_000_000_000n };
function scenario() {
	const f = initializationFixture(), now = f.input.validAfter;
	const initial = f.assertion(prepareInitialization(f.input).digest);
	const candidate = prepareCreationOperation(f.input, initial, terms, now);
	return { f, initial, now, candidate, proof: f.assertion(candidate.digest) };
}
describe('Account V3 first UserOperation, two explicit proofs and bounded gas', () => {
	it('allows only the first no-asset creation call and recomputes the EntryPoint hash', () => {
		const { f, initial, now, candidate, proof } = scenario();
		const signed = authorizeCreationOperation(f.input, initial, terms, proof, now);
		expect(decodeFunctionData({ abi: executionAbi, data: signed.operation.callData }).functionName).toBe('completeCreation');
		expect(signed.operation.nonce).toBe(0n);
		expect(signed.operation.paymaster).toBeUndefined();
		expect(signed.plan.paymaster).toBe(zeroAddress);
		expect(signed.userOpHash).toBe(getUserOperationHash({ chainId: Number(candidate.prepared.chainId),
			entryPointAddress: candidate.plan.entryPoint, entryPointVersion: '0.9', userOperation: signed.operation }));
		expect(signed.maximumEntryPointCharge).toBe(terms.maximumGasCharge);
		expect(Object.isFrozen(signed.operation)).toBe(true);
		expect(Object.isFrozen(signed.packed)).toBe(true);
	});
	it('initial possession is not operation approval and cannot be reused as that signature', () => {
		const { f, initial, now } = scenario();
		expect(() => authorizeCreationOperation(f.input, initial, terms, initial, now)).toThrow();
	});
	it('a new valid initial signature changes initCode and requires new operation approval', () => {
		const { f, now, proof } = scenario();
		const otherInitial = f.assertion(prepareInitialization(f.input).digest, { count: 3 });
		expect(() => authorizeCreationOperation(f.input, otherInitial, terms, proof, now)).toThrow();
	});
	it('requires the same key, origin and user verification for the operation', () => {
		const { f, initial, candidate, now } = scenario();
		for (const proof of [initializationFixture().assertion(candidate.digest), f.assertion(candidate.digest, { flags: 1 }),
			f.assertion(candidate.digest, { origin: 'https://wrong.example' })]) {
			expect(() => authorizeCreationOperation(f.input, initial, terms, proof, now)).toThrow();
		}
	});
	it.each(['verificationGasLimit', 'callGasLimit', 'preVerificationGas', 'maxFeePerGas', 'maxPriorityFeePerGas'] as const)(
		'binds %s to the operation signature and rejects 120-bit overflow', (field) => {
			const { f, initial, now, proof, candidate } = scenario();
			const changed = { ...terms, [field]: terms[field] + 1n, maximumGasCharge: terms.maximumGasCharge * 2n };
			if (field === 'maxPriorityFeePerGas') changed.maxFeePerGas++;
			expect(prepareCreationOperation(f.input, initial, changed, now).userOpHash).not.toBe(candidate.userOpHash);
			expect(() => authorizeCreationOperation(f.input, initial, changed, proof, now)).toThrow();
			expect(() => prepareCreationOperation(f.input, initial, { ...terms, [field]: 1n << 120n }, now)).toThrow();
		});
	it('binds the approved cap even when the EntryPoint charge remains unchanged', () => {
		const { f, initial, now, proof, candidate } = scenario();
		const changed = { ...terms, maximumGasCharge: terms.maximumGasCharge + 1n };
		expect(prepareCreationOperation(f.input, initial, changed, now).userOpHash).toBe(candidate.userOpHash);
		expect(() => authorizeCreationOperation(f.input, initial, changed, proof, now)).toThrow();
	});
	it('rejects insufficient/zero cap, negative gas and priority above maximum', () => {
		const { f, initial, now } = scenario();
		for (const changed of [{ ...terms, maximumGasCharge: terms.maximumGasCharge - 1n }, { ...terms, maximumGasCharge: 0n },
			{ ...terms, preVerificationGas: -1n }, { ...terms, verificationGasLimit: 0n }, { ...terms, maxPriorityFeePerGas: terms.maxFeePerGas + 1n }]) {
			expect(() => prepareCreationOperation(f.input, initial, changed, now)).toThrow();
		}
	});
	it('cannot extend or refresh the original half-open creation lifetime', () => {
		const { f, initial, proof } = scenario();
		for (const now of [f.input.validAfter - 1, f.input.validUntil, f.input.validUntil + 1]) {
			expect(() => authorizeCreationOperation(f.input, initial, terms, proof, now)).toThrow();
		}
		// High bit denotes EntryPoint block-number validity, not an ordinary timestamp.
		expect(() => prepareInitialization({ ...f.input, validAfter: 0x800000000000, validUntil: 0x800000000001 })).toThrow();
	});
});
