import { readFileSync } from 'node:fs';
import { describe, expect, it } from 'vitest';
import { decodeFunctionData, encodeFunctionData, zeroHash, type Abi } from 'viem';
import { accountBackupAbi, assessPolicyContinuity, authorizeBackupEnrollment, authorizeBackupCommit, prepareBackupEnrollment, prepareBackupCommit } from '@gatopago/shared/v3/backup-enrollment';
import { signerId } from '@gatopago/shared/v3/security-policy';
import { backupFixture } from '@gatopago/test-fixtures/v3-backup';
import { fixtureHash } from '@gatopago/test-fixtures/v3-deployment-fixture';

describe('Account V3 optional backup consent compiler', () => {
	it('preserves account identity, requires both new factors and does not claim sovereignty', () => {
		const f = backupFixture(), p = prepareBackupEnrollment(f.input, f.input.validAfter);
		expect(p.initial.account).toBe(f.initial.account); expect(p.message.accountId).toBe(f.initial.message.accountId);
		expect(p.message).toMatchObject({ generation: 3, securityVersion: 1n, nonce: 0n });
		expect(p.enrollments).toHaveLength(2);
		expect(p.enrollments.every((e) => e.message.contextHash === p.digest && e.message.nextPolicyHash === p.message.nextPolicyHash)).toBe(true);
		expect(p.continuity).toEqual({ direct_key_quorums: { spend: true, admin: true },
			factor_independence: 'not_assessed', sovereign_readiness: 'not_assessed' });
	});
	it('does not equate a second passkey plus one direct key with domain-independent administration', () => {
		const f = backupFixture();
		const retained = { ...f.initial.policy.signers[0], roles: 3 };
		const policy = { ...f.input.nextPolicy, adminThreshold: 2, signers: [retained, f.input.nextPolicy.signers.find((s) => s.kind === 0)!]
			.sort((a, b) => signerId(a).localeCompare(signerId(b))) };
		expect(assessPolicyContinuity(policy).direct_key_quorums).toEqual({ spend: true, admin: false });
		expect(assessPolicyContinuity(f.initial.policy).direct_key_quorums).toEqual({ spend: false, admin: false });
	});
	it('does not require another enrollment proof for an unchanged existing owner', async () => {
		const f = backupFixture();
		const input = { ...f.input, nextPolicy: { ...f.input.nextPolicy, signers: f.input.nextPolicy.signers.map((s) => ({ ...s, roles: 3 })) } };
		const p = prepareBackupEnrollment(input, input.validAfter); expect(p.enrollments).toHaveLength(2);
		const result = await authorizeBackupEnrollment(input, f.assertion(p.digest), await f.proofs(input), input.validAfter);
		expect(result.account_readiness).toBe('not_assessed');
	});
	it('encodes exactly the compiled prepare ABI with no transfer or arbitrary call', async () => {
		const f = backupFixture(), p = prepareBackupEnrollment(f.input, f.input.validAfter);
		const result = await authorizeBackupEnrollment(f.input, f.assertion(p.digest), await f.proofs(), f.input.validAfter);
		const decoded = decodeFunctionData({ abi: accountBackupAbi, data: result.data }); expect(decoded.functionName).toBe('prepare');
		const compiled = JSON.parse(readFileSync(new URL(import.meta.resolve('@gatopago/contract-artifacts/AccountV3.json')), 'utf8')) as { abi: Abi };
		expect(encodeFunctionData({ abi: compiled.abi, functionName: decoded.functionName, args: decoded.args })).toBe(result.data);
		expect(decoded.args[0]).toBe(0); expect(decoded.args[3]).toEqual(f.initial.chains);
		expect(result.value).toBe(0n); expect(result.account).toBe(f.initial.account);
	});
	it.each(['account', 'account_id', 'manifest_sha256', 'network_id', 'security_version'] as const)('rejects changed observed %s', (field) => {
		const f = backupFixture(), observation = { ...f.input.observation, [field]: fixtureHash('e') };
		expect(() => prepareBackupEnrollment({ ...f.input, observation }, f.input.validAfter)).toThrow('BACKUP_STATE_MISMATCH');
	});
	it.each([
		{ phase: 'creation_pending' }, { creation_valid_until: 1 }, { creation_valid_after: 1 }, { phase: 'bootstrap' },
		{ manifest_hash: fixtureHash('e') }, { chain_scope_hash: fixtureHash('e') }, { policy_hash: fixtureHash('e') },
	])('rejects inconsistent initial security %#', (patch) => {
		const f = backupFixture(), observation = { ...f.input.observation, security: { ...f.input.observation.security, ...patch } };
		expect(() => prepareBackupEnrollment({ ...f.input, observation }, f.input.validAfter)).toThrow('BACKUP_STATE_MISMATCH');
	});
	it('rejects an existing pending proposal and never resets a consumed admin nonce', () => {
		const f = backupFixture();
		expect(() => prepareBackupEnrollment({ ...f.input, observation: f.pending() }, f.input.validAfter)).toThrow('BACKUP_PROPOSAL_PENDING');
		f.input.observation.security.nonces.admin = '17';
		expect(prepareBackupEnrollment(f.input, f.input.validAfter).message.nonce).toBe(17n);
		for (const nonce of [(2n ** 256n - 2n).toString(), (2n ** 256n - 1n).toString(), '-1', '01']) {
			f.input.observation.security.nonces.admin = nonce;
			expect(() => prepareBackupEnrollment(f.input, f.input.validAfter)).toThrow();
		}
	});
	it('rejects removal of the original owner rather than turning backup into recovery', () => {
		const f = backupFixture(), nextPolicy = { ...f.input.nextPolicy, signers: f.input.nextPolicy.signers.filter((s) => s.kind !== 1) };
		expect(() => prepareBackupEnrollment({ ...f.input, nextPolicy }, f.input.validAfter)).toThrow('BACKUP_MUST_RETAIN_INITIAL_FACTOR');
	});
	it.each([-1, 300])('rejects out-of-window signing at offset %i', (offset) => {
		const f = backupFixture(); expect(() => prepareBackupEnrollment(f.input, f.input.validAfter + offset)).toThrow('BACKUP_WINDOW_INVALID');
	});
	it.each([0, 300, 604801, Number.NaN, Number.POSITIVE_INFINITY, 1.5])('requires a bounded explicit proposal deadline at offset %s', (offset) => {
		const f = backupFixture(), proposalValidUntil = f.input.validAfter + offset;
		expect(() => prepareBackupEnrollment({ ...f.input, proposalValidUntil }, f.input.validAfter)).toThrow('BACKUP_PROPOSAL_WINDOW_INVALID');
	});
	it('binds the proposal expiry in both owner consent and new-factor enrollment', async () => {
		const f = backupFixture(), p = prepareBackupEnrollment(f.input, f.input.validAfter), proofs = await f.proofs();
		const changed = { ...f.input, proposalValidUntil: f.input.proposalValidUntil + 1 };
		const c = prepareBackupEnrollment(changed, changed.validAfter);
		expect(c.digest).not.toBe(p.digest); expect(c.enrollments[0].digest).not.toBe(p.enrollments[0].digest);
		await expect(authorizeBackupEnrollment(changed, f.assertion(p.digest), proofs, changed.validAfter)).rejects.toThrow();
		await expect(authorizeBackupEnrollment(changed, f.assertion(c.digest), proofs, changed.validAfter)).rejects.toThrow('BACKUP_ECDSA_INVALID');
	});
	it('rejects changed policies/nonce even with the old genuine signatures', async () => {
		const f = backupFixture(), p = prepareBackupEnrollment(f.input, f.input.validAfter), proofs = await f.proofs();
		const changed = { ...f.input, nextPolicy: { ...f.input.nextPolicy, upgradeDelaySeconds: f.input.nextPolicy.upgradeDelaySeconds + 1 } };
		await expect(authorizeBackupEnrollment(changed, f.assertion(p.digest), proofs, f.input.validAfter)).rejects.toThrow();
		await expect(authorizeBackupEnrollment(changed, f.assertion(prepareBackupEnrollment(changed, f.input.validAfter).digest), proofs,
			f.input.validAfter)).rejects.toThrow('BACKUP_ECDSA_INVALID');
	});
	it('rejects missing, duplicate, wrong-index and wrong-kind enrollment proofs', async () => {
		const f = backupFixture(), p = prepareBackupEnrollment(f.input, f.input.validAfter), proofs = await f.proofs();
		for (const bad of [proofs.slice(1), [proofs[0], proofs[0]], [proofs[0], { ...proofs[1], signerIndex: 99 }],
			[proofs[0], { signerIndex: proofs[1].signerIndex, kind: 'webauthn' as const, assertion: f.assertion(p.digest) }]]) {
			await expect(authorizeBackupEnrollment(f.input, f.assertion(p.digest), bad, f.input.validAfter)).rejects.toThrow();
		}
	});
	it('rejects malformed ECDSA, high-S and personal_sign-prefixed enrollment', async () => {
		const f = backupFixture(), p = prepareBackupEnrollment(f.input, f.input.validAfter), proofs = await f.proofs();
		const req = p.enrollments[0], member = p.nextPolicy.signers[req.signerIndex], key = f.keys.find((k) => k.address.toLowerCase() === member.key)!;
		const prefixed = await key.signMessage({ message: { raw: req.digest } });
		for (const signature of ['0x', `0x${'01'.repeat(32)}${'ff'.repeat(32)}1b`, `${prefixed}\n`, prefixed] as const) {
			await expect(authorizeBackupEnrollment(f.input, f.assertion(p.digest), [{ signerIndex: req.signerIndex, kind: 'ecdsa', signature }, proofs[1]],
				f.input.validAfter)).rejects.toThrow('BACKUP_ECDSA_INVALID');
		}
	});
	it('rejects an unverified ERC-1271 transport instead of treating its address as a direct key', () => {
		const f = backupFixture(), nextPolicy = { ...f.input.nextPolicy, signers: f.input.nextPolicy.signers.map((s) => s.kind === 0
			? { ...s, kind: 2 as const, verifier: s.key, verifierCodeHash: fixtureHash('a') } : s).sort((a, b) => signerId(a).localeCompare(signerId(b))) };
		expect(() => prepareBackupEnrollment({ ...f.input, nextPolicy }, f.input.validAfter)).toThrow('BACKUP_SIGNER_TRANSPORT_UNSUPPORTED');
		expect(assessPolicyContinuity(nextPolicy).direct_key_quorums).toEqual({ spend: false, admin: false });
	});
	it('rejects a different passkey verifier even when the supplied policy is structurally valid', () => {
		const f = backupFixture(), nextPolicy = { ...f.input.nextPolicy, signers: [...f.input.nextPolicy.signers,
			{ ...backupFixture().initial.policy.signers[0], verifierCodeHash: fixtureHash('e') }]
			.sort((a, b) => signerId(a).localeCompare(signerId(b))) };
		expect(() => prepareBackupEnrollment({ ...f.input, nextPolicy }, f.input.validAfter)).toThrow('BACKUP_VERIFIER_MISMATCH');
	});
	it('takes a snapshot of policy and proofs before asynchronous validation', async () => {
		const f = backupFixture(), p = prepareBackupEnrollment(f.input, f.input.validAfter), proofs = await f.proofs();
		const pending = authorizeBackupEnrollment(f.input, f.assertion(p.digest), proofs, f.input.validAfter);
		proofs.splice(0); f.input.nextPolicy.spendThreshold = 2;
		expect((await pending).proposalHash).toBe(p.digest);
	});
});

describe('Account V3 distinct backup commit', () => {
	it('binds fresh pending acknowledgement, incremented nonce and exact compiled commit ABI', () => {
		const f = backupFixture(), observed = f.pending(), now = f.input.validAfter;
		const c = prepareBackupCommit(f.input, observed, now, now + 100, now);
		const signed = authorizeBackupCommit(f.input, observed, now, now + 100, f.assertion(c.digest), now);
		expect(c.message).toMatchObject({ nonce: 1n, proposalHash: prepareBackupEnrollment(f.input, now).digest });
		expect(c.message.acknowledgementsHash).not.toBe(zeroHash); expect(c.digest).not.toBe(c.message.proposalHash);
		const decoded = decodeFunctionData({ abi: accountBackupAbi, data: signed.data }); expect(decoded.functionName).toBe('commit');
		const compiled = JSON.parse(readFileSync(new URL(import.meta.resolve('@gatopago/contract-artifacts/AccountV3.json')), 'utf8')) as { abi: Abi };
		expect(encodeFunctionData({ abi: compiled.abi, functionName: decoded.functionName, args: decoded.args })).toBe(signed.data);
		expect(signed.account_readiness).toBe('not_assessed');
	});
	it('does not accept a prepare signature as commit or switch the acknowledged checkpoint', () => {
		const f = backupFixture(), observed = f.pending(), now = f.input.validAfter, p = prepareBackupEnrollment(f.input, now);
		expect(() => authorizeBackupCommit(f.input, observed, now, now + 100, f.assertion(p.digest), now)).toThrow();
		const c = prepareBackupCommit(f.input, observed, now, now + 100, now);
		observed.checkpoint = { ...observed.checkpoint, block_hash: fixtureHash('f') };
		expect(() => authorizeBackupCommit(f.input, observed, now, now + 100, f.assertion(c.digest), now)).toThrow();
	});
	it.each([{ kind: 3 }, { hash: fixtureHash('e') }, { security_version: '2' }, { previous_manifest_hash: fixtureHash('e') },
		{ chain_scope_hash: fixtureHash('e') }, { ready_at: 0 }, { valid_until: 0 }])('rejects changed pending proposal %#', (patch) => {
		const f = backupFixture(), observed = f.pending(), now = f.input.validAfter;
		observed.security.pending = { ...observed.security.pending!, ...patch };
		expect(() => prepareBackupCommit(f.input, observed, now, now + 100, now)).toThrow('BACKUP_PENDING_MISMATCH');
	});
	it('rejects missing pending, stale checkpoint, wrong nonce and validity extension', () => {
		const f = backupFixture(), now = f.input.validAfter;
		expect(() => prepareBackupCommit(f.input, f.input.observation, now, now + 100, now)).toThrow();
		const old = f.pending(); old.checkpoint = { ...f.input.observation.checkpoint };
		expect(() => prepareBackupCommit(f.input, old, now, now + 100, now)).toThrow();
		const wrong = f.pending(); wrong.security.nonces.admin = '0';
		expect(() => prepareBackupCommit(f.input, wrong, now, now + 100, now)).toThrow();
		expect(() => prepareBackupCommit(f.input, f.pending(), now + 1, now + 302, now + 1)).toThrow('BACKUP_WINDOW_INVALID');
		const expiry = f.input.proposalValidUntil;
		expect(() => prepareBackupCommit(f.input, f.pending(), expiry - 1, expiry + 1, expiry - 1)).toThrow('BACKUP_PENDING_MISMATCH');
	});
	it('allows a fresh confirmation after prepare expiry without re-authorizing that prepare', async () => {
		const f = backupFixture(), late = f.input.validAfter + 3600, observed = f.pending();
		const p = prepareBackupEnrollment(f.input, f.input.validAfter), proofs = await f.proofs();
		await expect(authorizeBackupEnrollment(f.input, f.assertion(p.digest), proofs, late)).rejects.toThrow('BACKUP_WINDOW_INVALID');
		const c = prepareBackupCommit(f.input, observed, late, late + 300, late);
		expect(c.message.proposalHash).toBe(p.digest); expect(c.message.validUntil).toBe(late + 300);
		expect(authorizeBackupCommit(f.input, observed, late, late + 300, f.assertion(c.digest), late).proposalHash).toBe(p.digest);
		expect(() => authorizeBackupCommit(f.input, observed, late, late + 300, f.assertion(p.digest), late)).toThrow();
	});
});
