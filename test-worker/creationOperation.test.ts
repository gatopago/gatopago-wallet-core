import { testPrincipal } from './principal.fixture';
import { seedUser } from './user.fixture';
import { env } from 'cloudflare:workers';
import { applyD1Migrations } from 'cloudflare:test';
import { afterEach, beforeAll, beforeEach, describe, expect, it, vi } from 'vitest';
import { createResourceId, parseResourceId, type ResourceId } from '@gatopago/shared/v3/primitives';
import { authorizeCreationOperation, prepareCreationOperation } from '@gatopago/shared/v3/creation-operation';
import type { Principal } from '../src/auth/principal';
import { CreationOperationRepository } from '../src/creation/creationOperation';
import { InitializationRepository } from '../src/creation/initialization';
import { WalletRepository } from '../src/accounts/repository';
import { initializationFixture } from '@gatopago/test-fixtures/v3-initialization';
import { fixtureHash } from '@gatopago/test-fixtures/v3-inspection';

let f: ReturnType<typeof initializationFixture>;
const now = () => Math.floor(Date.now() / 1000);
const identity = (subject = 'creation-a'): Principal => testPrincipal(subject);
const gas = () => ({ verificationGasLimit: 2_000_000n, callGasLimit: 100_000n, preVerificationGas: 150_000n,
	maxFeePerGas: 1_000_000_000n, maxPriorityFeePerGas: 0n, maximumGasCharge: 2_250_000_000_000_000n });
const initializations = (principal = identity(), pins = [f.pin]) => new InitializationRepository(env.WALLET_DB, principal, f.input.scope, pins);
const repository = (principal = identity(), pins = [f.pin]) => new CreationOperationRepository(env.WALLET_DB, principal, f.input.scope, pins);
async function start(principal = identity(), authorized = true) {
	const session = await seedUser(env.WALLET_DB, principal);
	const enrolled = await env.WALLET_DB.prepare('SELECT id FROM webauthn_credentials WHERE user_id = ? AND public_key = ? AND rp_id = ?')
		.bind(session.user_id, f.input.publicKey, f.input.scope.rpId).first<string>('id');
	const credentialRef = enrolled ? parseResourceId('operation', enrolled) : createResourceId('operation');
	// Prior enrollment is a fixture; both creation authorizations below use real ephemeral P-256.
	if (!enrolled) await env.WALLET_DB.prepare(`INSERT INTO webauthn_credentials
		(id,user_id,rp_id,origin,credential_id,public_key,transports_json,aaguid,backup_eligible,backed_up,sign_count,response_hash,created_at)
		VALUES (?,?,?,?,?,?,'["internal"]','00000000-0000-0000-0000-000000000000',0,0,1,?,?)`)
		.bind(credentialRef, session.user_id, f.input.scope.rpId, f.input.scope.origin, credentialRef.replaceAll('-', ''), f.input.publicKey,
			fixtureHash('1'), now()).run();
	const id = createResourceId('operation');
	const prepared = await initializations(principal).prepare({ id, credentialRef, profileDigest: f.pin.digest, userSaltCommitment: f.input.userSaltCommitment });
	const proof = f.assertion(prepared.approval_digest);
	if (authorized) await initializations(principal).authorize(id, proof);
	return { id, proof, prepared, credentialRef, ...session };
}
async function candidate(principal = identity()) {
	const initial = await start(principal), prepared = await repository(principal).prepare(initial.id, gas());
	return { ...initial, operationProof: f.assertion(prepared.operation_digest), operation: prepared };
}
const operation = (id: string) => env.WALLET_DB.prepare('SELECT * FROM account_creation_operations WHERE initialization_id = ?').bind(id).first();
const outbox = (id: string) => env.WALLET_DB.prepare('SELECT * FROM account_creation_outbox WHERE initialization_id = ?').bind(id).first();
const operationCount = () => env.WALLET_DB.prepare('SELECT count(*) AS n FROM account_creation_operations').first<number>('n');
const clean = () => env.WALLET_DB.exec(`DROP TRIGGER IF EXISTS creation_fail_outbox;
	DELETE FROM account_creation_outbox; DELETE FROM account_creation_operations; DELETE FROM account_initializations;
	DELETE FROM webauthn_credentials; DELETE FROM webauthn_enrollments; DELETE FROM wallet_accounts;
	DELETE FROM wallets; DELETE FROM users;`);
beforeAll(async () => { await applyD1Migrations(env.WALLET_DB, env.V3_TEST_MIGRATIONS); });
beforeEach(async () => { f = initializationFixture(); await clean(); });
afterEach(async () => { vi.restoreAllMocks(); await clean(); });

describe('durable first UserOperation with distinct consent and transactional outbox', () => {
	it('has no construction I/O, external send or enabled account; initial authorization is required', async () => {
		const fetch = vi.spyOn(globalThis, 'fetch'), r = repository(), initial = await start(identity(), false);
		await expect(r.prepare(initial.id, gas())).rejects.toMatchObject({ code: 'INITIALIZATION_REQUIRED' });
		expect(await operationCount()).toBe(0); expect(fetch).not.toHaveBeenCalled();
	});
	it('restores the initial proof after a reload and recomputes exactly the independent client candidate', async () => {
		const a = await start();
		const result = await repository().prepare(a.id, gas()), restored = await repository().read(a.id);
		expect(restored.initialProof).toEqual(a.proof);
		const local = prepareCreationOperation(a.prepared.input, a.proof, gas(), now());
		expect(restored.candidate).toEqual(local);
		expect(result).toMatchObject({ user_op_hash: local.userOpHash, operation_digest: local.digest, state: 'prepared',
			delivery_state: 'not_requested', deployment_assessment: 'not_assessed', receive_enabled: false, spend_enabled: false });
		expect(await outbox(a.id)).toBeNull();
	});
	it('eight concurrent prepares have exactly one immutable record', async () => {
		const a = await start(), results = await Promise.all(Array.from({ length: 8 }, () => repository().prepare(a.id, gas())));
		expect(results.every((result) => JSON.stringify(result) === JSON.stringify(results[0]))).toBe(true);
		expect(await operationCount()).toBe(1); expect(await outbox(a.id)).toBeNull();
	});
	it('no gas field or approved cap can be silently changed on retry', async () => {
		const a = await candidate(), before = await operation(a.id);
		for (const field of Object.keys(gas()) as (keyof ReturnType<typeof gas>)[]) {
			await expect(repository().prepare(a.id, { ...gas(), [field]: gas()[field] + 1n })).rejects.toMatchObject({ code: 'CREATION_CONFLICT' });
		}
		expect(await operation(a.id)).toEqual(before);
	});
	it('persists both authorizations and one outbox atomically across eight equivalent retries', async () => {
		const a = await candidate();
		const results = await Promise.all(Array.from({ length: 8 }, () => repository().authorize(a.id, a.operationProof)));
		expect(results.every((result) => result.state === 'authorized' && result.delivery_state === 'pending' && result.deployment_assessment === 'not_assessed')).toBe(true);
		const restored = await repository().read(a.id);
		const expected = authorizeCreationOperation(a.prepared.input, a.proof, gas(), a.operationProof, now());
		expect(restored.signed).toEqual(expected);
		expect(await outbox(a.id)).toMatchObject({ initialization_id: a.id, user_op_hash: expected.userOpHash, state: 'pending' });
		expect(await env.WALLET_DB.prepare('SELECT count(*) AS n FROM account_creation_outbox').first('n')).toBe(1);
		expect(await env.WALLET_DB.prepare('SELECT count(*) AS n FROM wallets').first('n')).toBe(0);
		expect(await env.WALLET_DB.prepare('SELECT count(*) AS n FROM wallet_accounts').first('n')).toBe(0);
	});
	it('initial-consent, wrong-key, wrong-origin and no-user-verification proofs cannot authorize the operation', async () => {
		const a = await candidate();
		for (const proof of [a.proof, initializationFixture().assertion(a.operation.operation_digest),
			f.assertion(a.operation.operation_digest, { origin: 'https://other.gatopago.com' }), f.assertion(a.operation.operation_digest, { flags: 1 })]) {
			await expect(repository().authorize(a.id, proof)).rejects.toThrow();
		}
		expect((await operation(a.id))?.authorized_at).toBeNull(); expect(await outbox(a.id)).toBeNull();
	});
	it('only one of competing valid but different proofs wins; it cannot overwrite the winner', async () => {
		const a = await candidate(), second = f.assertion(a.operation.operation_digest, { count: 3 });
		const results = await Promise.allSettled([repository().authorize(a.id, a.operationProof), repository().authorize(a.id, second)]);
		expect(results.filter((result) => result.status === 'fulfilled')).toHaveLength(1);
		const failure = results.find((result) => result.status === 'rejected');
		expect(failure).toMatchObject({ reason: { code: 'CREATION_CONFLICT' } });
		const before = await operation(a.id), beforeOutbox = await outbox(a.id);
		const losingProof = results[0].status === 'fulfilled' ? second : a.operationProof;
		await expect(repository().authorize(a.id, losingProof)).rejects.toMatchObject({ code: 'CREATION_CONFLICT' });
		expect(await operation(a.id)).toEqual(before); expect(await outbox(a.id)).toEqual(beforeOutbox);
	});
	it('an outbox SQL failure rolls back the signature; the same proof can then retry successfully', async () => {
		const a = await candidate();
		await env.WALLET_DB.prepare(`CREATE TRIGGER creation_fail_outbox BEFORE INSERT ON account_creation_outbox
			BEGIN SELECT RAISE(ABORT, 'synthetic outbox failure'); END`).run();
		await expect(repository().authorize(a.id, a.operationProof)).rejects.toThrow();
		expect((await operation(a.id))?.authorized_at).toBeNull(); expect(await outbox(a.id)).toBeNull();
		await env.WALLET_DB.exec('DROP TRIGGER creation_fail_outbox;');
		expect(await repository().authorize(a.id, a.operationProof)).toMatchObject({ state: 'authorized' });
	});
	it('hides and protects another identity\'s candidates and proof bytes', async () => {
		const a = await candidate(), other = identity('creation-b');
		await seedUser(env.WALLET_DB, other);
		for (const r of [repository(other), repository({ ...other, environment: 'unsupported' as never })]) {
			await expect(r.read(a.id)).rejects.toThrow();
			await expect(r.prepare(a.id, gas())).rejects.toThrow();
			await expect(r.authorize(a.id, a.operationProof)).rejects.toThrow();
		}
		expect((await operation(a.id))?.authorized_at).toBeNull(); expect(await outbox(a.id)).toBeNull();
	});
	it('session expiry, disabled users, and an auth cutoff cannot commit a pending signature', async () => {
		const principal = identity(), a = await candidate(principal);
		await expect(repository({ ...principal, expiresAt: now() }).authorize(a.id, a.operationProof)).rejects.toMatchObject({ code: 'UNAUTHENTICATED' });
		await env.WALLET_DB.prepare('UPDATE users SET auth_not_before = ? WHERE id = ?').bind(principal.authTime + 1, a.user_id).run();
		await expect(repository(principal).authorize(a.id, a.operationProof)).rejects.toMatchObject({ code: 'UNAUTHENTICATED' });
		await env.WALLET_DB.prepare('UPDATE users SET auth_not_before = 0, disabled_at = ? WHERE id = ?').bind(now(), a.user_id).run();
		await expect(repository().read(a.id)).rejects.toMatchObject({ code: 'UNAUTHENTICATED' });
		expect((await operation(a.id))?.authorized_at).toBeNull(); expect(await outbox(a.id)).toBeNull();
	});
	it('expiry prevents new creation authorization without renewing a previously accepted operation', async () => {
		const a = await candidate(), b = await candidate();
		await repository().authorize(b.id, b.operationProof);
		const before = await operation(b.id), beforeOutbox = await outbox(b.id);
		vi.spyOn(Date, 'now').mockReturnValue((Math.max(a.prepared.input.validUntil, b.prepared.input.validUntil) + 1) * 1000);
		await expect(repository().prepare(a.id, gas())).rejects.toMatchObject({ code: 'CREATION_EXPIRED' });
		await expect(repository().authorize(a.id, a.operationProof)).rejects.toMatchObject({ code: 'CREATION_EXPIRED' });
		expect(await repository().authorize(b.id, b.operationProof)).toMatchObject({ state: 'authorized', authorization_expired: true });
		expect(await repository().prepare(b.id, gas())).toMatchObject({ state: 'authorized', authorization_expired: true });
		expect(await operation(b.id)).toEqual(before); expect(await outbox(b.id)).toEqual(beforeOutbox);
	});
	it.each(['disabled', 'cutoff'] as const)('SQL rechecks %s after the last successful ownership read', async (change) => {
		const principal = identity(), a = await candidate(principal);
		const original = WalletRepository.prototype.getSession;
		let reads = 0, invalidated = false;
		vi.spyOn(WalletRepository.prototype, 'getSession').mockImplementation(async function (this: WalletRepository) {
			const session = await original.call(this);
			// Two reads restore initial consent; the third is immediately before the atomic write.
			// Invalidate after that read so ONLY the SQL authorization predicate can stop commitment.
			if (++reads === 3) {
				if (change === 'disabled') await env.WALLET_DB.prepare('UPDATE users SET disabled_at = ? WHERE id = ?').bind(now(), a.user_id).run();
				else await env.WALLET_DB.prepare('UPDATE users SET auth_not_before = ? WHERE id = ?').bind(principal.authTime + 1, a.user_id).run();
				invalidated = true;
			}
			return session;
		});
		await expect(repository(principal).authorize(a.id, a.operationProof)).rejects.toMatchObject({ code: 'UNAUTHENTICATED' });
		expect(invalidated).toBe(true); expect((await operation(a.id))?.authorized_at).toBeNull(); expect(await outbox(a.id)).toBeNull();
	});
	it('rejects altered gas, hashes, proof bodies, signatures and outbox evidence after persistence', async () => {
		const a = await candidate(); await repository().authorize(a.id, a.operationProof);
		const before = await operation(a.id);
		for (const [column, replacement] of [['gas_terms_json', JSON.stringify({ ...JSON.parse(String(before!.gas_terms_json)), maxFeePerGas: '2' })],
			['user_op_hash', fixtureHash('a')], ['operation_digest', fixtureHash('b')], ['assertion_body', '{}'], ['operation_signature', '0xab']]) {
			// Static allowlisted columns only; this is a corruption test, never caller-built SQL.
			await env.WALLET_DB.prepare(`UPDATE account_creation_operations SET ${column} = ? WHERE initialization_id = ?`).bind(replacement, a.id).run();
			await expect(repository().read(a.id)).rejects.toMatchObject({ code: 'WALLET_DATA_INVALID' });
			await env.WALLET_DB.prepare(`UPDATE account_creation_operations SET ${column} = ? WHERE initialization_id = ?`).bind(before![column], a.id).run();
		}
		await env.WALLET_DB.prepare('UPDATE account_creation_outbox SET user_op_hash = ? WHERE initialization_id = ?').bind(fixtureHash('c'), a.id).run();
		await expect(repository().read(a.id)).rejects.toMatchObject({ code: 'WALLET_DATA_INVALID' });
	});
	it('requires both stored proofs to remain cryptographically valid, not just well-formed JSON', async () => {
		const a = await candidate(); await repository().authorize(a.id, a.operationProof);
		const initial = await env.WALLET_DB.prepare('SELECT assertion_body FROM account_initializations WHERE id = ?').bind(a.id).first<string>('assertion_body');
		const corrupted = JSON.parse(initial!); corrupted.signatureDER = `0x${'11'.repeat(70)}`;
		await env.WALLET_DB.prepare('UPDATE account_initializations SET assertion_body = ? WHERE id = ?').bind(JSON.stringify(corrupted), a.id).run();
		await expect(repository().read(a.id)).rejects.toMatchObject({ code: 'WALLET_DATA_INVALID' });
	});
	it('a removed profile or changed enrolled key invalidates reads without falling back to another deployment', async () => {
		const a = await candidate();
		await expect(repository(identity(), []).read(a.id)).rejects.toMatchObject({ code: 'PROFILE_UNAVAILABLE' });
		await env.WALLET_DB.prepare('UPDATE webauthn_credentials SET public_key = ? WHERE id = ?')
			.bind(initializationFixture().input.publicKey, a.credentialRef).run();
		await expect(repository().authorize(a.id, a.operationProof)).rejects.toMatchObject({ code: 'WALLET_DATA_INVALID' });
		expect(await outbox(a.id)).toBeNull();
	});
	it('snapshots mutable gas and proof input before asynchronous ownership checks', async () => {
		const a = await start(), terms = gas(), pending = repository().prepare(a.id, terms);
		terms.maximumGasCharge = 1n; await pending;
		const read = await repository().read(a.id), proof = f.assertion(read.operation_digest);
		const authorization = repository().authorize(a.id, proof); proof.authenticatorData.fill(0); proof.signatureDER.fill(0);
		expect(await authorization).toMatchObject({ state: 'authorized' });
		expect((await repository().read(a.id)).terms).toEqual(gas());
	});
	it('SQL cannot accept a partial signature with a null authorization timestamp', async () => {
		const a = await candidate();
		await expect(env.WALLET_DB.prepare('UPDATE account_creation_operations SET operation_signature = ? WHERE initialization_id = ?')
			.bind('0xab', a.id).run()).rejects.toThrow();
		expect((await operation(a.id))?.authorized_at).toBeNull();
	});
	it('an expired initial consent cannot create a new gas candidate or delivery request', async () => {
		const a = await start();
		vi.spyOn(Date, 'now').mockReturnValue(a.prepared.input.validUntil * 1000);
		await expect(repository().prepare(a.id, gas())).rejects.toMatchObject({ code: 'CREATION_EXPIRED' });
		expect(await operationCount()).toBe(0); expect(await outbox(a.id)).toBeNull();
	});
	it('missing outbox after authorization is corruption, not an invitation to enqueue again', async () => {
		const a = await candidate(); await repository().authorize(a.id, a.operationProof);
		await env.WALLET_DB.prepare('DELETE FROM account_creation_outbox WHERE initialization_id = ?').bind(a.id).run();
		await expect(repository().authorize(a.id, a.operationProof)).rejects.toMatchObject({ code: 'WALLET_DATA_INVALID' });
		expect(await outbox(a.id)).toBeNull();
	});
	it('malformed or oversized proof and gas input is rejected without authorizing or enqueueing', async () => {
		const a = await candidate(), before = await operation(a.id);
		for (const field of ['authenticatorData', 'clientDataJSON', 'signatureDER'] as const) {
			await expect(repository().authorize(a.id, { ...a.operationProof, [field]: new Uint8Array(8000) })).rejects.toThrow();
			await expect(repository().authorize(a.id, { ...a.operationProof, [field]: new Uint8Array(0) })).rejects.toThrow();
		}
		const b = await start();
		for (const terms of [{ ...gas(), verificationGasLimit: 1n << 120n }, { ...gas(), maximumGasCharge: 1n },
			{ ...gas(), maxFeePerGas: -1n }, { ...gas(), maximumGasCharge: 1n << 256n }]) {
			await expect(repository().prepare(b.id, terms)).rejects.toThrow();
		}
		expect(await operation(a.id)).toEqual(before); expect(await outbox(a.id)).toBeNull(); expect(await operation(b.id)).toBeNull();
	});
	it('noncanonical persisted proof cannot bypass exact retry comparisons', async () => {
		const a = await candidate(); await repository().authorize(a.id, a.operationProof);
		const before = await operation(a.id);
		await env.WALLET_DB.prepare('UPDATE account_creation_operations SET assertion_body = ? WHERE initialization_id = ?')
			.bind(` ${String(before!.assertion_body)}`, a.id).run();
		await expect(repository().read(a.id)).rejects.toMatchObject({ code: 'WALLET_DATA_INVALID' });
	});
	it('a missing operation is not reconstructed or queued just by reading an authorized initialization', async () => {
		const a = await start();
		await expect(repository().read(a.id)).rejects.toMatchObject({ code: 'NOT_FOUND' });
		await expect(repository().read('invalid' as ResourceId<'operation'>)).rejects.toThrow();
		expect(await operationCount()).toBe(0);
	});
});
