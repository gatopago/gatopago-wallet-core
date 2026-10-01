import { testPrincipal } from './principal.fixture';
import { seedUser } from './user.fixture';
import { env, exports } from 'cloudflare:workers';
import { applyD1Migrations } from 'cloudflare:test';
import { afterEach, beforeAll, beforeEach, describe, expect, it, vi } from 'vitest';
import manifests from '@gatopago/environment/environments.json';
import { parseEnvironment } from '@gatopago/environment';
import { createResourceId } from '@gatopago/shared/v3/primitives';
import { clientMutationHeaders, WALLET_RELEASE_POLICY } from '@gatopago/shared/v3/client-release';
import { parseInitializationHistory, parseInitializationPreparation, parseInitializationRestoration } from '@gatopago/shared/v3/initialization-wire';
import { createInitializationRoute } from '../src/creation/initializationRoute';
import { WalletRepository } from '../src/accounts/repository';
import { initializationFixture } from '@gatopago/test-fixtures/v3-initialization';
import { fixtureHash } from '@gatopago/test-fixtures/v3-inspection';
import { clearIdentityKeys, projectId, testIdentitySigner } from './identity.fixture';

const initializationRoute = createInitializationRoute({ profiles: [], releasePolicy: WALLET_RELEASE_POLICY, async requireFreshDeployment() { throw new Error('Unexpected observer'); } });

const ROOT = '/app/v1/account-initializations';
const now = () => Math.floor(Date.now() / 1000);
const config = parseEnvironment({ ...manifests.staging, status: 'provisioned', firebase_project_id: projectId,
	wallet_enabled: ['eip155:84532'] });
let signer: Awaited<ReturnType<typeof testIdentitySigner>>;
let f: ReturnType<typeof initializationFixture>;
const account = () => ({ generation: '3', contract_manifest_version: f.profile.deployment.manifest_id });
const requestBody = (credentialRef: string) => ({ request_id: createResourceId('operation'), credential_ref: credentialRef,
	profile_sha256: f.pin.digest, user_salt_commitment: f.input.userSaltCommitment });
const count = () => env.WALLET_DB.prepare('SELECT count(*) AS n FROM account_initializations').first<number>('n');
const b64 = (bytes: Uint8Array) => Buffer.from(bytes).toString('base64url');
function proof(digest: `0x${string}`, options: Parameters<typeof f.assertion>[1] = {}) {
	const p = f.assertion(digest, options);
	return { authenticator_data: b64(p.authenticatorData), client_data: b64(p.clientDataJSON), signature: b64(p.signatureDER) };
}
// Only the fresh deployment observer is stubbed in these HTTP tests. Profiles are
// synthetic. JWT verification, P-256 typed signatures, ownership and D1 are real.
function candidate(observe = vi.fn(async () => undefined)) {
	const deps = { profiles: [{ ...f.pin, environment: 'staging' as const }],
		releasePolicy: { ...WALLET_RELEASE_POLICY, account_profiles: [account()] }, requireFreshDeployment: observe };
	return { run: createInitializationRoute(deps), observe, deps };
}
async function request(path: string, body: unknown, user = 'test-user-a', method = 'POST') {
	return new Request(`${config.api_origin}${path}`, { method, headers: { Origin: config.web_origin,
		Authorization: `Bearer ${await signer.token({ sub: user })}`, 'Content-Type': 'application/json', ...clientMutationHeaders('staging', method === 'GET' ? undefined : account()) },
		...(method === 'POST' ? { body: JSON.stringify(body) } : {}) });
}
async function enroll(subject = 'test-user-a') {
	const principal = testPrincipal(subject);
	const session = await seedUser(env.WALLET_DB, principal);
	const id = createResourceId('operation'), rawId = b64(crypto.getRandomValues(new Uint8Array(32)));
	await env.WALLET_DB.prepare(`INSERT INTO webauthn_credentials
		(id,user_id,rp_id,origin,credential_id,public_key,transports_json,aaguid,backup_eligible,backed_up,sign_count,response_hash,created_at)
		VALUES (?,?,?,?,?,?,'["internal"]','00000000-0000-0000-0000-000000000000',0,0,1,?,?)`)
		.bind(id, session.user_id, config.webauthn_rp_id, config.web_origin, rawId,
			subject === 'test-user-a' ? f.input.publicKey : initializationFixture().input.publicKey, fixtureHash('1'), now()).run();
	return { id, rawId, ...session };
}
beforeAll(async () => { await applyD1Migrations(env.WALLET_DB, env.V3_TEST_MIGRATIONS); signer = await testIdentitySigner(); });
beforeEach(async () => {
	f = initializationFixture(); await clearIdentityKeys(); signer.mock();
	await env.WALLET_DB.exec(`DELETE FROM account_creation_outbox; DELETE FROM account_creation_operations;
		DELETE FROM account_initializations; DELETE FROM webauthn_credentials; DELETE FROM webauthn_enrollments;
		DELETE FROM wallet_accounts; DELETE FROM wallets; DELETE FROM users;`);
});
afterEach(() => { vi.restoreAllMocks(); vi.unstubAllGlobals(); });

describe('initialization HTTP consent, not account deployment', () => {
	it('mounts the route but neither unprovisioned runtime nor the real empty release can authorize accounts', async () => {
		const req = await request(ROOT, requestBody(createResourceId('operation')));
		expect((await exports.default.fetch(await request(ROOT, requestBody(createResourceId('operation'))))).status).toBe(503);
		const result = await initializationRoute(req, env, config);
		expect(await result.json()).toEqual({ error_code: 'ACCOUNT_VERSION_UNAVAILABLE' }); expect(await count()).toBe(0);
	});
	it('reconstructs the selected credential consent and commits an exact signed retry only once', async () => {
		const key = await enroll(), input = requestBody(key.id), c = candidate();
		const response = await c.run(await request(ROOT, input), env, config);
		expect(response.status).toBe(200); expect(response.headers.get('Cache-Control')).toContain('no-store');
		const value = await response.json();
		const expected = { id: input.request_id, credentialRef: key.id, document: f.pin.document, profileDigest: f.pin.digest,
			userSaltCommitment: input.user_salt_commitment, scope: f.input.scope };
		const p = parseInitializationPreparation(value, expected);
		expect(p.credential_id).toBe(key.rawId);
		expect(p).toMatchObject({ state: 'prepared', account_deployed: false, receive_enabled: false, spend_enabled: false });
		const signed = proof(p.approval_digest);
		for (let i = 0; i < 2; i++) {
			const result = await c.run(await request(`${ROOT}/${input.request_id}/authorize`, signed), env, config);
			expect(result.status).toBe(200); expect(await result.json()).toMatchObject({ state: 'authorized', approval_digest: p.approval_digest,
				account_deployed: false, receive_enabled: false, spend_enabled: false });
		}
		const reload = await c.run(await request(ROOT, input), env, config);
		expect(parseInitializationPreparation(await reload.json(), expected).state).toBe('authorized');
		expect(await count()).toBe(1); expect(c.observe).toHaveBeenCalledTimes(4);
		expect(await env.WALLET_DB.prepare('SELECT count(*) AS n FROM wallets').first('n')).toBe(0);
		expect(await env.WALLET_DB.prepare('SELECT count(*) AS n FROM account_creation_outbox').first('n')).toBe(0);
		expect(JSON.stringify(value)).not.toContain('assertion'); expect(JSON.stringify(value)).not.toContain('document');
	});
	it('requires a valid login and existing profile before probing deployment or writing data', async () => {
		const c = candidate(), body = requestBody(createResourceId('operation'));
		const unauth = await request(ROOT, body); unauth.headers.delete('Authorization');
		expect((await c.run(unauth, env, config)).status).toBe(401);
		expect((await c.run(await request(ROOT, body), env, config)).status).toBe(409);
		expect(c.observe).not.toHaveBeenCalled(); expect(await count()).toBe(0);
	});
	it('cannot select another user credential or authorize another user initialization', async () => {
		const key = await enroll(); await enroll('test-user-b'); const c = candidate(), input = requestBody(key.id);
		expect((await c.run(await request(ROOT, input, 'test-user-b'), env, config)).status).toBe(404);
		const p = await (await c.run(await request(ROOT, input), env, config)).json<{ approval_digest: `0x${string}` }>();
		c.observe.mockClear();
		expect((await c.run(await request(`${ROOT}/${input.request_id}/authorize`, proof(p.approval_digest), 'test-user-b'), env, config)).status).toBe(404);
		expect(c.observe).not.toHaveBeenCalled();
	});
	it.each(['public_key', 'document', 'factory', 'scope', 'checkpoint', 'rpc_url'])('does not accept %s in the request', async (field) => {
		const key = await enroll(), c = candidate();
		expect((await c.run(await request(ROOT, { ...requestBody(key.id), [field]: 'caller value' }), env, config)).status).toBe(400);
		expect(await count()).toBe(0); expect(c.observe).not.toHaveBeenCalled();
	});
	it('checks both header compatibility and the configured network, not just a profile hash', async () => {
		const key = await enroll(), input = requestBody(key.id), c = candidate();
		const identityHeaders = await request(ROOT, input);
		for (const [key, value] of Object.entries(clientMutationHeaders('staging'))) identityHeaders.headers.set(key, value);
		expect((await c.run(identityHeaders, env, config)).status).toBe(409);
		expect((await c.run(await request(ROOT, input), env, { ...config, wallet_enabled: [] })).status).toBe(503);
		expect((await c.run(await request(ROOT, { ...input, profile_sha256: fixtureHash('a') }), env, config)).status).toBe(503);
		expect(c.observe).not.toHaveBeenCalled(); expect(await count()).toBe(0);
	});
	it('rejects unavailable observation and rechecks identity after deployment observation', async () => {
		const key = await enroll(), input = requestBody(key.id), c = candidate(vi.fn(async () => { throw new Error('RPC unavailable'); }));
		expect((await c.run(await request(ROOT, input), env, config)).status).toBe(503); expect(await count()).toBe(0);
		c.observe.mockImplementation(async () => {
			await env.WALLET_DB.prepare('UPDATE users SET disabled_at = ? WHERE id = ?').bind(now(), key.user_id).run();
		});
		expect((await c.run(await request(ROOT, input), env, config)).status).toBe(401); expect(await count()).toBe(0);
	});
	it('does not accept a registration/unrelated digest or an assertion without verification', async () => {
		const key = await enroll(), input = requestBody(key.id), c = candidate();
		const p = await (await c.run(await request(ROOT, input), env, config)).json<{ approval_digest: `0x${string}` }>();
		for (const bad of [proof(fixtureHash('c')), proof(p.approval_digest, { flags: 1 })]) {
			expect((await c.run(await request(`${ROOT}/${input.request_id}/authorize`, bad), env, config)).status).toBe(400);
		}
		expect(await env.WALLET_DB.prepare('SELECT authorized_at FROM account_initializations WHERE id = ?').bind(input.request_id).first('authorized_at')).toBeNull();
	});
	it('rejects changed idempotency content without replacing consent', async () => {
		const key = await enroll(), input = requestBody(key.id), c = candidate();
		expect((await c.run(await request(ROOT, input), env, config)).status).toBe(200);
		expect((await c.run(await request(ROOT, { ...input, user_salt_commitment: fixtureHash('a') }), env, config)).status).toBe(409);
		expect(await count()).toBe(1);
	});
	it('does not expose signing metadata if ownership is revoked after the D1 read', async () => {
		const key = await enroll(), c = candidate(), input = requestBody(key.id);
		await c.run(await request(ROOT, input), env, config);
		const original = WalletRepository.prototype.getSession;
		let calls = 0;
		vi.spyOn(WalletRepository.prototype, 'getSession').mockImplementation(async function (this: WalletRepository) {
			if (++calls === 3) await env.WALLET_DB.prepare('UPDATE users SET disabled_at = ? WHERE id = ?').bind(now(), key.user_id).run();
			return original.call(this);
		});
		const response = await c.run(await request(`${ROOT}/${input.request_id}/authorize`, proof(fixtureHash('a'))), env, config);
		expect(response.status).toBe(401); expect(await response.json()).toEqual({ error_code: 'UNAUTHENTICATED' });
	});
	it('expired unsigned consent cannot be extended by prepare or authorize', async () => {
		const key = await enroll(), input = requestBody(key.id), c = candidate();
		const p = await (await c.run(await request(ROOT, input), env, config)).json<{ approval_digest: `0x${string}` }>();
		const initialTime = Date.now(), date = vi.spyOn(Date, 'now').mockReturnValue(initialTime + 301_000);
		expect((await c.run(await request(ROOT, input), env, config)).status).toBe(410);
		expect((await c.run(await request(`${ROOT}/${input.request_id}/authorize`, proof(p.approval_digest)), env, config)).status).toBe(410);
		date.mockRestore(); expect(await count()).toBe(1);
	});
	it('never accepts GET mutations, foreign origins, query parameters or unexpected CORS headers', async () => {
		const c = candidate(), body = requestBody(createResourceId('operation'));
		expect((await c.run(await request(`${ROOT}/${body.request_id}/authorize`, body, 'test-user-a', 'GET'), env, config)).status).toBe(405);
		expect((await c.run(await request(`${ROOT}?profile=other`, body), env, config)).status).toBe(404);
		const foreign = await request(ROOT, body); foreign.headers.set('Origin', 'https://gatopago.com');
		expect((await c.run(foreign, env, config)).status).toBe(403);
		const preflight = await request(ROOT, {}, 'test-user-a', 'OPTIONS');
		preflight.headers.set('Access-Control-Request-Method', 'POST'); preflight.headers.set('Access-Control-Request-Headers', 'authorization,content-type');
		expect((await c.run(preflight, env, config)).status).toBe(200);
		preflight.headers.set('Access-Control-Request-Headers', 'x-secret'); expect((await c.run(preflight, env, config)).status).toBe(403);
		expect(c.observe).not.toHaveBeenCalled(); expect(await count()).toBe(0);
	});
	it('bounds body size and detaches server-owned configuration before asynchronous requests', async () => {
		const key = await enroll(), input = requestBody(key.id), c = candidate();
		c.deps.profiles.length = 0; c.deps.releasePolicy.account_profiles.length = 0;
		expect((await c.run(await request(ROOT, { padding: 'a'.repeat(9000) }), env, config)).status).toBe(413);
		expect((await c.run(await request(ROOT, input), env, config)).status).toBe(200);
	});
});

describe('owned history and restoration after a new HTTP session', () => {
	async function prepare() {
		const key = await enroll(), input = requestBody(key.id), c = candidate();
		const result = await c.run(await request(ROOT, input), env, config);
		expect(result.status).toBe(200);
		const preparation = await result.json<{ approval_digest: `0x${string}` }>();
		return { key, input, c, preparation };
	}
	async function history(c: ReturnType<typeof candidate>, user = 'test-user-a', after = '') {
		const result = await c.run(await request(`${ROOT}${after}`, null, user, 'GET'), env, config);
		expect(result.status).toBe(200); expect(result.headers.get('Cache-Control')).toContain('no-store');
		return parseInitializationHistory(await result.json());
	}
	it('restores the exact unsigned consent using only GET and never leaks saved signatures', async () => {
		const t = await prepare(), c = candidate(vi.fn(async () => { throw new Error('No RPC on reads'); }));
		const page = await history(c);
		expect(page.data).toHaveLength(1); expect(page.data[0]).toMatchObject({ initialization_id: t.input.request_id, state: 'prepared' });
		const result = await c.run(await request(`${ROOT}/${t.input.request_id}`, null, 'test-user-a', 'GET'), env, config);
		expect(result.status).toBe(200);
		const value = await result.json(), restored = parseInitializationRestoration(value, page.data[0], f.pin, f.input.scope);
		expect(restored.consent.expected.userSaltCommitment).toBe(t.input.user_salt_commitment);
		expect(restored.consent.preparation.approval_digest).toBe(t.preparation.approval_digest);
		expect(restored.creationOperationRecorded).toBe(false);
		for (const field of ['assertion', 'signature', 'document', 'expected_address', 'firebase']) expect(JSON.stringify(value)).not.toContain(field);
		for (const field of ['public_key', 'credential_id', 'user_salt_commitment']) expect(JSON.stringify(page)).not.toContain(field);
		expect(c.observe).not.toHaveBeenCalled(); expect(await count()).toBe(1);
		expect(await env.WALLET_DB.prepare('SELECT count(*) AS n FROM account_creation_outbox').first('n')).toBe(0);
	});
	it('discovers an authorization whose response was lost, including after its signing window expired', async () => {
		const t = await prepare();
		expect((await t.c.run(await request(`${ROOT}/${t.input.request_id}/authorize`, proof(t.preparation.approval_digest)), env, config)).status).toBe(200);
		const snapshot = await env.WALLET_DB.prepare('SELECT * FROM account_initializations').first();
		vi.spyOn(Date, 'now').mockReturnValue(Date.now() + 301_000);
		const c = candidate(), page = await history(c);
		expect(page.data[0].state).toBe('authorized');
		const restored = await c.run(await request(`${ROOT}/${t.input.request_id}`, null, 'test-user-a', 'GET'), env, config);
		expect(parseInitializationRestoration(await restored.json(), page.data[0], f.pin, f.input.scope).consent.preparation.state).toBe('authorized');
		expect(await env.WALLET_DB.prepare('SELECT * FROM account_initializations').first()).toEqual(snapshot);
		expect(c.observe).not.toHaveBeenCalled();
	});
	it('keeps expired unsigned consent readable without extending or authorizing it', async () => {
		const t = await prepare(); vi.spyOn(Date, 'now').mockReturnValue(Date.now() + 301_000);
		const page = await history(t.c); expect(page.data[0].state).toBe('expired');
		const restored = await t.c.run(await request(`${ROOT}/${t.input.request_id}`, null, 'test-user-a', 'GET'), env, config);
		expect(parseInitializationRestoration(await restored.json(), page.data[0], f.pin, f.input.scope).consent.preparation.valid_until).toBe(page.data[0].expires_at);
		expect((await t.c.run(await request(`${ROOT}/${t.input.request_id}/authorize`, proof(t.preparation.approval_digest)), env, config)).status).toBe(410);
	});
	it('reports an existing creation-operation record without claiming execution or returning its authorization', async () => {
		const t = await prepare(); await t.c.run(await request(`${ROOT}/${t.input.request_id}/authorize`, proof(t.preparation.approval_digest)), env, config);
		await env.WALLET_DB.prepare(`INSERT INTO account_creation_operations
			(initialization_id,gas_terms_json,user_op_hash,operation_digest,created_at,expires_at) VALUES (?,'{}',?,?,?,?)`)
			.bind(t.input.request_id, fixtureHash('1'), fixtureHash('2'), now(), now() + 300).run();
		const page = await history(t.c); expect(page.data[0].creation_operation_recorded).toBe(true);
		const result = await t.c.run(await request(`${ROOT}/${t.input.request_id}`, null, 'test-user-a', 'GET'), env, config);
		const restored = parseInitializationRestoration(await result.json(), page.data[0], f.pin, f.input.scope);
		expect(restored.creationOperationRecorded).toBe(true);
		expect(restored.consent.preparation).toMatchObject({ account_deployed: false, receive_enabled: false, spend_enabled: false });
		expect(await env.WALLET_DB.prepare('SELECT count(*) AS n FROM account_creation_outbox').first('n')).toBe(0);
	});
	it('does not let another identity discover or restore the owner request', async () => {
		const t = await prepare(); await enroll('test-user-b');
		expect((await history(t.c, 'test-user-b')).data).toEqual([]);
		expect((await t.c.run(await request(`${ROOT}/${t.input.request_id}`, null, 'test-user-b', 'GET'), env, config)).status).toBe(404);
		const unauth = await request(ROOT, null, 'test-user-a', 'GET'); unauth.headers.delete('Authorization');
		expect((await t.c.run(unauth, env, config)).status).toBe(401);
	});
	it.each(['', '/selected'])('rechecks revocation after the %s read', async (suffix) => {
		const t = await prepare(), original = WalletRepository.prototype.getSession; let calls = 0;
		vi.spyOn(WalletRepository.prototype, 'getSession').mockImplementation(async function (this: WalletRepository) {
			if (++calls === 3) await env.WALLET_DB.prepare('UPDATE users SET disabled_at = ? WHERE id = ?').bind(now(), t.key.user_id).run();
			return original.call(this);
		});
		const result = await t.c.run(await request(`${ROOT}${suffix ? `/${t.input.request_id}` : ''}`, null, 'test-user-a', 'GET'), env, config);
		expect(result.status).toBe(401); expect(await result.json()).toEqual({ error_code: 'UNAUTHENTICATED' });
	});
	it('keeps metadata visible when new accounts are disabled, but refuses restoration without its pinned profile', async () => {
		const t = await prepare(), req = () => request(ROOT, null, 'test-user-a', 'GET');
		expect((await t.c.run(await req(), env, { ...config, wallet_enabled: [] })).status).toBe(200);
		const page = await initializationRoute(await req(), env, config);
		expect(parseInitializationHistory(await page.json()).data[0].initialization_id).toBe(t.input.request_id);
		const result = await initializationRoute(await request(`${ROOT}/${t.input.request_id}`, null, 'test-user-a', 'GET'), env, config);
		expect(result.status).toBe(503); expect(await result.json()).toEqual({ error_code: 'PROFILE_UNAVAILABLE' });
	});
	it('revalidates saved consent before restoring it, and does not treat history metadata as proof', async () => {
		const t = await prepare(); await t.c.run(await request(`${ROOT}/${t.input.request_id}/authorize`, proof(t.preparation.approval_digest)), env, config);
		await env.WALLET_DB.prepare('UPDATE account_initializations SET assertion_body = ? WHERE id = ?').bind('{}', t.input.request_id).run();
		expect((await history(t.c)).data[0].state).toBe('authorized');
		expect((await t.c.run(await request(`${ROOT}/${t.input.request_id}`, null, 'test-user-a', 'GET'), env, config)).status).toBe(503);
	});
	it('paginates tied timestamps by ID without repeats and accepts the browser GET preflight', async () => {
		const t = await prepare();
		for (let index = 0; index < 11; index++) {
			await env.WALLET_DB.prepare(`INSERT INTO account_initializations
				(id,user_id,credential_ref,profile_sha256,user_salt_commitment,public_key,approval_digest,expected_address,created_at,expires_at)
				SELECT ?,user_id,credential_ref,profile_sha256,user_salt_commitment,public_key,approval_digest,expected_address,created_at,expires_at
				FROM account_initializations WHERE id = ?`).bind(createResourceId('operation'), t.input.request_id).run();
		}
		const first = await history(t.c); expect(first.data).toHaveLength(10); expect(first.next_cursor).not.toBeNull();
		const path = `?after=${encodeURIComponent(first.next_cursor!)}`, second = await history(t.c, 'test-user-a', path);
		expect(second.data).toHaveLength(2); expect(second.next_cursor).toBeNull();
		expect(new Set([...first.data, ...second.data].map((row) => row.initialization_id)).size).toBe(12);
		const preflight = await request(`${ROOT}${path}`, null, 'test-user-a', 'OPTIONS');
		preflight.headers.set('Access-Control-Request-Method', 'GET'); preflight.headers.set('Access-Control-Request-Headers', Object.keys(clientMutationHeaders('staging', account())).concat('authorization').join(','));
		expect((await t.c.run(preflight, env, config)).status).toBe(200);
		for (const query of ['?after=bad', `${path}&after=bad`, '?profile=bad']) expect((await t.c.run(await request(`${ROOT}${query}`, null, 'test-user-a', 'GET'), env, config)).status).toBeGreaterThanOrEqual(400);
	});
});
