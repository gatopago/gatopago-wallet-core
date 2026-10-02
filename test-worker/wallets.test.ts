import { testPrincipal } from './principal.fixture';
import { seedUser } from './user.fixture';
import { sha256, stringToHex, type Hex } from 'viem';
import { signerId, type SecurityPolicy } from '@gatopago/shared/v3/security-policy';
import { refreshUserAccess } from '../src/auth/access';
import { env, exports } from 'cloudflare:workers';
import { applyD1Migrations } from 'cloudflare:test';
import { afterEach, beforeAll, beforeEach, describe, expect, it, vi } from 'vitest';
import manifests from '@gatopago/environment/environments.json';
import { parseEnvironment } from '@gatopago/environment';
import { createResourceId } from '@gatopago/shared/v3/primitives';
import { clientMutationHeaders } from '@gatopago/shared/v3/client-release';
import { walletReadRoute } from '../src/accounts/route';
import { WalletRepository } from '../src/accounts/repository';
import { verifyConsumerIdentity } from '../src/auth/identity';
import { inspectOwnedWalletAccount } from '../src/accounts/inspection';
import { finalizedSecurityScenario } from '@gatopago/test-fixtures/v3-security-inspection';
import { clearIdentityKeys, projectId, testIdentitySigner, unixNow } from './identity.fixture';

const config = parseEnvironment({ ...manifests.production, status: 'provisioned', firebase_project_id: projectId });
let signer: Awaited<ReturnType<typeof testIdentitySigner>>;
const now = unixNow();
type Session = { user_id: string };

async function input(path = '/session', method = 'GET', subject = 'test-user-a', body: unknown = {}) {
	return new Request(`${config.api_origin}/app/v1${path}`, { method, headers: {
		Origin: config.web_origin, Authorization: `Bearer ${await signer.token({ sub: subject, auth_time: now - 100 })}`,
		'Content-Type': 'application/json', ...clientMutationHeaders('production'),
	}, ...(method === 'POST' ? { body: JSON.stringify(body) } : {}) });
}
const run = (request: Request) => walletReadRoute(request, env, config, async () => []);
async function session(subject = 'test-user-a') {
	return seedUser(env.WALLET_DB, await verifyConsumerIdentity(await input('/session', 'GET', subject), projectId, 'production'));
}
async function repository(subject = 'test-user-a') {
	return new WalletRepository(env.WALLET_DB, await verifyConsumerIdentity(await input('/wallets', 'GET', subject), projectId, 'production'));
}
async function seedWallet(owner: Session) {
	const id = createResourceId('wallet'), commitment = sha256(stringToHex(id));
	await env.WALLET_DB.prepare(`INSERT INTO wallets(id,user_id,status,account_id,initial_security_commitment,user_salt_commitment,canonical_address,created_at)
		VALUES (?,?,'active',?,?,?,?,?)`).bind(id, owner.user_id, commitment, commitment, commitment, `0x${commitment.slice(-40)}`, now).run();
	return id;
}
async function seedAccount(owner: Session, addressOverride?: string) {
	const scenario = finalizedSecurityScenario(), walletId = await seedWallet(owner);
	const accountId = createResourceId('walletAccount'), address = addressOverride ?? scenario.account.toLowerCase();
	await env.WALLET_DB.batch([
		env.WALLET_DB.prepare(`UPDATE wallets SET account_id = ?, initial_security_commitment = ?, user_salt_commitment = ?, canonical_address = ? WHERE id = ?`)
			.bind(scenario.state.observation.accountId, scenario.input.initialSecurityCommitment, scenario.input.userSaltCommitment, address, walletId),
		env.WALLET_DB.prepare(`INSERT INTO wallet_accounts(id,wallet_id,network_id,address,deployment_manifest_sha256,deployment_state,created_at)
			VALUES (?,?,?,?,?,'active',?)`).bind(accountId, walletId, scenario.manifest.network_id, address, scenario.input.expectedDigest, now),
	]);
	const key = await env.WALLET_DB.prepare('SELECT public_key FROM webauthn_credentials WHERE user_id = ? AND login_enabled = 1').bind(owner.user_id).first<{ public_key: Hex }>();
	if (!key) throw new Error('Missing login credential');
	const verifier = scenario.manifest.components.implementation;
	const policy: SecurityPolicy = { ...scenario.policy, signers: [...scenario.policy.signers,
		{ kind: 1 as const, roles: 3, key: key.public_key, verifier: verifier.address, verifierCodeHash: verifier.runtime_code_hash }]
		.sort((a, b) => signerId(a).localeCompare(signerId(b))) };
	scenario.wirePolicy.signers = [...policy.signers];
	if (!addressOverride) {
		const previousFetch = globalThis.fetch;
		vi.stubGlobal('fetch', async (_url: RequestInfo | URL, init?: RequestInit) => {
			if (!scenario.input.rpcUrls.some(url => new URL(url).href === String(_url))) throw new Error('Unexpected access provider');
			const body = JSON.parse(String(init?.body)) as { id: number; method: string; params: unknown[] };
			return Response.json({ jsonrpc: '2.0', id: body.id, result: await scenario.request(body) });
		});
		try {
			await refreshUserAccess(env.WALLET_DB, owner.user_id, 'production',
				{ rpId: config.webauthn_rp_id, origin: config.web_origin }, async () => [{ document: scenario.input.document,
					digest: scenario.input.expectedDigest, verifier, rpcUrls: scenario.input.rpcUrls,
					finalityPolicy: scenario.pin, finalityEvidence: scenario.source }], new AbortController().signal);
		} finally { vi.stubGlobal('fetch', previousFetch); }
	}
	return { walletId, accountId, scenario: { ...scenario, policy } };
}
const countIdentities = () => env.WALLET_DB.prepare('SELECT count(*) AS n FROM users').first('n');

beforeAll(async () => {
	await applyD1Migrations(env.WALLET_DB, env.V3_TEST_MIGRATIONS);
	signer = await testIdentitySigner();
});
beforeEach(async () => {
	await clearIdentityKeys();
	// This binding is ephemeral local D1, never the legacy or remote database.
	await env.WALLET_DB.exec(`DELETE FROM wallet_accounts; DELETE FROM wallets; DELETE FROM webauthn_credentials; DELETE FROM users;`);
	signer.mock();
});
afterEach(() => { vi.restoreAllMocks(); vi.unstubAllGlobals(); });

describe('V3 Consumer session and ownership with real D1', () => {
	it('mounts private routes but does not bypass the actual unprovisioned manifest', async () => {
		for (const path of ['/session', '/wallets', `/wallets/${createResourceId('wallet')}/accounts`]) {
			expect((await exports.default.fetch(await input(path))).status).toBe(503);
		}
		expect(await countIdentities()).toBe(0);
	});
	it('reads only admitted users and cannot bypass signup through a session POST', async () => {
		expect((await run(await input())).status).toBe(409);
		expect((await run(await input('/session', 'POST'))).status).toBe(405);
		expect(await countIdentities()).toBe(0);
		const admitted = await session(), response = await run(await input());
		expect(await response.json()).toEqual(admitted);
		expect(Object.keys(admitted)).toEqual(['user_id']);
		expect(response.headers.get('Cache-Control')).toBe('no-store');
		expect(response.headers.get('Access-Control-Allow-Origin')).toBe(config.web_origin);
		expect(await env.WALLET_DB.prepare('SELECT count(*) AS n FROM wallets').first('n')).toBe(0);
	});
	it('keeps ownership independent of the configured token project while enforcing the app environment', async () => {
		const admitted = await session(), nextProject = 'another-auth-project', request = await input();
		request.headers.set('Authorization', `Bearer ${await signer.token({ aud: nextProject, iss: `https://securetoken.google.com/${nextProject}` })}`);
		const principal = await verifyConsumerIdentity(request, nextProject, 'production');
		expect(Object.keys(principal).sort()).toEqual(['accessVersion', 'authTime', 'credentialRef', 'environment', 'expiresAt', 'userId']);
		expect(await new WalletRepository(env.WALLET_DB, principal).getSession()).toEqual(admitted);
		await expect(new WalletRepository(env.WALLET_DB, { ...principal, environment: 'unsupported' as never }).getSession())
			.rejects.toMatchObject({ code: 'SESSION_REQUIRED' });
	});
	it('keeps a removed credential revoked after Firebase refresh while preserving another authorized key', async () => {
    const admitted = await session(), identity = testPrincipal('test-user-a');
    const other = { ...identity, credentialRef: createResourceId('operation') };
    await seedUser(env.WALLET_DB, other);
    await env.WALLET_DB.prepare('UPDATE webauthn_credentials SET revoked_at = ? WHERE id = ?').bind(unixNow(), identity.credentialRef).run();
    expect((await run(await input())).status).toBe(401);
    const refreshed = await input();
    refreshed.headers.set('Authorization', `Bearer ${await signer.token({ auth_time: unixNow() - 100, iat: unixNow() })}`);
    expect((await run(refreshed)).status).toBe(401);
    const alternate = await input();
    alternate.headers.set('Authorization', `Bearer ${await signer.token({ credential_ref: other.credentialRef })}`);
    expect(await (await run(alternate)).json()).toEqual(admitted);
  });
  it('rejects a stale credential access version even if the ID token is freshly issued', async () => {
    await session();
    await env.WALLET_DB.prepare('UPDATE webauthn_credentials SET access_version = 2').run();
    expect((await run(await input())).status).toBe(401);
    const renewed = await input();
    renewed.headers.set('Authorization', `Bearer ${await signer.token({ access_version: 2 })}`);
    expect((await run(renewed)).status).toBe(200);
  });
	it('separates admitted users and does not expose provider identifiers', async () => {
		const one = await session('one'), two = await session('two');
		expect(one.user_id).not.toBe(two.user_id);
		expect(await (await run(await input('/session','GET','one'))).json()).toEqual(one);
	});
	it('requires exact origin, API hostname and bearer authentication', async () => {
		for (const origin of ['https://business.gatopago.com', 'https://other.gatopago.com', 'null', '']) {
			const request = await input(); request.headers.set('Origin', origin);
			expect((await run(request)).status).toBe(403);
		}
		const request = await input();
		expect((await run(new Request('https://other.gatopago.com/app/v1/session', request))).status).toBe(403);
		request.headers.set('Cookie','session=untrusted'); expect((await run(request)).status).toBe(401);
	});
	it('permits read preflight and rejects mutation methods', async () => {
		const request = await input();
		const preflight = new Request(request.url, { method:'OPTIONS', headers:{ Origin:config.web_origin,
			'Access-Control-Request-Method':'GET','Access-Control-Request-Headers':'authorization' } });
		expect((await run(preflight)).status).toBe(200);
		preflight.headers.set('Access-Control-Request-Headers','cookie'); expect((await run(preflight)).status).toBe(403);
		expect((await run(await input('/wallets','POST'))).status).toBe(405);
	});
	it('rejects disabled users and checks auth_time rather than refreshed iat', async () => {
		const admitted = await session();
		await env.WALLET_DB.prepare('UPDATE users SET disabled_at = ? WHERE id = ?').bind(now, admitted.user_id).run();
		expect((await run(await input())).status).toBe(401);
		await env.WALLET_DB.prepare('UPDATE users SET disabled_at = NULL, auth_not_before = ? WHERE id = ?').bind(now - 60, admitted.user_id).run();
		expect((await run(await input())).status).toBe(401);
		const request = await input(); request.headers.set('Authorization', `Bearer ${await signer.token({ auth_time:unixNow() })}`);
		expect((await run(request)).status).toBe(200);
	});
	it('scopes wallet pages to the owner and treats foreign/missing accounts identically', async () => {
		const first = await session(), second = await session('test-user-b');
		const owned = await seedWallet(first), foreign = await seedWallet(second);
		const response = await run(await input('/wallets'));
		const result = await response.json<{ data: { id: string }[]; next_cursor: null }>();
		expect(result.data.map((value) => value.id)).toEqual([owned]);
		expect(result.next_cursor).toBeNull();
		for (const id of [foreign, createResourceId('wallet')]) {
			const response = await run(await input(`/wallets/${id}/accounts`));
			expect(response.status).toBe(404); expect(await response.json()).toEqual({ error_code: 'NOT_FOUND' });
		}
	});
	it('paginates deterministically and rejects unbounded/ambiguous/cross-resource cursors', async () => {
		const owner = await session();
		const ids = [await seedWallet(owner), await seedWallet(owner), await seedWallet(owner)].sort();
		const first = await (await run(await input('/wallets?limit=2'))).json<{ data: { id: string }[]; next_cursor: string }>();
		expect(first.data.map((value) => value.id)).toEqual(ids.slice(0, 2)); expect(first.next_cursor).toBe(ids[1]);
		const second = await (await run(await input(`/wallets?limit=2&after=${first.next_cursor}`))).json<{ data: { id: string }[]; next_cursor: null }>();
		expect(second.data.map((value) => value.id)).toEqual(ids.slice(2)); expect(second.next_cursor).toBeNull();
		for (const query of ['limit=0', 'limit=51', 'limit=-1', 'limit=2&limit=3', 'after=', `after=${createResourceId('party')}`, 'uid=victim', 'rpc=https://evil.test']) {
			expect((await run(await input(`/wallets?${query}`))).status).toBe(400);
		}
	});
	it('returns chain resource projections without an unverified deposit address or signing readiness', async () => {
		const seeded = await seedAccount(await session());
		const result = await (await run(await input(`/wallets/${seeded.walletId}/accounts`))).json<{ data: unknown[] }>();
		expect(result.data).toEqual([{ id: seeded.accountId, wallet_id: seeded.walletId,
			network_id: 'eip155:84532', generation: 3, deployment_state: 'active', spend_readiness: 'not_assessed', receive_enabled: false }]);
	});
	it('enforces one account per network and the wallet canonical address in D1', async () => {
		const seeded = await seedAccount(await session());
		const insert = (network: string, address: string) => env.WALLET_DB.prepare(`INSERT INTO wallet_accounts
			(id,wallet_id,network_id,address,deployment_manifest_sha256,deployment_state,created_at)
			VALUES (?,?,?,?,?,'active',?)`).bind(createResourceId('walletAccount'),seeded.walletId,network,address,seeded.scenario.input.expectedDigest,now).run();
		await expect(insert('eip155:84532',seeded.scenario.account.toLowerCase())).rejects.toThrow();
		await expect(insert('eip155:43113',`0x${'1'.repeat(40)}`)).rejects.toThrow();
		await expect(insert('eip155:01',seeded.scenario.account.toLowerCase())).rejects.toThrow();
	});
	it('fails closed on corrupt resource IDs instead of exposing raw database content', async () => {
		const seeded = await seedWallet(await session());
		await env.WALLET_DB.prepare('UPDATE wallets SET id = ? WHERE id = ?').bind(`wal_${'x'.repeat(36)}`, seeded).run();
		const result = await run(await input('/wallets'));
		expect(result.status).toBe(503); expect(await result.json()).toEqual({ error_code: 'WALLET_DATA_INVALID' });
	});
});

describe('V3 authenticated ownership → pinned inspection integration', () => {
	it('returns a public owned context without provider secrets, commitments or monetary permission', async () => {
		const seeded = await seedAccount(await session()), scenario = seeded.scenario;
		const request = await input(`/wallets/${seeded.walletId}/accounts/${seeded.accountId}/context`);
		// Prime JWT verification before checking that context resolution makes no RPC calls.
		await verifyConsumerIdentity(request, projectId, 'production');
		const fetcher = vi.fn(); vi.stubGlobal('fetch', fetcher);
		const profile = { document: scenario.input.document, digest: scenario.input.expectedDigest,
			finalityPolicy: scenario.pin, finalityEvidence: scenario.source, assetIds: [], assetDisplay: {},
			providers: [{ operatorId: 'private-provider', url: 'https://rpc.example.test/DO_NOT_SERIALIZE' }] };
		const response = await walletReadRoute(request, env, config, async () => [profile]);
		expect(response.status).toBe(200);
		expect(await response.json()).toEqual({ schema_version: 1, wallet_id: seeded.walletId, wallet_account_id: seeded.accountId,
			network_id: scenario.manifest.network_id, account_id: scenario.state.observation.accountId,
			address: scenario.account.toLowerCase(), deployment: { document: profile.document, digest: profile.digest },
			spend_readiness: 'not_assessed', receive_enabled: false, send_enabled: false });
		expect(response.headers.get('Cache-Control')).toBe('no-store');
		expect(fetcher).not.toHaveBeenCalled();
		expect(await env.WALLET_DB.prepare('SELECT deployment_state FROM wallet_accounts').first('deployment_state')).toBe('active');
	});
	it('protects context reads with identity, ownership, method and query boundaries', async () => {
		const seeded = await seedAccount(await session()); await session('test-user-b');
		const path = `/wallets/${seeded.walletId}/accounts/${seeded.accountId}/context`;
		expect((await run(await input(path))).status).toBe(503);
		expect((await run(await input(path, 'GET', 'test-user-b'))).status).toBe(404);
		const anonymous = await input(path); anonymous.headers.delete('Authorization');
		expect((await run(anonymous)).status).toBe(401);
		expect((await run(await input(path, 'POST'))).status).toBe(405);
		for (const query of ['address=0x1', 'digest=0x1', 'rpc=https://example.test', 'limit=1']) {
			expect((await run(await input(`${path}?${query}`))).status).toBe(400);
		}
		expect((await exports.default.fetch(await input(path))).status).toBe(503);
	});
	it.each(['missing', 'duplicate', 'tampered', 'wrong-address', 'archive', 'disabled'] as const)('rejects unusable account context (%s)', async fault => {
		const seeded = await seedAccount(await session(), fault === 'wrong-address' ? `0x${'ab'.repeat(20)}` : undefined), scenario = seeded.scenario;
		const profile = { document: scenario.input.document, digest: scenario.input.expectedDigest,
			finalityPolicy: scenario.pin, finalityEvidence: scenario.source, assetIds: [], assetDisplay: {}, providers: [] };
		if (fault === 'tampered') profile.document += ' ';
		if (fault === 'archive') await env.WALLET_DB.prepare("UPDATE wallets SET status = 'archived'").run();
		if (fault === 'disabled') await env.WALLET_DB.prepare('UPDATE users SET disabled_at = ?').bind(now).run();
		const response = await walletReadRoute(await input(`/wallets/${seeded.walletId}/accounts/${seeded.accountId}/context`), env, config,
			async () => fault === 'missing' ? [] : fault === 'duplicate' ? [profile, profile] : [profile]);
		expect(response.status).toBe(fault === 'disabled' ? 401 : 503);
		const body = await response.json();
		expect(body).not.toHaveProperty('account_id'); expect(body).not.toHaveProperty('deployment');
	});
	it('exposes balance reads only to the owner and fails closed without server admission', async () => {
		const seeded = await seedAccount(await session()); await session('test-user-b');
		const path = `/wallets/${seeded.walletId}/accounts/${seeded.accountId}/balances`;
		const response = await run(await input(path));
		expect(response.status).toBe(503); expect(await response.json()).toEqual({ error_code: 'SERVICE_UNAVAILABLE' });
		expect(response.headers.get('Cache-Control')).toBe('no-store');
		expect((await run(await input(path, 'GET', 'test-user-b'))).status).toBe(404);
		const missingAuth = await input(path); missingAuth.headers.delete('Authorization');
		expect((await run(missingAuth)).status).toBe(401);
		expect((await run(await input(path, 'POST'))).status).toBe(405);
		for (const query of ['address=0x1', 'rpc=https://example.test', 'block=100', 'limit=1']) {
			expect((await run(await input(`${path}?${query}`))).status).toBe(400);
		}
		expect((await exports.default.fetch(await input(path))).status).toBe(503);
	});
	it.each(['none', 'disable', 'archive'])('returns balance only while ownership remains valid through HTTP (%s)', async (change) => {
		const seeded = await seedAccount(await session()), scenario = seeded.scenario;
		const request = await input(`/wallets/${seeded.walletId}/accounts/${seeded.accountId}/balances`);
		const profiles = [{ document: scenario.input.document, digest: scenario.input.expectedDigest,
			finalityPolicy: scenario.pin, finalityEvidence: scenario.source, assetIds: ['eip155:84532/slip44:60'],
			assetDisplay: { 'eip155:84532/slip44:60': { symbol: 'ETH', decimals: 18 } },
			providers: [{ operatorId: 'provider-a', url: 'https://a.example/rpc' }, { operatorId: 'provider-b', url: 'https://b.example/rpc' }] }];
		let changed = false;
		vi.stubGlobal('fetch', vi.fn(async (_url: RequestInfo | URL, init?: RequestInit) => {
			if (!changed) {
				changed = true;
				if (change === 'disable') await env.WALLET_DB.prepare('UPDATE users SET disabled_at = ?').bind(now).run();
				if (change === 'archive') await env.WALLET_DB.prepare("UPDATE wallets SET status = 'archived'").run();
			}
			const body = JSON.parse(String(init?.body)) as { id: number; method: string; params?: readonly unknown[] };
			return Response.json({ jsonrpc: '2.0', id: body.id, result: body.method === 'eth_getBalance' ? '0x123' : await scenario.request(body) });
		}));
		const response = await walletReadRoute(request, env, config, async () => profiles);
		if (change !== 'none') {
			expect(response.status).toBe(change === 'disable' ? 401 : 503);
			expect(await response.json()).toEqual({ error_code: change === 'disable' ? 'UNAUTHENTICATED' : 'WALLET_DATA_INVALID' });
			return;
		}
		expect(response.status).toBe(200);
		expect(await response.json()).toMatchObject({ wallet_id: seeded.walletId, wallet_account_id: seeded.accountId,
			balances: [{ amount_atomic: '291' }], finality: 'finalized', available_balance: 'not_assessed', spend_readiness: 'not_assessed' });
		expect(response.headers.get('Cache-Control')).toBe('no-store');
		expect(await env.WALLET_DB.prepare('SELECT deployment_state FROM wallet_accounts').first('deployment_state')).toBe('active');
	});
	it('inspects only the owned resource and never mutates its deployment state', async () => {
		const seeded = await seedAccount(await session());
		const repo = await repository();
		const fetchMock = vi.fn(async (_url: RequestInfo | URL, init?: RequestInit) => {
			const body = JSON.parse(String(init?.body)) as { id: number; method: string; params?: readonly unknown[] };
			return Response.json({ jsonrpc: '2.0', id: body.id, result: await seeded.scenario.request(body) });
		});
		vi.stubGlobal('fetch', fetchMock);
		const result = await inspectOwnedWalletAccount(repo, seeded.walletId, seeded.accountId, [{ document: seeded.scenario.input.document,
			digest: seeded.scenario.input.expectedDigest, finalityPolicy: seeded.scenario.pin, finalityEvidence: seeded.scenario.source,
			rpcUrls: ['https://rpc.example.test', 'https://second.example.test'] }], new AbortController().signal);
		expect(result).toMatchObject({ wallet_id: seeded.walletId, wallet_account_id: seeded.accountId, status: 'recognized', spend_readiness: 'not_assessed' });
		expect(result).toMatchObject({ providers_agree: true, security: { phase: 'active_policy', policy: seeded.scenario.policy } });
		expect(result).toMatchObject({ finality: 'finalized', security_expires_at: seeded.scenario.source.expires_at });
		expect(fetchMock).toHaveBeenCalledTimes(50); // Includes the WebAuthn verifier code on both providers.
		expect(await env.WALLET_DB.prepare('SELECT deployment_state FROM wallet_accounts').first('deployment_state')).toBe('active');
	});
	it.each(['disable', 'archive', 'pin'])('rechecks ownership and identity after RPC (%s)', async (change) => {
		const owner = await session(), seeded = await seedAccount(owner), repo = await repository();
		let changed = false;
		vi.stubGlobal('fetch', vi.fn(async (_url: RequestInfo | URL, init?: RequestInit) => {
			if (!changed) {
				changed = true;
				if (change === 'disable') await env.WALLET_DB.prepare('UPDATE users SET disabled_at = ?').bind(now).run();
				if (change === 'archive') await env.WALLET_DB.prepare("UPDATE wallets SET status = 'archived'").run();
				if (change === 'pin') await env.WALLET_DB.prepare('UPDATE wallet_accounts SET deployment_manifest_sha256 = ?').bind(`0x${'f'.repeat(64)}`).run();
			}
			const body = JSON.parse(String(init?.body));
			return Response.json({ jsonrpc: '2.0', id: body.id, result: await seeded.scenario.request(body) });
		}));
		await expect(inspectOwnedWalletAccount(repo, seeded.walletId, seeded.accountId, [{ document: seeded.scenario.input.document,
			digest: seeded.scenario.input.expectedDigest, finalityPolicy: seeded.scenario.pin, finalityEvidence: seeded.scenario.source,
			rpcUrls: seeded.scenario.input.rpcUrls }], new AbortController().signal)).rejects.toMatchObject({
			code: change === 'disable' ? 'UNAUTHENTICATED' : 'WALLET_DATA_INVALID',
		});
	});
	it('does not reuse a verified identity after its token expires', async () => {
		const seeded = await seedAccount(await session()), repo = await repository();
		vi.spyOn(Date, 'now').mockReturnValue((unixNow() + 7200) * 1000);
		await expect(repo.ownedAccount(seeded.walletId, seeded.accountId)).rejects.toMatchObject({ code: 'UNAUTHENTICATED' });
	});
	it('blocks foreign, missing and cross-wallet resources before calling RPC or selecting a profile', async () => {
		const seeded = await seedAccount(await session());
		await session('test-user-b'); const repo = await repository('test-user-b');
		const fetchMock = vi.fn(); vi.stubGlobal('fetch', fetchMock);
		await expect(inspectOwnedWalletAccount(repo, seeded.walletId, seeded.accountId, [], new AbortController().signal)).rejects.toMatchObject({ code: 'NOT_FOUND' });
		expect(fetchMock).not.toHaveBeenCalled();
	});
	it('does not use a database pin as admission or turn a missing profile into backup', async () => {
		const seeded = await seedAccount(await session()); const repo = await repository();
		const fetchMock = vi.fn(); vi.stubGlobal('fetch', fetchMock);
		await expect(inspectOwnedWalletAccount(repo, seeded.walletId, seeded.accountId, [], new AbortController().signal)).rejects.toThrow('INSPECTION_PROFILE_UNAVAILABLE');
		expect(fetchMock).not.toHaveBeenCalled();
	});
	it('rejects inconsistent cryptographic identity before RPC', async () => {
		const seeded = await seedAccount(await session()); const repo = await repository();
		await env.WALLET_DB.prepare('UPDATE wallets SET user_salt_commitment = ?').bind(`0x${'d'.repeat(64)}`).run();
		const fetchMock = vi.fn(); vi.stubGlobal('fetch', fetchMock);
		await expect(inspectOwnedWalletAccount(repo, seeded.walletId, seeded.accountId, [], new AbortController().signal)).rejects.toMatchObject({ code: 'WALLET_DATA_INVALID' });
		expect(fetchMock).not.toHaveBeenCalled();
	});
	it('a disable committed after JWT verification is still enforced by the ownership query', async () => {
		const owner = await session(), seeded = await seedAccount(owner), repo = await repository();
		await env.WALLET_DB.prepare('UPDATE users SET disabled_at = ? WHERE id = ?').bind(now, owner.user_id).run();
		const fetchMock = vi.fn(); vi.stubGlobal('fetch', fetchMock);
		await expect(inspectOwnedWalletAccount(repo, seeded.walletId, seeded.accountId, [], new AbortController().signal)).rejects.toMatchObject({ code: 'UNAUTHENTICATED' });
		expect(fetchMock).not.toHaveBeenCalled();
	});
});
