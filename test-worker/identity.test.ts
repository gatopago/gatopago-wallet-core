import { testUserId, testCredentialRef } from './principal.fixture';
import { afterEach, beforeAll, beforeEach, describe, expect, it, vi } from 'vitest';
import { verifyConsumerIdentity } from '../src/auth/identity';
import { clearIdentityKeys, projectId, seedIdentityKeys, testIdentitySigner, unixNow } from './identity.fixture';

let signer: Awaited<ReturnType<typeof testIdentitySigner>>;
const request = (token: string) => new Request('https://api.staging.gatopago.com/app/v1/session', { headers: { Authorization: `Bearer ${token}` } });
beforeAll(async () => { signer = await testIdentitySigner(); });
beforeEach(clearIdentityKeys);
afterEach(() => { vi.restoreAllMocks(); vi.unstubAllGlobals(); });

describe('V3 Firebase identity using real RSA signatures in workerd', () => {
	it('accepts the custom session contract without Google or verified email', async () => {
		const fetchMock = signer.mock();
		const identity = await verifyConsumerIdentity(request(await signer.token()), projectId, 'staging');
		expect(identity).toEqual({ environment: 'staging', userId: testUserId('test-user-a'), credentialRef: testCredentialRef('test-user-a'), accessVersion: 1, authTime: expect.any(Number), expiresAt: expect.any(Number) });
		expect(Object.isFrozen(identity)).toBe(true);
		expect(fetchMock).toHaveBeenCalledTimes(1);
	});
	it.each([
		{ aud: 'other-project' }, { aud: [projectId] }, { iss: 'https://evil.test' }, { sub: '' }, { sub: 'a'.repeat(129) }, { sub: 'user\n' },
		{ user_id: 'other-user' }, { credential_ref: undefined }, { access_version: undefined }, { access_version: 0 }, { access_version: 1.5 }, { exp: 1 },
		{ auth_time: 0 }, { auth_time: '123' }, { firebase: { sign_in_provider: 'anonymous' } },
		{ firebase: { sign_in_provider: 'google.com' } }, { firebase: { sign_in_provider: 'password' } }, { firebase: { sign_in_provider: 'custom', tenant: 'other-tenant' } },
	])('rejects invalid claims: %j', async (claims) => {
		signer.mock();
		await expect(verifyConsumerIdentity(request(await signer.token({ sub: testUserId('test-user-a'), ...claims }, undefined, true)), projectId, 'staging')).rejects.toMatchObject({ code: 'UNAUTHENTICATED' });
	});
	it('rejects future issuance/auth_time, fractional times, extended TTL and missing required claims', async () => {
		signer.mock(); const now = unixNow();
		for (const claims of [{ iat: now + 30 }, { auth_time: now + 30 }, { iat: now - 1, exp: now + 3600 },
			{ exp: now + 0.5 }, { auth_time: now - 0.5 }, { iat: undefined }, { auth_time: undefined }]) {
			await expect(verifyConsumerIdentity(request(await signer.token({ sub: testUserId('test-user-a'), ...claims }, undefined, true)), projectId, 'staging')).rejects.toMatchObject({ code: 'UNAUTHENTICATED' });
		}
	});
	it('rejects signatures made with another RSA private key', async () => {
		signer.mock(); const other = await testIdentitySigner();
		await expect(verifyConsumerIdentity(request(await other.token()), projectId, 'staging')).rejects.toMatchObject({ code: 'UNAUTHENTICATED' });
	});
	it('rejects malformed/header-injected tokens, cookies and duplicate authorization without fetch', async () => {
		const fetchMock = signer.mock();
		const token = await signer.token();
		const cookie = request(token); cookie.headers.set('Cookie', 'session=untrusted');
		const duplicate = request(token); duplicate.headers.append('Authorization', `Bearer ${token}`);
		const injected = await signer.token({}, { alg: 'RS256', kid: 'test-public-key', jku: 'https://evil.test/keys' });
		const badAlgorithm = `${btoa(JSON.stringify({ alg: 'none', kid: 'test-public-key' }))}.e30.AA`;
		for (const input of [request('a'.repeat(8193)), request(''), request(badAlgorithm), request(injected), cookie, duplicate]) {
			await expect(verifyConsumerIdentity(input, projectId, 'staging')).rejects.toMatchObject({ code: 'UNAUTHENTICATED' });
		}
		expect(fetchMock).not.toHaveBeenCalled();
	});
	it('caches only public keys and does not fetch for fresh unknown kids', async () => {
		const fetchMock = signer.mock();
		await verifyConsumerIdentity(request(await signer.token()), projectId, 'staging');
		await verifyConsumerIdentity(request(await signer.token({ sub: 'second-user' })), projectId, 'staging');
		await expect(verifyConsumerIdentity(request(await signer.token({}, { alg: 'RS256', kid: 'unknown-key' })), projectId, 'staging')).rejects.toMatchObject({ code: 'UNAUTHENTICATED' });
		expect(fetchMock).toHaveBeenCalledTimes(1);
	});
	it('refreshes older unknown-kid cache and enforces the recorded max-age', async () => {
		const fetchMock = signer.mock();
		await seedIdentityKeys({ keys: [{ ...signer.keys.keys[0], kid: 'older-key' }] }, unixNow() - 61);
		await verifyConsumerIdentity(request(await signer.token()), projectId, 'staging');
		await seedIdentityKeys(signer.keys, unixNow() - 120, 60);
		await verifyConsumerIdentity(request(await signer.token()), projectId, 'staging');
		expect(fetchMock).toHaveBeenCalledTimes(2);
	});
	it('ignores duplicate-key cache and does not accept an invalid fresh keyset', async () => {
		const fetchMock = signer.mock();
		await seedIdentityKeys({ keys: [signer.keys.keys[0], signer.keys.keys[0]] }, unixNow());
		await verifyConsumerIdentity(request(await signer.token()), projectId, 'staging');
		expect(fetchMock).toHaveBeenCalledTimes(1);
		await clearIdentityKeys();
		fetchMock.mockImplementation(async () => Response.json({ keys: [signer.keys.keys[0], signer.keys.keys[0]] }));
		await expect(verifyConsumerIdentity(request(await signer.token()), projectId, 'staging')).rejects.toMatchObject({ code: 'IDENTITY_UNAVAILABLE' });
	});
	it('respects no-store from the provider', async () => {
		const fetchMock = signer.mock();
		fetchMock.mockImplementation(async () => Response.json(signer.keys, { headers: { 'Cache-Control': 'no-store, max-age=3600' } }));
		await verifyConsumerIdentity(request(await signer.token()), projectId, 'staging');
		await verifyConsumerIdentity(request(await signer.token()), projectId, 'staging');
		expect(fetchMock).toHaveBeenCalledTimes(2);
	});
	it('sanitizes provider failures and releases their response body', async () => {
		let cancelled = false;
		vi.stubGlobal('fetch', vi.fn(async () => new Response(new ReadableStream({ cancel() { cancelled = true; } }), { status: 503 })));
		await expect(verifyConsumerIdentity(request(await signer.token()), projectId, 'staging')).rejects.toMatchObject({ message: 'IDENTITY_UNAVAILABLE' });
		expect(cancelled).toBe(true);
	});
	it('bounds JWKS responses and cancels overflow', async () => {
		let cancelled = false;
		vi.stubGlobal('fetch', vi.fn(async () => new Response(new ReadableStream<Uint8Array>({
			start(controller) { controller.enqueue(new Uint8Array(65_537)); }, cancel() { cancelled = true; },
		}))));
		await expect(verifyConsumerIdentity(request(await signer.token()), projectId, 'staging')).rejects.toMatchObject({ code: 'IDENTITY_UNAVAILABLE' });
		expect(cancelled).toBe(true);
	});
});
