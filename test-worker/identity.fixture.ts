import { testUserId, testCredentialRef } from './principal.fixture';
import { exportJWK, generateKeyPair, SignJWT, type JWTPayload, type JWTHeaderParameters } from 'jose';
import { vi } from 'vitest';

const jwksUrl = 'https://www.googleapis.com/robot/v1/metadata/jwk/securetoken@system.gserviceaccount.com';
const cacheName = 'gatopago-wallet-core-public-jwks';
const cacheKey = 'https://gatopago-wallet-core.invalid/firebase-public-jwks';
export const projectId = 'v3-runtime-test';
export const unixNow = () => Math.floor(Date.now() / 1000);

/** Ephemeral synthetic JWT signer. Never a credential for any actual Firebase project. */
export async function testIdentitySigner() {
	const key = await generateKeyPair('RS256', { modulusLength: 2048 });
	const jwk = { ...await exportJWK(key.publicKey), kid: 'test-public-key', alg: 'RS256', use: 'sig' };
	const keys = { keys: [jwk] };
	return {
		keys,
		async token(claims: JWTPayload = {}, header: JWTHeaderParameters = { alg: 'RS256', kid: jwk.kid }, rawSubject = false) {
			const now = unixNow();
			const subject = rawSubject ? claims.sub : testUserId(claims.sub ?? 'test-user-a');
			return new SignJWT({ iss: `https://securetoken.google.com/${projectId}`, aud: projectId,
				iat: now, exp: now + 3600, auth_time: now - 30, credential_ref: testCredentialRef(subject ?? 'test-user-a'), access_version: 1,
				firebase: { sign_in_provider: 'custom' }, ...claims, sub: subject }).setProtectedHeader(header).sign(key.privateKey);
		},
		mock() {
			const mock = vi.fn(async (input: RequestInfo | URL) => {
				if (String(input) !== jwksUrl) throw new Error('Unexpected provider');
				return Response.json(keys, { headers: { 'Cache-Control': 'public, max-age=3600' } });
			});
			vi.stubGlobal('fetch', mock);
			return mock;
		},
	};
}

export async function clearIdentityKeys() { await (await caches.open(cacheName)).delete(cacheKey); }
export async function seedIdentityKeys(keys: unknown, fetchedAt: number, maxAge = 3600) {
	await (await caches.open(cacheName)).put(cacheKey, Response.json(keys, { headers: {
		'Cache-Control': `public, max-age=${maxAge}`, 'X-Keys-Fetched-At': String(fetchedAt),
	} }));
}
