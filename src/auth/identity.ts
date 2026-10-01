import { parseResourceId } from '@gatopago/shared/v3/primitives';
import { createLocalJWKSet, decodeProtectedHeader, jwtVerify, type JSONWebKeySet } from 'jose';
import { discardResponseBody, readJsonBounded } from '@gatopago/shared/http';
import type { Principal } from './principal';

const JWKS_URL = 'https://www.googleapis.com/robot/v1/metadata/jwk/securetoken@system.gserviceaccount.com';
const CACHE_NAME = 'gatopago-wallet-core-public-jwks';
const CACHE_KEY = 'https://gatopago-wallet-core.invalid/firebase-public-jwks';

export class IdentityError extends Error {
	constructor(readonly code: 'UNAUTHENTICATED' | 'IDENTITY_UNAVAILABLE') { super(code); this.name = 'IdentityError'; }
}

function record(value: unknown): value is Record<string, unknown> {
	return value !== null && typeof value === 'object' && !Array.isArray(value);
}

function keySet(value: unknown): value is JSONWebKeySet {
	return record(value) && Array.isArray(value.keys) && value.keys.length > 0 && value.keys.length <= 16
		&& value.keys.every((key: unknown) => record(key) && key.kty === 'RSA'
			&& typeof key.kid === 'string' && /^[A-Za-z0-9_-]{1,128}$(?![\s\S])/.test(key.kid)
			&& typeof key.n === 'string' && /^[A-Za-z0-9_-]{342,1366}$(?![\s\S])/.test(key.n)
			&& key.e === 'AQAB' && (key.alg === undefined || key.alg === 'RS256')
			&& (key.use === undefined || key.use === 'sig') && !['d', 'p', 'q', 'dp', 'dq', 'qi'].some((field) => field in key))
		&& new Set(value.keys.map((key: Record<string, unknown>) => key.kid)).size === value.keys.length;
}

function cacheLifetime(headers: Headers): number {
	const control = headers.get('Cache-Control') ?? '';
	if (/(?:^|,)\s*(?:no-store|no-cache|private)(?:\s*(?:,|$))/i.test(control)) return 0;
	const age = Number(/(?:^|,)\s*max-age=(\d+)(?:\s*(?:,|$))/i.exec(control)?.[1] ?? 0);
	return Number.isSafeInteger(age) ? Math.min(age, 3600) : 0;
}

/** Only resolved PUBLIC keys enter Cache API. No JWT, user data, imported-key promises,
 * global client or request context is retained. A new kid can refresh a cache older than
 * 60s; arbitrary unknown kids cannot force a fetch on every warm-cache request.
 */
async function firebaseKeys(kid: string, signal: AbortSignal): Promise<JSONWebKeySet> {
	const now = Math.floor(Date.now() / 1000);
	const cache = await caches.open(CACHE_NAME);
	const cached = await cache.match(CACHE_KEY).catch(() => undefined);
	if (cached) {
		try {
			const fetchedAt = Number(cached.headers.get('X-Keys-Fetched-At'));
			const lifetime = cacheLifetime(cached.headers);
			const keys = await readJsonBounded<unknown>(cached, 65_536, signal);
			if (keySet(keys) && Number.isSafeInteger(fetchedAt) && fetchedAt > 0 && fetchedAt <= now && now - fetchedAt < lifetime) {
				if (keys.keys.some((key) => key.kid === kid)) return keys;
				if (now - fetchedAt < 60) throw new IdentityError('UNAUTHENTICATED');
			}
		} catch (error) { if (error instanceof IdentityError) throw error; }
	}
	const timeout = AbortSignal.any([signal, AbortSignal.timeout(5000)]);
	const response = await fetch(JWKS_URL, { redirect: 'manual', signal: timeout, headers: { Accept: 'application/json' } });
	if (!response.ok) { await discardResponseBody(response); throw new IdentityError('IDENTITY_UNAVAILABLE'); }
	const maxAge = cacheLifetime(response.headers);
	const keys = await readJsonBounded<unknown>(response, 65_536, timeout);
	if (!keySet(keys)) throw new IdentityError('IDENTITY_UNAVAILABLE');
	if (maxAge > 0) {
		// Cache persistence is an optimization, not authority. A failed put does not invalidate fresh keys.
		await cache.put(CACHE_KEY, Response.json(keys, { headers: {
			'Cache-Control': `public, max-age=${maxAge}`, 'X-Keys-Fetched-At': String(now),
		} })).catch(() => undefined);
	}
	return keys;
}

/** Identifies a Firebase user, NOT an onchain signer. Local app session cutoffs are checked
 * in the repository. Firebase Admin revocation/disable synchronization is a separate gate;
 * a valid offline JWT alone does not prove that Firebase has not revoked the session.
 */
export async function verifyConsumerIdentity(request: Request, projectId: string, environment: Principal['environment']): Promise<Principal> {
	if (environment !== 'staging' && environment !== 'production') throw new IdentityError('IDENTITY_UNAVAILABLE');
	const authorization = request.headers.get('Authorization') ?? '';
	if (authorization.length > 8192 || !/^Bearer [A-Za-z0-9_-]+\.[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+$(?![\s\S])/.test(authorization)
		|| request.headers.has('Cookie')) throw new IdentityError('UNAUTHENTICATED');
	const token = authorization.slice(7);
	let kid: string;
	try {
		const header = decodeProtectedHeader(token);
		if (header.alg !== 'RS256' || typeof header.kid !== 'string' || !/^[A-Za-z0-9_-]{1,128}$(?![\s\S])/.test(header.kid)
			|| header.jku || header.jwk || header.x5u || header.crit) throw new Error('Unsupported token header');
		kid = header.kid;
	} catch { throw new IdentityError('UNAUTHENTICATED'); }
	let keys: JSONWebKeySet;
	try { keys = await firebaseKeys(kid, request.signal); }
	catch (error) { throw error instanceof IdentityError ? error : new IdentityError('IDENTITY_UNAVAILABLE'); }
	try {
		const now = Math.floor(Date.now() / 1000);
		const { payload } = await jwtVerify(token, createLocalJWKSet(keys), {
			issuer: `https://securetoken.google.com/${projectId}`, audience: projectId, algorithms: ['RS256'],
			requiredClaims: ['exp', 'iat', 'auth_time', 'sub', 'aud', 'iss'], currentDate: new Date(now * 1000),
		});
		if (payload.aud !== projectId || typeof payload.sub !== 'string' || payload.sub.length === 0 || payload.sub.length > 128
			|| [...payload.sub].some((char) => char.charCodeAt(0) <= 31 || char.charCodeAt(0) === 127)
			|| !Number.isSafeInteger(payload.iat) || !Number.isSafeInteger(payload.exp) || !Number.isSafeInteger(payload.auth_time)
			|| typeof payload.iat !== 'number' || typeof payload.exp !== 'number' || typeof payload.auth_time !== 'number'
			|| payload.auth_time <= 0 || payload.auth_time > payload.iat || payload.iat > now || payload.exp <= now
			|| payload.exp - payload.iat > 3600 || !record(payload.firebase) || payload.firebase.tenant !== undefined
			|| payload.firebase.sign_in_provider !== 'custom'
			|| !Number.isSafeInteger(payload.access_version) || typeof payload.access_version !== 'number' || payload.access_version < 1
			|| (payload.user_id !== undefined && payload.user_id !== payload.sub)) throw new Error('Invalid identity claims');
		const subject = parseResourceId('user', payload.sub), credentialRef = parseResourceId('operation', payload.credential_ref);
		return Object.freeze({ environment, userId: subject, credentialRef, accessVersion: payload.access_version,
			authTime: payload.auth_time, expiresAt: payload.exp });
	} catch { throw new IdentityError('UNAUTHENTICATED'); }
}
