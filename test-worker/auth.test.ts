import { env } from 'cloudflare:workers';
import { applyD1Migrations } from 'cloudflare:test';
import { afterEach, beforeAll, beforeEach, describe, expect, it, vi } from 'vitest';
import { exportPKCS8, generateKeyPair, jwtVerify } from 'jose';
import manifests from '@gatopago/environment/environments.json';
import { parseEnvironment } from '@gatopago/environment';
import { clientMutationHeaders } from '@gatopago/shared/v3/client-release';
import { authRoute } from '../src/auth/route';
import { issueInvitation } from './invitations.fixture';
import { consumeLimit, privateLimitKey, pruneLimits } from '../src/auth/limits';
import { credential, generateKey, authentication } from './passkey.fixture';
import type { RegistrationRepository } from '../src/auth/registration';
import type { LoginRepository } from '../src/auth/login';

const config = parseEnvironment({ ...manifests.production, status: 'provisioned', firebase_project_id: 'v3-runtime-test' });
const root = `${config.api_origin}/app/v1/auth`;
let signer: string, publicKey: CryptoKey;
const bindings = () => ({ ...env, FIREBASE_CUSTOM_TOKEN_SIGNER_JSON: signer });
function request(path: string, body: unknown = {}, headers: Record<string, string> = {}) {
  return new Request(`${root}/${path}`, { method: 'POST', body: JSON.stringify(body), headers: {
    Origin: config.web_origin, 'Content-Type': 'application/json', 'CF-Connecting-IP': '192.0.2.1',
    ...clientMutationHeaders('production'), ...headers } });
}
const run = (req: Request) => authRoute(req, bindings(), config);
async function signup() {
  const invite = await issueInvitation(env.WALLET_DB, 'operator', Math.floor(Date.now() / 1000) + 3600);
  return { invite: invite.token, name: 'Daniel', username: 'daniel', turnstile_token: 'synthetic-token' };
}
function human(fields: Record<string, unknown> = {}) {
  return vi.stubGlobal('fetch', vi.fn(async () => Response.json({ success: true, action: 'signup',
    hostname: new URL(config.web_origin).hostname, ...fields })));
}
beforeAll(async () => {
  await applyD1Migrations(env.WALLET_DB, env.V3_TEST_MIGRATIONS);
  const keys = await generateKeyPair('RS256', { extractable: true }); publicKey = keys.publicKey;
  signer = JSON.stringify({ project_id: 'v3-runtime-test', client_email: 'sessions@v3-runtime-test.iam.gserviceaccount.com',
    private_key: await exportPKCS8(keys.privateKey) });
});
beforeEach(async () => {
  await env.WALLET_DB.exec('DELETE FROM auth_limits; DELETE FROM auth_challenges; DELETE FROM signup_invites; DELETE FROM webauthn_credentials; DELETE FROM users;');
  human();
});
afterEach(() => { vi.restoreAllMocks(); vi.unstubAllGlobals(); });

describe('public passkey authentication boundary', () => {
  it('registers by invitation and logs into the same UID without Google, email or a second invite', async () => {
    const prepared = await run(request('register/options', await signup())); expect(prepared.status).toBe(200);
    const p = await prepared.json<Awaited<ReturnType<RegistrationRepository['prepare']>>>(), key = generateKey();
    const proof = credential(p, { key });
    const completed = await run(request('register/complete', { request_id: p.request_id, response: proof }));
    expect(completed.status).toBe(200); expect(completed.headers.get('Cache-Control')).toBe('no-store');
    const first = await jwtVerify((await completed.json<{ custom_token: string }>()).custom_token, publicKey);
    expect(first.payload).toHaveProperty('uid');
    expect(first.payload).not.toHaveProperty('email');
    const login = await run(request('login/options'));
    const l = await login.json<Awaited<ReturnType<LoginRepository['prepare']>>>();
    const response = await run(request('login/complete', { request_id: l.request_id,
      response: authentication(l, key, proof.credential_id, p.options.user.id) }));
    expect(response.status).toBe(200);
    const second = await jwtVerify((await response.json<{ custom_token: string }>()).custom_token, publicKey);
    expect(second.payload.uid).toBe(first.payload.uid); expect(second.payload.claims).toEqual(first.payload.claims);
    expect(await env.WALLET_DB.prepare('SELECT count(*) AS n FROM users').first('n')).toBe(1);
    expect(fetch).toHaveBeenCalledTimes(1);
  });
  it('has no email-link or implicit registration route', async () => {
    expect((await run(request('email-link/request', { email: 'test@example.test' }))).status).toBe(404);
    expect((await run(request('register/options', { name: 'Daniel', username: 'daniel', turnstile_token: 'x' }))).status).toBe(400);
    expect(await env.WALLET_DB.prepare('SELECT count(*) AS n FROM users').first('n')).toBe(0);
  });
  it.each([{ Origin: 'https://evil.test' }, { Origin: 'null' }])('rejects an invalid origin before providers or quotas', async headers => {
    expect((await run(request('register/options', await signup(), headers))).status).toBe(403);
    expect(fetch).not.toHaveBeenCalled();
    expect(await env.WALLET_DB.prepare('SELECT count(*) AS n FROM auth_limits').first('n')).toBe(0);
  });
  it.each<Record<string, string>>([{ Cookie: 'session=x' }, { Authorization: 'Bearer token' }, { 'Content-Type': 'text/plain' }])('rejects ambient credentials or non-JSON', async headers => {
    expect((await run(request('login/options', {}, headers))).status).toBe(400);
    expect(fetch).not.toHaveBeenCalled();
  });
  it.each([{ success: false }, { action: 'email_login' }, { hostname: 'evil.test' }])('requires the expected Turnstile action and hostname', async fields => {
    human(fields);
    expect((await run(request('register/options', await signup()))).status).toBe(403);
    expect(await env.WALLET_DB.prepare('SELECT count(*) AS n FROM auth_challenges').first('n')).toBe(0);
  });
  it('does not consume invitation or create a challenge on a provider failure', async () => {
    vi.stubGlobal('fetch', vi.fn().mockRejectedValue(new Error('provider failed')));
    expect((await run(request('register/options', await signup()))).status).toBe(503);
    expect(await env.WALLET_DB.prepare('SELECT count(*) AS n FROM auth_challenges').first('n')).toBe(0);
    expect(await env.WALLET_DB.prepare('SELECT consumed_by FROM signup_invites').first('consumed_by')).toBeNull();
  });
  it('rejects oversized bodies and missing edge IP, ignoring X-Forwarded-For', async () => {
    expect((await run(request('login/options', { filler: 'x'.repeat(25000) }))).status).toBe(413);
    const req = request('login/options', {}, { 'X-Forwarded-For': '192.0.2.3' }); req.headers.delete('CF-Connecting-IP');
    expect((await run(req)).status).toBe(403);
  });
  it('requires a compatible client before creating challenges', async () => {
    const req = request('login/options');
    for (const header of Object.keys(clientMutationHeaders('production'))) req.headers.delete(header);
    expect((await run(req)).status).toBe(409);
    expect(await env.WALLET_DB.prepare('SELECT count(*) AS n FROM auth_challenges').first('n')).toBe(0);
  });
  it('does not duplicate an admitted user after Firebase token signing fails', async () => {
    const p = await (await run(request('register/options', await signup()))).json<Awaited<ReturnType<RegistrationRepository['prepare']>>>();
    const key = generateKey(), proof = credential(p, { key });
    const broken = { ...bindings(), FIREBASE_CUSTOM_TOKEN_SIGNER_JSON: '{}' };
    expect((await authRoute(request('register/complete', { request_id: p.request_id, response: proof }), broken, config)).status).toBe(503);
    expect(await env.WALLET_DB.prepare('SELECT count(*) AS n FROM users').first('n')).toBe(1);
    const l = await (await run(request('login/options'))).json<Awaited<ReturnType<LoginRepository['prepare']>>>();
    expect((await run(request('login/complete', { request_id: l.request_id,
      response: authentication(l, key, proof.credential_id, p.options.user.id) }))).status).toBe(200);
    expect(await env.WALLET_DB.prepare('SELECT count(*) AS n FROM users').first('n')).toBe(1);
  });
  it('serializes quotas across concurrent requests and does not extend exhausted windows', async () => {
    const results = await Promise.all(Array.from({ length: 25 }, () => consumeLimit(env.WALLET_DB, 'ip', 'test', 1000, 20)));
    expect(results.filter(Boolean)).toHaveLength(20);
    expect(await consumeLimit(env.WALLET_DB, 'ip', 'test', 4599, 20)).toBe(false);
    expect(await env.WALLET_DB.prepare('SELECT count,reset_at FROM auth_limits').first()).toEqual({ count: 20, reset_at: 4600 });
    expect(await consumeLimit(env.WALLET_DB, 'ip', 'test', 4600, 20)).toBe(true);
  });
  it('enforces a global cap before crypto or provider work', async () => {
    const limited = { ...bindings(), AUTH_GLOBAL_REQUESTS_PER_HOUR: '1' };
    expect((await authRoute(request('login/options'), limited, config)).status).toBe(200);
    expect((await authRoute(request('login/options', {}, { 'CF-Connecting-IP': '192.0.2.2' }), limited, config)).status).toBe(429);
    expect(fetch).not.toHaveBeenCalled();
  });
  it('hashes private quota keys by scope and prunes expired limits', async () => {
    const key = await privateLimitKey(env, 'ip', '192.0.2.1');
    expect(key).toMatch(/^[0-9a-f]{64}$/);
    expect(key).not.toBe(await privateLimitKey(env, 'global', '192.0.2.1'));
    await consumeLimit(env.WALLET_DB, 'ip', key, 1000, 10); await consumeLimit(env.WALLET_DB, 'global', 'all', 4000, 10);
    await pruneLimits(env.WALLET_DB, 4600);
    expect((await env.WALLET_DB.prepare('SELECT key_hash FROM auth_limits').all()).results).toEqual([{ key_hash: 'all' }]);
  });
});
