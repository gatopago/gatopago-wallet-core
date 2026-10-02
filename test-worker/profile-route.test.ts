import { env } from 'cloudflare:workers';
import { applyD1Migrations } from 'cloudflare:test';
import { afterEach, beforeAll, beforeEach, describe, expect, it, vi } from 'vitest';
import { parseEnvironment } from '@gatopago/environment';
import manifests from '@gatopago/environment/environments.json';
import { createResourceId } from '@gatopago/shared/v3/primitives';
import { clientMutationHeaders } from '@gatopago/shared/v3/client-release';
import { createWalletWorker } from '../src/index';
import { profileRoute } from '../src/accounts/profileRoute';
import { testIdentitySigner, clearIdentityKeys, seedIdentityKeys } from './identity.fixture';
import { testPrincipal } from './principal.fixture';
import { seedUser } from './user.fixture';

const config = parseEnvironment({ ...manifests.production, status: 'provisioned', firebase_project_id: 'v3-runtime-test', wallet_enabled: ['eip155:84532'] });
const principal = () => testPrincipal('profile-route');
let signer: Awaited<ReturnType<typeof testIdentitySigner>>;
const profiles = vi.fn(async () => { throw new Error('Unexpected chain read'); });
async function request(path = '/profile', method = 'GET', body?: object, extra: Record<string, string> = {}) {
  return new Request(`${config.api_origin}/app/v1${path}`, { method, ...(body ? { body: JSON.stringify(body) } : {}), headers: {
    Origin: config.web_origin, ...(path.startsWith('/profile') ? { Authorization: `Bearer ${await signer.token({ sub: principal().userId })}` } : {}),
    'CF-Connecting-IP': '192.0.2.1', ...(method === 'POST' ? { 'Content-Type': 'application/json', ...clientMutationHeaders('production') } : {}), ...extra } });
}
const run = (request: Request, bindings = env) => profileRoute(request, bindings, config, profiles);
beforeAll(async () => { await applyD1Migrations(env.WALLET_DB, env.V3_TEST_MIGRATIONS); signer = await testIdentitySigner(); });
beforeEach(async () => {
  await env.WALLET_DB.exec('DELETE FROM auth_limits; DELETE FROM webauthn_credentials; DELETE FROM users;');
  vi.spyOn(Date, 'now').mockReturnValue(Date.now()); profiles.mockClear();
  await clearIdentityKeys(); await seedIdentityKeys(signer.keys, Math.floor(Date.now() / 1000)); await seedUser(env.WALLET_DB, principal());
});
afterEach(() => { vi.restoreAllMocks(); });

describe('Profile HTTP authorization and public lookup limits', () => {
  it('reads and saves an admitted user profile with custom JWT, never requiring a chain provider', async () => {
    expect((await run(await request())).status).toBe(200);
    const response = await run(await request('/profile', 'POST', { display_name: 'Daniel' }));
    expect(response.status).toBe(200); expect(await response.json()).toMatchObject({ display_name: 'Daniel', username: null, receiving_wallet_id: null });
    expect(response.headers.get('Cache-Control')).toBe('no-store'); expect(profiles).not.toHaveBeenCalled();
  });
  it('mounts profile reads on the real Worker independently of financial runtime availability', async () => {
    const worker = createWalletWorker({ invalid: true }, () => config);
    const response = await worker.fetch(await request(), env);
    expect(response.status).toBe(200); expect(await response.json()).toHaveProperty('user_id', principal().userId);
  });
  it('rejects foreign origins, obsolete clients and unknown fields before mutation', async () => {
    expect((await run(await request('/profile', 'POST', { display_name: 'Daniel' }, { Origin: 'https://evil.test' }))).status).toBe(403);
    const old = await request('/profile', 'POST', { display_name: 'Daniel' });
    for (const name of Object.keys(clientMutationHeaders('production'))) old.headers.delete(name);
    expect((await run(old)).status).toBe(409);
    expect((await run(await request('/profile', 'POST', { display_name: 'Daniel', receiving_wallet_id: 'foreign' }))).status).toBe(400);
    expect(profiles).not.toHaveBeenCalled();
  });
  it('rejects removed credentials for both reads and edits, including a fresh token', async () => {
    await env.WALLET_DB.prepare('UPDATE webauthn_credentials SET access_version = access_version + 1 WHERE id = ?').bind(principal().credentialRef).run();
    expect((await run(await request())).status).toBe(401);
    expect((await run(await request('/profile', 'POST', { display_name: 'Daniel' }))).status).toBe(401);
  });
  it('requires a selected admitted network for public resolution and never guesses an account', async () => {
    for (const path of ['/recipients/daniel', '/recipients/daniel?network_id=eip155:84532&network_id=eip155:1']) expect((await run(await request(path))).status).toBe(400);
    expect((await run(await request('/recipients/daniel?network_id=eip155:1'))).status).toBe(404);
    expect((await run(await request('/recipients/daniel?network_id=eip155:84532'))).status).toBe(404);
    expect(profiles).not.toHaveBeenCalled();
  });
  it('limits public enumeration before provider work, using a bucket separate from authentication', async () => {
    const bindings = { ...env, PUBLIC_LOOKUP_IP_REQUESTS_PER_HOUR: '1' };
    const path = '/recipients/daniel?network_id=eip155:84532';
    expect((await run(await request(path), bindings)).status).toBe(404);
    expect((await run(await request(path), bindings)).status).toBe(429);
    expect(await env.WALLET_DB.prepare("SELECT count(*) AS n FROM auth_limits WHERE scope = 'global' AND key_hash = 'all'").first('n')).toBe(0);
    expect(profiles).not.toHaveBeenCalled();
  });
  it('also charges publication checks to the receiving quota, without charging name edits', async () => {
    const bindings = { ...env, PUBLIC_LOOKUP_IP_REQUESTS_PER_HOUR: '1' };
    expect((await run(await request('/profile', 'POST', { display_name: 'Daniel' }), bindings)).status).toBe(200);
    expect((await run(await request('/profile/username', 'POST', { username: 'daniel', wallet_id: createResourceId('wallet'), wallet_account_id: createResourceId('walletAccount') }), bindings)).status).toBe(404);
    expect((await run(await request('/recipients/daniel?network_id=eip155:84532'), bindings)).status).toBe(429);
  });
  it('rejects public cookies, bearer tokens and absent trusted IP', async () => {
    const path = '/recipients/daniel?network_id=eip155:84532';
    for (const headers of ([{ Cookie: 'session=x' }, { Authorization: 'Bearer token' }] as Record<string, string>[])) expect((await run(await request(path, 'GET', undefined, headers))).status).toBe(400);
    expect((await run(await request(path, 'GET', undefined, { 'CF-Connecting-IP': '' }))).status).toBe(403);
    expect(await env.WALLET_DB.prepare('SELECT count(*) AS n FROM auth_limits').first('n')).toBe(0);
  });
});
