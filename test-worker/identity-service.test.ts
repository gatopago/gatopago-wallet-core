import { env } from 'cloudflare:workers';
import { applyD1Migrations, createExecutionContext } from 'cloudflare:test';
import { afterEach, beforeAll, beforeEach, describe, expect, it, vi } from 'vitest';
import { parseEnvironment } from '@gatopago/environment';
import manifests from '@gatopago/environment/environments.json';
import { identityService, WalletIdentity } from '../src/auth/service';
import { createWalletWorker } from '../src/index';
import { testIdentitySigner, clearIdentityKeys, seedIdentityKeys } from './identity.fixture';
import { testPrincipal } from './principal.fixture';
import { seedUser } from './user.fixture';

const config = parseEnvironment({ ...manifests.staging, status: 'provisioned', firebase_project_id: 'v3-runtime-test' });
const principal = testPrincipal('flow-identity');
let signer: Awaited<ReturnType<typeof testIdentitySigner>>;
const run = (request: Request) => identityService(request, env, () => config);
async function request(claims: Parameters<typeof signer.token>[0] = {}, headers: Record<string, string> = {}) {
  return new Request('https://wallet-identity.internal/session', { method: 'POST', headers: {
    Authorization: `Bearer ${await signer.token({ sub: principal.userId, ...claims })}`,
    'X-GatoPago-Environment': 'staging', ...headers } });
}
beforeAll(async () => { await applyD1Migrations(env.WALLET_DB, env.V3_TEST_MIGRATIONS); signer = await testIdentitySigner(); });
beforeEach(async () => {
  await env.WALLET_DB.exec('DELETE FROM webauthn_credentials; DELETE FROM users;');
  vi.spyOn(Date, 'now').mockReturnValue(Date.now());
  await clearIdentityKeys(); await seedIdentityKeys(signer.keys, Math.floor(Date.now() / 1000));
  await seedUser(env.WALLET_DB, principal);
});
afterEach(() => vi.restoreAllMocks());

describe('private Wallet Core identity service', () => {
  it('returns only a stable internal identity, environment and bounded access expiry', async () => {
    const response = await run(await request());
    expect(response.status).toBe(200);
    expect(response.headers.get('Cache-Control')).toBe('no-store');
    expect(await response.json()).toEqual({ user_id: principal.userId, environment: 'staging', expires_at: Math.floor(Date.now() / 1000) + 30 });
  });
  it.each([
    'UPDATE webauthn_credentials SET login_enabled = 0',
    'UPDATE webauthn_credentials SET revoked_at = 1',
    'UPDATE webauthn_credentials SET access_version = access_version + 1',
    'UPDATE users SET disabled_at = 1',
    'UPDATE users SET auth_not_before = 9999999999',
  ])('checks current admission on every call, including refreshed tokens: %s', async (sql) => {
    const original = await request();
    expect((await run(original)).status).toBe(200);
    await env.WALLET_DB.exec(sql);
    expect((await run(original)).status).toBe(401);
    expect((await run(await request())).status).toBe(401);
  });
  it('rejects Google/password and users absent from Wallet Core', async () => {
    for (const provider of ['google.com', 'password']) expect((await run(await request({ firebase: { sign_in_provider: provider } }))).status).toBe(401);
    expect((await run(await request({ sub: testPrincipal('not-admitted').userId }))).status).toBe(401);
  });
  it('rejects cookies, browser origins, wrong environment and wrong audience', async () => {
    expect((await run(await request({}, { Cookie: 'session=value' }))).status).toBe(401);
    expect((await run(await request({}, { Origin: config.web_origin }))).status).toBe(401);
    expect((await run(await request({}, { 'X-GatoPago-Environment': 'production' }))).status).toBe(503);
    expect((await run(await request({ aud: 'other-project' }))).status).toBe(401);
  });
  it('does not expose introspection on the public worker or provision an unconfigured service', async () => {
    const worker = createWalletWorker({}, () => config);
    expect((await worker.fetch(await request(), env)).status).toBe(404);
    const service = new WalletIdentity(createExecutionContext(), env);
    expect((await service.fetch(await request())).status).toBe(503);
    expect((await run(new Request('https://wallet-identity.internal/session'))).status).toBe(404);
  });
});
