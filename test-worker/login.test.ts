import { env } from 'cloudflare:workers';
import { applyD1Migrations } from 'cloudflare:test';
import { afterEach, beforeAll, beforeEach, describe, expect, it, vi } from 'vitest';
import { exportPKCS8, generateKeyPair, jwtVerify } from 'jose';
import { LoginRepository } from '../src/auth/login';
import { RegistrationRepository } from '../src/auth/registration';
import { issueInvitation } from './invitations.fixture';
import { createSessionToken } from '../src/auth/customToken';
import { authentication, credential, generateKey } from './passkey.fixture';

const scope = { rpId: 'gatopago.com', origin: 'https://gatopago.com' };
const login = () => new LoginRepository(env.WALLET_DB, scope);
async function user(synchronized = false) {
  const now = Math.floor(Date.now() / 1000),
    key = generateKey();
  const invitation = await issueInvitation(env.WALLET_DB, 'operator', now + 3600);
  const registration = new RegistrationRepository(env.WALLET_DB, 'production', scope);
  const prepared = await registration.prepare({
    invite: invitation.token,
    name: 'Daniel',
    username: 'daniel',
  });
  const proof = credential(prepared, {
    key,
    ...(synchronized ? { createFlags: 0x5d, proofFlags: 0x1d, proofCount: 0 } : {}),
  });
  const principal = await registration.complete(prepared.request_id, proof);
  return { key, id: proof.credential_id, handle: prepared.options.user.id, principal, prepared };
}
beforeAll(async () => {
  await applyD1Migrations(env.WALLET_DB, env.V3_TEST_MIGRATIONS);
});
beforeEach(async () => {
  await env.WALLET_DB.exec(
    'DELETE FROM auth_challenges; DELETE FROM signup_invites; DELETE FROM webauthn_credentials; DELETE FROM users;',
  );
});
afterEach(() => vi.restoreAllMocks());

describe('discoverable passkey login', () => {
  it('returns the same user and consumes an assertion only once, without another invitation', async () => {
    const f = await user(),
      p = await login().prepare(),
      proof = authentication(p, f.key, f.id, f.handle);
    expect(await login().complete(p.request_id, proof)).toEqual(f.principal);
    await expect(login().complete(p.request_id, proof)).rejects.toThrow('UNAUTHENTICATED');
    expect(
      await env.WALLET_DB.prepare('SELECT sign_count FROM webauthn_credentials').first(
        'sign_count',
      ),
    ).toBe(2);
    expect(await env.WALLET_DB.prepare('SELECT count(*) AS n FROM users').first('n')).toBe(1);
  });
  it('accepts synchronized passkeys with a zero counter without treating it as cloning', async () => {
    const f = await user(true);
    for (let i = 0; i < 2; i++) {
      const p = await login().prepare();
      expect(
        await login().complete(
          p.request_id,
          authentication(p, f.key, f.id, f.handle, { count: 0, flags: 0x1d }),
        ),
      ).toEqual(f.principal);
    }
  });
  it('consumes a synchronized assertion once even when two completions race', async () => {
    const f = await user(true),
      p = await login().prepare(),
      proof = authentication(p, f.key, f.id, f.handle, { count: 0, flags: 0x1d });
    const results = await Promise.allSettled([
      login().complete(p.request_id, proof),
      login().complete(p.request_id, proof),
    ]);
    expect(results.filter((result) => result.status === 'fulfilled')).toHaveLength(1);
  });
  it.each([
    'origin',
    'rp',
    'challenge',
    'flags',
    'counter',
    'key',
    'handle',
    'eligibility',
  ] as const)('rejects changed %s', async (field) => {
    const f = await user(),
      p = await login().prepare();
    const options = {
      ...(field === 'origin' ? { origin: 'https://evil.test' } : {}),
      ...(field === 'rp' ? { rp: 'evil.test' } : {}),
      ...(field === 'challenge' ? { challenge: 'AAAA' } : {}),
      ...(field === 'flags' ? { flags: 1 } : {}),
      ...(field === 'eligibility' ? { flags: 0x1d } : {}),
      ...(field === 'counter' ? { count: 1 } : {}),
    };
    await expect(
      login().complete(
        p.request_id,
        authentication(
          p,
          field === 'key' ? generateKey() : f.key,
          f.id,
          field === 'handle' ? 'A'.repeat(43) : f.handle,
          options,
        ),
      ),
    ).rejects.toThrow('UNAUTHENTICATED');
    expect(
      await env.WALLET_DB.prepare(
        "SELECT consumed_at FROM auth_challenges WHERE purpose = 'login'",
      ).first('consumed_at'),
    ).toBeNull();
  });
  it.each(['credential', 'user', 'uninstalled', 'expired'] as const)(
    'denies a %s after challenge issuance',
    async (change) => {
      const f = await user(),
        p = await login().prepare(),
        proof = authentication(p, f.key, f.id, f.handle);
      if (change === 'credential')
        await env.WALLET_DB.prepare('UPDATE webauthn_credentials SET revoked_at = 1').run();
      if (change === 'user') await env.WALLET_DB.prepare('UPDATE users SET disabled_at = 1').run();
      if (change === 'uninstalled')
        await env.WALLET_DB.prepare('UPDATE webauthn_credentials SET login_enabled = 0').run();
      if (change === 'expired') vi.spyOn(Date, 'now').mockReturnValue(p.expires_at * 1000);
      await expect(login().complete(p.request_id, proof)).rejects.toThrow('UNAUTHENTICATED');
    },
  );
  it('rejects a registration challenge as login even when signed by the registered key', async () => {
    const f = await user(),
      p = { scope, options: { challenge: f.prepared.options.challenge } };
    await expect(
      login().complete(f.prepared.request_id, authentication(p, f.key, f.id, f.handle)),
    ).rejects.toThrow('UNAUTHENTICATED');
  });
  it('creates a short Firebase exchange token scoped to the user, credential and access version', async () => {
    const f = await user(),
      keys = await generateKeyPair('RS256', { extractable: true });
    const email = 'sessions@v3-runtime-test.iam.gserviceaccount.com';
    const signer = JSON.stringify({
      project_id: 'v3-runtime-test',
      client_email: email,
      private_key: await exportPKCS8(keys.privateKey),
    });
    const token = await createSessionToken(signer, 'v3-runtime-test', f.principal);
    const { payload } = await jwtVerify(token, keys.publicKey, {
      issuer: email,
      subject: email,
      algorithms: ['RS256'],
      audience:
        'https://identitytoolkit.googleapis.com/google.identity.identitytoolkit.v1.IdentityToolkit',
    });
    expect(payload).toMatchObject({
      uid: f.principal.userId,
      claims: { credential_ref: f.principal.credentialRef, access_version: 1 },
    });
    expect(payload.exp! - payload.iat!).toBe(300);
    await expect(createSessionToken(signer, 'other-project', f.principal)).rejects.toThrow(
      'Invalid Firebase signer',
    );
  });
});
