import { testCredentialRef } from './principal.fixture';
import { credential, generateKey } from './passkey.fixture';
import { env, exports } from 'cloudflare:workers';
import { applyD1Migrations } from 'cloudflare:test';
import { afterEach, beforeAll, beforeEach, describe, expect, it, vi } from 'vitest';
import { hexToBytes, type Hex } from 'viem';
import manifests from '@gatopago/environment/environments.json';
import { parseEnvironment } from '@gatopago/environment';
import { createResourceId } from '@gatopago/shared/v3/primitives';
import { parseCredentialDetail } from '@gatopago/shared/v3/credential-detail';
import { clientMutationHeaders } from '@gatopago/shared/v3/client-release';
import { enrollmentRoute } from '../src/enrollment/route';
import { base64url } from '../src/enrollment/verification';
import { seedUser } from './user.fixture';
import { verifyConsumerIdentity } from '../src/auth/identity';
import { WalletRepository } from '../src/accounts/repository';
import { clearIdentityKeys, projectId, testIdentitySigner } from './identity.fixture';

const config = parseEnvironment({
  ...manifests.production,
  status: 'provisioned',
  firebase_project_id: projectId,
});
const ROOT = '/app/v1/security/enrollments';
let signer: Awaited<ReturnType<typeof testIdentitySigner>>;
type Prepared = {
  enrollment_id: string;
  state: 'prepared';
  expires_at: number;
  proof_challenge: Hex;
  scope: { rpId: string; origin: string };
  options: {
    challenge: string;
    user: { id: string; name: string };
    excludeCredentials: { id: string }[];
  };
};
async function input(
  path = ROOT,
  body: unknown = { request_id: createResourceId('operation') },
  subject = 'test-user-a',
  method = 'POST',
) {
  return new Request(`${config.api_origin}${path}`, {
    method,
    headers: {
      Origin: config.web_origin,
      Authorization: `Bearer ${await signer.token({ sub: subject })}`,
      'Content-Type': 'application/json',
      ...clientMutationHeaders('production'),
    },
    ...(method === 'POST' ? { body: JSON.stringify(body) } : {}),
  });
}
const run = (request: Request) => enrollmentRoute(request, env, config);
// Count additional enrollments separately from the passkey that admitted each user.
const count = () =>
  env.WALLET_DB.prepare(
    'SELECT count(*) AS n FROM webauthn_credentials WHERE login_enabled = 0',
  ).first<number>('n');
async function session(subject = 'test-user-a') {
  return seedUser(
    env.WALLET_DB,
    await verifyConsumerIdentity(
      await input('/app/v1/session', {}, subject),
      projectId,
      'production',
    ),
  );
}
async function prepare(subject = 'test-user-a', id = createResourceId('operation')) {
  const response = await run(await input(ROOT, { request_id: id }, subject));
  expect(response.status).toBe(200);
  return response.json<Prepared>();
}
async function complete(
  attempt: Prepared,
  body: unknown = credential(attempt),
  subject = 'test-user-a',
) {
  return run(await input(`${ROOT}/${attempt.enrollment_id}/complete`, body, subject));
}

beforeAll(async () => {
  await applyD1Migrations(env.WALLET_DB, env.V3_TEST_MIGRATIONS);
  signer = await testIdentitySigner();
});
beforeEach(async () => {
  await clearIdentityKeys();
  signer.mock();
  await env.WALLET_DB.exec(`DELETE FROM webauthn_credentials; DELETE FROM webauthn_enrollments;
		DELETE FROM wallet_accounts; DELETE FROM wallets; DELETE FROM users;`);
});
afterEach(() => {
  vi.restoreAllMocks();
  vi.unstubAllGlobals();
});

describe('V3 authenticated credential inventory', () => {
  const PATH = '/app/v1/security/credentials';
  const read = async (subject = 'test-user-a') => run(await input(PATH, {}, subject, 'GET'));
  it('is mounted but unprovisioned runtime remains closed', async () => {
    expect((await exports.default.fetch(await input(PATH, {}, 'test-user-a', 'GET'))).status).toBe(
      503,
    );
  });
  it('requires admission and includes the passkey used at signup', async () => {
    expect((await read()).status).toBe(409);
    expect(await env.WALLET_DB.prepare('SELECT count(*) AS n FROM users').first('n')).toBe(0);
    await session();
    expect(await (await read()).json()).toEqual({
      scope: { rpId: config.webauthn_rp_id, origin: config.web_origin },
      data: [
        {
          credential_ref: testCredentialRef('test-user-a'),
          created_at: expect.any(Number),
          transports: ['internal'],
          aaguid: '00000000-0000-0000-0000-000000000000',
          backup_eligible: false,
          backed_up_at_registration: false,
        },
      ],
      device_availability: 'unknown',
      onchain_authority: 'not_assessed',
    });
    expect(
      await env.WALLET_DB.prepare('SELECT count(*) AS n FROM webauthn_enrollments').first('n'),
    ).toBe(0);
  });
  it('reads only owned completed registrations and never claims current device or onchain state', async () => {
    await session();
    await session('user-b');
    const a = await prepare(),
      b = await prepare('user-b');
    const body = credential(a, { createFlags: 0x5d, proofFlags: 0x1d, proofCount: 0 });
    expect((await complete(a, body)).status).toBe(200);
    expect((await complete(b, credential(b), 'user-b')).status).toBe(200);
    await prepare(); // An uncompleted creation is not a registered credential.
    const before = await env.WALLET_DB.prepare(
      'SELECT * FROM webauthn_credentials ORDER BY id',
    ).all();
    const result = await read();
    expect(result.status).toBe(200);
    expect(result.headers.get('Cache-Control')).toBe('no-store');
    expect(result.headers.get('Access-Control-Allow-Origin')).toBe(config.web_origin);
    const value = await result.json<{
      data: object[];
      onchain_authority: string;
      device_availability: string;
    }>();
    expect(value.data).toHaveLength(2);
    expect(value.data).toContainEqual({
      credential_ref: a.enrollment_id,
      created_at: expect.any(Number),
      transports: ['internal'],
      aaguid: '00000000-0000-0000-0000-000000000000',
      backup_eligible: true,
      backed_up_at_registration: true,
    });
    expect(value).toMatchObject({
      onchain_authority: 'not_assessed',
      device_availability: 'unknown',
    });
    for (const forbidden of [
      body.credential_id,
      b.enrollment_id,
      'public_key',
      'response_hash',
      'test-user-a',
      'sign_count',
    ]) {
      expect(JSON.stringify(value)).not.toContain(forbidden);
    }
    expect(
      (await env.WALLET_DB.prepare('SELECT * FROM webauthn_credentials ORDER BY id').all()).results,
    ).toEqual(before.results);
    expect(await env.WALLET_DB.prepare('SELECT count(*) AS n FROM wallets').first('n')).toBe(0);
  });
  it.each(['disabled_at', 'auth_not_before'])(
    'rejects a revoked owner via %s instead of returning empty',
    async (column) => {
      const owner = await session();
      await env.WALLET_DB.prepare(`UPDATE users SET ${column} = ? WHERE id = ?`)
        .bind(Math.floor(Date.now() / 1000) + 1, owner.user_id)
        .run();
      expect((await read()).status).toBe(401);
    },
  );
  it('retains the inventory after the short-lived enrollment operation is pruned', async () => {
    await session();
    const attempt = await prepare();
    expect((await complete(attempt)).status).toBe(200);
    await env.WALLET_DB.prepare('DELETE FROM webauthn_enrollments WHERE id = ?')
      .bind(attempt.enrollment_id)
      .run();
    const result = await read();
    expect(result.status).toBe(200);
    expect(
      (await result.json<{ data: { credential_ref: string }[] }>()).data.map(
        (item) => item.credential_ref,
      ),
    ).toEqual(expect.arrayContaining([testCredentialRef('test-user-a'), attempt.enrollment_id]));
  });
  it('rechecks session revocation after reading D1', async () => {
    const owner = await session();
    const original = WalletRepository.prototype.getSession;
    let calls = 0;
    vi.spyOn(WalletRepository.prototype, 'getSession').mockImplementation(async function (
      this: WalletRepository,
    ) {
      if (++calls === 2)
        await env.WALLET_DB.prepare('UPDATE users SET disabled_at = 1 WHERE id = ?')
          .bind(owner.user_id)
          .run();
      return original.call(this);
    });
    expect((await read()).status).toBe(401);
    expect(calls).toBe(2);
  });
  it.each([
    ['transports_json', '["internal","internal"]'],
    ['transports_json', '["invented"]'],
    ['transports_json', '{}'],
    ['transports_json', JSON.stringify(['x'.repeat(300)])],
    ['aaguid', 'claimed-provider'],
    ['created_at', -1],
    ['created_at', 9999999999999],
    ['rp_id', 'other.test'],
    ['origin', 'https://other.test'],
  ] as const)(
    'rejects inconsistent metadata (%s = %s), not an empty inventory',
    async (column, value) => {
      await session();
      const attempt = await prepare();
      expect((await complete(attempt)).status).toBe(200);
      await env.WALLET_DB.prepare(`UPDATE webauthn_credentials SET ${column} = ? WHERE id = ?`)
        .bind(value, attempt.enrollment_id)
        .run();
      const result = await read();
      expect(result.status).toBe(503);
      expect(await result.json()).toEqual({ error_code: 'WALLET_DATA_INVALID' });
    },
  );
  it('bounds a complete inventory at 16 and rejects a seventeenth row without silently truncating', async () => {
    await session();
    const attempt = await prepare();
    expect((await complete(attempt)).status).toBe(200);
    // Synthetic rows exercise the inventory bound, not registration crypto or payment authority.
    const clone = (index: number) =>
      env.WALLET_DB.prepare(
        `INSERT INTO webauthn_credentials(id,user_id,rp_id,origin,credential_id,public_key,transports_json,aaguid,backup_eligible,backed_up,sign_count,response_hash,created_at)
			SELECT ?,user_id,rp_id,origin,?, ?,transports_json,aaguid,backup_eligible,backed_up,sign_count,response_hash,created_at
			FROM webauthn_credentials WHERE id = ?`,
      )
        .bind(
          createResourceId('operation'),
          `synthetic-${index}`,
          `0x${index.toString(16).padStart(256, '0')}`,
          attempt.enrollment_id,
        )
        .run();
    for (let index = 1; index < 15; index++) await clone(index);
    const result = await read();
    expect(result.status).toBe(200);
    expect((await result.json<{ data: object[] }>()).data).toHaveLength(16);
    await clone(15);
    expect((await read()).status).toBe(503);
  });
  it('requires bearer/project/origin ownership, but not mutation headers for a GET', async () => {
    await session();
    const request = await input(PATH, {}, 'test-user-a', 'GET');
    request.headers.delete('Content-Type');
    for (const key of Object.keys(clientMutationHeaders('production'))) request.headers.delete(key);
    expect((await run(request)).status).toBe(200);
    request.headers.set(
      'Authorization',
      `Bearer ${await signer.token({ aud: 'another-project' })}`,
    );
    expect((await run(request)).status).toBe(401);
    request.headers.delete('Authorization');
    request.headers.set('Cookie', 'session=synthetic');
    expect((await run(request)).status).toBe(401);
    request.headers.set('Origin', 'https://other.test');
    expect((await run(request)).status).toBe(403);
  });
  it('confines the inventory to GET with no caller-selected user, RP, or cross-origin preflight', async () => {
    expect((await run(await input(PATH))).status).toBe(405);
    expect((await run(await input(`${PATH}?uid=user-b`, {}, 'test-user-a', 'GET'))).status).toBe(
      404,
    );
    const request = await input(PATH, {}, 'test-user-a', 'OPTIONS');
    request.headers.set('Access-Control-Request-Method', 'GET');
    request.headers.set('Access-Control-Request-Headers', 'authorization');
    const response = await run(request);
    expect(response.status).toBe(200);
    expect(response.headers.get('Access-Control-Allow-Methods')).toBe('GET');
    request.headers.set('Access-Control-Request-Method', 'POST');
    expect((await run(request)).status).toBe(403);
  });
});

describe('V3 owner-only credential details', () => {
  const path = (id: string) => `/app/v1/security/credentials/${id}`;
  const read = async (id: string, subject = 'test-user-a') =>
    run(await input(path(id), {}, subject, 'GET'));
  it('returns validated public material after real registration, with no write, proof or availability claim', async () => {
    await session();
    const attempt = await prepare(),
      body = credential(attempt);
    expect((await complete(attempt, body)).status).toBe(200);
    const before = await env.WALLET_DB.prepare('SELECT * FROM webauthn_credentials').all();
    const pending = await env.WALLET_DB.prepare(
      'SELECT * FROM webauthn_enrollments ORDER BY id',
    ).all();
    const response = await read(attempt.enrollment_id),
      value = await response.json();
    expect(response.status).toBe(200);
    expect(response.headers.get('Cache-Control')).toBe('no-store');
    expect(response.headers.get('Access-Control-Allow-Origin')).toBe(config.web_origin);
    expect(parseCredentialDetail(value, attempt.scope, attempt.enrollment_id)).toEqual({
      scope: attempt.scope,
      credential_ref: attempt.enrollment_id,
      credential_id: body.credential_id,
      public_key: before.results.find((row) => row.id === attempt.enrollment_id)!.public_key,
      device_availability: 'unknown',
      onchain_authority: 'not_assessed',
    });
    for (const forbidden of [
      'response_hash',
      'sign_count',
      'user_id',
      'proof',
      body.proof.signature,
    ]) {
      expect(JSON.stringify(value)).not.toContain(forbidden);
    }
    expect(
      (await env.WALLET_DB.prepare('SELECT * FROM webauthn_credentials').all()).results,
    ).toEqual(before.results);
    expect(
      (await env.WALLET_DB.prepare('SELECT * FROM webauthn_enrollments ORDER BY id').all()).results,
    ).toEqual(pending.results);
  });
  it('returns the same not-found response for a foreign, missing or not-completed reference', async () => {
    await session();
    await session('user-b');
    const a = await prepare(),
      b = await prepare('user-b'),
      pending = await prepare();
    expect((await complete(a)).status).toBe(200);
    expect((await complete(b, credential(b), 'user-b')).status).toBe(200);
    for (const id of [b.enrollment_id, pending.enrollment_id, createResourceId('operation')]) {
      const response = await read(id);
      expect(response.status).toBe(404);
      expect(await response.json()).toEqual({ error_code: 'NOT_FOUND' });
    }
  });
  it('does not create a profile or enrollment on read', async () => {
    expect((await read(createResourceId('operation'))).status).toBe(409);
    expect(await env.WALLET_DB.prepare('SELECT count(*) AS n FROM users').first('n')).toBe(0);
    expect(await count()).toBe(0);
  });
  it('rechecks revocation after loading the credential', async () => {
    const owner = await session(),
      attempt = await prepare();
    expect((await complete(attempt)).status).toBe(200);
    const original = WalletRepository.prototype.getSession;
    let calls = 0;
    vi.spyOn(WalletRepository.prototype, 'getSession').mockImplementation(async function (
      this: WalletRepository,
    ) {
      if (++calls === 2)
        await env.WALLET_DB.prepare('UPDATE users SET disabled_at = 1 WHERE id = ?')
          .bind(owner.user_id)
          .run();
      return original.call(this);
    });
    expect((await read(attempt.enrollment_id)).status).toBe(401);
    expect(calls).toBe(2);
  });
  it.each([
    ['credential_id', 'Zg=='],
    ['credential_id', 'Zh'],
    ['credential_id', 'x'.repeat(1366)],
    ['public_key', `0x${'00'.repeat(128)}`],
    ['rp_id', 'other.test'],
    ['origin', 'https://other.test'],
  ] as const)(
    'rejects corrupted %s rather than exporting unusable material',
    async (column, value) => {
      await session();
      const attempt = await prepare();
      expect((await complete(attempt)).status).toBe(200);
      await env.WALLET_DB.prepare(`UPDATE webauthn_credentials SET ${column} = ? WHERE id = ?`)
        .bind(value, attempt.enrollment_id)
        .run();
      const response = await read(attempt.enrollment_id);
      expect(response.status).toBe(503);
      expect(await response.json()).toEqual({ error_code: 'WALLET_DATA_INVALID' });
    },
  );
  it('limits transport to authenticated GET and exact canonical references', async () => {
    await session();
    const attempt = await prepare();
    expect((await complete(attempt)).status).toBe(200);
    const request = await input(path(attempt.enrollment_id), {}, 'test-user-a', 'GET');
    for (const key of ['Content-Type', ...Object.keys(clientMutationHeaders('production'))])
      request.headers.delete(key);
    expect((await run(request)).status).toBe(200);
    request.headers.delete('Authorization');
    expect((await run(request)).status).toBe(401);
    for (const suffix of ['?uid=user-b', '/', '/complete', '%20']) {
      expect(
        (
          await run(
            await input(`${path(attempt.enrollment_id)}${suffix}`, {}, 'test-user-a', 'GET'),
          )
        ).status,
      ).toBe(404);
    }
    expect((await run(await input(path(attempt.enrollment_id)))).status).toBe(405);
    const options = await input(path(attempt.enrollment_id), {}, 'test-user-a', 'OPTIONS');
    options.headers.set('Access-Control-Request-Method', 'GET');
    options.headers.set('Access-Control-Request-Headers', 'authorization');
    expect((await run(options)).headers.get('Access-Control-Allow-Methods')).toBe('GET');
    options.headers.set('Origin', 'https://other.test');
    expect((await run(options)).status).toBe(403);
  });
});

describe('V3 passkey enrollment: identity is not monetary authority', () => {
  it('mounts the endpoint but actual unprovisioned configuration remains closed', async () => {
    expect((await exports.default.fetch(await input())).status).toBe(503);
    expect(await count()).toBe(0);
  });
  it('requires a prior session; a GET never prepares or creates anything', async () => {
    expect((await run(await input())).status).toBe(409);
    expect((await run(await input(ROOT, {}, 'test-user-a', 'GET'))).status).toBe(405);
    expect(
      await env.WALLET_DB.prepare('SELECT count(*) AS n FROM webauthn_enrollments').first('n'),
    ).toBe(0);
  });
  it('prepares idempotently with two distinct random challenges and no credential/account', async () => {
    await session();
    const id = createResourceId('operation');
    const requests = await Promise.all(Array.from({ length: 8 }, () => prepare('test-user-a', id)));
    expect(requests.every((value) => JSON.stringify(value) === JSON.stringify(requests[0]))).toBe(
      true,
    );
    const a = requests[0],
      b = await prepare();
    expect(a.options.challenge).not.toBe(base64url(hexToBytes(a.proof_challenge)));
    expect(a.options.challenge).not.toBe(b.options.challenge);
    expect(a.options.user.id).toBe(b.options.user.id);
    expect(JSON.stringify(a)).not.toContain('test-user-a');
    expect(await count()).toBe(0);
  });
  it('completes both real ceremonies and records public metadata, not an onchain signer', async () => {
    await session();
    const attempt = await prepare(),
      body = credential(attempt);
    const response = await complete(attempt, body);
    expect(response.status).toBe(200);
    expect(await response.json()).toEqual({
      enrollment_id: attempt.enrollment_id,
      state: 'enrolled',
      onchain_authority: false,
    });
    expect(response.headers.get('Cache-Control')).toBe('no-store');
    const stored = await env.WALLET_DB.prepare('SELECT * FROM webauthn_credentials WHERE id = ?')
      .bind(attempt.enrollment_id)
      .first();
    expect(stored).toMatchObject({
      credential_id: body.credential_id,
      rp_id: config.webauthn_rp_id,
      origin: config.web_origin,
      sign_count: 1,
      backup_eligible: 0,
      backed_up: 0,
    });
    expect(String(stored?.public_key)).toMatch(/^0x[0-9a-f]{256}$/);
    expect(await env.WALLET_DB.prepare('SELECT count(*) AS n FROM wallets').first('n')).toBe(0);
    expect(await env.WALLET_DB.prepare('SELECT count(*) AS n FROM wallets').first('n')).toBe(0);
    const next = await prepare();
    expect(next.options.excludeCredentials).toHaveLength(2);
    expect(next.options.excludeCredentials).toEqual(
      expect.arrayContaining([{ type: 'public-key', id: body.credential_id }]),
    );
  });
  it('repeated/concurrent completion is idempotent and cannot replace the winning credential', async () => {
    await session();
    const attempt = await prepare(),
      body = credential(attempt);
    const results = await Promise.all(Array.from({ length: 8 }, () => complete(attempt, body)));
    expect(results.map((result) => result.status)).toEqual(Array(8).fill(200));
    expect(await count()).toBe(1);
    expect((await complete(attempt, credential(attempt))).status).toBe(409);
    expect(await count()).toBe(1);
  });
  it('cannot attach the same proven key to another credential or user', async () => {
    await session();
    await session('user-b');
    const key = generateKey();
    const first = await prepare(),
      second = await prepare('user-b');
    expect((await complete(first, credential(first, { key }))).status).toBe(200);
    expect((await complete(second, credential(second, { key }), 'user-b')).status).toBe(409);
    expect(await count()).toBe(1);
  });
  it('a public key without possession never reserves that key for an attacker', async () => {
    await session();
    await session('user-b');
    const key = generateKey();
    const first = await prepare(),
      second = await prepare('user-b');
    expect(
      (await complete(first, credential(first, { key, proofKey: generateKey() }))).status,
    ).toBe(400);
    expect((await complete(second, credential(second, { key }), 'user-b')).status).toBe(200);
    expect(await count()).toBe(1);
  });
  it('rejects a foreign operation before verification; no cross-user challenge or key leak', async () => {
    await session();
    await session('user-b');
    const attempt = await prepare();
    expect((await complete(attempt, credential(attempt), 'user-b')).status).toBe(404);
    expect(await count()).toBe(0);
  });
  it('expires on the exact boundary, without resetting the deadline on retry', async () => {
    await session();
    const attempt = await prepare(),
      body = credential(attempt);
    const clock = vi.spyOn(Date, 'now').mockReturnValue(attempt.expires_at * 1000);
    try {
      expect((await complete(attempt, body)).status).toBe(410);
      expect((await run(await input(ROOT, { request_id: attempt.enrollment_id }))).status).toBe(
        410,
      );
    } finally {
      clock.mockRestore();
    }
    expect(await count()).toBe(0);
  });
  it('rejects a disabled/revoked session after preparation', async () => {
    const owner = await session();
    const attempt = await prepare();
    await env.WALLET_DB.prepare('UPDATE users SET auth_not_before = ? WHERE id = ?')
      .bind(Math.floor(Date.now() / 1000) + 1, owner.user_id)
      .run();
    expect((await complete(attempt)).status).toBe(401);
    expect(await count()).toBe(0);
  });
  it('rolls back the credential insert if marking the operation fails', async () => {
    await session();
    const attempt = await prepare(),
      body = credential(attempt);
    await env.WALLET_DB.exec(
      `CREATE TRIGGER reject_enrollment_completion BEFORE UPDATE ON webauthn_enrollments BEGIN SELECT RAISE(ABORT, 'synthetic failure'); END;`,
    );
    try {
      expect((await complete(attempt, body)).status).toBe(503);
      expect(await count()).toBe(0);
    } finally {
      await env.WALLET_DB.exec('DROP TRIGGER reject_enrollment_completion');
    }
    expect((await complete(attempt, body)).status).toBe(200);
  });
  it('limits concurrent preparation per user, not globally', async () => {
    await session();
    await session('user-b');
    const results = await Promise.all(Array.from({ length: 12 }, async () => run(await input())));
    expect(results.filter((result) => result.status === 200)).toHaveLength(6);
    expect(results.filter((result) => result.status === 429)).toHaveLength(6);
    expect((await prepare('user-b')).state).toBe('prepared');
  });
  it.each([
    { createChallenge: base64url(new Uint8Array(32)) },
    { proofChallenge: base64url(new Uint8Array(32)) },
    { createOrigin: 'https://evil.test' },
    { proofOrigin: 'https://evil.test' },
    { rp: 'evil.test' },
    { createFlags: 0x41 },
    { proofFlags: 1 },
    { proofFlags: 0x15 },
    { crossOrigin: true },
    { createFlags: 0x4d, proofFlags: 5 },
    { createCount: 2, proofCount: 1 },
    { alg: -257 },
    { fmt: 'packed' },
  ])('rejects mismatched/unsupported registration or proof (%j)', async (options) => {
    await session();
    const attempt = await prepare();
    expect((await complete(attempt, credential(attempt, options))).status).toBe(400);
    expect(await count()).toBe(0);
  });
  it('accepts synced credentials with zero counters; no unverified claim about vendor or independent backup', async () => {
    await session();
    const attempt = await prepare();
    expect(
      (
        await complete(
          attempt,
          credential(attempt, { createFlags: 0x5d, proofFlags: 0x1d, proofCount: 0 }),
        )
      ).status,
    ).toBe(200);
    expect(
      await env.WALLET_DB.prepare(
        'SELECT backup_eligible,backed_up,sign_count FROM webauthn_credentials WHERE id = ?',
      )
        .bind(attempt.enrollment_id)
        .first(),
    ).toEqual({ backup_eligible: 1, backed_up: 1, sign_count: 0 });
  });
  it('rejects raw-ID substitution, malformed wire data and oversized input', async () => {
    await session();
    const attempt = await prepare(),
      valid = credential(attempt);
    for (const body of [
      { ...valid, credential_id: base64url(new Uint8Array(32)) },
      { ...valid, origin: config.web_origin },
      { ...valid, attestation: '!!!!' },
      { ...valid, transports: ['internal', 'internal'] },
      { ...valid, proof: {} },
    ]) {
      expect((await complete(attempt, body)).status).toBe(400);
    }
    expect((await complete(attempt, { ...valid, attestation: 'a'.repeat(25000) })).status).toBe(
      413,
    );
    expect(await count()).toBe(0);
  });
  it('requires exact API/origin, bearer auth and a compatible client; cookie auth is rejected', async () => {
    await session();
    for (const [header, value, status] of [
      ['Origin', 'https://evil.test', 403],
      ['Authorization', 'Bearer invalid', 401],
      ['Cookie', 'session=x', 401],
      ['X-GatoPago-Client-Release', 'old', 409],
    ] as const) {
      const request = await input();
      request.headers.set(header, value);
      expect((await run(request)).status).toBe(status);
    }
    const request = await input();
    expect(
      (
        await run(
          new Request(request.url.replace('api.gatopago.com', 'wrong.gatopago.com'), request),
        )
      ).status,
    ).toBe(403);
  });
  it('CORS is limited to the explicit POST transport; query parameters cannot choose the RP', async () => {
    const request = await input(ROOT, {}, 'test-user-a', 'OPTIONS');
    request.headers.set('Access-Control-Request-Method', 'POST');
    request.headers.set('Access-Control-Request-Headers', 'authorization,content-type');
    expect((await run(request)).status).toBe(200);
    request.headers.set('Access-Control-Request-Headers', 'x-custom-rp');
    expect((await run(request)).status).toBe(403);
    expect((await run(await input(`${ROOT}?rpId=evil.test`))).status).toBe(404);
  });
});
