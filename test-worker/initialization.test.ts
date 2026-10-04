import { testPrincipal } from './principal.fixture';
import { seedUser } from './user.fixture';
import { env } from 'cloudflare:workers';
import { applyD1Migrations } from 'cloudflare:test';
import { afterEach, beforeAll, beforeEach, describe, expect, it, vi } from 'vitest';
import { createResourceId } from '@gatopago/shared/v3/primitives';
import { prepareInitialization } from '@gatopago/shared/v3/initialization';
import type { Principal } from '../src/auth/principal';
import { InitializationRepository } from '../src/creation/initialization';
import { initializationFixture } from '@gatopago/test-fixtures/v3-initialization';
import { fixtureHash } from '@gatopago/test-fixtures/v3-inspection';

let f: ReturnType<typeof initializationFixture>;
const now = () => Math.floor(Date.now() / 1000);
const identity = (subject = 'user-a'): Principal => testPrincipal(subject);
const repository = (principal = identity(), pins = [f.pin]) =>
  new InitializationRepository(env.WALLET_DB, principal, f.input.scope, pins);
const request = (credentialRef: ReturnType<typeof createResourceId<'operation'>>) => ({
  id: createResourceId('operation'),
  credentialRef,
  profileDigest: f.pin.digest,
  userSaltCommitment: f.input.userSaltCommitment,
});
async function enroll(principal = identity(), key = f.input.publicKey) {
  const session = await seedUser(env.WALLET_DB, principal);
  const id = createResourceId('operation');
  // Seed only prior enrollment for these repository tests. Signatures below are real ephemeral
  // P-256/WebAuthn; enrollment's CBOR/create+get/JWT path is independently tested in enrollment.test.ts.
  await env.WALLET_DB.prepare(
    `INSERT INTO webauthn_credentials
		(id,user_id,rp_id,origin,credential_id,public_key,transports_json,aaguid,backup_eligible,backed_up,sign_count,response_hash,created_at)
		VALUES (?,?,?,?,?,?,'["internal"]','00000000-0000-0000-0000-000000000000',0,0,1,?,?)`,
  )
    .bind(
      id,
      session.user_id,
      f.input.scope.rpId,
      f.input.scope.origin,
      id.replaceAll('-', ''),
      key,
      fixtureHash('1'),
      now(),
    )
    .run();
  return { id, ...session };
}
const count = () =>
  env.WALLET_DB.prepare('SELECT count(*) AS n FROM account_initializations').first<number>('n');
const stored = (id: string) =>
  env.WALLET_DB.prepare('SELECT * FROM account_initializations WHERE id = ?').bind(id).first();
beforeAll(async () => {
  await applyD1Migrations(env.WALLET_DB, env.V3_TEST_MIGRATIONS);
});
beforeEach(async () => {
  f = initializationFixture();
  await env.WALLET_DB
    .exec(`DELETE FROM account_initializations; DELETE FROM webauthn_credentials; DELETE FROM webauthn_enrollments;
		DELETE FROM wallet_accounts; DELETE FROM wallets; DELETE FROM users;`);
});
afterEach(async () => {
  vi.restoreAllMocks();
  await env.WALLET_DB.exec('DELETE FROM account_initializations;');
});

describe('D1 durable initialization authorization, not account backup', () => {
  it('has no I/O or writes on construction; no admitted profiles means no preparation', async () => {
    const fetchMock = vi.spyOn(globalThis, 'fetch');
    const r = repository(identity(), []);
    expect(await count()).toBe(0);
    await expect(r.prepare(request(createResourceId('operation')))).rejects.toMatchObject({
      code: 'PROFILE_UNAVAILABLE',
    });
    expect(fetchMock).not.toHaveBeenCalled();
    expect(await count()).toBe(0);
  });
  it('requires an enrolled key owned by the authenticated identity, not a body-supplied key', async () => {
    const own = await enroll();
    await enroll(identity('b'), initializationFixture().input.publicKey);
    await expect(repository(identity('b')).prepare(request(own.id))).rejects.toMatchObject({
      code: 'NOT_FOUND',
    });
    await expect(
      repository().prepare(request(createResourceId('operation'))),
    ).rejects.toMatchObject({ code: 'NOT_FOUND' });
    expect(await count()).toBe(0);
  });
  it('prepares concurrent retries once and never silently changes the initial digest', async () => {
    const key = await enroll(),
      input = request(key.id);
    const result = await Promise.all(Array.from({ length: 8 }, () => repository().prepare(input)));
    expect(result.every((value) => JSON.stringify(value) === JSON.stringify(result[0]))).toBe(true);
    expect(result[0]).toMatchObject({
      state: 'prepared',
      account_deployed: false,
      receive_enabled: false,
      spend_enabled: false,
    });
    expect(result[0].input.publicKey).toBe(f.input.publicKey);
    expect(result[0].approval_digest).toBe(prepareInitialization(result[0].input).digest);
    expect(await count()).toBe(1);
  });
  it('will not reuse an idempotency key for another salt or credential', async () => {
    const key = await enroll(),
      second = await enroll(identity(), initializationFixture().input.publicKey),
      input = request(key.id);
    await repository().prepare(input);
    for (const changed of [
      { ...input, userSaltCommitment: fixtureHash('e') },
      { ...input, credentialRef: second.id },
    ]) {
      await expect(repository().prepare(changed)).rejects.toMatchObject({
        code: 'INITIALIZATION_CONFLICT',
      });
    }
    expect(await count()).toBe(1);
  });
  it('records real typed possession with CAS, not a deployed wallet or a transaction', async () => {
    const key = await enroll(),
      input = request(key.id),
      r = repository(),
      prepared = await r.prepare(input);
    const proof = f.assertion(prepared.approval_digest);
    const results = await Promise.all(
      Array.from({ length: 8 }, () => repository().authorize(input.id, proof)),
    );
    expect(
      results.every(
        (value) =>
          value.state === 'authorized' &&
          !value.account_deployed &&
          !value.spend_enabled &&
          !value.receive_enabled,
      ),
    ).toBe(true);
    expect((await stored(input.id))?.assertion_signature).toMatch(/^0x[0-9a-f]+$/);
    expect(await env.WALLET_DB.prepare('SELECT count(*) AS n FROM wallets').first('n')).toBe(0);
    expect(
      await env.WALLET_DB.prepare('SELECT count(*) AS n FROM wallet_accounts').first('n'),
    ).toBe(0);
    expect(await r.prepare(input)).toMatchObject({ state: 'authorized' });
  });
  it('another valid assertion cannot replace the first committed approval', async () => {
    const key = await enroll(),
      input = request(key.id),
      r = repository(),
      p = await r.prepare(input);
    await r.authorize(input.id, f.assertion(p.approval_digest));
    const before = await stored(input.id);
    await expect(
      r.authorize(input.id, f.assertion(p.approval_digest, { count: 3 })),
    ).rejects.toMatchObject({ code: 'INITIALIZATION_CONFLICT' });
    expect(await stored(input.id)).toEqual(before);
  });
  it('proof for another user, another key, or the registration challenge never commits', async () => {
    const key = await enroll(),
      input = request(key.id),
      r = repository(),
      p = await r.prepare(input);
    await enroll(identity('b'), initializationFixture().input.publicKey);
    await expect(
      repository(identity('b')).authorize(input.id, f.assertion(p.approval_digest)),
    ).rejects.toMatchObject({ code: 'NOT_FOUND' });
    for (const proof of [
      initializationFixture().assertion(p.approval_digest),
      f.assertion(fixtureHash('a')),
      f.assertion(p.approval_digest, { flags: 1 }),
    ])
      await expect(r.authorize(input.id, proof)).rejects.toThrow();
    expect((await stored(input.id))?.authorized_at).toBeNull();
  });
  it('disabled identity cannot authorize or read/reuse a pending approval', async () => {
    const key = await enroll(),
      input = request(key.id),
      r = repository(),
      p = await r.prepare(input);
    await env.WALLET_DB.prepare('UPDATE users SET disabled_at = ? WHERE id = ?')
      .bind(now(), key.user_id)
      .run();
    await expect(r.authorize(input.id, f.assertion(p.approval_digest))).rejects.toMatchObject({
      code: 'UNAUTHENTICATED',
    });
    await expect(r.prepare(input)).rejects.toMatchObject({ code: 'UNAUTHENTICATED' });
    expect((await stored(input.id))?.authorized_at).toBeNull();
  });
  it('expired login and auth-not-before cutoff do not become passkey authority', async () => {
    const principal = identity(),
      key = await enroll(principal),
      input = request(key.id),
      p = await repository(principal).prepare(input);
    await expect(
      repository({ ...principal, expiresAt: now() }).authorize(
        input.id,
        f.assertion(p.approval_digest),
      ),
    ).rejects.toMatchObject({ code: 'UNAUTHENTICATED' });
    await env.WALLET_DB.prepare('UPDATE users SET auth_not_before = ? WHERE id = ?')
      .bind(principal.authTime + 1, key.user_id)
      .run();
    await expect(
      repository(principal).authorize(input.id, f.assertion(p.approval_digest)),
    ).rejects.toMatchObject({ code: 'UNAUTHENTICATED' });
  });
  it('rejects stored content corruption and changed enrolled keys', async () => {
    const key = await enroll(),
      input = request(key.id),
      r = repository(),
      p = await r.prepare(input);
    await env.WALLET_DB.prepare(
      'UPDATE account_initializations SET expected_address = ? WHERE id = ?',
    )
      .bind('0x1111111111111111111111111111111111111111', input.id)
      .run();
    await expect(r.authorize(input.id, f.assertion(p.approval_digest))).rejects.toMatchObject({
      code: 'WALLET_DATA_INVALID',
    });
    const second = request(key.id),
      p2 = await r.prepare(second);
    await env.WALLET_DB.prepare('UPDATE webauthn_credentials SET public_key = ? WHERE id = ?')
      .bind(initializationFixture().input.publicKey, key.id)
      .run();
    await expect(r.authorize(second.id, f.assertion(p2.approval_digest))).rejects.toMatchObject({
      code: 'WALLET_DATA_INVALID',
    });
  });
  it('bounds starts per owner without a global account or link lock', async () => {
    const key = await enroll(),
      r = repository();
    for (let i = 0; i < 6; i++) await r.prepare(request(key.id));
    await expect(r.prepare(request(key.id))).rejects.toMatchObject({
      code: 'INITIALIZATION_LIMIT',
    });
    const other = await enroll(identity('b'), initializationFixture().input.publicKey);
    expect(await repository(identity('b')).prepare(request(other.id))).toMatchObject({
      state: 'prepared',
    });
  });
  it('pending expiry cannot be extended by retry; accepted replay does not reauthorize', async () => {
    const key = await enroll(),
      pending = request(key.id),
      accepted = request(key.id),
      r = repository();
    const p = await r.prepare(pending),
      a = await r.prepare(accepted),
      proof = f.assertion(a.approval_digest);
    await r.authorize(accepted.id, proof);
    const before = await stored(accepted.id);
    vi.spyOn(Date, 'now').mockReturnValue((p.input.validUntil + 1) * 1000);
    await expect(r.prepare(pending)).rejects.toMatchObject({ code: 'INITIALIZATION_EXPIRED' });
    await expect(r.authorize(pending.id, f.assertion(p.approval_digest))).rejects.toMatchObject({
      code: 'INITIALIZATION_EXPIRED',
    });
    expect(await r.authorize(accepted.id, proof)).toMatchObject({
      state: 'authorized',
      account_deployed: false,
    });
    expect(await stored(accepted.id)).toEqual(before);
  });
  it('detaches mutable request/identity/profile inputs before any asynchronous ownership work', async () => {
    const principal = identity(),
      key = await enroll(principal),
      input = request(key.id),
      pin = { ...f.pin },
      pins = [pin];
    const r = repository(principal, pins),
      expectedSalt = input.userSaltCommitment;
    const work = r.prepare(input);
    input.userSaltCommitment = fixtureHash('e');
    pin.document = '{}';
    pins.length = 0;
    expect((await work).input.userSaltCommitment).toBe(expectedSalt);
  });
});
