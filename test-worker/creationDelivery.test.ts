import { env } from 'cloudflare:workers';
import { applyD1Migrations } from 'cloudflare:test';
import { afterEach, beforeAll, beforeEach, describe, expect, it, vi } from 'vitest';
import { CreationDeliveryRepository } from '../src/creation/creationDelivery';
import { CreationOperationRepository } from '../src/creation/creationOperation';
import { fixtureHash } from '@gatopago/test-fixtures/v3-inspection';
import { initializationFixture } from '@gatopago/test-fixtures/v3-initialization';
import {
  cleanCreationDelivery,
  deliveryIdentity,
  deliveryNow,
  deliveryOutbox,
  seedCreationDelivery,
} from './creationDelivery.fixture';

type Fixture = Awaited<ReturnType<typeof seedCreationDelivery>>;
const repository = (f: Fixture) => new CreationDeliveryRepository(env.WALLET_DB, f.configuration);
const at = (time: number) => vi.spyOn(Date, 'now').mockReturnValue(time * 1000);
async function claim(f: Fixture) {
  const result = await repository(f).claim(f.id);
  if (!result) throw new Error('Expected a delivery lease');
  return result;
}
beforeAll(async () => {
  await applyD1Migrations(env.WALLET_DB, env.V3_TEST_MIGRATIONS);
});
beforeEach(async () => {
  at(deliveryNow());
  await cleanCreationDelivery();
});
afterEach(async () => {
  vi.restoreAllMocks();
  await cleanCreationDelivery();
});

describe('durable first-operation dispatch leases in actual D1', () => {
  it('eight competing workers obtain one lease and one send marker', async () => {
    const f = await seedCreationDelivery(),
      fetch = vi.spyOn(globalThis, 'fetch');
    const claims = await Promise.all(Array.from({ length: 8 }, () => repository(f).claim(f.id)));
    const winners = claims.filter((value) => value !== null);
    expect(winners).toHaveLength(1);
    const results = await Promise.all(
      Array.from({ length: 8 }, () => repository(f).beginSend(winners[0])),
    );
    expect(results.filter(Boolean)).toHaveLength(1);
    expect(await deliveryOutbox(f.id)).toMatchObject({ state: 'sending', attempt_count: 1 });
    expect(fetch).not.toHaveBeenCalled();
  });
  it('reclaims only a lease that expired before the send boundary; old owners cannot mutate it', async () => {
    const f = await seedCreationDelivery(),
      first = await claim(f);
    at(first.until);
    const second = await claim(f);
    expect(second.token).not.toBe(first.token);
    expect(await repository(f).beginSend(first)).toBe(false);
    expect(await repository(f).retryBeforeSend(first)).toBe(false);
    expect(await repository(f).uncertain(first)).toBe(false);
    expect(await repository(f).accepted(first, f.signed.userOpHash)).toBe(false);
    expect(await repository(f).beginSend(second)).toBe(true);
    expect(await deliveryOutbox(f.id)).toMatchObject({
      state: 'sending',
      attempt_count: 2,
      lease_token: second.token,
    });
  });
  it('recovers an expired sending lease as uncertain and never automatically resends it', async () => {
    const f = await seedCreationDelivery(),
      first = await claim(f);
    await repository(f).beginSend(first);
    at(first.until);
    expect(await repository(f).due()).toEqual([f.id]);
    expect(await repository(f).claim(f.id)).toBeNull();
    expect(await deliveryOutbox(f.id)).toMatchObject({
      state: 'uncertain',
      lease_token: null,
      lease_expires_at: null,
    });
    expect(await repository(f).retryBeforeSend(first)).toBe(false);
    expect(await repository(f).accepted(first, f.signed.userOpHash)).toBe(false);
    at(f.initial.input.validUntil + 1);
    expect(await repository(f).claim(f.id)).toBeNull();
    expect(await repository(f).due()).toEqual([]);
    expect((await deliveryOutbox(f.id))?.state).toBe('uncertain');
  });
  it('expires an unsent operation without manufacturing a send or active account', async () => {
    const f = await seedCreationDelivery();
    at(f.initial.input.validUntil);
    expect(await repository(f).claim(f.id)).toBeNull();
    expect(await deliveryOutbox(f.id)).toMatchObject({
      state: 'expired',
      attempt_count: 0,
      send_started_at: null,
    });
    expect(await repository(f).due()).toEqual([]);
    const freshSession = { ...f.principal, expiresAt: deliveryNow() + 3600 };
    const refreshed = new CreationOperationRepository(
      env.WALLET_DB,
      freshSession,
      f.configuration.scope,
      f.configuration.profiles,
    );
    expect(await refreshed.read(f.id)).toMatchObject({
      delivery_state: 'expired',
      authorization_expired: true,
      deployment_assessment: 'not_assessed',
      receive_enabled: false,
      spend_enabled: false,
    });
  });
  it('records exact provider acceptance, not inclusion, backup or permission to spend', async () => {
    const f = await seedCreationDelivery(),
      lease = await claim(f);
    await repository(f).beginSend(lease);
    expect(await repository(f).accepted(lease, f.signed.userOpHash)).toBe(true);
    expect(await repository(f).accepted(lease, f.signed.userOpHash)).toBe(false);
    expect(await repository(f).uncertain(lease)).toBe(false);
    expect(await f.operations.read(f.id)).toMatchObject({
      delivery_state: 'accepted',
      deployment_assessment: 'not_assessed',
      receive_enabled: false,
      spend_enabled: false,
    });
    expect(
      await env.WALLET_DB.prepare('SELECT count(*) AS n FROM wallet_accounts').first('n'),
    ).toBe(0);
    at(f.initial.input.validUntil + 1);
    expect(await repository(f).claim(f.id)).toBeNull();
    expect((await deliveryOutbox(f.id))?.state).toBe('accepted');
  });
  it('rejects a different returned hash and quarantines a late matching response', async () => {
    const f = await seedCreationDelivery(),
      lease = await claim(f);
    await repository(f).beginSend(lease);
    await expect(repository(f).accepted(lease, fixtureHash('9'))).rejects.toMatchObject({
      code: 'PROVIDER_HASH_MISMATCH',
    });
    at(lease.until);
    expect(await repository(f).accepted(lease, f.signed.userOpHash)).toBe(false);
    expect(await repository(f).uncertain(lease)).toBe(true);
    expect((await deliveryOutbox(f.id))?.state).toBe('uncertain');
  });
  it('retries only before send with bounded backoff and without changing any signed byte', async () => {
    const f = await seedCreationDelivery(),
      lease = await claim(f),
      original = f.signed;
    expect(await repository(f).retryBeforeSend(lease)).toBe(true);
    expect(await deliveryOutbox(f.id)).toMatchObject({
      state: 'pending',
      next_attempt_at: deliveryNow() + 2,
      attempt_count: 1,
      lease_token: null,
    });
    expect(await repository(f).claim(f.id)).toBeNull();
    expect(await repository(f).due()).toEqual([]);
    at(deliveryNow() + 2);
    const second = await claim(f);
    expect(second.record.signed).toEqual(original);
    await repository(f).beginSend(second);
    expect(await repository(f).retryBeforeSend(second)).toBe(false);
    expect((await deliveryOutbox(f.id))?.state).toBe('sending');
  });
  it('caps unsuccessful delivery attempts and later expires them without starving the sweep', async () => {
    const f = await seedCreationDelivery();
    await env.WALLET_DB.prepare(
      'UPDATE account_creation_outbox SET attempt_count = 31 WHERE initialization_id = ?',
    )
      .bind(f.id)
      .run();
    const last = await claim(f);
    await repository(f).retryBeforeSend(last);
    expect((await deliveryOutbox(f.id))?.next_attempt_at).toBe(deliveryNow() + 30);
    at(deliveryNow() + 31);
    expect(await repository(f).claim(f.id)).toBeNull();
    expect(await repository(f).due()).toEqual([]);
    at(f.initial.input.validUntil);
    expect(await repository(f).due()).toEqual([f.id]);
    await repository(f).claim(f.id);
    expect((await deliveryOutbox(f.id))?.state).toBe('expired');
  });
  it('uses the stored operation grant after login-token expiry, without extending its monetary expiry', async () => {
    const principal = deliveryIdentity(),
      f = await seedCreationDelivery(principal);
    at(principal.expiresAt + 1);
    await expect(f.operations.read(f.id)).rejects.toMatchObject({ code: 'UNAUTHENTICATED' });
    const lease = await claim(f);
    expect(lease.record.authTime).toBe(principal.authTime);
    expect(lease.record.signed).toEqual(f.signed);
    expect(await repository(f).beginSend(lease)).toBe(true);
  });
  it.each(['disabled', 'cutoff', 'environment'] as const)(
    'rejects a %s grant before acquiring a lease',
    async (change) => {
      const f = await seedCreationDelivery();
      if (change === 'disabled')
        await env.WALLET_DB.prepare('UPDATE users SET disabled_at = ? WHERE id = ?')
          .bind(deliveryNow(), f.session.user_id)
          .run();
      if (change === 'cutoff')
        await env.WALLET_DB.prepare('UPDATE users SET auth_not_before = ? WHERE id = ?')
          .bind(f.principal.authTime + 1, f.session.user_id)
          .run();
      if (change === 'environment') {
        expect(
          () =>
            new CreationDeliveryRepository(env.WALLET_DB, {
              ...f.configuration,
              environment: 'unsupported' as never,
            }),
        ).toThrow();
        return;
      }
      const r = repository(f);
      await expect(r.claim(f.id)).rejects.toMatchObject({ code: 'CREATION_GRANT_REVOKED' });
      expect(await deliveryOutbox(f.id)).toMatchObject({
        state: 'pending',
        attempt_count: 0,
        lease_token: null,
      });
    },
  );
  it.each(['disabled', 'cutoff', 'key', 'proof', 'gas'] as const)(
    'rechecks %s between acquiring a lease and crossing the send boundary',
    async (change) => {
      const f = await seedCreationDelivery(),
        lease = await claim(f);
      if (change === 'disabled')
        await env.WALLET_DB.prepare('UPDATE users SET disabled_at = ? WHERE id = ?')
          .bind(deliveryNow(), f.session.user_id)
          .run();
      if (change === 'cutoff')
        await env.WALLET_DB.prepare('UPDATE users SET auth_not_before = ? WHERE id = ?')
          .bind(f.principal.authTime + 1, f.session.user_id)
          .run();
      if (change === 'key')
        await env.WALLET_DB.prepare('UPDATE webauthn_credentials SET public_key = ? WHERE id = ?')
          .bind(initializationFixture().input.publicKey, f.credentialRef)
          .run();
      if (change === 'proof')
        await env.WALLET_DB.prepare(
          `UPDATE account_initializations SET assertion_body = '{}' WHERE id = ?`,
        )
          .bind(f.id)
          .run();
      if (change === 'gas')
        await env.WALLET_DB.prepare(
          `UPDATE account_creation_operations SET gas_terms_json = '{}' WHERE initialization_id = ?`,
        )
          .bind(f.id)
          .run();
      expect(await repository(f).beginSend(lease)).toBe(false);
      expect((await deliveryOutbox(f.id))?.send_started_at).toBeNull();
    },
  );
  it('fails closed on missing profile or corrupted proof during restoration', async () => {
    const f = await seedCreationDelivery();
    await expect(
      new CreationDeliveryRepository(env.WALLET_DB, { ...f.configuration, profiles: [] }).claim(
        f.id,
      ),
    ).rejects.toMatchObject({ code: 'PROFILE_UNAVAILABLE' });
    await env.WALLET_DB.prepare(
      `UPDATE account_creation_operations SET assertion_body = '{}' WHERE initialization_id = ?`,
    )
      .bind(f.id)
      .run();
    await expect(repository(f).claim(f.id)).rejects.toMatchObject({ code: 'WALLET_DATA_INVALID' });
    expect((await deliveryOutbox(f.id))?.attempt_count).toBe(0);
  });
  it('sweeps production grants across users, with bounded identifiers and no proof/JWT payload', async () => {
    const f = await seedCreationDelivery(),
      other = await seedCreationDelivery(deliveryIdentity('other'));
    const ids = [f.id, other.id].sort();
    expect(await repository(f).due(1)).toEqual(ids.slice(0, 1));
    expect(await repository(other).due()).toEqual(ids);
    for (const limit of [0, 51, 1.5, NaN]) await expect(repository(f).due(limit)).rejects.toThrow();
  });
  it('does not acknowledge a SQL failure while recovering an ambiguous send', async () => {
    const f = await seedCreationDelivery(),
      lease = await claim(f);
    await repository(f).beginSend(lease);
    at(lease.until);
    await env.WALLET_DB.prepare(
      `CREATE TRIGGER delivery_fail_transition BEFORE UPDATE ON account_creation_outbox
			BEGIN SELECT RAISE(ABORT, 'synthetic transition failure'); END`,
    ).run();
    await expect(repository(f).claim(f.id)).rejects.toThrow();
    expect((await deliveryOutbox(f.id))?.state).toBe('sending');
    await env.WALLET_DB.exec('DROP TRIGGER delivery_fail_transition;');
    await repository(f).claim(f.id);
    expect((await deliveryOutbox(f.id))?.state).toBe('uncertain');
  });
});
