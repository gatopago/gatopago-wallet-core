import { seedUser } from './user.fixture';
import { env } from 'cloudflare:workers';
import { applyD1Migrations } from 'cloudflare:test';
import { afterEach, beforeAll, beforeEach, describe, expect, it, vi } from 'vitest';
import { createResourceId } from '@gatopago/shared/v3/primitives';
import { processCreationObservation } from '../src/creation/processCreationObservation';
import { WalletRepository } from '../src/accounts/repository';
import { fixtureHash } from '@gatopago/test-fixtures/v3-inspection';
import { cleanCreationDelivery, deliveryIdentity, deliveryNow } from './creationDelivery.fixture';
import { creationProjectionScenario as scenario } from './creationProjection.fixture';

beforeAll(async () => {
  await applyD1Migrations(env.WALLET_DB, env.V3_TEST_MIGRATIONS);
});
beforeEach(async () => {
  await cleanCreationDelivery();
});
afterEach(async () => {
  vi.restoreAllMocks();
  await env.WALLET_DB.exec('DROP TRIGGER IF EXISTS projection_fail_insert');
  await cleanCreationDelivery();
});
const count = async () =>
  (await env.WALLET_DB.prepare(
    `SELECT
	(SELECT count(*) FROM wallets) AS wallets, (SELECT count(*) FROM wallet_accounts) AS accounts,
	(SELECT count(*) FROM account_creation_projections) AS projections`,
  ).first())!;

describe('finalized creation → atomic bootstrap projection', () => {
  it('persists owned resources and a source-linked historical record without enabling funds', async () => {
    const f = await scenario();
    expect(await f.run()).toBe('projected');
    expect(await count()).toEqual({ wallets: 1, accounts: 1, projections: 1 });
    const repository = new WalletRepository(env.WALLET_DB, f.principal);
    const wallets = await repository.listWallets({ after: '', limit: 20 });
    const accounts = await repository.listAccounts(wallets.data[0].id, { after: '', limit: 20 });
    expect(accounts.data[0]).toMatchObject({
      deployment_state: 'active',
      receive_enabled: false,
      spend_readiness: 'not_assessed',
    });
    expect(accounts.data[0]).not.toHaveProperty('address');
    expect(await repository.ownedAccount(wallets.data[0].id, accounts.data[0].id)).toMatchObject({
      account_id: f.prepared.message.accountId,
      address: f.prepared.account.toLowerCase(),
    });
    const record = await env.WALLET_DB.prepare(
      'SELECT * FROM account_creation_projections WHERE initialization_id = ?',
    )
      .bind(f.id)
      .first();
    expect(record).toMatchObject({ source_epoch: 1 });
    expect(f.reply.mock.calls.every(([method]) => !method.startsWith('eth_send'))).toBe(true);
    expect(f.fetch).toHaveBeenCalledTimes(50);
  });
  it('is idempotent across process instances without restarting RPC on a completed projection', async () => {
    const f = await scenario();
    await f.run();
    f.fetch.mockClear();
    expect(await f.run()).toBe('already_projected');
    expect(f.fetch).not.toHaveBeenCalled();
    expect(await count()).toEqual({ wallets: 1, accounts: 1, projections: 1 });
  });
  it('keeps the economic result of a previously sent grant after login revocation', async () => {
    const f = await scenario();
    await env.WALLET_DB.prepare('UPDATE users SET disabled_at = ? WHERE id = ?')
      .bind(deliveryNow(), f.session.user_id)
      .run();
    expect(await f.run()).toBe('projected');
    await expect(
      new WalletRepository(env.WALLET_DB, f.principal).listWallets({ after: '', limit: 20 }),
    ).rejects.toMatchObject({ code: 'UNAUTHENTICATED' });
  });
  it('does not create any resource from an accepted send lacking observed evidence', async () => {
    const f = await scenario(false);
    expect(await f.run()).toBe('pending');
    expect(f.fetch).not.toHaveBeenCalled();
    expect(await count()).toEqual({ wallets: 0, accounts: 0, projections: 0 });
  });
  it('does not treat provider ordering as a different authority', async () => {
    const f = await scenario();
    f.configuration.networks[0].providers.reverse();
    expect(await f.run()).toBe('projected');
  });
  it('rejects duplicated provider identity before querying RPC', async () => {
    const f = await scenario();
    f.configuration.networks[0].providers[1].operatorId = 'provider_a';
    await expect(f.run()).rejects.toThrow('Projection observers overlap');
    expect(f.fetch).not.toHaveBeenCalled();
  });
  it.each(['spendNonce', 'adminNonce'] as const)(
    'rejects bootstrap that already changed %s',
    async (nonce) => {
      const f = await scenario();
      f.state[nonce] = 1n;
      await expect(f.run()).rejects.toThrow('CREATION_SECURITY_CHANGED');
      expect((await count()).wallets).toBe(0);
    },
  );
  it('rejects a creation window still open at the finalized checkpoint', async () => {
    const f = await scenario();
    f.state.creationAfter = BigInt(f.initial.input.validAfter);
    f.state.creationUntil = BigInt(f.initial.input.validUntil);
    await expect(f.run()).rejects.toThrow('CREATION_SECURITY_CHANGED');
    expect((await count()).projections).toBe(0);
  });
  it('does not use an expired finalized source as a fallback', async () => {
    const f = await scenario(),
      source = await f.journal.latest(f.id);
    if (source?.result.status !== 'observed' || source.result.finality === 'not_assessed')
      throw new Error('Expected finality');
    vi.spyOn(Date, 'now').mockReturnValue(source.result.finality_evidence.expires_at * 1000);
    await expect(f.run()).rejects.toThrow('SECURITY_FINALITY_UNUSABLE');
    expect(f.fetch).not.toHaveBeenCalled();
    expect((await count()).wallets).toBe(0);
  });
  it('racing projectors converge on one resource set', async () => {
    const f = await scenario();
    const results = await Promise.all(Array.from({ length: 4 }, () => f.run()));
    expect(results.filter((r) => r === 'projected')).toHaveLength(1);
    expect(results.filter((r) => r === 'already_projected')).toHaveLength(3);
    expect(await count()).toEqual({ wallets: 1, accounts: 1, projections: 1 });
  });
  it('rolls back every resource if the final evidence insert fails and can retry', async () => {
    const f = await scenario();
    await env.WALLET_DB.prepare(
      `CREATE TRIGGER projection_fail_insert BEFORE INSERT ON account_creation_projections
			BEGIN SELECT RAISE(ABORT, 'Synthetic projection interruption'); END;`,
    ).run();
    await expect(f.run()).rejects.toThrow();
    expect(await count()).toEqual({ wallets: 0, accounts: 0, projections: 0 });
    await env.WALLET_DB.exec('DROP TRIGGER projection_fail_insert');
    expect(await f.run()).toBe('projected');
  });
  it('does not replace the owner of an existing cryptographic identity', async () => {
    const f = await scenario(),
      other = await seedUser(env.WALLET_DB, deliveryIdentity('other'));
    await seedIdentity(f, other.user_id);
    await expect(f.run()).rejects.toMatchObject({ code: 'WALLET_DATA_INVALID' });
    expect((await count()).projections).toBe(0);
  });
  it('reuses the wallet and identity already registered for another chain', async () => {
    const f = await scenario(),
      ids = await seedIdentity(f, f.session.user_id);
    await env.WALLET_DB.prepare(
      `INSERT INTO wallet_accounts(id,wallet_id,network_id,address,deployment_manifest_sha256,deployment_state,created_at)
			VALUES (?,?,'eip155:421614',?,?,'active',?)`,
    )
      .bind(
        createResourceId('walletAccount'),
        ids.wallet_id,
        f.prepared.account.toLowerCase(),
        fixtureHash('d'),
        deliveryNow(),
      )
      .run();
    expect(await f.run()).toBe('projected');
    expect(await count()).toEqual({ wallets: 1, accounts: 2, projections: 1 });
    expect(
      await env.WALLET_DB.prepare(
        'SELECT wallet_id FROM account_creation_projections WHERE initialization_id = ?',
      )
        .bind(f.id)
        .first(),
    ).toEqual(ids);
  });
  it('does not publish a projection after cancellation during RPC', async () => {
    const f = await scenario(),
      abort = new AbortController(),
      original = f.reply.getMockImplementation()!;
    f.reply.mockImplementationOnce(async (...args) => {
      const result = await original(...args);
      abort.abort();
      return result;
    });
    await expect(f.run(abort.signal)).rejects.toThrow();
    expect((await count()).projections).toBe(0);
  });
  it('stops scheduling creation observations after projection instead of polling forever', async () => {
    const f = await scenario();
    await f.run();
    await env.WALLET_DB.prepare(
      'UPDATE account_creation_observation_jobs SET next_poll_at = 0 WHERE initialization_id = ?',
    )
      .bind(f.id)
      .run();
    expect(await f.journal.due()).toEqual([]);
    expect(await f.journal.claim(f.id)).toBeNull();
    f.fetch.mockClear();
    expect(
      await processCreationObservation(
        env.WALLET_DB,
        f.id,
        f.configuration,
        new AbortController().signal,
      ),
    ).toBe('idle');
    expect(f.fetch).not.toHaveBeenCalled();
  });
  it('rejects a superseded journal head atomically, leaving no orphan wallet', async () => {
    const f = await scenario(),
      original = f.reply.getMockImplementation()!;
    f.reply.mockImplementationOnce(async (...args) => {
      await env.WALLET_DB.prepare(
        'UPDATE account_creation_observation_jobs SET next_poll_at = 0 WHERE initialization_id = ?',
      )
        .bind(f.id)
        .run();
      const claim = await f.journal.claim(f.id);
      if (!claim) throw new Error('Expected new observer');
      await f.journal.append(claim, {
        status: 'not_observed',
        transaction_hash: null,
        provider_ids: ['provider_a', 'provider_b'],
        finality: 'not_assessed',
        account_readiness: 'not_assessed',
      });
      return original(...args);
    });
    expect(await f.run()).toBe('superseded');
    expect(await count()).toEqual({ wallets: 0, accounts: 0, projections: 0 });
  });
  it('waits for an already-running observer without projecting its previous head', async () => {
    const f = await scenario();
    await env.WALLET_DB.prepare(
      'UPDATE account_creation_observation_jobs SET next_poll_at = 0 WHERE initialization_id = ?',
    )
      .bind(f.id)
      .run();
    expect(await f.journal.claim(f.id)).not.toBeNull();
    expect(await f.run()).toBe('superseded');
    expect((await count()).wallets).toBe(0);
  });
  it('rechecks signed consent after RPC instead of projecting changed initialization data', async () => {
    const f = await scenario(),
      original = f.reply.getMockImplementation()!;
    f.reply.mockImplementationOnce(async (...args) => {
      await env.WALLET_DB.prepare(
        'UPDATE account_initializations SET approval_digest = ? WHERE id = ?',
      )
        .bind(fixtureHash('d'), f.id)
        .run();
      return original(...args);
    });
    await expect(f.run()).rejects.toMatchObject({ code: 'WALLET_DATA_INVALID' });
    expect((await count()).wallets).toBe(0);
  });
});

async function seedIdentity(f: Awaited<ReturnType<typeof scenario>>, userId: string) {
  const wallet = createResourceId('wallet'),
    message = f.prepared.message;
  await env.WALLET_DB.prepare(
    `INSERT INTO wallets(id,user_id,status,account_id,initial_security_commitment,user_salt_commitment,canonical_address,created_at)
		VALUES (?,?,'active',?,?,?,?,?)`,
  )
    .bind(
      wallet,
      userId,
      message.accountId,
      message.initialSecurityCommitment,
      message.userSaltCommitment,
      f.prepared.account.toLowerCase(),
      deliveryNow(),
    )
    .run();
  return { wallet_id: wallet };
}
