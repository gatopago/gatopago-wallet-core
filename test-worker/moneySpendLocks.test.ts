import { applyD1Migrations } from 'cloudflare:test';
import { env } from 'cloudflare:workers';
import { beforeAll, beforeEach, describe, expect, it } from 'vitest';
import { createResourceId } from '@gatopago/shared/v3/primitives';
import { deploymentDocumentDigest } from '@gatopago/shared/v3/deployment';
import { initializationFixture } from '@gatopago/test-fixtures/v3-initialization';
import { prepareInitialization } from '@gatopago/shared/v3/initialization';
import { seedUser } from './user.fixture';
import { testPrincipal } from './principal.fixture';

// These rows are deliberately SQL fixtures, not proof of cryptographic consent.
// The production coordinator must verify the complete signed review before insert.
beforeAll(() => applyD1Migrations(env.WALLET_DB, env.V3_TEST_MIGRATIONS));
beforeEach(async () => {
  await env.WALLET_DB
    .exec(`DELETE FROM money_reconciliations; DELETE FROM money_finality_conflicts; DELETE FROM money_finality_journal; DELETE FROM money_expirations;
    DELETE FROM money_operations; DELETE FROM money_preparations; DELETE FROM user_operation_submissions;
    DELETE FROM transfer_reconciliations; DELETE FROM wallet_balance_floors; DELETE FROM transfer_finality_conflicts;
    DELETE FROM transfer_finality_journal; DELETE FROM transfer_nonce_reservations; DELETE FROM wallet_accounts;
    DELETE FROM wallets; DELETE FROM webauthn_credentials; DELETE FROM users;`);
});
async function setup() {
  const now = Math.floor(Date.now() / 1000),
    f = initializationFixture(),
    principal = testPrincipal('money-lock-test');
  await seedUser(env.WALLET_DB, principal);
  const wallet = createResourceId('wallet'),
    account = createResourceId('walletAccount');
  const prepared = prepareInitialization(f.input);
  const address = prepared.account.toLowerCase(),
    entryPoint = f.profile.deployment.entry_point.toLowerCase(),
    hash = deploymentDocumentDigest('{}');
  await env.WALLET_DB.batch([
    env.WALLET_DB.prepare(
      `INSERT INTO wallets(id,user_id,status,account_id,initial_security_commitment,user_salt_commitment,canonical_address,created_at)
      VALUES (?,?,'active',?,?,?,?,?)`,
    ).bind(
      wallet,
      principal.userId,
      prepared.message.accountId,
      prepared.message.initialSecurityCommitment,
      prepared.message.userSaltCommitment,
      address,
      now,
    ),
    env.WALLET_DB.prepare(
      `INSERT INTO wallet_accounts(id,wallet_id,network_id,address,deployment_manifest_sha256,deployment_state,created_at)
      VALUES (?,?,'eip155:421614',?,?,'active',?)`,
    ).bind(account, wallet, address, hash, now),
  ]);
  function transfer(nonce: string) {
    const id = createResourceId('operation'),
      consent = deploymentDocumentDigest(id);
    return {
      id,
      query: env.WALLET_DB.prepare(
        `INSERT INTO transfer_nonce_reservations
      (id,wallet_id,wallet_account_id,network_id,account_address,entry_point,nonce,consent_digest,userop_hash,deployment_manifest_sha256,
        operation_json,operation_sha256,review_json,review_sha256,funds_json,funds_sha256,authorized_auth_time,state,created_at,expires_at)
      VALUES (?,?,?,'eip155:421614',?,?,?,?,?,?,'{}',?,'{}',?,'{}',?,?,'held',?,?)`,
      ).bind(
        id,
        wallet,
        account,
        address,
        entryPoint,
        nonce,
        consent,
        consent,
        hash,
        hash,
        hash,
        hash,
        principal.authTime,
        now,
        now + 30,
      ),
    };
  }
  async function money(nonce: string) {
    const preparation = createResourceId('operation'),
      id = createResourceId('operation'),
      consent = deploymentDocumentDigest(id);
    await env.WALLET_DB.prepare(
      `INSERT INTO money_preparations
      (id,wallet_id,wallet_account_id,actor_id,idempotency_key,request_sha256,consent_digest,deployment_manifest_sha256,market_sha256,
        review_json,review_sha256,authorized_auth_time,created_at,expires_at)
      VALUES (?,?,?,?,?,?,?,?,?,'{}',?,?,?,?)`,
    )
      .bind(
        preparation,
        wallet,
        account,
        principal.userId,
        preparation,
        hash,
        consent,
        hash,
        hash,
        hash,
        principal.authTime,
        now,
        now + 30,
      )
      .run();
    return {
      id,
      query: env.WALLET_DB.prepare(
        `INSERT INTO money_operations
      (id,preparation_id,wallet_id,wallet_account_id,actor_id,confirm_key,confirmation_sha256,network_id,account_address,entry_point,nonce,
        consent_digest,userop_hash,deployment_manifest_sha256,market_sha256,review_json,review_sha256,funds_json,funds_sha256,
        authorized_auth_time,state,created_at,expires_at)
      VALUES (?,?,?,?,?,?,?,'eip155:421614',?,?,?,?,?,?,?,'{}',?,'{}',?,?,'authorized',?,?)`,
      ).bind(
        id,
        preparation,
        wallet,
        account,
        principal.userId,
        id,
        hash,
        address,
        entryPoint,
        nonce,
        consent,
        consent,
        hash,
        hash,
        hash,
        hash,
        principal.authTime,
        now,
        now + 30,
      ),
    };
  }
  return { now, wallet, account, hash, transfer, money };
}
const locks = () =>
  env.WALLET_DB.prepare('SELECT * FROM wallet_spend_locks ORDER BY operation_id').all();
describe('Cross-domain spend exclusivity in real workerd/D1', () => {
  it.each(['0', '1'])(
    'admits only one winner between transfer and money with money nonce %s',
    async (nonce) => {
      const f = await setup(),
        transfer = f.transfer('0'),
        money = await f.money(nonce);
      const results = await Promise.allSettled([transfer.query.run(), money.query.run()]);
      expect(results.filter((result) => result.status === 'fulfilled')).toHaveLength(1);
      const active = (await locks()).results;
      expect(active).toHaveLength(1);
      expect(active[0].released_at).toBeNull();
      const count = await env.WALLET_DB.prepare(
        'SELECT (SELECT count(*) FROM transfer_nonce_reservations) + (SELECT count(*) FROM money_operations) AS n',
      ).first<{ n: number }>();
      expect(count?.n).toBe(1);
    },
  );
  it('blocks a second money operation even with a different nonce', async () => {
    const f = await setup(),
      a = await f.money('0'),
      b = await f.money('1');
    await a.query.run();
    await expect(b.query.run()).rejects.toThrow('ACCOUNT_SPEND_BUSY');
    expect((await locks()).results).toHaveLength(1);
  });
  it('records dispatch and job atomically and preserves uncertainty after expiry', async () => {
    const f = await setup(),
      operation = await f.money('0');
    await operation.query.run();
    await env.WALLET_DB.prepare(
      "UPDATE money_operations SET state = 'dispatch_pending',dispatch_started_at = ? WHERE id = ?",
    )
      .bind(f.now + 1, operation.id)
      .run();
    expect((await locks()).results[0]).toMatchObject({
      operation_id: operation.id,
      state: 'dispatch_pending',
      released_at: null,
    });
    expect(
      await env.WALLET_DB.prepare('SELECT state FROM money_jobs WHERE operation_id = ?')
        .bind(operation.id)
        .first(),
    ).toEqual({ state: 'ready' });
    await expect(
      env.WALLET_DB.prepare(
        "UPDATE money_operations SET state = 'expired_unsubmitted' WHERE id = ?",
      )
        .bind(operation.id)
        .run(),
    ).rejects.toThrow();
    await expect(
      env.WALLET_DB.prepare(
        "UPDATE wallet_spend_locks SET state = 'released',released_at = ?,release_reason = 'expired_unsubmitted' WHERE operation_id = ?",
      )
        .bind(f.now + 1000, operation.id)
        .run(),
    ).rejects.toThrow('spend lock release requires domain evidence');
    expect((await locks()).results[0].released_at).toBeNull();
  });
  it('does not release an authorized operation from a wall-clock timeout alone', async () => {
    const f = await setup(),
      operation = await f.money('0');
    await operation.query.run();
    await expect(
      env.WALLET_DB.prepare(
        "UPDATE money_operations SET state = 'expired_unsubmitted' WHERE id = ?",
      )
        .bind(operation.id)
        .run(),
    ).rejects.toThrow('uncertain money dispatch cannot expire');
    expect((await locks()).results[0].state).toBe('held');
  });
  it('requires a finalized checkpoint past validity and an unchanged nonce to release an unsubmitted operation', async () => {
    const f = await setup(),
      operation = await f.money('0');
    await operation.query.run();
    await env.WALLET_DB.prepare(
      `INSERT INTO money_expirations(operation_id,checkpoint_json,checkpoint_sha256,block_timestamp,observed_nonce,recorded_at)
      VALUES (?,'{}',?,?,'1',?)`,
    )
      .bind(operation.id, f.hash, f.now + 31, f.now + 32)
      .run();
    await expect(
      env.WALLET_DB.prepare(
        "UPDATE money_operations SET state = 'expired_unsubmitted' WHERE id = ?",
      )
        .bind(operation.id)
        .run(),
    ).rejects.toThrow();
    // A conflicting historical observation is retained; it is not rewritten.
    await expect(
      env.WALLET_DB.prepare(
        "UPDATE money_expirations SET observed_nonce = '0' WHERE operation_id = ?",
      )
        .bind(operation.id)
        .run(),
    ).rejects.toThrow('immutable money expiry evidence');
    expect((await locks()).results[0].released_at).toBeNull();
  });
  it('commits reconciliation, balance floor and release in one transaction', async () => {
    const f = await setup(),
      operation = await f.money('0');
    await operation.query.run();
    await env.WALLET_DB.prepare(
      "UPDATE money_operations SET state = 'dispatch_pending',dispatch_started_at = ? WHERE id = ?",
    )
      .bind(f.now + 1, operation.id)
      .run();
    await env.WALLET_DB.prepare(
      `INSERT INTO money_finality_journal(operation_id,receipt_json,receipt_sha256,finality_json,finality_sha256,block_number,block_hash,outcome,recorded_at)
      VALUES (?,'{}',?,'{}',?,'100',?,'reconciled',?)`,
    )
      .bind(operation.id, f.hash, f.hash, f.hash, f.now + 2)
      .run();
    await env.WALLET_DB.prepare(
      `INSERT INTO money_reconciliations(operation_id,wallet_account_id,receipt_sha256,block_number,block_hash,outcome,proof_json,proof_sha256,recorded_at)
      VALUES (?,?,?,'100',?,'reconciled','{}',?,?)`,
    )
      .bind(operation.id, f.account, f.hash, f.hash, f.hash, f.now + 2)
      .run();
    expect((await locks()).results[0]).toMatchObject({
      state: 'released',
      release_reason: 'reconciled',
    });
    expect(
      await env.WALLET_DB.prepare('SELECT state FROM money_operations WHERE id = ?')
        .bind(operation.id)
        .first(),
    ).toEqual({ state: 'reconciled' });
    expect(
      await env.WALLET_DB.prepare(
        'SELECT block_number,block_hash FROM wallet_balance_floors WHERE wallet_account_id = ?',
      )
        .bind(f.account)
        .first(),
    ).toEqual({ block_number: '100', block_hash: f.hash });
    await f.transfer('1').query.run();
    expect((await locks()).results).toHaveLength(2);
  });
  it('cannot release without financial reconciliation evidence', async () => {
    const f = await setup(),
      operation = await f.money('0');
    await operation.query.run();
    await env.WALLET_DB.prepare(
      "UPDATE money_operations SET state = 'dispatch_pending',dispatch_started_at = ? WHERE id = ?",
    )
      .bind(f.now + 1, operation.id)
      .run();
    await expect(
      env.WALLET_DB.prepare("UPDATE money_operations SET state = 'reconciled' WHERE id = ?")
        .bind(operation.id)
        .run(),
    ).rejects.toThrow('money reconciliation required');
    expect((await locks()).results[0].released_at).toBeNull();
  });
});
