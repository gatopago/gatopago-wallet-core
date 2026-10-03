import { applyD1Migrations } from 'cloudflare:test';
import { env } from 'cloudflare:workers';
import { afterEach, beforeAll, beforeEach, describe, expect, it, vi } from 'vitest';
import { createResourceId } from '@gatopago/shared/v3/primitives';
import { deploymentDocumentDigest } from '@gatopago/shared/v3/deployment';
import { MoneyJobRepository, parseMoneyWake } from '../src/money/moneyJobs';
import { reconcileMoneyJob } from '../src/money/moneyReconciliation';
import * as observer from '../src/money/moneyObservation';
import { seedMoneyDelivery } from './moneyDelivery.fixture';

beforeAll(() => applyD1Migrations(env.WALLET_DB, env.V3_TEST_MIGRATIONS));
beforeEach(async () => {
  await env.WALLET_DB.exec(`DELETE FROM money_reconciliations; DELETE FROM money_finality_conflicts; DELETE FROM money_finality_journal; DELETE FROM money_expirations;
    DELETE FROM money_operations; DELETE FROM money_preparations; DELETE FROM user_operation_submissions;
    DELETE FROM transfer_reconciliations; DELETE FROM wallet_balance_floors; DELETE FROM transfer_finality_conflicts;
    DELETE FROM transfer_finality_journal; DELETE FROM transfer_nonce_reservations; DELETE FROM wallet_accounts;
    DELETE FROM wallets; DELETE FROM webauthn_credentials; DELETE FROM users;`);
});
afterEach(() => vi.restoreAllMocks());
const job = (s: Awaited<ReturnType<typeof seedMoneyDelivery>>) => new MoneyJobRepository(env.WALLET_DB, { environment: s.f.identity.environment, profiles: [s.profile] });
function observation(s: Awaited<ReturnType<typeof seedMoneyDelivery>>, revert = false) {
  const c = s.stored.candidate, f = s.f, block = { block_hash: f.context.checkpoint.block_hash,
    block_number: f.context.checkpoint.block_number, block_timestamp: String(f.now) };
  // The synthetic evidence is assessed at f.now; pin its consuming clock too.
  // Real D1/crypto work can cross a second boundary before reconcile starts.
  vi.spyOn(Date, 'now').mockReturnValue(f.now * 1000);
  return { status: 'observed' as const, receipt: { schema_version: 1 as const, money_schema_version: 1 as const,
    network_id: c.request.network_id, market_id: s.market.market_id, market_sha256: f.context.market.digest, deployment_sha256: f.deployment,
    userop_hash: c.userOpHash, consent_digest: c.digest, transaction_hash: f.hash, ...block, transaction_index: '0',
    kind: c.request.kind, amount_atomic: c.request.amount_atomic, recipient_address: null,
    outcome: revert ? 'execution_reverted' as const : 'execution_succeeded' as const, actual_gas_cost: '100', actual_gas_used: '50',
    log_indexes: { operation: '8', calls: revert ? null : '7', pool: revert ? null : '4', transfers: revert ? [] : ['3'], approvals: revert ? [] : ['1', '2', '5'] },
    finality: 'not_assessed' as const, settlement: 'not_assessed' as const },
    finality: { schema_version: 1 as const, status: 'finalized' as const, policy_sha256: s.profile.finalityPolicy.digest,
      mechanism: s.policy.mechanism, network_id: c.request.network_id, genesis_hash: s.market.genesis_hash, target: block,
      checkpoint: block, assessed_at: f.now, expires_at: f.now + 10 },
    position: { network_id: c.request.network_id, market_id: s.market.market_id, market_digest: f.context.market.digest,
      asset_id: c.request.asset_id, a_token: s.market.a_token, account: c.account, checkpoint: { block_hash: block.block_hash, block_number: block.block_number },
      observed_at: f.now, expires_at: f.now + 10, usdc_balance_atomic: '80000000', native_balance_atomic: '999900', position_balance_atomic: '120000019',
      scaled_position_atomic: '120000000', liquidity_index_ray: '1000000000000000000000000001', debt_base_atomic: '0',
      liquidity_atomic: '100000000', supply_capacity_atomic: null, allowance_atomic: '0', active: true, frozen: false, paused: false,
      finality: 'not_assessed' as const, spend_readiness: 'not_assessed' as const } };
}

describe('Money jobs use durable internal authority', () => {
  it('has one enqueue and one claim winner, without signatures in the message', async () => {
    const s = await seedMoneyDelivery(env.WALLET_DB), jobs = job(s);
    expect(await jobs.due()).toEqual([s.stored.id]);
    const results = await Promise.all(Array.from({ length: 4 }, () => jobs.reserve(s.stored.id)));
    expect(results.filter(Boolean)).toHaveLength(1); const message = results.find(m => m)!;
    expect(Object.keys(message).sort()).toEqual(['kind', 'operation_id', 'schema_version', 'token']);
    expect((await Promise.all(Array.from({ length: 4 }, () => jobs.claim(message)))).filter(Boolean)).toHaveLength(1);
    expect((await jobs.observationSource(message)).record.operation).toEqual(s.stored.operation);
  });
  it('continues historical observation after disabling login and new features', async () => {
    const s = await seedMoneyDelivery(env.WALLET_DB), profile = { ...s.profile, features: { aave_supply: false, aave_withdraw: false, aave_withdraw_and_pay: false } };
    const jobs = new MoneyJobRepository(env.WALLET_DB, { environment: s.f.identity.environment, profiles: [profile] });
    await env.WALLET_DB.prepare('UPDATE users SET disabled_at = ?,auth_not_before = ?').bind(s.f.now, s.f.now + 1).run();
    const message = (await jobs.reserve(s.stored.id))!; expect(await jobs.claim(message)).toBe(true);
    expect((await jobs.observationSource(message)).record.candidate.digest).toBe(s.stored.candidate.digest);
    await expect(s.repository.readOperation(s.f.walletId, s.f.accountId, s.stored.id)).rejects.toThrow();
  });
  it.each(['token','lease','extra-field','other-kind','scope'])( 'rejects %s without replacing a lease', async fault => {
    const s = await seedMoneyDelivery(env.WALLET_DB), jobs = job(s), message = (await jobs.reserve(s.stored.id))!;
    await jobs.claim(message);
    if (fault === 'extra-field') expect(() => parseMoneyWake({ ...message, signature: '0x01' })).toThrow();
    else if (fault === 'other-kind') expect(() => parseMoneyWake({ ...message, kind: 'transfer_observation' })).toThrow();
    else if (fault === 'scope') await expect(new MoneyJobRepository(env.WALLET_DB, { environment: 'production', profiles: [] }).observationSource(message)).rejects.toThrow();
    else {
      if (fault === 'lease') await env.WALLET_DB.prepare('UPDATE money_jobs SET lease_expires_at = 1').run();
      await expect(jobs.observationSource(fault === 'token' ? { ...message, token: createResourceId('operation') } : message)).rejects.toThrow();
    }
    expect(await env.WALLET_DB.prepare('SELECT state FROM wallet_spend_locks').first()).toEqual({ state: 'dispatch_pending' });
  });
  it('keeps the reservation after eight failed processing attempts', async () => {
    const s = await seedMoneyDelivery(env.WALLET_DB), jobs = job(s);
    for (let i = 0; i < 8; i++) {
      const message = (await jobs.reserve(s.stored.id))!; expect(await jobs.claim(message)).toBe(true);
      expect(await jobs.fail(message, 'running')).toBe(true);
      await env.WALLET_DB.prepare('UPDATE money_jobs SET next_attempt_at = 0').run();
    }
    expect(await jobs.due()).toEqual([]);
    expect(await env.WALLET_DB.prepare('SELECT state,reason,failures FROM money_jobs').first()).toEqual({ state: 'review', reason: 'processing_error', failures: 8 });
    expect(await env.WALLET_DB.prepare('SELECT state FROM wallet_spend_locks').first()).toEqual({ state: 'dispatch_pending' });
  });
  it.each([false, true])('commits receipt, position floor and lock release atomically; reverted=%s', async reverted => {
    const s = await seedMoneyDelivery(env.WALLET_DB), jobs = job(s), message = (await jobs.reserve(s.stored.id))!;
    await jobs.claim(message); vi.spyOn(observer, 'observeMoneySource').mockResolvedValue(observation(s, reverted));
    expect(await reconcileMoneyJob(env.WALLET_DB, 'production', message, [s.profile], new AbortController().signal)).toMatchObject({
      state: 'reconciled', outcome: reverted ? 'reverted_confirmed' : 'reconciled', funds_reserved: false });
    expect(await env.WALLET_DB.prepare('SELECT state,release_reason FROM wallet_spend_locks').first()).toEqual({ state: 'released', release_reason: reverted ? 'reverted_confirmed' : 'reconciled' });
    expect(await env.WALLET_DB.prepare('SELECT block_number,block_hash FROM wallet_balance_floors').first()).toEqual({ block_number: s.f.context.checkpoint.block_number, block_hash: s.f.context.checkpoint.block_hash });
    expect(await env.WALLET_DB.prepare('SELECT state,lease_token FROM money_jobs').first()).toEqual({ state: 'reconciled', lease_token: null });
    await expect(jobs.observationSource(message)).rejects.toThrow();
  });
  it.each(['missing','pending','stale','market','lost-lease','stale-floor','conflict'])( 'does not release funds with %s evidence', async fault => {
    const s = await seedMoneyDelivery(env.WALLET_DB), jobs = job(s), message = (await jobs.reserve(s.stored.id))!; await jobs.claim(message);
    const value = observation(s), spy = vi.spyOn(observer, 'observeMoneySource');
    if (fault === 'missing') spy.mockResolvedValue({ status: 'not_observed' });
    else if (fault === 'pending') spy.mockResolvedValue({ ...value, position: null, finality: { ...value.finality, status: 'pending', checkpoint: { ...value.finality.target, block_number: '1', block_hash: s.f.hash, block_timestamp: '1' } } });
    else {
      if (fault === 'stale') value.position.expires_at = s.f.now;
      if (fault === 'market') value.receipt.market_sha256 = s.f.hash;
      if (fault === 'lost-lease') spy.mockImplementation(async () => { await env.WALLET_DB.prepare('UPDATE money_jobs SET lease_expires_at = 1').run(); return value; });
      else spy.mockResolvedValue(value);
      if (fault === 'stale-floor') await env.WALLET_DB.prepare('INSERT INTO wallet_balance_floors VALUES (?,?,?,?)')
        .bind(s.f.accountId, (BigInt(value.receipt.block_number) + 1n).toString(), s.f.hash, s.f.now).run();
      if (fault === 'conflict') {
        const altered = JSON.stringify({ ...value.receipt, actual_gas_used: '51' }), evidence = JSON.stringify(value.finality);
        await env.WALLET_DB.prepare('INSERT INTO money_finality_journal VALUES (?,?,?,?,?,?,?,?,?)')
          .bind(s.stored.id, altered, deploymentDocumentDigest(altered), evidence, deploymentDocumentDigest(evidence),
            value.receipt.block_number, value.receipt.block_hash, 'reconciled', s.f.now).run();
      }
    }
    const invoke = () => reconcileMoneyJob(env.WALLET_DB, 'production', message, [s.profile], new AbortController().signal);
    if (['missing','pending'].includes(fault)) expect(await invoke()).toEqual({ state: 'waiting' });
    else if (fault === 'conflict') expect(await invoke()).toEqual({ state: 'review', reason: 'conflicting_evidence' });
    else await expect(invoke()).rejects.toThrow();
    expect(await env.WALLET_DB.prepare('SELECT count(*) AS n FROM money_reconciliations').first()).toEqual({ n: 0 });
    expect(await env.WALLET_DB.prepare('SELECT state FROM wallet_spend_locks').first()).toEqual({ state: 'dispatch_pending' });
  });
});
