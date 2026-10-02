import { env } from 'cloudflare:workers';
import { applyD1Migrations } from 'cloudflare:test';
import { beforeAll, beforeEach, describe, expect, it } from 'vitest';
import { toHex } from 'viem';
import { testUserId } from './principal.fixture';
import { SponsorshipBudget, budgetUnits } from '../src/sponsorship/budget';

beforeAll(async () => { await applyD1Migrations(env.WALLET_DB, env.V3_TEST_MIGRATIONS); });
beforeEach(async () => {
  await env.WALLET_DB.exec('DELETE FROM sponsorship_reservations; DELETE FROM users;');
  await env.WALLET_DB.batch(['user-a', 'other-user', ...Array.from({ length: 20 }, (_, i) => `u-${i}`)]
    .map(label => env.WALLET_DB.prepare("INSERT INTO users(id,environment,created_at) VALUES (?,'production',?)").bind(testUserId(label), now)));
});
const now = 1_800_000_000;
const input = (id: number, subject = 'user-a') => ({ digest: toHex(id, { size: 32 }), scope: `421614:0x${'ab'.repeat(20)}`, userId: testUserId(subject),
  maximumWei: 3_000_000_001n, validUntil: now + 60, dailyGwei: 12, userDailyGwei: 8, userDailyOperations: 2 });

describe('durable sponsorship budgets', () => {
  it('rounds up instead of understating liability or using floating point wei', () => {
    expect(budgetUnits(1n)).toBe(1); expect(budgetUnits(1_000_000_001n)).toBe(2);
    expect(() => budgetUnits(-1n)).toThrow();
    expect(() => budgetUnits(BigInt(Number.MAX_SAFE_INTEGER) * 1_000_000_000n + 1n)).toThrow();
  });
  it('admits only the per-user budget under a concurrent burst', async () => {
    const budget = new SponsorshipBudget(env.WALLET_DB);
    const results = await Promise.allSettled(Array.from({ length: 20 }, (_, i) => budget.reserve(input(i + 1), now)));
    expect(results.filter(r => r.status === 'fulfilled')).toHaveLength(2);
    expect((await env.WALLET_DB.prepare('SELECT SUM(charged_gwei) AS cost FROM sponsorship_reservations').first())?.cost).toBe(8);
  });
  it('also enforces the global budget across different users', async () => {
    const budget = new SponsorshipBudget(env.WALLET_DB);
    const results = await Promise.allSettled(Array.from({ length: 20 }, (_, i) => budget.reserve(input(i + 1, `u-${i}`), now)));
    expect(results.filter(r => r.status === 'fulfilled')).toHaveLength(3);
  });
  it('same-operation retries reserve once and cannot cross owners', async () => {
    const budget = new SponsorshipBudget(env.WALLET_DB);
    await Promise.all(Array.from({ length: 8 }, () => budget.reserve(input(1), now)));
    expect((await env.WALLET_DB.prepare('SELECT COUNT(*) AS count FROM sponsorship_reservations').first())?.count).toBe(1);
    await expect(budget.reserve(input(1, 'other-user'), now)).rejects.toThrow('SPONSOR_RESERVATION_CONFLICT');
  });
  it('retains uncertain or expired operations at their maximum cost', async () => {
    const budget = new SponsorshipBudget(env.WALLET_DB);
    await budget.reserve(input(1), now); await budget.reserve(input(2), now);
    await expect(budget.reserve({ ...input(3), validUntil: now + 200 }, now + 100)).rejects.toThrow('SPONSOR_BUDGET_EXHAUSTED');
  });
  it('settles exactly once and detects conflicting cost or transaction evidence', async () => {
    const budget = new SponsorshipBudget(env.WALLET_DB), hash = toHex(100, { size: 32 }), tx = toHex(200, { size: 32 });
    await budget.reserve(input(1), now); await budget.bind(input(1).digest, hash);
    await expect(budget.bind(input(1).digest, tx)).rejects.toThrow('SPONSOR_RESERVATION_CONFLICT');
    await expect(budget.settle(hash, 4_000_000_000n, tx)).rejects.toThrow('SPONSOR_SETTLEMENT_CONFLICT');
    await budget.settle(hash, 1n, tx); await budget.settle(hash, 1n, tx);
    expect((await env.WALLET_DB.prepare('SELECT charged_gwei FROM sponsorship_reservations').first())?.charged_gwei).toBe(1);
    await expect(budget.settle(hash, 2n, tx)).rejects.toThrow('SPONSOR_SETTLEMENT_CONFLICT');
    await expect(budget.settle(hash, 1n, hash)).rejects.toThrow('SPONSOR_SETTLEMENT_CONFLICT');
  });
  it.each([
    ['digest', 'invalid'], ['scope', '421614:paymaster'], ['maximum_wei', '03'], ['maximum_wei', '1e9'],
    ['maximum_gwei', 3], ['charged_gwei', 0], ['userop_hash', '0x12'], ['actual_wei', '1'],
    ['transaction_hash', toHex(9, { size: 32 })], ['day', -1], ['valid_until', 0],
  ] as const)('rejects an inconsistent persisted %s even outside the service', async (column, value) => {
    await new SponsorshipBudget(env.WALLET_DB).reserve(input(1), now);
    await expect(env.WALLET_DB.prepare(`UPDATE sponsorship_reservations SET ${column} = ?`).bind(value).run()).rejects.toThrow();
  });
  it('requires a real internal user and preserves that user while reservations exist', async () => {
    const budget = new SponsorshipBudget(env.WALLET_DB);
    await expect(budget.reserve(input(1, 'missing'), now)).rejects.toThrow();
    await budget.reserve(input(1), now);
    await expect(env.WALLET_DB.prepare('DELETE FROM users WHERE id = ?').bind(input(1).userId).run()).rejects.toThrow();
  });
  it.each([0n, 1n, 999_999_999n, 1_000_000_000n, 1_000_000_001n, 9_007_199_254_740_991_000_000_000n])(
    'preserves exact decimal cost and round-up accounting at %s wei', async cost => {
      const budget = new SponsorshipBudget(env.WALLET_DB), maximum = cost > 0n ? cost : 1n;
      await budget.reserve({ ...input(1), maximumWei: maximum, dailyGwei: Number.MAX_SAFE_INTEGER,
        userDailyGwei: Number.MAX_SAFE_INTEGER }, now);
      const hash = toHex(100, { size: 32 }); await budget.bind(input(1).digest, hash);
      await budget.settle(hash, cost, toHex(200, { size: 32 }));
      expect(await env.WALLET_DB.prepare('SELECT actual_wei,charged_gwei FROM sponsorship_reservations').first())
        .toEqual({ actual_wei: cost.toString(), charged_gwei: budgetUnits(cost) });
    });
});
