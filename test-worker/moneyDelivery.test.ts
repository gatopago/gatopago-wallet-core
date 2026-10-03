import { applyD1Migrations } from 'cloudflare:test';
import { env } from 'cloudflare:workers';
import { afterEach, beforeAll, beforeEach, describe, expect, it, vi } from 'vitest';
import * as preflight from '../src/money/moneyPreflight';
import * as transport from '../src/execution/operationTransport';
import { deliverOwnedMoney } from '../src/money/moneyDelivery';
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
async function fixture() {
  const s = await seedMoneyDelivery(env.WALLET_DB, false);
  const checks = vi.spyOn(preflight, 'preflightOwnedMoney').mockResolvedValue(s.preflight);
  const send = vi.spyOn(transport, 'sendOperation').mockResolvedValue(s.stored.candidate.userOpHash);
  const run = (signal = new AbortController().signal) => deliverOwnedMoney(env.WALLET_DB, s.f.identity,
    s.f.walletId, s.f.accountId, s.stored.id, s.f.keys.input.scope, [s.profile], signal);
  return { ...s, checks, send, run };
}
describe('Durable money dispatch', () => {
  it('allows only one concurrent caller to send the exact stored operation', async () => {
    const s = await fixture(), results = await Promise.all(Array.from({ length: 4 }, () => s.run()));
    expect(results.filter(r => r.delivery === 'accepted')).toHaveLength(1); expect(s.send).toHaveBeenCalledTimes(1);
    const payload = s.send.mock.calls[0][2];
    expect(payload.operation).toEqual(s.stored.operation); expect(payload.userOpHash).toBe(s.stored.candidate.userOpHash);
    expect(await env.WALLET_DB.prepare('SELECT state FROM money_jobs').first()).toEqual({ state: 'ready' });
    expect(await env.WALLET_DB.prepare('SELECT state FROM wallet_spend_locks').first()).toEqual({ state: 'dispatch_pending' });
  });
  it('keeps an uncertain send and reopens it without another simulation or broadcast', async () => {
    const s = await fixture(); s.send.mockRejectedValue(new Error('network timeout'));
    expect(await s.run()).toMatchObject({ delivery: 'uncertain', state: 'dispatch_pending' });
    s.checks.mockClear(); expect(await s.run()).toMatchObject({ delivery: 'existing', state: 'dispatch_pending' });
    expect(s.checks).not.toHaveBeenCalled(); expect(s.send).toHaveBeenCalledTimes(1);
    expect(await env.WALLET_DB.prepare('SELECT state FROM wallet_spend_locks').first()).toEqual({ state: 'dispatch_pending' });
  });
  it('leaves the authorization held after a preflight refusal', async () => {
    const s = await fixture(); s.checks.mockRejectedValue(new Error('insufficient liquidity'));
    await expect(s.run()).rejects.toThrow(); expect(s.send).not.toHaveBeenCalled();
    expect(await env.WALLET_DB.prepare('SELECT state FROM money_operations').first()).toEqual({ state: 'authorized' });
    expect(await env.WALLET_DB.prepare('SELECT count(*) AS n FROM money_jobs').first()).toEqual({ n: 0 });
  });
  it('refuses a stale preflight before marking dispatch', async () => {
    const s = await fixture(); s.checks.mockResolvedValue({ ...s.preflight, expires_at: s.f.now });
    await expect(s.run()).rejects.toThrow(); expect(s.send).not.toHaveBeenCalled();
    expect(await env.WALLET_DB.prepare('SELECT state FROM wallet_spend_locks').first()).toEqual({ state: 'held' });
  });
  it('preserves uncertain dispatch after cancellation during sending', async () => {
    const s = await fixture(), controller = new AbortController();
    s.send.mockImplementation(async () => { controller.abort(); throw new Error('cancelled after marker'); });
    expect(await s.run(controller.signal)).toMatchObject({ delivery: 'uncertain' });
    expect(await s.run()).toMatchObject({ delivery: 'existing' }); expect(s.send).toHaveBeenCalledTimes(1);
  });
});
