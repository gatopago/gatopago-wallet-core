import { applyD1Migrations } from 'cloudflare:test';
import { env } from 'cloudflare:workers';
import { afterEach, beforeAll, beforeEach, describe, expect, it, vi } from 'vitest';
import { encodeFunctionData, keccak256, toHex, zeroAddress, type Hex } from 'viem';
import { privateKeyToAccount } from 'viem/accounts';
import { entryPoint09Abi, toPackedUserOperation } from 'viem/account-abstraction';
import * as finality from '@gatopago/shared/v3/finality';
import * as accountInspection from '@gatopago/shared/v3/account-inspection';
import * as chain from '../src/chainInspection';
import * as runtime from '../src/runtime/finality';
import * as nonceReader from '../src/transfers/transferNonce';
import * as positionReader from '../src/portfolio/aavePositionObservation';
import { MoneyJobRepository } from '../src/money/moneyJobs';
import { reconcileMoneyJob } from '../src/money/moneyReconciliation';
import { readOwnedMoneyStatus } from '../src/money/moneyStatus';
import { seedMoneyDelivery } from './moneyDelivery.fixture';
import { clearMoneyTestRows } from './moneyOwned.fixture';

beforeAll(() => applyD1Migrations(env.WALLET_DB, env.V3_TEST_MIGRATIONS));
beforeEach(() => clearMoneyTestRows(env.WALLET_DB));
afterEach(() => vi.restoreAllMocks());
async function fixture() {
  const s = await seedMoneyDelivery(env.WALLET_DB), c = s.stored.candidate;
  const jobs = new MoneyJobRepository(env.WALLET_DB, { environment: 'production', profiles: [s.profile] });
  const message = (await jobs.reserve(s.stored.id))!; await jobs.claim(message);
  const now = s.f.now + 60; vi.spyOn(Date, 'now').mockReturnValue(now * 1000);
  const operator = privateKeyToAccount(`0x${'12'.repeat(32)}`), data = (beneficiary: Hex) => encodeFunctionData({
    abi: entryPoint09Abi, functionName: 'handleOps', args: [[toPackedUserOperation(s.stored.operation)], beneficiary] });
  const raw = await operator.signTransaction({ type: 'eip1559', chainId: 421614, to: c.plan.entryPoint, value: 0n,
    data: data(operator.address), nonce: 0, gas: 100_000n, maxFeePerGas: 20n, maxPriorityFeePerGas: 0n });
  await env.WALLET_DB.prepare(`INSERT INTO user_operation_submissions(user_op_hash,payload_hash,kind,endpoint,network_id,
    operator,nonce,raw_transaction,transaction_hash,valid_until) VALUES (?,?,'self',?,?,?,?,?,?,?)`)
    .bind(c.userOpHash, keccak256(data(zeroAddress)), 'https://historical.example/rpc', c.request.network_id,
      operator.address.toLowerCase(), 0, raw, keccak256(raw), c.plan.validUntil).run();
  const outerNumber = BigInt(c.checkpoint.block_number) + 1n, firstExpiry = outerNumber + 6n;
  const block = (number: bigint) => ({ block_number: number.toString(), block_hash: `0x${number.toString(16).padStart(64, '0')}` as Hex,
    block_timestamp: String(number < firstExpiry ? c.plan.validUntil - 1 : c.plan.validUntil + 1) });
  const outer = block(outerNumber), latest = block(outerNumber + 30n), settlement = block(firstExpiry);
  const receipt = { status: '0x0', type: '0x2', from: operator.address, to: c.plan.entryPoint, contractAddress: null,
    transactionHash: keccak256(raw), blockHash: outer.block_hash, blockNumber: toHex(outerNumber), transactionIndex: '0x0',
    logs: [], gasUsed: '0x3e8', effectiveGasPrice: '0xa', gasUsedForL1: '0xc8' };
  const rpc = vi.fn(async (input: { method: string; params: unknown[] }) => {
    if (input.method === 'eth_getTransactionReceipt') return structuredClone(receipt);
    if (input.method !== 'eth_getBlockByNumber') throw new Error('Unexpected financial mutation');
    const point = block(BigInt(String(input.params[0])));
    return { hash: point.block_hash, number: toHex(BigInt(point.block_number)), timestamp: toHex(BigInt(point.block_timestamp)) };
  });
  vi.spyOn(chain, 'createInspectionClient').mockImplementation(() => ({ request: rpc }) as unknown as ReturnType<typeof chain.createInspectionClient>);
  const assessment = (target: typeof latest): finality.FinalityAssessment => ({ schema_version: 1, status: 'finalized',
    policy_sha256: s.profile.finalityPolicy.digest, mechanism: s.policy.mechanism, network_id: c.request.network_id,
    genesis_hash: s.market.genesis_hash, target: { block_number: target.block_number, block_hash: target.block_hash, block_timestamp: target.block_timestamp },
    checkpoint: latest, assessed_at: Math.floor(Date.now() / 1000), expires_at: Math.floor(Date.now() / 1000) + 10 });
  vi.spyOn(runtime, 'networkFinality').mockImplementation(async () => assessment(latest));
  vi.spyOn(finality, 'assessCheckpointFinality').mockImplementation(async (_clients, target) => assessment(target));
  vi.spyOn(accountInspection, 'inspectAccountDeployment').mockImplementation(async (_client, input) => ({
    status: 'recognized', account: c.account, account_id: c.plan.accountId, network_id: c.request.network_id,
    manifest_id: s.f.keys.profile.deployment.manifest_id, manifest_sha256: s.profile.digest, checkpoint: input.checkpoint,
    implementation: s.f.keys.profile.deployment.components.implementation.address, security_version: '1',
    storage_layout_hash: s.f.keys.profile.deployment.storage_layout_hash, spend_readiness: 'not_assessed' }));
  const nonce = vi.spyOn(nonceReader, 'observeTransferNonce').mockImplementation(async input => ({ network_id: c.request.network_id,
    account: c.account, entry_point: c.plan.entryPoint, checkpoint: input.checkpoint, nonce: '0', observed_at: now }));
  vi.spyOn(positionReader, 'observeAavePosition').mockImplementation(async input => ({ network_id: c.request.network_id,
    market_id: s.market.market_id, market_digest: s.profile.market.digest, asset_id: c.request.asset_id, a_token: s.market.a_token,
    account: c.account, checkpoint: input.checkpoint, observed_at: now, expires_at: now + 10, usdc_balance_atomic: '100000000',
    native_balance_atomic: '1000000', position_balance_atomic: '0', scaled_position_atomic: '0', liquidity_index_ray: '1',
    debt_base_atomic: '0', liquidity_atomic: '100000000', supply_capacity_atomic: null, allowance_atomic: '0', active: true,
    frozen: false, paused: false, finality: 'not_assessed', spend_readiness: 'not_assessed' }));
  const profile = { ...s.profile, features: { aave_supply: false, aave_withdraw: false, aave_withdraw_and_pay: false } };
  return { ...s, c, now, message, settlement, nonce, profile, rpc,
    run: () => reconcileMoneyJob(env.WALLET_DB, 'production', message, [profile], new AbortController().signal) };
}
describe('Outer revert closes the real D1 obligation', () => {
  it('atomically persists separate costs, advances the post-expiry floor and releases once', async () => {
    const s = await fixture();
    expect(await s.run()).toMatchObject({ state: 'reconciled', outcome: 'reverted_confirmed', funds_reserved: false });
    expect(await env.WALLET_DB.prepare('SELECT state,release_reason FROM wallet_spend_locks').first()).toEqual({ state: 'released', release_reason: 'reverted_confirmed' });
    expect(await env.WALLET_DB.prepare('SELECT block_number,block_hash FROM wallet_balance_floors').first()).toEqual({
      block_number: s.settlement.block_number, block_hash: s.settlement.block_hash });
    const status = await readOwnedMoneyStatus(env.WALLET_DB, s.repository, s.f.walletId, s.f.accountId, s.stored.id);
    expect(status).toMatchObject({ state: 'reverted_confirmed', funds_reserved: false, receipt: {
      outcome: 'outer_transaction_reverted', actual_gas_cost: '0', outer_transaction: { gas_cost_atomic: '10000' } } });
    const journal = await env.WALLET_DB.prepare('SELECT finality_json FROM money_finality_journal').first<{ finality_json: string }>();
    expect(JSON.parse(journal!.finality_json)).toHaveProperty('inclusion.status', 'finalized');
    await expect(s.run()).rejects.toThrow('MONEY_HISTORY_UNAVAILABLE');
  });
  it('retains the lock when the original UserOp nonce was consumed elsewhere', async () => {
    const s = await fixture(); s.nonce.mockImplementation(async input => ({ network_id: s.c.request.network_id,
      account: s.c.account, entry_point: s.c.plan.entryPoint, checkpoint: input.checkpoint, nonce: '1', observed_at: s.now }));
    expect(await s.run()).toEqual({ state: 'waiting' });
    expect(await env.WALLET_DB.prepare('SELECT state FROM wallet_spend_locks').first()).toEqual({ state: 'dispatch_pending' });
  });
  it('can restart after the immutable receipt journal was written but reconciliation failed', async () => {
    const s = await fixture();
    await env.WALLET_DB.exec("CREATE TRIGGER fail_money_close BEFORE INSERT ON money_reconciliations BEGIN SELECT RAISE(ABORT,'synthetic interruption'); END;");
    try { await expect(s.run()).rejects.toThrow('synthetic interruption'); }
    finally { await env.WALLET_DB.exec('DROP TRIGGER fail_money_close;'); }
    expect(await env.WALLET_DB.prepare('SELECT count(*) AS n FROM money_finality_journal').first()).toEqual({ n: 1 });
    expect(await env.WALLET_DB.prepare('SELECT state FROM wallet_spend_locks').first()).toEqual({ state: 'dispatch_pending' });
    vi.spyOn(Date, 'now').mockReturnValue((s.now + 1) * 1000);
    expect(await s.run()).toMatchObject({ outcome: 'reverted_confirmed', funds_reserved: false });
    expect(await env.WALLET_DB.prepare('SELECT count(*) AS n FROM money_finality_conflicts').first()).toEqual({ n: 0 });
  });
});
