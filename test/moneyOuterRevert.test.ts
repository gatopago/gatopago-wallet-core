import { afterEach, describe, expect, it, vi } from 'vitest';
import { moneyOuterFixture } from './moneyOuterRevert.fixture';
import { encodeFunctionData, keccak256, type Hex } from 'viem';
import { privateKeyToAccount } from 'viem/accounts';
import { entryPoint09Abi, toPackedUserOperation } from 'viem/account-abstraction';

afterEach(() => vi.restoreAllMocks());
describe('Exact private outer revert with finalized nonexecution', () => {
  it.each([false, true])('closes only after expiry and preserves separate account/operator costs; late=%s', async late => {
    const f = await moneyOuterFixture(late), result = await f.observed();
    expect(result).toMatchObject({ status: 'observed', receipt: { outcome: 'outer_transaction_reverted', actual_gas_cost: '0',
      actual_gas_used: '0', outer_transaction: { gas_cost_atomic: '10000', gas_used_for_l1: '200' },
      nonexecution: { nonce: '0', valid_until: f.c.plan.validUntil, checkpoint: f.block(late ? 140 : 130) } } });
    expect(f.nonce).toHaveBeenCalledTimes(1);
    expect(f.profile.features.aave_supply).toBe(false);
  });
  it('keeps a deterministic receipt after a newer finalized head and a new proof timestamp', async () => {
    const f = await moneyOuterFixture(), first = await f.run();
    f.latest.block_number = '300'; f.latest.block_hash = f.block(300).block_hash;
    f.head.mockResolvedValue(f.assessment(f.latest));
    const second = await f.run();
    expect(first.status).toBe('observed'); expect(second.status).toBe('observed');
    if (first.status !== 'observed' || second.status !== 'observed') throw new Error('Missing proof');
    expect(second.receipt).toEqual(first.receipt);
  });
  it('does not substitute another SPEND signature under the same UserOp hash', async () => {
    const f = await moneyOuterFixture(), operator = privateKeyToAccount(`0x${'12'.repeat(32)}`);
    const data = encodeFunctionData({ abi: entryPoint09Abi, functionName: 'handleOps', args: [
      [toPackedUserOperation({ ...f.record.operation, signature: '0x1234' })], operator.address] });
    f.stored.raw_transaction = await operator.signTransaction({ type: 'eip1559', chainId: 421614, to: f.c.plan.entryPoint,
      value: 0n, data, nonce: 7, gas: 100_000n, maxFeePerGas: 20n, maxPriorityFeePerGas: 0n });
    f.stored.transaction_hash = keccak256(f.stored.raw_transaction);
    await expect(f.run()).rejects.toThrow('BACKUP_TRANSACTION_INVALID'); expect(f.nonce).not.toHaveBeenCalled();
  });
  it('normalizes RPC receipt field order before comparing independent peers', async () => {
    const f = await moneyOuterFixture();
    f.requests[1].mockImplementation(async input => input.method === 'eth_getTransactionReceipt'
      ? Object.fromEntries(Object.entries(f.receipt).reverse()) : f.requests[0](input));
    expect(await f.observed()).toMatchObject({ status: 'observed', receipt: { outcome: 'outer_transaction_reverted' } });
  });
  it.each(['bundler', 'wrong-payload', 'wrong-hash', 'wrong-operator', 'wrong-nonce', 'wrong-network', 'wrong-window', 'wrong-signature'])(
    'never derives nonexecution from %s journal data', async fault => {
      const f = await moneyOuterFixture();
      if (fault === 'bundler') f.stored.kind = 'bundler';
      if (fault === 'wrong-payload') f.stored.payload_hash = f.f.hash;
      if (fault === 'wrong-hash') f.stored.transaction_hash = f.f.hash;
      if (fault === 'wrong-operator') f.stored.operator = `0x${'66'.repeat(20)}`;
      if (fault === 'wrong-nonce') f.stored.nonce++;
      if (fault === 'wrong-network') Reflect.set(f.stored, 'network_id', 'eip155:1');
      if (fault === 'wrong-window') f.stored.valid_until++;
      if (fault === 'wrong-signature') f.stored.raw_transaction = `${f.stored.raw_transaction.slice(0, -2)}ff` as Hex;
      if (fault === 'bundler') expect(await f.run()).toEqual({ status: 'unavailable' }); else await expect(f.run()).rejects.toThrow();
      expect(f.nonce).not.toHaveBeenCalled();
    });
  it.each(['success', 'logs', 'missing-l1-gas', 'excess-gas', 'excess-price', 'excess-l1-gas', 'wrong-recipient', 'wrong-block', 'rpc-error'])(
    'refuses malformed or mismatched %s evidence', async fault => {
      const f = await moneyOuterFixture();
      if (fault === 'success') f.receipt.status = '0x1';
      if (fault === 'logs') Reflect.set(f.receipt, 'logs', [{}]);
      if (fault === 'missing-l1-gas') Reflect.deleteProperty(f.receipt, 'gasUsedForL1');
      if (fault === 'excess-gas') f.receipt.gasUsed = '0x186a1';
      if (fault === 'excess-price') f.receipt.effectiveGasPrice = '0x15';
      if (fault === 'excess-l1-gas') f.receipt.gasUsedForL1 = '0x3e9';
      if (fault === 'wrong-recipient') f.receipt.to = `0x${'66'.repeat(20)}`;
      if (fault === 'wrong-block') f.receipt.blockHash = f.f.hash;
      if (fault === 'rpc-error') f.requests[1].mockRejectedValue(new Error('Synthetic RPC failure'));
      await expect(f.run()).rejects.toThrow(); expect(f.nonce).not.toHaveBeenCalled();
    });
  it('retains uncertainty when both valid receipts disagree on gas', async () => {
    const f = await moneyOuterFixture();
    f.requests[1].mockImplementation(async input => input.method === 'eth_getTransactionReceipt'
      ? { ...f.receipt, gasUsed: '0x3e9' } : f.requests[0](input));
    expect(await f.observed()).toEqual({ status: 'disagreement' }); expect(f.nonce).not.toHaveBeenCalled();
  });
  it.each(['at-expiry', 'old-head', 'pending', 'changed-nonce', 'unknown-account', 'closing-reorg', 'stale-position', 'abort'])(
    'cannot release on %s', async fault => {
      const f = await moneyOuterFixture();
      if (fault === 'at-expiry') {
        const bound = { ...f.latest, block_timestamp: String(f.c.plan.validUntil) };
        f.head.mockResolvedValue({ ...f.assessment(bound), checkpoint: bound });
      }
      if (fault === 'old-head') f.head.mockResolvedValue({ ...f.assessment(f.block(120)), checkpoint: f.block(120) });
      if (fault === 'pending') f.final.mockResolvedValue({ ...f.assessment(f.block(124)), status: 'pending', checkpoint: f.block(100) });
      if (fault === 'changed-nonce') f.nonce.mockImplementation(async input => ({ network_id: f.c.request.network_id, account: f.c.account,
        entry_point: f.c.plan.entryPoint, checkpoint: input.checkpoint, nonce: '1', observed_at: f.now }));
      if (fault === 'unknown-account') f.account.mockRejectedValue(new Error('Unrecognized code'));
      if (fault === 'closing-reorg') f.final.mockImplementation(async (_clients, target) => target.block_number === '130'
        ? { ...f.assessment(target), status: 'reorg_detected', checkpoint: null, expires_at: f.now } : f.assessment(target));
      if (fault === 'stale-position') f.position.mockImplementation(async input => ({
        network_id: f.c.request.network_id, market_id: f.market.market_id, market_digest: f.profile.market.digest, asset_id: f.c.request.asset_id,
        a_token: f.market.a_token, account: f.c.account, checkpoint: input.checkpoint, observed_at: f.now - 10, expires_at: f.now,
        usdc_balance_atomic: '0', native_balance_atomic: '0', position_balance_atomic: '0', scaled_position_atomic: '0', liquidity_index_ray: '1',
        debt_base_atomic: '0', liquidity_atomic: '0', supply_capacity_atomic: null, allowance_atomic: '0', active: true, frozen: false, paused: false,
        finality: 'not_assessed', spend_readiness: 'not_assessed' }));
      if (fault === 'abort') f.controller.abort();
      if (['at-expiry','old-head','pending'].includes(fault)) expect(await f.run()).toEqual({ status: 'not_observed' });
      else await expect(f.run()).rejects.toThrow();
    });
});
