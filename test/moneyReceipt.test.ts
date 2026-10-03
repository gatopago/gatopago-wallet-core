import { describe, expect, it } from 'vitest';
import { encodeAbiParameters, zeroHash } from 'viem';
import { createMoneyReceiptFixture as fixture } from './moneyReceipt.fixture';

describe('Principal proof for the exact signed money recipe', () => {
  it.each(['aave_supply', 'aave_withdraw', 'aave_withdraw_and_pay'] as const)('proves %s without asserting finality', async kind => {
    const f = await fixture(kind);
    expect(f.run()).toMatchObject({ kind, amount_atomic: '20000000', outcome: 'execution_succeeded',
      userop_hash: f.record.candidate.userOpHash, finality: 'not_assessed', settlement: 'not_assessed' });
  });
  it.each(['aave_supply', 'aave_withdraw', 'aave_withdraw_and_pay'] as const)('accepts an atomic reverted %s with no principal effects', async kind => {
    const f = await fixture(kind, false);
    expect(f.run()).toMatchObject({ outcome: 'execution_reverted', log_indexes: { calls: null, pool: null, transfers: [], approvals: [] } });
    f.logs.splice(1, 0, f.transfer(f.record.candidate.account, f.market.a_token)); f.reindex();
    expect(f.run).toThrow('MONEY_RECEIPT_REVERT_INCONSISTENT');
  });
  it.each(['missing-principal', 'wrong-amount', 'wrong-reserve', 'wrong-recipient', 'duplicate-pool', 'no-calls', 'late-payment', 'orphan', 'false-success', 'cross-operation'])(
    'rejects a withdraw-and-pay receipt with %s', async fault => {
      const f = await fixture('aave_withdraw_and_pay'), c = f.record.candidate;
      if (fault === 'missing-principal') f.logs.splice(1, 1);
      if (fault === 'wrong-amount') f.logs[1].data = f.amount(1n);
      if (fault === 'wrong-reserve') f.logs[2].topics[1] = zeroHash;
      if (fault === 'wrong-recipient') f.logs[3].topics[2] = f.topic(c.account);
      if (fault === 'duplicate-pool') f.logs.splice(2, 0, { ...f.logs[2] });
      if (fault === 'no-calls') f.logs.splice(4, 1);
      if (fault === 'late-payment') [f.logs[3], f.logs[4]] = [f.logs[4], f.logs[3]];
      if (fault === 'orphan') f.logs[1].removed = true;
      if (fault === 'false-success') f.operation.data = encodeAbiParameters(
        [{ type: 'uint256' }, { type: 'bool' }, { type: 'uint256' }, { type: 'uint256' }], [c.plan.nonce, false, 100n, 50n]);
      if (fault === 'cross-operation') f.logs.splice(4, 0, { ...f.operation, topics: [f.operation.topics[0], zeroHash, ...f.operation.topics.slice(2)] });
      f.reindex(); expect(f.run).toThrow();
    });
  it.each(['missing', 'wrong-spender', 'unbounded', 'wrong-order', 'trailing-data', 'not-cleared'])(
    'rejects supply allowance evidence: %s', async fault => {
      const f = await fixture('aave_supply');
      if (fault === 'missing') f.logs.splice(5, 1);
      if (fault === 'wrong-spender') f.logs[2].topics[2] = f.topic(f.market.a_token);
      if (fault === 'unbounded') f.logs[2].data = f.amount((1n << 256n) - 1n);
      if (fault === 'wrong-order') [f.logs[1], f.logs[2]] = [f.logs[2], f.logs[1]];
      if (fault === 'trailing-data') f.logs[2].data = `${f.logs[2].data}00`;
      if (fault === 'not-cleared') f.logs[5].data = f.amount(1n);
      f.reindex(); expect(f.run).toThrow();
    });
  it('ignores aToken interest events instead of comparing Mint/Burn to principal', async () => {
    const f = await fixture('aave_withdraw'), noise = { ...f.logs[1], address: f.market.a_token,
      data: f.amount(20000019n), topics: [f.logs[1].topics[0], zeroHash, f.topic(f.record.candidate.account)] };
    f.logs.splice(2, 0, noise); f.reindex();
    expect(f.run()).toMatchObject({ amount_atomic: '20000000', outcome: 'execution_succeeded' });
  });
  it('does not count principal events from the preceding operation in a bundle', async () => {
    const f = await fixture('aave_withdraw_and_pay'), previous = { ...f.operation, topics: [f.operation.topics[0], zeroHash, ...f.operation.topics.slice(2)] };
    f.logs.splice(1, 0, { ...f.logs[1] }, previous); f.reindex();
    expect(f.run().log_indexes.transfers).toEqual(['3', '5']);
  });
});
