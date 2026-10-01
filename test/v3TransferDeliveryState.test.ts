import { describe, expect, it } from 'vitest';
import { createResourceId } from '@gatopago/shared/v3/primitives';
import { authorizeTransferOperation } from '@gatopago/shared/v3/transfer-authorization';
import { prepareTransferOperation } from '@gatopago/shared/v3/transfer-operation';
import { assertTransferDeliveryState, type TransferDeliveryEvidence } from '../src/transfers/transferDeliveryState';
import { readTransferReview, writeTransferReview } from '@gatopago/shared/v3/transfer-review-record';
import { transferFixture } from '@gatopago/test-fixtures/v3-transfer';

async function fixture(native = true, max = false) {
  const f = transferFixture(native), request = { ...f.request, amount: max ? { kind: 'max' as const } : f.request.amount };
  const prepared = prepareTransferOperation(request, f.context, f.now);
  const signed = await authorizeTransferOperation(request, f.context, { ...f.approval, reviewed_digest: prepared.digest },
    await f.proofs(prepared.digest), () => f.now + 1);
  const stored = writeTransferReview(signed.consent_review), record = await readTransferReview(stored.json, stored.digest);
  const now = f.now + 5, accountId = createResourceId('walletAccount');
  const checkpoint = { block_number: '124', block_hash: `0x${'dd'.repeat(32)}` as const, block_timestamp: String(now - 5) };
  const finality = { ...f.approval.security_evidence.finality, target: checkpoint, checkpoint, assessed_at: now, expires_at: now + 30 };
  const evidence = {
    security: { ...f.approval.security_evidence, observed_at: now, expires_at: now + 30, finality,
      observation: { ...f.approval.security_evidence.observation, checkpoint } },
    reviewed_block: { ...finality, target: f.approval.security_evidence.finality.target },
    balances: { wallet_id: request.wallet_id, wallet_account_id: accountId, network_id: request.network_id,
      address: f.context.account, checkpoint, observed_at: now, expires_at: now + 30,
      finality: 'finalized' as const, finality_evidence: finality, available_balance: 'not_assessed' as const, spend_readiness: 'not_assessed' as const,
      balances: f.approval.balance_evidence.balances.map(b => ({ ...b, symbol: 'TEST', decimals: 18 })) },
    nonce: { ...f.approval.nonce_evidence, checkpoint, observed_at: now },
    holds: { id: createResourceId('operation'), wallet_id: request.wallet_id, wallet_account_id: accountId,
      network_id: request.network_id, account: f.context.account, userop_hash: signed.userOpHash, consent_digest: signed.digest,
      own_funds: signed.funding_reservation,
      total_reserved: signed.funding_reservation.map(t => ({ asset_id: t.asset_id, amount_atomic: t.debit_atomic })),
      fingerprint: 'synthetic-private-snapshot', observed_at: now, expires_at: now + 5, send_enabled: false as const },
  } satisfies TransferDeliveryEvidence;
  return { record, signed, evidence, now };
}

describe('Current transfer delivery state without changing signed consent', () => {
  it.each([[true, false], [false, false], [true, true]])('accepts an advancing finalized block (native=%s MAX=%s)', async (native, max) => {
    const { record, signed, evidence, now } = await fixture(native, max);
    evidence.balances.balances.forEach(b => { b.amount_atomic = '20000'; });
    const result = assertTransferDeliveryState(record, evidence, now);
    expect(result.checkpoint.block_number).toBe('124');
    expect(result.userop_hash).toBe(signed.userOpHash);
    expect(result.send_enabled).toBe(false);
    expect(record.operation).toEqual(signed.operation);
    expect(record.candidate.funding).toEqual(signed.funding);
  });
  it.each(['spent-nonce', 'balance', 'other-holds', 'expired-holds', 'old-nonce', 'nan-time', 'fractional-time',
    'wrong-account', 'wrong-policy-version', 'orphaned-review', 'missing-asset', 'duplicate-asset', 'expired-plan'])(
    'rejects inconsistent current state: %s', async fault => {
      const { record, evidence, now } = await fixture(false);
      if (fault === 'spent-nonce') evidence.nonce.nonce = '1';
      if (fault === 'balance') evidence.balances.balances[0].amount_atomic = '0';
      if (fault === 'other-holds') evidence.holds.total_reserved[0].amount_atomic = '10001';
      if (fault === 'expired-holds') evidence.holds.expires_at = now;
      if (fault === 'old-nonce') evidence.nonce.observed_at = now - 10;
      if (fault === 'nan-time') evidence.holds.observed_at = NaN;
      if (fault === 'fractional-time') evidence.balances.observed_at = now - 0.5;
      if (fault === 'wrong-account') evidence.nonce.account = `0x${'aa'.repeat(20)}`;
      if (fault === 'wrong-policy-version') evidence.security.observation.security_version = '3';
      if (fault === 'orphaned-review') evidence.reviewed_block.target = { ...evidence.reviewed_block.target, block_hash: `0x${'ee'.repeat(32)}` };
      if (fault === 'missing-asset') evidence.balances.balances.pop();
      if (fault === 'duplicate-asset') evidence.balances.balances[1] = { ...evidence.balances.balances[0] };
      expect(() => assertTransferDeliveryState(record, evidence, fault === 'expired-plan' ? record.candidate.plan.validUntil : now)).toThrow();
    });
});
