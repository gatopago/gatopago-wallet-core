import { afterEach, describe, expect, it, vi } from 'vitest';
import type { Hex } from 'viem';
import * as finality from '@gatopago/shared/v3/finality';
import { finalityPolicyFixture } from '@gatopago/test-fixtures/v3-finality';
import { deploymentDocumentDigest } from '@gatopago/shared/v3/deployment';
import * as inspection from '../src/chainInspection';
import * as receiptAccount from '../src/execution/receiptAccount';
import * as transport from '../src/execution/operationTransport';
import * as positionReader from '../src/portfolio/aavePositionObservation';
import { observeMoneySource } from '../src/money/moneyObservation';
import type { MoneyDeliveryProfile } from '../src/money/moneyPreflight';
import { createMoneyReceiptFixture } from './moneyReceipt.fixture';

afterEach(() => vi.restoreAllMocks());
async function fixture(success = true) {
  const f = await createMoneyReceiptFixture('aave_supply', success),
    c = f.record.candidate;
  const policy = {
    ...finalityPolicyFixture(f.market, f.f.now),
    mechanism: 'arbitrum_l1_data_finalized' as const,
  };
  const document = JSON.stringify(policy);
  const profile: MoneyDeliveryProfile = {
    document: f.f.deploymentDocument,
    digest: f.f.deployment,
    market: f.f.context.market,
    finalityPolicy: { document, digest: deploymentDocumentDigest(document) },
    entryPointCodeHash: f.f.keys.profile.entry_point_code_hash,
    providers: [
      { operatorId: 'operator-a', url: 'https://a.example/rpc' },
      { operatorId: 'operator-b', url: 'https://b.example/rpc' },
    ],
    assetIds: [f.f.request.asset_id, f.f.context.native_asset_id],
    assetDisplay: {},
    features: { aave_supply: true, aave_withdraw: true, aave_withdraw_and_pay: true },
    gasByKind: { aave_supply: f.f.context.gas, aave_withdraw: null, aave_withdraw_and_pay: null },
    transport: { kind: 'bundler', url: 'https://bundler.example/rpc' },
  };
  const block = {
    block_hash: f.receipt.blockHash,
    block_number: '124',
    block_timestamp: String(f.f.now),
  };
  const evidence: finality.FinalityAssessment = {
    schema_version: 1,
    status: 'finalized',
    policy_sha256: profile.finalityPolicy.digest,
    mechanism: policy.mechanism,
    network_id: c.request.network_id,
    genesis_hash: f.market.genesis_hash,
    target: block,
    checkpoint: block,
    assessed_at: f.f.now,
    expires_at: f.f.now + 10,
  };
  const position: Awaited<ReturnType<typeof positionReader.observeAavePosition>> = {
    network_id: c.request.network_id,
    market_id: f.market.market_id,
    market_digest: profile.market.digest,
    asset_id: c.request.asset_id,
    a_token: f.market.a_token,
    account: c.account,
    checkpoint: block,
    observed_at: f.f.now,
    expires_at: f.f.now + 10,
    usdc_balance_atomic: '80000000',
    native_balance_atomic: '1000000',
    position_balance_atomic: '120000019',
    scaled_position_atomic: '120000000',
    liquidity_index_ray: '1000000000000000000000000001',
    debt_base_atomic: '0',
    liquidity_atomic: '100000000',
    supply_capacity_atomic: null,
    allowance_atomic: '0',
    active: true,
    frozen: false,
    paused: false,
    finality: 'not_assessed',
    spend_readiness: 'not_assessed',
  };
  const source = vi.fn(async () => ({
    record: f.record,
    context: 'unchanged',
    initialSecurityCommitment: f.f.initial.message.initialSecurityCommitment,
    userSaltCommitment: f.f.initial.message.userSaltCommitment,
  }));
  const requests = [
    vi.fn(async () => structuredClone(f.receipt) as typeof f.receipt | null),
    vi.fn(async () => structuredClone(f.receipt) as typeof f.receipt | null),
  ];
  let next = 0;
  vi.spyOn(inspection, 'createInspectionClient').mockImplementation(
    () =>
      ({ request: requests[next++] }) as unknown as ReturnType<
        typeof inspection.createInspectionClient
      >,
  );
  const submitted = vi.spyOn(transport, 'submissionTransaction').mockResolvedValue(f.f.hash);
  const account = vi
    .spyOn(receiptAccount, 'inspectReceiptAccount')
    .mockResolvedValue(String(f.f.now));
  const finalized = vi.spyOn(finality, 'assessCheckpointFinality').mockResolvedValue(evidence);
  const readPosition = vi.spyOn(positionReader, 'observeAavePosition').mockResolvedValue(position);
  const controller = new AbortController();
  return {
    ...f,
    profile,
    source,
    requests,
    submitted,
    account,
    finalized,
    readPosition,
    position,
    evidence,
    controller,
    run: (profiles: readonly MoneyDeliveryProfile[] = [profile]) =>
      observeMoneySource({} as D1Database, source, profiles, controller.signal),
  };
}

describe('Bilateral monetary receipt observation', () => {
  it.each([true, false])(
    'proves the scoped receipt and closes finality; success=%s',
    async (success) => {
      const f = await fixture(success),
        result = await f.run();
      expect(result).toMatchObject({
        status: 'observed',
        receipt: {
          amount_atomic: '20000000',
          outcome: success ? 'execution_succeeded' : 'execution_reverted',
        },
        position: { allowance_atomic: '0' },
      });
      expect(f.source).toHaveBeenCalledTimes(2);
      expect(f.finalized).toHaveBeenCalledTimes(2);
      for (const request of f.requests)
        expect(request).toHaveBeenCalledWith(
          { method: 'eth_getTransactionReceipt', params: [f.f.hash] },
          { retryCount: 0, dedupe: false },
        );
      expect(f.readPosition).toHaveBeenCalledWith(
        {
          account: f.record.candidate.account,
          market: f.profile.market,
          checkpoint: { block_hash: f.receipt.blockHash, block_number: '124' },
        },
        f.profile.providers,
        expect.any(AbortSignal),
      );
    },
  );
  it.each([
    'no-journal',
    'both-missing',
    'one-missing',
    'rpc-error',
    'gas-disagreement',
    'account-mismatch',
    'principal-mismatch',
  ])('retains uncertainty for %s', async (fault) => {
    const f = await fixture();
    if (fault === 'no-journal') f.submitted.mockResolvedValue(null);
    if (fault === 'both-missing') f.requests.forEach((request) => request.mockResolvedValue(null));
    if (fault === 'one-missing') f.requests[1].mockResolvedValue(null);
    if (fault === 'rpc-error') f.requests[1].mockRejectedValue(new Error('Synthetic RPC outage'));
    if (fault === 'account-mismatch')
      f.account.mockRejectedValue(new Error('Unknown account composition'));
    if (fault === 'principal-mismatch') {
      f.logs[3].data = f.amount(1n);
      f.reindex();
    }
    if (fault === 'gas-disagreement') {
      const different = structuredClone(f.receipt);
      different.logs.at(-1)!.data = different.logs
        .at(-1)!
        .data.replace(/0000000000000064/, '0000000000000065') as Hex;
      f.requests[1].mockResolvedValue(different);
    }
    const result = await f.run();
    expect(result.status).toBe(
      ['no-journal', 'both-missing'].includes(fault)
        ? 'not_observed'
        : ['one-missing', 'gas-disagreement'].includes(fault)
          ? 'disagreement'
          : 'unavailable',
    );
    expect(f.readPosition).not.toHaveBeenCalled();
    expect(f.source).toHaveBeenCalledTimes(2);
  });
  it('returns an unfinalized observation without asserting a position', async () => {
    const f = await fixture();
    f.finalized.mockResolvedValue({ ...f.evidence, status: 'pending' });
    expect(await f.run()).toMatchObject({
      status: 'observed',
      position: null,
      finality: { status: 'pending' },
    });
    expect(f.readPosition).not.toHaveBeenCalled();
  });
  it.each([
    'allowance',
    'position-error',
    'position-stale',
    'position-future',
    'closing-pending',
    'closing-error',
    'closing-stale',
    'initial-stale',
  ])('refuses release evidence with %s', async (fault) => {
    const f = await fixture();
    if (fault === 'allowance') f.position.allowance_atomic = '1';
    if (fault === 'position-error')
      f.readPosition.mockRejectedValue(new Error('Changed Aave implementation'));
    if (fault === 'position-stale') f.position.expires_at = f.f.now;
    if (fault === 'position-future') f.position.observed_at = f.f.now + 1;
    if (fault === 'initial-stale')
      f.finalized.mockResolvedValueOnce({ ...f.evidence, expires_at: f.f.now });
    if (fault.startsWith('closing-')) {
      f.finalized.mockResolvedValueOnce(f.evidence);
      if (fault === 'closing-error')
        f.finalized.mockRejectedValueOnce(new Error('Closing RPC outage'));
      else
        f.finalized.mockResolvedValueOnce({
          ...f.evidence,
          ...(fault === 'closing-pending'
            ? { status: 'pending' as const }
            : { expires_at: f.f.now }),
        });
    }
    expect(await f.run()).toEqual({ status: 'unavailable' });
  });
  it('rejects a changed owner/job source after RPCs', async () => {
    const f = await fixture(),
      original = await f.source();
    f.source
      .mockResolvedValueOnce(original)
      .mockResolvedValueOnce({ ...original, context: 'changed' });
    await expect(f.run()).rejects.toThrow('MONEY_OBSERVATION_CHANGED');
  });
  it('rejects an unmatched manifest before reading a receipt', async () => {
    const f = await fixture();
    await expect(f.run([{ ...f.profile, digest: `0x${'33'.repeat(32)}` as Hex }])).rejects.toThrow(
      'MONEY_OBSERVATION_PROFILE',
    );
    expect(f.submitted).not.toHaveBeenCalled();
  });
  it('propagates cancellation after the receipt without claiming unavailability', async () => {
    const f = await fixture();
    f.readPosition.mockImplementation(async () => {
      f.controller.abort();
      return f.position;
    });
    await expect(f.run()).rejects.toMatchObject({ name: 'AbortError' });
  });
});
