import { deploymentDocumentDigest } from '@gatopago/shared/v3/deployment';
import { writeMoneyReview } from '@gatopago/shared/v3/money-review-record';
import { loadAaveMarket } from '@gatopago/shared/v3/aave-market';
import { finalityPolicyFixture } from '@gatopago/test-fixtures/v3-finality';
import { writeExecutionOperationRecord } from '../src/execution/executionOperationRecord';
import { MoneyRepository, moneyFunds } from '../src/money/moneyRepository';
import { createResourceId } from '@gatopago/shared/v3/primitives';
import { moneyConfirmationDigest } from '../src/money/moneyWire';
import type { MoneyDeliveryProfile } from '../src/money/moneyPreflight';
import { seedMoneyFixture } from './money.fixture';

export async function seedMoneyDelivery(database: D1Database, dispatch = true, historical = false) {
  const f = await seedMoneyFixture(database),
    repository = new MoneyRepository(database, f.identity, f.keys.input.scope, f.pins);
  const prepared = await repository.savePreparation(
    { candidate: f.candidate, review: f.review, send_enabled: false },
    'prepare',
  );
  const review = {
    ...f.review,
    approved_at: f.now,
    proofs: [
      {
        signerIndex: 0,
        kind: 'webauthn' as const,
        assertion: f.keys.assertion(f.candidate.digest),
      },
    ],
  };
  const record = writeMoneyReview(review),
    fingerprint = moneyConfirmationDigest(prepared.id, f.candidate.digest, review.proofs);
  const fresh = {
    consent_digest: f.candidate.digest,
    userop_hash: f.candidate.userOpHash,
    record_sha256: record.digest,
    checkpoint: f.context.checkpoint,
    checked_at: f.now,
    expires_at: f.now + 5,
    security_version: '1',
    usdc_balance_atomic: '100000000',
    position_balance_atomic: '100000000',
    native_balance_atomic: '1000000',
    nonce: '0',
    send_enabled: false as const,
  };

  let historicId;
  if (historical) {
    historicId = createResourceId('operation');
    const funds = moneyFunds(f.candidate);
    const row = {
      id: historicId,
      preparation_id: prepared.id,
      wallet_id: f.walletId,
      wallet_account_id: f.accountId,
      actor_id: f.identity.userId,
      confirm_key: 'confirm',
      confirmation_sha256: fingerprint,
      network_id: f.request.network_id,
      account_address: f.candidate.account.toLowerCase(),
      entry_point: f.candidate.plan.entryPoint.toLowerCase(),
      nonce: '0',
      consent_digest: f.candidate.digest,
      userop_hash: f.candidate.userOpHash,
      deployment_manifest_sha256: f.deployment,
      market_sha256: f.context.market.digest,
      review_json: record.json,
      review_sha256: record.digest,
      funds_json: funds.json,
      funds_sha256: funds.digest,
      authorized_auth_time: f.identity.authTime,
      state: 'authorized',
      created_at: f.now,
      expires_at: f.candidate.plan.validUntil,
    };
    await database
      .prepare(
        `INSERT INTO money_operations(${Object.keys(row).join(',')}) VALUES (${Object.keys(row)
          .map(() => '?')
          .join(',')})`,
      )
      .bind(...Object.values(row))
      .run();
  }
  const stored = historicId
      ? await repository.readOperation(f.walletId, f.accountId, historicId)
      : await repository.authorizeOperation(
          f.walletId,
          f.accountId,
          prepared.id,
          review,
          'confirm',
          fingerprint,
          fresh,
        ),
    c = stored.candidate;
  const payload = writeExecutionOperationRecord(stored.operation, {
    network_id: c.request.network_id,
    account: c.account,
    account_id: c.plan.accountId,
    entry_point: c.plan.entryPoint,
    userop_hash: c.userOpHash,
    consent_digest: c.digest,
    valid_until: c.plan.validUntil,
  });
  const preflight = {
    ...fresh,
    operation_id: stored.id,
    operation_sha256: payload.digest,
    simulation: {
      userop_hash: c.userOpHash,
      consent_digest: c.digest,
      operation_sha256: payload.digest,
      gas: { verificationGasLimit: '100', callGasLimit: '100', preVerificationGas: '100' },
      observed_at: f.now,
      expires_at: f.now + 5,
      send_enabled: false as const,
    },
  };
  if (dispatch) await repository.beginDelivery(f.walletId, f.accountId, stored.id, preflight);
  return { f, repository, stored, preflight, ...moneyTestProfile(f) };
}

export function moneyTestProfile(f: Awaited<ReturnType<typeof seedMoneyFixture>>) {
  const market = loadAaveMarket(f.context.market),
    policy = {
      ...finalityPolicyFixture(market, f.now),
      mechanism: 'arbitrum_l1_data_finalized' as const,
    };
  const policyDocument = JSON.stringify(policy);
  const profile: MoneyDeliveryProfile = {
    document: f.deploymentDocument,
    digest: f.deployment,
    market: f.context.market,
    finalityPolicy: { document: policyDocument, digest: deploymentDocumentDigest(policyDocument) },
    entryPointCodeHash: f.keys.profile.entry_point_code_hash,
    providers: [
      { operatorId: 'operator-a', url: 'https://a.example/rpc' },
      { operatorId: 'operator-b', url: 'https://b.example/rpc' },
    ],
    assetIds: [f.request.asset_id, f.context.native_asset_id],
    assetDisplay: {
      [f.request.asset_id]: { symbol: 'USDC', decimals: 6 },
      [f.context.native_asset_id]: { symbol: 'ETH', decimals: 18 },
    },
    features: { aave_supply: true, aave_withdraw: true, aave_withdraw_and_pay: true },
    gasByKind: {
      aave_supply: f.context.gas,
      aave_withdraw: f.context.gas,
      aave_withdraw_and_pay: f.context.gas,
    },
    transport: { kind: 'bundler', url: 'https://bundler.example/rpc' },
  };
  return { profile, policy, market };
}
