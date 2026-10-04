import { loadPinnedDeploymentManifest } from '@gatopago/shared/v3/deployment';
import type { FinalityAssessment } from '@gatopago/shared/v3/finality';
import type { MoneyKind } from '@gatopago/shared/v3/money-wire';
import { hashSecurityPolicy } from '@gatopago/shared/v3/security-policy';
import type { inspectWalletSecurity } from '../src/chainInspection';
import type { inspectOwnedAavePosition } from '../src/portfolio/aavePosition';
import { seedMoneyFixture } from './money.fixture';
import { moneyTestProfile } from './moneyDelivery.fixture';

export async function clearMoneyTestRows(database: D1Database) {
  await database.exec(`DELETE FROM money_reconciliations; DELETE FROM money_finality_conflicts; DELETE FROM money_finality_journal; DELETE FROM money_expirations;
    DELETE FROM money_operations; DELETE FROM money_preparations; DELETE FROM user_operation_submissions;
    DELETE FROM transfer_reconciliations; DELETE FROM wallet_balance_floors; DELETE FROM transfer_finality_conflicts;
    DELETE FROM transfer_finality_journal; DELETE FROM transfer_nonce_reservations; DELETE FROM wallet_accounts;
    DELETE FROM wallets; DELETE FROM webauthn_credentials; DELETE FROM users;`);
}

export async function moneyOwnedFixture(database: D1Database, kind: MoneyKind = 'aave_supply') {
  const f = await seedMoneyFixture(database, kind),
    { profile, policy, market } = moneyTestProfile(f);
  const manifest = loadPinnedDeploymentManifest(profile.document, profile.digest);
  const block = {
    block_hash: f.context.checkpoint.block_hash,
    block_number: f.context.checkpoint.block_number,
    block_timestamp: String(f.now),
  };
  const evidence: FinalityAssessment = {
    schema_version: 1,
    status: 'finalized',
    policy_sha256: profile.finalityPolicy.digest,
    mechanism: policy.mechanism,
    network_id: f.request.network_id,
    genesis_hash: market.genesis_hash,
    target: block,
    checkpoint: block,
    assessed_at: f.now,
    expires_at: f.now + 10,
  };
  const security: Extract<
    Awaited<ReturnType<typeof inspectWalletSecurity>>,
    { status: 'recognized' }
  > = {
    status: 'recognized',
    account: f.candidate.account,
    account_id: f.candidate.plan.accountId,
    network_id: f.request.network_id,
    manifest_id: manifest.manifest_id,
    manifest_sha256: profile.digest,
    checkpoint: block,
    spend_readiness: 'not_assessed',
    providers_agree: true,
    implementation: manifest.components.implementation.address,
    security_version: '1',
    storage_layout_hash: manifest.storage_layout_hash,
    security: {
      phase: 'active_policy',
      manifest_hash: f.hash,
      chain_scope_hash: f.hash,
      policy_hash: hashSecurityPolicy(f.review.policy),
      policy: structuredClone(f.review.policy),
      upgrades_frozen: false,
      creation_valid_after: 0,
      creation_valid_until: f.now + 30,
      nonces: { spend: '0', admin: '0' },
      pending: null,
    },
  };
  const authority = {
    ...security,
    wallet_id: f.walletId,
    wallet_account_id: f.accountId,
    finality: 'finalized' as const,
    finality_evidence: evidence,
    security_observed_at: f.now,
    security_expires_at: f.now + 10,
  };
  const position: Awaited<ReturnType<typeof inspectOwnedAavePosition>> = {
    wallet_id: f.walletId,
    wallet_account_id: f.accountId,
    network_id: f.request.network_id,
    market_id: market.market_id,
    market_digest: profile.market.digest,
    asset_id: f.request.asset_id,
    a_token: market.a_token,
    account: f.candidate.account,
    checkpoint: block,
    observed_at: f.now,
    expires_at: f.now + 10,
    usdc_balance_atomic: '100000000',
    native_balance_atomic: '1000000',
    position_balance_atomic: '100000019',
    scaled_position_atomic: '100000000',
    liquidity_index_ray: '1000000000000000000000000001',
    debt_base_atomic: '0',
    liquidity_atomic: '100000000',
    supply_capacity_atomic: null,
    allowance_atomic: '0',
    active: true,
    frozen: false,
    paused: false,
    finality: 'finalized',
    finality_evidence: evidence,
    spend_readiness: 'not_assessed',
    available_balance: 'not_assessed',
  };
  const nonce = {
    network_id: f.request.network_id,
    account: f.candidate.account,
    entry_point: f.candidate.plan.entryPoint,
    checkpoint: block,
    nonce: '0',
    observed_at: f.now,
  };
  return {
    f,
    profile: { ...profile, finalityEvidence: evidence },
    policy,
    market,
    manifest,
    block,
    evidence,
    authority,
    security,
    position,
    nonce,
  };
}
