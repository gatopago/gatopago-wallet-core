import { isAddressEqual, toHex } from 'viem';
import { loadPinnedDeploymentManifest, requireHash } from '@gatopago/shared/v3/deployment';
import { assessCheckpointFinality, loadPinnedFinalityPolicy } from '@gatopago/shared/v3/finality';
import { hashSecurityPolicy } from '@gatopago/shared/v3/security-policy';
import {
  readMoneyDraft,
  writeMoneyDraft,
  writeMoneyReview,
  type MoneyConsentReview,
} from '@gatopago/shared/v3/money-review-record';
import type { ResourceId } from '@gatopago/shared/v3/primitives';
import { predictAccountAddress } from '@gatopago/shared/v3/authorizations';
import { WalletRepository } from '../accounts/repository';
import { createInspectionClient, inspectWalletSecurity } from '../chainInspection';
import { validateRpcProviders } from '../chainProviders';
import { observeAavePosition } from '../portfolio/aavePositionObservation';
import { rpcQuantity } from '../portfolio/checkpointReader';
import { observeTransferNonce } from '../transfers/transferNonce';
import type { Principal } from '../auth/principal';
import { withDeadline } from '../deadline';
import { assertMoneyBalanceFloor, type MoneyPreparationProfile } from './moneyPreparation';

export async function observeOwnedMoneyCurrent(
  database: D1Database,
  identityInput: Principal,
  walletId: ResourceId<'wallet'>,
  accountId: ResourceId<'walletAccount'>,
  reviewInput: Omit<MoneyConsentReview, 'approved_at' | 'proofs'> | MoneyConsentReview,
  profileInput: Omit<MoneyPreparationProfile, 'finalityEvidence'>,
  signal: AbortSignal,
) {
  const identity = Object.freeze({ ...identityInput }),
    review = structuredClone(reviewInput),
    profile = structuredClone(profileInput);
  const draft = writeMoneyDraft(review),
    record = readMoneyDraft(draft.json, draft.digest),
    candidate = record.candidate;
  const signedRecord = 'proofs' in review ? writeMoneyReview(review).digest : draft.digest;
  return withDeadline(signal, 30_000, async (deadline) => {
    const owner = () => new WalletRepository(database, identity).ownedAccount(walletId, accountId);
    const owned = await owner(),
      manifest = loadPinnedDeploymentManifest(profile.document, profile.digest);
    const policy = loadPinnedFinalityPolicy(profile.finalityPolicy, manifest),
      gas = profile.gasByKind[candidate.request.kind];
    const started = Math.floor(Date.now() / 1000);
    if (
      walletId !== candidate.request.wallet_id ||
      accountId !== candidate.request.wallet_account_id ||
      owned.account_id !== candidate.plan.accountId ||
      owned.deployment_manifest_sha256 !== candidate.deployment_digest ||
      profile.digest !== candidate.deployment_digest ||
      profile.market.digest !== review.context.market.digest ||
      profile.market.document !== review.context.market.document ||
      manifest.network_id !== candidate.request.network_id ||
      owned.network_id !== candidate.request.network_id ||
      manifest.lifecycle_status !== 'deployed' ||
      !isAddressEqual(owned.address, candidate.account) ||
      !isAddressEqual(
        predictAccountAddress(
          manifest.components.factory.address,
          owned.account_id,
          manifest.proxy.init_code_hash,
        ),
        candidate.account,
      )
    )
      throw new Error('MONEY_REVIEW_MISMATCH');
    if (
      !profile.features[candidate.request.kind] ||
      !gas ||
      Object.keys(gas).some(
        (key) => gas[key as keyof typeof gas] !== review.context.gas[key as keyof typeof gas],
      )
    )
      throw new Error('MONEY_CAPABILITY_UNAVAILABLE');
    if (
      started < review.prepared_at ||
      started >= candidate.plan.validUntil ||
      started >= identity.expiresAt ||
      started < policy.valid_from ||
      started >= policy.valid_until
    )
      throw new Error('MONEY_REVIEW_EXPIRED');
    const peers = validateRpcProviders(profile.providers),
      clients = peers.map((peer) => createInspectionClient(peer.url, deadline));
    const reviewedTag = toHex(BigInt(candidate.checkpoint.block_number));
    const historical = await clients[0].request(
      { method: 'eth_getBlockByNumber', params: [reviewedTag, false] },
      { retryCount: 0, dedupe: false },
    );
    if (
      !historical ||
      historical.number !== reviewedTag ||
      historical.hash !== candidate.checkpoint.block_hash
    )
      throw new Error('MONEY_REVIEW_ORPHANED');
    const historicalTarget = {
      ...candidate.checkpoint,
      block_timestamp: rpcQuantity(historical.timestamp).toString(),
      network_id: manifest.network_id,
      genesis_hash: manifest.genesis_hash,
    };
    const finality = await assessCheckpointFinality(
      clients,
      historicalTarget,
      profile.finalityPolicy,
      deadline,
    );
    if (finality.status !== 'finalized' || !finality.checkpoint)
      throw new Error('MONEY_REVIEW_ORPHANED');
    const heads = await Promise.all(
      clients.map((client) =>
        client.request(
          { method: 'eth_getBlockByNumber', params: ['latest', false] },
          { retryCount: 0, dedupe: false },
        ),
      ),
    );
    const heights = heads.map((head) => {
      if (!head) throw new Error('MONEY_HEAD_UNAVAILABLE');
      return rpcQuantity(head.number);
    });
    const height = heights[0] < heights[1] ? heights[0] : heights[1],
      tag = toHex(height);
    const selected = await Promise.all(
      clients.map((client) =>
        client.request(
          { method: 'eth_getBlockByNumber', params: [tag, false] },
          { retryCount: 0, dedupe: false },
        ),
      ),
    );
    const first = selected[0],
      second = selected[1];
    if (
      !first ||
      !second ||
      first.number !== tag ||
      second.number !== tag ||
      first.hash !== second.hash ||
      first.timestamp !== second.timestamp
    )
      throw new Error('MONEY_HEAD_DISAGREEMENT');
    requireHash(first.hash);
    const timestamp = rpcQuantity(first.timestamp),
      now = BigInt(Math.floor(Date.now() / 1000));
    if (
      timestamp > now + BigInt(policy.max_clock_skew_seconds) ||
      now - timestamp > BigInt(policy.max_latest_age_seconds) ||
      height < BigInt(finality.checkpoint.block_number)
    )
      throw new Error('MONEY_HEAD_UNAVAILABLE');
    const checkpoint = { block_number: height.toString(), block_hash: first.hash };
    const results = await Promise.allSettled([
      inspectWalletSecurity(
        {
          document: profile.document,
          expectedDigest: profile.digest,
          initialSecurityCommitment: owned.initial_security_commitment,
          userSaltCommitment: owned.user_salt_commitment,
          checkpoint,
        },
        peers.map((peer) => peer.url),
        deadline,
      ),
      observeAavePosition(
        { account: candidate.account, market: profile.market, checkpoint },
        peers,
        deadline,
      ),
      observeTransferNonce(
        {
          network_id: manifest.network_id,
          genesis_hash: manifest.genesis_hash,
          account: candidate.account,
          entry_point: candidate.plan.entryPoint,
          entry_point_code_hash: profile.entryPointCodeHash,
          checkpoint,
        },
        peers,
        deadline,
      ),
    ]);
    deadline.throwIfAborted();
    const [security, position, nonce] = results;
    if (
      security.status !== 'fulfilled' ||
      position.status !== 'fulfilled' ||
      nonce.status !== 'fulfilled'
    )
      throw new Error('MONEY_CURRENT_STATE_UNAVAILABLE');
    const authority = security.value,
      financial = position.value,
      sequence = nonce.value;
    if (
      authority.status !== 'recognized' ||
      authority.security.phase !== 'active_policy' ||
      authority.security_version !== candidate.plan.securityVersion.toString() ||
      hashSecurityPolicy(authority.security.policy) !== candidate.policy_hash ||
      hashSecurityPolicy(review.policy) !== candidate.policy_hash
    )
      throw new Error('MONEY_SECURITY_CHANGED');
    if (
      sequence.nonce !== candidate.plan.nonce.toString() ||
      !isAddressEqual(sequence.account, candidate.account) ||
      !isAddressEqual(sequence.entry_point, candidate.plan.entryPoint)
    )
      throw new Error('MONEY_NONCE_CHANGED');
    for (const value of [authority, financial, sequence]) {
      if (
        value.checkpoint.block_number !== checkpoint.block_number ||
        value.checkpoint.block_hash !== checkpoint.block_hash
      )
        throw new Error('MONEY_CHECKPOINT_MISMATCH');
    }
    if (
      !financial.active ||
      financial.paused ||
      (candidate.request.kind === 'aave_supply' && financial.frozen)
    )
      throw new Error('MONEY_MARKET_UNAVAILABLE');
    if (financial.debt_base_atomic !== '0') throw new Error('MONEY_DEBT_NOT_SUPPORTED');
    const amount = BigInt(candidate.request.amount_atomic);
    if (candidate.request.kind === 'aave_supply') {
      if (
        BigInt(financial.usdc_balance_atomic) < amount ||
        (financial.supply_capacity_atomic !== null &&
          BigInt(financial.supply_capacity_atomic) < amount)
      )
        throw new Error('MONEY_SUPPLY_FUNDS_INSUFFICIENT');
    } else if (
      BigInt(financial.position_balance_atomic) < amount ||
      BigInt(financial.liquidity_atomic) < amount
    )
      throw new Error('MONEY_WITHDRAW_FUNDS_INSUFFICIENT');
    if (
      BigInt(financial.native_balance_atomic) < BigInt(candidate.funding.maximum_native_gas_atomic)
    )
      throw new Error('MONEY_GAS_FUNDS_INSUFFICIENT');
    await assertMoneyBalanceFloor(database, accountId, checkpoint);
    const closing = await Promise.all(
      clients.map((client) =>
        client.request(
          { method: 'eth_getBlockByNumber', params: [tag, false] },
          { retryCount: 0, dedupe: false },
        ),
      ),
    );
    if (
      closing.some(
        (block) =>
          !block ||
          block.hash !== checkpoint.block_hash ||
          block.number !== tag ||
          block.timestamp !== first.timestamp,
      )
    )
      throw new Error('MONEY_HEAD_ORPHANED');
    const current = await owner(),
      checked = Math.floor(Date.now() / 1000);
    deadline.throwIfAborted();
    const expires = Math.min(
      checked + 5,
      candidate.plan.validUntil,
      identity.expiresAt,
      finality.expires_at,
      financial.expires_at,
    );
    if (
      JSON.stringify(current) !== JSON.stringify(owned) ||
      checked < started ||
      checked >= expires ||
      BigInt(checked) - timestamp > BigInt(policy.max_latest_age_seconds)
    )
      throw new Error('MONEY_CURRENT_STATE_EXPIRED');
    return Object.freeze({
      consent_digest: candidate.digest,
      userop_hash: candidate.userOpHash,
      record_sha256: signedRecord,
      checkpoint,
      checked_at: checked,
      expires_at: expires,
      security_version: authority.security_version,
      usdc_balance_atomic: financial.usdc_balance_atomic,
      position_balance_atomic: financial.position_balance_atomic,
      native_balance_atomic: financial.native_balance_atomic,
      nonce: sequence.nonce,
      send_enabled: false as const,
    });
  });
}
