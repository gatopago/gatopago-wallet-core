import { isAddressEqual } from 'viem';
import { loadPinnedDeploymentManifest } from '@gatopago/shared/v3/deployment';
import {
  assertFinalityAssessment,
  loadPinnedFinalityPolicy,
  type FinalityAssessment,
} from '@gatopago/shared/v3/finality';
import { assertAssetNetwork, parseAtomicAmount } from '@gatopago/shared/v3/primitives';
import {
  assertCurrentTransferSecurity,
  type TransferSecurityEvidence,
} from '@gatopago/shared/v3/transfer-security';
import type { inspectOwnedWalletBalances } from '../portfolio/balances';
import type { observeTransferNonce } from './transferNonce';
import type { TransferNonceReservationRepository } from './transferNonceReservation';
import type { readTransferReview } from '@gatopago/shared/v3/transfer-review-record';

export interface TransferDeliveryEvidence {
  readonly security: TransferSecurityEvidence;
  readonly reviewed_block: FinalityAssessment;
  readonly balances: Awaited<ReturnType<typeof inspectOwnedWalletBalances>>;
  readonly nonce: Awaited<ReturnType<typeof observeTransferNonce>>;
  readonly holds: Awaited<ReturnType<TransferNonceReservationRepository['deliveryFundsSnapshot']>>;
}

export function assertTransferDeliveryState(
  record: Awaited<ReturnType<typeof readTransferReview>>,
  input: TransferDeliveryEvidence,
  now: number,
) {
  const evidence = structuredClone(input),
    candidate = record.candidate,
    approvedAt = record.review.approved_at;
  if (!Number.isSafeInteger(now) || now < approvedAt || now >= candidate.plan.validUntil)
    throw new Error('TRANSFER_DELIVERY_EXPIRED');
  const security = evidence.security;
  assertCurrentTransferSecurity(candidate, security, now);
  if (security.observed_at < approvedAt) throw new Error('TRANSFER_DELIVERY_STALE');
  const manifest = loadPinnedDeploymentManifest(security.document, security.digest);
  const policy = loadPinnedFinalityPolicy(security.finality_policy, manifest);
  const checkpoint = security.finality.target;
  function finality(value: FinalityAssessment, target: FinalityAssessment['target']) {
    assertFinalityAssessment(value, {
      ...target,
      network_id: manifest.network_id,
      genesis_hash: manifest.genesis_hash,
    });
    if (
      value.status !== 'finalized' ||
      value.policy_sha256 !== security.finality_policy.digest ||
      value.mechanism !== policy.mechanism ||
      value.assessed_at < approvedAt ||
      value.assessed_at < policy.valid_from ||
      value.assessed_at > now ||
      now >= value.expires_at ||
      value.expires_at >
        Math.min(policy.valid_until, value.assessed_at + policy.evidence_ttl_seconds) ||
      BigInt(value.target.block_timestamp) > BigInt(now + policy.max_clock_skew_seconds) ||
      BigInt(now) - BigInt(value.target.block_timestamp) > BigInt(policy.max_finalized_age_seconds)
    )
      throw new Error('TRANSFER_DELIVERY_FINALITY');
  }
  finality(security.finality, checkpoint);
  const acknowledgement = evidence.reviewed_block;
  finality(acknowledgement, {
    ...acknowledgement.target,
    block_hash: candidate.checkpoint.block_hash,
    block_number: candidate.checkpoint.block_number,
  });
  if (
    !acknowledgement.checkpoint ||
    BigInt(acknowledgement.checkpoint.block_number) < BigInt(checkpoint.block_number) ||
    (acknowledgement.checkpoint.block_number === checkpoint.block_number &&
      acknowledgement.checkpoint.block_hash !== checkpoint.block_hash)
  ) {
    throw new Error('TRANSFER_DELIVERY_REVIEW_ORPHANED');
  }
  const balances = evidence.balances,
    nonce = evidence.nonce,
    holds = evidence.holds;
  if (
    ![
      balances.observed_at,
      balances.expires_at,
      nonce.observed_at,
      holds.observed_at,
      holds.expires_at,
    ].every(Number.isSafeInteger)
  ) {
    throw new Error('TRANSFER_DELIVERY_STALE');
  }
  finality(balances.finality_evidence, checkpoint);
  if (
    balances.wallet_id !== candidate.request.wallet_id ||
    balances.wallet_account_id !== holds.wallet_account_id ||
    balances.network_id !== candidate.request.network_id ||
    !isAddressEqual(balances.address, candidate.account) ||
    balances.checkpoint.block_number !== checkpoint.block_number ||
    balances.checkpoint.block_hash !== checkpoint.block_hash ||
    balances.checkpoint.block_timestamp !== checkpoint.block_timestamp ||
    balances.observed_at < approvedAt ||
    balances.observed_at > now ||
    now >= balances.expires_at ||
    balances.expires_at > Math.min(balances.finality_evidence.expires_at, balances.observed_at + 60)
  ) {
    throw new Error('TRANSFER_DELIVERY_BALANCE');
  }
  if (
    nonce.network_id !== candidate.request.network_id ||
    !isAddressEqual(nonce.account, candidate.account) ||
    !isAddressEqual(nonce.entry_point, candidate.plan.entryPoint) ||
    nonce.nonce !== candidate.plan.nonce.toString() ||
    nonce.checkpoint.block_number !== checkpoint.block_number ||
    nonce.checkpoint.block_hash !== checkpoint.block_hash ||
    nonce.observed_at < approvedAt ||
    nonce.observed_at > now ||
    now - nonce.observed_at >= 60
  )
    throw new Error('TRANSFER_DELIVERY_NONCE');
  if (
    holds.wallet_id !== candidate.request.wallet_id ||
    holds.network_id !== candidate.request.network_id ||
    !isAddressEqual(holds.account, candidate.account) ||
    holds.userop_hash !== candidate.userOpHash ||
    holds.consent_digest !== candidate.digest ||
    holds.observed_at < approvedAt ||
    holds.observed_at > now ||
    now >= holds.expires_at ||
    holds.expires_at > Math.min(holds.observed_at + 5, candidate.plan.validUntil)
  )
    throw new Error('TRANSFER_DELIVERY_HOLDS');
  const relevant = new Set([candidate.request.asset_id, record.review.context.native_asset_id]);
  if (
    holds.own_funds.length !== relevant.size ||
    holds.total_reserved.length !== relevant.size ||
    balances.balances.length < relevant.size ||
    balances.balances.length > 16
  )
    throw new Error('TRANSFER_DELIVERY_HOLDS');
  const observed = new Map<string, bigint>(),
    reserved = new Map<string, bigint>();
  for (const asset of balances.balances) {
    assertAssetNetwork(asset.asset_id, candidate.request.network_id);
    if (observed.has(asset.asset_id)) throw new Error('TRANSFER_DELIVERY_BALANCE');
    observed.set(asset.asset_id, BigInt(parseAtomicAmount(asset.amount_atomic)));
  }
  for (const term of holds.total_reserved) {
    if (!relevant.has(term.asset_id) || reserved.has(term.asset_id))
      throw new Error('TRANSFER_DELIVERY_HOLDS');
    reserved.set(term.asset_id, BigInt(parseAtomicAmount(term.amount_atomic)));
  }
  const own = new Set<string>();
  for (const term of holds.own_funds) {
    const expected =
      term.asset_id === candidate.request.asset_id
        ? candidate.funding.asset_debit_atomic
        : (
            BigInt(record.review.context.budget.native_available_atomic) -
            BigInt(candidate.funding.native_remaining_atomic)
          ).toString();
    const total = reserved.get(term.asset_id),
      balance = observed.get(term.asset_id);
    if (
      !relevant.has(term.asset_id) ||
      own.has(term.asset_id) ||
      term.debit_atomic !== expected ||
      total === undefined ||
      balance === undefined ||
      total < BigInt(expected) ||
      balance < total
    )
      throw new Error('TRANSFER_DELIVERY_INSUFFICIENT_FUNDS');
    own.add(term.asset_id);
  }
  return Object.freeze({
    userop_hash: candidate.userOpHash,
    consent_digest: candidate.digest,
    checkpoint: Object.freeze({ ...checkpoint }),
    checked_at: now,
    expires_at: Math.min(
      candidate.plan.validUntil,
      security.expires_at,
      security.finality.expires_at,
      acknowledgement.expires_at,
      balances.expires_at,
      holds.expires_at,
      nonce.observed_at + 60,
    ),
    send_enabled: false as const,
  });
}
