import type { Hex } from 'viem';
import type { ResourceId } from '@gatopago/shared/v3/primitives';
import {
  readMoneyReview,
  writeMoneyReview,
  type MoneyProof,
} from '@gatopago/shared/v3/money-review-record';
import { verifyTransferQuorum } from '@gatopago/shared/v3/transfer-authorization';
import type { WebAuthnScope } from '@gatopago/shared/v3/webauthn';
import type { Principal } from '../auth/principal';
import { withDeadline } from '../deadline';
import { observeOwnedMoneyCurrent } from './moneyCurrentState';
import { MoneyRepository, moneyIdempotencyKey } from './moneyRepository';
import type { MoneyPreparationProfile } from './moneyPreparation';
import { moneyConfirmationDigest } from './moneyWire';

/** SPEND verifies the exact stored review. HTTP provides public assertions, never
 * a replacement context, market, policy, nonce, fee or RPC provider. */
export async function confirmOwnedMoney(
  database: D1Database,
  identityInput: Principal,
  walletId: ResourceId<'wallet'>,
  accountId: ResourceId<'walletAccount'>,
  preparationId: ResourceId<'operation'>,
  consentDigest: Hex,
  proofsInput: readonly MoneyProof[],
  keyInput: unknown,
  scopeInput: WebAuthnScope,
  profilesInput: readonly Omit<MoneyPreparationProfile, 'finalityEvidence'>[],
  signal: AbortSignal,
) {
  const identity = Object.freeze({ ...identityInput }),
    profiles = structuredClone(profilesInput),
    scope = { ...scopeInput },
    proofs = structuredClone(proofsInput);
  const key = moneyIdempotencyKey(keyInput),
    fingerprint = moneyConfirmationDigest(preparationId, consentDigest, proofs);
  return withDeadline(signal, 30_000, async (deadline) => {
    const repository = new MoneyRepository(
      database,
      identity,
      scope,
      profiles.map((profile) => ({ deployment: profile.digest, market: profile.market.digest })),
    );
    const prepared = await repository.readPreparation(walletId, accountId, preparationId);
    if (prepared.candidate.digest !== consentDigest) throw new Error('MONEY_REVIEW_MISMATCH');
    await verifyTransferQuorum(consentDigest, prepared.review.policy, scope, proofs);
    deadline.throwIfAborted();
    const prior = await repository.findConfirmation(walletId, accountId, key, fingerprint);
    if (prior) {
      if (prior.preparation_id !== preparationId || prior.candidate.digest !== consentDigest)
        throw new Error('MONEY_IDEMPOTENCY_CONFLICT');
      return {
        id: prior.id,
        preparation_id: preparationId,
        consent_digest: consentDigest,
        state: prior.state,
        expires_at: prior.candidate.plan.validUntil,
        send_enabled: false as const,
      };
    }
    const matching = profiles.filter(
      (profile) =>
        profile.digest === prepared.candidate.deployment_digest &&
        profile.market.digest === prepared.review.context.market.digest,
    );
    if (matching.length !== 1) throw new Error('MONEY_PROFILE_UNAVAILABLE');
    const approved = Math.floor(Date.now() / 1000);
    if (prepared.state !== 'prepared' || approved >= prepared.candidate.plan.validUntil)
      throw new Error('MONEY_REVIEW_EXPIRED');
    const review = { ...prepared.review, approved_at: approved, proofs },
      record = writeMoneyReview(review);
    await readMoneyReview(record.json, record.digest);
    const fresh = await observeOwnedMoneyCurrent(
      database,
      identity,
      walletId,
      accountId,
      review,
      matching[0],
      deadline,
    );
    deadline.throwIfAborted();
    const current = await repository.readPreparation(walletId, accountId, preparationId);
    if (current.record_sha256 !== prepared.record_sha256)
      throw new Error('MONEY_CONFIRMATION_CHANGED');
    const stored = await repository.authorizeOperation(
      walletId,
      accountId,
      preparationId,
      review,
      key,
      fingerprint,
      fresh,
    );
    return {
      id: stored.id,
      preparation_id: preparationId,
      consent_digest: consentDigest,
      state: stored.state,
      expires_at: stored.candidate.plan.validUntil,
      send_enabled: false as const,
    };
  });
}
