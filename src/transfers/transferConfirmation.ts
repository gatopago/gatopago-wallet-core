import { validateRpcProviders } from '../chainProviders';
import { toHex, type Hex } from 'viem';
import { loadPinnedDeploymentManifest, requireHash } from '@gatopago/shared/v3/deployment';
import { assessCheckpointFinality } from '@gatopago/shared/v3/finality';
import type { ResourceId } from '@gatopago/shared/v3/primitives';
import {
  authorizeTransferOperation,
  verifyTransferQuorum,
} from '@gatopago/shared/v3/transfer-authorization';
import type { WebAuthnScope } from '@gatopago/shared/v3/webauthn';
import type { Principal } from '../auth/principal';
import { createInspectionClient, inspectWalletSecurity } from '../chainInspection';
import { withDeadline } from '../deadline';

import { observeAccountBalances } from '../portfolio/balanceObservation';
import { WalletRepository } from '../accounts/repository';
import type { TransferDeliveryProfile } from './transferDeliveryObservation';
import { observeTransferNonce } from './transferNonce';
import { TransferNonceReservationRepository } from './transferNonceReservation';
import { TransferPreparationRepository } from './transferPreparations';
import { writeTransferDraft } from '@gatopago/shared/v3/transfer-review-record';

/** Confirmation restores economic context exclusively from the owned draft.
 * Browser inputs are its locator, reviewed digest and public-key proofs, never
 * balances/policy/nonce/costs. Profiles and scope are internal admission.
 * Re-observe the original block without extending the signed validity window.
 * Current-head checks and signed simulation still precede actual delivery. */
export async function confirmOwnedTransfer(
  database: D1Database,
  identityInput: Principal,
  walletId: ResourceId<'wallet'>,
  accountId: ResourceId<'walletAccount'>,
  preparationId: ResourceId<'operation'>,
  reviewedDigest: Hex,
  proofsInput: Parameters<typeof authorizeTransferOperation>[3],
  scopeInput: WebAuthnScope,
  profilesInput: readonly TransferDeliveryProfile[],
  signal: AbortSignal,
) {
  const identity = Object.freeze({ ...identityInput }),
    scope = { ...scopeInput };
  const profiles = structuredClone(profilesInput),
    proofs = structuredClone(proofsInput);
  requireHash(reviewedDigest);
  return withDeadline(signal, 30_000, async (deadline) => {
    const drafts = () =>
      new TransferPreparationRepository(
        database,
        identity,
        scope,
        profiles.map((p) => p.digest),
      );
    const stored = await drafts().readOwned(walletId, accountId, preparationId);
    const { candidate, review } = stored;
    if (candidate.digest !== reviewedDigest) throw new Error('TRANSFER_REVIEW_MISMATCH');
    // Reject invalid proof sets before spending RPC capacity. Full authorization
    // repeats verification with live evidence and checks expiry after crypto.
    await verifyTransferQuorum(candidate.digest, review.policy, scope, proofs);
    const prior = await new TransferNonceReservationRepository(
      database,
      identity,
    ).findOwnedByConsent(walletId, accountId, candidate.digest);
    if (prior) {
      const current = await drafts().readOwned(walletId, accountId, preparationId);
      deadline.throwIfAborted();
      if (
        prior.state === 'expired' ||
        writeTransferDraft(prior.review).digest !== current.record_sha256 ||
        current.record_sha256 !== stored.record_sha256
      )
        throw new Error('TRANSFER_CONFIRMATION_CHANGED');
      return Object.freeze({
        id: prior.id,
        state: prior.state,
        expires_at: prior.plan.validUntil,
        preparation_id: preparationId,
        consent_digest: candidate.digest,
        send_enabled: false as const,
      });
    }
    const matching = profiles.filter((p) => p.digest === candidate.deployment_digest);
    if (matching.length !== 1) throw new Error('TRANSFER_CONFIRMATION_PROFILE');
    const profile = matching[0],
      manifest = loadPinnedDeploymentManifest(profile.document, profile.digest);
    requireHash(profile.entryPointCodeHash);
    const assets = [
      ...new Set([candidate.request.asset_id, review.context.native_asset_id]),
    ].sort();
    if (
      manifest.lifecycle_status !== 'deployed' ||
      manifest.network_id !== candidate.request.network_id ||
      profile.assetIds.length !== assets.length ||
      new Set(profile.assetIds).size !== assets.length ||
      profile.assetIds.some((id) => !assets.includes(id))
    )
      throw new Error('TRANSFER_CONFIRMATION_PROFILE');
    const owned = await new WalletRepository(database, identity).ownedAccount(walletId, accountId);
    const peers = validateRpcProviders(profile.providers),
      clients = peers.map((p) => createInspectionClient(p.url, deadline));
    const checkpoint = candidate.checkpoint,
      tag = toHex(BigInt(checkpoint.block_number));
    const header = await clients[0].request(
      { method: 'eth_getBlockByNumber', params: [tag, false] },
      { retryCount: 0, dedupe: false },
    );
    if (
      !header ||
      header.number !== tag ||
      header.hash !== checkpoint.block_hash ||
      typeof header.timestamp !== 'string' ||
      !/^0x(?:0|[1-9a-f][0-9a-f]{0,63})$(?![\s\S])/.test(header.timestamp)
    ) {
      throw new Error('TRANSFER_CONFIRMATION_BLOCK');
    }
    const target = {
      network_id: manifest.network_id,
      genesis_hash: manifest.genesis_hash,
      block_number: checkpoint.block_number,
      block_hash: checkpoint.block_hash,
      block_timestamp: BigInt(header.timestamp).toString(),
    };
    const source = await assessCheckpointFinality(
      clients,
      target,
      profile.finalityPolicy,
      deadline,
    );
    if (source.status !== 'finalized') throw new Error('TRANSFER_CONFIRMATION_FINALITY');
    const results = await Promise.allSettled([
      inspectWalletSecurity(
        {
          document: profile.document,
          expectedDigest: profile.digest,
          checkpoint,
          initialSecurityCommitment: owned.initial_security_commitment,
          userSaltCommitment: owned.user_salt_commitment,
        },
        peers.map((p) => p.url),
        deadline,
      ),
      observeAccountBalances(
        {
          network_id: manifest.network_id,
          genesis_hash: manifest.genesis_hash,
          address: candidate.account,
          checkpoint,
          asset_ids: assets,
        },
        peers,
        deadline,
      ),
      observeTransferNonce(
        {
          network_id: manifest.network_id,
          genesis_hash: manifest.genesis_hash,
          account: candidate.account,
          entry_point: manifest.entry_point,
          entry_point_code_hash: profile.entryPointCodeHash,
          checkpoint,
        },
        peers,
        deadline,
      ),
      new TransferNonceReservationRepository(database, identity).reservedFunds(
        walletId,
        accountId,
        assets,
      ),
    ]);
    deadline.throwIfAborted();
    const [security, balances, nonce, holds] = results;
    if (
      security.status !== 'fulfilled' ||
      balances.status !== 'fulfilled' ||
      nonce.status !== 'fulfilled' ||
      holds.status !== 'fulfilled'
    ) {
      throw new Error('TRANSFER_CONFIRMATION_OBSERVATION');
    }
    const closing = await assessCheckpointFinality(
      clients,
      target,
      profile.finalityPolicy,
      deadline,
    );
    const observedAt = Math.floor(Date.now() / 1000),
      expiresAt = Math.min(source.expires_at, closing.expires_at);
    const authorization = await authorizeTransferOperation(
      review.request,
      review.context,
      {
        prepared_at: review.prepared_at,
        reviewed_digest: reviewedDigest,
        policy: review.policy,
        scope,
        security_evidence: {
          document: profile.document,
          digest: profile.digest,
          observation: security.value,
          finality: closing,
          finality_policy: profile.finalityPolicy,
          observed_at: observedAt,
          expires_at: expiresAt,
        },
        balance_evidence: {
          ...balances.value,
          wallet_id: walletId,
          checkpoint: target,
          finality_evidence: closing,
          expires_at: expiresAt,
          reserved: holds.value,
        },
        nonce_evidence: nonce.value,
      },
      proofs,
    );
    const current = await drafts().readOwned(walletId, accountId, preparationId);
    const currentOwner = await new WalletRepository(database, identity).ownedAccount(
      walletId,
      accountId,
    );
    deadline.throwIfAborted();
    if (
      current.record_sha256 !== stored.record_sha256 ||
      JSON.stringify(currentOwner) !== JSON.stringify(owned)
    ) {
      throw new Error('TRANSFER_CONFIRMATION_CHANGED');
    }
    const reservation = await new TransferNonceReservationRepository(database, identity).reserve(
      accountId,
      authorization,
      { id: preparationId, record_sha256: stored.record_sha256 },
    );
    return Object.freeze({
      ...reservation,
      preparation_id: preparationId,
      consent_digest: candidate.digest,
    });
  });
}
