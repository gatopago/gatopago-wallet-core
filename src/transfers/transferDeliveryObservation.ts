import { validateRpcProviders } from '../chainProviders';
import { toHex, type Hex } from 'viem';
import { loadPinnedDeploymentManifest, requireHash } from '@gatopago/shared/v3/deployment';
import { assessCheckpointFinality } from '@gatopago/shared/v3/finality';
import type { ResourceId } from '@gatopago/shared/v3/primitives';
import type { Principal } from '../auth/principal';
import { createInspectionClient } from '../chainInspection';
import { withDeadline } from '../deadline';

import { inspectOwnedWalletBalances, type BalanceProfile } from '../portfolio/balances';
import { inspectOwnedWalletAccount } from '../accounts/inspection';
import { WalletRepository } from '../accounts/repository';
import { assertTransferDeliveryState } from './transferDeliveryState';
import { observeTransferNonce } from './transferNonce';
import { TransferNonceReservationRepository } from './transferNonceReservation';

export interface TransferDeliveryProfile extends Omit<BalanceProfile, 'finalityEvidence'> {
  readonly entryPointCodeHash: Hex;
}

/** Private coordinator: profiles come from admission, never an HTTP request.
 * Fresh readers share a deadline, not global promises. This does not simulate,
 * acquire a delivery lease or send anything; the caller still needs those gates.
 */
export async function observeOwnedTransferDelivery(
  database: D1Database,
  identityInput: Principal,
  walletId: ResourceId<'wallet'>,
  accountId: ResourceId<'walletAccount'>,
  operationId: ResourceId<'operation'>,
  profilesInput: readonly TransferDeliveryProfile[],
  signal: AbortSignal,
) {
  const profiles = structuredClone(profilesInput),
    identity = Object.freeze({ ...identityInput });
  return withDeadline(signal, 30_000, async (deadline) => {
    const reservations = new TransferNonceReservationRepository(database, identity);
    const stored = await reservations.readOwned(walletId, accountId, operationId);
    deadline.throwIfAborted();
    if (stored.state !== 'held') throw new Error('TRANSFER_RESERVATION_EXPIRED');
    const candidate = stored.candidate;
    const matching = profiles.filter((p) => p.digest === candidate.deployment_digest);
    if (matching.length !== 1) throw new Error('TRANSFER_DELIVERY_PROFILE_UNAVAILABLE');
    const profile = matching[0],
      manifest = loadPinnedDeploymentManifest(profile.document, profile.digest);
    requireHash(profile.entryPointCodeHash);
    const peers = validateRpcProviders(profile.providers);
    const assets = new Set([candidate.request.asset_id, stored.review.context.native_asset_id]);
    if (
      manifest.network_id !== candidate.request.network_id ||
      manifest.lifecycle_status !== 'deployed' ||
      profile.assetIds.length !== assets.size ||
      profile.assetIds.some((id) => !assets.has(id)) ||
      new Set(profile.assetIds).size !== assets.size
    )
      throw new Error('TRANSFER_DELIVERY_PROFILE_UNAVAILABLE');
    const clients = peers.map((p) => createInspectionClient(p.url, deadline));
    const tag = toHex(BigInt(candidate.checkpoint.block_number));
    // Only seed the timestamp from this header; assessCheckpointFinality checks
    // the complete original block and consensus against both independent peers.
    const header = await clients[0].request(
      { method: 'eth_getBlockByNumber', params: [tag, false] },
      { retryCount: 0, dedupe: false },
    );
    if (
      !header ||
      header.number !== tag ||
      header.hash !== candidate.checkpoint.block_hash ||
      typeof header.timestamp !== 'string' ||
      !/^0x(?:0|[1-9a-f][0-9a-f]{0,63})$(?![\s\S])/.test(header.timestamp)
    ) {
      throw new Error('TRANSFER_DELIVERY_REVIEW_ORPHANED');
    }
    const target = {
      network_id: manifest.network_id,
      genesis_hash: manifest.genesis_hash,
      block_number: candidate.checkpoint.block_number,
      block_hash: candidate.checkpoint.block_hash,
      block_timestamp: BigInt(header.timestamp).toString(),
    };
    const source = await assessCheckpointFinality(
      clients,
      target,
      profile.finalityPolicy,
      deadline,
    );
    if (source.status !== 'finalized' || !source.checkpoint)
      throw new Error('TRANSFER_DELIVERY_FINALITY');
    const checkpoint = source.checkpoint;
    // A new primary session for every ownership recheck, including after RPC.
    const owner = {
      ownedAccount: (wid: ResourceId<'wallet'>, aid: ResourceId<'walletAccount'>) =>
        new WalletRepository(database, identity).ownedAccount(wid, aid),
    };
    const rpcUrls: readonly [string, string] = [peers[0].url, peers[1].url];
    const results = await Promise.allSettled([
      inspectOwnedWalletAccount(
        owner,
        walletId,
        accountId,
        [{ ...profile, rpcUrls, finalityEvidence: source }],
        deadline,
      ),
      inspectOwnedWalletBalances(
        owner,
        walletId,
        accountId,
        [{ ...profile, finalityEvidence: source }],
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
    const [security, balances, nonce] = results;
    if (
      security.status !== 'fulfilled' ||
      balances.status !== 'fulfilled' ||
      nonce.status !== 'fulfilled'
    ) {
      throw new Error('TRANSFER_DELIVERY_OBSERVATION_FAILED');
    }
    const reviewedBlock = await assessCheckpointFinality(
      clients,
      target,
      profile.finalityPolicy,
      deadline,
    );
    const holds = await reservations.deliveryFundsSnapshot(walletId, accountId, operationId);
    deadline.throwIfAborted();
    const checked = assertTransferDeliveryState(
      stored,
      {
        security: {
          document: profile.document,
          digest: profile.digest,
          observation: security.value,
          finality: security.value.finality_evidence,
          finality_policy: profile.finalityPolicy,
          observed_at: security.value.security_observed_at,
          expires_at: security.value.security_expires_at,
        },
        reviewed_block: reviewedBlock,
        balances: balances.value,
        nonce: nonce.value,
        holds,
      },
      Math.floor(Date.now() / 1000),
    );
    return Object.freeze({
      ...checked,
      operation_id: operationId,
      operation: stored.operation,
      reservation_fingerprint: holds.fingerprint,
      reservation_observed_at: holds.observed_at,
    });
  });
}
