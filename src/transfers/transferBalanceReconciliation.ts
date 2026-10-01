import { validateRpcProviders } from '../chainProviders';
import type { Hex } from 'viem';
import { deploymentDocumentDigest, loadPinnedDeploymentManifest } from '@gatopago/shared/v3/deployment';
import { assessCheckpointFinality } from '@gatopago/shared/v3/finality';
import type { ResourceId } from '@gatopago/shared/v3/primitives';
import type { Principal } from '../auth/principal';
import { createInspectionClient } from '../chainInspection';
import { withDeadline } from '../deadline';

import { inspectOwnedWalletBalances } from '../portfolio/balances';
import { WalletRepository } from '../accounts/repository';
import { TransferNonceReservationRepository } from './transferNonceReservation';
import { recordOwnedTransferFinality } from './transferReconciliation';
import { readOwnedTransferStatus } from './transferStatus';

/** Observe post-inclusion balances before any reservation release. Actual balance
 * may include unrelated incoming/outgoing transfers: never derive it by subtracting
 * this receipt from an old cache. No balance write, release or send authority here.
 */
export async function observeTransferReconciliationBalance(database: D1Database, identityInput: Principal,
  walletId: ResourceId<'wallet'>, accountId: ResourceId<'walletAccount'>, operationId: ResourceId<'operation'>,
  transaction: Hex | undefined, profilesInput: Parameters<typeof recordOwnedTransferFinality>[6], signal: AbortSignal) {
  const identity = Object.freeze({ ...identityInput }), profiles = structuredClone(profilesInput);
  return withDeadline(signal, 90_000, async deadline => {
    const result = await recordOwnedTransferFinality(database, identity, walletId, accountId, operationId, transaction, profiles, deadline);
    if (result.journal !== 'recorded' || result.status !== 'observed' || result.finality_evidence.status !== 'finalized') {
      throw new Error('TRANSFER_RECONCILIATION_NOT_CONFIRMED');
    }
    const read = () => new TransferNonceReservationRepository(database, identity).readOwned(walletId, accountId, operationId);
    const stored = await read();
    const matching = profiles.filter(p => p.digest === stored.candidate.deployment_digest);
    if (matching.length !== 1) throw new Error('TRANSFER_RECONCILIATION_PROFILE');
    const profile = matching[0], manifest = loadPinnedDeploymentManifest(profile.document, profile.digest);
    const owner = { ownedAccount: (wid: ResourceId<'wallet'>, aid: ResourceId<'walletAccount'>) =>
      new WalletRepository(database, identity).ownedAccount(wid, aid) };
    const balances = await inspectOwnedWalletBalances(owner, walletId, accountId,
      [{ ...profile, finalityEvidence: result.finality_evidence }], deadline);
    const receipt = result.observation, checkpoint = balances.checkpoint;
    const requiredAssets = new Set(stored.funds.map(f => f.asset_id));
    if (balances.wallet_id !== walletId || balances.wallet_account_id !== accountId || balances.network_id !== receipt.network_id
      || balances.address.toLowerCase() !== stored.candidate.account.toLowerCase()
      || BigInt(checkpoint.block_number) < BigInt(receipt.block_number)
      || (checkpoint.block_number === receipt.block_number && checkpoint.block_hash !== receipt.block_hash)
      || balances.balances.some(row => !requiredAssets.has(row.asset_id)) || balances.balances.length !== requiredAssets.size
      || new Set(balances.balances.map(row => row.asset_id)).size !== requiredAssets.size) throw new Error('TRANSFER_RECONCILIATION_BALANCE');
    // Recheck the original receipt after all balance RPCs, not just the later checkpoint.
    const peers = validateRpcProviders(profile.providers);
    const closing = await assessCheckpointFinality(peers.map(p => createInspectionClient(p.url, deadline)),
      { ...receipt, genesis_hash: manifest.genesis_hash }, profile.finalityPolicy, deadline);
    const current = await read();
    const status = await readOwnedTransferStatus(database, identity, walletId, accountId, operationId);
    deadline.throwIfAborted();
    const now = Math.floor(Date.now() / 1000);
    if (status.status !== 'confirmation_recorded' || current.state !== 'delivery_pending'
      || current.candidate.digest !== stored.candidate.digest || current.candidate.userOpHash !== stored.candidate.userOpHash
      || status.historical_confirmation?.transaction_hash !== receipt.transaction_hash
      || closing.status !== 'finalized' || !closing.checkpoint || closing.assessed_at > now || now >= closing.expires_at
      || now < balances.observed_at || now >= balances.expires_at
      || BigInt(closing.checkpoint.block_number) < BigInt(checkpoint.block_number)
      || (closing.checkpoint.block_number === checkpoint.block_number && closing.checkpoint.block_hash !== checkpoint.block_hash)) {
      throw new Error('TRANSFER_RECONCILIATION_CHANGED');
    }
    return Object.freeze({ operation_id: operationId, wallet_id: walletId, wallet_account_id: accountId,
      userop_hash: stored.candidate.userOpHash, consent_digest: stored.candidate.digest,
      receipt_sha256: deploymentDocumentDigest(JSON.stringify(receipt)), balances,
      receipt_finality: closing, checked_at: now, expires_at: Math.min(balances.expires_at, closing.expires_at),
      settlement: 'not_assessed' as const, release_enabled: false as const });
  });
}
