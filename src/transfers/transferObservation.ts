import type { OperationTransport } from '../execution/operationTransport';
import type { Environment } from '@gatopago/environment';
import { validateRpcProviders } from '../chainProviders';
import type { Hex } from 'viem';
import { loadPinnedDeploymentManifest, requireHash } from '@gatopago/shared/v3/deployment';
import { assessCheckpointFinality, loadPinnedFinalityPolicy } from '@gatopago/shared/v3/finality';
import type { ResourceId } from '@gatopago/shared/v3/primitives';
import { submissionTransaction, bundlerTransaction } from '../execution/operationTransport';
import type { Principal } from '../auth/principal';
import { createInspectionClient } from '../chainInspection';
import { withDeadline } from '../deadline';


import { WalletRepository } from '../accounts/repository';
import type { TransferDeliveryProfile } from './transferDeliveryObservation';
import { TransferNonceReservationRepository } from './transferNonceReservation';
import { observeTransferReceipt } from './transferReceiptObservation';
import type { readTransferReview } from '@gatopago/shared/v3/transfer-review-record';
import { TransferJobRepository, parseTransferWake, type TransferWake } from './transferJobs';

/** Private read-only observation. The transaction is a hint, not payment evidence.
 * No timeout, missing receipt or reverted execution releases reservations here.
 * Profiles are operator-admitted configuration, never caller-supplied HTTP data.
 */
export async function observeOwnedTransfer(database: D1Database, identityInput: Principal,
  walletId: ResourceId<'wallet'>, accountId: ResourceId<'walletAccount'>, operationId: ResourceId<'operation'>,
  transaction: Hex | undefined, profilesInput: readonly (TransferDeliveryProfile & { readonly transport?: OperationTransport })[], signal: AbortSignal) {
  const identity = Object.freeze({ ...identityInput });
  const source = async () => {
    const record = await new TransferNonceReservationRepository(database, identity).readOwned(walletId, accountId, operationId);
    const owned = await new WalletRepository(database, identity).ownedAccount(walletId, accountId);
    if (record.state !== 'delivery_pending') throw new Error('TRANSFER_OBSERVATION_NOT_PENDING');
    return { record, context: JSON.stringify(owned), initialSecurityCommitment: owned.initial_security_commitment, userSaltCommitment: owned.user_salt_commitment };
  };
  return observeTransferSource(database, operationId, source, transaction, profilesInput, signal);
}

/** Internal consumer access uses a live lease and admitted environment/profile, not
 * a synthetic user session. It has no path to the sender or reservation release.
 */
export async function observeTransferJob(database: D1Database, environment: Environment['environment'], input: TransferWake,
  profiles: readonly (TransferDeliveryProfile & { readonly transport?: OperationTransport })[], signal: AbortSignal) {
  const message = parseTransferWake(input), snapshot = structuredClone(profiles);
  const jobs = new TransferJobRepository(database, { environment, profiles: snapshot });
  return observeTransferSource(database, message.operation_id, () => jobs.observationSource(message), undefined, snapshot, signal);
}

async function observeTransferSource(database: D1Database, operationId: ResourceId<'operation'>, source: () => Promise<{
  record: Awaited<ReturnType<typeof readTransferReview>>; context: string; initialSecurityCommitment: Hex; userSaltCommitment: Hex;
}>, transaction: Hex | undefined, profilesInput: readonly (TransferDeliveryProfile & { readonly transport?: OperationTransport })[], signal: AbortSignal) {
  const profiles = structuredClone(profilesInput);
  if (transaction !== undefined) requireHash(transaction);
  return withDeadline(signal, 40_000, async deadline => {
    const original = await source(), stored = original.record;
    const matching = profiles.filter(p => p.digest === stored.candidate.deployment_digest);
    if (matching.length !== 1) throw new Error('TRANSFER_OBSERVATION_PROFILE');
    const profile = matching[0], manifest = loadPinnedDeploymentManifest(profile.document, profile.digest);
    requireHash(profile.entryPointCodeHash);
    loadPinnedFinalityPolicy(profile.finalityPolicy, manifest);
    const peers = validateRpcProviders(profile.providers);
    const clients = peers.map(p => createInspectionClient(p.url, deadline));
    let located = transaction;
    const base = () => ({ operation_id: operationId, transaction_hash: located ?? null, userop_hash: stored.candidate.userOpHash,
      provider_ids: Object.freeze(peers.map(p => p.operatorId)), settlement: 'not_assessed' as const });
    async function observe() {
      if (located === undefined) {
        const submitted = await submissionTransaction(database, stored.candidate.userOpHash, deadline);
        located = submitted ?? undefined;
        if (submitted === undefined && !profile.transport) throw new Error('TRANSFER_HINT_PROFILE');
        if (submitted === undefined && profile.transport?.kind === 'bundler')
          located = await bundlerTransaction(profile.transport.url, stored.candidate.userOpHash, deadline);
      }
      if (located === undefined) return { ...base(), status: 'not_observed' as const };
      const hash = located;
      const results = await Promise.allSettled(clients.map(client => observeTransferReceipt(client, stored, hash, {
        document: profile.document, expectedDigest: profile.digest, entryPointCodeHash: profile.entryPointCodeHash,
        initialSecurityCommitment: original.initialSecurityCommitment, userSaltCommitment: original.userSaltCommitment,
      })));
      deadline.throwIfAborted();
      const [a, b] = results;
      if (a.status === 'rejected' || b.status === 'rejected') return { ...base(), status: 'unavailable' as const };
      if (JSON.stringify(a.value) !== JSON.stringify(b.value)) return { ...base(), status: 'disagreement' as const };
      if (a.value === null) return { ...base(), status: 'not_observed' as const };
      const assessment = await assessCheckpointFinality(clients,
        { ...a.value, genesis_hash: manifest.genesis_hash }, profile.finalityPolicy, deadline);
      return { ...base(), status: 'observed' as const, observation: a.value, finality_evidence: assessment };
    }
    let result: Awaited<ReturnType<typeof observe>>;
    try { result = await observe(); }
    catch { result = { ...base(), status: 'unavailable' }; }
    // Recheck even on null/error: user revocation or loss of the job lease fails closed.
    const current = await source();
    deadline.throwIfAborted();
    // Internal typed records contain bigint operation fields (not JSON wire data).
    const snapshot = (value: typeof original) => JSON.stringify(value, (_key, item: unknown) =>
      typeof item === 'bigint' ? item.toString() : item);
    if (snapshot(current) !== snapshot(original)) throw new Error('TRANSFER_OBSERVATION_CHANGED');
    if (result.status === 'observed' && Math.floor(Date.now() / 1000) >= result.finality_evidence.expires_at) {
      return Object.freeze({ ...base(), status: 'unavailable' as const });
    }
    return Object.freeze(result);
  });
}
