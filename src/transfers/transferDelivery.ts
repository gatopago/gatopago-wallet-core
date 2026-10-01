import type { ResourceId } from '@gatopago/shared/v3/primitives';
import { sendOperation } from '../execution/operationTransport';
import type { Hex } from 'viem';
import type { Principal } from '../auth/principal';
import { withDeadline } from '../deadline';

import { TransferNonceReservationRepository } from './transferNonceReservation';
import { preflightOwnedTransfer, type TransferPreflightProfile } from './transferPreflight';

/** Private delivery coordinator. No public route or admitted production profile.
 * Persists a one-use dispatch marker before handing the operation to its transport.
 * Acceptance is never settlement. Any failure beyond dispatch stays uncertain.
 */
export async function deliverOwnedTransfer(database: D1Database, identityInput: Principal,
  walletId: ResourceId<'wallet'>, accountId: ResourceId<'walletAccount'>, operationId: ResourceId<'operation'>,
  profilesInput: readonly TransferPreflightProfile[], signal: AbortSignal, relayerKey?: Hex) {
  const identity = Object.freeze({ ...identityInput }), profiles = structuredClone(profilesInput);
  const repository = new TransferNonceReservationRepository(database, identity);
  const stored = await repository.readOwned(walletId, accountId, operationId);
  if (stored.state !== 'held') throw new Error('TRANSFER_DELIVERY_ALREADY_CLAIMED');
  const matching = profiles.filter(p => p.digest === stored.candidate.deployment_digest);
  if (matching.length !== 1) throw new Error('TRANSFER_DELIVERY_PROFILE_UNAVAILABLE');
  signal.throwIfAborted();
  const preflight = await preflightOwnedTransfer(database, identity, walletId, accountId, operationId, matching, signal);
  signal.throwIfAborted();
  const claim = await repository.beginDelivery(walletId, accountId, preflight);
  signal.throwIfAborted();
  const grant = await repository.consumeDelivery(walletId, accountId, operationId, claim.claim_token);
  try {
    await withDeadline(signal, Math.max(1, Math.min(30_000, grant.expires_at * 1000 - Date.now())), async deadline => {
      // Do not begin network I/O after the preflight observation has expired.
      const now = Math.floor(Date.now() / 1000);
      if (now < grant.dispatched_at || now >= grant.expires_at) throw new Error('TRANSFER_DISPATCH_EXPIRED');
      await sendOperation(database, matching[0].transport, { operation: grant.operation, networkId: grant.network_id,
        entryPoint: grant.entry_point, userOpHash: grant.userop_hash, validUntil: stored.candidate.plan.validUntil }, deadline, relayerKey);
    });
    return Object.freeze({ operation_id: operationId, userop_hash: grant.userop_hash, delivery: 'accepted' as const, settlement: 'unconfirmed' as const });
  } catch {
    // Never retry, free reservations or disclose RPC error details/signatures.
    return Object.freeze({ operation_id: operationId, userop_hash: grant.userop_hash, delivery: 'uncertain' as const, settlement: 'unconfirmed' as const });
  }
}
