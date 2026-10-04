import type { OperationTransport } from '../execution/operationTransport';
import type { ResourceId } from '@gatopago/shared/v3/primitives';
import type { Principal } from '../auth/principal';
import { withDeadline } from '../deadline';
import {
  observeOwnedTransferDelivery,
  type TransferDeliveryProfile,
} from './transferDeliveryObservation';
import { TransferNonceReservationRepository } from './transferNonceReservation';
import { writeTransferOperationRecord } from './transferOperationRecord';
import { simulateTransferOperation } from './transferSimulation';

export interface TransferPreflightProfile extends TransferDeliveryProfile {
  readonly transport: OperationTransport;
}

export async function preflightOwnedTransfer(
  database: D1Database,
  identityInput: Principal,
  walletId: ResourceId<'wallet'>,
  accountId: ResourceId<'walletAccount'>,
  operationId: ResourceId<'operation'>,
  profilesInput: readonly TransferPreflightProfile[],
  signal: AbortSignal,
) {
  const identity = Object.freeze({ ...identityInput }),
    profiles = structuredClone(profilesInput);
  return withDeadline(signal, 30_000, async (deadline) => {
    const stored = await new TransferNonceReservationRepository(database, identity).readOwned(
      walletId,
      accountId,
      operationId,
    );
    if (stored.state !== 'held') throw new Error('TRANSFER_RESERVATION_EXPIRED');
    const matching = profiles.filter((p) => p.digest === stored.candidate.deployment_digest);
    if (matching.length !== 1) throw new Error('TRANSFER_DELIVERY_PROFILE_UNAVAILABLE');
    const results = await Promise.allSettled([
      observeOwnedTransferDelivery(
        database,
        identity,
        walletId,
        accountId,
        operationId,
        matching,
        deadline,
      ),
      simulateTransferOperation(stored, matching[0].transport, deadline),
    ]);
    deadline.throwIfAborted();
    const [observation, simulation] = results;
    if (observation.status !== 'fulfilled' || simulation.status !== 'fulfilled')
      throw new Error('TRANSFER_PREFLIGHT_FAILED');
    const checked = observation.value,
      estimated = simulation.value,
      candidate = stored.candidate;
    const payload = writeTransferOperationRecord(checked.operation, {
      network_id: candidate.request.network_id,
      account: candidate.account,
      account_id: candidate.plan.accountId,
      entry_point: candidate.plan.entryPoint,
      userop_hash: candidate.userOpHash,
      consent_digest: candidate.digest,
      valid_until: candidate.plan.validUntil,
    });
    const now = Math.floor(Date.now() / 1000);
    if (
      now < checked.checked_at ||
      now < estimated.observed_at ||
      now >= checked.expires_at ||
      now >= estimated.expires_at ||
      checked.operation_id !== operationId ||
      checked.userop_hash !== candidate.userOpHash ||
      estimated.userop_hash !== candidate.userOpHash ||
      checked.consent_digest !== candidate.digest ||
      estimated.consent_digest !== candidate.digest ||
      estimated.operation_sha256 !== payload.digest
    )
      throw new Error('TRANSFER_PREFLIGHT_STALE_OR_CHANGED');
    return Object.freeze({
      ...checked,
      simulation: estimated,
      expires_at: Math.min(checked.expires_at, estimated.expires_at),
      checked_at: now,
      send_enabled: false as const,
    });
  });
}
