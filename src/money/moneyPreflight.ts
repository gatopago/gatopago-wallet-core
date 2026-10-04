import type { ResourceId } from '@gatopago/shared/v3/primitives';
import type { WebAuthnScope } from '@gatopago/shared/v3/webauthn';
import type { Principal } from '../auth/principal';
import { withDeadline } from '../deadline';
import type { OperationTransport } from '../execution/operationTransport';
import { writeExecutionOperationRecord } from '../execution/executionOperationRecord';
import { MoneyRepository } from './moneyRepository';
import { observeOwnedMoneyCurrent } from './moneyCurrentState';
import type { MoneyPreparationProfile } from './moneyPreparation';
import { simulateMoneyOperation } from './moneySimulation';

export interface MoneyDeliveryProfile extends Omit<MoneyPreparationProfile, 'finalityEvidence'> {
  readonly transport: OperationTransport;
}

export async function preflightOwnedMoney(
  database: D1Database,
  identityInput: Principal,
  walletId: ResourceId<'wallet'>,
  accountId: ResourceId<'walletAccount'>,
  operationId: ResourceId<'operation'>,
  scope: WebAuthnScope,
  profilesInput: readonly MoneyDeliveryProfile[],
  signal: AbortSignal,
) {
  const identity = Object.freeze({ ...identityInput }),
    profiles = structuredClone(profilesInput);
  return withDeadline(signal, 30_000, async (deadline) => {
    const repository = new MoneyRepository(
      database,
      identity,
      scope,
      profiles.map((p) => ({ deployment: p.digest, market: p.market.digest })),
    );
    const stored = await repository.readOperation(walletId, accountId, operationId),
      candidate = stored.candidate;
    if (stored.state !== 'authorized') throw new Error('MONEY_DELIVERY_ALREADY_CLAIMED');
    const matching = profiles.filter(
      (p) =>
        p.digest === candidate.deployment_digest &&
        p.market.digest === stored.review.context.market.digest,
    );
    if (matching.length !== 1) throw new Error('MONEY_PROFILE_UNAVAILABLE');
    const [observation, simulation] = await Promise.allSettled([
      observeOwnedMoneyCurrent(
        database,
        identity,
        walletId,
        accountId,
        stored.review,
        matching[0],
        deadline,
      ),
      simulateMoneyOperation(stored, matching[0].transport, deadline),
    ]);
    deadline.throwIfAborted();
    if (observation.status !== 'fulfilled' || simulation.status !== 'fulfilled')
      throw new Error('MONEY_PREFLIGHT_FAILED');
    const checked = observation.value,
      estimated = simulation.value,
      plan = candidate.plan;
    const payload = writeExecutionOperationRecord(stored.operation, {
      network_id: candidate.request.network_id,
      account: candidate.account,
      account_id: plan.accountId,
      entry_point: plan.entryPoint,
      userop_hash: candidate.userOpHash,
      consent_digest: candidate.digest,
      valid_until: plan.validUntil,
    });
    const now = Math.floor(Date.now() / 1000);
    if (
      now < checked.checked_at ||
      now < estimated.observed_at ||
      now >= checked.expires_at ||
      now >= estimated.expires_at ||
      checked.record_sha256 !== stored.record_sha256 ||
      checked.consent_digest !== candidate.digest ||
      checked.userop_hash !== candidate.userOpHash ||
      estimated.consent_digest !== candidate.digest ||
      estimated.userop_hash !== candidate.userOpHash ||
      estimated.operation_sha256 !== payload.digest
    )
      throw new Error('MONEY_PREFLIGHT_STALE_OR_CHANGED');
    return Object.freeze({
      ...checked,
      operation_id: operationId,
      operation_sha256: payload.digest,
      simulation: estimated,
      checked_at: now,
      expires_at: Math.min(checked.expires_at, estimated.expires_at),
      send_enabled: false as const,
    });
  });
}
