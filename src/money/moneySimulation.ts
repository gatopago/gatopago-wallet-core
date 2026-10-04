import type { readMoneyReview } from '@gatopago/shared/v3/money-review-record';
import { writeExecutionOperationRecord } from '../execution/executionOperationRecord';
import { simulateOperation, type OperationTransport } from '../execution/operationTransport';
import { withDeadline } from '../deadline';

/** Exact signed bytes, preserving every user-approved gas cap and call. An
 * estimate is never an execution receipt or a fresh authority observation. */
export async function simulateMoneyOperation(
  input: Awaited<ReturnType<typeof readMoneyReview>>,
  transportInput: OperationTransport,
  signal: AbortSignal,
) {
  const { candidate, operation, review } = structuredClone(input),
    transport = structuredClone(transportInput),
    plan = candidate.plan;
  const payload = writeExecutionOperationRecord(operation, {
    network_id: candidate.request.network_id,
    account: candidate.account,
    account_id: plan.accountId,
    entry_point: plan.entryPoint,
    userop_hash: candidate.userOpHash,
    consent_digest: candidate.digest,
    valid_until: plan.validUntil,
  });
  const started = Math.floor(Date.now() / 1000);
  const fresh = () => {
    const now = Math.floor(Date.now() / 1000);
    if (
      now < started ||
      now < review.approved_at ||
      now < plan.validAfter ||
      now >= plan.validUntil
    )
      throw new Error('MONEY_SIMULATION_EXPIRED');
    return now;
  };
  fresh();
  return withDeadline(signal, 15_000, async (deadline) => {
    const gas = await simulateOperation(
      transport,
      {
        operation,
        networkId: candidate.request.network_id,
        entryPoint: plan.entryPoint,
        userOpHash: candidate.userOpHash,
        validUntil: plan.validUntil,
      },
      deadline,
    );
    deadline.throwIfAborted();
    const now = fresh();
    return Object.freeze({
      userop_hash: candidate.userOpHash,
      consent_digest: candidate.digest,
      operation_sha256: payload.digest,
      gas: Object.freeze(gas),
      observed_at: now,
      expires_at: Math.min(now + 5, plan.validUntil),
      send_enabled: false as const,
    });
  });
}
