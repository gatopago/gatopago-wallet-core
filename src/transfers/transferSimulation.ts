import { simulateOperation, type OperationTransport } from '../execution/operationTransport';
import { withDeadline } from '../deadline';

import { writeTransferOperationRecord } from './transferOperationRecord';
import type { readTransferReview } from '@gatopago/shared/v3/transfer-review-record';

/** Private ERC-4337 preflight of EXACT stored bytes. A bundler estimate is not
 * inclusion, fresh security/funds evidence or a durable send grant. Caller must
 * admit the provider and restore/verify the historical quorum before calling.
 */
export async function simulateTransferOperation(
  recordInput: Awaited<ReturnType<typeof readTransferReview>>,
  transport: OperationTransport,
  signal: AbortSignal,
) {
  const record = structuredClone(recordInput);
  const { candidate, operation } = record,
    plan = candidate.plan;
  const payload = writeTransferOperationRecord(operation, {
    network_id: candidate.request.network_id,
    account: candidate.account,
    account_id: plan.accountId,
    entry_point: plan.entryPoint,
    userop_hash: candidate.userOpHash,
    consent_digest: candidate.digest,
    valid_until: plan.validUntil,
  });
  const started = Math.floor(Date.now() / 1000);
  function fresh() {
    const now = Math.floor(Date.now() / 1000);
    if (
      now < started ||
      now < record.review.approved_at ||
      now < plan.validAfter ||
      now >= plan.validUntil
    )
      throw new Error('TRANSFER_SIMULATION_EXPIRED');
    return now;
  }
  fresh();
  return withDeadline(signal, 15_000, async (deadline) => {
    const estimates = await simulateOperation(
      transport,
      {
        operation,
        networkId: candidate.request.network_id,
        entryPoint: plan.entryPoint,
        userOpHash: candidate.userOpHash,
        validUntil: Number(plan.validUntil),
      },
      deadline,
    );
    deadline.throwIfAborted();
    const now = fresh();
    return Object.freeze({
      userop_hash: candidate.userOpHash,
      consent_digest: candidate.digest,
      operation_sha256: payload.digest,
      gas: Object.freeze(estimates),
      observed_at: now,
      expires_at: Math.min(now + 5, plan.validUntil),
      send_enabled: false as const,
    });
  });
}
