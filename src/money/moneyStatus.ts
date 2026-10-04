import { deploymentDocumentDigest } from '@gatopago/shared/v3/deployment';
import { writeMoneyDraft } from '@gatopago/shared/v3/money-review-record';
import type { ResourceId } from '@gatopago/shared/v3/primitives';
import type { MoneyRepository } from './moneyRepository';

export async function readOwnedMoneyStatus(
  database: D1Database,
  repository: MoneyRepository,
  walletId: ResourceId<'wallet'>,
  accountId: ResourceId<'walletAccount'>,
  operationId: ResourceId<'operation'>,
) {
  const original = await repository.readOperationHistory(walletId, accountId, operationId),
    c = original.candidate;
  const db = database.withSession('first-primary');
  const [journal, job, reconciliation, conflict] = await Promise.all([
    db
      .prepare('SELECT * FROM money_finality_journal WHERE operation_id = ?')
      .bind(operationId)
      .first(),
    db
      .prepare('SELECT state,reason,failures FROM money_jobs WHERE operation_id = ?')
      .bind(operationId)
      .first(),
    db
      .prepare(
        'SELECT receipt_sha256,proof_json,proof_sha256,outcome FROM money_reconciliations WHERE operation_id = ?',
      )
      .bind(operationId)
      .first(),
    db
      .prepare('SELECT operation_id FROM money_finality_conflicts WHERE operation_id = ?')
      .bind(operationId)
      .first(),
  ]);
  let receipt: Record<string, unknown> | null = null;
  if (journal) {
    if (
      typeof journal.receipt_json !== 'string' ||
      journal.receipt_json.length > 16384 ||
      deploymentDocumentDigest(journal.receipt_json) !== journal.receipt_sha256 ||
      typeof journal.finality_json !== 'string' ||
      journal.finality_json.length > 16384 ||
      deploymentDocumentDigest(journal.finality_json) !== journal.finality_sha256
    )
      throw new Error('MONEY_STATUS_INVALID');
    const value: unknown = JSON.parse(journal.receipt_json);
    if (!value || typeof value !== 'object' || Array.isArray(value))
      throw new Error('MONEY_STATUS_INVALID');
    receipt = value as Record<string, unknown>;
    const checkpoint =
      receipt.outcome === 'outer_transaction_reverted'
        ? (receipt.nonexecution as { checkpoint?: Record<string, unknown> } | undefined)?.checkpoint
        : receipt;
    if (
      receipt.userop_hash !== c.userOpHash ||
      receipt.consent_digest !== c.digest ||
      receipt.deployment_sha256 !== c.deployment_digest ||
      receipt.market_sha256 !== original.review.context.market.digest ||
      receipt.amount_atomic !== c.request.amount_atomic ||
      receipt.kind !== c.request.kind ||
      receipt.recipient_address !== (c.request.recipient_address ?? null) ||
      receipt.network_id !== c.request.network_id ||
      !checkpoint ||
      checkpoint.block_hash !== journal.block_hash ||
      checkpoint.block_number !== journal.block_number
    )
      throw new Error('MONEY_STATUS_INVALID');
  }
  if (
    reconciliation &&
    (!journal ||
      conflict ||
      reconciliation.receipt_sha256 !== journal.receipt_sha256 ||
      reconciliation.outcome !== original.state ||
      typeof reconciliation.proof_json !== 'string' ||
      reconciliation.proof_json.length > 32768 ||
      deploymentDocumentDigest(reconciliation.proof_json) !== reconciliation.proof_sha256)
  )
    throw new Error('MONEY_STATUS_INVALID');
  const current = await repository.readOperationHistory(walletId, accountId, operationId);
  if (current.record_sha256 !== original.record_sha256 || current.state !== original.state)
    throw new Error('MONEY_OPERATION_CHANGED');
  const draft = writeMoneyDraft(original.review);
  const settled = ['reconciled', 'reverted_confirmed'].includes(original.state);
  if (settled && !reconciliation) throw new Error('MONEY_STATUS_INVALID');
  return Object.freeze({
    money_schema_version: 1,
    operation_id: operationId,
    preparation_id: original.preparation_id,
    wallet_id: walletId,
    wallet_account_id: accountId,
    network_id: c.request.network_id,
    state: original.state,
    consent_digest: c.digest,
    userop_hash: c.userOpHash,
    review_json: draft.json,
    review_sha256: draft.digest,
    expires_at: c.plan.validUntil,
    dispatched_at: original.dispatch_started_at,
    job: job ? { state: job.state, reason: job.reason, failures: job.failures } : null,
    funds_reserved: !['reconciled', 'reverted_confirmed', 'expired_unsubmitted'].includes(
      original.state,
    ),
    settlement: settled ? original.state : 'unconfirmed',
    receipt,
    receipt_sha256: journal?.receipt_sha256 ?? null,
    evidence_conflict: !!conflict,
    send_enabled: false,
  });
}
