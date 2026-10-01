import { AUTHORIZED_USER, authorizationValues } from '../auth/authorization';
import { SponsorshipBudget } from '../sponsorship/budget';
import type { Hex } from 'viem';
import { deploymentDocumentDigest } from '@gatopago/shared/v3/deployment';
import type { ResourceId } from '@gatopago/shared/v3/primitives';
import type { Principal } from '../auth/principal';
import { TransferNonceReservationRepository } from './transferNonceReservation';
import { observeOwnedTransfer } from './transferObservation';
import { prepareTransferFinalityEvidence } from './transferFinalityEvidence';

/** Record independently observed finality, never a caller-posted receipt.
 * One immutable checkpoint per operation. Conflicts require review; neither a
 * conflict nor an unavailable read overwrites evidence or releases funds.
 * Balance reconciliation / reservation release is a separate coordinator.
 */
export async function recordOwnedTransferFinality(database: D1Database, identityInput: Principal,
  walletId: ResourceId<'wallet'>, accountId: ResourceId<'walletAccount'>, operationId: ResourceId<'operation'>,
  transaction: Hex | undefined, profilesInput: Parameters<typeof observeOwnedTransfer>[6], signal: AbortSignal) {
  const identity = Object.freeze({ ...identityInput }), profiles = structuredClone(profilesInput);
  const started = Math.floor(Date.now() / 1000);
  const read = () => new TransferNonceReservationRepository(database, identity).readOwned(walletId, accountId, operationId);
  const stored = await read();
  if (stored.state !== 'delivery_pending') throw new Error('TRANSFER_RECONCILIATION_NOT_PENDING');
  const result = await observeOwnedTransfer(database, identity, walletId, accountId, operationId, transaction, profiles, signal);
  signal.throwIfAborted();
  if (result.status !== 'observed' || result.finality_evidence.status !== 'finalized') {
    return Object.freeze({ ...result, journal: 'not_recorded' as const });
  }
  const now = Math.floor(Date.now() / 1000);
  if (now >= identity.expiresAt) throw new Error('TRANSFER_RECONCILIATION_EVIDENCE');
  const { profile, receiptJson, evidenceJson, receiptDigest, evidenceDigest } =
    prepareTransferFinalityEvidence(stored, operationId, result, profiles, started, now);
  const db = database.withSession('first-primary');
  const writes = await db.batch<Record<string, unknown>>([
    db.prepare(`INSERT INTO transfer_finality_journal
      (operation_id,receipt_json,receipt_sha256,evidence_json,evidence_sha256,recorded_at)
      SELECT r.id,?,?,?,?,? FROM transfer_nonce_reservations r
      JOIN wallet_accounts a ON a.id = r.wallet_account_id JOIN wallets w ON w.id = a.wallet_id
      JOIN users u ON u.id = w.user_id
      WHERE r.id = ? AND r.wallet_id = ? AND r.wallet_account_id = ? AND r.state = 'delivery_pending'
      AND r.userop_hash = ? AND r.consent_digest = ? AND r.deployment_manifest_sha256 = ?
      AND a.deployment_manifest_sha256 = r.deployment_manifest_sha256 AND a.address = r.account_address
      AND a.deployment_state NOT IN ('unsupported','retired') AND w.status = 'active'

      AND ${AUTHORIZED_USER}
      ON CONFLICT(operation_id) DO NOTHING`).bind(receiptJson, receiptDigest, evidenceJson, evidenceDigest, now,
        operationId, walletId, accountId, stored.candidate.userOpHash, stored.candidate.digest, profile.digest,
        ...authorizationValues(identity)),
    db.prepare(`INSERT INTO transfer_finality_conflicts
      (operation_id,receipt_json,receipt_sha256,evidence_json,evidence_sha256,recorded_at)
      SELECT j.operation_id,?,?,?,?,? FROM transfer_finality_journal j
      JOIN transfer_nonce_reservations r ON r.id = j.operation_id
      JOIN wallet_accounts a ON a.id = r.wallet_account_id JOIN wallets w ON w.id = a.wallet_id
      JOIN users u ON u.id = w.user_id
      WHERE r.id = ? AND r.wallet_id = ? AND r.wallet_account_id = ? AND r.state = 'delivery_pending'
      AND (j.receipt_json != ? OR j.receipt_sha256 != ?) AND r.userop_hash = ? AND r.consent_digest = ?
      AND r.deployment_manifest_sha256 = ? AND a.deployment_manifest_sha256 = r.deployment_manifest_sha256
      AND a.address = r.account_address AND a.deployment_state NOT IN ('unsupported','retired')
      AND w.status = 'active'
      AND ${AUTHORIZED_USER}
      ON CONFLICT(operation_id) DO NOTHING`).bind(receiptJson, receiptDigest, evidenceJson, evidenceDigest, now,
        operationId, walletId, accountId, receiptJson, receiptDigest, stored.candidate.userOpHash, stored.candidate.digest,
        profile.digest, ...authorizationValues(identity)),
    db.prepare('SELECT * FROM transfer_finality_journal WHERE operation_id = ?').bind(operationId),
    db.prepare('SELECT * FROM transfer_finality_conflicts WHERE operation_id = ?').bind(operationId),
  ]);
  const current = await read();
  signal.throwIfAborted();
  if (writes.some(r => !r.success) || writes.slice(0, 2).some(r => ![0, 1].includes(r.meta.changes)) || current.state !== 'delivery_pending'
    || current.candidate.digest !== stored.candidate.digest || current.candidate.userOpHash !== stored.candidate.userOpHash) {
    throw new Error('TRANSFER_RECONCILIATION_CHANGED');
  }
  const saved = writes[2].results[0], conflict = writes[3].results[0];
  if (!saved || typeof saved.receipt_json !== 'string' || typeof saved.evidence_json !== 'string'
    || deploymentDocumentDigest(saved.receipt_json) !== saved.receipt_sha256
    || deploymentDocumentDigest(saved.evidence_json) !== saved.evidence_sha256) throw new Error('TRANSFER_RECONCILIATION_JOURNAL');
  if (conflict && (typeof conflict.receipt_json !== 'string' || typeof conflict.evidence_json !== 'string'
    || deploymentDocumentDigest(conflict.receipt_json) !== conflict.receipt_sha256
    || deploymentDocumentDigest(conflict.evidence_json) !== conflict.evidence_sha256)) throw new Error('TRANSFER_RECONCILIATION_JOURNAL');
  if (!conflict && saved.receipt_json === receiptJson && stored.candidate.operation.paymaster) {
    await new SponsorshipBudget(database).settle(stored.candidate.userOpHash,
      BigInt(result.observation.actual_gas_cost), result.observation.transaction_hash);
  }
  // A newer observation never replaces the first final block / outcome.
  return Object.freeze({ ...result, journal: !conflict && saved.receipt_json === receiptJson && saved.receipt_sha256 === receiptDigest
    ? 'recorded' as const : 'conflict' as const });
}
