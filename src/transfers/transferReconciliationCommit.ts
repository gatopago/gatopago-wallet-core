import { AUTHORIZED_USER, authorizationValues } from '../auth/authorization';
import type { ResourceId } from '@gatopago/shared/v3/primitives';
import { deploymentDocumentDigest } from '@gatopago/shared/v3/deployment';
import type { Principal } from '../auth/principal';
import { WalletRepository } from '../accounts/repository';
import { observeTransferReconciliationBalance } from './transferBalanceReconciliation';
import { TransferNonceReservationRepository } from './transferNonceReservation';

/** Private coordinator: evidence is obtained here, never accepted from HTTP.
 * The D1 trigger commits evidence, balance watermark and hold release together.
 * A reverted execution also needs reconciliation (including gas); releasing its
 * hold is not a claim that the payment succeeded.
 */
export async function reconcileOwnedTransfer(database: D1Database, identityInput: Principal,
  walletId: ResourceId<'wallet'>, accountId: ResourceId<'walletAccount'>, operationId: ResourceId<'operation'>,
  transaction: Parameters<typeof observeTransferReconciliationBalance>[5],
  profiles: Parameters<typeof observeTransferReconciliationBalance>[6], signal: AbortSignal) {
  const identity = Object.freeze({ ...identityInput });
  const proof = await observeTransferReconciliationBalance(database, identity, walletId, accountId,
    operationId, transaction, profiles, signal);
  const owned = await new WalletRepository(database, identity).ownedAccount(walletId, accountId);
  const read = () => new TransferNonceReservationRepository(database, identity).readOwned(walletId, accountId, operationId);
  const stored = await read(), now = Math.floor(Date.now() / 1000);
  signal.throwIfAborted();
  if (stored.state !== 'delivery_pending' || proof.operation_id !== operationId || proof.wallet_id !== walletId
    || proof.wallet_account_id !== accountId || proof.userop_hash !== stored.candidate.userOpHash
    || proof.consent_digest !== stored.candidate.digest || proof.checked_at > now || now >= proof.expires_at
    || now >= identity.expiresAt || proof.balances.network_id !== owned.network_id
    || proof.balances.address.toLowerCase() !== owned.address) throw new Error('TRANSFER_COMMIT_CHANGED');
  const json = JSON.stringify(proof), digest = deploymentDocumentDigest(json), checkpoint = proof.balances.checkpoint;
  if (json.length > 32768) throw new Error('TRANSFER_COMMIT_SIZE');
  const db = database.withSession('first-primary');
  const result = await db.prepare(`INSERT INTO transfer_reconciliations
    (operation_id,wallet_account_id,receipt_sha256,block_number,block_hash,proof_json,proof_sha256,recorded_at)
    SELECT r.id,r.wallet_account_id,?,?,?,?,?,? FROM transfer_nonce_reservations r
    JOIN wallet_accounts a ON a.id = r.wallet_account_id JOIN wallets w ON w.id = a.wallet_id
    JOIN users u ON u.id = w.user_id
    WHERE r.id = ? AND r.wallet_id = ? AND r.wallet_account_id = ? AND r.state = 'delivery_pending'
    AND r.userop_hash = ? AND r.consent_digest = ? AND r.deployment_manifest_sha256 = ?
    AND a.deployment_manifest_sha256 = r.deployment_manifest_sha256 AND a.address = r.account_address
    AND a.deployment_state NOT IN ('unsupported','retired') AND w.status = 'active'

    AND ${AUTHORIZED_USER}
    ON CONFLICT(operation_id) DO NOTHING`).bind(proof.receipt_sha256, checkpoint.block_number, checkpoint.block_hash,
      json, digest, now, operationId, walletId, accountId, proof.userop_hash, proof.consent_digest,
      stored.candidate.deployment_digest, ...authorizationValues(identity)).run();
  const current = await read();
  signal.throwIfAborted();
  if (!result.success || result.meta.changes < 1 || current.state !== 'reconciled'
    || current.candidate.digest !== stored.candidate.digest) throw new Error('TRANSFER_COMMIT_CHANGED');
  return Object.freeze({ operation_id: operationId, reservation: 'reconciled' as const,
    balance_checkpoint: checkpoint, funds_reserved: false as const, send_enabled: false as const });
}
