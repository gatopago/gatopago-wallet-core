import { validateRpcProviders, type RpcProvider } from '../chainProviders';
import { BackupDeliveryRepository, type BackupDeliveryClaim } from './backupDelivery';
import { verifyBackupTransaction, type BackupSponsorPolicy } from './backupTransaction';
import { backupTransport, preflightBackupTransaction } from './backupRpc';
import { withDeadline } from '../deadline';

/** Internal final transport boundary, NOT provider admission, account-state/finality
 * inspection, nonce allocation or a signer. Caller must first admit the pinned network,
 * sponsor budget and current backup state under its independent checkpoint policy.
 * Sign-only adapters cannot broadcast; the persisted envelope is their idempotency unit.
 * Two private, independently operated RPCs recheck chain/nonce/operator balance and
 * simulate the exact call. Only the first broadcasts, once. No provider fallback/retry.
 * Neither HTTP nor queue inputs may supply policy, endpoints or signed transaction bytes. */
export async function broadcastBackupTransaction(repository: BackupDeliveryRepository, claim: BackupDeliveryClaim,
 policy: BackupSponsorPolicy, raw: unknown, providers: readonly RpcProvider[], signal: AbortSignal,
 beforeSend: (signal: AbortSignal) => Promise<number>) {
 const sponsor = Object.freeze({ ...policy });
 const peers = validateRpcProviders(providers);
 signal.throwIfAborted();
 const request = await repository.transactionRequest(claim, sponsor);
 if (!request) return 'lease_lost' as const;
 const signed = await verifyBackupTransaction(request, raw);
 return withDeadline(signal, Math.max(1, Math.min(30_000, claim.until * 1000 - Date.now())), async (deadline) => {
 let evidenceExpiresAt: number;
 try {
  await preflightBackupTransaction(request, peers, deadline);
  // Mandatory fresh account/finality check AFTER signer and RPC simulation. There
  // is deliberately no default callback that treats a transport check as authority.
  evidenceExpiresAt = await beforeSend(deadline);
  if (!Number.isSafeInteger(evidenceExpiresAt) || evidenceExpiresAt <= Math.floor(Date.now() / 1000)) throw new Error('BACKUP_EVIDENCE_EXPIRED');
  deadline.throwIfAborted();
 } catch {
  await repository.retryBeforeSend(claim);
  return 'deferred' as const;
 }
 // An ambiguous D1 acknowledgement is NOT caught as preflight failure. A restarted
 // consumer observes the committed marker rather than signing/broadcasting again.
 if (!await repository.beginSend(claim, sponsor, signed.serialized, evidenceExpiresAt)) return 'lease_lost' as const;
 try {
  deadline.throwIfAborted();
  const hash = await backupTransport(peers[0].url, deadline)('eth_sendRawTransaction', [signed.serialized]);
  if (hash === signed.hash && await repository.accepted(claim, signed.hash)) return 'accepted' as const;
 } catch { /* Sent or possibly sent: only evidence-based observation may resolve it. */ }
 await repository.uncertain(claim);
 return 'uncertain' as const;
 });
}
