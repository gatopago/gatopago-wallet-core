import type { Hex, PublicClient } from 'viem';
import { requireHash } from '@gatopago/shared/v3/deployment';
import { inspectReceiptAccount, type ReceiptAccountProfile } from '../execution/receiptAccount';
import { verifyTransferReceipt } from './transferReceipt';
import type { readTransferReview } from '@gatopago/shared/v3/transfer-review-record';

/** One read-only observer. A second observer and finality remain mandatory. */
export async function observeTransferReceipt(
  client: PublicClient,
  recordInput: Awaited<ReturnType<typeof readTransferReview>>,
  transactionHash: Hex,
  profileInput: ReceiptAccountProfile,
) {
  const record = structuredClone(recordInput),
    profile = structuredClone(profileInput);
  requireHash(transactionHash);
  requireHash(profile.entryPointCodeHash);
  if (profile.expectedDigest !== record.candidate.deployment_digest)
    throw new Error('TRANSFER_RECEIPT_PROFILE');
  try {
    const raw = await client.request(
      { method: 'eth_getTransactionReceipt', params: [transactionHash] },
      { retryCount: 0, dedupe: false },
    );
    if (raw === null) return null;
    const observation = verifyTransferReceipt(record, transactionHash, raw);
    const timestamp = await inspectReceiptAccount(client, record.candidate, observation, profile);
    return Object.freeze({ ...observation, block_timestamp: timestamp });
  } catch {
    throw new Error('TRANSFER_RECEIPT_OBSERVATION_UNAVAILABLE');
  }
}
