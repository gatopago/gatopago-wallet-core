import { isAddressEqual, keccak256, toHex, type Hex, type PublicClient } from 'viem';
import { inspectAccountDeployment, type AccountInspectionInput } from '@gatopago/shared/v3/account-inspection';
import { deriveAccountId, predictAccountAddress } from '@gatopago/shared/v3/authorizations';
import { loadPinnedDeploymentManifest, requireHash } from '@gatopago/shared/v3/deployment';
import { verifyTransferReceipt } from './transferReceipt';
import type { readTransferReview } from '@gatopago/shared/v3/transfer-review-record';

interface Profile extends Omit<AccountInspectionInput, 'checkpoint'> {
  readonly entryPointCodeHash: Hex;
}
function quantity(value: unknown) {
  if (typeof value !== 'string' || !/^0x(?:0|[1-9a-f][0-9a-f]{0,63})$(?![\s\S])/.test(value)) throw new Error('TRANSFER_RECEIPT_RPC_INVALID');
  return BigInt(value);
}

/** One bounded, read-only execution RPC. A second independent observer and
 * chain-specific finality are mandatory before reconciliation. Missing evidence
 * never proves non-inclusion and never permits rebroadcast or releasing holds.
 */
export async function observeTransferReceipt(client: PublicClient, recordInput: Awaited<ReturnType<typeof readTransferReview>>,
  transactionHash: Hex, profileInput: Profile) {
  const record = structuredClone(recordInput), profile = structuredClone(profileInput), candidate = record.candidate;
  requireHash(transactionHash); requireHash(profile.entryPointCodeHash);
  const manifest = loadPinnedDeploymentManifest(profile.document, profile.expectedDigest);
  const accountId = deriveAccountId(profile.initialSecurityCommitment, profile.userSaltCommitment);
  if (profile.expectedDigest !== candidate.deployment_digest || manifest.network_id !== candidate.request.network_id
    || manifest.lifecycle_status !== 'deployed' || accountId !== candidate.plan.accountId
    || !isAddressEqual(manifest.entry_point, candidate.plan.entryPoint)
    || !isAddressEqual(predictAccountAddress(manifest.components.factory.address, accountId, manifest.proxy.init_code_hash), candidate.account)) {
    throw new Error('TRANSFER_RECEIPT_PROFILE');
  }
  const options = { retryCount: 0, dedupe: false } as const;
  try {
    const raw = await client.request({ method: 'eth_getTransactionReceipt', params: [transactionHash] }, options);
    if (raw === null) return null;
    const observation = verifyTransferReceipt(record, transactionHash, raw);
    const checkpoint = { block_hash: observation.block_hash, block_number: observation.block_number };
    const inspected = await inspectAccountDeployment(client, { ...profile, checkpoint });
    if (inspected.status !== 'recognized' || inspected.account_id !== accountId || !isAddressEqual(inspected.account, candidate.account)) {
      throw new Error('TRANSFER_RECEIPT_ACCOUNT');
    }
    const tag = toHex(BigInt(observation.block_number));
    async function header() {
      const block = await client.request({ method: 'eth_getBlockByNumber', params: [tag, false] }, options);
      if (!block || block.hash !== observation.block_hash || quantity(block.number) !== BigInt(observation.block_number)) {
        throw new Error('TRANSFER_RECEIPT_BLOCK_CHANGED');
      }
      const time = quantity(block.timestamp);
      if (time < BigInt(candidate.plan.validAfter) || time > BigInt(candidate.plan.validUntil)) throw new Error('TRANSFER_RECEIPT_INCLUSION_TIME');
      return time;
    }
    const timestamp = await header();
    const code = await client.request({ method: 'eth_getCode', params: [candidate.plan.entryPoint,
      { blockHash: observation.block_hash, requireCanonical: true }] }, options);
    if (typeof code !== 'string' || code.length > 2 + 24_576 * 2 || !/^0x(?:[0-9a-fA-F]{2})+$(?![\s\S])/.test(code)
      || keccak256(code) !== profile.entryPointCodeHash) throw new Error('TRANSFER_RECEIPT_ENTRYPOINT');
    if (await header() !== timestamp) throw new Error('TRANSFER_RECEIPT_BLOCK_CHANGED');
    return Object.freeze({ ...observation, block_timestamp: timestamp.toString() });
  } catch {
    // Never return upstream URLs, credentials, signatures or detailed RPC errors.
    throw new Error('TRANSFER_RECEIPT_OBSERVATION_UNAVAILABLE');
  }
}
