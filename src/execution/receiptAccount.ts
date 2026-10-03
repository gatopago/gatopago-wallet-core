import { isAddressEqual, keccak256, toHex, type Address, type Hex, type PublicClient } from 'viem';
import { inspectAccountDeployment, type AccountInspectionInput } from '@gatopago/shared/v3/account-inspection';
import { deriveAccountId, predictAccountAddress } from '@gatopago/shared/v3/authorizations';
import { loadPinnedDeploymentManifest, requireHash } from '@gatopago/shared/v3/deployment';
import { rpcQuantity } from '../portfolio/checkpointReader';

export interface ReceiptAccountProfile extends Omit<AccountInspectionInput, 'checkpoint'> { readonly entryPointCodeHash: Hex }
export interface ReceiptAccountBinding {
  readonly account: Address; readonly deployment_digest: Hex; readonly request: { readonly network_id: string };
  readonly plan: { readonly accountId: Hex; readonly entryPoint: Address; readonly validAfter: number; readonly validUntil: number };
}

/** Historic code/composition and inclusion window, fenced at one canonical block.
 * This does not prove the financial effects or assess chain-specific finality. */
export async function inspectReceiptAccount(client: PublicClient, input: ReceiptAccountBinding,
  checkpointInput: { block_hash: Hex; block_number: string }, profileInput: ReceiptAccountProfile) {
  const candidate = structuredClone(input), checkpoint = { block_hash: checkpointInput.block_hash,
    block_number: checkpointInput.block_number }, profile = structuredClone(profileInput);
  requireHash(profile.entryPointCodeHash);
  const manifest = loadPinnedDeploymentManifest(profile.document, profile.expectedDigest);
  const accountId = deriveAccountId(profile.initialSecurityCommitment, profile.userSaltCommitment);
  if (profile.expectedDigest !== candidate.deployment_digest || manifest.network_id !== candidate.request.network_id
    || manifest.lifecycle_status !== 'deployed' || accountId !== candidate.plan.accountId
    || !isAddressEqual(manifest.entry_point, candidate.plan.entryPoint)
    || !isAddressEqual(predictAccountAddress(manifest.components.factory.address, accountId, manifest.proxy.init_code_hash), candidate.account)) throw new Error('EXECUTION_RECEIPT_PROFILE');
  const options = { retryCount: 0, dedupe: false } as const, tag = toHex(BigInt(checkpoint.block_number));
  async function header() {
    const block = await client.request({ method: 'eth_getBlockByNumber', params: [tag, false] }, options);
    if (!block || block.hash !== checkpoint.block_hash || rpcQuantity(block.number) !== BigInt(checkpoint.block_number)) throw new Error('EXECUTION_RECEIPT_BLOCK_CHANGED');
    const time = rpcQuantity(block.timestamp);
    if (time < BigInt(candidate.plan.validAfter) || time > BigInt(candidate.plan.validUntil)) throw new Error('EXECUTION_RECEIPT_INCLUSION_TIME');
    return time;
  }
  const timestamp = await header();
  const inspected = await inspectAccountDeployment(client, { ...profile, checkpoint });
  if (inspected.status !== 'recognized' || inspected.account_id !== accountId || !isAddressEqual(inspected.account, candidate.account)) throw new Error('EXECUTION_RECEIPT_ACCOUNT');
  const code = await client.request({ method: 'eth_getCode', params: [candidate.plan.entryPoint,
    { blockHash: checkpoint.block_hash, requireCanonical: true }] }, options);
  if (typeof code !== 'string' || code.length > 2 + 24_576 * 2 || !/^0x(?:[0-9a-fA-F]{2})+$(?![\s\S])/.test(code)
    || keccak256(code) !== profile.entryPointCodeHash) throw new Error('EXECUTION_RECEIPT_ENTRYPOINT');
  if (await header() !== timestamp) throw new Error('EXECUTION_RECEIPT_BLOCK_CHANGED');
  return timestamp.toString();
}
