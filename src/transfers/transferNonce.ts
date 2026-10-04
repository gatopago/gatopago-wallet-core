import { validateRpcProviders, type RpcProvider } from '../chainProviders';
import {
  encodeFunctionData,
  getAddress,
  keccak256,
  parseAbi,
  toHex,
  zeroAddress,
  type Address,
  type Hex,
} from 'viem';
import { requireHash } from '@gatopago/shared/v3/deployment';
import { evmChainId, parseAtomicAmount, type NetworkId } from '@gatopago/shared/v3/primitives';
import { createInspectionClient } from '../chainInspection';
import { withDeadline } from '../deadline';

const abi = parseAbi([
  'function getNonce(address sender, uint192 key) view returns (uint256 nonce)',
]);

/** Internal observation only. Ownership, live finality and EntryPoint admission
 * precede this call. It does not allocate a nonce or inspect the pending mempool.
 * The sender's direct spendNonce is intentionally never queried here.
 */
export async function observeTransferNonce(
  input: {
    network_id: NetworkId;
    genesis_hash: Hex;
    account: Address;
    entry_point: Address;
    entry_point_code_hash: Hex;
    checkpoint: { block_number: string; block_hash: Hex };
  },
  providers: readonly RpcProvider[],
  signal: AbortSignal,
) {
  const snapshot = structuredClone(input),
    peers = validateRpcProviders(providers);
  const chain = evmChainId(snapshot.network_id);
  const account = getAddress(snapshot.account),
    entryPoint = getAddress(snapshot.entry_point);
  if (account === zeroAddress || entryPoint === zeroAddress || account === entryPoint)
    throw new Error('TRANSFER_NONCE_CONTEXT');
  requireHash(snapshot.genesis_hash);
  requireHash(snapshot.entry_point_code_hash);
  requireHash(snapshot.checkpoint.block_hash);
  const blockNumber = toHex(BigInt(parseAtomicAmount(snapshot.checkpoint.block_number)));
  const block = { blockHash: snapshot.checkpoint.block_hash, requireCanonical: true } as const;
  const data = encodeFunctionData({ abi, functionName: 'getNonce', args: [account, 0n] });
  return withDeadline(signal, 30_000, async (deadline) => {
    const results = await Promise.allSettled(
      peers.map(async (peer) => {
        const client = createInspectionClient(peer.url, deadline),
          options = { retryCount: 0, dedupe: false } as const;
        const chainValue = await client.request({ method: 'eth_chainId' }, options);
        if (chainValue !== toHex(chain)) throw new Error('TRANSFER_NONCE_CHAIN');
        async function checkBlock(number: Hex, hash: Hex) {
          const value = await client.request(
            { method: 'eth_getBlockByNumber', params: [number, false] },
            options,
          );
          if (!value || value.number !== number || value.hash !== hash)
            throw new Error('TRANSFER_NONCE_BLOCK');
        }
        await checkBlock('0x0', snapshot.genesis_hash);
        await checkBlock(blockNumber, snapshot.checkpoint.block_hash);
        const code = await client.request(
          { method: 'eth_getCode', params: [entryPoint, block] },
          options,
        );
        if (
          typeof code !== 'string' ||
          code.length > 2 + 24576 * 2 ||
          !/^0x(?:[0-9a-fA-F]{2})+$(?![\s\S])/.test(code) ||
          keccak256(code) !== snapshot.entry_point_code_hash
        )
          throw new Error('TRANSFER_NONCE_ENTRYPOINT');
        const result = await client.request(
          { method: 'eth_call', params: [{ to: entryPoint, data, gas: '0x186a0' }, block] },
          options,
        );
        if (typeof result !== 'string' || !/^0x[0-9a-fA-F]{64}$(?![\s\S])/.test(result))
          throw new Error('TRANSFER_NONCE_INVALID');
        const nonce = BigInt(result);
        if (nonce >= 1n << 64n) throw new Error('TRANSFER_NONCE_KEY');
        await checkBlock(blockNumber, snapshot.checkpoint.block_hash);
        return nonce.toString();
      }),
    );
    deadline.throwIfAborted();
    const [a, b] = results;
    if (a.status !== 'fulfilled' || b.status !== 'fulfilled')
      throw new Error('TRANSFER_NONCE_UNAVAILABLE');
    if (a.value !== b.value) throw new Error('TRANSFER_NONCE_DISAGREEMENT');
    return Object.freeze({
      network_id: snapshot.network_id,
      account,
      entry_point: entryPoint,
      checkpoint: Object.freeze(snapshot.checkpoint),
      nonce: a.value,
      observed_at: Math.floor(Date.now() / 1000),
    });
  });
}
