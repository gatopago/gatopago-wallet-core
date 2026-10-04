import { validateRpcProviders, type RpcProvider } from '../chainProviders';
import { encodeFunctionData, erc20Abi, getAddress, numberToHex, type Hex } from 'viem';
import { requireHash } from '@gatopago/shared/v3/deployment';
import {
  assertAssetNetwork,
  evmChainId,
  parseAtomicAmount,
  type NetworkId,
} from '@gatopago/shared/v3/primitives';
import { discardResponseBody, readJsonBounded } from '@gatopago/shared/http';
import { withDeadline } from '../deadline';

interface Input {
  readonly network_id: NetworkId;
  readonly genesis_hash: Hex;
  readonly address: Hex;
  readonly checkpoint: { readonly block_number: string; readonly block_hash: Hex };
  /** Admitted fungible asset IDs, not names/decimals supplied by a token or browser. */
  readonly asset_ids: readonly string[];
}
function quantity(value: unknown): string {
  if (typeof value !== 'string' || !/^0x(?:0|[1-9a-f][0-9a-f]{0,63})$(?![\s\S])/.test(value))
    throw new Error('BALANCE_RPC_INVALID');
  return parseAtomicAmount(BigInt(value).toString());
}
function block(value: unknown, number: string, hash: Hex) {
  if (
    !value ||
    typeof value !== 'object' ||
    Array.isArray(value) ||
    !('number' in value) ||
    !('hash' in value) ||
    quantity(value.number) !== number ||
    value.hash !== hash
  )
    throw new Error('BALANCE_CHECKPOINT_MISMATCH');
}

/** Bounded, read-only snapshot at an exact EIP-1898 block hash. Caller supplies a
 * policy-selected checkpoint AFTER ownership/network admission. This lower layer
 * does not claim finality, wallet activation, available funds or spend authority.
 * Provider errors/disagreement throw, never become a fabricated zero balance.
 */
export async function observeAccountBalances(
  input: Input,
  providers: readonly RpcProvider[],
  signal: AbortSignal,
) {
  const network = input.network_id,
    chain = evmChainId(network),
    genesis = input.genesis_hash;
  requireHash(genesis);
  requireHash(input.checkpoint.block_hash);
  const address = getAddress(input.address),
    checkpoint = Object.freeze({ ...input.checkpoint });
  parseAtomicAmount(checkpoint.block_number);
  const assets = [...input.asset_ids];
  if (!assets.length || assets.length > 16 || new Set(assets).size !== assets.length)
    throw new Error('BALANCE_ASSETS_INVALID');
  let nativeCount = 0;
  for (const asset of assets) {
    assertAssetNetwork(asset, network);
    const kind = asset.split('/')[1];
    if (kind.startsWith('slip44:')) nativeCount++;
    else if (!kind.startsWith('erc20:') || /^erc20:0x0{40}$/.test(kind))
      throw new Error('BALANCE_ASSETS_INVALID');
  }
  if (nativeCount > 1) throw new Error('BALANCE_ASSETS_INVALID');
  const peers = validateRpcProviders(providers);
  return withDeadline(signal, 30_000, async (deadline) => {
    const selectedBlock = Object.freeze({
      blockHash: checkpoint.block_hash,
      requireCanonical: true,
    });
    const data = encodeFunctionData({ abi: erc20Abi, functionName: 'balanceOf', args: [address] });
    const observations = await Promise.allSettled(
      peers.map(async (peer) => {
        let nextId = 0;
        const rpc = (method: string, params: readonly unknown[]) =>
          withDeadline(deadline, 5000, async (timeout) => {
            const id = ++nextId;
            const response = await fetch(peer.url, {
              method: 'POST',
              redirect: 'manual',
              signal: timeout,
              headers: { 'Content-Type': 'application/json', Accept: 'application/json' },
              body: JSON.stringify({ jsonrpc: '2.0', id, method, params }),
            });
            if (!response.ok) {
              await discardResponseBody(response);
              throw new Error('BALANCE_RPC_UNAVAILABLE');
            }
            const envelope = await readJsonBounded<unknown>(response, 131_072, timeout);
            if (
              !envelope ||
              typeof envelope !== 'object' ||
              Array.isArray(envelope) ||
              !('jsonrpc' in envelope) ||
              envelope.jsonrpc !== '2.0' ||
              !('id' in envelope) ||
              envelope.id !== id ||
              !('result' in envelope) ||
              'error' in envelope
            ) {
              throw new Error('BALANCE_RPC_INVALID');
            }
            return envelope.result;
          });
        if (BigInt(quantity(await rpc('eth_chainId', []))) !== chain)
          throw new Error('BALANCE_NETWORK_MISMATCH');
        block(await rpc('eth_getBlockByNumber', ['0x0', false]), '0', genesis);
        const blockNumber = numberToHex(BigInt(checkpoint.block_number));
        block(
          await rpc('eth_getBlockByNumber', [blockNumber, false]),
          checkpoint.block_number,
          checkpoint.block_hash,
        );
        const balances: { asset_id: string; amount_atomic: string }[] = [];
        // Bounded sequential asset reads per peer; never an unbounded Promise fan-out.
        for (const asset of assets) {
          const kind = asset.split('/')[1];
          let amount: string;
          if (kind.startsWith('slip44:'))
            amount = quantity(await rpc('eth_getBalance', [address, selectedBlock]));
          else {
            const value = await rpc('eth_call', [
              { to: kind.slice(6), data, gas: '0x186a0' },
              selectedBlock,
            ]);
            if (typeof value !== 'string' || !/^0x[0-9a-fA-F]{64}$(?![\s\S])/.test(value))
              throw new Error('BALANCE_TOKEN_RESULT_INVALID');
            amount = BigInt(value).toString();
          }
          balances.push({ asset_id: asset, amount_atomic: amount });
        }
        block(
          await rpc('eth_getBlockByNumber', [blockNumber, false]),
          checkpoint.block_number,
          checkpoint.block_hash,
        );
        return balances;
      }),
    );
    deadline.throwIfAborted();
    const [first, second] = observations;
    if (first.status !== 'fulfilled' || second.status !== 'fulfilled')
      throw new Error('BALANCE_UNAVAILABLE');
    if (JSON.stringify(first.value) !== JSON.stringify(second.value))
      throw new Error('BALANCE_PROVIDERS_DISAGREE');
    return {
      network_id: network,
      address,
      checkpoint,
      balances: first.value,
      observed_at: Math.floor(Date.now() / 1000),
      finality: 'not_assessed' as const,
      spend_readiness: 'not_assessed' as const,
    };
  });
}
