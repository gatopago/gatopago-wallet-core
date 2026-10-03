import { getAddress, numberToHex, type Address, type Hex } from 'viem';
import { requireHash } from '@gatopago/shared/v3/deployment';
import { parseAtomicAmount } from '@gatopago/shared/v3/primitives';
import { discardResponseBody, readJsonBounded } from '@gatopago/shared/http';
import type { RpcProvider } from '../chainProviders';
import { withDeadline } from '../deadline';

export function rpcQuantity(value: unknown): bigint {
  if (typeof value !== 'string' || !/^0x(?:0|[1-9a-f][0-9a-f]{0,63})$(?![\s\S])/.test(value)) throw new Error('POSITION_RPC_INVALID');
  return BigInt(value);
}
function rpcBytes(value: unknown): Hex {
  if (typeof value !== 'string' || !/^0x(?:[0-9a-fA-F]{2})*$(?![\s\S])/.test(value)) throw new Error('POSITION_RPC_INVALID');
  return value.toLowerCase() as Hex;
}

/** Invocation-local, bounded reader. Contract reads use an EIP-1898 canonical
 * block hash, with opening/closing chain fences. No signing or write methods. */
export function checkpointReader(peerInput: RpcProvider, inputSource: {
  chainId: bigint; genesisHash: Hex; blockNumber: string; blockHash: Hex;
}, signal: AbortSignal) {
  const peer = { ...peerInput }, input = { ...inputSource };
  requireHash(input.genesisHash); requireHash(input.blockHash);
  const number = parseAtomicAmount(input.blockNumber), block = Object.freeze({ blockHash: input.blockHash, requireCanonical: true });
  let sequence = 0;
  async function rpc(method: 'eth_chainId' | 'eth_getBlockByNumber' | 'eth_call' | 'eth_getCode' | 'eth_getStorageAt' | 'eth_getBalance', params: readonly unknown[]) {
    const id = ++sequence;
    if (id > 64) throw new Error('POSITION_READ_LIMIT');
    return withDeadline(signal, 5000, async deadline => {
      const response = await fetch(peer.url, { method: 'POST', redirect: 'manual', signal: deadline,
        headers: { 'Content-Type': 'application/json', Accept: 'application/json' },
        body: JSON.stringify({ jsonrpc: '2.0', id, method, params }) });
      if (!response.ok) { await discardResponseBody(response); throw new Error('POSITION_RPC_UNAVAILABLE'); }
      const envelope = await readJsonBounded<unknown>(response, 131_072, deadline);
      if (!envelope || typeof envelope !== 'object' || Array.isArray(envelope) || !('jsonrpc' in envelope)
        || envelope.jsonrpc !== '2.0' || !('id' in envelope) || envelope.id !== id || !('result' in envelope) || 'error' in envelope) throw new Error('POSITION_RPC_INVALID');
      return envelope.result;
    });
  }
  async function fence(tag: Hex, expectedNumber: string, expectedHash: Hex) {
    const value = await rpc('eth_getBlockByNumber', [tag, false]);
    if (!value || typeof value !== 'object' || !('number' in value) || !('hash' in value)
      || rpcQuantity(value.number).toString() !== expectedNumber || value.hash !== expectedHash) throw new Error('POSITION_CHECKPOINT_MISMATCH');
  }
  return {
    async open() {
      if (rpcQuantity(await rpc('eth_chainId', [])) !== input.chainId) throw new Error('POSITION_NETWORK_MISMATCH');
      await fence('0x0', '0', input.genesisHash);
      await fence(numberToHex(BigInt(number)), number, input.blockHash);
    },
    close: () => fence(numberToHex(BigInt(number)), number, input.blockHash),
    async call(address: Address, data: Hex) {
      return rpcBytes(await rpc('eth_call', [{ to: getAddress(address), data, gas: '0x1e8480' }, block]));
    },
    async code(address: Address) { return rpcBytes(await rpc('eth_getCode', [getAddress(address), block])); },
    async storage(address: Address, slot: Hex) {
      const value = rpcBytes(await rpc('eth_getStorageAt', [getAddress(address), slot, block]));
      if (value.length !== 66) throw new Error('POSITION_STORAGE_INVALID');
      return value;
    },
    async nativeBalance(address: Address) { return rpcQuantity(await rpc('eth_getBalance', [getAddress(address), block])); },
  };
}
