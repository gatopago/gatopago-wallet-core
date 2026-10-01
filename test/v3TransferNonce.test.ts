import { afterEach, describe, expect, it, vi } from 'vitest';
import { encodeFunctionData, keccak256, parseAbi, toHex, type Address, type Hex } from 'viem';
import { observeTransferNonce } from '../src/transfers/transferNonce';
import type { NetworkId } from '@gatopago/shared/v3/primitives';

afterEach(() => { vi.restoreAllMocks(); vi.unstubAllGlobals(); });
function fixture(fault = '') {
  const code: Hex = '0x6001600055';
  const input = { network_id: 'eip155:84532' as NetworkId, genesis_hash: `0x${'aa'.repeat(32)}` as Hex,
    account: `0x${'ab'.repeat(20)}` as Address, entry_point: `0x${'cd'.repeat(20)}` as Address,
    entry_point_code_hash: keccak256(code), checkpoint: { block_number: '123', block_hash: `0x${'bb'.repeat(32)}` as Hex } };
  const calls: { method: string; params: unknown[] }[] = [];
  const counts = new Map<string, number>();
  const transport = vi.fn(async (url: URL | RequestInfo, init?: RequestInit) => {
    const body = JSON.parse(String(init?.body)); calls.push(body); const host = new URL(String(url)).hostname;
    let result: unknown;
    if (body.method === 'eth_chainId') result = fault === 'chain' ? '0x1' : toHex(84532);
    else if (body.method === 'eth_getBlockByNumber') {
      const number = body.params[0]; const count = (counts.get(host) ?? 0) + 1; counts.set(host, count);
      result = { number, hash: number === '0x0' ? (fault === 'genesis' ? input.checkpoint.block_hash : input.genesis_hash)
        : fault === 'reorg' && count === 3 ? input.genesis_hash : input.checkpoint.block_hash };
    } else if (body.method === 'eth_getCode') result = fault === 'code' ? '0x6002' : code;
    else if (body.method === 'eth_call') result = fault === 'empty' ? '0x' : toHex(fault === 'key' ? 1n << 64n
      : fault === 'disagree' && host === 'b.example' ? 4n : 3n, { size: 32 });
    else throw new Error('Unexpected method');
    if (fault === 'rpc' && host === 'a.example') return new Response('unavailable', { status: 503 });
    return Response.json({ jsonrpc: '2.0', id: body.id, result });
  });
  vi.stubGlobal('fetch', transport);
  const peers = [{ operatorId: 'provider-a', url: 'https://a.example/rpc' }, { operatorId: 'provider-b', url: 'https://b.example/rpc' }];
  return { input, calls, transport, peers, run: (signal = new AbortController().signal) => observeTransferNonce(input, peers, signal) };
}
describe('EntryPoint nonce observation', () => {
  it('reads key zero at the selected hash using both peers and verifies EntryPoint code', async () => {
    const f = fixture(); const result = await f.run(); expect(result.nonce).toBe('3'); expect(f.transport).toHaveBeenCalledTimes(12);
    const read = f.calls.filter(c => c.method === 'eth_call'); expect(read).toHaveLength(2);
    const data = encodeFunctionData({ abi: parseAbi(['function getNonce(address,uint192) view returns(uint256)']), functionName: 'getNonce', args: [f.input.account, 0n] });
    for (const call of read) expect(call.params).toEqual([{ to: result.entry_point, data, gas: '0x186a0' },
      { blockHash: f.input.checkpoint.block_hash, requireCanonical: true }]);
    expect(f.calls.some(c => c.method === 'eth_getTransactionCount')).toBe(false);
  });
  it.each(['chain','genesis','reorg','code','empty','key','disagree','rpc'])('rejects %s instead of guessing a nonce', async fault => {
    const f = fixture(fault); await expect(f.run()).rejects.toThrow();
  });
  it('does no RPC when already aborted', async () => {
    const f = fixture(); await expect(f.run(AbortSignal.abort())).rejects.toThrow(); expect(f.transport).not.toHaveBeenCalled();
  });
  it('refuses duplicate operators before network access', async () => {
    const f = fixture(); f.peers[1].operatorId = f.peers[0].operatorId;
    await expect(f.run()).rejects.toThrow(); expect(f.transport).not.toHaveBeenCalled();
  });
});
