import { afterEach, describe, expect, it, vi } from 'vitest';
import { observeAccountBalances } from '../src/portfolio/balanceObservation';

const hash = `0x${'aa'.repeat(32)}` as const, genesis = `0x${'bb'.repeat(32)}` as const;
const native = 'eip155:84532/slip44:60', token = `eip155:84532/erc20:0x${'cc'.repeat(20)}`;
const input = () => ({ network_id: 'eip155:84532' as const, genesis_hash: genesis, address: `0x${'dd'.repeat(20)}` as const,
 checkpoint: { block_number: '100', block_hash: hash }, asset_ids: [native, token] });
const peers = [{ operatorId: 'provider-a', url: 'https://a.example/rpc' }, { operatorId: 'provider-b', url: 'https://b.example/rpc' }];
type Call = { jsonrpc: string; id: number; method: string; params: unknown[] };
function rpcFixture(change: (call: Call, host: string, result: unknown) => unknown = (_c, _h, result) => result) {
 const calls: Call[] = [];
 const fetcher = vi.fn(async (url: RequestInfo | URL, init?: RequestInit) => {
  const call = JSON.parse(String(init?.body)) as Call; calls.push(call);
  expect(init?.redirect).toBe('manual'); expect(init?.signal).toBeDefined();
  let result: unknown;
  if (call.method === 'eth_chainId') result = '0x14a34';
  else if (call.method === 'eth_getBlockByNumber') result = call.params[0] === '0x0'
   ? { number: '0x0', hash: genesis } : { number: '0x64', hash };
  else if (call.method === 'eth_getBalance') result = '0x0';
  else if (call.method === 'eth_call') result = `0x${(12345987654n).toString(16).padStart(64, '0')}`;
  else throw new Error('Unexpected RPC method');
  return Response.json({ jsonrpc: '2.0', id: call.id, result: change(call, new URL(String(url)).hostname, result) });
 });
 vi.stubGlobal('fetch', fetcher); return { calls, fetcher };
}
afterEach(() => { vi.useRealTimers(); vi.unstubAllGlobals(); vi.restoreAllMocks(); });
describe('Account balance snapshot: two peers, same canonical hash, no monetary readiness', () => {
 it('preserves real zero and exact token units at a common hash without polling or signing', async () => {
  const f = rpcFixture(); const result = await observeAccountBalances(input(), peers, new AbortController().signal);
  expect(result.balances).toEqual([{ asset_id: native, amount_atomic: '0' }, { asset_id: token, amount_atomic: '12345987654' }]);
  expect(result).toMatchObject({ checkpoint: input().checkpoint, finality: 'not_assessed', spend_readiness: 'not_assessed' });
  for (const call of f.calls.filter((c) => ['eth_call', 'eth_getBalance'].includes(c.method))) {
   expect(call.params[1]).toEqual({ blockHash: hash, requireCanonical: true });
  }
  expect(f.fetcher).toHaveBeenCalledTimes(12);
 });
 it('does not turn a disagreeing balance into zero or choose one successful peer', async () => {
  rpcFixture((c, host, value) => c.method === 'eth_getBalance' && host === 'b.example' ? '0x1' : value);
  await expect(observeAccountBalances(input(), peers, new AbortController().signal)).rejects.toThrow('BALANCE_PROVIDERS_DISAGREE');
 });
 it.each(['chain', 'genesis', 'block', 'empty-token', 'short-token', 'quantity'])('refuses invalid %s evidence', async (kind) => {
  rpcFixture((c, host, value) => {
   if (host !== 'a.example') return value;
   if (kind === 'chain' && c.method === 'eth_chainId') return '0x1';
   if (kind === 'genesis' && c.method === 'eth_getBlockByNumber' && c.params[0] === '0x0') return { number: '0x0', hash };
   if (kind === 'block' && c.method === 'eth_getBlockByNumber' && c.params[0] === '0x64') return { number: '0x64', hash: genesis };
   if (kind === 'empty-token' && c.method === 'eth_call') return '0x';
   if (kind === 'short-token' && c.method === 'eth_call') return '0x01';
   if (kind === 'quantity' && c.method === 'eth_getBalance') return '0x00';
   return value;
  });
  await expect(observeAccountBalances(input(), peers, new AbortController().signal)).rejects.toThrow('BALANCE_UNAVAILABLE');
 });
 it('rechecks canonical inclusion after the balance reads', async () => {
  let reads = 0;
  rpcFixture((c, host, value) => {
   if (host === 'a.example' && c.method === 'eth_getBlockByNumber' && c.params[0] === '0x64' && ++reads === 2) return { number: '0x64', hash: genesis };
   return value;
  });
  await expect(observeAccountBalances(input(), peers, new AbortController().signal)).rejects.toThrow('BALANCE_UNAVAILABLE');
 });
 it('rejects invalid scope before network access', async () => {
  const f = rpcFixture();
  for (const asset_ids of [[], [native, native], ['eip155:1/slip44:60'], [native, 'eip155:84532/slip44:1'],
   [`eip155:84532/erc721:0x${'cc'.repeat(20)}/1`]]) {
   await expect(observeAccountBalances({ ...input(), asset_ids }, peers, new AbortController().signal)).rejects.toThrow();
  }
  await expect(observeAccountBalances(input(), [peers[0], peers[0]], new AbortController().signal)).rejects.toThrow();
  await expect(observeAccountBalances(input(), peers, AbortSignal.abort())).rejects.toThrow();
  expect(f.fetcher).not.toHaveBeenCalled();
 });
 it('detaches caller input before awaiting a response', async () => {
  rpcFixture(); const mutable = input(); const task = observeAccountBalances(mutable, peers, new AbortController().signal);
  mutable.asset_ids.length = 0; mutable.checkpoint.block_number = '200';
  const result = await task; expect(result.checkpoint.block_number).toBe('100'); expect(result.balances).toHaveLength(2);
 });
 it('rejects an oversized provider response without a zero fallback', async () => {
  vi.stubGlobal('fetch', vi.fn(async () => new Response('x'.repeat(131_073))));
  await expect(observeAccountBalances(input(), peers, new AbortController().signal)).rejects.toThrow('BALANCE_UNAVAILABLE');
 });
 it('honors cancellation during reads and does not deliver late balances', async () => {
  const controller = new AbortController();
  vi.stubGlobal('fetch', vi.fn((_url: RequestInfo | URL, init?: RequestInit) => new Promise<Response>((_resolve, reject) => {
   init?.signal?.addEventListener('abort', () => reject(new Error('aborted')), { once: true });
  })));
  const task = observeAccountBalances(input(), peers, controller.signal);
  controller.abort(new Error('session changed'));
  await expect(task).rejects.toThrow('session changed');
 });
 it('bounds a stalled RPC instead of retrying or polling forever', async () => {
  vi.useFakeTimers();
  const fetcher = vi.fn((_url: RequestInfo | URL, init?: RequestInit) => new Promise<Response>((_resolve, reject) => {
   init?.signal?.addEventListener('abort', () => reject(new Error('timeout')), { once: true });
  }));
  vi.stubGlobal('fetch', fetcher);
  const task = expect(observeAccountBalances(input(), peers, new AbortController().signal)).rejects.toThrow('BALANCE_UNAVAILABLE');
  await vi.advanceTimersByTimeAsync(5000); await task; expect(fetcher).toHaveBeenCalledTimes(2);
 });
});
