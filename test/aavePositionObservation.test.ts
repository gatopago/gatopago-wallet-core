import { afterEach, describe, expect, it, vi } from 'vitest';
import { decodeFunctionData, encodeFunctionResult, erc20Abi, getAddress, keccak256, type Address, type Hex } from 'viem';
import { aavePoolAbi, aaveProviderAbi, aaveTokenAbi } from '@gatopago/shared/v3/aave-market';
import { deploymentDocumentDigest } from '@gatopago/shared/v3/deployment';
import { observeAavePosition } from '../src/portfolio/aavePositionObservation';
import { aavePositionExtraAbi, aaveReadAbiDigest } from '../src/portfolio/aaveReadAbi';

const hash = `0x${'aa'.repeat(32)}` as Hex, genesis = `0x${'bb'.repeat(32)}` as Hex;
const address = (byte: string) => getAddress(`0x${byte.repeat(20)}`);
const token = getAddress('0x75faf114eafb1bdbe2f0316df893fd58ce46aa4d'), provider = address('22'), pool = address('33'), aToken = address('44'), account = address('55');
const peers = [{ operatorId: 'one', url: 'https://one.example/rpc' }, { operatorId: 'two', url: 'https://two.example/rpc' }];
const code = '0x60126000' as Hex, RAY = 10n ** 27n;
const abi = [...aavePoolAbi, ...aaveProviderAbi, ...aaveTokenAbi, ...erc20Abi, ...aavePositionExtraAbi];
function input() {
  const now = Math.floor(Date.now() / 1000);
  const document = JSON.stringify({ schema_version: 1, market_id: 'aave-v3-arbitrum-sepolia-usdc', network_id: 'eip155:421614',
    asset_id: `eip155:421614/erc20:${token.toLowerCase()}`, decimals: 6, provider, pool, a_token: aToken,
    genesis_hash: genesis, abi_sha256: aaveReadAbiDigest, admitted_block_number: '100', admitted_block_hash: hash,
    valid_from: now - 60, valid_until: now + 3600, max_observation_age_seconds: 30,
    contracts: Object.entries({ provider, pool, token, a_token: aToken }).map(([name, address]) => ({
      name, address, code_hash: keccak256(code), implementation: null, implementation_code_hash: null,
    })) });
  return { account, market: { document, digest: deploymentDocumentDigest(document) }, checkpoint: { block_number: '100', block_hash: hash } };
}
interface Call { id: number; method: string; params: unknown[] }
function fixture(change: (call: Call, host: string, value: unknown) => unknown = (_c, _h, value) => value) {
  const calls: Call[] = [];
  vi.stubGlobal('fetch', vi.fn(async (url: string, init: RequestInit) => {
    const call = JSON.parse(String(init.body)) as Call; calls.push(call);
    expect(init.redirect).toBe('manual'); expect(init.signal).toBeDefined();
    let result: unknown;
    if (call.method === 'eth_chainId') result = '0x66eee';
    else if (call.method === 'eth_getBlockByNumber') result = call.params[0] === '0x0'
      ? { number: '0x0', hash: genesis } : { number: '0x64', hash };
    else if (call.method === 'eth_getCode') result = code;
    else if (call.method === 'eth_getStorageAt') result = `0x${'00'.repeat(32)}`;
    else if (call.method === 'eth_getBalance') result = '0x123456';
    else if (call.method === 'eth_call') {
      const request = call.params[0] as { to: Address; data: Hex }, decoded = decodeFunctionData({ abi, data: request.data });
      const name = decoded.functionName;
      if (name === 'getPool' || name === 'POOL') result = encodeFunctionResult({ abi, functionName: name, result: pool });
      else if (name === 'ADDRESSES_PROVIDER') result = encodeFunctionResult({ abi, functionName: name, result: provider });
      else if (name === 'UNDERLYING_ASSET_ADDRESS') result = encodeFunctionResult({ abi, functionName: name, result: token });
      else if (name === 'decimals') result = encodeFunctionResult({ abi, functionName: name, result: 6 });
      else if (name === 'getReserveData') result = encodeFunctionResult({ abi, functionName: name, result: {
        configuration: { data: (6n << 48n) | (1n << 56n) | (10000n << 116n) }, liquidityIndex: RAY,
        currentLiquidityRate: 0n, variableBorrowIndex: RAY, currentVariableBorrowRate: 0n, currentStableBorrowRate: 0n,
        lastUpdateTimestamp: 1, id: 0, aTokenAddress: aToken, stableDebtTokenAddress: address('66'), variableDebtTokenAddress: address('77'),
        interestRateStrategyAddress: address('88'), accruedToTreasury: 10n, unbacked: 0n, isolationModeTotalDebt: 0n,
      } });
      else if (name === 'getUserAccountData') result = encodeFunctionResult({ abi, functionName: name, result: [0n, 0n, 0n, 0n, 0n, 0n] });
      else if (name === 'balanceOf') result = encodeFunctionResult({ abi, functionName: name,
        result: request.to.toLowerCase() === aToken.toLowerCase() ? 12300000n : decoded.args?.[0]?.toLowerCase() === aToken.toLowerCase() ? 90000000n : 60000000n });
      else if (name === 'scaledBalanceOf') result = encodeFunctionResult({ abi, functionName: name, result: 10000000n });
      else if (name === 'scaledTotalSupply') result = encodeFunctionResult({ abi, functionName: name, result: 100000000n });
      else if (name === 'getReserveNormalizedIncome') result = encodeFunctionResult({ abi, functionName: name, result: RAY * 123n / 100n });
      else if (name === 'allowance') result = encodeFunctionResult({ abi, functionName: name, result: 0n });
      else throw new Error('Unexpected read');
    } else throw new Error('Unexpected method');
    return Response.json({ jsonrpc: '2.0', id: call.id, result: change(call, new URL(url).hostname, result) });
  }));
  return calls;
}
afterEach(() => { vi.restoreAllMocks(); vi.unstubAllGlobals(); });
describe('Exact-checkpoint Aave position observation', () => {
  it('keeps available USDC separate from interest-bearing position, debt and native gas', async () => {
    const calls = fixture(), result = await observeAavePosition(input(), peers, new AbortController().signal);
    expect(result).toMatchObject({ usdc_balance_atomic: '60000000', position_balance_atomic: '12300000', scaled_position_atomic: '10000000',
      debt_base_atomic: '0', allowance_atomic: '0', liquidity_atomic: '90000000', supply_capacity_atomic: '9876999987',
      finality: 'not_assessed', spend_readiness: 'not_assessed', active: true, frozen: false, paused: false });
    for (const call of calls) {
      if (['eth_call', 'eth_getCode', 'eth_getBalance'].includes(call.method)) expect(call.params[1]).toEqual({ blockHash: hash, requireCanonical: true });
      if (call.method === 'eth_getStorageAt') expect(call.params[2]).toEqual({ blockHash: hash, requireCanonical: true });
      expect(call.method).not.toMatch(/send|sign/);
    }
  });
  it('refuses differing peers instead of choosing a result', async () => {
    fixture((call, host, value) => call.method === 'eth_getBalance' && host === 'two.example' ? '0x0' : value);
    await expect(observeAavePosition(input(), peers, new AbortController().signal)).rejects.toThrow('POSITION_PROVIDERS_DISAGREE');
  });
  it.each(['chain', 'genesis', 'block', 'code', 'proxy', 'pool', 'token', 'decimals', 'reserve', 'index', 'short-result'])('rejects changed %s evidence', async kind => {
    fixture((call, host, value) => {
      if (host !== 'one.example') return value;
      if (kind === 'chain' && call.method === 'eth_chainId') return '0x1';
      if (kind === 'genesis' && call.method === 'eth_getBlockByNumber' && call.params[0] === '0x0') return { number: '0x0', hash };
      if (kind === 'block' && call.method === 'eth_getBlockByNumber' && call.params[0] === '0x64') return { number: '0x64', hash: genesis };
      if (kind === 'code' && call.method === 'eth_getCode') return '0x6013';
      if (kind === 'proxy' && call.method === 'eth_getStorageAt') return `0x${'00'.repeat(12)}${pool.slice(2).toLowerCase()}`;
      if (call.method !== 'eth_call') return value;
      const name = decodeFunctionData({ abi, data: (call.params[0] as { data: Hex }).data }).functionName;
      if (kind === 'pool' && name === 'getPool') return encodeFunctionResult({ abi, functionName: name, result: address('99') });
      if (kind === 'token' && name === 'UNDERLYING_ASSET_ADDRESS') return encodeFunctionResult({ abi, functionName: name, result: address('99') });
      if (kind === 'decimals' && name === 'decimals') return encodeFunctionResult({ abi, functionName: name, result: 18 });
      if (kind === 'reserve' && name === 'getReserveData') return '0x';
      if (kind === 'index' && name === 'getReserveNormalizedIncome') return encodeFunctionResult({ abi, functionName: name, result: RAY - 1n });
      if (kind === 'short-result') return '0x01';
      return value;
    });
    await expect(observeAavePosition(input(), peers, new AbortController().signal)).rejects.toThrow('POSITION_UNAVAILABLE');
  });
  it('rechecks canonical block inclusion after the position reads', async () => {
    let fences = 0;
    fixture((call, host, value) => host === 'one.example' && call.method === 'eth_getBlockByNumber' && call.params[0] === '0x64' && ++fences === 2
      ? { number: '0x64', hash: genesis } : value);
    await expect(observeAavePosition(input(), peers, new AbortController().signal)).rejects.toThrow('POSITION_UNAVAILABLE');
  });
  it('rejects ABI/market pin drift before any RPC', async () => {
    const calls = fixture(), source = input(), bad = JSON.parse(source.market.document); bad.abi_sha256 = hash;
    const document = JSON.stringify(bad);
    await expect(observeAavePosition({ ...source, market: { document, digest: deploymentDocumentDigest(document) } }, peers, new AbortController().signal)).rejects.toThrow('POSITION_MARKET_UNAVAILABLE');
    expect(calls).toHaveLength(0);
  });
  it('detaches market digest and checkpoint before I/O', async () => {
    fixture(); const mutable = input(), digest = mutable.market.digest;
    const task = observeAavePosition(mutable, peers, new AbortController().signal);
    mutable.market.digest = hash; mutable.checkpoint.block_hash = genesis;
    expect(await task).toMatchObject({ market_digest: digest, checkpoint: { block_hash: hash } });
  });
  it('rejects oversized response and cancellation without fabricated balances', async () => {
    vi.stubGlobal('fetch', vi.fn(async () => new Response('x'.repeat(131073))));
    await expect(observeAavePosition(input(), peers, new AbortController().signal)).rejects.toThrow('POSITION_UNAVAILABLE');
    await expect(observeAavePosition(input(), peers, AbortSignal.abort())).rejects.toThrow();
  });
});
