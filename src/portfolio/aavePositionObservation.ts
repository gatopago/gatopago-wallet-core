import {
  decodeFunctionResult,
  encodeFunctionData,
  erc20Abi,
  getAddress,
  isAddressEqual,
  keccak256,
  type Address,
  type Hex,
} from 'viem';
import {
  aavePoolAbi,
  aaveProviderAbi,
  aaveTokenAbi,
  EIP1967_IMPLEMENTATION_SLOT,
  loadAaveMarket,
  marketToken,
  type AaveMarketPin,
} from '@gatopago/shared/v3/aave-market';
import { parseAtomicAmount } from '@gatopago/shared/v3/primitives';
import { validateRpcProviders, type RpcProvider } from '../chainProviders';
import { withDeadline } from '../deadline';
import { checkpointReader } from './checkpointReader';
import { aavePositionExtraAbi, aaveReadAbiDigest } from './aaveReadAbi';
export { aaveReadAbiDigest } from './aaveReadAbi';
const RAY = 10n ** 27n;
const ceilRay = (scaled: bigint, index: bigint) => (scaled * index + RAY - 1n) / RAY;

export async function observeAavePosition(
  input: {
    account: Address;
    market: AaveMarketPin;
    checkpoint: { block_number: string; block_hash: Hex };
  },
  providers: readonly RpcProvider[],
  signal: AbortSignal,
) {
  const marketPin = structuredClone(input.market),
    market = loadAaveMarket(marketPin),
    account = getAddress(input.account),
    token = marketToken(market);
  const checkpoint = Object.freeze({ ...input.checkpoint });
  const block = BigInt(parseAtomicAmount(checkpoint.block_number));
  const now = Math.floor(Date.now() / 1000);
  if (
    market.abi_sha256 !== aaveReadAbiDigest ||
    now < market.valid_from ||
    now >= market.valid_until ||
    block < BigInt(market.admitted_block_number) ||
    (block === BigInt(market.admitted_block_number) &&
      checkpoint.block_hash !== market.admitted_block_hash)
  )
    throw new Error('POSITION_MARKET_UNAVAILABLE');
  const peers = validateRpcProviders(providers);
  return withDeadline(signal, 30_000, async (deadline) => {
    const results = await Promise.allSettled(
      peers.map(async (peer) => {
        const reader = checkpointReader(
          peer,
          {
            chainId: 421614n,
            genesisHash: market.genesis_hash,
            blockNumber: checkpoint.block_number,
            blockHash: checkpoint.block_hash,
          },
          deadline,
        );
        await reader.open();
        for (const contract of market.contracts) {
          const code = await reader.code(contract.address);
          if (code === '0x' || keccak256(code) !== contract.code_hash)
            throw new Error('POSITION_CODE_CHANGED');
          const word = await reader.storage(contract.address, EIP1967_IMPLEMENTATION_SLOT);
          if (!/^0x0{24}/.test(word)) throw new Error('POSITION_PROXY_CHANGED');
          const implementation = getAddress(`0x${word.slice(-40)}`);
          if (contract.implementation === null) {
            if (!/^0x0{40}$/.test(implementation)) throw new Error('POSITION_PROXY_CHANGED');
          } else if (
            !isAddressEqual(implementation, contract.implementation) ||
            keccak256(await reader.code(implementation)) !== contract.implementation_code_hash
          )
            throw new Error('POSITION_PROXY_CHANGED');
        }
        const poolOfProvider = decodeFunctionResult({
          abi: aaveProviderAbi,
          functionName: 'getPool',
          data: await reader.call(
            market.provider,
            encodeFunctionData({ abi: aaveProviderAbi, functionName: 'getPool' }),
          ),
        });
        const providerOfPool = decodeFunctionResult({
          abi: aavePoolAbi,
          functionName: 'ADDRESSES_PROVIDER',
          data: await reader.call(
            market.pool,
            encodeFunctionData({ abi: aavePoolAbi, functionName: 'ADDRESSES_PROVIDER' }),
          ),
        });
        const underlying = decodeFunctionResult({
          abi: aaveTokenAbi,
          functionName: 'UNDERLYING_ASSET_ADDRESS',
          data: await reader.call(
            market.a_token,
            encodeFunctionData({ abi: aaveTokenAbi, functionName: 'UNDERLYING_ASSET_ADDRESS' }),
          ),
        });
        const poolOfToken = decodeFunctionResult({
          abi: aaveTokenAbi,
          functionName: 'POOL',
          data: await reader.call(
            market.a_token,
            encodeFunctionData({ abi: aaveTokenAbi, functionName: 'POOL' }),
          ),
        });
        const decimals = decodeFunctionResult({
          abi: erc20Abi,
          functionName: 'decimals',
          data: await reader.call(
            token,
            encodeFunctionData({ abi: erc20Abi, functionName: 'decimals' }),
          ),
        });
        const reserve = decodeFunctionResult({
          abi: aavePoolAbi,
          functionName: 'getReserveData',
          data: await reader.call(
            market.pool,
            encodeFunctionData({ abi: aavePoolAbi, functionName: 'getReserveData', args: [token] }),
          ),
        });
        if (
          !isAddressEqual(poolOfProvider, market.pool) ||
          !isAddressEqual(providerOfPool, market.provider) ||
          !isAddressEqual(underlying, token) ||
          !isAddressEqual(poolOfToken, market.pool) ||
          !isAddressEqual(reserve.aTokenAddress, market.a_token) ||
          decimals !== market.decimals
        )
          throw new Error('POSITION_COMPOSITION_CHANGED');
        const config = reserve.configuration.data;
        if (Number((config >> 48n) & 255n) !== 6) throw new Error('POSITION_COMPOSITION_CHANGED');
        const user = decodeFunctionResult({
          abi: aavePoolAbi,
          functionName: 'getUserAccountData',
          data: await reader.call(
            market.pool,
            encodeFunctionData({
              abi: aavePoolAbi,
              functionName: 'getUserAccountData',
              args: [account],
            }),
          ),
        });
        const balanceOf = async (address: Address, owner: Address) =>
          decodeFunctionResult({
            abi: erc20Abi,
            functionName: 'balanceOf',
            data: await reader.call(
              address,
              encodeFunctionData({ abi: erc20Abi, functionName: 'balanceOf', args: [owner] }),
            ),
          });
        const usdc = await balanceOf(token, account),
          position = await balanceOf(market.a_token, account),
          liquidity = await balanceOf(token, market.a_token);
        const native = await reader.nativeBalance(account);
        const scaled = decodeFunctionResult({
          abi: aaveTokenAbi,
          functionName: 'scaledBalanceOf',
          data: await reader.call(
            market.a_token,
            encodeFunctionData({
              abi: aaveTokenAbi,
              functionName: 'scaledBalanceOf',
              args: [account],
            }),
          ),
        });
        const scaledTotal = decodeFunctionResult({
          abi: aavePositionExtraAbi,
          functionName: 'scaledTotalSupply',
          data: await reader.call(
            market.a_token,
            encodeFunctionData({ abi: aavePositionExtraAbi, functionName: 'scaledTotalSupply' }),
          ),
        });
        const index = decodeFunctionResult({
          abi: aavePositionExtraAbi,
          functionName: 'getReserveNormalizedIncome',
          data: await reader.call(
            market.pool,
            encodeFunctionData({
              abi: aavePositionExtraAbi,
              functionName: 'getReserveNormalizedIncome',
              args: [token],
            }),
          ),
        });
        if (index < RAY) throw new Error('POSITION_INDEX_INVALID');
        const allowance = decodeFunctionResult({
          abi: erc20Abi,
          functionName: 'allowance',
          data: await reader.call(
            token,
            encodeFunctionData({
              abi: erc20Abi,
              functionName: 'allowance',
              args: [account, market.pool],
            }),
          ),
        });
        const cap = ((config >> 116n) & ((1n << 36n) - 1n)) * 10n ** 6n;

        const used = ceilRay(scaledTotal + reserve.accruedToTreasury, index);
        const capacity = cap === 0n ? null : (cap > used ? cap - used : 0n).toString();
        await reader.close();
        return {
          usdc_balance_atomic: usdc.toString(),
          native_balance_atomic: native.toString(),
          position_balance_atomic: position.toString(),
          scaled_position_atomic: scaled.toString(),
          liquidity_index_ray: index.toString(),
          debt_base_atomic: user[1].toString(),
          liquidity_atomic: liquidity.toString(),
          supply_capacity_atomic: capacity,
          allowance_atomic: allowance.toString(),
          active: ((config >> 56n) & 1n) === 1n,
          frozen: ((config >> 57n) & 1n) === 1n,
          paused: ((config >> 60n) & 1n) === 1n,
        };
      }),
    );
    deadline.throwIfAborted();
    const [first, second] = results;
    if (first.status !== 'fulfilled' || second.status !== 'fulfilled')
      throw new Error('POSITION_UNAVAILABLE');
    if (JSON.stringify(first.value) !== JSON.stringify(second.value))
      throw new Error('POSITION_PROVIDERS_DISAGREE');
    const observed = Math.floor(Date.now() / 1000);
    if (observed >= market.valid_until) throw new Error('POSITION_MARKET_UNAVAILABLE');
    return {
      ...first.value,
      network_id: market.network_id,
      market_id: market.market_id,
      market_digest: marketPin.digest,
      asset_id: market.asset_id,
      a_token: market.a_token,
      account,
      checkpoint,
      observed_at: observed,
      expires_at: Math.min(observed + market.max_observation_age_seconds, market.valid_until),
      finality: 'not_assessed' as const,
      spend_readiness: 'not_assessed' as const,
    };
  });
}
