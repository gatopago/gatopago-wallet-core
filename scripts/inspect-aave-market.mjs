import assert from 'node:assert/strict';
import { createHash } from 'node:crypto';
import { mkdirSync, writeFileSync } from 'node:fs';
import { resolve } from 'node:path';
import { createPublicClient, http, parseAbi, keccak256, zeroAddress } from 'viem';
import { arbitrumSepolia } from 'viem/chains';

// Read-only admission. No account signer, transaction or credential-file loading.
const root = resolve(import.meta.dirname, '..');
const endpoints = process.env.WALLET_RPC_ENDPOINTS ? JSON.parse(process.env.WALLET_RPC_ENDPOINTS) : {
  arbitrum_sepolia_offchain: 'https://sepolia-rollup.arbitrum.io/rpc',
  arbitrum_sepolia_tenderly: 'https://arbitrum-sepolia.gateway.tenderly.co',
};
const operators = ['offchain-labs', 'tenderly'];
const urls = ['arbitrum_sepolia_offchain', 'arbitrum_sepolia_tenderly'].map(key => {
  const url = new URL(endpoints[key]);
  assert(url.protocol === 'https:' && !url.username && !url.password && !url.hash, 'Invalid RPC endpoint');
  return url.href;
});
assert(new URL(urls[0]).hostname !== new URL(urls[1]).hostname, 'Independent RPCs required');
const peers = urls.map(url => createPublicClient({ chain: arbitrumSepolia, transport: http(url, { timeout: 15_000, retryCount: 1 }) }));
const addresses = {
  provider: '0xB25a5D144626a0D488e52AE717A051a2E9997076',
  pool: '0xBfC91D59fdAA134A4ED45f7B584cAf96D7792Eff',
  token: '0x75faf114eafb1BDbe2F0316DF893fd58CE46AA4d',
  a_token: '0x460b97BD498E1157530AEb3086301d5225b91216',
};
const sourceUrl = 'https://raw.githubusercontent.com/bgd-labs/aave-address-book/main/src/AaveV3ArbitrumSepolia.sol';
const implementationSlot = '0x360894a13ba1a3210667c828492db98dca3e2076cc3735a920a3ca505d382bbc';
const abi = parseAbi([
  'function getPool() view returns (address)',
  'function decimals() view returns (uint8)',
  'function UNDERLYING_ASSET_ADDRESS() view returns (address)',
  'function POOL() view returns (address)',
  'function balanceOf(address) view returns (uint256)',
  'function getConfiguration(address asset) view returns ((uint256 data))',
  'function getReserveData(address asset) view returns (((uint256 data) configuration,uint128 liquidityIndex,uint128 currentLiquidityRate,uint128 variableBorrowIndex,uint128 currentVariableBorrowRate,uint128 currentStableBorrowRate,uint40 lastUpdateTimestamp,uint16 id,address aTokenAddress,address stableDebtTokenAddress,address variableDebtTokenAddress,address interestRateStrategyAddress,uint128 accruedToTreasury,uint128 unbacked,uint128 isolationModeTotalDebt))',
]);
const json = value => JSON.stringify(value, (_, item) => typeof item === 'bigint' ? item.toString() : item);
const output = resolve(root, '../protocol/docs/arbitrum-delivery/market-admission.json');
const observedAt = new Date().toISOString();
try {
  const sourceResponse = await fetch(sourceUrl, { signal: AbortSignal.timeout(15_000) });
  assert(sourceResponse.ok, 'Address source unavailable');
  const source = await sourceResponse.text();
  for (const address of Object.values(addresses)) assert(source.toLowerCase().includes(address.toLowerCase()), 'Address source changed');
  const headers = await Promise.all(peers.map(async client => ({ chain: await client.getChainId(),
    finalized: await client.getBlock({ blockTag: 'finalized' }), genesis: await client.getBlock({ blockNumber: 0n }) })));
  assert(headers.every(header => header.chain === 421614), 'Wrong chain');
  assert(headers[0].genesis.hash === headers[1].genesis.hash, 'Genesis disagreement');
  const blockNumber = headers.reduce((n, header) => header.finalized.number < n ? header.finalized.number : n, headers[0].finalized.number);
  const blocks = await Promise.all(peers.map(client => client.getBlock({ blockNumber })));
  assert(blocks[0].hash === blocks[1].hash, 'Checkpoint disagreement');
  assert(Number(blocks[0].timestamp) > Date.now() / 1000 - 7200, 'Finalized checkpoint too old');
  const observations = await Promise.all(peers.map(async client => {
    const read = (address, functionName, args = []) => client.readContract({ address, abi, functionName, args, blockNumber });
    const [pool, decimals, underlying, aPool, reserve, configuration, liquidity] = await Promise.all([
      read(addresses.provider, 'getPool'), read(addresses.token, 'decimals'),
      read(addresses.a_token, 'UNDERLYING_ASSET_ADDRESS'), read(addresses.a_token, 'POOL'),
      read(addresses.pool, 'getReserveData', [addresses.token]), read(addresses.pool, 'getConfiguration', [addresses.token]),
      read(addresses.token, 'balanceOf', [addresses.a_token]),
    ]);
    const contracts = await Promise.all(Object.entries(addresses).map(async ([name, address]) => {
      const code = await client.getCode({ address, blockNumber });
      assert(code && code !== '0x', 'Contract code absent');
      const storage = await client.getStorageAt({ address, slot: implementationSlot, blockNumber });
      const implementation = storage ? `0x${storage.slice(-40)}` : zeroAddress;
      let implementationCodeHash = null;
      if (implementation !== zeroAddress) {
        assert(/^0x0{24}/.test(storage), 'Noncanonical proxy slot');
        const implementationCode = await client.getCode({ address: implementation, blockNumber });
        assert(implementationCode && implementationCode !== '0x', 'Proxy implementation absent');
        implementationCodeHash = keccak256(implementationCode);
      }
      return { name, address: address.toLowerCase(), code_hash: keccak256(code),
        eip1967_implementation: implementation, implementation_code_hash: implementationCodeHash };
    }));
    const config = configuration.data;
    return { pool, decimals, underlying, aPool, reserve, configuration: config, liquidity, contracts,
      flags: { active: !!(config & 1n << 56n), frozen: !!(config & 1n << 57n), paused: !!(config & 1n << 60n),
        decimals: Number(config >> 48n & 255n), supply_cap_tokens: (config >> 116n & ((1n << 36n) - 1n)).toString() } };
  }));
  assert(json(observations[0]).toLowerCase() === json(observations[1]).toLowerCase(), 'RPC market disagreement');
  const observation = observations[0];
  assert(observation.pool.toLowerCase() === addresses.pool.toLowerCase(), 'Provider pool mismatch');
  assert(observation.underlying.toLowerCase() === addresses.token.toLowerCase() && observation.aPool.toLowerCase() === addresses.pool.toLowerCase(), 'aToken composition mismatch');
  assert(observation.reserve.aTokenAddress.toLowerCase() === addresses.a_token.toLowerCase(), 'Reserve aToken mismatch');
  assert(observation.decimals === 6 && observation.flags.decimals === 6, 'Decimals mismatch');
  assert(observation.flags.active && !observation.flags.frozen && !observation.flags.paused, 'Reserve unavailable');
  assert(observation.liquidity >= 20_000_000n, 'Demo withdrawal liquidity unavailable');
  const record = { schema_version: 1, status: 'market_observed', observed_at: observedAt,
    network_id: 'eip155:421614', market_id: 'aave-v3-arbitrum-sepolia-usdc', addresses,
    source: { url: sourceUrl, sha256: createHash('sha256').update(source).digest('hex') },
    abi_sha256: createHash('sha256').update(JSON.stringify(abi)).digest('hex'), abi,
    checkpoint: { block_number: blockNumber.toString(), block_hash: blocks[0].hash, timestamp: blocks[0].timestamp.toString(), genesis_hash: headers[0].genesis.hash },
    operators, observation, limitations: ['Read-only market check; not proof of account debt, execution or gas budget', 'EIP1967 identity observation is not a complete proxy audit', 'Admission does not enable a feature flag'] };
  mkdirSync(resolve(output, '..'), { recursive: true });
  writeFileSync(output, JSON.stringify(JSON.parse(json(record)), null, 2) + '\n');
  console.log(json({ status: record.status, block: blockNumber, liquidity_atomic: observation.liquidity, flags: observation.flags }));
} catch {
  // Provider errors may contain secret endpoint URLs: persist only a stable public code.
  mkdirSync(resolve(output, '..'), { recursive: true });
  writeFileSync(output, JSON.stringify({ schema_version: 1, status: 'not_admitted', observed_at: observedAt,
    error_code: 'AAVE_MARKET_INSPECTION_FAILED', operators }, null, 2) + '\n');
  console.error('AAVE_MARKET_INSPECTION_FAILED');
  process.exitCode = 1;
}
