import { describe, expect, it } from 'vitest';
import application from '../config/application.json';
import market from '../config/markets/aave-v3-arbitrum-sepolia-usdc.json';
import {
  configureMoney,
  parseMoneyApplication,
  requireMoneyFeature,
} from '../src/runtime/moneyConfig';
import { loadAaveMarket } from '@gatopago/shared/v3/aave-market';
import { deploymentDocumentDigest } from '@gatopago/shared/v3/deployment';
import { configureWalletNetworks } from '../src/runtime/config';
import { arbitrumSepolia } from '../src/runtime/catalog';
import { parseEnvironment } from '@gatopago/environment';
import environments from '@gatopago/environment/environments.json';

function networks() {
  const environment = parseEnvironment(environments.production);
  return configureWalletNetworks(
    { schema_version: 1, production: [arbitrumSepolia] },
    environment,
    {
      WALLET_RPC_ENDPOINTS: JSON.stringify({
        arbitrum_sepolia_offchain: 'https://one.example/rpc',
        arbitrum_sepolia_tenderly: 'https://two.example/rpc',
      }),
      PRIVATE_KEY: `0x${'01'.repeat(32)}`,
      WALLET_BACKUP_SIGNER_KEY: '',
    },
  );
}
describe('Public JSON monetary admission', () => {
  it('loads the versioned market and enabled recipes without admitting absent gas limits', () => {
    const result = configureMoney(application, market, networks());
    expect(loadAaveMarket(result.market).pool).toBe(market.pool);
    expect(result.application.features).toEqual({
      aave_supply: true,
      aave_withdraw: true,
      aave_withdraw_and_pay: true,
    });
    expect(result.gasByKind).toEqual({
      aave_supply: null,
      aave_withdraw: null,
      aave_withdraw_and_pay: null,
    });
    expect(result.market.digest).toBe(deploymentDocumentDigest(JSON.stringify(market)));
    expect(JSON.stringify(result.market)).not.toMatch(/private_key|https?:\/\//i);
  });
  it.each([
    { extra: true },
    { schema_version: 2 },
    { money_schema_version: 2 },
    { network_id: 'eip155:42161' },
    { account_profile: 'other' },
    { markets: [] },
    { markets: ['aave-v3-arbitrum-sepolia-usdc', 'aave-v3-arbitrum-sepolia-usdc'] },
    { features: { ...application.features, aave_supply: 'true' } },
    { features: { ...application.features, arbitrary_call: true } },
  ])('rejects malformed selector %j', (patch) => {
    expect(() => parseMoneyApplication({ ...application, ...patch })).toThrow();
  });
  it('rejects missing network, ABI and genesis mismatch while the legacy catalog stays valid', () => {
    const values = networks();
    expect(() => configureMoney(application, market, [])).toThrow();
    expect(() =>
      configureMoney(application, { ...market, abi_sha256: `0x${'12'.repeat(32)}` }, values),
    ).toThrow();
    expect(() =>
      configureMoney(application, { ...market, genesis_hash: `0x${'12'.repeat(32)}` }, values),
    ).toThrow();
    expect(values).toHaveLength(1);
    expect(values[0].transferProfile.assetIds).toContain(market.asset_id);
  });
  it('rejects a closed feature before preparing any operation', () => {
    const configuration = configureMoney(
      { ...application, features: { ...application.features, aave_supply: false } },
      market,
      networks(),
    );
    expect(() =>
      requireMoneyFeature(configuration, {
        schema_version: 1,
        kind: 'aave_supply',
        wallet_id: 'wal_11111111-1111-4111-8111-111111111111',
        wallet_account_id: 'wac_22222222-2222-4222-8222-222222222222',
        network_id: market.network_id,
        market_id: market.market_id,
        asset_id: market.asset_id,
        amount_atomic: '1',
        client_release_id: 'test',
      }),
    ).toThrow('MONEY_CAPABILITY_UNAVAILABLE');
  });
});
