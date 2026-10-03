import { loadAaveMarket, type AaveMarketPin } from '@gatopago/shared/v3/aave-market';
import { deploymentDocumentDigest } from '@gatopago/shared/v3/deployment';
import { moneyFields, parseMoneyRequest, type MoneyOperationRequest } from '@gatopago/shared/v3/money-wire';
import type { WalletNetwork } from './config';
import { aaveReadAbiDigest } from '../portfolio/aavePositionObservation';
import { loadMoneyGas } from './moneyGas';

const moneyKinds = ['aave_supply', 'aave_withdraw', 'aave_withdraw_and_pay'] as const;
export function parseMoneyApplication(value: unknown) {
  const input = moneyFields(value, ['schema_version', 'network_id', 'account_profile', 'money_schema_version', 'features', 'markets']);
  if (input.schema_version !== 1 || input.money_schema_version !== 1 || input.network_id !== 'eip155:421614'
    || input.account_profile !== 'account-v3-arbitrum-sepolia' || !Array.isArray(input.markets)
    || input.markets.length !== 1 || input.markets[0] !== 'aave-v3-arbitrum-sepolia-usdc') throw new Error('MONEY_CONFIGURATION_INVALID');
  const features = moneyFields(input.features, moneyKinds);
  if (Object.values(features).some(value => typeof value !== 'boolean')) throw new Error('MONEY_CONFIGURATION_INVALID');
  return Object.freeze({ schema_version: 1 as const, money_schema_version: 1 as const, network_id: 'eip155:421614' as const,
    account_profile: 'account-v3-arbitrum-sepolia' as const, markets: Object.freeze(['aave-v3-arbitrum-sepolia-usdc'] as const),
    features: Object.freeze({ ...features } as Record<MoneyOperationRequest['kind'], boolean>) });
}

/** Keep monetary admission separate: a bad/expired money configuration must not
 * replace identity, stored history or the legacy network configuration. */
export function configureMoney(applicationInput: unknown, marketInput: unknown, networks: readonly WalletNetwork[], gasInput: unknown = null) {
  const application = parseMoneyApplication(applicationInput);
  const document = JSON.stringify(marketInput), marketPin: AaveMarketPin = { document, digest: deploymentDocumentDigest(document) };
  const market = loadAaveMarket(marketPin);
  const network = networks.find(network => network.deployment.network_id === application.network_id);
  if (!network || network.deployment.genesis_hash !== market.genesis_hash || market.abi_sha256 !== aaveReadAbiDigest
    || !network.transferProfile.assetIds.includes(market.asset_id)) throw new Error('MONEY_CONFIGURATION_INVALID');
  const gasByKind = loadMoneyGas(gasInput, marketPin, network.transferProfile.digest);
  return Object.freeze({ application, market: Object.freeze(marketPin), network, gasByKind });
}
export function requireMoneyFeature(configuration: ReturnType<typeof configureMoney>, requestInput: unknown) {
  const request = parseMoneyRequest(requestInput), market = loadAaveMarket(configuration.market);
  const now = Math.floor(Date.now() / 1000);
  if (!configuration.application.features[request.kind] || !configuration.gasByKind[request.kind] || request.market_id !== market.market_id
    || now < market.valid_from || now >= market.valid_until) throw new Error('MONEY_CAPABILITY_UNAVAILABLE');
  return request;
}
