import { describe, expect, it } from 'vitest';
import { generatePrivateKey, privateKeyToAccount } from 'viem/accounts';
import { configureWalletNetworks } from '../src/runtime/config';
import { runtimeFixture } from './runtime.fixture';
import { finalityPin, finalityPolicyFixture } from '@gatopago/test-fixtures/v3-finality';

describe('reviewed Wallet Core runtime configuration', () => {
  it('resolves only named secrets and keeps contract pins independent of endpoint credentials', () => {
    const f = runtimeFixture(), [network] = configureWalletNetworks(f.catalog, f.environment, f.bindings);
    expect(network.providers.map(p => p.url)).toEqual(['https://observer-a.invalid/', 'https://observer-b.invalid/']);
    expect(network.transferProfile.entryPointCodeHash).toBe(f.profile.entry_point_code_hash);
    expect(network.transferProfile.digest).not.toBe(network.digest);
    expect(network.creationGas.verificationGasLimit).toBe(2000000n);
    expect(network.backup).toBeUndefined();
    network.transferProfile.assetIds.splice(0);
    expect(configureWalletNetworks(f.catalog, f.environment, f.bindings)[0].transferProfile.assetIds).toHaveLength(1);
  });
  it.each(['digest', 'unprovisioned', 'disabled-network', 'duplicate-network', 'operator-overlap', 'host-overlap',
    'missing-endpoint', 'unsafe-endpoint', 'bad-gas', 'priority-fee', 'wrong-asset-network', 'missing-native',
    'expired-policy', 'unknown-field', 'malformed-secrets'] as const)('rejects %s before creating any transport', fault => {
    const f = runtimeFixture();
    if (fault === 'digest') f.network.creationProfile.digest = `0x${'a'.repeat(64)}`;
    if (fault === 'unprovisioned') f.environment.status = 'unprovisioned';
    if (fault === 'disabled-network') f.environment.wallet_enabled = [];
    if (fault === 'duplicate-network') f.catalog.staging.push(structuredClone(f.network));
    if (fault === 'operator-overlap') f.network.rpc[1].operatorId = f.network.rpc[0].operatorId;
    if (fault === 'host-overlap') f.bindings.WALLET_RPC_ENDPOINTS = JSON.stringify({ observer_a: 'https://same.invalid/a', observer_b: 'https://same.invalid/b', bundler: 'https://bundler.invalid' });
    if (fault === 'missing-endpoint') f.network.transport.endpoint = 'missing';
    if (fault === 'unsafe-endpoint') f.bindings.WALLET_RPC_ENDPOINTS = JSON.stringify({ observer_a: 'http://secret.invalid/key' });
    if (fault === 'bad-gas') f.network.creationGas.verificationGasLimit = '0';
    if (fault === 'priority-fee') f.network.transferGas.maxPriorityFeePerGas = '1000000001';
    if (fault === 'wrong-asset-network') f.network.assets = { 'eip155:1/slip44:60': { symbol: 'ETH', decimals: 18 } };
    if (fault === 'missing-native') f.network.assets = {};
    if (fault === 'expired-policy') f.network.finalityPolicy = finalityPin(finalityPolicyFixture(f.profile.deployment, Math.floor(Date.now() / 1000) - 86401));
    if (fault === 'unknown-field') Object.assign(f.network, { skipValidation: true });
    if (fault === 'malformed-secrets') f.bindings.WALLET_RPC_ENDPOINTS = 'secret-invalid-json';
    expect(() => configureWalletNetworks(f.catalog, f.environment, f.bindings)).toThrow(/^WALLET_RUNTIME_CONFIGURATION_INVALID$/);
  });
  it('admits a separately pinned paymaster with bounded budgets and rejects unlimited policy', () => {
    const f = runtimeFixture(), signer = privateKeyToAccount(generatePrivateKey()).address;
    const paymaster = { address: signer, codeHash: `0x${'ab'.repeat(32)}`, signer, verificationGasLimit: '100000', postOpGasLimit: '0',
      maximumCostWei: '1000000000000000', dailyGwei: 10000000, userDailyGwei: 1000000, userDailyOperations: 10 };
    const catalog = (p: typeof paymaster) => ({ ...f.catalog, staging: [{ ...f.network, paymaster: p }] });
    expect(configureWalletNetworks(catalog(paymaster), f.environment, f.bindings)[0].paymaster).toEqual(paymaster);
    for (const changed of [{ ...paymaster, userDailyGwei: 10000001 }, { ...paymaster, maximumCostWei: '0' },
      { ...paymaster, userDailyOperations: 0 }, { ...paymaster, codeHash: `0x${'00'.repeat(32)}` }]) {
      expect(() => configureWalletNetworks(catalog(changed), f.environment, f.bindings)).toThrow('WALLET_RUNTIME_CONFIGURATION_INVALID');
    }
  });
  it('admits self relay without a bundler endpoint and requires an independent operator key', () => {
    const f = runtimeFixture(), key = generatePrivateKey();
    const transport = { kind: 'self', endpoint: 'observer_a', maxGas: '2000000',
      maxFeePerGas: '100000000', maxPriorityFeePerGas: '0' };
    const catalog = { ...f.catalog, staging: [{ ...f.network, transport }] };
    const bindings = { ...f.bindings, PRIVATE_KEY: key,
      WALLET_RPC_ENDPOINTS: JSON.stringify({ observer_a: 'https://observer-a.invalid/', observer_b: 'https://observer-b.invalid/' }) };
    const [network] = configureWalletNetworks(catalog, f.environment, bindings);
    expect(network.transport.kind).toBe('self');
    for (const changed of [{ ...bindings, PRIVATE_KEY: '' },
      { ...bindings, WALLET_BACKUP_SIGNER_KEY: key }, { ...bindings, WALLET_PAYMASTER_SIGNER_KEY: key }]) {
      expect(() => configureWalletNetworks(catalog, f.environment, changed)).toThrow('WALLET_RUNTIME_CONFIGURATION_INVALID');
    }
    for (const changed of [{ ...transport, kind: 'unknown' }, { ...transport, maxGas: '30000001' },
      { ...transport, maxPriorityFeePerGas: '100000001' }, { ...transport, endpoint: 'missing' }]) {
      expect(() => configureWalletNetworks({ ...catalog, staging: [{ ...f.network, transport: changed }] }, f.environment, bindings))
        .toThrow('WALLET_RUNTIME_CONFIGURATION_INVALID');
    }
  });
  it('binds the optional gas sponsor to the reviewed operator, never to an arbitrary supplied key', () => {
    const f = runtimeFixture(), key = generatePrivateKey(), operator = privateKeyToAccount(key).address;
    const sponsor = { operator, maxGas: '1000000', maxFeePerGas: '1000000000', maxPriorityFeePerGas: '0', maxExecutionFee: '1000000000000000' };
    const catalog = { ...f.catalog, staging: [{ ...f.network, backupSponsor: sponsor }] };
    expect(configureWalletNetworks(catalog, f.environment, { ...f.bindings, WALLET_BACKUP_SIGNER_KEY: key })[0].backup?.signer.operator).toBe(operator.toLowerCase());
    expect(() => configureWalletNetworks(catalog, f.environment, { ...f.bindings, WALLET_BACKUP_SIGNER_KEY: generatePrivateKey() })).toThrow('WALLET_RUNTIME_CONFIGURATION_INVALID');
    expect(configureWalletNetworks(catalog, f.environment, f.bindings)[0].backup).toBeUndefined();
  });
});
