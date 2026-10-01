import { describe, expect, it } from 'vitest';
import { ARBITRUM_SEPOLIA_CREATION, ARBITRUM_SEPOLIA_DEPLOYMENT } from '@gatopago/shared/v3/wallet-release';
import { loadPinnedCreationProfile } from '@gatopago/shared/v3/initialization';
import { loadPinnedDeploymentManifest } from '@gatopago/shared/v3/deployment';
import { arbitrumSepolia } from '../src/runtime/catalog';
import { configureWalletNetworks } from '../src/runtime/config';
import { runtimeFixture } from './runtime.fixture';

describe('deployed Arbitrum Sepolia profile', () => {
  it('binds creation and later account inspection to the same deployed factory and revision', () => {
    const creation = loadPinnedCreationProfile(ARBITRUM_SEPOLIA_CREATION.document, ARBITRUM_SEPOLIA_CREATION.digest);
    const current = loadPinnedDeploymentManifest(ARBITRUM_SEPOLIA_DEPLOYMENT.document, ARBITRUM_SEPOLIA_DEPLOYMENT.digest);
    expect(creation.deployment).toEqual(current);
    expect(current.network_id).toBe('eip155:421614');
    expect(current.components.factory.address).toBe('0x61c74d8f0834791db732fba9ac022224bf3bbb5f');
    expect(current.components.implementation.address).toBe('0xfe909a09561632a0f9b1a5a00090a658820e4122');
    expect(creation.webauthn_verifier.address).toBe('0x33def7fd931a7df910fe7def70327cb15712c71a');
    expect(current.components.implementation.deployer).toBe('0x4e59b44847b379578588920ca78fbf26c0b4956c');
  });
  it('composes the real release when the environment and provider bindings are provisioned', () => {
    const f = runtimeFixture(ARBITRUM_SEPOLIA_CREATION);
    const catalog = { schema_version: 1, staging: [arbitrumSepolia], production: [] };
    const bindings = { WALLET_BACKUP_SIGNER_KEY: '', PRIVATE_KEY: `0x${'11'.repeat(32)}`, WALLET_RPC_ENDPOINTS: JSON.stringify({
      arbitrum_sepolia_offchain: 'https://observer-a.invalid/', arbitrum_sepolia_tenderly: 'https://observer-b.invalid/',
      arbitrum_sepolia_bundler: 'https://bundler.invalid/',
    }) };
    const [network] = configureWalletNetworks(catalog, f.environment, bindings);
    expect(network.transferProfile.digest).toBe(ARBITRUM_SEPOLIA_DEPLOYMENT.digest);
    expect(network.transferProfile.assetIds).toEqual(Object.keys(arbitrumSepolia.assets));
    expect(network.backup).toBeUndefined();
    expect(() => configureWalletNetworks(catalog, f.environment, { ...bindings, WALLET_RPC_ENDPOINTS: '{}' }))
      .toThrow('WALLET_RUNTIME_CONFIGURATION_INVALID');
    expect(() => configureWalletNetworks(catalog, { ...f.environment, wallet_enabled: [] }, bindings))
      .toThrow('WALLET_RUNTIME_CONFIGURATION_INVALID');
  });
});
