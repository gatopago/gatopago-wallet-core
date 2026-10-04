import { expect, it, vi } from 'vitest';
import { ARBITRUM_SEPOLIA_CREATION } from '@gatopago/shared/v3/wallet-release';
import { loadPinnedCreationProfile } from '@gatopago/shared/v3/initialization';
import { arbitrumSepolia } from '../src/runtime/catalog';
import { requireFreshCreationDeployment } from '../src/runtime/finality';
import { validateRpcProviders } from '../src/chainProviders';

it.runIf(process.env.V3_LIVE_RPC === '1')(
  'reads the deployed V3 composition through both production RPC adapters',
  async () => {
    const pin = ARBITRUM_SEPOLIA_CREATION;
    const { deployment } = loadPinnedCreationProfile(pin.document, pin.digest);
    const providers = validateRpcProviders([
      { operatorId: 'offchain-labs', url: 'https://sepolia-rollup.arbitrum.io/rpc' },
      { operatorId: 'tenderly', url: 'https://arbitrum-sepolia.gateway.tenderly.co' },
    ]);
    const signal = AbortSignal.timeout(60_000);
    const original = globalThis.fetch;
    const http = vi.spyOn(globalThis, 'fetch').mockImplementation((...args) => original(...args));
    try {
      await requireFreshCreationDeployment(
        {
          document: pin.document,
          digest: pin.digest,
          deployment,
          providers,
          finalityPolicy: arbitrumSepolia.finalityPolicy,
        },
        signal,
      );
      expect(http).toHaveBeenCalledTimes(32);
    } finally {
      http.mockRestore();
    }
  },
  65_000,
);
