import { expect, it } from 'vitest';
import { ARBITRUM_SEPOLIA_CREATION } from '@gatopago/shared/v3/wallet-release';
import { loadPinnedCreationProfile } from '@gatopago/shared/v3/initialization';
import { arbitrumSepolia } from '../src/runtime/catalog';
import { networkFinality } from '../src/runtime/finality';
import { inspectWalletCreationProfile } from '../src/chainInspection';
import { validateRpcProviders } from '../src/chainProviders';

// Explicit read-only testnet inspection. Normal unit/CI runs never depend on public RPCs.
it.runIf(process.env.V3_LIVE_RPC === '1')('reads the deployed V3 composition through both production RPC adapters', async () => {
  const pin = ARBITRUM_SEPOLIA_CREATION;
  const { deployment } = loadPinnedCreationProfile(pin.document, pin.digest);
  const providers = validateRpcProviders([
    { operatorId: 'offchain-labs', url: 'https://sepolia-rollup.arbitrum.io/rpc' },
    { operatorId: 'tenderly', url: 'https://arbitrum-sepolia.gateway.tenderly.co' },
  ]);
  const signal = AbortSignal.timeout(60_000);
  const evidence = await networkFinality({ deployment, providers, finalityPolicy: arbitrumSepolia.finalityPolicy }, signal);
  expect(evidence.status).toBe('finalized');
  const results = await Promise.allSettled(providers.map(p => inspectWalletCreationProfile({ document: pin.document,
    expectedDigest: pin.digest, checkpoint: evidence.checkpoint! }, p.url, signal)));
  for (const result of results) {
    if (result.status === 'rejected') throw result.reason;
    expect(result.value.status).toBe('composition_matches');
  }
}, 65_000);
