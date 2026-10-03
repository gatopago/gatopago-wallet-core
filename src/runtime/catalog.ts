import type { Environment } from '@gatopago/environment';
import { ARBITRUM_SEPOLIA_CREATION } from '@gatopago/shared/v3/wallet-release';
import { deploymentDocumentDigest } from '@gatopago/shared/v3/deployment';
import { loadPinnedCreationProfile } from '@gatopago/shared/v3/initialization';

const { deployment } = loadPinnedCreationProfile(ARBITRUM_SEPOLIA_CREATION.document, ARBITRUM_SEPOLIA_CREATION.digest);
const document = JSON.stringify({ schema_version: 1, policy_id: 'arbitrum-sepolia-finalized-2026-09',
  network_id: deployment.network_id, genesis_hash: deployment.genesis_hash, mechanism: 'arbitrum_l1_data_finalized',
  valid_from: Date.parse('2026-09-26T00:00:00Z') / 1000, valid_until: Date.parse('2026-12-25T00:00:00Z') / 1000, max_latest_age_seconds: 120,
  max_finalized_age_seconds: 7200, max_clock_skew_seconds: 30, evidence_ttl_seconds: 30 });

export const arbitrumSepolia = {
  creationProfile: ARBITRUM_SEPOLIA_CREATION,
  finalityPolicy: { document, digest: deploymentDocumentDigest(document) },
  rpc: [{ operatorId: 'offchain-labs', endpoint: 'arbitrum_sepolia_offchain' },
    { operatorId: 'tenderly', endpoint: 'arbitrum_sepolia_tenderly' }],
  transport: { kind: 'self', endpoint: 'arbitrum_sepolia_offchain', maxGas: '2000000',
    maxFeePerGas: '100000000', maxPriorityFeePerGas: '0' },
  assets: { 'eip155:421614/slip44:60': { symbol: 'ETH', decimals: 18 },
    'eip155:421614/erc20:0x75faf114eafb1bdbe2f0316df893fd58ce46aa4d': { symbol: 'USDC', decimals: 6 } },
  // Caps for signed-operation estimation; exact signed-operation simulation remains a live check.
  // Native P256 creation rejected 496k with AA13 on both RPCs; 750k passed
  // exact handleOps eth_call with synthetic prefunding. This is the self
  // transport ceiling, not public bundler admission or a completed creation.
  // Existing prepared operations retain their separately stored signed terms.
  creationGas: { verificationGasLimit: '750000', callGasLimit: '100000', preVerificationGas: '150000',
    maxFeePerGas: '100000000', maxPriorityFeePerGas: '0' },
  transferGas: { verificationGasLimit: '496000', callGasLimit: '150000', preVerificationGas: '100000',
    maxFeePerGas: '100000000', maxPriorityFeePerGas: '0' },
  backupSponsor: null,
  paymaster: null, // Populate only with verified deployment evidence and a dedicated sponsor key.
};

export default function catalog(environment: Environment) {
  return { schema_version: 1,
    [environment.environment]: environment.wallet_enabled.includes(deployment.network_id) ? [arbitrumSepolia] : [],
  };
}
