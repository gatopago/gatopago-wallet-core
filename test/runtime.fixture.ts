import manifests from '@gatopago/environment/environments.json';
import { parseEnvironment } from '@gatopago/environment';
import { initializationFixture } from '@gatopago/test-fixtures/v3-initialization';
import { finalityPin, finalityPolicyFixture } from '@gatopago/test-fixtures/v3-finality';
import { loadPinnedCreationProfile } from '@gatopago/shared/v3/initialization';

export function runtimeFixture(pin = initializationFixture().pin) {
  const profile = loadPinnedCreationProfile(pin.document, pin.digest);
  const environment = parseEnvironment({
    ...manifests.production,
    status: 'provisioned',
    firebase_project_id: 'v3-runtime-test',
    wallet_enabled: [profile.deployment.network_id],
  });
  const gas = {
    verificationGasLimit: '2000000',
    callGasLimit: '100000',
    preVerificationGas: '150000',
    maxFeePerGas: '1000000000',
    maxPriorityFeePerGas: '0',
  };
  const network = {
    creationProfile: pin,
    finalityPolicy: finalityPin(
      finalityPolicyFixture(profile.deployment, Math.floor(Date.now() / 1000)),
    ),
    rpc: [
      { operatorId: 'observer-a', endpoint: 'observer_a' },
      { operatorId: 'observer-b', endpoint: 'observer_b' },
    ],
    transport: { kind: 'bundler', endpoint: 'bundler' },
    assets: { [`${profile.deployment.network_id}/slip44:60`]: { symbol: 'ETH', decimals: 18 } },
    creationGas: { ...gas },
    transferGas: { ...gas },
    backupSponsor: null,
    paymaster: null,
  };
  const catalog = { schema_version: 1, production: [network] };
  const bindings = {
    WALLET_RPC_ENDPOINTS: JSON.stringify({
      observer_a: 'https://observer-a.invalid/',
      observer_b: 'https://observer-b.invalid/',
      bundler: 'https://bundler.invalid/',
    }),
    WALLET_BACKUP_SIGNER_KEY: '',
  };
  return { catalog, network, bindings, environment, profile };
}
