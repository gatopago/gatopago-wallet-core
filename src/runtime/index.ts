import { loadPinnedCreationProfile } from '@gatopago/shared/v3/initialization';
import { createGasSponsor } from '../sponsorship/service';
import type { Principal } from '../auth/principal';
import { evmChainId } from '@gatopago/shared/v3/primitives';
import type { Hex } from 'viem';
import type { Environment } from '@gatopago/environment';
import { createInitializationRoute } from '../creation/initializationRoute';
import { createCreationOperationRoute } from '../creation/creationOperationRoute';
import { createBackupRoute } from '../security/backupRoute';
import { BackupError } from '../security/backup';
import { createTransferRoute } from '../transfers/transferRoute';
import { createCreationJobHandlers } from '../creation/creationJobHandlers';
import { createBackupJobHandlers } from '../security/backupJobHandlers';
import { createTransferJobHandlers } from '../transfers/transferJobHandlers';
import type { WalletRepository } from '../accounts/repository';
import type { CreationProfilePin } from '../creation/initialization';
import { configureWalletNetworks, maximumGasCharge } from './config';
import { networkFinality, requireFreshCreationDeployment } from './finality';
import { recoverSelfSubmissions } from '../execution/operationTransport';

type Owned = Awaited<ReturnType<WalletRepository['ownedAccount']>>;

/** Composed once per invocation: no global clients, secrets, I/O or mutable evidence. */
export function createWalletRuntime(env: WalletCoreV3Bindings, environment: Environment, catalog: unknown) {
  const networks = configureWalletNetworks(catalog, environment, env);
  const sponsor = (network: typeof networks[number], database: D1Database, identity: Principal, signal: AbortSignal) => {
    if (!network.paymaster) return undefined;
    const key = env.WALLET_PAYMASTER_SIGNER_KEY;
    if (!key || !/^0x[0-9a-fA-F]{64}$/.test(key)) throw new Error('SPONSOR_CONFIGURATION_INVALID');
    return createGasSponsor(database, identity, network.paymaster, key as Hex, evmChainId(network.deployment.network_id),
      network.deployment.entry_point, network.providers.map(p => p.url), signal);
  };
  const byPin = (pin: CreationProfilePin) => {
    const network = networks.find(n => n.digest === pin.digest && n.document === pin.document);
    if (!network) throw new Error('RUNTIME_PROFILE_UNAVAILABLE');
    return network;
  };
  const forAccount = (owned: Owned) => {
    const network = networks.find(n => n.transferProfile.digest === owned.deployment_manifest_sha256 && n.deployment.network_id === owned.network_id);
    if (!network) throw new Error('RUNTIME_PROFILE_UNAVAILABLE');
    return network;
  };
  const receivingProfiles = async (owned: Owned, signal: AbortSignal) => {
      const network = forAccount(owned);
      return [{ document: network.transferProfile.document, digest: network.transferProfile.digest,
        rpcUrls: [network.providers[0].url, network.providers[1].url] as const,
        finalityPolicy: network.finalityPolicy, finalityEvidence: await networkFinality(network, signal),
        verifier: loadPinnedCreationProfile(network.document, network.digest).webauthn_verifier }];
    };
  const accountProfiles = networks.map(n => ({
    generation: String(n.deployment.generation), contract_manifest_version: n.deployment.manifest_id,
  }));
  const requireFreshDeployment = (pin: CreationProfilePin, signal: AbortSignal) => requireFreshCreationDeployment(byPin(pin), signal);
  const scope = { rpId: environment.webauthn_rp_id, origin: environment.web_origin };
  const identity = { environment: environment.environment, scope };
  const finality = (pin: CreationProfilePin, signal: AbortSignal) => networkFinality(byPin(pin), signal);
  const creation = createCreationJobHandlers(() => ({ ...identity, networks, relayerKey: env.PRIVATE_KEY as `0x${string}` | undefined,
    checkpoint: async (pin, signal) => (await finality(pin, signal)).checkpoint! }));
  const backup = createBackupJobHandlers(() => ({ ...identity, finality,
    networks: networks.map(n => ({ ...n, delivery: n.backup })) }));
  const transfer = createTransferJobHandlers(() => ({ environment: environment.environment,
    profiles: networks.map(n => n.transferProfile) }));
  return {
    accountProfiles,
    configured: networks.length > 0,
    networks: networks.map(n => ({ network_id: n.deployment.network_id, transport: n.transport.kind,
      relayer_address: n.transport.kind === 'self' ? n.transport.policy.operator : null })),
    capabilities: { creation: networks.length > 0, transfers: networks.length > 0,
      backup: networks.length > 0 && networks.every(n => !!n.backup) },
    jobs: { creation, backup, transfer },
    async recoverRelay(database: D1Database) {
      const results = await Promise.allSettled(networks.map(async network => {
        if (network.transport.kind === 'self') {
          await recoverSelfSubmissions(database, network.transport, AbortSignal.timeout(30_000));
        }
      }));
      if (results.some(result => result.status === 'rejected')) throw new Error('RELAYER_RECOVERY_UNAVAILABLE');
    },
    initialization: createInitializationRoute({ accessProfiles: receivingProfiles, profiles: networks, requireFreshDeployment }),
    creationOperation: createCreationOperationRoute({ accessProfiles: receivingProfiles, profiles: networks, requireFreshDeployment,
      sponsor: (pin, database, identity, signal) => sponsor(byPin(pin), database, identity, signal),
      async quoteGas(pin, _initial, cap, signal) {
        signal.throwIfAborted();
        const terms = byPin(pin).creationGas;
        if (maximumGasCharge(terms) > cap) throw new Error('CREATION_GAS_CAP_EXCEEDED');
        // These are reviewed upper bounds, not an unsigned simulation. The selected transport
        // must simulate the exact signed operation within them before delivery.
        return { ...terms, maximumGasCharge: cap };
      } }),
    backup: createBackupRoute({ accessProfiles: receivingProfiles, profiles: networks, async resolveProfiles(owned, signal) {
      const network = forAccount(owned);
      if (!network.backup) throw new BackupError('BACKUP_PROFILE_UNAVAILABLE');
      return [{ ...network.transferProfile, rpcUrls: [network.providers[0].url, network.providers[1].url] as const,
        finalityEvidence: await networkFinality(network, signal) }];
    } }),
    transfer: createTransferRoute({ relayerKey: env.PRIVATE_KEY as `0x${string}` | undefined, accessProfiles: receivingProfiles, profiles: networks.map(n => n.transferProfile),
      sponsor: (profile, database, identity, signal) => {
        const network = networks.find(n => n.transferProfile.digest === profile.digest);
        if (!network) throw new Error('RUNTIME_PROFILE_UNAVAILABLE');
        return sponsor(network, database, identity, signal);
      },
      async resolvePreparation(owned, request, profile, signal) {
        const network = forAccount(owned), evidence = await networkFinality(network, signal);
        if (network.transferProfile.digest !== profile.digest) throw new Error('RUNTIME_PROFILE_UNAVAILABLE');
        const now = Math.floor(Date.now() / 1000);
        return { finalityEvidence: evidence, terms: { request, wallet_account_id: owned.id,
          deployment_digest: profile.digest, native_asset_id: network.nativeAssetId, gas: network.transferGas,
          maximum_native_gas_atomic: maximumGasCharge(network.transferGas).toString(),
          platform_fee: { asset_id: request.asset_id, amount_atomic: '0' }, fee_recipient: null,
          observed_at: now, expires_at: Math.min(now + 60, evidence.expires_at) } };
      } }),
    receivingProfiles,
    async balanceProfiles(owned: Owned, signal: AbortSignal) {
      const network = forAccount(owned);
      return [{ ...network.transferProfile, finalityEvidence: await networkFinality(network, signal) }];
    },
  };
}
