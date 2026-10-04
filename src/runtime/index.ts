import { loadPinnedCreationProfile } from '@gatopago/shared/v3/initialization';
import { maximumOperationGasCost } from '@gatopago/shared/v3/paymaster';
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
import application from '../../config/application.json';
import aaveMarket from '../../config/markets/aave-v3-arbitrum-sepolia-usdc.json';
import { configureMoney } from './moneyConfig';
import { createMoneyReadRoute } from '../money/moneyReadRoute';
import { createMoneyRoute } from '../money/moneyRoute';
import { createMoneyJobHandlers } from '../money/moneyJobHandlers';
import type { MoneyDeliveryProfile } from '../money/moneyPreflight';
import moneyGas from '../../config/money-gas.json';

type Owned = Awaited<ReturnType<WalletRepository['ownedAccount']>>;

export function createWalletRuntime(
  env: WalletCoreV3Bindings,
  environment: Environment,
  catalog: unknown,
) {
  const networks = configureWalletNetworks(catalog, environment, env);
  const sponsor = (
    network: (typeof networks)[number],
    database: D1Database,
    identity: Principal,
    signal: AbortSignal,
  ) => {
    if (!network.paymaster) return undefined;
    const key = env.WALLET_PAYMASTER_SIGNER_KEY;
    if (!key || !/^0x[0-9a-fA-F]{64}$/.test(key)) throw new Error('SPONSOR_CONFIGURATION_INVALID');
    return createGasSponsor(
      database,
      identity,
      network.paymaster,
      key as Hex,
      evmChainId(network.deployment.network_id),
      network.deployment.entry_point,
      network.providers.map((p) => p.url),
      signal,
    );
  };
  const byPin = (pin: CreationProfilePin) => {
    const network = networks.find((n) => n.digest === pin.digest && n.document === pin.document);
    if (!network) throw new Error('RUNTIME_PROFILE_UNAVAILABLE');
    return network;
  };
  const forAccount = (owned: Owned) => {
    const network = networks.find(
      (n) =>
        n.transferProfile.digest === owned.deployment_manifest_sha256 &&
        n.deployment.network_id === owned.network_id,
    );
    if (!network) throw new Error('RUNTIME_PROFILE_UNAVAILABLE');
    return network;
  };
  const receivingProfiles = async (owned: Owned, signal: AbortSignal) => {
    const network = forAccount(owned);
    return [
      {
        document: network.transferProfile.document,
        digest: network.transferProfile.digest,
        rpcUrls: [network.providers[0].url, network.providers[1].url] as const,
        finalityPolicy: network.finalityPolicy,
        finalityEvidence: await networkFinality(network, signal),
        verifier: loadPinnedCreationProfile(network.document, network.digest).webauthn_verifier,
      },
    ];
  };
  const accountProfiles = networks.map((n) => ({
    generation: String(n.deployment.generation),
    contract_manifest_version: n.deployment.manifest_id,
  }));
  const requireFreshDeployment = (pin: CreationProfilePin, signal: AbortSignal) =>
    requireFreshCreationDeployment(byPin(pin), signal);
  const scope = { rpId: environment.webauthn_rp_id, origin: environment.web_origin };
  const identity = { environment: environment.environment, scope };
  const finality = (pin: CreationProfilePin, signal: AbortSignal) =>
    networkFinality(byPin(pin), signal);
  const creation = createCreationJobHandlers(() => ({
    ...identity,
    networks,
    relayerKey: env.PRIVATE_KEY as `0x${string}` | undefined,
    checkpoint: async (pin, signal) => (await finality(pin, signal)).checkpoint!,
  }));
  const backup = createBackupJobHandlers(() => ({
    ...identity,
    finality,
    networks: networks.map((n) => ({ ...n, delivery: n.backup })),
  }));
  const transfer = createTransferJobHandlers(() => ({
    environment: environment.environment,
    profiles: networks.map((n) => n.transferProfile),
  }));
  let moneyConfiguration: ReturnType<typeof configureMoney> | null = null;
  try {
    moneyConfiguration = configureMoney(application, aaveMarket, networks, moneyGas);
  } catch {
    // Optional money module configuration
  }
  const moneyProfiles: readonly (MoneyDeliveryProfile & {
    environment: Environment['environment'];
  })[] = moneyConfiguration
    ? [
        {
          ...moneyConfiguration.network.transferProfile,
          market: moneyConfiguration.market,
          features: moneyConfiguration.application.features,
          gasByKind: moneyConfiguration.gasByKind,
        },
      ]
    : [];
  const money = createMoneyJobHandlers(() => ({
    environment: environment.environment,
    profiles: moneyProfiles,
  }));
  return {
    accountProfiles,
    accountContextProfiles: networks.map((n) => ({
      document: n.transferProfile.document,
      digest: n.transferProfile.digest,
      assetIds: n.transferProfile.assetIds,
      assetDisplay: n.transferProfile.assetDisplay,
    })),
    configured: networks.length > 0,
    networks: networks.map((n) => ({
      network_id: n.deployment.network_id,
      transport: n.transport.kind,
      relayer_address: n.transport.kind === 'self' ? n.transport.policy.operator : null,
    })),
    capabilities: {
      creation: networks.length > 0,
      transfers: networks.length > 0,
      backup: networks.length > 0 && networks.every((n) => !!n.backup),
    },
    jobs: { creation, backup, transfer, money },
    async recoverRelay(database: D1Database) {
      const results = await Promise.allSettled(
        networks.map(async (network) => {
          if (network.transport.kind === 'self') {
            await recoverSelfSubmissions(database, network.transport, AbortSignal.timeout(30_000));
          }
        }),
      );
      if (results.some((result) => result.status === 'rejected'))
        throw new Error('RELAYER_RECOVERY_UNAVAILABLE');
    },
    initialization: createInitializationRoute({
      accessProfiles: receivingProfiles,
      profiles: networks,
      requireFreshDeployment,
    }),
    creationOperation: createCreationOperationRoute({
      accessProfiles: receivingProfiles,
      profiles: networks,
      requireFreshDeployment,
      sponsor: (pin, database, identity, signal) => sponsor(byPin(pin), database, identity, signal),
      async automaticGasCap(pin, _initial, signal) {
        signal.throwIfAborted();
        const network = byPin(pin),
          paymaster = network.paymaster;

        return maximumOperationGasCost({
          ...network.creationGas,
          ...(paymaster
            ? {
                paymasterVerificationGasLimit: BigInt(paymaster.verificationGasLimit),
                paymasterPostOpGasLimit: BigInt(paymaster.postOpGasLimit),
              }
            : {}),
        });
      },
      async quoteGas(pin, _initial, cap, signal) {
        signal.throwIfAborted();
        const terms = byPin(pin).creationGas;
        if (maximumGasCharge(terms) > cap) throw new Error('CREATION_GAS_CAP_EXCEEDED');

        return { ...terms, maximumGasCharge: cap };
      },
    }),
    backup: createBackupRoute({
      accessProfiles: receivingProfiles,
      profiles: networks,
      async resolveProfiles(owned, signal) {
        const network = forAccount(owned);
        if (!network.backup) throw new BackupError('BACKUP_PROFILE_UNAVAILABLE');
        return [
          {
            ...network.transferProfile,
            rpcUrls: [network.providers[0].url, network.providers[1].url] as const,
            finalityEvidence: await networkFinality(network, signal),
          },
        ];
      },
    }),
    transfer: createTransferRoute({
      relayerKey: env.PRIVATE_KEY as `0x${string}` | undefined,
      accessProfiles: receivingProfiles,
      profiles: networks.map((n) => n.transferProfile),
      sponsor: (profile, database, identity, signal) => {
        const network = networks.find((n) => n.transferProfile.digest === profile.digest);
        if (!network) throw new Error('RUNTIME_PROFILE_UNAVAILABLE');
        return sponsor(network, database, identity, signal);
      },
      async resolvePreparation(owned, request, profile, signal) {
        const network = forAccount(owned),
          evidence = await networkFinality(network, signal);
        if (network.transferProfile.digest !== profile.digest)
          throw new Error('RUNTIME_PROFILE_UNAVAILABLE');
        const now = Math.floor(Date.now() / 1000);
        return {
          finalityEvidence: evidence,
          terms: {
            request,
            wallet_account_id: owned.id,
            deployment_digest: profile.digest,
            native_asset_id: network.nativeAssetId,
            gas: network.transferGas,
            maximum_native_gas_atomic: maximumGasCharge(network.transferGas).toString(),
            platform_fee: { asset_id: request.asset_id, amount_atomic: '0' },
            fee_recipient: null,
            observed_at: now,
            expires_at: Math.min(now + 60, evidence.expires_at),
          },
        };
      },
    }),
    receivingProfiles,
    money: createMoneyRoute({
      profiles: moneyProfiles,
      accessProfiles: receivingProfiles,
      relayerKey: env.PRIVATE_KEY as `0x${string}` | undefined,
      async resolvePreparation(owned, profile, signal) {
        const network = forAccount(owned);
        if (
          profile.digest !== network.transferProfile.digest ||
          !moneyConfiguration ||
          moneyConfiguration.network !== network
        )
          throw new Error('MONEY_PROFILE_UNAVAILABLE');
        return networkFinality(network, signal);
      },
    }),
    moneyRead: createMoneyReadRoute({
      configuration: moneyConfiguration,
      accessProfiles: receivingProfiles,
      async resolveProfiles(owned, signal) {
        const network = forAccount(owned);
        if (!moneyConfiguration || moneyConfiguration.network !== network)
          throw new Error('POSITION_PROFILE_UNAVAILABLE');
        return [
          {
            ...network.transferProfile,
            market: moneyConfiguration.market,
            finalityEvidence: await networkFinality(network, signal),
          },
        ];
      },
    }),
    async balanceProfiles(owned: Owned, signal: AbortSignal) {
      const network = forAccount(owned);
      return [
        { ...network.transferProfile, finalityEvidence: await networkFinality(network, signal) },
      ];
    },
  };
}
