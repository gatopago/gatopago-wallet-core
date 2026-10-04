import { validateRpcProviders, type RpcProvider } from '../chainProviders';
import { isAddressEqual, type Hex } from 'viem';
import { predictAccountAddress } from '@gatopago/shared/v3/authorizations';
import { loadPinnedDeploymentManifest } from '@gatopago/shared/v3/deployment';
import {
  assessCheckpointFinality,
  assertFinalityAssessment,
  loadPinnedFinalityPolicy,
  type FinalityAssessment,
} from '@gatopago/shared/v3/finality';
import type { ResourceId } from '@gatopago/shared/v3/primitives';
import { createInspectionClient } from '../chainInspection';
import { withDeadline } from '../deadline';
import { observeAccountBalances } from './balanceObservation';

import type { InspectionProfile } from '../accounts/inspection';
import { WalletAccessError } from '../accounts/repository';

export interface BalanceProfile extends Omit<InspectionProfile, 'rpcUrls'> {
  readonly providers: readonly RpcProvider[];
  readonly assetIds: readonly string[];
  readonly assetDisplay: Readonly<
    Record<string, { readonly symbol: string; readonly decimals: number }>
  >;
}

export function balanceAssetMetadata(profile: Pick<BalanceProfile, 'assetIds' | 'assetDisplay'>) {
  if (
    !Array.isArray(profile.assetIds) ||
    !profile.assetIds.length ||
    profile.assetIds.length > 32 ||
    new Set(profile.assetIds).size !== profile.assetIds.length ||
    !profile.assetDisplay ||
    Object.keys(profile.assetDisplay).length !== profile.assetIds.length
  )
    throw new Error('BALANCE_METADATA_UNAVAILABLE');
  return profile.assetIds.map((asset_id) => {
    const display = profile.assetDisplay[asset_id];
    if (
      !Object.hasOwn(profile.assetDisplay, asset_id) ||
      !display ||
      typeof display.symbol !== 'string' ||
      !/^[A-Za-z0-9][A-Za-z0-9._-]{0,15}$(?![\s\S])/.test(display.symbol) ||
      !Number.isInteger(display.decimals) ||
      display.decimals < 0 ||
      display.decimals > 255
    )
      throw new Error('BALANCE_METADATA_UNAVAILABLE');
    return Object.freeze({ asset_id, symbol: display.symbol, decimals: display.decimals });
  });
}

export async function inspectOwnedWalletBalances(
  repository: {
    ownedAccount(
      walletId: ResourceId<'wallet'>,
      accountId: ResourceId<'walletAccount'>,
    ): Promise<{
      network_id: string;
      address: Hex;
      account_id: Hex;
      deployment_manifest_sha256: Hex;
    }>;
  },
  walletId: ResourceId<'wallet'>,
  accountId: ResourceId<'walletAccount'>,
  profilesInput: readonly BalanceProfile[],
  signal: AbortSignal,
) {
  const profiles = structuredClone(profilesInput);
  return withDeadline(signal, 30_000, async (deadline) => {
    const owned = await repository.ownedAccount(walletId, accountId);
    deadline.throwIfAborted();
    const matching = profiles.filter((p) => p.digest === owned.deployment_manifest_sha256);
    if (matching.length !== 1) throw new Error('BALANCE_PROFILE_UNAVAILABLE');
    const profile = matching[0],
      manifest = loadPinnedDeploymentManifest(profile.document, profile.digest);
    balanceAssetMetadata(profile);
    const peers = validateRpcProviders(profile.providers);
    if (
      manifest.network_id !== owned.network_id ||
      manifest.lifecycle_status !== 'deployed' ||
      !isAddressEqual(
        predictAccountAddress(
          manifest.components.factory.address,
          owned.account_id,
          manifest.proxy.init_code_hash,
        ),
        owned.address,
      )
    ) {
      throw new WalletAccessError('WALLET_DATA_INVALID');
    }
    const policy = loadPinnedFinalityPolicy(profile.finalityPolicy, manifest),
      source = profile.finalityEvidence;
    function fresh(evidence: FinalityAssessment) {
      assertFinalityAssessment(evidence, {
        ...evidence.target,
        network_id: manifest.network_id,
        genesis_hash: manifest.genesis_hash,
      });
      const now = Math.floor(Date.now() / 1000);
      if (
        evidence.status !== 'finalized' ||
        !evidence.checkpoint ||
        evidence.policy_sha256 !== profile.finalityPolicy.digest ||
        evidence.mechanism !== policy.mechanism ||
        now < policy.valid_from ||
        now >= policy.valid_until ||
        evidence.assessed_at < policy.valid_from ||
        evidence.assessed_at > now ||
        now >= evidence.expires_at ||
        evidence.expires_at >
          Math.min(evidence.assessed_at + policy.evidence_ttl_seconds, policy.valid_until) ||
        BigInt(evidence.checkpoint.block_timestamp) > BigInt(now + policy.max_clock_skew_seconds) ||
        BigInt(now) - BigInt(evidence.checkpoint.block_timestamp) >
          BigInt(policy.max_finalized_age_seconds)
      )
        throw new Error('BALANCE_FINALITY_UNUSABLE');
      return evidence.checkpoint;
    }
    const checkpoint = { ...fresh(source) };
    const balances = await observeAccountBalances(
      {
        network_id: manifest.network_id,
        genesis_hash: manifest.genesis_hash,
        address: owned.address,
        checkpoint,
        asset_ids: profile.assetIds,
      },
      peers,
      deadline,
    );
    fresh(source);
    deadline.throwIfAborted();
    const closing = await assessCheckpointFinality(
      peers.map((p) => createInspectionClient(p.url, deadline)),
      { ...checkpoint, network_id: manifest.network_id, genesis_hash: manifest.genesis_hash },
      profile.finalityPolicy,
      deadline,
    );
    fresh(closing);
    fresh(source);
    deadline.throwIfAborted();

    const current = await repository.ownedAccount(walletId, accountId);
    deadline.throwIfAborted();
    fresh(closing);
    fresh(source);
    if (JSON.stringify(current) !== JSON.stringify(owned))
      throw new WalletAccessError('WALLET_DATA_INVALID');
    return {
      ...balances,
      checkpoint,
      wallet_id: walletId,
      wallet_account_id: accountId,
      balances: balances.balances.map((asset) => ({
        ...asset,
        symbol: profile.assetDisplay[asset.asset_id].symbol,
        decimals: profile.assetDisplay[asset.asset_id].decimals,
      })),
      finality: 'finalized' as const,
      finality_evidence: closing,
      expires_at: Math.min(source.expires_at, closing.expires_at),
      available_balance: 'not_assessed' as const,
    };
  });
}
