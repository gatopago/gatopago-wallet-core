import {
  assessCheckpointFinality,
  assertFinalityAssessment,
  loadPinnedFinalityPolicy,
  type FinalityAssessment,
} from '@gatopago/shared/v3/finality';
import { loadPinnedDeploymentManifest } from '@gatopago/shared/v3/deployment';
import { loadAaveMarket, type AaveMarketPin } from '@gatopago/shared/v3/aave-market';
import type { ResourceId } from '@gatopago/shared/v3/primitives';
import { createInspectionClient } from '../chainInspection';
import { WalletAccessError, type WalletRepository } from '../accounts/repository';
import { withDeadline } from '../deadline';
import { inspectOwnedWalletBalances, type BalanceProfile } from './balances';
import { observeAavePosition } from './aavePositionObservation';

export interface AavePositionProfile extends BalanceProfile {
  readonly market: AaveMarketPin;
}

/** Owner-only observation. Financial readiness and pending spends are separate
 * from this read; finalized position amounts cannot authorize an operation. */
export async function inspectOwnedAavePosition(
  repository: Pick<WalletRepository, 'ownedAccount'>,
  walletId: ResourceId<'wallet'>,
  accountId: ResourceId<'walletAccount'>,
  profilesInput: readonly AavePositionProfile[],
  signal: AbortSignal,
) {
  const profiles = structuredClone(profilesInput);
  return withDeadline(signal, 30_000, async (deadline) => {
    const owned = await repository.ownedAccount(walletId, accountId);
    const matching = profiles.filter(
      (profile) => profile.digest === owned.deployment_manifest_sha256,
    );
    if (matching.length !== 1) throw new Error('POSITION_PROFILE_UNAVAILABLE');
    const profile = matching[0],
      manifest = loadPinnedDeploymentManifest(profile.document, profile.digest);
    const market = loadAaveMarket(profile.market),
      policy = loadPinnedFinalityPolicy(profile.finalityPolicy, manifest);
    if (
      market.network_id !== manifest.network_id ||
      market.genesis_hash !== manifest.genesis_hash ||
      !profile.assetIds.includes(market.asset_id) ||
      !profile.assetIds.includes('eip155:421614/slip44:60')
    )
      throw new Error('POSITION_PROFILE_UNAVAILABLE');
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
        throw new Error('POSITION_FINALITY_UNUSABLE');
      return evidence.checkpoint;
    }
    const source = profile.finalityEvidence,
      checkpoint = { ...fresh(source) };
    const results = await Promise.allSettled([
      inspectOwnedWalletBalances(repository, walletId, accountId, [profile], deadline),
      observeAavePosition(
        { account: owned.address, market: profile.market, checkpoint },
        profile.providers,
        deadline,
      ),
    ]);
    deadline.throwIfAborted();
    fresh(source);
    const [balances, position] = results;
    if (balances.status !== 'fulfilled' || position.status !== 'fulfilled')
      throw new Error('POSITION_UNAVAILABLE');
    const balance = balances.value,
      value = position.value;
    if (
      balance.checkpoint.block_hash !== value.checkpoint.block_hash ||
      balance.balances.find((asset) => asset.asset_id === market.asset_id)?.amount_atomic !==
        value.usdc_balance_atomic ||
      balance.balances.find((asset) => asset.asset_id === 'eip155:421614/slip44:60')
        ?.amount_atomic !== value.native_balance_atomic
    )
      throw new Error('POSITION_BALANCE_CHANGED');
    const closing = await assessCheckpointFinality(
      profile.providers.map((peer) => createInspectionClient(peer.url, deadline)),
      { ...checkpoint, network_id: manifest.network_id, genesis_hash: manifest.genesis_hash },
      profile.finalityPolicy,
      deadline,
    );
    fresh(closing);
    fresh(source);
    const current = await repository.ownedAccount(walletId, accountId);
    deadline.throwIfAborted();
    fresh(closing);
    fresh(source);
    if (JSON.stringify(current) !== JSON.stringify(owned))
      throw new WalletAccessError('WALLET_DATA_INVALID');
    const expires = Math.min(
      value.expires_at,
      balance.expires_at,
      source.expires_at,
      closing.expires_at,
    );
    if (Math.floor(Date.now() / 1000) >= expires) throw new Error('POSITION_FINALITY_UNUSABLE');
    return {
      ...value,
      wallet_id: walletId,
      wallet_account_id: accountId,
      checkpoint,
      finality: 'finalized' as const,
      finality_evidence: closing,
      expires_at: expires,
      available_balance: 'not_assessed' as const,
    };
  });
}
