import { isAddressEqual, type Hex } from 'viem';
import { loadPinnedDeploymentManifest, requireHash } from '@gatopago/shared/v3/deployment';
import { loadAaveMarket } from '@gatopago/shared/v3/aave-market';
import { parseMoneyRequest, type MoneyKind } from '@gatopago/shared/v3/money-wire';
import { prepareMoneyOperation, type MoneyOperationContext } from '@gatopago/shared/v3/money-operation';
import { readMoneyDraft, writeMoneyDraft } from '@gatopago/shared/v3/money-review-record';
import { hashSecurityPolicy } from '@gatopago/shared/v3/security-policy';
import { maximumOperationGasCost } from '@gatopago/shared/v3/paymaster';
import { parseAtomicAmount, type ResourceId } from '@gatopago/shared/v3/primitives';
import { assertWebAuthnScope, type WebAuthnScope } from '@gatopago/shared/v3/webauthn';
import { WalletRepository } from '../accounts/repository';
import { inspectOwnedWalletAccount } from '../accounts/inspection';
import { inspectOwnedAavePosition, type AavePositionProfile } from '../portfolio/aavePosition';
import { observeTransferNonce } from '../transfers/transferNonce';
import type { Principal } from '../auth/principal';
import { validateRpcProviders } from '../chainProviders';
import { withDeadline } from '../deadline';

export interface MoneyPreparationProfile extends AavePositionProfile {
  readonly entryPointCodeHash: Hex;
  readonly features: Readonly<Record<MoneyKind, boolean>>;
  readonly gasByKind: Readonly<Record<MoneyKind, MoneyOperationContext['gas'] | null>>;
}
async function assertMoneyAccountUnoccupied(database: D1Database, accountId: ResourceId<'walletAccount'>) {
  const lock = await database.withSession('first-primary').prepare('SELECT operation_id FROM wallet_spend_locks WHERE wallet_account_id = ? AND released_at IS NULL LIMIT 1')
    .bind(accountId).first();
  if (lock) throw new Error('ACCOUNT_SPEND_BUSY');
}
export async function assertMoneyBalanceFloor(database: D1Database, accountId: ResourceId<'walletAccount'>, checkpoint: { block_number: string; block_hash: Hex }) {
  const floor = await database.withSession('first-primary').prepare('SELECT block_number,block_hash FROM wallet_balance_floors WHERE wallet_account_id = ?')
    .bind(accountId).first();
  if (floor) {
    requireHash(floor.block_hash);
    const minimum = BigInt(parseAtomicAmount(floor.block_number)), actual = BigInt(parseAtomicAmount(checkpoint.block_number));
    if (actual < minimum || (actual === minimum && checkpoint.block_hash !== floor.block_hash)) throw new Error('MONEY_BALANCE_CHECKPOINT_STALE');
  }
}

/** Caller supplies identity/admission, never an HTTP financial context. Prepare
 * observes but cannot sign, reserve, increase gas or dispatch. Active service
 * spends block new preparation; exact D1 exclusion is repeated at confirmation. */
export async function prepareOwnedMoney(database: D1Database, identityInput: Principal,
  walletId: ResourceId<'wallet'>, accountId: ResourceId<'walletAccount'>, requestInput: unknown,
  scopeInput: WebAuthnScope, profilesInput: readonly MoneyPreparationProfile[], signal: AbortSignal) {
  const identity = Object.freeze({ ...identityInput }), scope = { ...scopeInput }, profiles = structuredClone(profilesInput);
  const request = parseMoneyRequest(requestInput);
  assertWebAuthnScope(scope);
  if (request.wallet_id !== walletId || request.wallet_account_id !== accountId) throw new Error('MONEY_ACCOUNT_MISMATCH');
  return withDeadline(signal, 30_000, async deadline => {
    const owner = { ownedAccount: (wallet: ResourceId<'wallet'>, account: ResourceId<'walletAccount'>) => new WalletRepository(database, identity).ownedAccount(wallet, account) };
    const owned = await owner.ownedAccount(walletId, accountId);
    deadline.throwIfAborted();
    const matching = profiles.filter(profile => profile.digest === owned.deployment_manifest_sha256);
    if (matching.length !== 1) throw new Error('MONEY_PROFILE_UNAVAILABLE');
    const profile = matching[0], manifest = loadPinnedDeploymentManifest(profile.document, profile.digest), market = loadAaveMarket(profile.market);
    const gas = profile.gasByKind[request.kind], source = profile.finalityEvidence;
    requireHash(profile.entryPointCodeHash);
    if (!profile.features[request.kind] || gas === null) throw new Error('MONEY_CAPABILITY_UNAVAILABLE');
    if (owned.network_id !== request.network_id || manifest.network_id !== request.network_id || manifest.lifecycle_status !== 'deployed'
      || market.market_id !== request.market_id || market.asset_id !== request.asset_id || market.genesis_hash !== manifest.genesis_hash
      || source.status !== 'finalized' || !source.checkpoint) throw new Error('MONEY_PROFILE_UNAVAILABLE');
    const peers = validateRpcProviders(profile.providers), checkpoint = { ...source.checkpoint };
    await assertMoneyAccountUnoccupied(database, accountId);
    await assertMoneyBalanceFloor(database, accountId, checkpoint);
    const observations = await Promise.allSettled([
      inspectOwnedWalletAccount(owner, walletId, accountId, [{ ...profile, rpcUrls: [peers[0].url, peers[1].url] }], deadline),
      inspectOwnedAavePosition(owner, walletId, accountId, [profile], deadline),
      observeTransferNonce({ network_id: manifest.network_id, genesis_hash: manifest.genesis_hash, account: owned.address,
        entry_point: manifest.entry_point, entry_point_code_hash: profile.entryPointCodeHash, checkpoint }, peers, deadline),
    ]);
    deadline.throwIfAborted();
    const [security, position, nonce] = observations;
    if (security.status !== 'fulfilled' || position.status !== 'fulfilled' || nonce.status !== 'fulfilled') throw new Error('MONEY_OBSERVATION_UNAVAILABLE');
    const authority = security.value, financial = position.value, sequence = nonce.value;
    if (authority.status !== 'recognized' || !('security' in authority) || authority.security.phase !== 'active_policy') throw new Error('MONEY_ACCOUNT_NOT_ACTIVE');
    if (!financial.active || financial.paused || (request.kind === 'aave_supply' && financial.frozen)) throw new Error('MONEY_MARKET_UNAVAILABLE');
    if (financial.debt_base_atomic !== '0') throw new Error('MONEY_DEBT_NOT_SUPPORTED');
    for (const observed of [authority, financial, sequence]) {
      if (observed.checkpoint.block_number !== checkpoint.block_number || observed.checkpoint.block_hash !== checkpoint.block_hash) throw new Error('MONEY_CHECKPOINT_MISMATCH');
    }
    const now = Math.floor(Date.now() / 1000), expires = Math.min(source.expires_at, authority.security_expires_at, financial.expires_at, identity.expiresAt);
    if (now >= expires || sequence.observed_at > now || sequence.observed_at < now - 30 || sequence.network_id !== request.network_id
      || !isAddressEqual(sequence.account, owned.address) || !isAddressEqual(sequence.entry_point, manifest.entry_point)) throw new Error('MONEY_OBSERVATION_EXPIRED');
    const context: MoneyOperationContext = { account: owned.address, wallet_account_id: accountId, account_id: owned.account_id,
      deployment_digest: profile.digest, policy_hash: hashSecurityPolicy(authority.security.policy), security_version: BigInt(authority.security_version),
      entry_point: manifest.entry_point, nonce: BigInt(sequence.nonce), market: profile.market, native_asset_id: 'eip155:421614/slip44:60', gas,
      budget: { usdc_available_atomic: financial.usdc_balance_atomic, position_available_atomic: financial.position_balance_atomic,
        native_available_atomic: financial.native_balance_atomic, maximum_native_gas_atomic: maximumOperationGasCost(gas).toString(),
        debt_base_atomic: financial.debt_base_atomic, liquidity_atomic: financial.liquidity_atomic, supply_capacity_atomic: financial.supply_capacity_atomic },
      checkpoint: { block_number: checkpoint.block_number, block_hash: checkpoint.block_hash, observed_at: now, expires_at: expires }, valid_until: expires };
    const review = { request, context, policy: authority.security.policy, scope, prepared_at: now };
    const candidate = prepareMoneyOperation(request, context, now), encoded = writeMoneyDraft(review);
    const record = readMoneyDraft(encoded.json, encoded.digest);
    if (record.candidate.digest !== candidate.digest) throw new Error('MONEY_REVIEW_MISMATCH');
    await assertMoneyAccountUnoccupied(database, accountId); await assertMoneyBalanceFloor(database, accountId, checkpoint);
    const current = await owner.ownedAccount(walletId, accountId);
    deadline.throwIfAborted();
    if (JSON.stringify(current) !== JSON.stringify(owned) || Math.floor(Date.now() / 1000) >= expires) throw new Error('MONEY_PREPARATION_CHANGED');
    return Object.freeze({ candidate, review, evidence: { security: authority, position: financial, nonce: sequence }, send_enabled: false as const });
  });
}
