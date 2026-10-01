import type { GasSponsor } from '../sponsorship/service';
import { validateRpcProviders } from '../chainProviders';
import { isAddressEqual, type Hex } from 'viem';
import { loadPinnedDeploymentManifest, requireHash } from '@gatopago/shared/v3/deployment';
import { parseAtomicAmount, type ResourceId } from '@gatopago/shared/v3/primitives';
import { hashSecurityPolicy } from '@gatopago/shared/v3/security-policy';
import { parseTransferRequest, type TransferRequest } from '@gatopago/shared/v3/transfer';
import type { authorizeTransferOperation } from '@gatopago/shared/v3/transfer-authorization';
import { assertTransferBalance } from '@gatopago/shared/v3/transfer-balance';
import { prepareTransferOperation } from '@gatopago/shared/v3/transfer-operation';
import { assertTransferSecurity } from '@gatopago/shared/v3/transfer-security';
import { assertWebAuthnScope, type WebAuthnScope } from '@gatopago/shared/v3/webauthn';
import type { Principal } from '../auth/principal';
import { withDeadline } from '../deadline';

import { inspectOwnedWalletBalances, type BalanceProfile } from '../portfolio/balances';
import { inspectOwnedWalletAccount } from '../accounts/inspection';
import { WalletRepository } from '../accounts/repository';
import { observeTransferNonce } from './transferNonce';
import { TransferNonceReservationRepository } from './transferNonceReservation';

type Context = Parameters<typeof prepareTransferOperation>[1];
type Approval = Parameters<typeof authorizeTransferOperation>[2];

/** Internal admitted fee/gas limits, NOT an HTTP quote or estimation result.
 * The supplying fee/estimation policy must bind them to this precise request.
 * Signed preflight must subsequently prove the operation fits these limits.
 * Only the private sponsor service can replace the account gas budget with bound paymaster terms. */
export interface TransferPreparationTerms {
  request: TransferRequest;
  wallet_account_id: ResourceId<'walletAccount'>;
  deployment_digest: Hex;
  native_asset_id: string;
  gas: Context['gas'];
  maximum_native_gas_atomic: string;
  platform_fee: Context['budget']['platform_fee'];
  fee_recipient: Context['fee_recipient'];
  observed_at: number;
  expires_at: number;
}

/** Private preparation: only request/account ID are user inputs. Identity is
 * verified upstream; scope, profiles, finality and cost terms come from admission.
 * No persisted review, reservation, signature or broadcast is performed here.
 * The HTTP integration must persist this context, never accept it back as proof. */
export async function prepareOwnedTransfer(database: D1Database, identityInput: Principal,
  accountId: ResourceId<'walletAccount'>, requestInput: unknown, scopeInput: WebAuthnScope,
  profilesInput: readonly (BalanceProfile & { readonly entryPointCodeHash: Hex })[],
  termsInput: TransferPreparationTerms, signal: AbortSignal, sponsor?: GasSponsor) {
  const request = parseTransferRequest(requestInput);
  const identity = Object.freeze({ ...identityInput }), scope = { ...scopeInput };
  const profiles = structuredClone(profilesInput), terms = structuredClone(termsInput);
  assertWebAuthnScope(scope);
  const termsRequest = parseTransferRequest(terms.request);
  // Fixed field order; input property order is not part of the economic request.
  const binding = (value: TransferRequest) => JSON.stringify([value.schema_version, value.generation, value.wallet_id,
    value.network_id, value.asset_id, value.destination.address, value.destination.address_type,
    value.amount.kind, value.amount.kind === 'exact' ? value.amount.amount_atomic : null, value.client_release_id]);
  if (binding(request) !== binding(termsRequest) || terms.wallet_account_id !== accountId) throw new Error('TRANSFER_PREPARATION_TERMS');
  function freshTerms() {
    const now = Math.floor(Date.now() / 1000);
    if (![terms.observed_at, terms.expires_at, identity.expiresAt, now].every(Number.isSafeInteger)
      || terms.observed_at < 1 || terms.observed_at > now || now >= terms.expires_at
      || terms.expires_at > terms.observed_at + 60 || now >= identity.expiresAt) throw new Error('TRANSFER_PREPARATION_EXPIRED');
    return now;
  }
  freshTerms();
  return withDeadline(signal, 30_000, async deadline => {
    const owner = { ownedAccount: (wid: ResourceId<'wallet'>, aid: ResourceId<'walletAccount'>) =>
      new WalletRepository(database, identity).ownedAccount(wid, aid) };
    const owned = await owner.ownedAccount(request.wallet_id, accountId);
    deadline.throwIfAborted();
    const matching = profiles.filter(p => p.digest === owned.deployment_manifest_sha256);
    if (matching.length !== 1) throw new Error('TRANSFER_PREPARATION_PROFILE');
    const profile = matching[0], manifest = loadPinnedDeploymentManifest(profile.document, profile.digest);
    requireHash(profile.entryPointCodeHash);
    const assets = [...new Set([request.asset_id, terms.native_asset_id])].sort();
    if (manifest.lifecycle_status !== 'deployed' || manifest.network_id !== request.network_id || owned.network_id !== request.network_id
      || terms.deployment_digest !== profile.digest || profile.assetIds.length !== assets.length
      || new Set(profile.assetIds).size !== assets.length || profile.assetIds.some(id => !assets.includes(id))) {
      throw new Error('TRANSFER_PREPARATION_PROFILE');
    }
    const source = profile.finalityEvidence;
    if (source.status !== 'finalized' || !source.checkpoint) throw new Error('TRANSFER_PREPARATION_FINALITY');
    const peers = validateRpcProviders(profile.providers);
    const rpcUrls: readonly [string, string] = [peers[0].url, peers[1].url];
    const results = await Promise.allSettled([
      inspectOwnedWalletAccount(owner, request.wallet_id, accountId, [{ ...profile, rpcUrls }], deadline),
      inspectOwnedWalletBalances(owner, request.wallet_id, accountId, [profile], deadline),
      observeTransferNonce({ network_id: manifest.network_id, genesis_hash: manifest.genesis_hash, account: owned.address,
        entry_point: manifest.entry_point, entry_point_code_hash: profile.entryPointCodeHash, checkpoint: source.checkpoint }, peers, deadline),
      new TransferNonceReservationRepository(database, identity).reservedFunds(request.wallet_id, accountId, assets),
    ]);
    deadline.throwIfAborted();
    const [security, balances, nonce, holds] = results;
    if (security.status !== 'fulfilled' || balances.status !== 'fulfilled' || nonce.status !== 'fulfilled' || holds.status !== 'fulfilled') {
      throw new Error('TRANSFER_PREPARATION_OBSERVATION');
    }
    const observation = security.value;
    if (observation.status !== 'recognized' || !('security' in observation) || observation.security.phase !== 'active_policy') {
      throw new Error('TRANSFER_PREPARATION_SECURITY');
    }
    const reserved = await new TransferNonceReservationRepository(database, identity).reservedFunds(request.wallet_id, accountId, assets);
    const current = await owner.ownedAccount(request.wallet_id, accountId);
    deadline.throwIfAborted();
    if (JSON.stringify(current) !== JSON.stringify(owned) || JSON.stringify(reserved) !== JSON.stringify(holds.value)) {
      throw new Error('TRANSFER_PREPARATION_CHANGED');
    }
    const now = freshTerms(), balance = balances.value, n = nonce.value;
    const available = (id: string) => {
      const amount = balance.balances.find(row => row.asset_id === id), hold = reserved.find(row => row.asset_id === id);
      if (!amount || !hold) throw new Error('TRANSFER_PREPARATION_BALANCE');
      const value = BigInt(parseAtomicAmount(amount.amount_atomic)) - BigInt(parseAtomicAmount(hold.amount_atomic));
      if (value < 0n) throw new Error('TRANSFER_PREPARATION_BALANCE');
      return value.toString();
    };
    const expires = Math.min(terms.expires_at, identity.expiresAt, source.expires_at, observation.security_expires_at, balance.expires_at);
    const context: Context = { account: owned.address, account_id: owned.account_id, deployment_digest: profile.digest,
      security_version: BigInt(parseAtomicAmount(observation.security_version)), policy_hash: hashSecurityPolicy(observation.security.policy),
      entry_point: manifest.entry_point, nonce: BigInt(parseAtomicAmount(n.nonce)), native_asset_id: terms.native_asset_id,
      fee_recipient: terms.fee_recipient, gas: terms.gas,
      ...(sponsor ? { sponsorship: sponsor.terms(now, expires) } : {}),
      budget: { wallet_id: request.wallet_id, asset_id: request.asset_id, asset_available_atomic: available(request.asset_id),
        native_available_atomic: available(terms.native_asset_id), maximum_native_gas_atomic: sponsor ? '0' : terms.maximum_native_gas_atomic,
        platform_fee: terms.platform_fee },
      checkpoint: { block_number: balance.checkpoint.block_number, block_hash: balance.checkpoint.block_hash,
        observed_at: balance.observed_at, expires_at: expires }, valid_until: expires };
    let candidate = prepareTransferOperation(request, context, now);
    if (sponsor) {
      context.sponsorship = await sponsor.authorize(candidate.operation, candidate.plan.validAfter, candidate.plan.validUntil);
      deadline.throwIfAborted(); freshTerms();
      candidate = prepareTransferOperation(request, context, now);
    }
    const approval: Approval = { prepared_at: now, reviewed_digest: candidate.digest, policy: observation.security.policy, scope,
      security_evidence: { document: profile.document, digest: profile.digest, observation,
        finality: observation.finality_evidence, finality_policy: profile.finalityPolicy,
        observed_at: observation.security_observed_at, expires_at: observation.security_expires_at },
      balance_evidence: { ...balance, reserved }, nonce_evidence: n };
    assertTransferSecurity(candidate, approval.security_evidence, now);
    assertTransferBalance(candidate, context, approval.balance_evidence, approval.security_evidence.finality, now);
    if (n.network_id !== request.network_id || !isAddressEqual(n.account, owned.address) || !isAddressEqual(n.entry_point, manifest.entry_point)
      || n.checkpoint.block_number !== candidate.checkpoint.block_number || n.checkpoint.block_hash !== candidate.checkpoint.block_hash
      || !Number.isSafeInteger(n.observed_at) || n.observed_at > now || n.observed_at < now - 60) throw new Error('TRANSFER_NONCE_MISMATCH');
    return Object.freeze({ candidate, context, approval, wallet_account_id: accountId, send_enabled: false as const });
  });
}
