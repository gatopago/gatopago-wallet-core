import type { Hex } from 'viem';
import type { ResourceId } from '@gatopago/shared/v3/primitives';
import type { WebAuthnScope } from '@gatopago/shared/v3/webauthn';
import type { Principal } from '../auth/principal';
import { withDeadline } from '../deadline';
import { sendOperation } from '../execution/operationTransport';
import { MoneyRepository } from './moneyRepository';
import { preflightOwnedMoney, type MoneyDeliveryProfile } from './moneyPreflight';

/** Public retries read the existing state. Only the durable UPDATE winner may
 * send. Everything after that marker is uncertain until receipt/finality proof. */
export async function deliverOwnedMoney(database: D1Database, identityInput: Principal,
  walletId: ResourceId<'wallet'>, accountId: ResourceId<'walletAccount'>, operationId: ResourceId<'operation'>,
  scope: WebAuthnScope, profilesInput: readonly MoneyDeliveryProfile[], signal: AbortSignal, relayerKey?: Hex) {
  const identity = Object.freeze({ ...identityInput }), profiles = structuredClone(profilesInput);
  const repository = new MoneyRepository(database, identity, scope, profiles.map(p => ({ deployment: p.digest, market: p.market.digest })));
  const stored = await repository.readOperation(walletId, accountId, operationId);
  const view = (state: string, delivery: 'existing' | 'accepted' | 'uncertain') => Object.freeze({ money_schema_version: 1,
    operation_id: operationId, userop_hash: stored.candidate.userOpHash, state, delivery, settlement: 'unconfirmed' as const });
  if (stored.state !== 'authorized') return view(stored.state, 'existing');
  const matching = profiles.filter(p => p.digest === stored.candidate.deployment_digest && p.market.digest === stored.review.context.market.digest);
  if (matching.length !== 1) throw new Error('MONEY_PROFILE_UNAVAILABLE');
  const preflight = await preflightOwnedMoney(database, identity, walletId, accountId, operationId, scope, matching, signal);
  signal.throwIfAborted();
  const claim = await repository.beginDelivery(walletId, accountId, operationId, preflight);
  if (!claim.won) return view(claim.stored.state, 'existing');
  try {
    await withDeadline(signal, Math.max(1, Math.min(30_000, claim.expires_at * 1000 - Date.now())), async deadline => {
      const now = Math.floor(Date.now() / 1000), c = claim.stored.candidate;
      if (typeof claim.stored.dispatch_started_at !== 'number' || now < claim.stored.dispatch_started_at || now >= claim.expires_at) throw new Error('MONEY_DISPATCH_EXPIRED');
      await sendOperation(database, matching[0].transport, { operation: claim.stored.operation, networkId: c.request.network_id,
        entryPoint: c.plan.entryPoint, userOpHash: c.userOpHash, validUntil: c.plan.validUntil }, deadline, relayerKey);
    });
    return view('dispatch_pending', 'accepted');
  } catch { return view('dispatch_pending', 'uncertain'); }
}
