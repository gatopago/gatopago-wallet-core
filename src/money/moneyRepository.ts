import { isAddressEqual, type Hex } from 'viem';
import { deploymentDocumentDigest, requireHash } from '@gatopago/shared/v3/deployment';
import { createResourceId, parseResourceId, type ResourceId } from '@gatopago/shared/v3/primitives';
import {
  readMoneyDraft,
  readMoneyReview,
  writeMoneyDraft,
  writeMoneyReview,
  type MoneyConsentReview,
} from '@gatopago/shared/v3/money-review-record';
import { parseMoneyRequest } from '@gatopago/shared/v3/money-wire';
import { assertWebAuthnScope, type WebAuthnScope } from '@gatopago/shared/v3/webauthn';
import { WalletRepository } from '../accounts/repository';
import { AUTHORIZED_USER, authorizationValues } from '../auth/authorization';
import type { Principal } from '../auth/principal';
import { BALANCE_FLOOR_CURRENT, floorValues } from '../execution/spendCheckpoint';
import type { prepareOwnedMoney } from './moneyPreparation';
import type { observeOwnedMoneyCurrent } from './moneyCurrentState';
import { moneyConfirmationDigest } from './moneyWire';
import { writeExecutionOperationRecord } from '../execution/executionOperationRecord';
import type { preflightOwnedMoney } from './moneyPreflight';

export function moneyIdempotencyKey(value: unknown): string {
  if (typeof value !== 'string' || !/^[A-Za-z0-9][A-Za-z0-9._:-]{0,127}$(?![\s\S])/.test(value))
    throw new Error('MONEY_IDEMPOTENCY_KEY_INVALID');
  return value;
}
const moneyRequestDigest = (input: unknown) =>
  deploymentDocumentDigest(JSON.stringify(parseMoneyRequest(input)));
export const moneyFunds = (candidate: ReturnType<typeof readMoneyDraft>['candidate']) => {
  const json = JSON.stringify({
    schema_version: 1,
    usdc_debit_atomic: candidate.funding.asset_debit_atomic,
    position_debit_atomic: candidate.funding.position_debit_atomic,
    native_debit_atomic: candidate.funding.maximum_native_gas_atomic,
  });
  return { json, digest: deploymentDocumentDigest(json) };
};
type Prepared = ReturnType<typeof readMoneyDraft>;
type Owned = Awaited<ReturnType<WalletRepository['ownedAccount']>>;

/** Invocation-owned primary sessions. A restored unsigned review or a historical
 * signature is never a fresh dispatch grant. No method in this repository sends. */
export class MoneyRepository {
  private readonly identity: Principal;
  private readonly scope: WebAuthnScope;
  private readonly pins: readonly { deployment: Hex; market: Hex }[];
  constructor(
    private readonly database: D1Database,
    identity: Principal,
    scope: WebAuthnScope,
    pins: readonly { deployment: Hex; market: Hex }[],
  ) {
    this.identity = Object.freeze({ ...identity });
    this.scope = Object.freeze({ ...scope });
    this.pins = structuredClone(pins);
    assertWebAuthnScope(this.scope);
    if (!pins.length || pins.length > 32) throw new Error('MONEY_PROFILE_UNAVAILABLE');
    for (const pin of pins) {
      requireHash(pin.deployment);
      requireHash(pin.market);
    }
  }
  private owner(walletId: ResourceId<'wallet'>, accountId: ResourceId<'walletAccount'>) {
    return new WalletRepository(this.database, this.identity).ownedAccount(walletId, accountId);
  }
  private binding(record: Prepared, owned: Owned) {
    const { candidate: candidate, review } = record;
    if (
      candidate.request.wallet_id !== owned.wallet_id ||
      candidate.request.wallet_account_id !== owned.id ||
      !this.pins.some(
        (pin) =>
          pin.deployment === candidate.deployment_digest &&
          pin.market === review.context.market.digest,
      ) ||
      candidate.deployment_digest !== owned.deployment_manifest_sha256 ||
      candidate.request.network_id !== owned.network_id ||
      candidate.plan.accountId !== owned.account_id ||
      !isAddressEqual(candidate.account, owned.address) ||
      review.scope.origin !== this.scope.origin ||
      review.scope.rpId !== this.scope.rpId
    )
      throw new Error('MONEY_REVIEW_MISMATCH');
  }
  private authorizedRow(
    table: 'money_preparations' | 'money_operations',
    walletId: ResourceId<'wallet'>,
    accountId: ResourceId<'walletAccount'>,
    id: ResourceId<'operation'>,
    history = false,
  ) {
    return this.database
      .withSession('first-primary')
      .prepare(
        `SELECT r.* FROM ${table} r
      JOIN wallets w ON w.id = r.wallet_id JOIN users u ON u.id = w.user_id
      WHERE r.id = ? AND r.wallet_id = ? AND r.wallet_account_id = ? AND r.actor_id = u.id
        AND ${AUTHORIZED_USER}${history ? '' : ' AND u.auth_not_before <= r.authorized_auth_time'}`,
      )
      .bind(id, walletId, accountId, ...authorizationValues(this.identity))
      .first();
  }
  async findPreparation(
    walletId: ResourceId<'wallet'>,
    accountId: ResourceId<'walletAccount'>,
    keyInput: unknown,
    requestInput: unknown,
  ) {
    const key = moneyIdempotencyKey(keyInput),
      digest = moneyRequestDigest(requestInput);
    await this.owner(walletId, accountId);
    const row = await this.database
      .withSession('first-primary')
      .prepare(
        `SELECT id,request_sha256 FROM money_preparations
      WHERE wallet_id = ? AND wallet_account_id = ? AND actor_id = ? AND idempotency_key = ?`,
      )
      .bind(walletId, accountId, this.identity.userId, key)
      .first();
    if (!row) return null;
    if (row.request_sha256 !== digest) throw new Error('MONEY_IDEMPOTENCY_CONFLICT');
    return this.readPreparation(walletId, accountId, parseResourceId('operation', row.id));
  }
  async savePreparation(
    input: Pick<
      Awaited<ReturnType<typeof prepareOwnedMoney>>,
      'candidate' | 'review' | 'send_enabled'
    >,
    keyInput: unknown,
  ) {
    const prepared = structuredClone(input),
      key = moneyIdempotencyKey(keyInput),
      encoded = writeMoneyDraft(prepared.review);
    const record = readMoneyDraft(encoded.json, encoded.digest),
      candidate = record.candidate;
    const walletId = candidate.request.wallet_id,
      accountId = candidate.request.wallet_account_id;
    const owned = await this.owner(walletId, accountId);
    this.binding(record, owned);
    const now = Math.floor(Date.now() / 1000);
    if (
      candidate.digest !== prepared.candidate.digest ||
      prepared.send_enabled !== false ||
      now < record.review.prepared_at ||
      now >= candidate.plan.validUntil ||
      now >= this.identity.expiresAt
    )
      throw new Error('MONEY_OBSERVATION_EXPIRED');
    const prior = await this.findPreparation(walletId, accountId, key, candidate.request);
    if (prior) return prior;
    const id = createResourceId('operation'),
      db = this.database.withSession('first-primary');
    const results = await db.batch<Record<string, unknown>>([
      db
        .prepare(
          `INSERT INTO money_preparations(id,wallet_id,wallet_account_id,actor_id,idempotency_key,request_sha256,consent_digest,
        deployment_manifest_sha256,market_sha256,review_json,review_sha256,authorized_auth_time,created_at,expires_at)
        SELECT ?,w.id,a.id,u.id,?,?,?,?,?,?,?,?,?,? FROM wallet_accounts a JOIN wallets w ON w.id = a.wallet_id JOIN users u ON u.id = w.user_id
        WHERE a.id = ? AND w.id = ? AND w.status = 'active' AND a.address = ? AND a.deployment_manifest_sha256 = ?
          AND ${AUTHORIZED_USER} AND ${BALANCE_FLOOR_CURRENT}
          AND NOT EXISTS (SELECT 1 FROM wallet_spend_locks l WHERE l.wallet_account_id = a.id AND l.released_at IS NULL)
          AND (SELECT count(*) FROM money_preparations p WHERE p.wallet_account_id = a.id AND p.expires_at > ?) < 16
        ON CONFLICT DO NOTHING`,
        )
        .bind(
          id,
          key,
          moneyRequestDigest(candidate.request),
          candidate.digest,
          candidate.deployment_digest,
          record.review.context.market.digest,
          encoded.json,
          encoded.digest,
          this.identity.authTime,
          record.review.prepared_at,
          candidate.plan.validUntil,
          accountId,
          walletId,
          owned.address,
          candidate.deployment_digest,
          ...authorizationValues(this.identity),
          ...floorValues(accountId, candidate.checkpoint),
          now,
        ),
      db
        .prepare(
          `SELECT id,request_sha256 FROM money_preparations WHERE actor_id = ? AND wallet_account_id = ? AND idempotency_key = ?`,
        )
        .bind(this.identity.userId, accountId, key),
    ]);
    if (results.some((result) => !result.success)) throw new Error('MONEY_STORAGE_UNAVAILABLE');
    const selected = results[1].results[0];
    if (!selected) throw new Error('MONEY_PREPARATION_CAPACITY_OR_CHANGED');
    if (selected.request_sha256 !== moneyRequestDigest(candidate.request))
      throw new Error('MONEY_IDEMPOTENCY_CONFLICT');
    const stored = await this.readPreparation(
      walletId,
      accountId,
      parseResourceId('operation', selected.id),
    );
    if (JSON.stringify(await this.owner(walletId, accountId)) !== JSON.stringify(owned))
      throw new Error('MONEY_PREPARATION_CHANGED');
    return stored;
  }
  async readPreparation(
    walletId: ResourceId<'wallet'>,
    accountId: ResourceId<'walletAccount'>,
    id: ResourceId<'operation'>,
  ) {
    return this.loadPreparation(walletId, accountId, id, false);
  }
  /** A fresh valid owner may read an older reference after session revocation.
   * Confirm/deliver continue to require the original authorization epoch. */
  async readPreparationHistory(
    walletId: ResourceId<'wallet'>,
    accountId: ResourceId<'walletAccount'>,
    id: ResourceId<'operation'>,
  ) {
    return this.loadPreparation(walletId, accountId, id, true);
  }
  private async loadPreparation(
    walletId: ResourceId<'wallet'>,
    accountId: ResourceId<'walletAccount'>,
    id: ResourceId<'operation'>,
    history: boolean,
  ) {
    parseResourceId('operation', id);
    const owned = await this.owner(walletId, accountId),
      row = await this.authorizedRow('money_preparations', walletId, accountId, id, history);
    if (!row) throw new Error('MONEY_PREPARATION_NOT_FOUND');
    const record = readMoneyDraft(row.review_json, row.review_sha256);
    this.binding(record, owned);
    const candidate = record.candidate;
    if (
      row.request_sha256 !== moneyRequestDigest(record.review.request) ||
      row.consent_digest !== candidate.digest ||
      row.deployment_manifest_sha256 !== candidate.deployment_digest ||
      row.market_sha256 !== record.review.context.market.digest ||
      row.created_at !== record.review.prepared_at ||
      row.expires_at !== candidate.plan.validUntil ||
      row.actor_id !== this.identity.userId
    )
      throw new Error('MONEY_REVIEW_MISMATCH');
    const current = await this.owner(walletId, accountId),
      repeated = await this.authorizedRow('money_preparations', walletId, accountId, id, history);
    if (
      JSON.stringify(current) !== JSON.stringify(owned) ||
      JSON.stringify(repeated) !== JSON.stringify(row)
    )
      throw new Error('MONEY_PREPARATION_CHANGED');
    requireHash(row.review_sha256);
    const now = Math.floor(Date.now() / 1000);
    return Object.freeze({
      id,
      ...record,
      record_json: row.review_json as string,
      record_sha256: row.review_sha256,
      state:
        now >= candidate.plan.validUntil ? ('expired_unsigned' as const) : ('prepared' as const),
      send_enabled: false as const,
    });
  }
  async findConfirmation(
    walletId: ResourceId<'wallet'>,
    accountId: ResourceId<'walletAccount'>,
    keyInput: unknown,
    fingerprint: Hex,
  ) {
    const key = moneyIdempotencyKey(keyInput);
    requireHash(fingerprint);
    await this.owner(walletId, accountId);
    const row = await this.database
      .withSession('first-primary')
      .prepare(
        `SELECT id,confirmation_sha256 FROM money_operations
      WHERE wallet_id = ? AND wallet_account_id = ? AND actor_id = ? AND confirm_key = ?`,
      )
      .bind(walletId, accountId, this.identity.userId, key)
      .first();
    if (!row) return null;
    if (row.confirmation_sha256 !== fingerprint) throw new Error('MONEY_IDEMPOTENCY_CONFLICT');
    return this.readOperation(walletId, accountId, parseResourceId('operation', row.id));
  }
  /** Recover a lost confirmation response using the owned preparation ID only.
   * No saved assertions, fresh signature or mutation is required for this read. */
  async operationForPreparation(
    walletId: ResourceId<'wallet'>,
    accountId: ResourceId<'walletAccount'>,
    preparationId: ResourceId<'operation'>,
  ) {
    await this.readPreparationHistory(walletId, accountId, preparationId);
    const row = await this.database
      .withSession('first-primary')
      .prepare(
        `SELECT id FROM money_operations
      WHERE preparation_id = ? AND wallet_id = ? AND wallet_account_id = ? AND actor_id = ?`,
      )
      .bind(preparationId, walletId, accountId, this.identity.userId)
      .first();
    if (!row) return null;
    const stored = await this.readOperationHistory(
      walletId,
      accountId,
      parseResourceId('operation', row.id),
    );
    if (stored.preparation_id !== preparationId) throw new Error('MONEY_REVIEW_MISMATCH');
    return stored.id;
  }
  /** Acquire the cross-domain lock in the same transaction as the immutable
   * signed record. Fresh evidence is private coordinator output, never HTTP. */
  async authorizeOperation(
    walletId: ResourceId<'wallet'>,
    accountId: ResourceId<'walletAccount'>,
    preparationId: ResourceId<'operation'>,
    reviewInput: MoneyConsentReview,
    keyInput: unknown,
    fingerprint: Hex,
    freshInput: Awaited<ReturnType<typeof observeOwnedMoneyCurrent>>,
  ) {
    const key = moneyIdempotencyKey(keyInput);
    requireHash(fingerprint);
    const review = structuredClone(reviewInput),
      fresh = structuredClone(freshInput),
      encoded = writeMoneyReview(review);
    const verified = await readMoneyReview(encoded.json, encoded.digest),
      candidate = verified.candidate;
    if (
      moneyConfirmationDigest(preparationId, candidate.digest, verified.review.proofs) !==
      fingerprint
    )
      throw new Error('MONEY_IDEMPOTENCY_CONFLICT');
    const prior = await this.findConfirmation(walletId, accountId, key, fingerprint);
    if (prior) {
      if (prior.candidate.digest !== candidate.digest || prior.preparation_id !== preparationId)
        throw new Error('MONEY_IDEMPOTENCY_CONFLICT');
      return prior;
    }
    const preparation = await this.readPreparation(walletId, accountId, preparationId),
      owned = await this.owner(walletId, accountId);
    this.binding({ candidate, review: verified.review }, owned);
    const draft = writeMoneyDraft(review),
      now = Math.floor(Date.now() / 1000);
    if (
      preparation.state !== 'prepared' ||
      draft.digest !== preparation.record_sha256 ||
      candidate.digest !== preparation.candidate.digest ||
      encoded.digest !== fresh.record_sha256 ||
      candidate.digest !== fresh.consent_digest ||
      candidate.userOpHash !== fresh.userop_hash ||
      fresh.nonce !== candidate.plan.nonce.toString() ||
      fresh.security_version !== candidate.plan.securityVersion.toString() ||
      ![fresh.checked_at, fresh.expires_at, review.approved_at, now].every(Number.isSafeInteger) ||
      now < fresh.checked_at ||
      now >= fresh.expires_at ||
      fresh.expires_at > fresh.checked_at + 5 ||
      now < review.approved_at ||
      now >= candidate.plan.validUntil ||
      fresh.expires_at > candidate.plan.validUntil
    )
      throw new Error('MONEY_CONFIRMATION_CHANGED');
    const funds = moneyFunds(candidate),
      id = createResourceId('operation'),
      db = this.database.withSession('first-primary');
    const results = await db
      .batch<Record<string, unknown>>([
        db
          .prepare(
            `INSERT INTO money_operations(id,preparation_id,wallet_id,wallet_account_id,actor_id,confirm_key,confirmation_sha256,
        network_id,account_address,entry_point,nonce,consent_digest,userop_hash,deployment_manifest_sha256,market_sha256,
        review_json,review_sha256,funds_json,funds_sha256,authorized_auth_time,state,created_at,expires_at)
        SELECT ?,?,w.id,a.id,u.id,?,?,a.network_id,a.address,?,?,?,?,?,?,?,?,?,?,?,'authorized',?,?
        FROM wallet_accounts a JOIN wallets w ON w.id = a.wallet_id JOIN users u ON u.id = w.user_id
        WHERE a.id = ? AND w.id = ? AND w.status = 'active' AND a.address = ? AND a.deployment_manifest_sha256 = ?
          AND ${AUTHORIZED_USER} AND ${BALANCE_FLOOR_CURRENT}
          AND EXISTS (SELECT 1 FROM money_preparations p WHERE p.id = ? AND p.wallet_id = w.id AND p.wallet_account_id = a.id
            AND p.actor_id = u.id AND p.review_sha256 = ? AND p.consent_digest = ? AND p.expires_at > unixepoch()
            AND p.authorized_auth_time >= u.auth_not_before)
          AND ? <= unixepoch() AND ? > unixepoch()
        ON CONFLICT DO NOTHING`,
          )
          .bind(
            id,
            preparationId,
            key,
            fingerprint,
            candidate.plan.entryPoint.toLowerCase(),
            candidate.plan.nonce.toString(),
            candidate.digest,
            candidate.userOpHash,
            candidate.deployment_digest,
            review.context.market.digest,
            encoded.json,
            encoded.digest,
            funds.json,
            funds.digest,
            this.identity.authTime,
            review.approved_at,
            candidate.plan.validUntil,
            accountId,
            walletId,
            owned.address,
            candidate.deployment_digest,
            ...authorizationValues(this.identity),
            ...floorValues(accountId, fresh.checkpoint),
            preparationId,
            preparation.record_sha256,
            candidate.digest,
            fresh.checked_at,
            fresh.expires_at,
          ),
        db
          .prepare(
            `SELECT id,confirm_key,confirmation_sha256 FROM money_operations WHERE preparation_id = ? AND wallet_account_id = ?`,
          )
          .bind(preparationId, accountId),
      ])
      .catch((error) => {
        if (error instanceof Error && /ACCOUNT_SPEND_BUSY/.test(error.message))
          throw new Error('ACCOUNT_SPEND_BUSY');
        throw error;
      });
    if (results.some((result) => !result.success)) throw new Error('MONEY_STORAGE_UNAVAILABLE');
    const selected = results[1].results[0];
    if (!selected) throw new Error('MONEY_CONFIRMATION_CHANGED');
    if (selected.confirm_key !== key || selected.confirmation_sha256 !== fingerprint)
      throw new Error('MONEY_IDEMPOTENCY_CONFLICT');
    const stored = await this.readOperation(
      walletId,
      accountId,
      parseResourceId('operation', selected.id),
    );
    if (
      stored.candidate.digest !== candidate.digest ||
      JSON.stringify(await this.owner(walletId, accountId)) !== JSON.stringify(owned)
    )
      throw new Error('MONEY_CONFIRMATION_CHANGED');
    return stored;
  }
  /** One durable winner. The UPDATE, cross-domain dispatch lock and recovery job
   * are a single D1 transaction through migration triggers, before any broadcast. */
  async beginDelivery(
    walletId: ResourceId<'wallet'>,
    accountId: ResourceId<'walletAccount'>,
    operationId: ResourceId<'operation'>,
    input: Awaited<ReturnType<typeof preflightOwnedMoney>>,
  ) {
    const fresh = structuredClone(input),
      stored = await this.readOperation(walletId, accountId, operationId);
    if (stored.state !== 'authorized') return Object.freeze({ won: false as const, stored });
    const c = stored.candidate,
      plan = c.plan,
      estimate = fresh.simulation;
    const payload = writeExecutionOperationRecord(stored.operation, {
      network_id: c.request.network_id,
      account: c.account,
      account_id: plan.accountId,
      entry_point: plan.entryPoint,
      userop_hash: c.userOpHash,
      consent_digest: c.digest,
      valid_until: plan.validUntil,
    });
    const now = Math.floor(Date.now() / 1000);
    if (
      fresh.operation_id !== operationId ||
      fresh.record_sha256 !== stored.record_sha256 ||
      fresh.operation_sha256 !== payload.digest ||
      fresh.consent_digest !== c.digest ||
      fresh.userop_hash !== c.userOpHash ||
      fresh.nonce !== plan.nonce.toString() ||
      fresh.security_version !== plan.securityVersion.toString() ||
      fresh.send_enabled !== false ||
      estimate.send_enabled !== false ||
      estimate.operation_sha256 !== payload.digest ||
      estimate.userop_hash !== c.userOpHash ||
      estimate.consent_digest !== c.digest ||
      ![fresh.checked_at, fresh.expires_at, estimate.observed_at, estimate.expires_at].every(
        Number.isSafeInteger,
      ) ||
      now < fresh.checked_at ||
      now < estimate.observed_at ||
      now >= fresh.expires_at ||
      now >= estimate.expires_at ||
      fresh.expires_at > fresh.checked_at + 5 ||
      estimate.expires_at > estimate.observed_at + 5 ||
      fresh.expires_at > plan.validUntil ||
      estimate.expires_at > plan.validUntil ||
      now >= plan.validUntil
    )
      throw new Error('MONEY_PREFLIGHT_STALE_OR_CHANGED');
    const db = this.database.withSession('first-primary');
    const result = await db
      .prepare(
        `UPDATE money_operations AS r SET state = 'dispatch_pending',dispatch_started_at = unixepoch()
      WHERE r.id = ? AND r.wallet_id = ? AND r.wallet_account_id = ? AND r.actor_id = ? AND r.state = 'authorized'
        AND r.dispatch_started_at IS NULL AND r.review_sha256 = ? AND r.consent_digest = ? AND r.userop_hash = ?
        AND r.created_at <= unixepoch() AND r.expires_at > unixepoch() AND ? <= unixepoch() AND ? > unixepoch()
        AND ? <= unixepoch() AND ? > unixepoch() AND ${BALANCE_FLOOR_CURRENT}
        AND EXISTS (SELECT 1 FROM wallet_accounts a JOIN wallets w ON w.id = a.wallet_id JOIN users u ON u.id = w.user_id
          WHERE a.id = r.wallet_account_id AND w.id = r.wallet_id AND w.status = 'active' AND a.address = r.account_address
            AND a.network_id = r.network_id AND a.deployment_manifest_sha256 = r.deployment_manifest_sha256
            AND ${AUTHORIZED_USER} AND u.auth_not_before <= r.authorized_auth_time)
        AND EXISTS (SELECT 1 FROM wallet_spend_locks l WHERE l.operation_id = r.id AND l.wallet_account_id = r.wallet_account_id
          AND l.domain = 'money' AND l.state = 'held' AND l.released_at IS NULL AND l.consent_digest = r.consent_digest)
      RETURNING id`,
      )
      .bind(
        operationId,
        walletId,
        accountId,
        this.identity.userId,
        stored.record_sha256,
        c.digest,
        c.userOpHash,
        fresh.checked_at,
        fresh.expires_at,
        estimate.observed_at,
        estimate.expires_at,
        ...floorValues(accountId, fresh.checkpoint),
        ...authorizationValues(this.identity),
      )
      .first<{ id: string }>();
    const current = await this.readOperation(walletId, accountId, operationId);
    if (result?.id !== operationId) {
      if (current.state === 'authorized') throw new Error('MONEY_DELIVERY_CHANGED');
      return Object.freeze({ won: false as const, stored: current });
    }
    if (
      current.state !== 'dispatch_pending' ||
      current.record_sha256 !== stored.record_sha256 ||
      current.dispatch_started_at !== now
    ) {
      // A second boundary may elapse while D1 commits; accept only a timestamp
      // inside the measured freshness window, never reinterpret a later state.
      if (
        current.state !== 'dispatch_pending' ||
        current.record_sha256 !== stored.record_sha256 ||
        typeof current.dispatch_started_at !== 'number' ||
        current.dispatch_started_at < fresh.checked_at ||
        current.dispatch_started_at >= fresh.expires_at
      )
        throw new Error('MONEY_DELIVERY_CHANGED');
    }
    return Object.freeze({
      won: true as const,
      stored: current,
      expires_at: Math.min(fresh.expires_at, estimate.expires_at),
    });
  }
  async readOperation(
    walletId: ResourceId<'wallet'>,
    accountId: ResourceId<'walletAccount'>,
    id: ResourceId<'operation'>,
  ) {
    return this.loadOperation(walletId, accountId, id, false);
  }
  async readOperationHistory(
    walletId: ResourceId<'wallet'>,
    accountId: ResourceId<'walletAccount'>,
    id: ResourceId<'operation'>,
  ) {
    return this.loadOperation(walletId, accountId, id, true);
  }
  private async loadOperation(
    walletId: ResourceId<'wallet'>,
    accountId: ResourceId<'walletAccount'>,
    id: ResourceId<'operation'>,
    history: boolean,
  ) {
    parseResourceId('operation', id);
    const owned = await this.owner(walletId, accountId),
      row = await this.authorizedRow('money_operations', walletId, accountId, id, history);
    if (!row) throw new Error('MONEY_OPERATION_NOT_FOUND');
    const verified = await readMoneyReview(row.review_json, row.review_sha256);
    this.binding({ candidate: verified.candidate, review: verified.review }, owned);
    const candidate = verified.candidate;
    const funds = moneyFunds(candidate);
    if (
      row.consent_digest !== candidate.digest ||
      row.userop_hash !== candidate.userOpHash ||
      row.nonce !== candidate.plan.nonce.toString() ||
      row.entry_point !== candidate.plan.entryPoint.toLowerCase() ||
      row.network_id !== candidate.request.network_id ||
      row.account_address !== candidate.account.toLowerCase() ||
      row.deployment_manifest_sha256 !== candidate.deployment_digest ||
      row.market_sha256 !== verified.review.context.market.digest ||
      row.created_at !== verified.review.approved_at ||
      row.expires_at !== candidate.plan.validUntil ||
      row.funds_json !== funds.json ||
      row.funds_sha256 !== funds.digest ||
      ![
        'authorized',
        'dispatch_pending',
        'submitted',
        'confirming',
        'reconciled',
        'reverted_confirmed',
        'expired_unsubmitted',
        'review_required',
      ].includes(String(row.state))
    )
      throw new Error('MONEY_REVIEW_MISMATCH');
    const current = await this.owner(walletId, accountId),
      repeated = await this.authorizedRow('money_operations', walletId, accountId, id, history);
    if (
      JSON.stringify(current) !== JSON.stringify(owned) ||
      JSON.stringify(repeated) !== JSON.stringify(row)
    )
      throw new Error('MONEY_OPERATION_CHANGED');
    requireHash(row.review_sha256);
    return Object.freeze({
      id,
      ...verified,
      state: String(row.state),
      preparation_id: parseResourceId('operation', row.preparation_id),
      record_sha256: row.review_sha256,
      dispatch_started_at: row.dispatch_started_at,
      send_enabled: false as const,
    });
  }
}
