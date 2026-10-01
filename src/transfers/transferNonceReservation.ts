import { AUTHORIZED_USER, authorizationValues } from '../auth/authorization';
import { getAddress, toHex, type Hex } from 'viem';
import { assertAssetNetwork, createResourceId, evmChainId, parseAtomicAmount, parseResourceId, type ResourceId } from '@gatopago/shared/v3/primitives';
import { authorizationDigest } from '@gatopago/shared/v3/authorizations';
import { deploymentDocumentDigest, requireHash } from '@gatopago/shared/v3/deployment';
import type { authorizeTransferOperation } from '@gatopago/shared/v3/transfer-authorization';
import type { Principal } from '../auth/principal';
import { WalletRepository } from '../accounts/repository';
import { readTransferOperationRecord, writeTransferOperationRecord } from './transferOperationRecord';
import { readTransferFunds, writeTransferFunds } from './transferFundsRecord';
import { readTransferReview, writeTransferDraft, writeTransferReview } from '@gatopago/shared/v3/transfer-review-record';

// Compare canonical decimal strings by length then lexically; never SQLite REAL
// or signed-64-bit casts. Included in each monetary write, not just a prior read.
const BALANCE_FLOOR_CURRENT = `NOT EXISTS (SELECT 1 FROM wallet_balance_floors f WHERE f.wallet_account_id = ?
  AND (length(f.block_number) > length(?) OR (length(f.block_number) = length(?) AND f.block_number > ?)
    OR (f.block_number = ? AND f.block_hash != ?)))`;
const floorValues = (id: ResourceId<'walletAccount'>, checkpoint: { block_number: string; block_hash: Hex }) =>
  [id, checkpoint.block_number, checkpoint.block_number, checkpoint.block_number, checkpoint.block_number, checkpoint.block_hash];

/** Request-owned primary D1 session. A claim is NOT signature verification
 * or a send grant. Holds only coordinate this service, not external spending.
 * Caller must pass a freshly verified authorization from the private
 * coordinator; this is never an HTTP body API.
 */
export class TransferNonceReservationRepository {
  private readonly db: D1DatabaseSession;
  private readonly identity: Principal;
  constructor(private readonly database: D1Database, identity: Principal) {
    this.identity = Object.freeze({ ...identity });
    this.db = database.withSession('first-primary');
  }
  private owner(walletId: ResourceId<'wallet'>, accountId: ResourceId<'walletAccount'>) {
    // Each revalidation starts on primary, rather than reusing an older read bookmark.
    return new WalletRepository(this.database, this.identity).ownedAccount(walletId, accountId);
  }
  private async liveFunds(accountId: ResourceId<'walletAccount'>, network: string, now: number) {
    const result = await this.db.prepare(`SELECT id,consent_digest,funds_json,funds_sha256 FROM transfer_nonce_reservations
      WHERE wallet_account_id = ? AND (state = 'delivery_pending' OR (state = 'held' AND expires_at > ?)) ORDER BY id LIMIT 33`).bind(accountId, now).all();
    if (result.results.length > 32) throw new Error('TRANSFER_RESERVATION_CAPACITY');
    const totals = new Map<string, bigint>();
    const rows = result.results.map(row => {
      const id = parseResourceId('operation', row.id); requireHash(row.consent_digest); requireHash(row.funds_sha256);
      for (const term of readTransferFunds(row.funds_json, row.funds_sha256, network)) {
        const sum = (totals.get(term.asset_id) ?? 0n) + BigInt(term.debit_atomic);
        parseAtomicAmount(sum.toString()); totals.set(term.asset_id, sum);
      }
      return { id, digest: row.consent_digest, checksum: row.funds_sha256 };
    });
    return { rows, totals, fingerprint: rows.map(row => `${row.id}:${row.checksum}`).join(',') };
  }
  /** For the private balance/quote coordinator. Explicit zeros, never SQL float sums. */
  async reservedFunds(walletId: ResourceId<'wallet'>, accountId: ResourceId<'walletAccount'>, assetIds: readonly string[]) {
    if (assetIds.length < 1 || assetIds.length > 16 || new Set(assetIds).size !== assetIds.length) throw new Error('TRANSFER_FUNDS_INVALID');
    const ids = [...assetIds], owned = await this.owner(walletId, accountId), now = Math.floor(Date.now() / 1000);
    ids.forEach(id => assertAssetNetwork(id, owned.network_id));
    const snapshot = await this.liveFunds(accountId, owned.network_id, now);
    const current = await this.owner(walletId, accountId);
    if (JSON.stringify(current) !== JSON.stringify(owned)) throw new Error('TRANSFER_RESERVATION_INVALID');
    return ids.map(asset_id => ({ asset_id, amount_atomic: (snapshot.totals.get(asset_id) ?? 0n).toString() }));
  }
  /** Private snapshot for pre-dispatch checks. The future lease transition MUST
   * compare this fingerprint atomically; this read does not acquire a lease. */
  async deliveryFundsSnapshot(walletId: ResourceId<'wallet'>, accountId: ResourceId<'walletAccount'>, id: ResourceId<'operation'>) {
    const stored = await this.readOwned(walletId, accountId, id);
    if (stored.state !== 'held') throw new Error('TRANSFER_RESERVATION_EXPIRED');
    const owned = await this.owner(walletId, accountId), now = Math.floor(Date.now() / 1000);
    const live = await this.liveFunds(accountId, owned.network_id, now);
    const digest = authorizationDigest('ExecutionPlan', evmChainId(owned.network_id), stored.operation.sender, stored.plan);
    if (!live.rows.some(row => row.id === id && row.digest === digest)) throw new Error('TRANSFER_RESERVATION_CONCURRENT_CHANGE');
    const current = await this.owner(walletId, accountId), finished = Math.floor(Date.now() / 1000);
    const expires = Math.min(now + 5, stored.plan.validUntil);
    if (JSON.stringify(current) !== JSON.stringify(owned) || finished < now || finished >= expires) throw new Error('TRANSFER_RESERVATION_EXPIRED');
    return Object.freeze({ id, wallet_id: walletId, wallet_account_id: accountId, network_id: owned.network_id,
      account: stored.operation.sender, userop_hash: stored.plan.userOpHash, consent_digest: digest,
      own_funds: stored.funds, total_reserved: Object.freeze(stored.funds.map(row => Object.freeze({ asset_id: row.asset_id,
        amount_atomic: (live.totals.get(row.asset_id) ?? 0n).toString() }))), fingerprint: live.fingerprint,
      observed_at: now, expires_at: expires, send_enabled: false as const });
  }
  /** Private one-winner transition BEFORE any broadcast. The raw claim token is
   * returned only once and never persisted/logged. Losing the response requires
   * reconciliation, not a fresh claim or expiry-based release of funds.
   * Input is the internal preflight result, never an HTTP payload.
   */
  async beginDelivery(walletId: ResourceId<'wallet'>, accountId: ResourceId<'walletAccount'>, input: {
    operation_id: ResourceId<'operation'>; userop_hash: Hex; consent_digest: Hex;
    checked_at: number; expires_at: number; reservation_fingerprint: string; reservation_observed_at: number;
    simulation: { userop_hash: Hex; consent_digest: Hex; operation_sha256: Hex; observed_at: number; expires_at: number };
  }) {
    const proof = structuredClone(input), stored = await this.readOwned(walletId, accountId, proof.operation_id);
    if (stored.state !== 'held') throw new Error('TRANSFER_DELIVERY_ALREADY_CLAIMED');
    const owned = await this.owner(walletId, accountId), now = Math.floor(Date.now() / 1000), simulation = proof.simulation;
    const payload = writeTransferOperationRecord(stored.operation, { network_id: owned.network_id, account: owned.address,
      account_id: owned.account_id, entry_point: stored.plan.entryPoint, userop_hash: stored.plan.userOpHash,
      consent_digest: stored.candidate.digest, valid_until: stored.plan.validUntil });
    if (![proof.checked_at, proof.expires_at, proof.reservation_observed_at, simulation.observed_at, simulation.expires_at].every(Number.isSafeInteger)
      || now < proof.checked_at || now < proof.reservation_observed_at || now < simulation.observed_at || now >= proof.expires_at
      || proof.expires_at > Math.min(proof.checked_at + 5, proof.reservation_observed_at + 5, simulation.expires_at, stored.plan.validUntil)
      || simulation.expires_at > simulation.observed_at + 5 || this.identity.expiresAt <= now
      || proof.userop_hash !== stored.plan.userOpHash || proof.consent_digest !== stored.candidate.digest
      || simulation.userop_hash !== proof.userop_hash || simulation.consent_digest !== proof.consent_digest
      || simulation.operation_sha256 !== payload.digest || typeof proof.reservation_fingerprint !== 'string'
      || proof.reservation_fingerprint.length > 3500) throw new Error('TRANSFER_DELIVERY_PREFLIGHT_INVALID');
    const token = toHex(crypto.getRandomValues(new Uint8Array(32))), tokenDigest = deploymentDocumentDigest(token);
    const result = await this.db.prepare(`UPDATE transfer_nonce_reservations
      SET state = 'delivery_pending', delivery_token_sha256 = ?, delivery_started_at = ?, delivery_expires_at = ?
      WHERE id = ? AND wallet_id = ? AND wallet_account_id = ? AND state = 'held' AND expires_at > ?
        AND operation_sha256 = ? AND consent_digest = ? AND userop_hash = ?
        AND EXISTS (SELECT 1 FROM wallet_accounts a JOIN wallets w ON w.id = a.wallet_id
          JOIN users u ON u.id = w.user_id
          WHERE a.id = ? AND w.id = ? AND w.status = 'active' AND a.address = ? AND a.deployment_manifest_sha256 = ?
            AND ${AUTHORIZED_USER})
        AND ${BALANCE_FLOOR_CURRENT}
        AND COALESCE((SELECT group_concat(item, ',') FROM
          (SELECT id || ':' || funds_sha256 AS item FROM transfer_nonce_reservations
            WHERE wallet_account_id = ? AND (state = 'delivery_pending' OR (state = 'held' AND expires_at > ?)) ORDER BY id)), '') = ? RETURNING id`)
      .bind(tokenDigest, now, proof.expires_at, proof.operation_id, walletId, accountId, now, payload.digest, proof.consent_digest, proof.userop_hash,
        accountId, walletId, owned.address, owned.deployment_manifest_sha256, ...authorizationValues(this.identity),
        ...floorValues(accountId, stored.candidate.checkpoint),
        accountId, now, proof.reservation_fingerprint).first<{ id: string }>();
    // RETURNING identifies this row; meta.changes also counts the durable-job trigger.
    if (result?.id !== proof.operation_id) throw new Error('TRANSFER_DELIVERY_CONCURRENT_CHANGE');
    // If this recheck fails, keep the durable uncertainty marker. Never unclaim.
    const current = await this.owner(walletId, accountId), finished = Math.floor(Date.now() / 1000);
    if (JSON.stringify(current) !== JSON.stringify(owned) || finished < now || finished >= proof.expires_at || this.identity.expiresAt <= finished) {
      throw new Error('TRANSFER_DELIVERY_PREFLIGHT_EXPIRED');
    }
    return Object.freeze({ id: proof.operation_id, state: 'delivery_pending' as const, claim_token: token,
      claimed_at: now, expires_at: proof.expires_at, userop_hash: proof.userop_hash, send_enabled: false as const });
  }
  /** One-use dispatch boundary. Persist BEFORE external I/O. A lost response or
   * abort after this write is uncertain and cannot consume the same token again. */
  async consumeDelivery(walletId: ResourceId<'wallet'>, accountId: ResourceId<'walletAccount'>,
    id: ResourceId<'operation'>, token: Hex) {
    requireHash(token);
    const stored = await this.readOwned(walletId, accountId, id);
    if (stored.state !== 'delivery_pending') throw new Error('TRANSFER_DISPATCH_NOT_CLAIMED');
    const owned = await this.owner(walletId, accountId), now = Math.floor(Date.now() / 1000);
    if (now >= stored.plan.validUntil || now >= this.identity.expiresAt) throw new Error('TRANSFER_DISPATCH_EXPIRED');
    const digest = deploymentDocumentDigest(token);
    const results = await this.db.batch<Record<string, unknown>>([
      this.db.prepare(`UPDATE transfer_nonce_reservations SET delivery_dispatched_at = ?
        WHERE id = ? AND wallet_id = ? AND wallet_account_id = ? AND state = 'delivery_pending'
          AND delivery_token_sha256 = ? AND delivery_dispatched_at IS NULL
          AND delivery_started_at <= ? AND delivery_expires_at > ? AND expires_at > ?
          AND EXISTS (SELECT 1 FROM wallet_accounts a JOIN wallets w ON w.id = a.wallet_id
            JOIN users u ON u.id = w.user_id
            WHERE a.id = ? AND w.id = ? AND w.status = 'active' AND a.address = ? AND a.deployment_manifest_sha256 = ?
              AND ${AUTHORIZED_USER})
          AND ${BALANCE_FLOOR_CURRENT}`)
        .bind(now, id, walletId, accountId, digest, now, now, now, accountId, walletId, owned.address,
          owned.deployment_manifest_sha256, ...authorizationValues(this.identity),
          ...floorValues(accountId, stored.candidate.checkpoint)),
      this.db.prepare(`SELECT delivery_expires_at FROM transfer_nonce_reservations
        WHERE id = ? AND wallet_id = ? AND wallet_account_id = ? AND delivery_token_sha256 = ?`).bind(id, walletId, accountId, digest),
    ]);
    const expiry = results[1].results[0]?.delivery_expires_at;
    if (results.some(r => !r.success) || results[0].meta.changes !== 1 || typeof expiry !== 'number' || !Number.isSafeInteger(expiry)) {
      throw new Error('TRANSFER_DISPATCH_CONSUMED_OR_EXPIRED');
    }
    const current = await this.owner(walletId, accountId), finished = Math.floor(Date.now() / 1000);
    if (JSON.stringify(current) !== JSON.stringify(owned) || finished < now || finished >= expiry || finished >= this.identity.expiresAt) {
      throw new Error('TRANSFER_DISPATCH_EXPIRED');
    }
    return Object.freeze({ id, operation: stored.operation, entry_point: stored.plan.entryPoint,
      userop_hash: stored.plan.userOpHash, network_id: owned.network_id, dispatched_at: now, expires_at: expiry });
  }
  async reserve(walletAccountId: ResourceId<'walletAccount'>, authorization: Awaited<ReturnType<typeof authorizeTransferOperation>>,
    preparation?: { id: ResourceId<'operation'>; record_sha256: Hex }) {
    const a = structuredClone(authorization), draft = preparation ? structuredClone(preparation) : null;
    const accountId = parseResourceId('walletAccount', walletAccountId), walletId = parseResourceId('wallet', a.request.wallet_id);
    const owned = await this.owner(walletId, accountId);
    requireHash(a.digest); requireHash(a.userOpHash);
    const now = Math.floor(Date.now() / 1000);
    if (owned.account_id !== a.plan.accountId || getAddress(owned.address) !== a.account || owned.network_id !== a.request.network_id
      || owned.deployment_manifest_sha256 !== a.deployment_digest || a.operation.signature === '0x'
      || a.operation.nonce !== a.plan.nonce || a.operation.sender !== a.account || a.plan.userOpHash !== a.userOpHash
      || a.plan.nonce < 0n || a.plan.nonce >= (1n << 64n) || now < a.plan.validAfter || now >= a.plan.validUntil
      || this.identity.expiresAt <= now) throw new Error('TRANSFER_RESERVATION_INVALID');
    const binding = { network_id: a.request.network_id, account: a.account, account_id: a.plan.accountId,
      entry_point: a.plan.entryPoint, userop_hash: a.userOpHash, consent_digest: a.digest, valid_until: a.plan.validUntil };
    const payload = writeTransferOperationRecord(a.operation, binding);
    const review = writeTransferReview(a.consent_review);
    const verified = await readTransferReview(review.json, review.digest);
    if (draft) {
      parseResourceId('operation', draft.id); requireHash(draft.record_sha256);
      if (writeTransferDraft(verified.review).digest !== draft.record_sha256) throw new Error('TRANSFER_PREPARATION_CHANGED');
    }
    const checkDraft = async () => {
      if (!draft) return;
      const value = await this.database.withSession('first-primary').prepare(`SELECT t.id FROM transfer_preparations t
        JOIN wallets w ON w.id = t.wallet_id JOIN users u ON u.id = w.user_id
        WHERE t.id = ? AND t.wallet_id = ? AND t.wallet_account_id = ? AND t.consent_digest = ? AND t.review_sha256 = ?
          AND t.expires_at > ? AND ${AUTHORIZED_USER} AND u.auth_not_before <= t.authorized_auth_time`).bind(draft.id, walletId, accountId, a.digest, draft.record_sha256,
            Math.floor(Date.now() / 1000), ...authorizationValues(this.identity)).first();
      if (!value) throw new Error('TRANSFER_PREPARATION_CHANGED');
    };
    await checkDraft();
    if (verified.candidate.digest !== a.digest || verified.review.approved_at > now
      || verified.candidate.deployment_digest !== a.deployment_digest || verified.candidate.policy_hash !== a.policy_hash
      || JSON.stringify(verified.candidate.request) !== JSON.stringify(a.request)
      || JSON.stringify(verified.candidate.funding) !== JSON.stringify(a.funding)
      || writeTransferOperationRecord(verified.operation, binding).json !== payload.json) throw new Error('TRANSFER_REVIEW_INVALID');
    const funds = writeTransferFunds(a.funding_reservation, a.request.network_id);
    const assetFunds = funds.rows.find(row => row.asset_id === a.request.asset_id);
    const nativeFunds = funds.rows.find(row => row.asset_id.split('/')[1].startsWith('slip44:'));
    if (!assetFunds || !nativeFunds || funds.rows.length !== (assetFunds === nativeFunds ? 1 : 2)
      || nativeFunds.asset_id !== verified.review.context.native_asset_id
      || BigInt(assetFunds.observed_atomic) - BigInt(assetFunds.reserved_atomic) !== BigInt(verified.review.context.budget.asset_available_atomic)
      || BigInt(nativeFunds.observed_atomic) - BigInt(nativeFunds.reserved_atomic) !== BigInt(verified.review.context.budget.native_available_atomic)
      || assetFunds.debit_atomic !== a.funding.asset_debit_atomic
      || BigInt(nativeFunds.observed_atomic) - BigInt(nativeFunds.reserved_atomic) - BigInt(nativeFunds.debit_atomic)
        !== BigInt(a.funding.native_remaining_atomic)) throw new Error('TRANSFER_FUNDS_INVALID');
    const snapshot = await this.liveFunds(accountId, a.request.network_id, now);
    const existing = snapshot.rows.find(row => row.digest === a.digest);
    if (existing) {
      const stored = await this.readOwned(walletId, accountId, existing.id);
      if (stored.state !== 'held' || stored.plan.userOpHash !== a.userOpHash || stored.plan.validUntil !== a.plan.validUntil) {
        throw new Error('TRANSFER_RESERVATION_CONFLICT');
      }
      await checkDraft();
      return { id: existing.id, state: 'held' as const, expires_at: a.plan.validUntil, send_enabled: false as const };
    }
    if (snapshot.rows.length >= 32) throw new Error('TRANSFER_RESERVATION_CAPACITY');
    if (funds.rows.some(row => (snapshot.totals.get(row.asset_id) ?? 0n).toString() !== row.reserved_atomic)) {
      throw new Error('TRANSFER_FUNDS_CHANGED');
    }
    const id = createResourceId('operation');
    // The batch is atomic; a database error rolls back expiry and insertion together.
    // Only the same wallet account is touched by this request. A future sender
    // MUST transition to a different durable state before any external I/O;
    // this expiry path is exclusively for never-dispatched claims.
    const results = await this.db.batch<Record<string, unknown>>([
      this.db.prepare(`UPDATE transfer_nonce_reservations SET state = 'expired'
        WHERE wallet_account_id = ? AND state = 'held' AND expires_at <= ?`).bind(accountId, now),
      this.db.prepare(`INSERT INTO transfer_nonce_reservations
        (id,wallet_id,wallet_account_id,network_id,account_address,entry_point,nonce,consent_digest,userop_hash,
          deployment_manifest_sha256,operation_json,operation_sha256,review_json,review_sha256,funds_json,funds_sha256,authorized_auth_time,state,created_at,expires_at)
        SELECT ?,w.id,a.id,a.network_id,a.address,?,?,?,?,?,?,?,?,?,?,?,?, 'held',?,?
        FROM wallet_accounts a JOIN wallets w ON w.id = a.wallet_id
        JOIN users u ON u.id = w.user_id
        WHERE a.id = ? AND w.id = ? AND w.status = 'active' AND a.address = ? AND a.deployment_manifest_sha256 = ?
          AND ${AUTHORIZED_USER}
          AND (? IS NULL OR EXISTS (SELECT 1 FROM transfer_preparations t WHERE t.id = ? AND t.wallet_account_id = a.id AND t.wallet_id = w.id
            AND t.review_sha256 = ? AND t.consent_digest = ? AND t.expires_at > ? AND t.authorized_auth_time >= u.auth_not_before))
          AND ${BALANCE_FLOOR_CURRENT}
          AND COALESCE((SELECT group_concat(item, ',') FROM
            (SELECT id || ':' || funds_sha256 AS item FROM transfer_nonce_reservations
              WHERE wallet_account_id = ? AND (state = 'delivery_pending' OR (state = 'held' AND expires_at > ?)) ORDER BY id)), '') = ?
        ON CONFLICT DO NOTHING`).bind(id, a.plan.entryPoint.toLowerCase(), a.plan.nonce.toString(), a.digest, a.userOpHash,
          a.deployment_digest, payload.json, payload.digest, review.json, review.digest, funds.json, funds.digest, this.identity.authTime, now, a.plan.validUntil,
          accountId, walletId, a.account.toLowerCase(), a.deployment_digest, ...authorizationValues(this.identity),
          draft?.id ?? null, draft?.id ?? null, draft?.record_sha256 ?? null, a.digest, now,
          ...floorValues(accountId, a.checkpoint),
          accountId, now, snapshot.fingerprint),
      this.db.prepare(`SELECT id,state,expires_at,userop_hash,deployment_manifest_sha256,operation_json,operation_sha256 FROM transfer_nonce_reservations
        WHERE wallet_account_id = ? AND consent_digest = ?`).bind(accountId, a.digest),
    ]);
    if (results.some(r => !r.success)) throw new Error('TRANSFER_RESERVATION_FAILED');
    // Recheck session/ownership after a concurrent revocation before exposing even a claim locator.
    const current = await this.owner(walletId, accountId);
    const finishedAt = Math.floor(Date.now() / 1000);
    if (JSON.stringify(current) !== JSON.stringify(owned) || finishedAt < now || finishedAt >= a.plan.validUntil
      || this.identity.expiresAt <= finishedAt) throw new Error('TRANSFER_RESERVATION_INVALID');
    const row = results[2].results[0];
    if (!row) throw new Error('TRANSFER_RESERVATION_CONCURRENT_CHANGE');
    if (row.userop_hash !== a.userOpHash || row.expires_at !== a.plan.validUntil || row.state !== 'held'
      || row.deployment_manifest_sha256 !== a.deployment_digest) throw new Error('TRANSFER_RESERVATION_CONFLICT');
    // A separately produced valid assertion for the same consent must not replace
    // the first stored signature. Restore the original bytes on every retry.
    readTransferOperationRecord(row.operation_json, row.operation_sha256, binding);
    await checkDraft();
    return { id: parseResourceId('operation', row.id), state: 'held' as const, expires_at: a.plan.validUntil, send_enabled: false as const };
  }

  /** Private, owned restoration. No HTTP serialization and no dispatch authority.
   * Historical expiry is returned as state, never silently extended by a read.
   */
  async findOwnedByConsent(walletId: ResourceId<'wallet'>, accountId: ResourceId<'walletAccount'>, digest: Hex) {
    requireHash(digest);
    await this.owner(walletId, accountId);
    const row = await this.database.withSession('first-primary').prepare(
      'SELECT id FROM transfer_nonce_reservations WHERE wallet_id = ? AND wallet_account_id = ? AND consent_digest = ?')
      .bind(walletId, accountId, digest).first();
    if (!row) return null;
    const stored = await this.readOwned(walletId, accountId, parseResourceId('operation', row.id));
    if (stored.candidate.digest !== digest) throw new Error('TRANSFER_RESERVATION_INVALID');
    return stored;
  }
  async readOwned(walletId: ResourceId<'wallet'>, accountId: ResourceId<'walletAccount'>, id: ResourceId<'operation'>) {
    parseResourceId('operation', id);
    parseResourceId('wallet', walletId); parseResourceId('walletAccount', accountId);
    const owned = await this.owner(walletId, accountId);
    const row = await this.db.prepare(`SELECT * FROM transfer_nonce_reservations
      WHERE id = ? AND wallet_id = ? AND wallet_account_id = ?`).bind(id, walletId, accountId).first();
    if (!row) throw new Error('TRANSFER_RESERVATION_NOT_FOUND');
    requireHash(row.userop_hash); requireHash(row.consent_digest);
    if (row.network_id !== owned.network_id || row.account_address !== owned.address
      || row.deployment_manifest_sha256 !== owned.deployment_manifest_sha256 || typeof row.entry_point !== 'string'
      || typeof row.expires_at !== 'number' || !Number.isSafeInteger(row.expires_at)
      || !['held', 'expired', 'delivery_pending', 'reconciled'].includes(String(row.state))) throw new Error('TRANSFER_RESERVATION_INVALID');
    const restored = readTransferOperationRecord(row.operation_json, row.operation_sha256, {
      network_id: owned.network_id, account: owned.address, account_id: owned.account_id, entry_point: row.entry_point,
      userop_hash: row.userop_hash, consent_digest: row.consent_digest, valid_until: row.expires_at,
    });
    if (restored.operation.nonce.toString() !== row.nonce) throw new Error('TRANSFER_RESERVATION_INVALID');
    const funds = readTransferFunds(row.funds_json, row.funds_sha256, owned.network_id);
    const verified = await readTransferReview(row.review_json, row.review_sha256);
    if (verified.candidate.digest !== row.consent_digest || verified.review.request.wallet_id !== walletId
      || verified.candidate.deployment_digest !== row.deployment_manifest_sha256
      || writeTransferOperationRecord(verified.operation, { network_id: owned.network_id, account: owned.address,
        account_id: owned.account_id, entry_point: row.entry_point, userop_hash: row.userop_hash,
        consent_digest: row.consent_digest, valid_until: row.expires_at }).json !== row.operation_json) throw new Error('TRANSFER_REVIEW_INVALID');
    const context = verified.review.context, candidate = verified.candidate;
    for (const term of funds) {
      const isAsset = term.asset_id === candidate.request.asset_id;
      if (!isAsset && term.asset_id !== context.native_asset_id) throw new Error('TRANSFER_FUNDS_INVALID');
      const available = isAsset ? context.budget.asset_available_atomic : context.budget.native_available_atomic;
      const debit = isAsset ? candidate.funding.asset_debit_atomic
        : (BigInt(context.budget.native_available_atomic) - BigInt(candidate.funding.native_remaining_atomic)).toString();
      if (BigInt(term.observed_atomic) - BigInt(term.reserved_atomic) !== BigInt(available) || term.debit_atomic !== debit) {
        throw new Error('TRANSFER_FUNDS_INVALID');
      }
    }
    if (funds.length !== new Set([candidate.request.asset_id, context.native_asset_id]).size) throw new Error('TRANSFER_FUNDS_INVALID');
    const current = await this.owner(walletId, accountId);
    if (JSON.stringify(current) !== JSON.stringify(owned)) throw new Error('TRANSFER_RESERVATION_INVALID');
    return Object.freeze({ id, state: row.state === 'reconciled' ? 'reconciled' as const : row.state === 'delivery_pending' ? 'delivery_pending' as const
      : row.state === 'expired' || row.expires_at <= Math.floor(Date.now() / 1000) ? 'expired' as const : 'held' as const,
      ...restored, candidate, review: verified.review, funds: Object.freeze(funds.map(row => Object.freeze(row))), send_enabled: false as const });
  }
}
