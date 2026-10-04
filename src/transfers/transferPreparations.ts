import { AUTHORIZED_USER, authorizationValues } from '../auth/authorization';
import { isAddressEqual, type Hex } from 'viem';
import { requireHash } from '@gatopago/shared/v3/deployment';
import { createResourceId, parseResourceId, type ResourceId } from '@gatopago/shared/v3/primitives';
import { assertTransferBalance } from '@gatopago/shared/v3/transfer-balance';
import { assertTransferSecurity } from '@gatopago/shared/v3/transfer-security';
import { assertWebAuthnScope, type WebAuthnScope } from '@gatopago/shared/v3/webauthn';
import type { Principal } from '../auth/principal';
import { WalletRepository } from '../accounts/repository';
import type { prepareOwnedTransfer } from './transferPreparation';
import { readTransferDraft, writeTransferDraft } from '@gatopago/shared/v3/transfer-review-record';

/** Private durable unsigned reviews. Scope/pins come from current admission.
 * No HTTP object is proof of preparation. This repository never signs, reserves
 * a nonce or broadcasts. At confirmation, retrieve this exact review and collect
 * independent live evidence; never accept a replacement context from the client. */
export class TransferPreparationRepository {
  private readonly identity: Principal;
  private readonly scope: WebAuthnScope;
  private readonly digests: readonly Hex[];
  constructor(
    private readonly database: D1Database,
    identity: Principal,
    scope: WebAuthnScope,
    digests: readonly Hex[],
  ) {
    this.identity = Object.freeze({ ...identity });
    this.scope = Object.freeze({ ...scope });
    this.digests = Object.freeze([...digests]);
    assertWebAuthnScope(this.scope);
    if (digests.length > 32 || new Set(digests).size !== digests.length)
      throw new Error('TRANSFER_PREPARATION_PROFILE');
    digests.forEach(requireHash);
  }
  private owner(walletId: ResourceId<'wallet'>, accountId: ResourceId<'walletAccount'>) {
    return new WalletRepository(this.database, this.identity).ownedAccount(walletId, accountId);
  }
  private validate(
    record: ReturnType<typeof readTransferDraft>,
    owned: Awaited<ReturnType<WalletRepository['ownedAccount']>>,
  ) {
    const { candidate: c, review: r } = record,
      now = Math.floor(Date.now() / 1000);
    if (
      !this.digests.includes(c.deployment_digest) ||
      owned.deployment_manifest_sha256 !== c.deployment_digest ||
      owned.network_id !== c.request.network_id ||
      owned.account_id !== c.plan.accountId ||
      !isAddressEqual(owned.address, c.account) ||
      r.scope.origin !== this.scope.origin ||
      r.scope.rpId !== this.scope.rpId
    )
      throw new Error('TRANSFER_PREPARATION_CONTEXT');
    if (now < r.prepared_at || now >= c.plan.validUntil || this.identity.expiresAt <= now)
      throw new Error('TRANSFER_PREPARATION_EXPIRED');
  }
  async save(input: Awaited<ReturnType<typeof prepareOwnedTransfer>>) {
    const p = structuredClone(input),
      accountId = parseResourceId('walletAccount', p.wallet_account_id);
    const walletId = p.candidate.request.wallet_id;
    const owned = await this.owner(walletId, accountId);
    const encoded = writeTransferDraft({
      request: p.candidate.request,
      context: p.context,
      policy: p.approval.policy,
      scope: p.approval.scope,
      prepared_at: p.approval.prepared_at,
    });
    const record = readTransferDraft(encoded.json, encoded.digest),
      c = record.candidate;
    this.validate(record, owned);
    const now = Math.floor(Date.now() / 1000),
      n = p.approval.nonce_evidence;
    if (
      c.digest !== p.candidate.digest ||
      c.digest !== p.approval.reviewed_digest ||
      p.send_enabled !== false ||
      n.network_id !== c.request.network_id ||
      !isAddressEqual(n.account, c.account) ||
      !isAddressEqual(n.entry_point, c.plan.entryPoint) ||
      n.nonce !== c.plan.nonce.toString() ||
      n.checkpoint.block_number !== c.checkpoint.block_number ||
      n.checkpoint.block_hash !== c.checkpoint.block_hash ||
      !Number.isSafeInteger(n.observed_at) ||
      n.observed_at > now ||
      n.observed_at < now - 60
    )
      throw new Error('TRANSFER_PREPARATION_INVALID');
    assertTransferSecurity(c, p.approval.security_evidence, now);
    assertTransferBalance(
      c,
      p.context,
      p.approval.balance_evidence,
      p.approval.security_evidence.finality,
      now,
    );
    const id = createResourceId('operation'),
      db = this.database.withSession('first-primary');
    const results = await db.batch<Record<string, unknown>>([
      db
        .prepare(
          'DELETE FROM transfer_preparations WHERE wallet_account_id = ? AND expires_at <= ?',
        )
        .bind(accountId, now),
      db
        .prepare(
          `INSERT INTO transfer_preparations
        (id,wallet_id,wallet_account_id,consent_digest,deployment_manifest_sha256,review_json,review_sha256,authorized_auth_time,created_at,expires_at)
        SELECT ?,w.id,a.id,?,?,?,?,?,?,? FROM wallet_accounts a JOIN wallets w ON w.id = a.wallet_id
        JOIN users u ON u.id = w.user_id
        WHERE a.id = ? AND w.id = ? AND w.status = 'active'
          AND a.deployment_state NOT IN ('unsupported','retired') AND a.address = ? AND a.deployment_manifest_sha256 = ?
          AND ${AUTHORIZED_USER}
          AND (SELECT count(*) FROM transfer_preparations WHERE wallet_account_id = ? AND expires_at > ?) < 16
        ON CONFLICT DO NOTHING`,
        )
        .bind(
          id,
          c.digest,
          c.deployment_digest,
          encoded.json,
          encoded.digest,
          this.identity.authTime,
          p.approval.prepared_at,
          c.plan.validUntil,
          accountId,
          walletId,
          owned.address,
          c.deployment_digest,
          ...authorizationValues(this.identity),
          accountId,
          now,
        ),
      db
        .prepare(
          'SELECT id FROM transfer_preparations WHERE wallet_account_id = ? AND consent_digest = ?',
        )
        .bind(accountId, c.digest),
    ]);
    if (results.some((r) => !r.success)) throw new Error('TRANSFER_PREPARATION_STORAGE');
    const selected = results[2].results[0];
    if (!selected) throw new Error('TRANSFER_PREPARATION_CAPACITY_OR_CHANGED');
    const result = await this.readOwned(
      walletId,
      accountId,
      parseResourceId('operation', selected.id),
    );
    if (
      result.record_sha256 !== encoded.digest ||
      JSON.stringify(await this.owner(walletId, accountId)) !== JSON.stringify(owned)
    ) {
      throw new Error('TRANSFER_PREPARATION_CHANGED');
    }
    return result;
  }
  async readOwned(
    walletId: ResourceId<'wallet'>,
    accountId: ResourceId<'walletAccount'>,
    id: ResourceId<'operation'>,
  ) {
    parseResourceId('operation', id);
    parseResourceId('wallet', walletId);
    parseResourceId('walletAccount', accountId);
    const owned = await this.owner(walletId, accountId);
    const readRow = () =>
      this.database
        .withSession('first-primary')
        .prepare(
          `SELECT r.* FROM transfer_preparations r
      JOIN wallets w ON w.id = r.wallet_id JOIN users u ON u.id = w.user_id
      WHERE r.id = ? AND r.wallet_id = ? AND r.wallet_account_id = ? AND ${AUTHORIZED_USER} AND u.auth_not_before <= r.authorized_auth_time`,
        )
        .bind(id, walletId, accountId, ...authorizationValues(this.identity))
        .first();
    const row = await readRow();
    if (!row) throw new Error('TRANSFER_PREPARATION_NOT_FOUND');
    const record = readTransferDraft(row.review_json, row.review_sha256);
    requireHash(row.review_sha256);
    this.validate(record, owned);
    if (
      record.candidate.request.wallet_id !== walletId ||
      record.candidate.digest !== row.consent_digest ||
      record.candidate.deployment_digest !== row.deployment_manifest_sha256 ||
      record.review.prepared_at !== row.created_at ||
      record.candidate.plan.validUntil !== row.expires_at
    )
      throw new Error('TRANSFER_PREPARATION_INVALID');
    const current = await this.owner(walletId, accountId);
    // A newer login may remain valid while the earlier preparation's authTime
    // is revoked. Checking the current owner alone would miss that transition.
    if (
      JSON.stringify(current) !== JSON.stringify(owned) ||
      JSON.stringify(await readRow()) !== JSON.stringify(row)
    ) {
      throw new Error('TRANSFER_PREPARATION_CHANGED');
    }
    this.validate(record, current);
    return Object.freeze({
      id,
      wallet_account_id: accountId,
      ...record,
      record_sha256: row.review_sha256,
      send_enabled: false as const,
    });
  }
}
