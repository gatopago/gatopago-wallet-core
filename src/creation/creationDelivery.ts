import type { Environment } from '@gatopago/environment';
import type { Hex } from 'viem';
import { loadPinnedCreationProfile } from '@gatopago/shared/v3/initialization';
import { createResourceId, parseResourceId, type ResourceId } from '@gatopago/shared/v3/primitives';
import { assertWebAuthnScope, type WebAuthnScope } from '@gatopago/shared/v3/webauthn';
import { writeAssertionRecord } from '@gatopago/shared/v3/assertion-record';
import { CreationOperationRepository } from './creationOperation';
import { creationOutboxColumns } from './creationOutbox';
import { InitializationRepository, type CreationProfilePin } from './initialization';
import { WalletAccessError } from '../accounts/repository';

type Row = Record<string, unknown>;
const nowSeconds = () => Math.floor(Date.now() / 1000);
const JOINS = `FROM account_creation_operations o JOIN account_initializations i ON i.id = o.initialization_id
	JOIN users u ON u.id = i.user_id JOIN webauthn_credentials c ON c.id = i.credential_ref AND c.user_id = u.id`;
const AUTHORIZED_SNAPSHOT = `EXISTS (SELECT 1 ${JOINS} WHERE o.initialization_id = account_creation_outbox.initialization_id
	AND o.user_op_hash = ? AND o.operation_digest = ? AND o.operation_signature = ? AND o.gas_terms_json = ?
	AND o.authorized_auth_time = ? AND i.assertion_body = ? AND i.approval_digest = ?
	AND c.public_key = i.public_key AND c.public_key = ? AND c.rp_id = ? AND c.origin = ?
	AND u.environment = ? AND u.disabled_at IS NULL AND u.auth_not_before <= ?)`;

export interface CreationDeliveryConfiguration {
  readonly environment: Environment['environment'];
  readonly scope: WebAuthnScope;
  readonly profiles: readonly CreationProfilePin[];
}
class DeliveryError extends Error {
  constructor(
    readonly code: 'CREATION_GRANT_REVOKED' | 'CREATION_LEASE_LOST' | 'PROVIDER_HASH_MISMATCH',
  ) {
    super(code);
    this.name = 'DeliveryError';
  }
}

/** Internal job authority is the stored, verified operation grant, never a fabricated
 * Firebase session or a JWT placed on a queue. Construction is not network admission.
 * Bind only to a private consumer/scheduler after environment/profile admission.
 */
export class CreationDeliveryRepository {
  private readonly db: D1DatabaseSession;
  private readonly configuration: CreationDeliveryConfiguration;
  constructor(database: D1Database, configuration: CreationDeliveryConfiguration) {
    assertWebAuthnScope(configuration.scope);
    if (configuration.environment !== 'production' || configuration.profiles.length > 32)
      throw new Error('Invalid delivery configuration');
    const profiles = configuration.profiles.map((pin) => {
      loadPinnedCreationProfile(pin.document, pin.digest);
      return Object.freeze({ document: pin.document, digest: pin.digest });
    });
    if (new Set(profiles.map((pin) => pin.digest)).size !== profiles.length)
      throw new Error('Duplicate delivery profile');
    this.configuration = Object.freeze({
      environment: configuration.environment,
      scope: Object.freeze({ ...configuration.scope }),
      profiles: Object.freeze(profiles),
    });
    this.db = database.withSession('first-primary');
  }
  private async load(id: ResourceId<'operation'>) {
    parseResourceId('operation', id);
    const results = await this.db.batch<Row>([
      this.db
        .prepare(
          `SELECT i.*, c.public_key AS current_key, c.rp_id, c.origin,
				u.environment AS owner_environment, u.disabled_at AS owner_disabled, u.auth_not_before AS auth_cutoff
				${JOINS} WHERE i.id = ?`,
        )
        .bind(id),
      this.db
        .prepare(
          `SELECT o.*, ${creationOutboxColumns} ${JOINS}
				LEFT JOIN account_creation_outbox b ON b.initialization_id = o.initialization_id WHERE i.id = ?`,
        )
        .bind(id),
    ]);
    if (results.length !== 2 || results.some((r) => !r.success || r.results.length > 1))
      throw new WalletAccessError('WALLET_DATA_INVALID');
    const row = results[0].results[0];
    if (!row || !results[1].results[0]) throw new WalletAccessError('NOT_FOUND');
    const initial = InitializationRepository.restoreRecord(
      row,
      this.configuration.scope,
      this.configuration.profiles,
    );
    if (initial.authorizedAt === null || !initial.initialProof)
      throw new WalletAccessError('WALLET_DATA_INVALID');
    const operation = CreationOperationRepository.restoreRecord(results[1].results[0], {
      input: initial.input,
      initialProof: initial.initialProof,
      authorizedAt: initial.authorizedAt,
    });
    if (
      !operation.signed ||
      !operation.delivery ||
      typeof operation.authTime !== 'number' ||
      typeof row.auth_cutoff !== 'number' ||
      !Number.isSafeInteger(row.auth_cutoff) ||
      row.auth_cutoff < 0 ||
      (row.owner_disabled !== null &&
        (typeof row.owner_disabled !== 'number' || !Number.isSafeInteger(row.owner_disabled)))
    )
      throw new WalletAccessError('WALLET_DATA_INVALID');
    return {
      id,
      initial,
      operation,
      signed: operation.signed,
      delivery: operation.delivery,
      authTime: operation.authTime,
      environmentMatches: row.owner_environment === this.configuration.environment,
      revoked:
        row.owner_disabled !== null ||
        row.owner_environment !== this.configuration.environment ||
        row.auth_cutoff > operation.authTime,
    };
  }
  /** Read-only reconciliation must continue after grant expiry/session revocation: a
   * previously sent operation can still have an economic outcome. Never grants a send. */
  async observationGrant(id: ResourceId<'operation'>) {
    const record = await this.load(id);
    if (!record.environmentMatches) throw new WalletAccessError('NOT_FOUND');
    if (!['sending', 'uncertain', 'accepted'].includes(record.delivery.state)) return null;
    return Object.freeze({ id, signed: record.signed });
  }
  private guard(record: Awaited<ReturnType<CreationDeliveryRepository['load']>>) {
    return [
      record.signed.userOpHash,
      record.signed.digest,
      record.signed.operation.signature,
      record.operation.gasJson,
      record.authTime,
      writeAssertionRecord(record.initial.initialProof!),
      record.signed.prepared.digest,
      record.initial.input.publicKey,
      this.configuration.scope.rpId,
      this.configuration.scope.origin,
      this.configuration.environment,
      record.authTime,
    ] as const;
  }
  /** Bounded sweep catches missed wake-ups; it returns identifiers, not JWTs or signatures. */
  async due(limit = 20) {
    if (!Number.isSafeInteger(limit) || limit < 1 || limit > 50)
      throw new Error('Invalid sweep limit');
    const now = nowSeconds();
    const rows = await this.db
      .prepare(
        `SELECT b.initialization_id FROM account_creation_outbox b
			JOIN account_initializations i ON i.id = b.initialization_id JOIN users u ON u.id = i.user_id
			WHERE u.environment = ? AND ((b.state = 'pending' AND (b.expires_at <= ? OR (b.attempt_count < 32 AND b.next_attempt_at <= ?))
			AND (b.lease_expires_at IS NULL OR b.lease_expires_at <= ?))
			OR (b.state = 'sending' AND b.lease_expires_at <= ?)) ORDER BY b.initialization_id LIMIT ?`,
      )
      .bind(this.configuration.environment, now, now, now, now, limit)
      .all<Row>();
    if (!rows.success) throw new WalletAccessError('WALLET_DATA_INVALID');
    return rows.results.map((row) => parseResourceId('operation', row.initialization_id));
  }
  async claim(id: ResourceId<'operation'>) {
    const record = await this.load(id),
      now = nowSeconds(),
      delivery = record.delivery;
    // A crash after the send marker is ambiguous even if the HTTP call never happened.
    // Never turn this back into pending: reconciliation, not automatic rebroadcast, follows.
    if (
      delivery.state === 'sending' &&
      typeof delivery.until === 'number' &&
      delivery.until <= now
    ) {
      const result = await this.db
        .prepare(
          `UPDATE account_creation_outbox SET state = 'uncertain', lease_token = NULL, lease_expires_at = NULL
				WHERE initialization_id = ? AND state = 'sending' AND lease_token = ? AND lease_expires_at <= ?`,
        )
        .bind(id, delivery.token, now)
        .run();
      if (!result.success || ![0, 1].includes(result.meta.changes))
        throw new WalletAccessError('WALLET_DATA_INVALID');
      return null;
    }
    if (delivery.state !== 'pending') return null;
    if (record.operation.expiresAt <= now) {
      const result = await this.db
        .prepare(
          `UPDATE account_creation_outbox SET state = 'expired', lease_token = NULL, lease_expires_at = NULL
				WHERE initialization_id = ? AND state = 'pending' AND expires_at <= ?`,
        )
        .bind(id, now)
        .run();
      if (!result.success || ![0, 1].includes(result.meta.changes))
        throw new WalletAccessError('WALLET_DATA_INVALID');
      return null;
    }
    if (record.revoked) throw new DeliveryError('CREATION_GRANT_REVOKED');
    if (
      delivery.attempts >= 32 ||
      delivery.next > now ||
      (typeof delivery.until === 'number' && delivery.until > now)
    )
      return null;
    const token = createResourceId('operation'),
      until = Math.min(now + 45, record.operation.expiresAt);
    const result = await this.db
      .prepare(
        `UPDATE account_creation_outbox
			SET lease_token = ?, lease_expires_at = ?, attempt_count = attempt_count + 1
			WHERE initialization_id = ? AND state = 'pending' AND expires_at > ? AND next_attempt_at <= ? AND attempt_count < 32
			AND (lease_expires_at IS NULL OR lease_expires_at <= ?) AND ${AUTHORIZED_SNAPSHOT}`,
      )
      .bind(token, until, id, now, now, now, ...this.guard(record))
      .run();
    if (!result.success || ![0, 1].includes(result.meta.changes))
      throw new WalletAccessError('WALLET_DATA_INVALID');
    if (result.meta.changes === 0) return null;
    const latest = await this.load(id);
    if (latest.revoked || latest.delivery.token !== token || latest.delivery.until !== until)
      throw new DeliveryError('CREATION_LEASE_LOST');
    return Object.freeze({ id, token, until, record: latest });
  }
  async beginSend(claim: NonNullable<Awaited<ReturnType<CreationDeliveryRepository['claim']>>>) {
    const now = nowSeconds();
    const result = await this.db
      .prepare(
        `UPDATE account_creation_outbox SET state = 'sending', send_started_at = ?
			WHERE initialization_id = ? AND lease_token = ? AND state = 'pending' AND lease_expires_at > ? AND expires_at > ?
			AND ${AUTHORIZED_SNAPSHOT}`,
      )
      .bind(now, claim.id, claim.token, now, now, ...this.guard(claim.record))
      .run();
    if (!result.success || ![0, 1].includes(result.meta.changes))
      throw new WalletAccessError('WALLET_DATA_INVALID');
    return result.meta.changes === 1;
  }
  async retryBeforeSend(
    claim: NonNullable<Awaited<ReturnType<CreationDeliveryRepository['claim']>>>,
  ) {
    const next = nowSeconds() + Math.min(30, 2 ** Math.min(claim.record.delivery.attempts, 5));
    const result = await this.db
      .prepare(
        `UPDATE account_creation_outbox SET lease_token = NULL, lease_expires_at = NULL, next_attempt_at = ?
			WHERE initialization_id = ? AND state = 'pending' AND lease_token = ?`,
      )
      .bind(next, claim.id, claim.token)
      .run();
    if (!result.success || ![0, 1].includes(result.meta.changes))
      throw new WalletAccessError('WALLET_DATA_INVALID');
    return result.meta.changes === 1;
  }
  async uncertain(claim: NonNullable<Awaited<ReturnType<CreationDeliveryRepository['claim']>>>) {
    const result = await this.db
      .prepare(
        `UPDATE account_creation_outbox SET state = 'uncertain', lease_token = NULL, lease_expires_at = NULL
			WHERE initialization_id = ? AND state = 'sending' AND lease_token = ?`,
      )
      .bind(claim.id, claim.token)
      .run();
    if (!result.success || ![0, 1].includes(result.meta.changes))
      throw new WalletAccessError('WALLET_DATA_INVALID');
    return result.meta.changes === 1;
  }
  async accepted(
    claim: NonNullable<Awaited<ReturnType<CreationDeliveryRepository['claim']>>>,
    returnedHash: Hex,
  ) {
    if (returnedHash !== claim.record.signed.userOpHash)
      throw new DeliveryError('PROVIDER_HASH_MISMATCH');
    const now = nowSeconds();
    const result = await this.db
      .prepare(
        `UPDATE account_creation_outbox SET state = 'accepted', accepted_at = ?, lease_token = NULL, lease_expires_at = NULL
			WHERE initialization_id = ? AND state = 'sending' AND lease_token = ? AND lease_expires_at > ? AND user_op_hash = ?`,
      )
      .bind(now, claim.id, claim.token, now, returnedHash)
      .run();
    if (!result.success || ![0, 1].includes(result.meta.changes))
      throw new WalletAccessError('WALLET_DATA_INVALID');
    return result.meta.changes === 1;
  }
}
