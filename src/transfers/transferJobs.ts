import type { Environment } from '@gatopago/environment';
import {
  deploymentDocumentDigest,
  loadPinnedDeploymentManifest,
  requireHash,
} from '@gatopago/shared/v3/deployment';
import { deriveAccountId } from '@gatopago/shared/v3/authorizations';
import { createResourceId, parseResourceId, type ResourceId } from '@gatopago/shared/v3/primitives';
import { readTransferReview } from '@gatopago/shared/v3/transfer-review-record';
import { writeTransferOperationRecord } from './transferOperationRecord';
import { readTransferFunds } from './transferFundsRecord';

export interface TransferWake {
  readonly schema_version: 1;
  readonly kind: 'transfer_observation';
  readonly operation_id: ResourceId<'operation'>;
  readonly token: ResourceId<'operation'>;
}
export function parseTransferWake(value: unknown): TransferWake {
  if (
    !value ||
    typeof value !== 'object' ||
    Array.isArray(value) ||
    Object.keys(value).length !== 4 ||
    Reflect.get(value, 'schema_version') !== 1 ||
    Reflect.get(value, 'kind') !== 'transfer_observation'
  ) {
    throw new Error('INVALID_TRANSFER_WAKE');
  }
  return Object.freeze({
    schema_version: 1,
    kind: 'transfer_observation',
    operation_id: parseResourceId('operation', Reflect.get(value, 'operation_id')),
    token: parseResourceId('operation', Reflect.get(value, 'token')),
  });
}
export interface TransferJobScope {
  readonly environment: Environment['environment'];
  readonly profiles: readonly { readonly document: string; readonly digest: `0x${string}` }[];
}
const changed = (result: D1Result) => {
  if (!result.success || ![0, 1].includes(result.meta.changes))
    throw new Error('TRANSFER_JOB_STORAGE');
  return result.meta.changes === 1;
};

export class TransferJobRepository {
  private readonly db: D1DatabaseSession;
  private readonly environment: Environment['environment'];
  private readonly pins: readonly string[];
  constructor(
    private readonly database: D1Database,
    configuration: TransferJobScope,
  ) {
    if (configuration.environment !== 'production' || configuration.profiles.length > 32) {
      throw new Error('TRANSFER_JOB_CONFIGURATION');
    }
    const pins = configuration.profiles.map((pin) => {
      loadPinnedDeploymentManifest(pin.document, pin.digest);
      return pin.digest;
    });
    if (new Set(pins).size !== pins.length) throw new Error('TRANSFER_JOB_CONFIGURATION');
    this.environment = configuration.environment;
    this.pins = Object.freeze(pins);
    this.db = database.withSession('first-primary');
  }
  private scope() {
    return `EXISTS (SELECT 1 FROM transfer_nonce_reservations r
      JOIN wallets w ON w.id = r.wallet_id JOIN users u ON u.id = w.user_id
      WHERE r.id = transfer_jobs.operation_id AND r.state = 'delivery_pending'
      AND u.environment = ? AND r.deployment_manifest_sha256 IN (${this.pins.map(() => '?').join(',')}))`;
  }

  async observationSource(input: TransferWake) {
    const message = parseTransferWake(input);
    if (!this.pins.length) throw new Error('TRANSFER_JOB_SCOPE');
    const read = () =>
      this.database
        .withSession('first-primary')
        .prepare(
          `SELECT r.*,
      c.account_id AS identity_account_id,c.initial_security_commitment,c.user_salt_commitment
      FROM transfer_jobs JOIN transfer_nonce_reservations r ON r.id = transfer_jobs.operation_id
      JOIN wallet_accounts a ON a.id = r.wallet_account_id AND a.wallet_id = r.wallet_id AND a.network_id = r.network_id
      JOIN wallets c ON c.id = r.wallet_id AND c.id = a.wallet_id AND c.canonical_address = r.account_address
      WHERE transfer_jobs.operation_id = ? AND transfer_jobs.lease_token = ? AND transfer_jobs.state = 'running'
      AND transfer_jobs.lease_expires_at > unixepoch() AND ${this.scope()}`,
        )
        .bind(message.operation_id, message.token, this.environment, ...this.pins)
        .first();
    const row = await read();
    if (!row) throw new Error('TRANSFER_JOB_LEASE_LOST');
    if (
      typeof row.delivery_started_at !== 'number' ||
      !Number.isSafeInteger(row.delivery_started_at) ||
      row.delivery_started_at <= 0
    )
      throw new Error('TRANSFER_JOB_RECORD');
    requireHash(row.identity_account_id);
    requireHash(row.initial_security_commitment);
    requireHash(row.user_salt_commitment);
    if (
      deriveAccountId(row.initial_security_commitment, row.user_salt_commitment) !==
      row.identity_account_id
    )
      throw new Error('TRANSFER_JOB_RECORD');
    const record = await readTransferReview(row.review_json, row.review_sha256),
      candidate = record.candidate;
    if (
      candidate.request.wallet_id !== row.wallet_id ||
      candidate.request.network_id !== row.network_id ||
      candidate.account.toLowerCase() !== row.account_address ||
      candidate.plan.accountId !== row.identity_account_id ||
      candidate.deployment_digest !== row.deployment_manifest_sha256 ||
      candidate.userOpHash !== row.userop_hash ||
      candidate.digest !== row.consent_digest ||
      candidate.operation.nonce.toString() !== row.nonce ||
      candidate.plan.validUntil !== row.expires_at
    )
      throw new Error('TRANSFER_JOB_RECORD');
    const operation = writeTransferOperationRecord(record.operation, {
      network_id: candidate.request.network_id,
      account: candidate.account,
      account_id: candidate.plan.accountId,
      entry_point: candidate.plan.entryPoint,
      userop_hash: candidate.userOpHash,
      consent_digest: candidate.digest,
      valid_until: candidate.plan.validUntil,
    });
    if (
      operation.json !== row.operation_json ||
      operation.digest !== row.operation_sha256 ||
      JSON.stringify(await read()) !== JSON.stringify(row)
    )
      throw new Error('TRANSFER_JOB_RECORD');
    const funds = readTransferFunds(row.funds_json, row.funds_sha256, candidate.request.network_id);
    const assetIds = new Set([candidate.request.asset_id, record.review.context.native_asset_id]);
    if (funds.length !== assetIds.size || funds.some((term) => !assetIds.has(term.asset_id)))
      throw new Error('TRANSFER_JOB_FUNDS');
    return Object.freeze({
      record,
      startedAt: row.delivery_started_at,
      walletAccountId: parseResourceId('walletAccount', row.wallet_account_id),
      funds,
      context: deploymentDocumentDigest(JSON.stringify(row)),
      initialSecurityCommitment: row.initial_security_commitment,
      userSaltCommitment: row.user_salt_commitment,
    });
  }
  async due(limit = 20) {
    if (!Number.isSafeInteger(limit) || limit < 1 || limit > 50)
      throw new Error('INVALID_TRANSFER_SWEEP');
    if (!this.pins.length) return [];
    const result = await this.db
      .prepare(
        `SELECT operation_id FROM transfer_jobs WHERE state IN ('ready','queued','running')
      AND next_attempt_at <= unixepoch() AND (lease_expires_at IS NULL OR lease_expires_at <= unixepoch()) AND ${this.scope()}
      ORDER BY next_attempt_at,operation_id LIMIT ?`,
      )
      .bind(this.environment, ...this.pins, limit)
      .all<{ operation_id: string }>();
    if (!result.success) throw new Error('TRANSFER_JOB_STORAGE');
    return result.results.map((row) => parseResourceId('operation', row.operation_id));
  }
  async reserve(id: ResourceId<'operation'>): Promise<TransferWake | null> {
    parseResourceId('operation', id);
    if (!this.pins.length) return null;
    const token = createResourceId('operation');
    const result = await this.db
      .prepare(
        `UPDATE transfer_jobs SET state = 'queued',lease_token = ?,lease_expires_at = unixepoch() + 120
      WHERE operation_id = ? AND state IN ('ready','queued','running') AND next_attempt_at <= unixepoch()
      AND (lease_expires_at IS NULL OR lease_expires_at <= unixepoch()) AND ${this.scope()}`,
      )
      .bind(token, id, this.environment, ...this.pins)
      .run();
    return changed(result)
      ? Object.freeze({ schema_version: 1, kind: 'transfer_observation', operation_id: id, token })
      : null;
  }
  async claim(input: TransferWake) {
    const message = parseTransferWake(input);
    if (!this.pins.length) return false;
    return changed(
      await this.db
        .prepare(
          `UPDATE transfer_jobs SET state = 'running',lease_expires_at = unixepoch() + 180
      WHERE operation_id = ? AND lease_token = ? AND state = 'queued' AND lease_expires_at > unixepoch() AND ${this.scope()}`,
        )
        .bind(message.operation_id, message.token, this.environment, ...this.pins)
        .run(),
    );
  }
  async defer(input: TransferWake, seconds: number) {
    const message = parseTransferWake(input);
    if (!Number.isSafeInteger(seconds) || seconds < 5 || seconds > 3600)
      throw new Error('INVALID_TRANSFER_RETRY');
    if (!this.pins.length) return false;
    return changed(
      await this.db
        .prepare(
          `UPDATE transfer_jobs SET state = 'ready',next_attempt_at = unixepoch() + ?,
      failures = 0,lease_token = NULL,lease_expires_at = NULL WHERE operation_id = ? AND lease_token = ?
      AND state = 'running' AND lease_expires_at > unixepoch() AND ${this.scope()}`,
        )
        .bind(seconds, message.operation_id, message.token, this.environment, ...this.pins)
        .run(),
    );
  }
  async review(input: TransferWake, reason: 'observation_timeout' | 'conflicting_evidence') {
    const message = parseTransferWake(input);
    if (!['observation_timeout', 'conflicting_evidence'].includes(reason))
      throw new Error('INVALID_TRANSFER_REVIEW');
    if (!this.pins.length) return false;
    return changed(
      await this.db
        .prepare(
          `UPDATE transfer_jobs SET state = 'review',reason = ?,lease_token = NULL,lease_expires_at = NULL
      WHERE operation_id = ? AND lease_token = ? AND state = 'running' AND lease_expires_at > unixepoch() AND ${this.scope()}`,
        )
        .bind(reason, message.operation_id, message.token, this.environment, ...this.pins)
        .run(),
    );
  }
  async fail(input: TransferWake, state: 'queued' | 'running') {
    const message = parseTransferWake(input);
    if (!['queued', 'running'].includes(state)) throw new Error('INVALID_TRANSFER_JOB_STATE');
    if (!this.pins.length) return false;
    return changed(
      await this.db
        .prepare(
          `UPDATE transfer_jobs SET state = CASE WHEN failures >= 7 THEN 'review' ELSE 'ready' END,
      reason = CASE WHEN failures >= 7 THEN 'processing_error' ELSE NULL END,
      next_attempt_at = unixepoch() + min(3600,30 * (1 << failures)),failures = min(8,failures + 1),lease_token = NULL,lease_expires_at = NULL
      WHERE operation_id = ? AND lease_token = ? AND state = ? AND lease_expires_at > unixepoch() AND ${this.scope()}`,
        )
        .bind(message.operation_id, message.token, state, this.environment, ...this.pins)
        .run(),
    );
  }
}
