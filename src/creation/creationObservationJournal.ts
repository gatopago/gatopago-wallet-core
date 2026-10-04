import type { Environment } from '@gatopago/environment';
import type { Hex } from 'viem';
import { deploymentDocumentDigest, requireHash } from '@gatopago/shared/v3/deployment';
import { assertResult, resultJson } from './creationObservationRecord';
import { createResourceId, parseResourceId, type ResourceId } from '@gatopago/shared/v3/primitives';
import { CreationDeliveryRepository, type CreationDeliveryConfiguration } from './creationDelivery';
import type { reconcileCreationObservation } from './creationObservation';
import { WalletAccessError } from '../accounts/repository';

type Result = Awaited<ReturnType<typeof reconcileCreationObservation>>;
type Row = Record<string, unknown>;
const nowSeconds = () => Math.floor(Date.now() / 1000);
const invalid = () => new WalletAccessError('WALLET_DATA_INVALID');
function integer(value: unknown): number {
  if (typeof value !== 'number' || !Number.isSafeInteger(value) || value < 0) throw invalid();
  return value;
}
function changed(result: D1Result): number {
  if (!result.success || ![0, 1].includes(result.meta.changes)) throw invalid();
  return result.meta.changes;
}

export class CreationObservationJournal {
  private readonly db: D1DatabaseSession;
  private readonly grants: CreationDeliveryRepository;
  private readonly environment: Environment['environment'];
  constructor(database: D1Database, configuration: CreationDeliveryConfiguration) {
    this.grants = new CreationDeliveryRepository(database, configuration);
    this.environment = configuration.environment;
    this.db = database.withSession('first-primary');
  }

  async due(limit = 20) {
    if (!Number.isSafeInteger(limit) || limit < 1 || limit > 50)
      throw new Error('Invalid observation sweep limit');
    const now = nowSeconds();
    const result = await this.db
      .prepare(
        `SELECT b.initialization_id FROM account_creation_outbox b
			JOIN account_initializations i ON i.id = b.initialization_id JOIN users u ON u.id = i.user_id
			LEFT JOIN account_creation_observation_jobs j ON j.initialization_id = b.initialization_id
			WHERE u.environment = ? AND b.state IN ('sending','uncertain','accepted')
			AND NOT EXISTS (SELECT 1 FROM account_creation_projections x WHERE x.initialization_id = b.initialization_id)
			AND (j.initialization_id IS NULL OR (j.next_poll_at <= ? AND (j.lease_token IS NULL OR j.lease_expires_at <= ?)))
			ORDER BY COALESCE(j.next_poll_at, 0), b.initialization_id LIMIT ?`,
      )
      .bind(this.environment, now, now, limit)
      .all<Row>();
    if (!result.success) throw invalid();
    return result.results.map((row) => parseResourceId('operation', row.initialization_id));
  }
  async claim(id: ResourceId<'operation'>) {
    const grant = await this.grants.observationGrant(id);
    if (!grant) return null;
    const now = nowSeconds(),
      token = createResourceId('operation');
    changed(
      await this.db
        .prepare(
          `INSERT INTO account_creation_observation_jobs (initialization_id) VALUES (?)
			ON CONFLICT(initialization_id) DO NOTHING`,
        )
        .bind(id)
        .run(),
    );
    const result = await this.db
      .prepare(
        `UPDATE account_creation_observation_jobs SET lease_epoch = lease_epoch + 1,
			lease_token = ?, lease_started_at = ?, lease_expires_at = ? WHERE initialization_id = ?
			AND next_poll_at <= ? AND (lease_token IS NULL OR lease_expires_at <= ?)
			AND NOT EXISTS (SELECT 1 FROM account_creation_projections x WHERE x.initialization_id = account_creation_observation_jobs.initialization_id)
			AND EXISTS (SELECT 1 FROM account_creation_operations o WHERE o.initialization_id = ?
			AND o.user_op_hash = ? AND o.operation_signature = ?)`,
      )
      .bind(
        token,
        now,
        now + 60,
        id,
        now,
        now,
        id,
        grant.signed.userOpHash,
        grant.signed.operation.signature,
      )
      .run();
    if (changed(result) === 0) return null;
    const row = await this.db
      .prepare('SELECT * FROM account_creation_observation_jobs WHERE initialization_id = ?')
      .bind(id)
      .first<Row>();
    if (
      !row ||
      row.lease_token !== token ||
      row.lease_started_at !== now ||
      row.lease_expires_at !== now + 60
    )
      throw invalid();
    return Object.freeze({
      id,
      token,
      started: now,
      until: now + 60,
      epoch: integer(row.lease_epoch),
      grant,
    });
  }
  async append(
    claim: NonNullable<Awaited<ReturnType<CreationObservationJournal['claim']>>>,
    result: Result,
  ) {
    const now = nowSeconds(),
      json = resultJson(result, claim.grant),
      digest = deploymentDocumentDigest(json);
    if (now < claim.started || now >= claim.until) return false;
    if (
      result.status === 'observed' &&
      result.finality !== 'not_assessed' &&
      (result.finality_evidence.assessed_at < claim.started ||
        result.finality_evidence.assessed_at > now)
    )
      throw invalid();

    const writes = await this.db.batch([
      this.db
        .prepare(
          `INSERT INTO account_creation_observations
				(initialization_id,lease_epoch,lease_token,started_at,observed_at,user_op_hash,status,transaction_hash,result_json,result_sha256)
				SELECT initialization_id,lease_epoch,lease_token,lease_started_at,?,?,?,?,?,? FROM account_creation_observation_jobs
				WHERE initialization_id = ? AND lease_token = ? AND lease_epoch = ? AND lease_expires_at > ?
				AND EXISTS (SELECT 1 FROM account_creation_operations o WHERE o.initialization_id = ?
				AND o.user_op_hash = ? AND o.operation_signature = ?)`,
        )
        .bind(
          now,
          claim.grant.signed.userOpHash,
          result.status,
          result.transaction_hash,
          json,
          digest,
          claim.id,
          claim.token,
          claim.epoch,
          now,
          claim.id,
          claim.grant.signed.userOpHash,
          claim.grant.signed.operation.signature,
        ),
      this.db
        .prepare(
          `UPDATE account_creation_observation_jobs SET latest_epoch = ?, lease_token = NULL,
				lease_started_at = NULL, lease_expires_at = NULL, next_poll_at = ?
				WHERE initialization_id = ? AND lease_token = ? AND lease_epoch = ? AND lease_expires_at > ?
				AND EXISTS (SELECT 1 FROM account_creation_observations r WHERE r.initialization_id = ?
				AND r.lease_epoch = ? AND r.lease_token = ? AND r.result_sha256 = ?)`,
        )
        .bind(
          claim.epoch,
          now +
            (result.status === 'observed'
              ? 30
              : Math.min(300, 10 * 2 ** Math.min(claim.epoch - 1, 5))),
          claim.id,
          claim.token,
          claim.epoch,
          now,
          claim.id,
          claim.epoch,
          claim.token,
          digest,
        ),
    ]);
    if (writes.length !== 2 || changed(writes[0]) !== changed(writes[1])) throw invalid();
    return writes[0].meta.changes === 1;
  }

  async latest(id: ResourceId<'operation'>) {
    const grant = await this.grants.observationGrant(id);
    if (!grant) return null;
    const row = await this.db
      .prepare(
        `SELECT j.latest_epoch,r.* FROM account_creation_observation_jobs j
			LEFT JOIN account_creation_observations r ON r.initialization_id = j.initialization_id AND r.lease_epoch = j.latest_epoch
			WHERE j.initialization_id = ?`,
      )
      .bind(id)
      .first<Row>();
    if (!row) return null;
    if (integer(row.latest_epoch) === 0) return null;
    if (
      row.initialization_id !== id ||
      integer(row.lease_epoch) !== row.latest_epoch ||
      row.user_op_hash !== grant.signed.userOpHash ||
      typeof row.result_json !== 'string' ||
      row.result_json.length > 8192 ||
      deploymentDocumentDigest(row.result_json) !== row.result_sha256
    )
      throw invalid();
    const value: unknown = JSON.parse(row.result_json);
    assertResult(value, grant);
    if (
      resultJson(value, grant) !== row.result_json ||
      value.status !== row.status ||
      value.transaction_hash !== row.transaction_hash
    )
      throw invalid();
    return Object.freeze({
      epoch: row.latest_epoch,
      observed_at: integer(row.observed_at),
      result: value,
    });
  }

  async knownTransaction(id: ResourceId<'operation'>): Promise<Hex | undefined> {
    const grant = await this.grants.observationGrant(id);
    if (!grant) return undefined;
    const row = await this.db
      .prepare(
        `SELECT result_json,result_sha256,transaction_hash FROM account_creation_observations
			WHERE initialization_id = ? AND status = 'observed' ORDER BY lease_epoch DESC LIMIT 1`,
      )
      .bind(id)
      .first<Row>();
    if (!row) return undefined;
    if (
      typeof row.result_json !== 'string' ||
      row.result_json.length > 8192 ||
      deploymentDocumentDigest(row.result_json) !== row.result_sha256
    )
      throw invalid();
    const value: unknown = JSON.parse(row.result_json);
    assertResult(value, grant);
    if (
      value.status !== 'observed' ||
      resultJson(value, grant) !== row.result_json ||
      value.transaction_hash !== row.transaction_hash
    )
      throw invalid();
    requireHash(value.transaction_hash);
    return value.transaction_hash;
  }

  async lastFinalizedReceipt(id: ResourceId<'operation'>) {
    const grant = await this.grants.observationGrant(id);
    if (!grant) return null;
    const row = await this.db
      .prepare(
        `SELECT result_json,result_sha256 FROM account_creation_observations
			WHERE initialization_id = ? AND json_extract(result_json, '$.finality') = 'finalized'
			ORDER BY lease_epoch DESC LIMIT 1`,
      )
      .bind(id)
      .first<Row>();
    if (!row) return null;
    if (
      typeof row.result_json !== 'string' ||
      row.result_json.length > 8192 ||
      deploymentDocumentDigest(row.result_json) !== row.result_sha256
    )
      throw invalid();
    const value: unknown = JSON.parse(row.result_json);
    assertResult(value, grant);
    if (
      value.status !== 'observed' ||
      value.finality !== 'finalized' ||
      resultJson(value, grant) !== row.result_json
    )
      throw invalid();
    return value.observation;
  }
}
