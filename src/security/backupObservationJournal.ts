import type { Environment } from '@gatopago/environment';
import { deploymentDocumentDigest } from '@gatopago/shared/v3/deployment';
import { createResourceId, parseResourceId, type ResourceId } from '@gatopago/shared/v3/primitives';
import { BackupDeliveryRepository, type BackupObservationGrant } from './backupDelivery';
import type { BackupObservationResult } from './backupObservation';
import { backupObservationJson, assertBackupObservation } from './backupObservationRecord';
import type { CreationDeliveryConfiguration } from '../creation/creationDelivery';

type Row = Record<string, unknown>;
const now = () => Math.floor(Date.now() / 1000);
const invalid = () => new Error('BACKUP_OBSERVATION_INVALID');
function integer(value: unknown) {
  if (typeof value !== 'number' || !Number.isSafeInteger(value) || value < 0) throw invalid();
  return value;
}
function changes(result: D1Result) {
  if (!result.success || ![0, 1].includes(result.meta.changes)) throw invalid();
  return result.meta.changes;
}

/** Request-local journal; independent of sending leases and current user sessions.
 * Historical observation must survive consent expiry, revocation and sponsor changes.
 * A new uncertain observation never falls back to an old successful head. */
export class BackupObservationJournal {
  private readonly db: D1DatabaseSession;
  private readonly grants: BackupDeliveryRepository;
  private readonly environment: Environment['environment'];
  constructor(database: D1Database, configuration: CreationDeliveryConfiguration) {
    this.db = database.withSession('first-primary');
    this.grants = new BackupDeliveryRepository(database, configuration);
    this.environment = configuration.environment;
  }
  async due(limit = 20) {
    if (!Number.isSafeInteger(limit) || limit < 1 || limit > 50) throw invalid();
    const time = now();
    const result = await this.db
      .prepare(
        `SELECT b.operation_id FROM account_backup_outbox b
   JOIN account_backups a ON a.id = b.backup_id JOIN users u ON u.id = a.user_id
   LEFT JOIN account_backup_observation_jobs j ON j.operation_id = b.operation_id
   WHERE u.environment = ? AND b.state IN ('sending','uncertain','accepted')
   AND (j.operation_id IS NULL OR (j.next_poll_at <= ? AND (j.lease_token IS NULL OR j.lease_expires_at <= ?)))
   ORDER BY COALESCE(j.next_poll_at,0),b.operation_id LIMIT ?`,
      )
      .bind(this.environment, time, time, limit)
      .all<Row>();
    if (!result.success) throw invalid();
    return result.results.map((r) => parseResourceId('operation', r.operation_id));
  }
  async claim(id: ResourceId<'operation'>) {
    const grant = await this.grants.observationGrant(id);
    if (!grant) return null;
    const time = now(),
      token = createResourceId('operation');
    changes(
      await this.db
        .prepare(
          'INSERT INTO account_backup_observation_jobs (operation_id) VALUES (?) ON CONFLICT DO NOTHING',
        )
        .bind(id)
        .run(),
    );
    const result = await this.db
      .prepare(
        `UPDATE account_backup_observation_jobs SET lease_epoch = lease_epoch + 1,
   lease_token = ?,lease_started_at = ?,lease_expires_at = ? WHERE operation_id = ?
   AND next_poll_at <= ? AND (lease_token IS NULL OR lease_expires_at <= ?)
   AND EXISTS (SELECT 1 FROM account_backup_transactions t WHERE t.operation_id = ? AND t.transaction_hash = ? AND t.serialized_transaction = ?)`,
      )
      .bind(
        token,
        time,
        time + 60,
        id,
        time,
        time,
        id,
        grant.transactionHash,
        grant.serializedTransaction,
      )
      .run();
    if (changes(result) === 0) return null;
    const r = await this.db
      .prepare('SELECT * FROM account_backup_observation_jobs WHERE operation_id = ?')
      .bind(id)
      .first<Row>();
    if (
      !r ||
      r.lease_token !== token ||
      r.lease_started_at !== time ||
      r.lease_expires_at !== time + 60
    )
      throw invalid();
    return Object.freeze({
      id,
      token,
      started: time,
      until: time + 60,
      epoch: integer(r.lease_epoch),
      grant,
    });
  }
  async append(
    claim: NonNullable<Awaited<ReturnType<BackupObservationJournal['claim']>>>,
    result: BackupObservationResult,
  ) {
    const time = now(),
      json = backupObservationJson(result, claim.grant),
      digest = deploymentDocumentDigest(json);
    if (time < claim.started || time >= claim.until) return false;
    if (
      result.status === 'observed' &&
      (result.finality_evidence.assessed_at < claim.started ||
        result.finality_evidence.assessed_at > time)
    )
      throw invalid();
    const delay =
      result.status === 'observed'
        ? result.finality === 'finalized'
          ? 300
          : 30
        : Math.min(300, 10 * 2 ** Math.min(claim.epoch - 1, 5));
    const writes = await this.db.batch([
      this.db
        .prepare(
          `INSERT INTO account_backup_observations
    (operation_id,lease_epoch,lease_token,started_at,observed_at,transaction_hash,status,result_json,result_sha256)
    SELECT operation_id,lease_epoch,lease_token,lease_started_at,?,?,?,?,? FROM account_backup_observation_jobs
    WHERE operation_id = ? AND lease_token = ? AND lease_epoch = ? AND lease_expires_at > ? AND unixepoch() < lease_expires_at
    AND EXISTS (SELECT 1 FROM account_backup_transactions t WHERE t.operation_id = ? AND t.transaction_hash = ? AND t.serialized_transaction = ?)`,
        )
        .bind(
          time,
          claim.grant.transactionHash,
          result.status,
          json,
          digest,
          claim.id,
          claim.token,
          claim.epoch,
          time,
          claim.id,
          claim.grant.transactionHash,
          claim.grant.serializedTransaction,
        ),
      this.db
        .prepare(
          `UPDATE account_backup_observation_jobs SET latest_epoch = ?,lease_token = NULL,lease_started_at = NULL,
    lease_expires_at = NULL,next_poll_at = ? WHERE operation_id = ? AND lease_token = ? AND lease_epoch = ?
    AND lease_expires_at > ? AND unixepoch() < lease_expires_at
    AND EXISTS (SELECT 1 FROM account_backup_observations r WHERE r.operation_id = ? AND r.lease_epoch = ? AND r.lease_token = ? AND r.result_sha256 = ?)`,
        )
        .bind(
          claim.epoch,
          time + delay,
          claim.id,
          claim.token,
          claim.epoch,
          time,
          claim.id,
          claim.epoch,
          claim.token,
          digest,
        ),
    ]);
    if (writes.length !== 2 || changes(writes[0]) !== changes(writes[1])) throw invalid();
    return writes[0].meta.changes === 1;
  }
  private read(r: Row, grant: BackupObservationGrant) {
    if (
      r.operation_id !== grant.id ||
      r.transaction_hash !== grant.transactionHash ||
      typeof r.result_json !== 'string' ||
      r.result_json.length > 8192 ||
      deploymentDocumentDigest(r.result_json) !== r.result_sha256
    )
      throw invalid();
    const result: unknown = JSON.parse(r.result_json);
    assertBackupObservation(result, grant);
    if (backupObservationJson(result, grant) !== r.result_json || result.status !== r.status)
      throw invalid();
    const started = integer(r.started_at),
      observed = integer(r.observed_at);
    if (observed < started || observed >= started + 60) throw invalid();
    return Object.freeze({ epoch: integer(r.lease_epoch), observed_at: observed, result });
  }
  async latest(id: ResourceId<'operation'>) {
    const grant = await this.grants.observationGrant(id);
    if (!grant) return null;
    const r = await this.db
      .prepare(
        `SELECT j.latest_epoch,r.* FROM account_backup_observation_jobs j
   LEFT JOIN account_backup_observations r ON r.operation_id = j.operation_id AND r.lease_epoch = j.latest_epoch
   WHERE j.operation_id = ?`,
      )
      .bind(id)
      .first<Row>();
    if (!r || integer(r.latest_epoch) === 0) return null;
    if (r.latest_epoch !== r.lease_epoch) throw invalid();
    return this.read(r, grant);
  }
  /** A previously finalized block identity must survive intervening unavailable reads. */
  async lastFinalizedReceipt(id: ResourceId<'operation'>) {
    const grant = await this.grants.observationGrant(id);
    if (!grant) return null;
    const r = await this.db
      .prepare(
        `SELECT * FROM account_backup_observations WHERE operation_id = ?
   AND json_extract(result_json, '$.finality') = 'finalized' ORDER BY lease_epoch DESC LIMIT 1`,
      )
      .bind(id)
      .first<Row>();
    if (!r) return null;
    const { result } = this.read(r, grant);
    if (result.status !== 'observed' || result.finality !== 'finalized') throw invalid();
    return result.observation;
  }
}
