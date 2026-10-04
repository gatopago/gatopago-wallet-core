import { AUTHORIZED_USER, authorizationValues } from '../auth/authorization';
import { parseBackupStatus } from '@gatopago/shared/v3/backup-status';
import { deploymentDocumentDigest } from '@gatopago/shared/v3/deployment';
import { parseResourceId, type ResourceId } from '@gatopago/shared/v3/primitives';
import type { WebAuthnScope } from '@gatopago/shared/v3/webauthn';
import type { Principal } from '../auth/principal';
import { BackupRepository } from './backup';
import { BackupDeliveryRepository, type BackupObservationGrant } from './backupDelivery';
import { assertBackupObservation, backupObservationJson } from './backupObservationRecord';
import type { CreationProfilePin } from '../creation/initialization';
import { WalletAccessError } from '../accounts/repository';

type Row = Record<string, unknown>;
const invalid = () => new WalletAccessError('WALLET_DATA_INVALID');
function integer(value: unknown, min = 1): number {
  if (typeof value !== 'number' || !Number.isSafeInteger(value) || value < min) throw invalid();
  return value;
}
function object(value: unknown): Row {
  if (!value || typeof value !== 'object' || Array.isArray(value)) throw invalid();
  return value as Row;
}
function evidence(json: unknown, digest: unknown, grant: BackupObservationGrant) {
  if (typeof json !== 'string' || json.length > 8192 || deploymentDocumentDigest(json) !== digest)
    throw invalid();
  const value: unknown = JSON.parse(json);
  assertBackupObservation(value, grant);
  if (backupObservationJson(value, grant) !== json) throw invalid();
  return value;
}

export class BackupStatusRepository {
  private readonly db: D1DatabaseSession;
  private readonly owned: BackupRepository;
  private readonly grants: BackupDeliveryRepository;
  private readonly identity: Principal;
  constructor(
    database: D1Database,
    identity: Principal,
    scope: WebAuthnScope,
    profiles: readonly CreationProfilePin[],
  ) {
    this.identity = Object.freeze({ ...identity });
    this.db = database.withSession('first-primary');
    this.owned = new BackupRepository(database, this.identity, scope, profiles);
    this.grants = new BackupDeliveryRepository(database, {
      environment: identity.environment,
      scope,
      profiles,
    });
  }
  async read(backupId: ResourceId<'operation'>, commitId?: ResourceId<'operation'>) {
    parseResourceId('operation', backupId);
    if (commitId) parseResourceId('operation', commitId);
    const id = commitId ?? backupId,
      kind = commitId ? ('commit' as const) : ('prepare' as const);
    const ownedRead = () =>
      commitId ? this.owned.readCommit(commitId) : this.owned.read(backupId);
    const record = await ownedRead();
    if (record.backup_id !== backupId) throw new WalletAccessError('NOT_FOUND');
    const expected = { backupId, operationId: id, kind, proposalHash: record.proposal_hash };

    const row = await this.db
      .prepare(
        `SELECT b.state AS delivery_state,b.transaction_hash,b.kind,
   j.state AS job_state,j.reason,q.latest_epoch,r.result_json,r.result_sha256,r.observed_at,r.started_at,
   r.transaction_hash AS observed_hash,r.status AS observed_status,
   p.operation_id AS projection_id,p.backup_id AS projection_backup,p.profile_sha256,
   p.transaction_hash AS projection_hash,p.manifest_hash,p.source_epoch,p.source_sha256,p.projected_at,p.evidence_expires_at,
   p.security_json,p.security_sha256,s.result_json AS source_json,s.result_sha256 AS actual_source_sha256,s.observed_at AS source_observed
   FROM account_backup_outbox b JOIN account_backups a ON a.id = b.backup_id
   JOIN users u ON u.id = a.user_id LEFT JOIN account_backup_jobs j ON j.operation_id = b.operation_id
   LEFT JOIN account_backup_observation_jobs q ON q.operation_id = b.operation_id
   LEFT JOIN account_backup_observations r ON r.operation_id = q.operation_id AND r.lease_epoch = q.latest_epoch
   LEFT JOIN account_backup_projections p ON p.operation_id = b.operation_id
   LEFT JOIN account_backup_observations s ON s.operation_id = p.operation_id AND s.lease_epoch = p.source_epoch
   WHERE b.operation_id = ? AND b.backup_id = ? AND ${AUTHORIZED_USER} AND unixepoch() < ?`,
      )
      .bind(id, backupId, ...authorizationValues(this.identity), this.identity.expiresAt)
      .first<Row>();
    if ((record.state === 'authorized') !== (row !== null)) throw invalid();
    let observation = null,
      confirmation = null;
    if (row) {
      if (row.kind !== kind) throw invalid();
      const state = await this.grants.status(id);

      if (state.state !== row.delivery_state || state.hash !== row.transaction_hash)
        throw invalid();
      const grant = await this.grants.observationGrant(id);
      if (
        row.transaction_hash !== null &&
        (!grant || grant.transactionHash !== row.transaction_hash || grant.backupId !== backupId)
      )
        throw invalid();
      if (row.latest_epoch !== null && row.latest_epoch !== 0) {
        if (!grant) throw invalid();
        const result = evidence(row.result_json, row.result_sha256, grant);
        const observedAt = integer(row.observed_at),
          startedAt = integer(row.started_at);
        if (
          row.observed_hash !== grant.transactionHash ||
          row.observed_status !== result.status ||
          observedAt < startedAt ||
          observedAt >= startedAt + 60
        )
          throw invalid();
        observation = {
          epoch: integer(row.latest_epoch),
          observed_at: observedAt,
          status: result.status,
          finality: result.finality,
          outcome: result.status === 'observed' ? result.observation.outcome : null,
          block_number: result.status === 'observed' ? result.observation.block_number : null,
          block_hash: result.status === 'observed' ? result.observation.block_hash : null,
          evidence_expires_at:
            result.status === 'observed' ? result.finality_evidence.expires_at : null,
        };
      }
      if (row.projection_id !== null) {
        if (!grant || !grant.commit || kind !== 'commit') throw invalid();
        const source = evidence(row.source_json, row.source_sha256, grant);
        if (
          row.projection_id !== id ||
          row.projection_backup !== backupId ||
          row.projection_hash !== grant.transactionHash ||
          row.profile_sha256 !== grant.profileDigest ||
          row.manifest_hash !== grant.signed.expectedManifestHash ||
          row.source_sha256 !== row.actual_source_sha256 ||
          source.status !== 'observed' ||
          source.finality !== 'finalized' ||
          source.observation.outcome !== 'backup_committed' ||
          source.observation.installed_manifest_hash !== row.manifest_hash ||
          typeof row.security_json !== 'string' ||
          row.security_json.length > 16384 ||
          deploymentDocumentDigest(row.security_json) !== row.security_sha256
        )
          throw invalid();
        const security = object(JSON.parse(row.security_json)),
          policy = object(security.security),
          nonces = object(policy.nonces);
        const checkpoint = object(security.checkpoint),
          message = grant.backup.message;
        if (
          security.status !== 'recognized' ||
          security.finality !== 'finalized' ||
          security.security_version !== '2' ||
          security.spend_readiness !== 'not_assessed' ||
          security.providers_agree !== true ||
          security.account_id !== grant.initial.message.accountId ||
          security.account !== grant.initial.account ||
          security.network_id !== grant.networkId ||
          policy.phase !== 'active_policy' ||
          policy.pending !== null ||
          policy.manifest_hash !== row.manifest_hash ||
          policy.policy_hash !== message.nextPolicyHash ||
          policy.chain_scope_hash !== message.chainScopeHash ||
          typeof nonces.admin !== 'string' ||
          !/^(0|[1-9][0-9]*)$/.test(nonces.admin) ||
          BigInt(nonces.admin) < grant.commit.message.nonce + 1n ||
          typeof checkpoint.block_number !== 'string' ||
          BigInt(checkpoint.block_number) < BigInt(source.observation.block_number) ||
          (checkpoint.block_number === source.observation.block_number &&
            checkpoint.block_hash !== source.observation.block_hash) ||
          integer(row.projected_at) < integer(row.source_observed) ||
          integer(row.projected_at) < integer(security.security_observed_at) ||
          integer(row.evidence_expires_at) > integer(security.security_expires_at) ||
          integer(row.evidence_expires_at) > source.finality_evidence.expires_at
        )
          throw invalid();
        confirmation = {
          manifest_hash: row.manifest_hash,
          recorded_at: row.projected_at,
          evidence_expires_at: row.evidence_expires_at,
          source_epoch: row.source_epoch,
        };
      }
    }
    const fresh = await ownedRead();
    if (
      fresh.backup_id !== backupId ||
      fresh.state !== record.state ||
      fresh.proposal_hash !== record.proposal_hash
    )
      throw invalid();
    return parseBackupStatus(
      {
        schema_version: 1,
        backup_id: backupId,
        operation_id: id,
        kind,
        proposal_hash: record.proposal_hash,
        consent_state: record.state,
        delivery_state: row?.delivery_state ?? 'not_requested',
        transaction_hash: row?.transaction_hash ?? null,
        job_state: row?.job_state ?? 'not_requested',
        reason: row?.reason ?? null,
        observation,
        policy_confirmation: confirmation,
        account_readiness: 'not_assessed',
        snapshot_at: Math.floor(Date.now() / 1000),
      },
      expected,
    );
  }
}
