import { validateRpcProviders } from '../chainProviders';
import { deploymentDocumentDigest } from '@gatopago/shared/v3/deployment';
import { loadPinnedCreationProfile } from '@gatopago/shared/v3/initialization';
import { assessCheckpointFinality, loadPinnedFinalityPolicy } from '@gatopago/shared/v3/finality';
import type { ResourceId } from '@gatopago/shared/v3/primitives';
import { inspectFinalizedWalletSecurity } from '../finalizedSecurityInspection';
import { withDeadline } from '../deadline';
import { createInspectionClient } from '../chainInspection';
import { BackupDeliveryRepository } from './backupDelivery';
import { BackupObservationJournal } from './backupObservationJournal';
import type { BackupObservationNetwork } from './backupObservation';

import type { BackupProcessorConfiguration } from './processBackupDelivery';
import type { CreationDeliveryConfiguration } from '../creation/creationDelivery';

interface Configuration extends Omit<CreationDeliveryConfiguration, 'profiles'> {
  readonly networks: readonly BackupObservationNetwork[];
  readonly finality: BackupProcessorConfiguration['finality'];
}
type Row = Record<string, unknown>;
const invalid = () => new Error('BACKUP_PROJECTION_INVALID');

export async function processBackupProjection(
  database: D1Database,
  id: ResourceId<'operation'>,
  configuration: Configuration,
  signal: AbortSignal,
) {
  signal.throwIfAborted();
  if (configuration.networks.length > 32 || typeof configuration.finality !== 'function')
    throw invalid();
  const networks = configuration.networks.map((n) => {
    const profile = loadPinnedCreationProfile(n.document, n.digest),
      finalityPolicy = Object.freeze({ ...n.finalityPolicy });
    loadPinnedFinalityPolicy(finalityPolicy, profile.deployment);
    return Object.freeze({
      document: n.document,
      digest: n.digest,
      finalityPolicy,
      profile,
      providers: validateRpcProviders(n.providers),
    });
  });
  const finality = configuration.finality;
  const config = {
    environment: configuration.environment,
    scope: { ...configuration.scope },
    profiles: networks,
  };
  const grants = new BackupDeliveryRepository(database, config),
    journal = new BackupObservationJournal(database, config);
  const db = database.withSession('first-primary'),
    grant = await grants.observationGrant(id);
  if (!grant || grant.kind !== 'commit') return 'pending' as const;
  const network = networks.find((n) => n.digest === grant.profileDigest);
  if (!network) throw invalid();
  const expectedManifest = grant.signed.expectedManifestHash,
    expected = grant.backup.message;
  const prior = await db
    .prepare(
      `SELECT p.*,r.result_sha256 AS observed_sha256,r.transaction_hash AS observed_transaction_hash,r.result_json AS observed_json
  FROM account_backup_projections p LEFT JOIN account_backup_observations r
  ON r.operation_id = p.operation_id AND r.lease_epoch = p.source_epoch WHERE p.operation_id = ?`,
    )
    .bind(id)
    .first<Row>();
  if (prior) {
    if (
      prior.backup_id !== grant.backupId ||
      prior.transaction_hash !== grant.transactionHash ||
      prior.profile_sha256 !== grant.profileDigest ||
      prior.manifest_hash !== expectedManifest ||
      prior.source_sha256 !== prior.observed_sha256 ||
      prior.transaction_hash !== prior.observed_transaction_hash ||
      typeof prior.observed_json !== 'string' ||
      deploymentDocumentDigest(prior.observed_json) !== prior.source_sha256 ||
      typeof prior.security_json !== 'string' ||
      prior.security_json.length > 16384 ||
      deploymentDocumentDigest(prior.security_json) !== prior.security_sha256 ||
      typeof prior.projected_at !== 'number' ||
      typeof prior.evidence_expires_at !== 'number' ||
      prior.evidence_expires_at <= prior.projected_at
    )
      throw invalid();
    return 'already_projected' as const;
  }
  const source = await journal.latest(id),
    result = source?.result;
  if (
    !source ||
    !result ||
    result.status !== 'observed' ||
    result.finality !== 'finalized' ||
    result.observation.outcome !== 'backup_committed'
  )
    return 'pending' as const;
  if (
    result.finality_evidence.policy_sha256 !== network.finalityPolicy.digest ||
    [...result.provider_ids].sort().join(',') !==
      network.providers
        .map((p) => p.operatorId)
        .sort()
        .join(',')
  )
    throw invalid();
  const time = () => Math.floor(Date.now() / 1000);
  if (result.finality_evidence.expires_at <= time()) return 'pending' as const;
  return withDeadline(signal, 40_000, async (deadline) => {
    const fresh = await finality({ document: network.document, digest: network.digest }, deadline);
    const deployment = JSON.stringify(network.profile.deployment);
    const security = await inspectFinalizedWalletSecurity(
      {
        document: deployment,
        expectedDigest: deploymentDocumentDigest(deployment),
        initialSecurityCommitment: grant.initial.message.initialSecurityCommitment,
        userSaltCommitment: grant.initial.message.userSaltCommitment,
        rpcUrls: network.providers.map((p) => p.url),
        finalityPolicy: network.finalityPolicy,
        finalityEvidence: fresh,
      },
      deadline,
    );
    if (
      security.status !== 'recognized' ||
      security.security_version !== '2' ||
      security.security.phase !== 'active_policy' ||
      security.security.manifest_hash !== expectedManifest ||
      security.security.policy_hash !== expected.nextPolicyHash ||
      security.security.chain_scope_hash !== expected.chainScopeHash ||
      security.security.pending !== null ||
      BigInt(security.security.nonces.admin) < grant.commit!.message.nonce + 1n ||
      BigInt(security.checkpoint.block_number) < BigInt(result.observation.block_number) ||
      (security.checkpoint.block_number === result.observation.block_number &&
        security.checkpoint.block_hash !== result.observation.block_hash)
    ) {
      throw new Error('BACKUP_POLICY_CHANGED');
    }

    const receiptFinality = await assessCheckpointFinality(
      network.providers.map((p) => createInspectionClient(p.url, deadline)),
      {
        network_id: network.profile.deployment.network_id,
        genesis_hash: network.profile.deployment.genesis_hash,
        block_hash: result.observation.block_hash,
        block_number: result.observation.block_number,
        block_timestamp: result.observation.block_timestamp,
      },
      network.finalityPolicy,
      deadline,
    );
    if (receiptFinality.status !== 'finalized') throw new Error('BACKUP_RECEIPT_FINALITY_CHANGED');
    const current = await grants.observationGrant(id);
    if (
      !current ||
      current.serializedTransaction !== grant.serializedTransaction ||
      current.signed.expectedManifestHash !== expectedManifest
    )
      throw invalid();
    const projectedAt = time(),
      expires = Math.min(
        security.security_expires_at,
        result.finality_evidence.expires_at,
        receiptFinality.expires_at,
      );
    deadline.throwIfAborted();
    if (projectedAt >= expires) return 'pending' as const;
    const json = JSON.stringify(security),
      sourceJson = JSON.stringify(result),
      sourceDigest = deploymentDocumentDigest(sourceJson);
    if (json.length > 16384) throw invalid();

    const saved = await db
      .prepare(
        `INSERT INTO account_backup_projections(operation_id,backup_id,source_epoch,source_sha256,
   transaction_hash,profile_sha256,manifest_hash,security_json,security_sha256,projected_at,evidence_expires_at)
   SELECT b.operation_id,b.backup_id,?,?,?,?,?,?,?,?,? FROM account_backup_outbox b
   JOIN account_backup_transactions t ON t.operation_id = b.operation_id
   JOIN account_backups a ON a.id = b.backup_id JOIN account_initializations i ON i.id = a.initialization_id
   JOIN users u ON u.id = a.user_id
   JOIN account_backup_observation_jobs j ON j.operation_id = b.operation_id
   JOIN account_backup_observations r ON r.operation_id = j.operation_id AND r.lease_epoch = j.latest_epoch
   JOIN wallet_accounts wa ON wa.id = a.wallet_account_id AND wa.wallet_id = a.wallet_id
   JOIN wallets w ON w.id = wa.wallet_id AND w.user_id = a.user_id
   WHERE b.operation_id = ? AND b.kind = 'commit' AND b.state IN ('sending','uncertain','accepted')
   AND b.transaction_hash = ? AND t.transaction_hash = b.transaction_hash AND t.serialized_transaction = ?
   AND i.profile_sha256 = ? AND a.expected_manifest_hash = ? AND u.environment = ?
   AND w.account_id = ? AND w.canonical_address = ? AND w.initial_security_commitment = ? AND w.user_salt_commitment = ?
   AND wa.address = w.canonical_address
   AND wa.deployment_manifest_sha256 = ? AND wa.network_id = ?
   AND j.latest_epoch = ? AND j.lease_token IS NULL AND r.result_json = ? AND r.result_sha256 = ?
   AND unixepoch() < ? ON CONFLICT(operation_id) DO NOTHING`,
      )
      .bind(
        source.epoch,
        sourceDigest,
        grant.transactionHash,
        grant.profileDigest,
        expectedManifest,
        json,
        deploymentDocumentDigest(json),
        projectedAt,
        expires,
        id,
        grant.transactionHash,
        grant.serializedTransaction,
        grant.profileDigest,
        expectedManifest,
        config.environment,
        grant.initial.message.accountId,
        grant.initial.account.toLowerCase(),
        grant.initial.message.initialSecurityCommitment,
        grant.initial.message.userSaltCommitment,
        deploymentDocumentDigest(deployment),
        network.profile.deployment.network_id,
        source.epoch,
        sourceJson,
        sourceDigest,
        expires,
      )
      .run();
    if (!saved.success || ![0, 1].includes(saved.meta.changes)) throw invalid();
    return saved.meta.changes === 1 ? ('projected' as const) : ('superseded' as const);
  });
}
