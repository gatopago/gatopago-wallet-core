import { assertFinalityAssessment } from '@gatopago/shared/v3/finality';
import { requireHash } from '@gatopago/shared/v3/deployment';
import { parseAtomicAmount } from '@gatopago/shared/v3/primitives';
import type { BackupObservationGrant } from './backupDelivery';
import type { BackupObservationResult } from './backupObservation';

type Row = Record<string, unknown>;
const invalid = () => new Error('BACKUP_OBSERVATION_INVALID');
function row(value: unknown): Row {
 if (!value || typeof value !== 'object' || Array.isArray(value)) throw invalid();
 return value as Row;
}
function exact(value: Row, keys: readonly string[]) {
 if (Object.keys(value).length !== keys.length || keys.some((k) => !Object.hasOwn(value, k))) throw invalid();
}

/** Checks serialized evidence against the original grant. The digest detects storage
 * drift, not a malicious database administrator; this is not a block inclusion proof. */
export function assertBackupObservation(value: unknown, grant: BackupObservationGrant): asserts value is BackupObservationResult {
 const result = row(value), observed = result.status === 'observed';
 exact(result, ['transaction_hash', 'provider_ids', 'finality', 'account_readiness', 'status', ...(observed ? ['observation', 'finality_evidence'] : [])]);
 if (result.transaction_hash !== grant.transactionHash || result.account_readiness !== 'not_assessed'
  || !Array.isArray(result.provider_ids) || result.provider_ids.length !== 2 || new Set(result.provider_ids).size !== 2
  || result.provider_ids.some((p: unknown) => typeof p !== 'string' || !/^[a-z0-9][a-z0-9-]{2,63}$(?![\s\S])/.test(p))) throw invalid();
 if (!observed) {
  if (!['unavailable', 'not_observed', 'disagreement'].includes(String(result.status)) || result.finality !== 'not_assessed') throw invalid();
  return;
 }
 const o = row(result.observation);
 exact(o, ['schema_version', 'operation_id', 'backup_id', 'kind', 'network_id', 'profile_sha256', 'transaction_hash', 'block_hash',
  'block_number', 'block_timestamp', 'transaction_index', 'account', 'operator', 'proposal_hash', 'outcome', 'installed_manifest_hash',
  'gas_used', 'effective_gas_price', 'execution_gas_cost', 'log_indexes', 'finality', 'account_readiness']);
 if (o.schema_version !== 1 || o.operation_id !== grant.id || o.backup_id !== grant.backupId || o.kind !== grant.kind
  || o.network_id !== grant.networkId || o.profile_sha256 !== grant.profileDigest || o.transaction_hash !== grant.transactionHash
  || o.account !== grant.transaction.request.to || o.operator !== grant.transaction.operator || o.proposal_hash !== grant.signed.proposalHash
  || o.finality !== 'not_assessed' || o.account_readiness !== 'not_assessed') throw invalid();
 requireHash(o.block_hash);
 if (BigInt(parseAtomicAmount(o.block_number)) <= BigInt(grant.afterCheckpoint)) throw invalid();
 const time = BigInt(parseAtomicAmount(o.block_timestamp)), gas = BigInt(parseAtomicAmount(o.gas_used)), price = BigInt(parseAtomicAmount(o.effective_gas_price));
 parseAtomicAmount(o.transaction_index);
 if (gas === 0n || gas > grant.transaction.request.gas || price > grant.transaction.request.maxFeePerGas
  || BigInt(parseAtomicAmount(o.execution_gas_cost)) !== gas * price) throw invalid();
 const reverted = o.outcome === 'execution_reverted', message = grant.commit?.message ?? grant.backup.message;
 if (!reverted && (o.outcome !== (grant.kind === 'prepare' ? 'proposal_prepared' : 'backup_committed')
  || time < BigInt(message.validAfter) || time >= BigInt(message.validUntil)
  || (grant.commit && (time < BigInt(grant.commit.readyAt) || time >= BigInt(grant.backup.message.proposalValidUntil))))) throw invalid();
 if (o.installed_manifest_hash !== (!reverted && grant.kind === 'commit' ? grant.signed.expectedManifestHash : null)
  || !Array.isArray(o.log_indexes) || o.log_indexes.length !== (reverted ? 0 : grant.kind === 'prepare' ? 1 : 2)) throw invalid();
 let previous = -1n;
 for (const index of o.log_indexes) {
  const number = BigInt(parseAtomicAmount(index)); if (number <= previous) throw invalid(); previous = number;
 }
 assertFinalityAssessment(result.finality_evidence, { network_id: grant.networkId, genesis_hash: grant.initial.profile.deployment.genesis_hash,
  block_hash: o.block_hash, block_number: parseAtomicAmount(o.block_number), block_timestamp: parseAtomicAmount(o.block_timestamp) });
 if (result.finality_evidence.status !== result.finality) throw invalid();
}
export function backupObservationJson(value: unknown, grant: BackupObservationGrant) {
 assertBackupObservation(value, grant);
 const json = JSON.stringify(value);
 if (json.length > 8192) throw invalid();
 return json;
}
