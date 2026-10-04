import type { authorizeCreationOperation } from '@gatopago/shared/v3/creation-operation';
import { assertFinalityAssessment } from '@gatopago/shared/v3/finality';
import { requireHash } from '@gatopago/shared/v3/deployment';
import { parseAtomicAmount } from '@gatopago/shared/v3/primitives';
import type { reconcileCreationObservation } from './creationObservation';
import { WalletAccessError } from '../accounts/repository';
type Row = Record<string, unknown>;
type Result = Awaited<ReturnType<typeof reconcileCreationObservation>>;
type Grant = { readonly signed: ReturnType<typeof authorizeCreationOperation> };
const invalid = () => new WalletAccessError('WALLET_DATA_INVALID');

function row(value: unknown): Row {
  if (!value || typeof value !== 'object' || Array.isArray(value)) throw invalid();
  return value as Row;
}
function exactKeys(value: Row, keys: readonly string[]) {
  if (Object.keys(value).length !== keys.length || keys.some((key) => !Object.hasOwn(value, key)))
    throw invalid();
}
export function assertResult(value: unknown, grant: Grant): asserts value is Result {
  const result = row(value);
  if (
    typeof result.finality !== 'string' ||
    ![
      'not_assessed',
      'finalized',
      'pending',
      'stale',
      'disagreement',
      'reorg_detected',
      'unavailable',
    ].includes(result.finality) ||
    result.account_readiness !== 'not_assessed' ||
    typeof result.status !== 'string' ||
    !['observed', 'not_observed', 'unavailable', 'disagreement'].includes(result.status) ||
    !Array.isArray(result.provider_ids) ||
    result.provider_ids.length !== 2 ||
    new Set(result.provider_ids).size !== 2 ||
    result.provider_ids.some(
      (id: unknown) => typeof id !== 'string' || !/^[a-z][a-z0-9_-]{1,63}$(?![\s\S])/.test(id),
    )
  )
    throw invalid();
  exactKeys(result, [
    'status',
    'transaction_hash',
    'provider_ids',
    'finality',
    'account_readiness',
    ...(result.status === 'observed' ? ['observation'] : []),
    ...(result.finality !== 'not_assessed' ? ['finality_evidence'] : []),
  ]);
  if (result.transaction_hash !== null) requireHash(result.transaction_hash);
  if (result.status !== 'observed') {
    if (result.finality !== 'not_assessed') throw invalid();
    return;
  }
  const o = row(result.observation),
    signed = grant.signed;
  exactKeys(o, [
    'schema_version',
    'network_id',
    'profile_sha256',
    'user_op_hash',
    'transaction_hash',
    'block_hash',
    'block_number',
    'transaction_index',
    'account',
    'entry_point',
    'outcome',
    'actual_gas_cost',
    'actual_gas_used',
    'initial_manifest_hash',
    'log_indexes',
    'finality',
    'account_readiness',
    'block_timestamp',
  ]);
  if (
    o.schema_version !== 1 ||
    o.user_op_hash !== signed.userOpHash ||
    o.transaction_hash !== result.transaction_hash ||
    o.profile_sha256 !== signed.prepared.profileDigest ||
    o.network_id !== signed.prepared.profile.deployment.network_id ||
    o.account !== signed.operation.sender.toLowerCase() ||
    o.entry_point !== signed.prepared.message.entryPoint.toLowerCase() ||
    o.finality !== 'not_assessed' ||
    o.account_readiness !== 'not_assessed'
  )
    throw invalid();
  requireHash(o.transaction_hash);
  requireHash(o.block_hash);
  requireHash(o.initial_manifest_hash);
  parseAtomicAmount(o.block_number);
  parseAtomicAmount(o.transaction_index);
  const timestamp = BigInt(parseAtomicAmount(o.block_timestamp)),
    cost = BigInt(parseAtomicAmount(o.actual_gas_cost));
  if (
    BigInt(parseAtomicAmount(o.actual_gas_used)) === 0n ||
    cost > signed.maximumEntryPointCharge ||
    timestamp < BigInt(signed.prepared.message.validAfter) ||
    timestamp > BigInt(signed.prepared.message.validUntil) ||
    !['creation_succeeded', 'execution_reverted'].includes(String(o.outcome))
  )
    throw invalid();
  const indexes = row(o.log_indexes);
  exactKeys(indexes, ['initialized', 'created', 'deployed', 'completed', 'operation']);
  const init = BigInt(parseAtomicAmount(indexes.initialized)),
    created = BigInt(parseAtomicAmount(indexes.created));
  const deployed = BigInt(parseAtomicAmount(indexes.deployed)),
    operation = BigInt(parseAtomicAmount(indexes.operation));
  if (!(init < created && created < deployed && deployed < operation)) throw invalid();
  if (o.outcome === 'creation_succeeded') {
    const completed = BigInt(parseAtomicAmount(indexes.completed));
    if (!(deployed < completed && completed < operation)) throw invalid();
  } else if (indexes.completed !== null) throw invalid();
  if (result.finality !== 'not_assessed') {
    assertFinalityAssessment(result.finality_evidence, {
      network_id: signed.prepared.profile.deployment.network_id,
      genesis_hash: signed.prepared.profile.deployment.genesis_hash,
      block_hash: o.block_hash,
      block_number: parseAtomicAmount(o.block_number),
      block_timestamp: parseAtomicAmount(o.block_timestamp),
    });
    if (result.finality_evidence.status !== result.finality) throw invalid();
  }
}
export function resultJson(value: unknown, grant: Grant): string {
  assertResult(value, grant);
  const result = value;
  const base = {
    status: result.status,
    transaction_hash: result.transaction_hash,
    provider_ids: [...result.provider_ids],
    finality: result.finality,
    account_readiness: 'not_assessed',
  };

  const json = JSON.stringify(
    result.status === 'observed'
      ? {
          ...base,
          observation: result.observation,
          ...(result.finality !== 'not_assessed'
            ? { finality_evidence: result.finality_evidence }
            : {}),
        }
      : base,
  );
  if (json.length > 8192) throw invalid();
  return json;
}
