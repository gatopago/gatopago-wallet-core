import type { authorizeCreationOperation } from '@gatopago/shared/v3/creation-operation';
import { parseCreationLifecycle } from '@gatopago/shared/v3/creation-lifecycle';
import { deploymentDocumentDigest } from '@gatopago/shared/v3/deployment';
import { hashSecurityManifest } from '@gatopago/shared/v3/authorizations';
import { zeroHash } from 'viem';
import { assertResult, resultJson } from './creationObservationRecord';
import { WalletAccessError } from '../accounts/repository';

type Row = Record<string, unknown>;
type Signed = ReturnType<typeof authorizeCreationOperation>;
const invalid = () => new WalletAccessError('WALLET_DATA_INVALID');

/** Every joined value is read in ONE SELECT with the operation and owner. The
 * observer's latest head is not substituted with an older successful result. */
export const creationLifecycleColumns = `j.state AS job_state, j.reason AS job_reason,
	q.latest_epoch, r.result_json AS latest_json, r.result_sha256 AS latest_sha256,
	r.observed_at AS latest_observed, r.user_op_hash AS latest_hash,
	x.initialization_id AS projection_id, x.source_epoch, x.source_sha256,
	x.wallet_id AS projected_wallet, x.wallet_account_id AS projected_account,
	x.projected_at, x.evidence_expires_at,
	x.security_json, x.security_sha256, s.result_json AS source_json,
	s.result_sha256 AS actual_source_sha256, s.observed_at AS source_observed,
	a.wallet_id AS actual_wallet,
	a.network_id AS actual_network, w.account_id AS actual_account_id, w.canonical_address,
	w.user_id AS projected_owner`;
export const creationLifecycleJoins = `LEFT JOIN account_creation_jobs j ON j.initialization_id = o.initialization_id
	LEFT JOIN account_creation_observation_jobs q ON q.initialization_id = o.initialization_id
	LEFT JOIN account_creation_observations r ON r.initialization_id = q.initialization_id AND r.lease_epoch = q.latest_epoch
	LEFT JOIN account_creation_projections x ON x.initialization_id = o.initialization_id
	LEFT JOIN account_creation_observations s ON s.initialization_id = x.initialization_id AND s.lease_epoch = x.source_epoch
	LEFT JOIN wallet_accounts a ON a.id = x.wallet_account_id
	LEFT JOIN wallets w ON w.id = a.wallet_id`;

export function creationLifecycle(
  row: Row,
  signed: Signed | null,
  receipt: { initialization_id: string; state: 'prepared' | 'authorized'; delivery_state: string },
  now: number,
) {
  function observation(json: unknown, digest: unknown) {
    if (
      !signed ||
      typeof json !== 'string' ||
      json.length > 8192 ||
      deploymentDocumentDigest(json) !== digest
    )
      throw invalid();
    const value: unknown = JSON.parse(json);
    assertResult(value, { signed });
    if (resultJson(value, { signed }) !== json) throw invalid();
    return value;
  }
  try {
    let latest = null,
      bootstrap = null;
    if (row.latest_epoch !== null && row.latest_epoch !== 0) {
      const result = observation(row.latest_json, row.latest_sha256);
      if (row.latest_hash !== signed?.userOpHash) throw invalid();
      latest = {
        epoch: row.latest_epoch,
        observed_at: row.latest_observed,
        status: result.status,
        finality: result.finality,
        valid_until:
          result.finality === 'not_assessed' ? null : result.finality_evidence.expires_at,
        transaction_hash: result.status === 'observed' ? result.transaction_hash : null,
        outcome: result.status === 'observed' ? result.observation.outcome : null,
      };
    }
    if (row.projection_id !== null) {
      if (!signed) throw invalid();
      const source = observation(row.source_json, row.source_sha256),
        m = signed.prepared.message;
      const manifestHash = hashSecurityManifest({
        accountId: m.accountId,
        generation: 3,
        securityVersion: 1n,
        previousManifestHash: zeroHash,
        policyHash: m.initialSecurityCommitment,
        chainScopeHash: m.chainScopeHash,
      });
      if (
        row.projection_id !== receipt.initialization_id ||
        row.source_sha256 !== row.actual_source_sha256 ||
        source.status !== 'observed' ||
        source.finality !== 'finalized' ||
        source.observation.outcome !== 'creation_succeeded' ||
        source.observation.initial_manifest_hash !== manifestHash ||
        typeof row.source_epoch !== 'number' ||
        !Number.isSafeInteger(row.source_epoch) ||
        row.source_epoch < 1 ||
        typeof row.latest_epoch !== 'number' ||
        row.source_epoch > row.latest_epoch ||
        row.projected_wallet !== row.actual_wallet ||
        row.projected_owner !== row.owner_id ||
        row.actual_network !== signed.prepared.profile.deployment.network_id ||
        row.actual_account_id !== m.accountId ||
        row.canonical_address !== signed.prepared.account.toLowerCase() ||
        typeof row.security_json !== 'string' ||
        row.security_json.length > 16384 ||
        deploymentDocumentDigest(row.security_json) !== row.security_sha256
      )
        throw invalid();
      const security: unknown = JSON.parse(row.security_json);
      if (
        !security ||
        typeof security !== 'object' ||
        !('security' in security) ||
        !security.security ||
        typeof security.security !== 'object'
      )
        throw invalid();
      const s = security as Row,
        policy = security.security as Row;
      if (
        s.status !== 'recognized' ||
        s.finality !== 'finalized' ||
        s.spend_readiness !== 'not_assessed' ||
        s.security_version !== '1' ||
        typeof s.account !== 'string' ||
        s.account.toLowerCase() !== signed.prepared.account.toLowerCase() ||
        s.account_id !== m.accountId ||
        s.network_id !== signed.prepared.profile.deployment.network_id ||
        s.providers_agree !== true ||
        policy.phase !== 'active_policy' ||
        policy.manifest_hash !== manifestHash ||
        policy.policy_hash !== m.initialSecurityCommitment ||
        policy.chain_scope_hash !== m.chainScopeHash ||
        s.security_expires_at !== row.evidence_expires_at ||
        typeof row.projected_at !== 'number' ||
        typeof s.security_observed_at !== 'number' ||
        typeof row.source_observed !== 'number' ||
        row.projected_at < s.security_observed_at ||
        row.projected_at < row.source_observed
      )
        throw invalid();
      bootstrap = {
        recorded_at: row.projected_at,
        evidence_expires_at: row.evidence_expires_at,
        wallet_id: row.projected_wallet,
        wallet_account_id: row.projected_account,
      };
    }
    return parseCreationLifecycle(
      {
        job_state: row.job_state ?? 'not_requested',
        reason: row.job_reason,
        observation: latest,
        bootstrap,
        account_readiness: 'not_assessed',
      },
      receipt,
      now,
    );
  } catch {
    throw invalid();
  }
}
