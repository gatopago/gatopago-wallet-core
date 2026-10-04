import {
  deploymentDocumentDigest,
  loadPinnedDeploymentManifest,
} from '@gatopago/shared/v3/deployment';
import { assertFinalityAssessment, loadPinnedFinalityPolicy } from '@gatopago/shared/v3/finality';
import type { ResourceId } from '@gatopago/shared/v3/primitives';
import type { observeOwnedTransfer } from './transferObservation';
import type { readTransferReview } from '@gatopago/shared/v3/transfer-review-record';

/** Evidence checks for the leased job's finality journal. This validates an
 * internal observation's binding/freshness, not the provenance of an HTTP body.
 */
export function prepareTransferFinalityEvidence(
  stored: Awaited<ReturnType<typeof readTransferReview>>,
  operationId: ResourceId<'operation'>,
  result: Extract<Awaited<ReturnType<typeof observeOwnedTransfer>>, { status: 'observed' }>,
  profiles: Parameters<typeof observeOwnedTransfer>[6],
  started: number,
  now: number,
) {
  const matching = profiles.filter((p) => p.digest === stored.candidate.deployment_digest);
  if (matching.length !== 1) throw new Error('TRANSFER_RECONCILIATION_PROFILE');
  const profile = matching[0],
    manifest = loadPinnedDeploymentManifest(profile.document, profile.digest);
  const policy = loadPinnedFinalityPolicy(profile.finalityPolicy, manifest);
  const observation = result.observation,
    evidence = result.finality_evidence;
  assertFinalityAssessment(evidence, { ...observation, genesis_hash: manifest.genesis_hash });
  if (
    evidence.status !== 'finalized' ||
    result.operation_id !== operationId ||
    result.userop_hash !== stored.candidate.userOpHash ||
    result.transaction_hash !== observation.transaction_hash ||
    observation.userop_hash !== stored.candidate.userOpHash ||
    observation.consent_digest !== stored.candidate.digest ||
    observation.deployment_sha256 !== profile.digest ||
    observation.network_id !== manifest.network_id ||
    evidence.policy_sha256 !== profile.finalityPolicy.digest ||
    evidence.mechanism !== policy.mechanism ||
    evidence.assessed_at < started ||
    evidence.assessed_at > now ||
    now >= evidence.expires_at ||
    now < policy.valid_from ||
    now >= policy.valid_until ||
    evidence.expires_at > evidence.assessed_at + policy.evidence_ttl_seconds
  )
    throw new Error('TRANSFER_RECONCILIATION_EVIDENCE');
  const receiptJson = JSON.stringify(observation),
    evidenceJson = JSON.stringify(result);
  if (receiptJson.length > 8192 || evidenceJson.length > 16384)
    throw new Error('TRANSFER_RECONCILIATION_SIZE');
  return {
    profile,
    receiptJson,
    evidenceJson,
    receiptDigest: deploymentDocumentDigest(receiptJson),
    evidenceDigest: deploymentDocumentDigest(evidenceJson),
  };
}
