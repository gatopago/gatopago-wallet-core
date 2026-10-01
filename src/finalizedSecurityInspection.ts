import type { AccountInspectionInput } from '@gatopago/shared/v3/account-inspection';
import { loadPinnedDeploymentManifest } from '@gatopago/shared/v3/deployment';
import { assessCheckpointFinality, assertFinalityAssessment, loadPinnedFinalityPolicy, type FinalityAssessment, type FinalityPolicyPin } from '@gatopago/shared/v3/finality';
import { createInspectionClient, inspectWalletSecurity } from './chainInspection';

interface Input extends Omit<AccountInspectionInput, 'checkpoint'> {
	readonly rpcUrls: readonly string[];
	readonly finalityPolicy: FinalityPolicyPin;
	/** Trusted observer output, never an HTTP body or an old D1 success fallback. */
	readonly finalityEvidence: FinalityAssessment;
}

/** Read security at the recent COMMON FINALIZED checkpoint, not at an old creation
 * receipt or caller-chosen height. Recheck consensus after the account reads and
 * retain the earlier expiry. No observation here proves factor possession, matches
 * a desired signed security history, enables deposits/spending, or admits a network.
 * Provider/operator independence is checked by admission outside this helper.
 */
export async function inspectFinalizedWalletSecurity(input: Input, signal: AbortSignal) {
	const document = input.document, expectedDigest = input.expectedDigest;
	const initialSecurityCommitment = input.initialSecurityCommitment, userSaltCommitment = input.userSaltCommitment;
	const urls = Object.freeze([...input.rpcUrls]), pin = Object.freeze({ ...input.finalityPolicy });
	const source = structuredClone(input.finalityEvidence);
	const manifest = loadPinnedDeploymentManifest(document, expectedDigest);
	const policy = loadPinnedFinalityPolicy(pin, manifest);
	function fresh(evidence: FinalityAssessment) {
		assertFinalityAssessment(evidence, { ...evidence.target, network_id: manifest.network_id, genesis_hash: manifest.genesis_hash });
		const now = Math.floor(Date.now() / 1000);
		if (evidence.status !== 'finalized' || !evidence.checkpoint || evidence.policy_sha256 !== pin.digest
			|| evidence.mechanism !== policy.mechanism || now < policy.valid_from || now >= policy.valid_until
			|| evidence.assessed_at < policy.valid_from || evidence.assessed_at > now || now >= evidence.expires_at
			|| evidence.expires_at > Math.min(evidence.assessed_at + policy.evidence_ttl_seconds, policy.valid_until)
			|| BigInt(evidence.checkpoint.block_timestamp) > BigInt(now + policy.max_clock_skew_seconds)
			|| BigInt(now) - BigInt(evidence.checkpoint.block_timestamp) > BigInt(policy.max_finalized_age_seconds)) {
			throw new Error('SECURITY_FINALITY_UNUSABLE');
		}
		return evidence.checkpoint;
	}
	const checkpoint = Object.freeze({ ...fresh(source) });
	const deadline = AbortSignal.any([signal, AbortSignal.timeout(30_000)]);
	deadline.throwIfAborted();
	const observation = await inspectWalletSecurity({ document, expectedDigest, initialSecurityCommitment, userSaltCommitment,
		checkpoint: { block_hash: checkpoint.block_hash, block_number: checkpoint.block_number } }, urls, deadline);
	// Never let slow account/RPC reads renew or extend the evidence that selected this block.
	fresh(source); deadline.throwIfAborted();
	const closing = await assessCheckpointFinality(urls.map((url) => createInspectionClient(url, deadline)),
		{ ...checkpoint, network_id: manifest.network_id, genesis_hash: manifest.genesis_hash }, pin, deadline);
	deadline.throwIfAborted(); fresh(closing); fresh(source);
	return Object.freeze({ ...observation, finality: 'finalized' as const, finality_evidence: closing,
		security_observed_at: Math.floor(Date.now() / 1000), security_expires_at: Math.min(source.expires_at, closing.expires_at) });
}
