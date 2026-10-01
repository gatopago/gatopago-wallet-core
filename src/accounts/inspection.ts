import { isAddressEqual, type Hex } from 'viem';
import { loadPinnedDeploymentManifest } from '@gatopago/shared/v3/deployment';
import { predictAccountAddress } from '@gatopago/shared/v3/authorizations';
import type { FinalityAssessment, FinalityPolicyPin } from '@gatopago/shared/v3/finality';
import type { ResourceId } from '@gatopago/shared/v3/primitives';
import { inspectFinalizedWalletSecurity } from '../finalizedSecurityInspection';
import { WalletAccessError, type WalletRepository } from './repository';

export interface InspectionProfile {
	readonly document: string;
	readonly digest: Hex;
	readonly rpcUrls: readonly [string, string];
	readonly finalityPolicy: FinalityPolicyPin;
	/** Chosen by trusted chain/finality policy, never HTTP params or an old success. */
	readonly finalityEvidence: FinalityAssessment;
}

/** Internal integration, not a public arbitrary-address RPC proxy. The eventual network
 * admission layer supplies profiles/checkpoints. No real profile is admitted by this helper.
 * Ownership is read first; every derivation is compared BEFORE sending any RPC request.
 */
export async function inspectOwnedWalletAccount(repository: Pick<WalletRepository, 'ownedAccount'>, walletId: ResourceId<'wallet'>,
	accountId: ResourceId<'walletAccount'>, trustedProfiles: readonly InspectionProfile[], signal: AbortSignal) {
	const profiles = structuredClone(trustedProfiles);
	const owned = await repository.ownedAccount(walletId, accountId);
	const observation = await inspectWalletAccount(owned, profiles, signal);
	const current = await repository.ownedAccount(walletId, accountId);
	signal.throwIfAborted();
	if (JSON.stringify(current) !== JSON.stringify(owned)) throw new WalletAccessError('WALLET_DATA_INVALID');
	if (Math.floor(Date.now() / 1000) >= observation.security_expires_at) throw new Error('SECURITY_FINALITY_UNUSABLE');
	return { wallet_id: walletId, wallet_account_id: accountId, ...observation };
}

/** Chain read for an already validated identity. Access and post-read ownership checks
 * belong to the caller; this function alone never makes an account publicly receivable. */
export async function inspectWalletAccount(owned: Awaited<ReturnType<WalletRepository['ownedAccount']>>,
  trustedProfiles: readonly InspectionProfile[], signal: AbortSignal) {
	// Detach before I/O; a mutable request/config object must not change a pin mid-inspection.
	const profiles = trustedProfiles.map((profile) => Object.freeze({ ...profile, rpcUrls: Object.freeze([...profile.rpcUrls]),
		finalityPolicy: Object.freeze({ ...profile.finalityPolicy }), finalityEvidence: structuredClone(profile.finalityEvidence) }));
	signal.throwIfAborted();
	const matching = profiles.filter((profile) => profile.digest === owned.deployment_manifest_sha256);
	if (matching.length !== 1) throw new Error('INSPECTION_PROFILE_UNAVAILABLE');
	const profile = matching[0];
	const manifest = loadPinnedDeploymentManifest(profile.document, profile.digest);
	if (manifest.network_id !== owned.network_id || manifest.lifecycle_status !== 'deployed'
		|| !isAddressEqual(predictAccountAddress(manifest.components.factory.address, owned.account_id, manifest.proxy.init_code_hash), owned.address)) {
		throw new WalletAccessError('WALLET_DATA_INVALID');
	}
	const observation = await inspectFinalizedWalletSecurity({ document: profile.document, expectedDigest: profile.digest,
		initialSecurityCommitment: owned.initial_security_commitment, userSaltCommitment: owned.user_salt_commitment,
		rpcUrls: profile.rpcUrls, finalityPolicy: profile.finalityPolicy, finalityEvidence: profile.finalityEvidence }, signal);
	if (Math.floor(Date.now() / 1000) >= observation.security_expires_at) throw new Error('SECURITY_FINALITY_UNUSABLE');
	// No projection update or activation follows inspection. Unknown/deployed are observations,
	// not authorization, spend-readiness, proof of an honest RPC or cross-chain security sync.
	return observation;
}
