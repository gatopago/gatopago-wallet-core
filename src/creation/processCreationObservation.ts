import type { OperationTransport } from '../execution/operationTransport';
import { submissionTransaction } from '../execution/operationTransport';
import { SponsorshipBudget } from '../sponsorship/budget';
import { rpcEndpoint } from '../chainProviders';
import type { ResourceId } from '@gatopago/shared/v3/primitives';
import { loadPinnedFinalityPolicy, type FinalityPolicyPin } from '@gatopago/shared/v3/finality';
import { loadPinnedCreationProfile } from '@gatopago/shared/v3/initialization';
import type { CreationDeliveryConfiguration } from './creationDelivery';

import { reconcileCreationObservation } from './creationObservation';
import { CreationObservationJournal } from './creationObservationJournal';
import type { CreationProfilePin } from './initialization';

interface Network extends CreationProfilePin {
	readonly transport: OperationTransport;
	readonly finalityPolicy: FinalityPolicyPin;
	readonly providers: readonly { readonly operatorId: string; readonly url: string }[];
}
interface Configuration extends Omit<CreationDeliveryConfiguration, 'profiles'> { readonly networks: readonly Network[] }

/** Internal durable observer. Admission of endpoints/operators/networks is external
 * to this service; no configuration comes from a public request. Not a sending job. */
export async function processCreationObservation(database: D1Database, id: ResourceId<'operation'>,
	configuration: Configuration, signal: AbortSignal) {
	const networks = configuration.networks.map((network) => {
		const finalityPolicy = Object.freeze({ ...network.finalityPolicy });
		loadPinnedFinalityPolicy(finalityPolicy, loadPinnedCreationProfile(network.document, network.digest).deployment);
		return Object.freeze({ ...network, finalityPolicy,
			providers: Object.freeze(network.providers.map((p) => Object.freeze({
				operatorId: p.operatorId, url: rpcEndpoint(p.url),
			}))),
		});
	});
	const journal = new CreationObservationJournal(database, { ...configuration, profiles: networks });
	signal.throwIfAborted();
	const claim = await journal.claim(id);
	if (!claim) return 'idle' as const;
	const network = networks.find((item) => item.digest === claim.grant.signed.prepared.profileDigest);
	if (!network) throw new Error('Missing admitted observation profile');
	let transaction = await journal.knownTransaction(id);
	const finalizedReceipt = await journal.lastFinalizedReceipt(id);
	const deadline = AbortSignal.any([signal, AbortSignal.timeout(Math.max(1, Math.min(40_000, claim.until * 1000 - Date.now())))]);
	const submitted = await submissionTransaction(database, claim.grant.signed.userOpHash, deadline);
	transaction ??= submitted ?? undefined;
	let result = await reconcileCreationObservation(claim.grant.signed, { profileDocument: network.document,
		transport: submitted === undefined ? network.transport : undefined, providers: network.providers, finalityPolicy: network.finalityPolicy }, deadline, transaction);
	if (finalizedReceipt && result.status === 'observed' && result.finality !== 'not_assessed'
		&& (result.observation.block_hash !== finalizedReceipt.block_hash || result.observation.block_number !== finalizedReceipt.block_number
			|| result.observation.block_timestamp !== finalizedReceipt.block_timestamp)) {
		// Two agreeing RPCs must not silently rewrite a historically finalized identity.
		const evidence = result.finality_evidence;
		result = Object.freeze({ ...result, finality: 'reorg_detected', finality_evidence: Object.freeze({ ...evidence,
			status: 'reorg_detected', checkpoint: null, expires_at: evidence.assessed_at }) });
	}
	if (!await journal.append(claim, result)) return 'lease_lost' as const;
    if (claim.grant.signed.operation.paymaster && result.status === 'observed' && result.finality === 'finalized') {
      await new SponsorshipBudget(database).settle(claim.grant.signed.userOpHash,
        BigInt(result.observation.actual_gas_cost), result.observation.transaction_hash);
    }
    return result.status;
}
