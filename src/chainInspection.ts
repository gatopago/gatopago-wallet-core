import { createPublicClient, custom } from 'viem';
import type { AccountInspectionInput } from '@gatopago/shared/v3/account-inspection';
import { inspectCreationDeployment, type CreationInspectionInput } from '@gatopago/shared/v3/creation-inspection';
import { inspectAccountSecurity } from '@gatopago/shared/v3/security-inspection';
import { rpcEndpoint } from './chainProviders';
import { inspectionRpc } from './inspectionRpc';

/** Internal, read-only RPC adapter. rpcUrl is trusted server configuration, NEVER a public
 * request parameter. Build per inspection/request; no cached clients, promises or observations.
 * No new credentials, network enablement, arbitrary-address HTTP route or signing key.
 */
export function createInspectionClient(rpcUrl: string, signal: AbortSignal, batch = false) {
	const url = rpcEndpoint(rpcUrl);
	return createPublicClient({
		cacheTime: 0, batch: { multicall: false }, ccipRead: false,
		transport: custom(inspectionRpc(url, signal, batch), { retryCount: 0, name: 'V3 bounded inspection', key: 'v3-inspection' }),
	});
}

/** Same bounded/read-only transport for original-composition verification, not an HTTP
 * provisioning endpoint or a network-admission shortcut. The checkpoint is supplied by policy. */
export async function inspectWalletCreationProfile(input: CreationInspectionInput, rpcUrl: string, signal: AbortSignal) {
	const deadline = AbortSignal.any([signal, AbortSignal.timeout(30_000)]);
	return inspectCreationDeployment(createInspectionClient(rpcUrl, deadline, true), input);
}

/** Current security needs agreement from two admitted providers at the SAME checkpoint.
 * Distinct hosts prevent accidental duplication; provider independence is an admission gate,
 * not something hostnames prove. No fulfilled Promise or observation survives this request.
 */
export async function inspectWalletSecurity(input: AccountInspectionInput, rpcUrls: readonly string[], signal: AbortSignal) {
	const urls = [...rpcUrls];
	if (urls.length !== 2 || new Set(urls.map((url) => new URL(url).hostname)).size !== 2) throw new Error('SECURITY_RPC_CONFIGURATION');
	const deadline = AbortSignal.any([signal, AbortSignal.timeout(30_000)]);
	const clients = urls.map((url) => createInspectionClient(url, deadline));
	const detached = Object.freeze({ ...input, checkpoint: Object.freeze({ ...input.checkpoint }) });
	const results = await Promise.allSettled(clients.map((client) => inspectAccountSecurity(client, detached)));
	deadline.throwIfAborted();
	const first = results[0], second = results[1];
	if (first.status === 'rejected') throw first.reason;
	if (second.status === 'rejected') throw second.reason;
	if (JSON.stringify(first.value) !== JSON.stringify(second.value)) throw new Error('SECURITY_OBSERVATIONS_DISAGREE');
	return { ...first.value, providers_agree: true as const };
}
