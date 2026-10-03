import { env } from 'cloudflare:workers';
import { decodeFunctionData, encodeFunctionResult, toHex, zeroHash, type Hex } from 'viem';
import { vi } from 'vitest';
import { accountInspectionAbi } from '@gatopago/shared/v3/account-inspection';
import { hashSecurityManifest } from '@gatopago/shared/v3/authorizations';
import { accountSecurityInspectionAbi } from '@gatopago/shared/v3/security-inspection';
import { createCreationJobHandlers } from '../src/creation/creationJobHandlers';
import type { CreationWake } from '../src/creation/creationJobs';
import { creationInspectionScenario } from '@gatopago/test-fixtures/v3-creation-inspection';
import { creationReceiptScenario } from '@gatopago/test-fixtures/v3-creation-receipt';
import { finalityPin, finalityPolicyFixture } from '@gatopago/test-fixtures/v3-finality';
import { creationGas, deliveryNow, seedCreationDelivery } from './creationDelivery.fixture';
import { rpcReply } from '../test/rpc.fixture';

/** Full private pipeline, real D1 and ephemeral P256 grants; synthetic RPC evidence. */
export async function creationJobsScenario() {
	const inspection = creationInspectionScenario();
	const f = await seedCreationDelivery(undefined, { document: inspection.input.document, digest: inspection.input.expectedDigest });
	const evidence = creationReceiptScenario(false, f.signed), prepared = f.signed.prepared, message = prepared.message;
	const manifestHash = hashSecurityManifest({ accountId: message.accountId, generation: 3, securityVersion: 1n,
		previousManifestHash: zeroHash, policyHash: message.initialSecurityCommitment, chainScopeHash: message.chainScopeHash });
	const state = { sent: false, ambiguous: false, missing: false, sends: 0 };
	const configuration = { ...f.configuration, networks: [{ ...f.configuration.profiles[0],
		transport: { kind: 'bundler' as const, url: 'https://bundler.invalid/' }, finalityPolicy: finalityPin(finalityPolicyFixture(inspection.profile.deployment, deliveryNow())),
		providers: [{ operatorId: 'provider_a', url: 'https://observer-a.invalid/' }, { operatorId: 'provider_b', url: 'https://observer-b.invalid/' }] }],
		checkpoint: vi.fn(async () => ({ ...inspection.input.checkpoint })) };
	const reply = vi.fn(async (method: string, params: readonly unknown[]): Promise<unknown> => {
		if (state.missing && method === 'eth_getTransactionReceipt') return null;
		if (method === 'eth_call') {
			const call = params[0] as { data: Hex };
			let securityMethod, accountMethod;
			try { securityMethod = decodeFunctionData({ abi: accountSecurityInspectionAbi, data: call.data }).functionName; } catch { /* Other ABI */ }
			try { accountMethod = decodeFunctionData({ abi: accountInspectionAbi, data: call.data }).functionName; } catch { /* Other ABI */ }
			if (securityMethod === 'securitySnapshot') return encodeFunctionResult({ abi: accountSecurityInspectionAbi, functionName: securityMethod,
				result: [1n, 1n, BigInt(manifestHash), BigInt(message.chainScopeHash), 0n, 0n, 0n, 0n, 1n, 0n, 0n, 0n, 0n, 0n, 0n, 0n] });
			if (securityMethod === 'securityPolicy') return encodeFunctionResult({ abi: accountSecurityInspectionAbi, functionName: securityMethod,
				result: { ...prepared.policy, mode: 1, signers: [...prepared.policy.signers] } });
			if (accountMethod === 'inspectAccount') return encodeFunctionResult({ abi: accountInspectionAbi, functionName: accountMethod,
				result: { account: prepared.account, accountId: message.accountId, implementation: prepared.profile.deployment.components.implementation.address,
					securityVersion: 1n, storageLayoutHash: prepared.profile.deployment.storage_layout_hash } });
			if (accountMethod === 'proxyImplementation') return encodeFunctionResult({ abi: accountInspectionAbi, functionName: accountMethod,
				result: prepared.profile.deployment.components.implementation.address });
		}
		return evidence.request({ method, params });
	});
	const fetch = vi.spyOn(globalThis, 'fetch').mockImplementation(async (url, init) => {
		init?.signal?.throwIfAborted();
		if (String(url) !== 'https://bundler.invalid/') {
			if (!configuration.networks[0].providers.some((p) => p.url === String(url))) throw new Error('Unexpected provider');
			return rpcReply(init, request => state.sent ? reply(request.method, request.params) : inspection.request(request));
		}
		const request = JSON.parse(String(init?.body)) as { id: number; method: string; params: readonly unknown[] };
		let result: unknown;
		if (String(url) === 'https://bundler.invalid/') {
			switch (request.method) {
				case 'eth_chainId': result = toHex(prepared.chainId); break;
				case 'eth_supportedEntryPoints': result = [message.entryPoint]; break;
				case 'eth_estimateUserOperationGas': result = { verificationGasLimit: toHex(creationGas().verificationGasLimit),
					callGasLimit: toHex(creationGas().callGasLimit), preVerificationGas: toHex(creationGas().preVerificationGas) }; break;
				case 'eth_sendUserOperation':
					state.sent = true; state.sends++;
					if (state.ambiguous) throw new Error('synthetic secret upstream failure after send');
					result = f.signed.userOpHash; break;
				case 'eth_getUserOperationReceipt': result = state.missing ? null : { userOpHash: f.signed.userOpHash, receipt: evidence.receipt }; break;
				default: throw new Error('Unexpected bundler method');
			}
		} else {
			if (!configuration.networks[0].providers.some((p) => p.url === String(url))) throw new Error('Unexpected provider');
			result = state.sent ? await reply(request.method, request.params) : await inspection.request(request);
		}
		return Response.json({ jsonrpc: '2.0', id: request.id, result });
	});
	const sent: CreationWake[] = [];
	const send = vi.fn(async (body: CreationWake) => {
		sent.push(body); return { metadata: { metrics: { backlogCount: sent.length, backlogBytes: 0 } } };
	});
	const handlers = createCreationJobHandlers(() => configuration);
	const bindings = { ...env, CREATION_QUEUE_NAME: 'test-creation-queue', CREATION_JOBS: { send } };
	return { ...f, inspection, evidence, configuration, state, fetch, reply, sent, send, handlers, bindings };
}
