import { createPublicClient, custom } from 'viem';
import type { AccountInspectionInput } from '@gatopago/shared/v3/account-inspection';
import {
  inspectCreationDeployment,
  type CreationInspectionInput,
} from '@gatopago/shared/v3/creation-inspection';
import { inspectAccountSecurity } from '@gatopago/shared/v3/security-inspection';
import { rpcEndpoint } from './chainProviders';
import { inspectionRpc } from './inspectionRpc';

export function createInspectionClient(rpcUrl: string, signal: AbortSignal, batch = false) {
  const url = rpcEndpoint(rpcUrl);
  return createPublicClient({
    cacheTime: 0,
    batch: { multicall: false },
    ccipRead: false,
    transport: custom(inspectionRpc(url, signal, batch), {
      retryCount: 0,
      name: 'V3 bounded inspection',
      key: 'v3-inspection',
    }),
  });
}

export async function inspectWalletCreationProfile(
  input: CreationInspectionInput,
  rpcUrl: string,
  signal: AbortSignal,
) {
  const deadline = AbortSignal.any([signal, AbortSignal.timeout(30_000)]);
  return inspectCreationDeployment(createInspectionClient(rpcUrl, deadline, true), input);
}

export async function inspectWalletSecurity(
  input: AccountInspectionInput,
  rpcUrls: readonly string[],
  signal: AbortSignal,
) {
  const urls = [...rpcUrls];
  if (urls.length !== 2 || new Set(urls.map((url) => new URL(url).hostname)).size !== 2)
    throw new Error('SECURITY_RPC_CONFIGURATION');
  const deadline = AbortSignal.any([signal, AbortSignal.timeout(30_000)]);
  const clients = urls.map((url) => createInspectionClient(url, deadline));
  const detached = Object.freeze({ ...input, checkpoint: Object.freeze({ ...input.checkpoint }) });
  const results = await Promise.allSettled(
    clients.map((client) => inspectAccountSecurity(client, detached)),
  );
  deadline.throwIfAborted();
  const first = results[0],
    second = results[1];
  if (first.status === 'rejected') throw first.reason;
  if (second.status === 'rejected') throw second.reason;
  if (JSON.stringify(first.value) !== JSON.stringify(second.value))
    throw new Error('SECURITY_OBSERVATIONS_DISAGREE');
  return { ...first.value, providers_agree: true as const };
}
