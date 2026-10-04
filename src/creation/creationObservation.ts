import type { OperationTransport } from '../execution/operationTransport';
import { rpcEndpoint } from '../chainProviders';
import type { Hex } from 'viem';
import type { authorizeCreationOperation } from '@gatopago/shared/v3/creation-operation';
import { observeCreationReceipt } from '@gatopago/shared/v3/creation-receipt';
import { requireHash } from '@gatopago/shared/v3/deployment';
import { loadPinnedCreationProfile } from '@gatopago/shared/v3/initialization';
import {
  assessCheckpointFinality,
  loadPinnedFinalityPolicy,
  type FinalityPolicyPin,
} from '@gatopago/shared/v3/finality';
import { bundlerTransaction } from '../execution/operationTransport';
import { createInspectionClient } from '../chainInspection';

type SignedCreation = ReturnType<typeof authorizeCreationOperation>;
interface Configuration {
  readonly profileDocument: string;
  readonly transport?: OperationTransport;

  readonly finalityPolicy?: FinalityPolicyPin;

  readonly providers: readonly { readonly operatorId: string; readonly url: string }[];
}

export async function reconcileCreationObservation(
  signed: SignedCreation,
  configuration: Configuration,
  signal: AbortSignal,
  knownTransaction?: Hex,
) {
  const document = configuration.profileDocument;
  const profile = loadPinnedCreationProfile(document, signed.prepared.profileDigest);
  const finalityPolicy = configuration.finalityPolicy
    ? Object.freeze({ ...configuration.finalityPolicy })
    : undefined;
  if (finalityPolicy) loadPinnedFinalityPolicy(finalityPolicy, profile.deployment);
  if (configuration.providers.length !== 2)
    throw new Error('Exactly two independent creation observers required');
  const providers = configuration.providers.map((provider) => {
    if (!/^[a-z][a-z0-9_-]{1,63}$(?![\s\S])/.test(provider.operatorId))
      throw new Error('Invalid observer identity');
    return Object.freeze({ operatorId: provider.operatorId, url: rpcEndpoint(provider.url) });
  });
  if (
    new Set(providers.map((item) => item.operatorId)).size !== 2 ||
    new Set(providers.map((item) => new URL(item.url).hostname)).size !== 2
  )
    throw new Error('Creation observers overlap');
  const transport = structuredClone(configuration.transport);
  if (knownTransaction !== undefined) requireHash(knownTransaction);
  const deadline = AbortSignal.any([signal, AbortSignal.timeout(40_000)]);
  const base = {
    finality: 'not_assessed' as const,
    account_readiness: 'not_assessed' as const,
    provider_ids: Object.freeze(providers.map((item) => item.operatorId)),
  };
  let transaction = knownTransaction;
  try {
    deadline.throwIfAborted();
    if (transaction === undefined && transport?.kind === 'bundler')
      transaction = await bundlerTransaction(transport.url, signed.userOpHash, deadline);
    if (transaction === undefined)
      return Object.freeze({ ...base, status: 'not_observed' as const, transaction_hash: null });

    const observations = await Promise.allSettled(
      providers.map((provider) =>
        observeCreationReceipt(
          createInspectionClient(provider.url, deadline),
          signed,
          transaction!,
          document,
        ),
      ),
    );
    deadline.throwIfAborted();
    const [a, b] = observations;
    if (a.status === 'rejected' || b.status === 'rejected')
      return Object.freeze({
        ...base,
        status: 'unavailable' as const,
        transaction_hash: transaction,
      });
    if (JSON.stringify(a.value) !== JSON.stringify(b.value))
      return Object.freeze({
        ...base,
        status: 'disagreement' as const,
        transaction_hash: transaction,
      });
    if (a.value === null)
      return Object.freeze({
        ...base,
        status: 'not_observed' as const,
        transaction_hash: transaction,
      });
    if (!finalityPolicy)
      return Object.freeze({
        ...base,
        status: 'observed' as const,
        transaction_hash: transaction,
        observation: a.value,
      });
    const assessment = await assessCheckpointFinality(
      providers.map((provider) => createInspectionClient(provider.url, deadline)),
      { ...a.value, genesis_hash: profile.deployment.genesis_hash },
      finalityPolicy,
      deadline,
    );
    return Object.freeze({
      ...base,
      status: 'observed' as const,
      transaction_hash: transaction,
      observation: a.value,
      finality: assessment.status,
      finality_evidence: assessment,
    });
  } catch {
    return Object.freeze({
      ...base,
      status: 'unavailable' as const,
      transaction_hash: transaction ?? null,
    });
  }
}
