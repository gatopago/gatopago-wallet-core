import { resumeSubmission } from '../execution/operationTransport';
import type { OperationTransport } from '../execution/operationTransport';
import { SponsorshipBudget } from '../sponsorship/budget';
import { rpcEndpoint } from '../chainProviders';
import type { InspectionCheckpoint } from '@gatopago/shared/v3/account-inspection';
import { loadPinnedFinalityPolicy, type FinalityPolicyPin } from '@gatopago/shared/v3/finality';
import { loadPinnedCreationProfile } from '@gatopago/shared/v3/initialization';
import type { ResourceId } from '@gatopago/shared/v3/primitives';

import { CreationDeliveryRepository, type CreationDeliveryConfiguration } from './creationDelivery';
import { CreationObservationJournal } from './creationObservationJournal';
import type { CreationJobOutcome } from './creationJobs';
import type { CreationProfilePin } from './initialization';
import { processCreationDelivery } from './processCreationDelivery';
import { processCreationObservation } from './processCreationObservation';
import { processCreationProjection } from './processCreationProjection';

interface CreationJobNetwork extends CreationProfilePin {
  readonly transport: OperationTransport;
  readonly finalityPolicy: FinalityPolicyPin;
  readonly providers: readonly { readonly operatorId: string; readonly url: string }[];
}
export interface CreationProcessorConfiguration extends Omit<
  CreationDeliveryConfiguration,
  'profiles'
> {
  readonly networks: readonly CreationJobNetwork[];
  readonly relayerKey?: `0x${string}`;
  readonly checkpoint: (
    network: CreationJobNetwork,
    signal: AbortSignal,
  ) => Promise<InspectionCheckpoint>;
}

export function createCreationProcessor(configuration: CreationProcessorConfiguration) {
  const networks = configuration.networks.map((network) => {
    const profile = loadPinnedCreationProfile(network.document, network.digest);
    const finalityPolicy = Object.freeze({ ...network.finalityPolicy });
    loadPinnedFinalityPolicy(finalityPolicy, profile.deployment);
    const providers = network.providers.map((p) =>
      Object.freeze({ operatorId: p.operatorId, url: rpcEndpoint(p.url) }),
    );
    if (
      providers.length !== 2 ||
      providers.some((p) => !/^[a-z][a-z0-9_-]{1,63}$(?![\s\S])/.test(p.operatorId)) ||
      new Set(providers.map((p) => p.operatorId)).size !== 2 ||
      new Set(providers.map((p) => new URL(p.url).hostname)).size !== 2
    )
      throw new Error('CREATION_OBSERVERS_OVERLAP');
    return Object.freeze({
      document: network.document,
      digest: network.digest,
      finalityPolicy,
      providers: Object.freeze(providers),
      transport: structuredClone(network.transport),
    });
  });
  const config = Object.freeze({
    environment: configuration.environment,
    scope: Object.freeze({ ...configuration.scope }),
    profiles: Object.freeze(networks),
  });
  const checkpoint = configuration.checkpoint;
  return Object.freeze({
    configuration: config,
    async run(
      database: D1Database,
      id: ResourceId<'operation'>,
      signal: AbortSignal,
    ): Promise<CreationJobOutcome> {
      const grants = new CreationDeliveryRepository(database, config);
      const journal = new CreationObservationJournal(database, config);
      const db = database.withSession('first-primary');
      const now = () => Math.floor(Date.now() / 1000);
      const later = (when: number): CreationJobOutcome => ({
        state: 'ready',
        next: Math.max(now() + 5, Math.min(now() + 300, when)),
      });
      async function lifecycle() {
        signal.throwIfAborted();
        const row = await db
          .prepare(
            `SELECT b.*, i.profile_sha256, u.disabled_at, u.auth_not_before, o.authorized_auth_time,
				j.next_poll_at, j.lease_expires_at AS observation_lease
				FROM account_creation_outbox b JOIN account_initializations i ON i.id = b.initialization_id
				JOIN account_creation_operations o ON o.initialization_id = i.id JOIN users u ON u.id = i.user_id
				LEFT JOIN account_creation_observation_jobs j ON j.initialization_id = i.id
				WHERE i.id = ? AND u.environment = ?`,
          )
          .bind(id, config.environment)
          .first<Record<string, unknown>>();
        if (
          !row ||
          typeof row.state !== 'string' ||
          !['pending', 'sending', 'uncertain', 'accepted', 'expired'].includes(row.state) ||
          ![
            'created_at',
            'expires_at',
            'next_attempt_at',
            'auth_not_before',
            'authorized_auth_time',
          ].every(
            (k) => typeof row[k] === 'number' && Number.isSafeInteger(row[k]) && row[k] >= 0,
          ) ||
          !['lease_expires_at', 'next_poll_at', 'observation_lease', 'disabled_at'].every(
            (k) =>
              row[k] === null ||
              (typeof row[k] === 'number' && Number.isSafeInteger(row[k]) && row[k] >= 0),
          )
        )
          throw new Error('CREATION_JOB_STORAGE');
        const network = networks.find((n) => n.digest === row.profile_sha256);
        if (!network) throw new Error('CREATION_PROFILE_UNAVAILABLE');
        return {
          state: row.state,
          network,
          expires: Number(row.expires_at),
          created: Number(row.created_at),
          next: Number(row.next_attempt_at),
          lease: Number(row.lease_expires_at),
          poll: Math.max(Number(row.next_poll_at), Number(row.observation_lease)),
          revoked:
            row.disabled_at !== null ||
            Number(row.auth_not_before) > Number(row.authorized_auth_time),
        };
      }
      let state = await lifecycle();
      if (state.state === 'pending') {
        if (state.expires <= now()) {
          await grants.claim(id);
          return { state: 'complete', reason: 'expired' };
        }
        if (state.revoked) return { state: 'review', reason: 'revoked' };
        if (state.lease > now() || state.next > now())
          return later(Math.max(state.lease, state.next));
        const fresh = await checkpoint(state.network, signal);
        signal.throwIfAborted();
        await processCreationDelivery(
          database,
          id,
          {
            ...config,
            relayerKey: configuration.relayerKey,
            networks: [
              { ...state.network, rpcUrl: state.network.providers[0].url, checkpoint: fresh },
            ],
          },
          signal,
        );
      } else if (state.state === 'sending' && state.lease <= now()) {
        await grants.claim(id);
      }
      state = await lifecycle();
      if (state.state === 'expired') return { state: 'complete', reason: 'expired' };
      if (state.state === 'pending') return later(Math.max(state.lease, state.next));
      const processing = { ...config, networks: [state.network] };
      const existing = await db
        .prepare(
          'SELECT initialization_id FROM account_creation_projections WHERE initialization_id = ?',
        )
        .bind(id)
        .first();
      if (
        existing &&
        (await processCreationProjection(database, id, processing, signal)) === 'already_projected'
      ) {
        return { state: 'complete', reason: 'projected' };
      }

      const latest = await journal.latest(id);
      if (
        latest?.result.status === 'observed' &&
        latest.result.finality === 'finalized' &&
        latest.result.finality_evidence.expires_at > now()
      ) {
        await new SponsorshipBudget(database).settle(
          latest.result.observation.user_op_hash,
          BigInt(latest.result.observation.actual_gas_cost),
          latest.result.observation.transaction_hash,
        );
        if (latest.result.observation.outcome === 'execution_reverted')
          return { state: 'review', reason: 'execution_reverted' };
        const projected = await processCreationProjection(database, id, processing, signal);
        if (projected === 'projected' || projected === 'already_projected')
          return { state: 'complete', reason: 'projected' };
      }
      if (state.created + 86400 <= now()) return { state: 'review', reason: 'observation_timeout' };
      if (state.poll > now()) return later(state.poll);
      const grant = await grants.observationGrant(id);
      if (grant) await resumeSubmission(database, grant.signed.userOpHash, signal);
      await processCreationObservation(database, id, processing, signal);
      signal.throwIfAborted();
      const observed = await journal.latest(id);
      if (observed?.result.status === 'observed' && observed.result.finality === 'finalized') {
        if (observed.result.observation.outcome === 'execution_reverted')
          return { state: 'review', reason: 'execution_reverted' };
        const projected = await processCreationProjection(database, id, processing, signal);
        if (projected === 'projected' || projected === 'already_projected')
          return { state: 'complete', reason: 'projected' };
      }
      return later((await lifecycle()).poll);
    },
  });
}
