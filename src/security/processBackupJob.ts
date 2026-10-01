import { validateRpcProviders } from '../chainProviders';
import { loadPinnedCreationProfile } from '@gatopago/shared/v3/initialization';
import { loadPinnedFinalityPolicy } from '@gatopago/shared/v3/finality';
import type { ResourceId } from '@gatopago/shared/v3/primitives';
import { BackupDeliveryRepository } from './backupDelivery';
import { BackupObservationJournal } from './backupObservationJournal';
import type { BackupObservationNetwork } from './backupObservation';

import { createBackupDeliveryProcessor, type BackupProcessorConfiguration } from './processBackupDelivery';
import { processBackupObservation } from './processBackupObservation';
import { processBackupProjection } from './processBackupProjection';
import type { CreationDeliveryConfiguration } from '../creation/creationDelivery';

export type BackupJobOutcome = { readonly state: 'ready'; readonly next: number }
 | { readonly state: 'observed'; readonly reason: 'proposal_finalized' | 'commit_finalized' }
 | { readonly state: 'expired'; readonly reason: 'consent_expired' }
 | { readonly state: 'review'; readonly reason: 'revoked' | 'execution_reverted' | 'observation_timeout' | 'reorg_detected' | 'delivery_exhausted' };
export interface BackupJobConfiguration extends Omit<CreationDeliveryConfiguration, 'profiles'> {
 readonly networks: readonly (BackupObservationNetwork & {
  readonly delivery?: Pick<BackupProcessorConfiguration['networks'][number], 'sponsor' | 'signer'>;
 })[];
 readonly finality?: BackupProcessorConfiguration['finality'];
}

/** One bounded iteration, not a polling loop. Sent operations remain observable
 * without a current sponsor or login. `observed` is historical evidence only;
 * a separate current-policy projection is required before enabling the account. */
export function createBackupProcessor(configuration: BackupJobConfiguration) {
 if (configuration.networks.length > 32 || new Set(configuration.networks.map((n) => n.digest)).size !== configuration.networks.length) {
  throw new Error('BACKUP_CONFIGURATION_INVALID');
 }
 const networks = Object.freeze(configuration.networks.map((n) => {
  const profile = loadPinnedCreationProfile(n.document, n.digest);
  const finalityPolicy = Object.freeze({ ...n.finalityPolicy }); loadPinnedFinalityPolicy(finalityPolicy, profile.deployment);
  return Object.freeze({ document: n.document, digest: n.digest, finalityPolicy, providers: validateRpcProviders(n.providers),
   delivery: n.delivery ? Object.freeze({ sponsor: Object.freeze({ ...n.delivery.sponsor }),
    signer: Object.freeze({ operator: n.delivery.signer.operator, sign: n.delivery.signer.sign.bind(n.delivery.signer) }) }) : undefined });
 }));
 const config = Object.freeze({ environment: configuration.environment, scope: Object.freeze({ ...configuration.scope }), profiles: networks });
 const deliveryNetworks = networks.flatMap((n) => n.delivery ? [{ ...n, ...n.delivery }] : []);
 const finality = configuration.finality;
 if (deliveryNetworks.length && !finality) throw new Error('BACKUP_FINALITY_REQUIRED');
 const sender = finality && deliveryNetworks.length ? createBackupDeliveryProcessor({ ...config, networks: deliveryNetworks, finality }) : null;
 return Object.freeze({ configuration: config, async run(database: D1Database, id: ResourceId<'operation'>, signal: AbortSignal): Promise<BackupJobOutcome> {
  signal.throwIfAborted();
  const grants = new BackupDeliveryRepository(database, config), journal = new BackupObservationJournal(database, config);
  const now = () => Math.floor(Date.now() / 1000);
  const later = (time: number): BackupJobOutcome => ({ state: 'ready', next: Math.max(now() + 5, Math.min(now() + 300, time)) });
  let state = await grants.status(id);
  const network = networks.find((n) => n.digest === state.profileDigest);
  if (!network) throw new Error('BACKUP_PROFILE_UNAVAILABLE');
  if (state.state === 'pending') {
   if (state.expires <= now()) { await grants.claim(id); state = await grants.status(id); }
   else {
    if (state.revoked) return { state: 'review', reason: 'revoked' };
    if (state.attempts >= 32) return { state: 'review', reason: 'delivery_exhausted' };
    if (state.next > now() || (state.until ?? 0) > now()) return later(Math.max(state.next, state.until ?? 0));
    if (!sender || !network.delivery) return later(now() + 300);
    await sender.run(database, id, signal); signal.throwIfAborted(); state = await grants.status(id);
   }
  }
  if (state.state === 'expired') return { state: 'expired', reason: 'consent_expired' };
  if (state.state === 'pending') return later(Math.max(state.next, state.until ?? 0));
  if (state.state === 'sending') {
   if ((state.until ?? 0) > now()) return later(state.until!);
   await grants.claim(id); // A crashed send becomes uncertain, never pending.
  }
  const inspectLatest = async (): Promise<BackupJobOutcome | null> => {
   const latest = await journal.latest(id), result = latest?.result;
   if (!result || result.status !== 'observed') return null;
   if (result.finality === 'reorg_detected') return { state: 'review', reason: 'reorg_detected' };
   if (result.finality !== 'finalized' || result.finality_evidence.expires_at <= now()
    || result.finality_evidence.policy_sha256 !== network.finalityPolicy.digest
    || [...result.provider_ids].sort().join(',') !== network.providers.map((p) => p.operatorId).sort().join(',')) return null;
   if (result.observation.outcome === 'execution_reverted') return { state: 'review', reason: 'execution_reverted' };
   if (state.kind === 'commit') {
    if (!finality) return null;
    const projected = await processBackupProjection(database, id, { ...config, networks: [network], finality }, signal);
    if (projected !== 'projected' && projected !== 'already_projected') return null;
   }
   return { state: 'observed', reason: state.kind === 'commit' ? 'commit_finalized' : 'proposal_finalized' };
  };
  const previous = await inspectLatest(); if (previous) return previous;
  if ((state.started ?? state.created) + 86400 <= now()) return { state: 'review', reason: 'observation_timeout' };
  await processBackupObservation(database, id, { ...config, networks: [network] }, signal); signal.throwIfAborted();
  const observed = await inspectLatest(); if (observed) return observed;
  const timing = await database.withSession('first-primary').prepare(`SELECT next_poll_at,lease_expires_at
   FROM account_backup_observation_jobs WHERE operation_id = ?`).bind(id).first<{ next_poll_at: number; lease_expires_at: number | null }>();
  if (!timing || !Number.isSafeInteger(timing.next_poll_at) || timing.next_poll_at < 0
   || (timing.lease_expires_at !== null && (!Number.isSafeInteger(timing.lease_expires_at) || timing.lease_expires_at < 0))) throw new Error('BACKUP_JOB_STORAGE');
  return later(Math.max(timing.next_poll_at, timing.lease_expires_at ?? 0));
 } });
}
