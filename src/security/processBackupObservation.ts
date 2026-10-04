import { validateRpcProviders } from '../chainProviders';
import type { ResourceId } from '@gatopago/shared/v3/primitives';
import { loadPinnedFinalityPolicy } from '@gatopago/shared/v3/finality';
import { loadPinnedCreationProfile } from '@gatopago/shared/v3/initialization';
import { withDeadline } from '../deadline';
import { reconcileBackupObservation, type BackupObservationNetwork } from './backupObservation';
import { BackupObservationJournal } from './backupObservationJournal';

import type { CreationDeliveryConfiguration } from '../creation/creationDelivery';

interface Configuration extends Omit<CreationDeliveryConfiguration, 'profiles'> {
  readonly networks: readonly BackupObservationNetwork[];
}

export async function processBackupObservation(
  database: D1Database,
  id: ResourceId<'operation'>,
  configuration: Configuration,
  signal: AbortSignal,
) {
  signal.throwIfAborted();
  const networks = configuration.networks.map((n) => {
    const profile = loadPinnedCreationProfile(n.document, n.digest),
      finalityPolicy = Object.freeze({ ...n.finalityPolicy });
    loadPinnedFinalityPolicy(finalityPolicy, profile.deployment);
    return Object.freeze({
      document: n.document,
      digest: n.digest,
      finalityPolicy,
      providers: validateRpcProviders(n.providers),
    });
  });
  const journal = new BackupObservationJournal(database, { ...configuration, profiles: networks });
  const claim = await journal.claim(id);
  if (!claim) return 'idle' as const;
  const network = networks.find((n) => n.digest === claim.grant.profileDigest);
  if (!network) throw new Error('BACKUP_OBSERVATION_PROFILE');
  const previous = await journal.lastFinalizedReceipt(id);
  let result = await withDeadline(
    signal,
    Math.max(1, Math.min(40_000, claim.until * 1000 - Date.now())),
    (deadline) => reconcileBackupObservation(claim.grant, network, deadline),
  );
  if (
    previous &&
    result.status === 'observed' &&
    JSON.stringify(previous) !== JSON.stringify(result.observation)
  ) {
    result = Object.freeze({
      ...result,
      finality: 'reorg_detected',
      finality_evidence: Object.freeze({
        ...result.finality_evidence,
        status: 'reorg_detected',
        checkpoint: null,
        expires_at: result.finality_evidence.assessed_at,
      }),
    });
  }
  signal.throwIfAborted();
  return (await journal.append(claim, result)) ? result.status : ('lease_lost' as const);
}
