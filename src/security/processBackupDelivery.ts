import { validateRpcProviders, type RpcProvider } from '../chainProviders';
import { isAddress } from 'viem';
import {
  prepareBackupEnrollment,
  prepareBackupCommit,
} from '@gatopago/shared/v3/backup-enrollment';
import {
  assessCheckpointFinality,
  loadPinnedFinalityPolicy,
  type FinalityAssessment,
  type FinalityPolicyPin,
} from '@gatopago/shared/v3/finality';
import { loadPinnedCreationProfile } from '@gatopago/shared/v3/initialization';
import { UINT256_MAX, type ResourceId } from '@gatopago/shared/v3/primitives';
import { createInspectionClient } from '../chainInspection';
import { inspectFinalizedWalletSecurity } from '../finalizedSecurityInspection';
import { withDeadline } from '../deadline';
import { broadcastBackupTransaction } from './backupBroadcast';
import { BackupDeliveryRepository, type BackupDeliveryClaim } from './backupDelivery';
import { preflightBackupTransaction, quoteBackupTransaction } from './backupRpc';
import type { BackupSigner } from './backupSigner';
import { verifyBackupTransaction, type BackupSponsorPolicy } from './backupTransaction';
import type { CreationDeliveryConfiguration } from '../creation/creationDelivery';
import type { CreationProfilePin } from '../creation/initialization';

interface BackupDeliveryNetwork extends CreationProfilePin {
  readonly finalityPolicy: FinalityPolicyPin;
  readonly providers: readonly RpcProvider[];
  readonly sponsor: BackupSponsorPolicy;
  readonly signer: BackupSigner;
}
export interface BackupProcessorConfiguration extends Omit<
  CreationDeliveryConfiguration,
  'profiles'
> {
  readonly networks: readonly BackupDeliveryNetwork[];
  /** Fresh private observer output. Never caller-provided success, timestamp or checkpoint. */
  readonly finality: (
    profile: CreationProfilePin,
    signal: AbortSignal,
  ) => Promise<FinalityAssessment>;
}
const now = () => Math.floor(Date.now() / 1000);

/** Private coordinator: historical user consent != current authority. No public signing
 * endpoint, fresh JWT, consent renewal, replacement transaction or readiness projection.
 * The source checkpoint and account state are independently verified before signing and
 * again at broadcast. Accepted/uncertain work belongs to the observer, never this sender. */
export function createBackupDeliveryProcessor(configuration: BackupProcessorConfiguration) {
  const finality = configuration.finality;
  if (typeof finality !== 'function' || configuration.networks.length > 32)
    throw new Error('BACKUP_CONFIGURATION_INVALID');
  const networks = Object.freeze(
    configuration.networks.map((network) => {
      const profile = loadPinnedCreationProfile(network.document, network.digest);
      const pin = Object.freeze({ ...network.finalityPolicy });
      loadPinnedFinalityPolicy(pin, profile.deployment);
      const sponsor = Object.freeze({ ...network.sponsor });
      if (
        sponsor.networkId !== profile.deployment.network_id ||
        !isAddress(sponsor.operator, { strict: false }) ||
        /^0x0{40}$/i.test(sponsor.operator) ||
        sponsor.operator.toLowerCase() !== network.signer.operator.toLowerCase() ||
        typeof network.signer.sign !== 'function' ||
        [sponsor.maxGas, sponsor.maxFeePerGas, sponsor.maxExecutionFee].some(
          (n) => typeof n !== 'bigint' || n <= 0n || n > UINT256_MAX,
        ) ||
        typeof sponsor.maxPriorityFeePerGas !== 'bigint' ||
        sponsor.maxPriorityFeePerGas < 0n ||
        sponsor.maxPriorityFeePerGas > sponsor.maxFeePerGas
      )
        throw new Error('BACKUP_SPONSOR_INVALID');
      return Object.freeze({
        document: network.document,
        digest: network.digest,
        profile,
        finalityPolicy: pin,
        providers: validateRpcProviders(network.providers),
        sponsor,
        sign: network.signer.sign.bind(network.signer),
      });
    }),
  );
  if (new Set(networks.map((n) => n.digest)).size !== networks.length)
    throw new Error('BACKUP_CONFIGURATION_INVALID');
  const config = Object.freeze({
    environment: configuration.environment,
    scope: Object.freeze({ ...configuration.scope }),
    profiles: Object.freeze(
      networks.map((n) => Object.freeze({ document: n.document, digest: n.digest })),
    ),
  });
  async function inspect(
    claim: BackupDeliveryClaim,
    network: (typeof networks)[number],
    signal: AbortSignal,
  ) {
    signal.throwIfAborted();
    const r = claim.record,
      initial = r.initial.prepared;
    const source = await finality(
      Object.freeze({ document: network.document, digest: network.digest }),
      signal,
    );
    signal.throwIfAborted();
    const observation = await inspectFinalizedWalletSecurity(
      {
        document: JSON.stringify(network.profile.deployment),
        expectedDigest: r.manifest,
        initialSecurityCommitment: initial.message.initialSecurityCommitment,
        userSaltCommitment: initial.message.userSaltCommitment,
        rpcUrls: network.providers.map((p) => p.url),
        finalityPolicy: network.finalityPolicy,
        finalityEvidence: source,
      },
      signal,
    );
    if (observation.status !== 'recognized') throw new Error('BACKUP_STATE_UNRECOGNIZED');
    const original =
      r.commit?.reviewed.observation.checkpoint ?? r.backup.input.observation.checkpoint;
    if (
      BigInt(observation.checkpoint.block_number) < BigInt(original.block_number) ||
      (observation.checkpoint.block_number === original.block_number &&
        observation.checkpoint.block_hash !== original.block_hash)
    )
      throw new Error('BACKUP_CHECKPOINT_REGRESSED');
    let expiresAt = Math.min(observation.security_expires_at, claim.until);
    if (r.commit) {
      // Recompile ONLY to check current pending proposal/nonce/window. The commit's
      // signed acknowledgement still refers to its original reviewed checkpoint.
      prepareBackupCommit(
        r.backup.input,
        observation,
        r.commit.validAfter,
        r.commit.validUntil,
        now(),
      );
      const reviewed = await assessCheckpointFinality(
        network.providers.map((p) => createInspectionClient(p.url, signal)),
        {
          ...r.commit.reviewed.finalityEvidence.target,
          network_id: network.profile.deployment.network_id,
          genesis_hash: network.profile.deployment.genesis_hash,
        },
        network.finalityPolicy,
        signal,
      );
      if (reviewed.status !== 'finalized') throw new Error('BACKUP_REVIEWED_CHECKPOINT_INVALID');
      expiresAt = Math.min(expiresAt, reviewed.expires_at);
    } else if (
      prepareBackupEnrollment({ ...r.backup.input, observation }, now()).digest !==
      r.backup.prepared.digest
    ) {
      throw new Error('BACKUP_AUTHORITY_CHANGED');
    }
    signal.throwIfAborted();
    if (expiresAt <= now()) throw new Error('BACKUP_EVIDENCE_EXPIRED');
    return expiresAt;
  }
  return Object.freeze({
    async run(database: D1Database, id: ResourceId<'operation'>, signal: AbortSignal) {
      signal.throwIfAborted();
      const repository = new BackupDeliveryRepository(database, config),
        claim = await repository.claim(id);
      if (!claim) return 'not_claimed' as const;
      const network = networks.find((n) => n.digest === claim.record.initial.input.expectedDigest);
      if (!network) throw new Error('BACKUP_PROFILE_UNAVAILABLE');
      return withDeadline(
        signal,
        Math.max(1, Math.min(40_000, claim.until * 1000 - Date.now())),
        async (deadline) => {
          let raw: unknown;
          try {
            const expiresAt = await inspect(claim, network, deadline);
            let request = await repository.transactionRequest(claim, network.sponsor);
            if (request) await preflightBackupTransaction(request, network.providers, deadline);
            else {
              const quoted = await quoteBackupTransaction(
                claim.record.signed,
                network.sponsor,
                network.providers,
                deadline,
              );
              request = await repository.reserveTransaction(claim, network.sponsor, quoted.request);
            }
            if (!request) {
              await repository.retryBeforeSend(claim);
              return 'lease_lost' as const;
            }
            // Check DB revocation/lease once more after RPC. The signer receives a detached,
            // frozen envelope, never the mutable claim, user proofs or provider configuration.
            const current = await repository.transactionRequest(claim, network.sponsor);
            if (!current || current.unsigned !== request.unsigned) {
              await repository.retryBeforeSend(claim);
              return 'lease_lost' as const;
            }
            deadline.throwIfAborted();
            if (expiresAt <= now()) throw new Error('BACKUP_EVIDENCE_EXPIRED');
            raw = await withDeadline(deadline, 5000, (signingSignal) =>
              network.sign(id, current, signingSignal),
            );
            await verifyBackupTransaction(current, raw);
          } catch {
            // Only the sign-only/pre-send stage is retryable. Its durable nonce reservation
            // remains exact even if a signer succeeded but its response was lost.
            await repository.retryBeforeSend(claim);
            return 'deferred' as const;
          }
          // Do not catch ambiguous send-marker acknowledgements as safe retries.
          return broadcastBackupTransaction(
            repository,
            claim,
            network.sponsor,
            raw,
            network.providers,
            deadline,
            (freshSignal) => inspect(claim, network, freshSignal),
          );
        },
      );
    },
  });
}
