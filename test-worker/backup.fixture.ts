import { env } from 'cloudflare:workers';
import { vi } from 'vitest';
import {
  prepareBackupEnrollment,
  type BackupSignerEnrollment,
  type BackupEnrollmentInput,
} from '@gatopago/shared/v3/backup-enrollment';
import { deploymentDocumentDigest } from '@gatopago/shared/v3/deployment';
import { createResourceId, parseResourceId } from '@gatopago/shared/v3/primitives';
import { signerId, type SecurityPolicy } from '@gatopago/shared/v3/security-policy';
import { BackupRepository, type BackupProfiles } from '../src/security/backup';
import { backupFixture } from '@gatopago/test-fixtures/v3-backup';
import { deliveryNow } from './creationDelivery.fixture';
import { creationProjectionScenario } from './creationProjection.fixture';

/** Uses the existing signed creation → two-provider inspection → D1 projection fixture.
 * RPC responses/admission are synthetic, but the real Worker adapters and P-256/ECDSA run. */
export async function backupScenario() {
  const f = await creationProjectionScenario();
  await f.run();
  const projection = await env.WALLET_DB.prepare(
    'SELECT wallet_id,wallet_account_id FROM account_creation_projections WHERE initialization_id = ?',
  )
    .bind(f.id)
    .first();
  const walletId = parseResourceId('wallet', projection?.wallet_id),
    walletAccountId = parseResourceId('walletAccount', projection?.wallet_account_id);
  const keys = backupFixture();
  const nextPolicy: SecurityPolicy = {
    ...f.prepared.policy,
    mode: 'active',
    adminThreshold: 1,
    signers: [
      f.prepared.policy.signers[0],
      ...keys.input.nextPolicy.signers.filter((s) => s.kind === 0),
    ].sort((a, b) => signerId(a).localeCompare(signerId(b))),
  };
  const principal = { ...f.principal, expiresAt: deliveryNow() + 3600 };
  const profiles: BackupProfiles = vi.fn(async () => {
    const source = await f.journal.latest(f.id);
    if (source?.result.status !== 'observed' || source.result.finality === 'not_assessed')
      throw new Error('Expected synthetic finality');
    const document = JSON.stringify(f.prepared.profile.deployment),
      network = f.configuration.networks[0];
    return [
      {
        document,
        digest: deploymentDocumentDigest(document),
        rpcUrls: [network.providers[0].url, network.providers[1].url] as const,
        finalityPolicy: network.finalityPolicy,
        finalityEvidence: source.result.finality_evidence,
      },
    ];
  });
  const repository = (identity = principal, resolver: BackupProfiles | undefined = profiles) =>
    new BackupRepository(
      env.WALLET_DB,
      identity,
      f.configuration.scope,
      f.configuration.profiles,
      resolver,
    );
  const request = () => ({
    id: createResourceId('operation'),
    initializationId: f.id,
    walletId,
    walletAccountId,
    nextPolicy: structuredClone(nextPolicy),
    proposalValidUntil: deliveryNow() + 86400,
  });
  async function proofs(input: BackupEnrollmentInput): Promise<BackupSignerEnrollment[]> {
    const prepared = prepareBackupEnrollment(input, input.validAfter);
    return Promise.all(
      prepared.enrollments.map(async (r): Promise<BackupSignerEnrollment> => {
        const member = prepared.nextPolicy.signers[r.signerIndex];
        if (member.kind === 1)
          return {
            kind: 'webauthn',
            signerIndex: r.signerIndex,
            assertion: f.f.assertion(r.digest),
          };
        const key = keys.keys.find((key) => key.address.toLowerCase() === member.key);
        if (!key) throw new Error('Missing ephemeral factor');
        return {
          kind: 'ecdsa',
          signerIndex: r.signerIndex,
          signature: await key.sign({ hash: r.digest }),
        };
      }),
    );
  }
  f.fetch.mockClear();
  return { ...f, walletId, walletAccountId, principal, profiles, repository, request, proofs };
}
