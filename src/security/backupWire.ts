import type { BackupSignerEnrollment } from '@gatopago/shared/v3/backup-enrollment';
import { parseInitializationProof } from '@gatopago/shared/v3/initialization-wire';
import { parseResourceId } from '@gatopago/shared/v3/primitives';
import { backupPolicy } from './backupRecord';

function fields(value: unknown, keys: readonly string[]): Record<string, unknown> {
  if (
    !value ||
    typeof value !== 'object' ||
    Array.isArray(value) ||
    Object.keys(value).length !== keys.length ||
    keys.some((key) => !Object.hasOwn(value, key))
  )
    throw new Error('Invalid backup fields');
  return value as Record<string, unknown>;
}

export function parseBackupRequest(value: unknown) {
  const r = fields(value, [
    'request_id',
    'initialization_id',
    'wallet_id',
    'wallet_account_id',
    'next_policy',
    'proposal_valid_until',
  ]);
  const p = fields(r.next_policy, [
    'mode',
    'signers',
    'spendThreshold',
    'adminThreshold',
    'upgradeDelaySeconds',
  ]);
  if (p.mode !== 'active' || !Array.isArray(p.signers) || p.signers.length > 16)
    throw new Error('Invalid backup policy');
  for (const signer of p.signers)
    fields(signer, ['kind', 'verifier', 'verifierCodeHash', 'key', 'roles']);
  const nextPolicy = backupPolicy(p);
  if (
    typeof r.proposal_valid_until !== 'number' ||
    !Number.isSafeInteger(r.proposal_valid_until) ||
    r.proposal_valid_until <= 0 ||
    r.proposal_valid_until >= 2 ** 48
  )
    throw new Error('Invalid proposal lifetime');
  return Object.freeze({
    id: parseResourceId('operation', r.request_id),
    initializationId: parseResourceId('operation', r.initialization_id),
    walletId: parseResourceId('wallet', r.wallet_id),
    walletAccountId: parseResourceId('walletAccount', r.wallet_account_id),
    nextPolicy,
    proposalValidUntil: r.proposal_valid_until,
  });
}

export function parseBackupAuthorization(value: unknown) {
  const r = fields(value, ['owner', 'enrollments']);
  if (!Array.isArray(r.enrollments) || r.enrollments.length > 16)
    throw new Error('Invalid enrollments');
  const owner = parseInitializationProof(r.owner);
  const enrollments = r.enrollments.map((value: unknown): BackupSignerEnrollment => {
    if (!value || typeof value !== 'object' || !('kind' in value))
      throw new Error('Invalid enrollment');
    const p = fields(
      value,
      value.kind === 'ecdsa'
        ? ['kind', 'signer_index', 'signature']
        : ['kind', 'signer_index', 'assertion'],
    );
    if (
      typeof p.signer_index !== 'number' ||
      !Number.isInteger(p.signer_index) ||
      p.signer_index < 0 ||
      p.signer_index > 15
    )
      throw new Error('Invalid signer index');
    if (p.kind === 'webauthn')
      return {
        kind: p.kind,
        signerIndex: p.signer_index,
        assertion: parseInitializationProof(p.assertion),
      };
    if (
      p.kind === 'ecdsa' &&
      typeof p.signature === 'string' &&
      /^0x[0-9a-f]{128}(1b|1c)$(?![\s\S])/.test(p.signature)
    ) {
      return { kind: p.kind, signerIndex: p.signer_index, signature: p.signature as `0x${string}` };
    }
    throw new Error('Invalid enrollment proof');
  });
  if (new Set(enrollments.map((p) => p.signerIndex)).size !== enrollments.length)
    throw new Error('Duplicate enrollment');
  return { owner, enrollments };
}

export function parseBackupCommitRequest(value: unknown) {
  return parseResourceId('operation', fields(value, ['request_id']).request_id);
}
