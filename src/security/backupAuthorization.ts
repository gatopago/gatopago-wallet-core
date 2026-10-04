import {
  authorizeBackupEnrollment,
  authorizeBackupCommit,
  prepareBackupEnrollment,
  prepareBackupCommit,
  type BackupEnrollmentInput,
} from '@gatopago/shared/v3/backup-enrollment';
import { deploymentDocumentDigest } from '@gatopago/shared/v3/deployment';
import type { InitializationInput } from '@gatopago/shared/v3/initialization';
import { parseResourceId } from '@gatopago/shared/v3/primitives';
import {
  readBackupCommitConfirmation,
  readBackupCommitSnapshot,
  readBackupPolicy,
  readBackupProofs,
  readBackupSnapshot,
} from './backupRecord';
import { readAssertionRecord } from '@gatopago/shared/v3/assertion-record';
import { WalletAccessError } from '../accounts/repository';

type Row = Record<string, unknown>;
function invalid(): never {
  throw new WalletAccessError('WALLET_DATA_INVALID');
}
function authTime(row: Row, authorizedAt: number | null) {
  const value = row.authorized_auth_time;
  if (authorizedAt === null) {
    if (value !== null) invalid();
    return null;
  }
  if (
    typeof value !== 'number' ||
    !Number.isSafeInteger(value) ||
    value < 1 ||
    value > authorizedAt
  )
    invalid();
  return value;
}
function checkpoint(
  original: BackupEnrollmentInput['observation']['checkpoint'],
  current: BackupEnrollmentInput['observation']['checkpoint'],
) {
  if (
    BigInt(current.block_number) < BigInt(original.block_number) ||
    (current.block_number === original.block_number && current.block_hash !== original.block_hash)
  )
    invalid();
}

/** Historical cryptographic reconstruction shared by owned HTTP and private delivery.
 * No fabricated Firebase identity, RPC, new signature, expiry extension or spending grant.
 * The caller must separately establish ownership/admission and check current authority. */
export async function restoreBackupAuthorization(row: Row, initialization: InitializationInput) {
  try {
    const id = parseResourceId('operation', row.id),
      initializationId = parseResourceId('operation', row.initialization_id);
    const walletId = parseResourceId('wallet', row.wallet_id),
      walletAccountId = parseResourceId('walletAccount', row.wallet_account_id);
    const validAfter = row.created_at,
      validUntil = row.expires_at,
      proposalValidUntil = row.proposal_expires_at,
      authorizedAt = row.authorized_at;
    if (
      typeof validAfter !== 'number' ||
      !Number.isSafeInteger(validAfter) ||
      typeof validUntil !== 'number' ||
      validUntil !== validAfter + 300 ||
      (authorizedAt !== null &&
        (typeof authorizedAt !== 'number' ||
          !Number.isSafeInteger(authorizedAt) ||
          authorizedAt < validAfter ||
          authorizedAt >= validUntil))
    )
      invalid();
    const authorizedAuthTime = authTime(row, authorizedAt);
    const nextPolicy = readBackupPolicy(row.policy_json),
      snapshot = readBackupSnapshot(row.snapshot_json, initialization);
    if (
      validAfter < snapshot.observedAt ||
      validAfter >= snapshot.expiresAt ||
      typeof proposalValidUntil !== 'number'
    )
      invalid();
    const input: BackupEnrollmentInput = {
      initialization,
      observation: snapshot.observation,
      nextPolicy,
      validAfter,
      validUntil,
      proposalValidUntil,
    };
    const prepared = prepareBackupEnrollment(input, validAfter);
    if (
      prepared.digest !== row.proposal_hash ||
      prepared.expectedManifestHash !== row.expected_manifest_hash
    )
      invalid();
    let signed: Awaited<ReturnType<typeof authorizeBackupEnrollment>> | null = null;
    if (authorizedAt === null) {
      if (
        row.authorization_json !== null ||
        row.authorization_snapshot_json !== null ||
        row.calldata_sha256 !== null
      )
        invalid();
    } else {
      const confirmation = readBackupSnapshot(row.authorization_snapshot_json, initialization);
      if (
        authorizedAt < confirmation.observedAt ||
        authorizedAt >= confirmation.expiresAt ||
        prepareBackupEnrollment({ ...input, observation: confirmation.observation }, authorizedAt)
          .digest !== prepared.digest
      )
        invalid();
      checkpoint(snapshot.observation.checkpoint, confirmation.observation.checkpoint);
      const proof = readBackupProofs(row.authorization_json);
      signed = await authorizeBackupEnrollment(input, proof.owner, proof.enrollments, authorizedAt);
      if (deploymentDocumentDigest(signed.data) !== row.calldata_sha256) invalid();
    }
    return {
      id,
      initializationId,
      walletId,
      walletAccountId,
      input,
      prepared,
      authorizedAt,
      authorizedAuthTime,
      signed,
      authorizationJson: row.authorization_json,
    };
  } catch {
    return invalid();
  }
}

export async function restoreBackupCommitAuthorization(
  row: Row,
  backup: Awaited<ReturnType<typeof restoreBackupAuthorization>>,
) {
  try {
    const id = parseResourceId('operation', row.id);
    if (row.backup_id !== backup.id || backup.authorizedAt === null || !backup.signed) invalid();
    const validAfter = row.valid_after,
      validUntil = row.valid_until,
      authorizedAt = row.authorized_at;
    if (
      typeof validAfter !== 'number' ||
      typeof validUntil !== 'number' ||
      (authorizedAt !== null &&
        (typeof authorizedAt !== 'number' ||
          !Number.isSafeInteger(authorizedAt) ||
          authorizedAt < validAfter ||
          authorizedAt >= validUntil))
    )
      invalid();
    const authorizedAuthTime = authTime(row, authorizedAt);
    const reviewed = readBackupCommitSnapshot(row.snapshot_json, backup.input.initialization);
    if (validAfter < reviewed.observedAt || validAfter >= reviewed.expiresAt) invalid();
    const compiled = prepareBackupCommit(
      backup.input,
      reviewed.observation,
      validAfter,
      validUntil,
      validAfter,
    );
    if (compiled.digest !== row.commit_digest) invalid();
    let signed: ReturnType<typeof authorizeBackupCommit> | null = null;
    if (authorizedAt === null) {
      if (
        row.assertion_body !== null ||
        row.confirmation_json !== null ||
        row.calldata_sha256 !== null
      )
        invalid();
    } else {
      const confirmation = readBackupCommitConfirmation(
        row.confirmation_json,
        backup.input.initialization,
        reviewed,
      );
      const current = confirmation.current,
        acknowledgement = confirmation.acknowledgement;
      if (
        authorizedAt < current.observedAt ||
        authorizedAt >= current.expiresAt ||
        authorizedAt < acknowledgement.assessed_at ||
        authorizedAt >= acknowledgement.expires_at
      )
        invalid();
      prepareBackupCommit(backup.input, current.observation, validAfter, validUntil, authorizedAt);
      checkpoint(reviewed.observation.checkpoint, current.observation.checkpoint);
      signed = authorizeBackupCommit(
        backup.input,
        reviewed.observation,
        validAfter,
        validUntil,
        readAssertionRecord(row.assertion_body),
        authorizedAt,
      );
      if (deploymentDocumentDigest(signed.data) !== row.calldata_sha256) invalid();
    }
    return {
      id,
      backup,
      reviewed,
      compiled,
      validAfter,
      validUntil,
      authorizedAt,
      authorizedAuthTime,
      signed,
      assertionBody: row.assertion_body,
    };
  } catch {
    return invalid();
  }
}
