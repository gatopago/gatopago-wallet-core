import { zeroHash, type Hex } from 'viem';
import { hashSecurityManifest } from '@gatopago/shared/v3/authorizations';
import type {
  BackupSignerEnrollment,
  BackupEnrollmentInput,
} from '@gatopago/shared/v3/backup-enrollment';
import { deploymentDocumentDigest, requireHash } from '@gatopago/shared/v3/deployment';
import { assertFinalityAssessment } from '@gatopago/shared/v3/finality';
import {
  prepareInitialization,
  type InitializationInput,
} from '@gatopago/shared/v3/initialization';
import { parseAtomicAmount } from '@gatopago/shared/v3/primitives';
import { parseSecurityPolicyRecord as backupPolicy } from '@gatopago/shared/v3/security-policy-record';
export { backupPolicy };
import type { inspectOwnedWalletAccount } from '../accounts/inspection';
import { readAssertionRecord, writeAssertionRecord } from '@gatopago/shared/v3/assertion-record';

type Row = Record<string, unknown>;
export type BackupObservation = Extract<
  Awaited<ReturnType<typeof inspectOwnedWalletAccount>>,
  { status: 'recognized' }
>;
function row(value: unknown): Row {
  if (!value || typeof value !== 'object' || Array.isArray(value))
    throw new Error('Invalid backup record');
  return value as Row;
}
function integer(value: unknown, min = 0): number {
  if (typeof value !== 'number' || !Number.isSafeInteger(value) || value < min)
    throw new Error('Invalid backup integer');
  return value;
}
function boolean(value: unknown): boolean {
  if (typeof value !== 'boolean') throw new Error('Invalid backup boolean');
  return value;
}
function hex(value: unknown): Hex {
  if (
    typeof value !== 'string' ||
    value.length > 258 ||
    !/^0x(?:[0-9a-f]{2})+$(?![\s\S])/.test(value)
  )
    throw new Error('Invalid backup hex');
  return value as Hex;
}
function parse(value: unknown, max: number): unknown {
  if (typeof value !== 'string' || value.length > max)
    throw new Error('Invalid backup record size');
  return JSON.parse(value);
}

export function readBackupPolicy(value: unknown) {
  const policy = backupPolicy(parse(value, 12288));
  if (JSON.stringify(policy) !== value) throw new Error('Noncanonical backup policy');
  return policy;
}

export function backupSnapshot(observation: BackupObservation) {
  return JSON.stringify({
    checkpoint: observation.checkpoint,
    nonces: observation.security.nonces,
    upgrades_frozen: observation.security.upgrades_frozen,
    finality_evidence: observation.finality_evidence,
    observed_at: observation.security_observed_at,
    expires_at: observation.security_expires_at,
  });
}
export function readBackupSnapshot(value: unknown, input: InitializationInput) {
  const r = row(parse(value, 8192)),
    checkpoint = row(r.checkpoint),
    nonces = row(r.nonces);
  requireHash(checkpoint.block_hash);
  const blockNumber = parseAtomicAmount(checkpoint.block_number);
  const initial = prepareInitialization(input),
    deployment = initial.profile.deployment;
  const evidence = r.finality_evidence,
    target = row(row(evidence).target);
  requireHash(target.block_hash);
  assertFinalityAssessment(evidence, {
    network_id: deployment.network_id,
    genesis_hash: deployment.genesis_hash,
    block_hash: target.block_hash,
    block_number: parseAtomicAmount(target.block_number),
    block_timestamp: parseAtomicAmount(target.block_timestamp),
  });
  const observedAt = integer(r.observed_at, 1),
    expiresAt = integer(r.expires_at, observedAt + 1);

  if (
    evidence.status !== 'finalized' ||
    !evidence.checkpoint ||
    evidence.target.block_hash !== checkpoint.block_hash ||
    evidence.target.block_number !== blockNumber ||
    observedAt < evidence.assessed_at ||
    expiresAt > evidence.expires_at
  )
    throw new Error('Invalid backup finality');
  const observation: BackupEnrollmentInput['observation'] = {
    status: 'recognized',
    account: initial.account,
    account_id: initial.message.accountId,
    network_id: deployment.network_id,
    manifest_id: deployment.manifest_id,
    manifest_sha256: deploymentDocumentDigest(JSON.stringify(deployment)),
    checkpoint: { block_hash: checkpoint.block_hash, block_number: blockNumber },
    spend_readiness: 'not_assessed',
    implementation: deployment.components.implementation.address,
    security_version: '1',
    storage_layout_hash: deployment.storage_layout_hash,
    security: {
      phase: 'active_policy',
      policy: initial.policy,
      policy_hash: initial.message.initialSecurityCommitment,
      manifest_hash: hashSecurityManifest({
        accountId: initial.message.accountId,
        generation: 3,
        securityVersion: 1n,
        previousManifestHash: zeroHash,
        policyHash: initial.message.initialSecurityCommitment,
        chainScopeHash: initial.message.chainScopeHash,
      }),
      chain_scope_hash: initial.message.chainScopeHash,
      upgrades_frozen: boolean(r.upgrades_frozen),
      creation_valid_after: 0,
      creation_valid_until: 0,
      nonces: { spend: parseAtomicAmount(nonces.spend), admin: parseAtomicAmount(nonces.admin) },
      pending: null,
    },
  };
  const canonical = JSON.stringify({
    checkpoint: observation.checkpoint,
    nonces: observation.security.nonces,
    upgrades_frozen: observation.security.upgrades_frozen,
    finality_evidence: evidence,
    observed_at: observedAt,
    expires_at: expiresAt,
  });
  if (canonical !== value) throw new Error('Noncanonical backup snapshot');
  return { observation, observedAt, expiresAt, finalityEvidence: evidence };
}

export function backupCommitSnapshot(observation: BackupObservation) {
  if (!observation.security.pending) throw new Error('Missing pending backup');
  return JSON.stringify({
    security: backupSnapshot(observation),
    pending: observation.security.pending,
  });
}
export function readBackupCommitSnapshot(value: unknown, input: InitializationInput) {
  const r = row(parse(value, 12288)),
    base = readBackupSnapshot(r.security, input),
    p = row(r.pending);
  requireHash(p.hash);
  requireHash(p.previous_manifest_hash);
  requireHash(p.chain_scope_hash);
  const pending = {
    kind: integer(p.kind, 1),
    hash: p.hash,
    security_version: parseAtomicAmount(p.security_version),
    previous_manifest_hash: p.previous_manifest_hash,
    chain_scope_hash: p.chain_scope_hash,
    ready_at: integer(p.ready_at, 1),
    valid_until: integer(p.valid_until, 1),
  };
  if (
    pending.kind !== 1 ||
    pending.security_version !== '1' ||
    pending.valid_until < pending.ready_at ||
    JSON.stringify({ security: r.security, pending }) !== value
  )
    throw new Error('Invalid pending backup');
  return {
    ...base,
    observation: { ...base.observation, security: { ...base.observation.security, pending } },
  };
}

export function readBackupCommitConfirmation(
  value: unknown,
  input: InitializationInput,
  reviewed: ReturnType<typeof readBackupCommitSnapshot>,
) {
  const r = row(parse(value, 16384)),
    current = readBackupCommitSnapshot(r.current, input);
  const initial = prepareInitialization(input),
    acknowledgement = r.acknowledgement;
  assertFinalityAssessment(acknowledgement, {
    ...reviewed.finalityEvidence.target,
    network_id: initial.profile.deployment.network_id,
    genesis_hash: initial.profile.deployment.genesis_hash,
  });
  if (
    acknowledgement.status !== 'finalized' ||
    JSON.stringify({ current: r.current, acknowledgement }) !== value
  )
    throw new Error('Invalid reviewed checkpoint confirmation');
  return { current, acknowledgement };
}

export function backupProofs(
  owner: Parameters<typeof writeAssertionRecord>[0],
  enrollments: readonly BackupSignerEnrollment[],
) {
  if (!Array.isArray(enrollments) || enrollments.length > 16)
    throw new Error('Too many backup proofs');
  const proofs = enrollments
    .map((p) => {
      const signerIndex = integer(p.signerIndex);
      if (signerIndex > 15) throw new Error('Invalid backup proof index');
      if (p.kind === 'ecdsa') {
        if (
          typeof p.signature !== 'string' ||
          p.signature.length !== 132 ||
          !/^0x[0-9a-f]+$(?![\s\S])/.test(p.signature)
        )
          throw new Error('Invalid backup signature');
        return { signerIndex, kind: p.kind, signature: p.signature };
      }
      if (p.kind !== 'webauthn') throw new Error('Invalid backup proof kind');
      return { signerIndex, kind: p.kind, assertion: writeAssertionRecord(p.assertion) };
    })
    .sort((a, b) => a.signerIndex - b.signerIndex);
  if (new Set(proofs.map((p) => p.signerIndex)).size !== proofs.length)
    throw new Error('Duplicate backup proof');
  return JSON.stringify({ owner: writeAssertionRecord(owner), enrollments: proofs });
}
export function readBackupProofs(value: unknown) {
  const r = row(parse(value, 120000)),
    owner = readAssertionRecord(r.owner);
  if (!Array.isArray(r.enrollments) || r.enrollments.length > 16)
    throw new Error('Invalid backup proofs');
  const enrollments = r.enrollments.map((v: unknown): BackupSignerEnrollment => {
    const p = row(v),
      signerIndex = integer(p.signerIndex);
    if (p.kind === 'ecdsa') return { signerIndex, kind: 'ecdsa', signature: hex(p.signature) };
    if (p.kind === 'webauthn')
      return { signerIndex, kind: 'webauthn', assertion: readAssertionRecord(p.assertion) };
    throw new Error('Invalid backup proof kind');
  });
  if (backupProofs(owner, enrollments) !== value) throw new Error('Noncanonical backup proofs');
  return { owner, enrollments };
}
