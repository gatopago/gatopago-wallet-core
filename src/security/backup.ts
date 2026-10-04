import { AUTHORIZED_USER, authorizationValues } from '../auth/authorization';
import {
  authorizeBackupEnrollment,
  authorizeBackupCommit,
  prepareBackupEnrollment,
  prepareBackupCommit,
  type BackupSignerEnrollment,
  type BackupEnrollmentInput,
} from '@gatopago/shared/v3/backup-enrollment';
import { deploymentDocumentDigest } from '@gatopago/shared/v3/deployment';
import { assessCheckpointFinality, type FinalityAssessment } from '@gatopago/shared/v3/finality';
import { prepareInitialization } from '@gatopago/shared/v3/initialization';
import { parseResourceId, type ResourceId } from '@gatopago/shared/v3/primitives';
import type { SecurityPolicy } from '@gatopago/shared/v3/security-policy';
import type { WebAuthnAssertionBytes, WebAuthnScope } from '@gatopago/shared/v3/webauthn';
import type { Principal } from '../auth/principal';
import { createInspectionClient } from '../chainInspection';
import { InitializationRepository, type CreationProfilePin } from '../creation/initialization';
import { inspectOwnedWalletAccount, type InspectionProfile } from '../accounts/inspection';
import { WalletAccessError, WalletRepository } from '../accounts/repository';
import {
  backupCommitSnapshot,
  backupPolicy,
  backupProofs,
  backupSnapshot,
  readBackupCommitConfirmation,
  readBackupCommitSnapshot,
  readBackupProofs,
  readBackupSnapshot,
} from './backupRecord';
import {
  restoreBackupAuthorization,
  restoreBackupCommitAuthorization,
} from './backupAuthorization';
import { readAssertionRecord, writeAssertionRecord } from '@gatopago/shared/v3/assertion-record';

type Row = Record<string, unknown>;
type Owned = Awaited<ReturnType<WalletRepository['ownedAccount']>>;
/** Server-only admission/finality resolver; never a request body or a persisted success.
 * It must assess a fresh common finalized checkpoint for the owned, pinned network. */
export type BackupProfiles = (
  owned: Owned,
  signal: AbortSignal,
) => Promise<readonly InspectionProfile[]>;
interface Request {
  readonly id: ResourceId<'operation'>;
  readonly initializationId: ResourceId<'operation'>;
  readonly walletId: ResourceId<'wallet'>;
  readonly walletAccountId: ResourceId<'walletAccount'>;
  readonly nextPolicy: SecurityPolicy;
  readonly proposalValidUntil: number;
}
export class BackupError extends Error {
  constructor(
    readonly code:
      | 'BACKUP_EXPIRED'
      | 'BACKUP_CONFLICT'
      | 'BACKUP_LIMIT'
      | 'BACKUP_PROFILE_UNAVAILABLE'
      | 'BACKUP_STATE_CHANGED'
      | 'BACKUP_REQUIRED'
      | 'INVALID_BACKUP_PROOF',
  ) {
    super(code);
    this.name = 'BackupError';
  }
}
const now = () => Math.floor(Date.now() / 1000);
const invalid = () => new WalletAccessError('WALLET_DATA_INVALID');

/** Owner-scoped optional backup enrollment, with separate prepare and commit consents.
 * Authorization atomically records durable delivery work. No HTTP broadcast, automatic
 * nonce retry, onchain execution, projection backup or receive/spend admission occurs here.
 * Instantiate per request. The default profile resolver denies all networks. */
export class BackupRepository {
  private readonly db: D1DatabaseSession;
  private readonly wallets: WalletRepository;
  private readonly initializations: InitializationRepository;
  private readonly identity: Principal;
  constructor(
    database: D1Database,
    identity: Principal,
    scope: WebAuthnScope,
    profiles: readonly CreationProfilePin[],
    private readonly resolveProfiles: BackupProfiles = async () => {
      throw new BackupError('BACKUP_PROFILE_UNAVAILABLE');
    },
  ) {
    this.identity = Object.freeze({ ...identity });
    this.db = database.withSession('first-primary');
    this.wallets = new WalletRepository(database, this.identity);
    this.initializations = new InitializationRepository(database, this.identity, scope, profiles);
  }
  private auth() {
    return authorizationValues(this.identity);
  }
  private select(id: ResourceId<'operation'>) {
    return this.db
      .prepare(
        `SELECT a.* FROM account_backups a JOIN users u ON u.id = a.user_id
   WHERE a.id = ? AND ${AUTHORIZED_USER}`,
      )
      .bind(id, ...this.auth());
  }
  private async context(
    initializationId: ResourceId<'operation'>,
    walletId: ResourceId<'wallet'>,
    walletAccountId: ResourceId<'walletAccount'>,
  ) {
    const owned = await this.wallets.ownedAccount(walletId, walletAccountId);
    const source = await this.initializations.readAuthorized(initializationId),
      initial = prepareInitialization(source.input);
    if (
      owned.account_id !== initial.message.accountId ||
      owned.address !== initial.account.toLowerCase() ||
      owned.network_id !== initial.profile.deployment.network_id ||
      owned.deployment_state !== 'active' ||
      owned.deployment_manifest_sha256 !==
        deploymentDocumentDigest(JSON.stringify(initial.profile.deployment))
    )
      throw invalid();
    return { owned, source, initial, initializationId, walletId, walletAccountId };
  }
  private async observe(
    c: Awaited<ReturnType<BackupRepository['context']>>,
    signal: AbortSignal,
    reviewed?: FinalityAssessment['target'],
  ) {
    signal.throwIfAborted();
    // Use the same detached server admission for state inspection and acknowledgement.
    // The resolver's caller must not be able to replace an RPC/policy between those awaits.
    const profiles = structuredClone(await this.resolveProfiles(c.owned, signal));
    const observed = await inspectOwnedWalletAccount(
      this.wallets,
      c.walletId,
      c.walletAccountId,
      profiles,
      signal,
    );
    if (observed.status !== 'recognized') throw new BackupError('BACKUP_STATE_CHANGED');
    let acknowledgement: FinalityAssessment | null = null;
    if (reviewed) {
      const matching = profiles.filter((p) => p.digest === c.owned.deployment_manifest_sha256);
      if (matching.length !== 1) throw new BackupError('BACKUP_PROFILE_UNAVAILABLE');
      const p = matching[0],
        deployment = c.initial.profile.deployment;
      acknowledgement = await assessCheckpointFinality(
        p.rpcUrls.map((url) => createInspectionClient(url, signal)),
        {
          ...reviewed,
          network_id: deployment.network_id,
          genesis_hash: deployment.genesis_hash,
        },
        p.finalityPolicy,
        signal,
      );
      if (acknowledgement.status !== 'finalized') throw new BackupError('BACKUP_STATE_CHANGED');
    }
    signal.throwIfAborted();
    const expires = Math.min(
      observed.security_expires_at,
      acknowledgement?.expires_at ?? Number.MAX_SAFE_INTEGER,
    );
    if (now() >= expires) throw new BackupError('BACKUP_EXPIRED');
    return { ...observed, security_expires_at: expires, acknowledgement };
  }
  /** SQL rechecks ownership, session cutoff, exact identity, original consent/key and deployment
   * pins at the write, not merely in an earlier RPC/GET. No database snapshot grants money rights. */
  private guard(c: Awaited<ReturnType<BackupRepository['context']>>) {
    const o = c.owned,
      i = c.initial;
    return {
      sql: `FROM wallet_accounts a JOIN wallets w ON w.id = a.wallet_id
   JOIN users u ON u.id = w.user_id
   JOIN account_initializations i ON i.user_id = u.id
   JOIN webauthn_credentials k ON k.id = i.credential_ref AND k.user_id = u.id
   WHERE ${AUTHORIZED_USER} AND unixepoch() < ? AND i.id = ? AND a.id = ? AND w.id = ?
   AND w.status = 'active'
   AND w.account_id = ? AND w.initial_security_commitment = ? AND w.user_salt_commitment = ? AND w.canonical_address = ?
   AND a.address = w.canonical_address AND a.deployment_state = 'active'
   AND a.deployment_manifest_sha256 = ? AND a.network_id = ? AND i.approval_digest = ? AND i.authorized_at IS NOT NULL
   AND i.profile_sha256 = ? AND i.public_key = ? AND k.public_key = i.public_key AND k.rp_id = ? AND k.origin = ?`,
      values: [
        ...this.auth(),
        this.identity.expiresAt,
        c.initializationId,
        c.walletAccountId,
        c.walletId,
        o.account_id,
        o.initial_security_commitment,
        o.user_salt_commitment,
        o.address,
        o.deployment_manifest_sha256,
        o.network_id,
        i.digest,
        i.profileDigest,
        c.source.input.publicKey,
        c.source.input.scope.rpId,
        c.source.input.scope.origin,
      ],
    };
  }
  private async decode(row: Row | null) {
    if (!row) throw new WalletAccessError('NOT_FOUND');
    const initializationId = parseResourceId('operation', row.initialization_id);
    const walletId = parseResourceId('wallet', row.wallet_id),
      walletAccountId = parseResourceId('walletAccount', row.wallet_account_id);
    const c = await this.context(initializationId, walletId, walletAccountId);
    return { ...(await restoreBackupAuthorization(row, c.source.input)), c };
  }
  private checkpoint(
    original: BackupEnrollmentInput['observation']['checkpoint'],
    current: BackupEnrollmentInput['observation']['checkpoint'],
  ) {
    if (
      BigInt(current.block_number) < BigInt(original.block_number) ||
      (current.block_number === original.block_number && current.block_hash !== original.block_hash)
    )
      throw new BackupError('BACKUP_STATE_CHANGED');
  }
  private receipt(record: Awaited<ReturnType<BackupRepository['decode']>>) {
    return Object.freeze({
      backup_id: record.id,
      initialization_id: record.c.initializationId,
      wallet_id: record.c.walletId,
      wallet_account_id: record.c.walletAccountId,
      state:
        record.authorizedAt !== null
          ? ('authorized' as const)
          : now() >= record.input.validUntil
            ? ('expired' as const)
            : ('prepared' as const),
      proposal_hash: record.prepared.digest,
      expected_manifest_hash: record.prepared.expectedManifestHash,
      valid_after: record.input.validAfter,
      valid_until: record.input.validUntil,
      proposal_valid_until: record.input.proposalValidUntil,
      backup_assessment: 'not_assessed' as const,
      receive_enabled: false as const,
      spend_enabled: false as const,
    });
  }
  /** Internal owned restoration for UI composition. No RPC, writes, renewal or private proof
   * disclosure. The original input allows the caller to independently reconstruct challenges. */
  async read(id: ResourceId<'operation'>) {
    parseResourceId('operation', id);
    await this.wallets.getSession();
    const record = await this.decode(await this.select(id).first<Row>());
    await this.context(record.c.initializationId, record.c.walletId, record.c.walletAccountId);
    return { ...this.receipt(record), input: record.input };
  }
  async prepare(request: Request, signal: AbortSignal) {
    const id = parseResourceId('operation', request.id),
      initializationId = parseResourceId('operation', request.initializationId);
    const walletId = parseResourceId('wallet', request.walletId),
      walletAccountId = parseResourceId('walletAccount', request.walletAccountId);
    const nextPolicy = backupPolicy(request.nextPolicy),
      policyJson = JSON.stringify(nextPolicy);
    const proposalValidUntil = request.proposalValidUntil;
    if (!Number.isSafeInteger(proposalValidUntil)) throw invalid();
    signal.throwIfAborted();
    const c = await this.context(initializationId, walletId, walletAccountId);
    const previous = await this.select(id).first<Row>();
    if (previous) {
      const record = await this.decode(previous);
      if (
        record.c.initializationId !== initializationId ||
        record.c.walletId !== walletId ||
        record.c.walletAccountId !== walletAccountId ||
        previous.policy_json !== policyJson ||
        record.input.proposalValidUntil !== proposalValidUntil
      )
        throw new BackupError('BACKUP_CONFLICT');
      if (record.authorizedAt === null && now() >= record.input.validUntil)
        throw new BackupError('BACKUP_EXPIRED');
      signal.throwIfAborted();
      return this.read(id);
    }
    const observation = await this.observe(c, signal),
      validAfter = now();
    const input: BackupEnrollmentInput = {
      initialization: c.source.input,
      nextPolicy,
      observation,
      validAfter,
      validUntil: validAfter + 300,
      proposalValidUntil,
    };
    const prepared = prepareBackupEnrollment(input, validAfter),
      snapshotJson = backupSnapshot(observation);
    readBackupSnapshot(snapshotJson, c.source.input);
    signal.throwIfAborted();
    const guard = this.guard(c);
    const result = await this.db
      .prepare(
        `INSERT INTO account_backups
   (id,user_id,initialization_id,wallet_id,wallet_account_id,policy_json,snapshot_json,proposal_hash,expected_manifest_hash,created_at,expires_at,proposal_expires_at)
   SELECT ?,u.id,i.id,w.id,a.id,?,?,?,?,?,?,? ${guard.sql} AND unixepoch() < ?
   AND (SELECT count(*) FROM account_backups x WHERE x.user_id = u.id AND x.created_at > ?) < 24
   AND (SELECT count(*) FROM account_backups x WHERE x.user_id = u.id AND x.created_at > ?) < 6
   ON CONFLICT(id) DO NOTHING`,
      )
      .bind(
        id,
        policyJson,
        snapshotJson,
        prepared.digest,
        prepared.expectedManifestHash,
        validAfter,
        input.validUntil,
        proposalValidUntil,
        ...guard.values,
        observation.security_expires_at,
        validAfter - 86400,
        validAfter - 600,
      )
      .run();
    if (!result.success || ![0, 1].includes(result.meta.changes)) throw invalid();
    await this.context(initializationId, walletId, walletAccountId);
    signal.throwIfAborted();
    const stored = await this.select(id).first<Row>();
    if (!stored) {
      if (now() >= observation.security_expires_at) throw new BackupError('BACKUP_STATE_CHANGED');
      throw new BackupError('BACKUP_LIMIT');
    }
    if (
      stored.initialization_id !== initializationId ||
      stored.wallet_id !== walletId ||
      stored.wallet_account_id !== walletAccountId ||
      stored.policy_json !== policyJson ||
      stored.proposal_expires_at !== proposalValidUntil
    )
      throw new BackupError('BACKUP_CONFLICT');
    return this.read(id);
  }
  async authorize(
    id: ResourceId<'operation'>,
    owner: WebAuthnAssertionBytes,
    enrollments: readonly BackupSignerEnrollment[],
    signal: AbortSignal,
  ) {
    parseResourceId('operation', id);
    // Canonical serialization copies every mutable signature buffer before the first await.
    const authorizationJson = backupProofs(owner, enrollments),
      proof = readBackupProofs(authorizationJson);
    signal.throwIfAborted();
    await this.wallets.getSession();
    const record = await this.decode(await this.select(id).first<Row>());
    if (record.authorizedAt !== null) {
      if (record.authorizationJson !== authorizationJson) throw new BackupError('BACKUP_CONFLICT');
      await this.context(record.c.initializationId, record.c.walletId, record.c.walletAccountId);
      signal.throwIfAborted();
      return this.receipt(record);
    }
    if (now() >= record.input.validUntil) throw new BackupError('BACKUP_EXPIRED');
    // Reject unrelated/missing proofs before expensive RPC, but do not persist until the
    // fresh chain state and expiry checks below agree with the exact signed proposal.
    let signed: Awaited<ReturnType<typeof authorizeBackupEnrollment>>;
    try {
      signed = await authorizeBackupEnrollment(record.input, proof.owner, proof.enrollments, now());
    } catch {
      throw new BackupError('INVALID_BACKUP_PROOF');
    }
    const observation = await this.observe(record.c, signal);
    const current = prepareBackupEnrollment({ ...record.input, observation }, now());
    this.checkpoint(record.input.observation.checkpoint, observation.checkpoint);
    if (current.digest !== record.prepared.digest) throw new BackupError('BACKUP_STATE_CHANGED');
    const authorizedAt = now(),
      expires = Math.min(record.input.validUntil, observation.security_expires_at);
    if (authorizedAt >= expires) throw new BackupError('BACKUP_EXPIRED');
    const snapshotJson = backupSnapshot(observation);
    readBackupSnapshot(snapshotJson, record.input.initialization);
    const guard = this.guard(record.c);
    signal.throwIfAborted();
    const result = await this.db
      .prepare(
        `UPDATE account_backups SET authorized_at = ?,authorization_json = ?,authorization_snapshot_json = ?,calldata_sha256 = ?,authorized_auth_time = ?
   WHERE id = ? AND authorized_at IS NULL AND proposal_hash = ? AND unixepoch() < ?
   AND EXISTS (SELECT 1 ${guard.sql})`,
      )
      .bind(
        authorizedAt,
        authorizationJson,
        snapshotJson,
        deploymentDocumentDigest(signed.data),
        this.identity.authTime,
        id,
        signed.proposalHash,
        expires,
        ...guard.values,
      )
      .run();
    // D1 counts consent + trigger-inserted outbox + durable scheduling job.
    if (!result.success || ![0, 3].includes(result.meta.changes)) throw invalid();
    const stored = await this.decode(await this.select(id).first<Row>());
    if (stored.authorizedAt === null || stored.authorizationJson !== authorizationJson)
      throw new BackupError('BACKUP_CONFLICT');
    await this.context(stored.c.initializationId, stored.c.walletId, stored.c.walletAccountId);
    signal.throwIfAborted();
    return this.receipt(stored);
  }

  private selectCommit(id: ResourceId<'operation'>) {
    return this.db
      .prepare(
        `SELECT c.* FROM account_backup_commits c JOIN account_backups a ON a.id = c.backup_id
   JOIN users u ON u.id = a.user_id WHERE c.id = ? AND ${AUTHORIZED_USER}`,
      )
      .bind(id, ...this.auth());
  }
  private async authorizedBackup(id: ResourceId<'operation'>) {
    const backup = await this.decode(await this.select(id).first<Row>());
    if (backup.authorizedAt === null) throw new BackupError('BACKUP_REQUIRED');
    return backup;
  }
  private async decodeCommit(row: Row | null) {
    if (!row) throw new WalletAccessError('NOT_FOUND');
    const backupId = parseResourceId('operation', row.backup_id);
    const backup = await this.authorizedBackup(backupId);
    return { ...(await restoreBackupCommitAuthorization(row, backup)), backup };
  }
  private commitReceipt(record: Awaited<ReturnType<BackupRepository['decodeCommit']>>) {
    return Object.freeze({
      commit_id: record.id,
      backup_id: record.backup.id,
      proposal_hash: record.backup.prepared.digest,
      commit_digest: record.compiled.digest,
      valid_after: record.validAfter,
      valid_until: record.validUntil,
      state:
        record.authorizedAt !== null
          ? ('authorized' as const)
          : now() >= record.validUntil
            ? ('expired' as const)
            : ('prepared' as const),
      backup_assessment: 'not_assessed' as const,
      receive_enabled: false as const,
      spend_enabled: false as const,
    });
  }
  /** Signing metadata for the same review after reload, never a proof-bearing execution grant. */
  async readCommit(id: ResourceId<'operation'>) {
    parseResourceId('operation', id);
    await this.wallets.getSession();
    const record = await this.decodeCommit(await this.selectCommit(id).first<Row>());
    await this.context(
      record.backup.c.initializationId,
      record.backup.c.walletId,
      record.backup.c.walletAccountId,
    );
    return {
      ...this.commitReceipt(record),
      input: record.backup.input,
      observation: record.reviewed.observation,
    };
  }
  async prepareCommit(
    id: ResourceId<'operation'>,
    backupId: ResourceId<'operation'>,
    signal: AbortSignal,
  ) {
    parseResourceId('operation', id);
    parseResourceId('operation', backupId);
    signal.throwIfAborted();
    await this.wallets.getSession();
    const backup = await this.authorizedBackup(backupId),
      previous = await this.selectCommit(id).first<Row>();
    if (previous) {
      const record = await this.decodeCommit(previous);
      if (record.backup.id !== backupId) throw new BackupError('BACKUP_CONFLICT');
      if (record.authorizedAt === null && now() >= record.validUntil)
        throw new BackupError('BACKUP_EXPIRED');
      signal.throwIfAborted();
      return this.readCommit(id);
    }
    if (now() >= backup.input.proposalValidUntil) throw new BackupError('BACKUP_EXPIRED');
    const observed = await this.observe(backup.c, signal),
      validAfter = now();
    const validUntil = Math.min(validAfter + 300, backup.input.proposalValidUntil);
    const compiled = prepareBackupCommit(
      backup.input,
      observed,
      validAfter,
      validUntil,
      validAfter,
    );
    const snapshotJson = backupCommitSnapshot(observed);
    readBackupCommitSnapshot(snapshotJson, backup.input.initialization);
    const guard = this.guard(backup.c);
    signal.throwIfAborted();
    const result = await this.db
      .prepare(
        `INSERT INTO account_backup_commits(id,backup_id,snapshot_json,commit_digest,valid_after,valid_until)
   SELECT ?,?,?,?, ?,? ${guard.sql} AND unixepoch() < ? AND unixepoch() < ?
   AND EXISTS (SELECT 1 FROM account_backups x WHERE x.id = ? AND x.user_id = u.id AND x.proposal_hash = ? AND x.authorization_json = ?)
   AND (SELECT count(*) FROM account_backup_commits z JOIN account_backups x ON x.id = z.backup_id
    WHERE x.user_id = u.id AND z.valid_after > ?) < 6
   ON CONFLICT(id) DO NOTHING`,
      )
      .bind(
        id,
        backupId,
        snapshotJson,
        compiled.digest,
        validAfter,
        validUntil,
        ...guard.values,
        observed.security_expires_at,
        validUntil,
        backupId,
        backup.prepared.digest,
        backup.authorizationJson,
        validAfter - 600,
      )
      .run();
    if (!result.success || ![0, 1].includes(result.meta.changes)) throw invalid();
    await this.context(backup.c.initializationId, backup.c.walletId, backup.c.walletAccountId);
    signal.throwIfAborted();
    const stored = await this.selectCommit(id).first<Row>();
    if (!stored)
      throw new BackupError(
        now() >= Math.min(observed.security_expires_at, validUntil)
          ? 'BACKUP_EXPIRED'
          : 'BACKUP_LIMIT',
      );
    if (stored.backup_id !== backupId) throw new BackupError('BACKUP_CONFLICT');
    return this.readCommit(id);
  }
  async authorizeCommit(
    id: ResourceId<'operation'>,
    assertion: WebAuthnAssertionBytes,
    signal: AbortSignal,
  ) {
    parseResourceId('operation', id);
    const body = writeAssertionRecord(assertion),
      proof = readAssertionRecord(body);
    signal.throwIfAborted();
    await this.wallets.getSession();
    const record = await this.decodeCommit(await this.selectCommit(id).first<Row>()),
      backup = record.backup;
    if (record.authorizedAt !== null) {
      if (record.assertionBody !== body) throw new BackupError('BACKUP_CONFLICT');
      await this.context(backup.c.initializationId, backup.c.walletId, backup.c.walletAccountId);
      signal.throwIfAborted();
      return this.commitReceipt(record);
    }
    if (now() >= record.validUntil) throw new BackupError('BACKUP_EXPIRED');
    let signed: ReturnType<typeof authorizeBackupCommit>;
    try {
      signed = authorizeBackupCommit(
        backup.input,
        record.reviewed.observation,
        record.validAfter,
        record.validUntil,
        proof,
        now(),
      );
    } catch {
      throw new BackupError('INVALID_BACKUP_PROOF');
    }
    const observed = await this.observe(backup.c, signal, record.reviewed.finalityEvidence.target);
    prepareBackupCommit(backup.input, observed, record.validAfter, record.validUntil, now());
    this.checkpoint(record.reviewed.observation.checkpoint, observed.checkpoint);
    const confirmationJson = JSON.stringify({
      current: backupCommitSnapshot(observed),
      acknowledgement: observed.acknowledgement,
    });
    readBackupCommitConfirmation(confirmationJson, backup.input.initialization, record.reviewed);
    const authorizedAt = now(),
      expires = Math.min(record.validUntil, observed.security_expires_at);
    if (authorizedAt >= expires) throw new BackupError('BACKUP_EXPIRED');
    const guard = this.guard(backup.c);
    signal.throwIfAborted();
    const result = await this.db
      .prepare(
        `UPDATE account_backup_commits SET authorized_at = ?,assertion_body = ?,confirmation_json = ?,calldata_sha256 = ?,authorized_auth_time = ?
   WHERE id = ? AND authorized_at IS NULL AND commit_digest = ? AND unixepoch() < ?
   AND EXISTS (SELECT 1 ${guard.sql}) AND EXISTS (SELECT 1 FROM account_backups x WHERE x.id = account_backup_commits.backup_id
    AND x.id = ? AND x.proposal_hash = ? AND x.authorization_json = ?)`,
      )
      .bind(
        authorizedAt,
        body,
        confirmationJson,
        deploymentDocumentDigest(signed.data),
        this.identity.authTime,
        id,
        record.compiled.digest,
        expires,
        ...guard.values,
        backup.id,
        backup.prepared.digest,
        backup.authorizationJson,
      )
      .run();
    if (!result.success || ![0, 3].includes(result.meta.changes)) throw invalid();
    const stored = await this.decodeCommit(await this.selectCommit(id).first<Row>());
    if (stored.authorizedAt === null || stored.assertionBody !== body)
      throw new BackupError('BACKUP_CONFLICT');
    await this.context(backup.c.initializationId, backup.c.walletId, backup.c.walletAccountId);
    signal.throwIfAborted();
    return this.commitReceipt(stored);
  }
}
