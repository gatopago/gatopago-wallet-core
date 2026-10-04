import { parseTransaction, type Hex } from 'viem';
import { deploymentDocumentDigest, requireHash } from '@gatopago/shared/v3/deployment';
import { loadPinnedCreationProfile } from '@gatopago/shared/v3/initialization';
import { createResourceId, parseResourceId, type ResourceId } from '@gatopago/shared/v3/primitives';
import { assertWebAuthnScope } from '@gatopago/shared/v3/webauthn';
import {
  restoreBackupAuthorization,
  restoreBackupCommitAuthorization,
} from './backupAuthorization';
import {
  prepareBackupTransaction,
  verifyBackupTransaction,
  type BackupSponsorPolicy,
  type BackupTransactionTerms,
} from './backupTransaction';
import type { CreationDeliveryConfiguration } from '../creation/creationDelivery';
import { InitializationRepository } from '../creation/initialization';
import { WalletAccessError } from '../accounts/repository';

type Row = Record<string, unknown>;
const now = () => Math.floor(Date.now() / 1000);
const invalid = () => new WalletAccessError('WALLET_DATA_INVALID');
const JOINS = `FROM account_backup_outbox b JOIN account_backups a ON a.id = b.backup_id
 LEFT JOIN account_backup_commits c ON c.id = b.commit_id AND c.backup_id = a.id
 JOIN account_initializations i ON i.id = a.initialization_id AND i.user_id = a.user_id
 JOIN users u ON u.id = a.user_id
 JOIN webauthn_credentials k ON k.id = i.credential_ref AND k.user_id = u.id
 JOIN wallets w ON w.id = a.wallet_id AND w.user_id = u.id
 JOIN wallet_accounts wa ON wa.id = a.wallet_account_id AND wa.wallet_id = w.id`;

function integer(row: Row, field: string, min = 0): number {
  const value = row[field];
  if (typeof value !== 'number' || !Number.isSafeInteger(value) || value < min) throw invalid();
  return value;
}
function optionalInteger(row: Row, field: string) {
  return row[field] === null ? null : integer(row, field, 1);
}
function delivery(row: Row) {
  const state = row.state;
  if (
    state !== 'pending' &&
    state !== 'sending' &&
    state !== 'uncertain' &&
    state !== 'accepted' &&
    state !== 'expired'
  )
    throw invalid();
  const token = row.lease_token === null ? null : parseResourceId('operation', row.lease_token);
  const until = optionalInteger(row, 'lease_expires_at'),
    started = optionalInteger(row, 'send_started_at');
  const accepted = optionalInteger(row, 'accepted_at');
  const hash = row.transaction_hash;
  if (hash !== null) requireHash(hash);
  const created = integer(row, 'created_at', 1),
    expires = integer(row, 'expires_at', created + 1),
    attempts = integer(row, 'attempt_count');
  if (
    attempts > 32 ||
    (token === null) !== (until === null) ||
    (until !== null && until > expires) ||
    (['pending', 'expired'].includes(state) &&
      (started !== null || hash !== null || accepted !== null)) ||
    (state === 'sending' &&
      (started === null || hash === null || token === null || accepted !== null)) ||
    (state === 'uncertain' &&
      (started === null || hash === null || token !== null || accepted !== null)) ||
    (state === 'accepted' &&
      (started === null || hash === null || accepted === null || token !== null)) ||
    (started !== null && (started < created || started >= expires)) ||
    (accepted !== null && (started === null || accepted < started))
  )
    throw invalid();
  return Object.freeze({
    state,
    token,
    until,
    started,
    accepted,
    hash,
    created,
    expires,
    attempts,
    next: integer(row, 'next_attempt_at', created),
  });
}

/** Private outbox authority. NOT a public endpoint, user session, current chain-state
 * assertion or transport admission. All cryptographic data is rebuilt from immutable
 * consent. Caller supplies server-pinned profiles, never data received in a queue.
 * No private key, fabricated Firebase session or module-global I/O is involved. */
export class BackupDeliveryRepository {
  private readonly db: D1DatabaseSession;
  private readonly configuration: CreationDeliveryConfiguration;
  constructor(database: D1Database, configuration: CreationDeliveryConfiguration) {
    assertWebAuthnScope(configuration.scope);
    if (configuration.environment !== 'production' || configuration.profiles.length > 32)
      throw invalid();
    const profiles = configuration.profiles.map((pin) => {
      loadPinnedCreationProfile(pin.document, pin.digest);
      return Object.freeze({ document: pin.document, digest: pin.digest });
    });
    if (new Set(profiles.map((p) => p.digest)).size !== profiles.length) throw invalid();
    this.configuration = Object.freeze({
      environment: configuration.environment,
      scope: Object.freeze({ ...configuration.scope }),
      profiles: Object.freeze(profiles),
    });
    this.db = database.withSession('first-primary');
  }
  private async load(id: ResourceId<'operation'>) {
    parseResourceId('operation', id);
    const select = (fields: string, extra = '') =>
      this.db
        .prepare(
          `SELECT ${fields} ${JOINS}
   WHERE b.operation_id = ? AND u.environment = ? ${extra}`,
        )
        .bind(id, this.configuration.environment);
    const rows = await this.db.batch<Row>([
      select('a.*'),
      select('c.*', 'AND c.id IS NOT NULL'),
      select('i.*, k.public_key AS current_key, k.rp_id, k.origin'),
      select(`b.*, u.disabled_at, u.auth_not_before, w.status AS wallet_status, wa.deployment_state,
    w.account_id, w.initial_security_commitment, w.user_salt_commitment, w.canonical_address,
    wa.address,  wa.deployment_manifest_sha256, wa.network_id`),
    ]);
    if (rows.length !== 4 || rows.some((r) => !r.success || r.results.length > 1)) throw invalid();
    const a = rows[0].results[0],
      c = rows[1].results[0],
      i = rows[2].results[0],
      b = rows[3].results[0];
    if (!a || !i || !b) throw new WalletAccessError('NOT_FOUND');
    const initial = InitializationRepository.restoreRecord(
      i,
      this.configuration.scope,
      this.configuration.profiles,
    );
    if (
      initial.authorizedAt === null ||
      !initial.initialProof ||
      initial.id !== a.initialization_id
    )
      throw invalid();
    const backup = await restoreBackupAuthorization(a, initial.input);
    const commit = c ? await restoreBackupCommitAuthorization(c, backup) : null;
    if (
      (b.kind !== 'prepare' && b.kind !== 'commit') ||
      (b.kind === 'commit') !== (commit !== null) ||
      b.backup_id !== backup.id ||
      (commit
        ? b.commit_id !== commit.id || id !== commit.id
        : id !== backup.id || b.commit_id !== null)
    )
      throw invalid();
    const source = commit ?? backup,
      signed = source.signed,
      authorizedAt = source.authorizedAt,
      authTime = source.authorizedAuthTime;
    if (
      !signed ||
      authorizedAt === null ||
      authTime === null ||
      b.calldata_sha256 !== deploymentDocumentDigest(signed.data) ||
      b.authorized_auth_time !== authTime ||
      b.created_at !== authorizedAt ||
      b.expires_at !== (commit?.validUntil ?? backup.input.validUntil)
    )
      throw invalid();
    const expected = initial.prepared;
    if (
      b.account_id !== expected.message.accountId ||
      b.initial_security_commitment !== expected.message.initialSecurityCommitment ||
      b.user_salt_commitment !== expected.message.userSaltCommitment ||
      b.canonical_address !== expected.account.toLowerCase() ||
      b.address !== b.canonical_address ||
      b.network_id !== expected.profile.deployment.network_id ||
      b.deployment_manifest_sha256 !==
        deploymentDocumentDigest(JSON.stringify(expected.profile.deployment))
    )
      throw invalid();
    const state = delivery(b),
      cutoff = integer(b, 'auth_not_before');
    optionalInteger(b, 'disabled_at');
    const revoked =
      b.disabled_at !== null ||
      cutoff > authTime ||
      b.wallet_status !== 'active' ||
      b.deployment_state !== 'active';
    return Object.freeze({
      id,
      backup,
      commit,
      signed,
      authorizedAt,
      authTime,
      state,
      initial,
      revoked,
      initialAssertion: i.assertion_body,
      backupProofs: a.authorization_json,
      commitProof: c?.assertion_body ?? null,
      manifest: b.deployment_manifest_sha256,
    });
  }
  private guard(r: Awaited<ReturnType<BackupDeliveryRepository['load']>>) {
    return {
      sql: `EXISTS (SELECT 1 ${JOINS} WHERE b.operation_id = account_backup_outbox.operation_id
   AND u.environment = ? AND u.disabled_at IS NULL AND u.auth_not_before <= ? AND w.status = 'active' AND wa.deployment_state = 'active'
   AND b.calldata_sha256 = ? AND b.authorized_auth_time = ? AND a.authorization_json = ? AND c.assertion_body IS ?
   AND i.assertion_body = ? AND i.approval_digest = ? AND i.profile_sha256 = ?
   AND k.public_key = i.public_key AND k.public_key = ? AND k.rp_id = ? AND k.origin = ?
   AND w.account_id = ? AND w.canonical_address = ? AND wa.address = w.canonical_address
   AND wa.deployment_manifest_sha256 = ? AND wa.network_id = ?)`,
      values: [
        this.configuration.environment,
        r.authTime,
        deploymentDocumentDigest(r.signed.data),
        r.authTime,
        r.backupProofs,
        r.commitProof,
        r.initialAssertion,
        r.initial.prepared.digest,
        r.initial.input.expectedDigest,
        r.initial.input.publicKey,
        this.configuration.scope.rpId,
        this.configuration.scope.origin,
        r.initial.prepared.message.accountId,
        r.initial.prepared.account.toLowerCase(),
        r.manifest,
        r.initial.prepared.profile.deployment.network_id,
      ],
    };
  }
  private async changed(statement: D1PreparedStatement) {
    const result = await statement.run();
    if (!result.success || ![0, 1].includes(result.meta.changes)) throw invalid();
    return result.meta.changes === 1;
  }
  /** Private, validated lifecycle view for the runner; never a spending decision. */
  async status(id: ResourceId<'operation'>) {
    const r = await this.load(id);
    return Object.freeze({
      ...r.state,
      revoked: r.revoked,
      profileDigest: r.initial.input.expectedDigest,
      kind: r.commit ? ('commit' as const) : ('prepare' as const),
    });
  }
  /** Bounded, environment-scoped discovery. IDs only, no session/proof in queue payloads. */
  async due(limit = 20) {
    if (!Number.isSafeInteger(limit) || limit < 1 || limit > 50) throw invalid();
    const time = now();
    const rows = await this.db
      .prepare(
        `SELECT b.operation_id ${JOINS} WHERE u.environment = ?
   AND ((b.state = 'pending' AND (b.expires_at <= ? OR b.attempt_count < 32 AND b.next_attempt_at <= ?)
    AND (b.lease_expires_at IS NULL OR b.lease_expires_at <= ?)) OR (b.state = 'sending' AND b.lease_expires_at <= ?))
   ORDER BY b.next_attempt_at,b.operation_id LIMIT ?`,
      )
      .bind(this.configuration.environment, time, time, time, time, limit)
      .all<Row>();
    if (!rows.success) throw invalid();
    return rows.results.map((r) => parseResourceId('operation', r.operation_id));
  }
  async claim(id: ResourceId<'operation'>) {
    const r = await this.load(id),
      time = now(),
      s = r.state;
    if (s.state === 'sending' && s.until !== null && s.until <= time) {
      await this.changed(
        this.db
          .prepare(
            `UPDATE account_backup_outbox SET state = 'uncertain',lease_token = NULL,lease_expires_at = NULL
    WHERE operation_id = ? AND state = 'sending' AND lease_token = ? AND lease_expires_at <= ?`,
          )
          .bind(id, s.token, time),
      );
      return null;
    }
    if (s.state !== 'pending') return null;
    if (s.expires <= time) {
      await this.changed(
        this.db
          .prepare(
            `UPDATE account_backup_outbox SET state = 'expired',lease_token = NULL,lease_expires_at = NULL
    WHERE operation_id = ? AND state = 'pending' AND expires_at <= ?`,
          )
          .bind(id, time),
      );
      return null;
    }
    if (r.revoked) throw new Error('BACKUP_GRANT_REVOKED');
    if (s.attempts >= 32 || s.next > time || (s.until !== null && s.until > time)) return null;
    const token = createResourceId('operation'),
      until = Math.min(time + 45, s.expires),
      g = this.guard(r);
    if (
      !(await this.changed(
        this.db
          .prepare(
            `UPDATE account_backup_outbox SET lease_token = ?,lease_expires_at = ?,attempt_count = attempt_count + 1
   WHERE operation_id = ? AND state = 'pending' AND expires_at > ? AND next_attempt_at <= ? AND attempt_count < 32
   AND (lease_expires_at IS NULL OR lease_expires_at <= ?) AND ${g.sql}`,
          )
          .bind(token, until, id, time, time, time, ...g.values),
      ))
    )
      return null;
    const fresh = await this.load(id);
    if (fresh.revoked || fresh.state.token !== token || fresh.state.until !== until)
      throw new Error('BACKUP_LEASE_LOST');
    return Object.freeze({ id, token, until, record: fresh });
  }
  /** Private scheduler supplies an admitted operator and independently observed nonce/fees.
   * A unique D1 constraint arbitrates concurrent consumers, across all users in this D1.
   * An interrupted signer may only retry this same envelope; reservations never auto-expire. */
  async reserveTransaction(
    claim: BackupDeliveryClaim,
    policy: BackupSponsorPolicy,
    terms: BackupTransactionTerms,
  ) {
    const expected = prepareBackupTransaction(
      claim.record.initial.prepared.profile.deployment.network_id,
      claim.record.signed,
      policy,
      terms,
    );
    const g = this.guard(claim.record),
      time = now();
    await this.changed(
      this.db
        .prepare(
          `INSERT INTO account_backup_transactions
   (operation_id,network_id,operator_address,nonce,unsigned_transaction,unsigned_hash,created_at)
   SELECT operation_id,?,?,?,?,?,? FROM account_backup_outbox
   WHERE operation_id = ? AND state = 'pending' AND lease_token = ? AND lease_expires_at > ? AND expires_at > ? AND ${g.sql}
   ON CONFLICT DO NOTHING`,
        )
        .bind(
          expected.networkId,
          expected.operator,
          terms.nonce,
          expected.unsigned,
          expected.unsignedHash,
          time,
          claim.id,
          claim.token,
          time,
          time,
          ...g.values,
        ),
    );
    const existing = await this.transactionRequest(claim, policy);
    if (existing && existing.unsigned !== expected.unsigned)
      throw new Error('BACKUP_SPONSOR_RESERVATION_CONFLICT');
    return existing;
  }
  /** Returns the reserved request only for the current lease and still-valid grant.
   * No auto-nonce/fee refresh after an ambiguous signer response. */
  async transactionRequest(claim: BackupDeliveryClaim, policy: BackupSponsorPolicy) {
    const g = this.guard(claim.record),
      time = now();
    const row = await this.db
      .prepare(
        `SELECT t.* FROM account_backup_transactions t JOIN account_backup_outbox
   ON account_backup_outbox.operation_id = t.operation_id WHERE t.operation_id = ?
   AND state = 'pending' AND lease_token = ? AND lease_expires_at > ? AND expires_at > ? AND ${g.sql}`,
      )
      .bind(claim.id, claim.token, time, time, ...g.values)
      .first<Row>();
    if (!row) return null;
    if (
      typeof row.unsigned_transaction !== 'string' ||
      !/^0x02[0-9a-f]+$(?![\s\S])/.test(row.unsigned_transaction) ||
      row.unsigned_transaction.length > 100_002
    )
      throw invalid();
    try {
      const tx = parseTransaction(row.unsigned_transaction as Hex);
      const expected = prepareBackupTransaction(
        claim.record.initial.prepared.profile.deployment.network_id,
        claim.record.signed,
        policy,
        {
          nonce: integer(row, 'nonce'),
          gas: tx.gas ?? 0n,
          maxFeePerGas: tx.maxFeePerGas ?? 0n,
          maxPriorityFeePerGas: tx.maxPriorityFeePerGas ?? 0n,
        },
      );
      if (
        row.network_id !== expected.networkId ||
        row.operator_address !== expected.operator ||
        row.unsigned_hash !== expected.unsignedHash ||
        row.unsigned_transaction !== expected.unsigned
      )
        throw invalid();
      return expected;
    } catch {
      throw invalid();
    }
  }
  /** Must follow private network/sponsor admission and simulation. Raw bytes are verified
   * against the durable reservation and saved atomically with their LOCAL hash. A true
   * return is a send marker, NEVER finality, installed policy or spend readiness. */
  async beginSend(
    claim: BackupDeliveryClaim,
    policy: BackupSponsorPolicy,
    raw: unknown,
    evidenceExpiresAt: number,
  ) {
    if (!Number.isSafeInteger(evidenceExpiresAt) || evidenceExpiresAt <= now()) return false;
    const request = await this.transactionRequest(claim, policy);
    if (!request) return false;
    const signed = await verifyBackupTransaction(request, raw),
      g = this.guard(claim.record),
      time = now();
    const results = await this.db.batch([
      this.db
        .prepare(
          `UPDATE account_backup_transactions SET serialized_transaction = ?,transaction_hash = ? WHERE operation_id = ?
    AND unsigned_transaction = ? AND (serialized_transaction IS NULL OR serialized_transaction = ?)
    AND EXISTS (SELECT 1 FROM account_backup_outbox WHERE operation_id = ? AND state = 'pending'
     AND lease_token = ? AND lease_expires_at > ? AND expires_at > ? AND unixepoch() < ? AND ${g.sql})`,
        )
        .bind(
          signed.serialized,
          signed.hash,
          claim.id,
          request.unsigned,
          signed.serialized,
          claim.id,
          claim.token,
          time,
          time,
          evidenceExpiresAt,
          ...g.values,
        ),
      this.db
        .prepare(
          `UPDATE account_backup_outbox SET state = 'sending',send_started_at = ?,transaction_hash = ?
   WHERE operation_id = ? AND state = 'pending' AND lease_token = ? AND lease_expires_at > ? AND expires_at > ? AND unixepoch() < ? AND ${g.sql}`,
        )
        .bind(time, signed.hash, claim.id, claim.token, time, time, evidenceExpiresAt, ...g.values),
    ]);
    if (
      results.length !== 2 ||
      results.some((r) => !r.success || ![0, 1].includes(r.meta.changes)) ||
      results[0].meta.changes !== results[1].meta.changes
    )
      throw invalid();
    return results[1].meta.changes === 1;
  }
  async retryBeforeSend(
    claim: NonNullable<Awaited<ReturnType<BackupDeliveryRepository['claim']>>>,
  ) {
    const next = now() + Math.min(30, 2 ** Math.min(claim.record.state.attempts, 5));
    return this.changed(
      this.db
        .prepare(
          `UPDATE account_backup_outbox SET lease_token = NULL,lease_expires_at = NULL,next_attempt_at = ?
   WHERE operation_id = ? AND state = 'pending' AND lease_token = ?`,
        )
        .bind(next, claim.id, claim.token),
    );
  }
  async uncertain(claim: NonNullable<Awaited<ReturnType<BackupDeliveryRepository['claim']>>>) {
    return this.changed(
      this.db
        .prepare(
          `UPDATE account_backup_outbox SET state = 'uncertain',lease_token = NULL,lease_expires_at = NULL
   WHERE operation_id = ? AND state = 'sending' AND lease_token = ?`,
        )
        .bind(claim.id, claim.token),
    );
  }
  /** Provider acknowledgement, not a receipt, finality, installed policy or readiness. */
  async accepted(
    claim: NonNullable<Awaited<ReturnType<BackupDeliveryRepository['claim']>>>,
    hash: Hex,
  ) {
    requireHash(hash);
    return this.changed(
      this.db
        .prepare(
          `UPDATE account_backup_outbox SET state = 'accepted',accepted_at = ?,lease_token = NULL,lease_expires_at = NULL
   WHERE operation_id = ? AND state = 'sending' AND lease_token = ? AND lease_expires_at > ? AND transaction_hash = ?`,
        )
        .bind(now(), claim.id, claim.token, now(), hash),
    );
  }
  /** Previously sent work must remain observable after consent expiry/revocation.
   * This read cannot produce a new send lease or activate any wallet. */
  async observationGrant(id: ResourceId<'operation'>) {
    const r = await this.load(id);
    if (!['sending', 'uncertain', 'accepted'].includes(r.state.state)) return null;
    // Historical evidence uses the immutable reservation, not today's sponsor key/budget.
    // Rotating an operator or expiring consent cannot erase a previously sent transaction.
    const row = await this.db
      .prepare('SELECT * FROM account_backup_transactions WHERE operation_id = ?')
      .bind(id)
      .first<Row>();
    if (
      !row ||
      typeof row.unsigned_transaction !== 'string' ||
      row.unsigned_transaction.length > 100_002 ||
      !/^0x02[0-9a-f]+$(?![\s\S])/.test(row.unsigned_transaction) ||
      typeof row.operator_address !== 'string'
    )
      throw invalid();
    try {
      const tx = parseTransaction(row.unsigned_transaction as Hex),
        networkId = r.initial.prepared.profile.deployment.network_id;
      const terms = {
        nonce: integer(row, 'nonce'),
        gas: tx.gas ?? 0n,
        maxFeePerGas: tx.maxFeePerGas ?? 0n,
        maxPriorityFeePerGas: tx.maxPriorityFeePerGas ?? 0n,
      };
      const transaction = prepareBackupTransaction(
        networkId,
        r.signed,
        {
          networkId,
          operator: row.operator_address as Hex,
          maxGas: terms.gas,
          maxFeePerGas: terms.maxFeePerGas,
          maxPriorityFeePerGas: terms.maxPriorityFeePerGas,
          maxExecutionFee: terms.gas * terms.maxFeePerGas,
        },
        terms,
      );
      const verified = await verifyBackupTransaction(transaction, row.serialized_transaction);
      if (
        row.network_id !== networkId ||
        row.operator_address !== transaction.operator ||
        row.unsigned_transaction !== transaction.unsigned ||
        row.unsigned_hash !== transaction.unsignedHash ||
        row.transaction_hash !== verified.hash ||
        r.state.hash !== verified.hash ||
        integer(row, 'created_at', r.authorizedAt) > r.state.started!
      )
        throw invalid();
      return Object.freeze({
        id,
        backupId: r.backup.id,
        kind: r.commit ? ('commit' as const) : ('prepare' as const),
        networkId,
        signed: r.signed,
        transactionHash: verified.hash,
        transaction,
        serializedTransaction: verified.serialized,
        profileDigest: r.initial.input.expectedDigest,
        initial: r.initial.prepared,
        backup: r.backup.prepared,
        afterCheckpoint: (r.commit?.reviewed.observation ?? r.backup.input.observation).checkpoint
          .block_number,
        commit: r.commit
          ? Object.freeze({
              message: r.commit.compiled.message,
              readyAt: r.commit.reviewed.observation.security.pending!.ready_at,
            })
          : null,
      });
    } catch {
      throw invalid();
    }
  }
}
export type BackupDeliveryClaim = NonNullable<
  Awaited<ReturnType<BackupDeliveryRepository['claim']>>
>;
export type BackupObservationGrant = NonNullable<
  Awaited<ReturnType<BackupDeliveryRepository['observationGrant']>>
>;
