import { AUTHORIZED_USER, authorizationValues } from '../auth/authorization';
import {
  authorizeCreationOperation,
  prepareCreationOperation,
  type CreationGasTerms,
} from '@gatopago/shared/v3/creation-operation';
import { requireHash } from '@gatopago/shared/v3/deployment';
import { parseResourceId, type ResourceId } from '@gatopago/shared/v3/primitives';
import type { WebAuthnAssertionBytes, WebAuthnScope } from '@gatopago/shared/v3/webauthn';
import type { Principal } from '../auth/principal';
import { readAssertionRecord, writeAssertionRecord } from '@gatopago/shared/v3/assertion-record';
import { InitializationRepository, type CreationProfilePin } from './initialization';
import { WalletAccessError, WalletRepository } from '../accounts/repository';
import { creationOutboxColumns, readCreationOutbox } from './creationOutbox';
import { creationGasWire, parseCreationGas } from '@gatopago/shared/v3/creation-operation-wire';
import {
  creationLifecycle,
  creationLifecycleColumns,
  creationLifecycleJoins,
} from './creationLifecycle';

type Row = Record<string, unknown>;
type Initial = Awaited<ReturnType<InitializationRepository['readAuthorized']>>;

const nowSeconds = () => Math.floor(Date.now() / 1000);

export class CreationOperationError extends Error {
  constructor(
    readonly code: 'CREATION_EXPIRED' | 'CREATION_CONFLICT' | 'INVALID_CREATION_ASSERTION',
  ) {
    super(code);
    this.name = 'CreationOperationError';
  }
}

function writeGas(terms: CreationGasTerms): string {
  return JSON.stringify(creationGasWire(terms));
}
function readGas(json: unknown): CreationGasTerms {
  if (typeof json !== 'string' || json.length > 2048) throw new Error('Invalid stored gas terms');
  const terms = parseCreationGas(JSON.parse(json));
  if (writeGas(terms) !== json) throw new Error('Noncanonical stored gas terms');
  return terms;
}

export class CreationOperationRepository {
  private readonly db: D1DatabaseSession;
  private readonly initializations: InitializationRepository;
  private readonly wallets: WalletRepository;
  private readonly identity: Principal;
  constructor(
    database: D1Database,
    identity: Principal,
    scope: WebAuthnScope,
    profiles: readonly CreationProfilePin[],
  ) {
    this.identity = Object.freeze({ ...identity });
    this.db = database.withSession('first-primary');
    this.initializations = new InitializationRepository(database, this.identity, scope, profiles);
    this.wallets = new WalletRepository(database, this.identity);
  }
  private auth() {
    return authorizationValues(this.identity);
  }
  private async owner() {
    if (this.identity.expiresAt <= nowSeconds()) throw new WalletAccessError('UNAUTHENTICATED');
    await this.wallets.getSession();
  }
  private select(id: ResourceId<'operation'>, lifecycle = false) {
    return this.db
      .prepare(
        `SELECT o.*, ${creationOutboxColumns}${lifecycle ? `, i.user_id AS owner_id, ${creationLifecycleColumns}` : ''}
			FROM account_creation_operations o JOIN account_initializations i ON i.id = o.initialization_id
			JOIN users u ON u.id = i.user_id LEFT JOIN account_creation_outbox b ON b.initialization_id = o.initialization_id
			${lifecycle ? creationLifecycleJoins : ''}
			WHERE o.initialization_id = ? AND ${AUTHORIZED_USER}`,
      )
      .bind(id, ...this.auth());
  }
  private decode(row: Row | null, initial: Initial) {
    return CreationOperationRepository.restoreRecord(row, initial);
  }

  static restoreRecord(row: Row | null, initial: Initial) {
    if (!row) throw new WalletAccessError('NOT_FOUND');
    try {
      const id = parseResourceId('operation', row.initialization_id),
        terms = readGas(row.gas_terms_json);
      requireHash(row.user_op_hash);
      requireHash(row.operation_digest);
      if (
        typeof row.created_at !== 'number' ||
        !Number.isSafeInteger(row.created_at) ||
        row.created_at < initial.authorizedAt ||
        row.created_at >= initial.input.validUntil ||
        row.expires_at !== initial.input.validUntil ||
        (row.authorized_at === null) !== (row.assertion_body === null) ||
        (row.authorized_at === null) !== (row.operation_signature === null) ||
        (row.authorized_at === null) !== (row.authorized_auth_time === null) ||
        (row.authorized_auth_time !== null &&
          (typeof row.authorized_auth_time !== 'number' ||
            !Number.isSafeInteger(row.authorized_auth_time) ||
            row.authorized_auth_time < 0)) ||
        (row.authorized_at !== null &&
          (typeof row.authorized_at !== 'number' ||
            !Number.isSafeInteger(row.authorized_at) ||
            row.authorized_at < row.created_at ||
            row.authorized_at >= initial.input.validUntil))
      )
        throw new Error();
      const authorizedAt = row.authorized_at;
      const signed =
        authorizedAt === null
          ? null
          : authorizeCreationOperation(
              initial.input,
              initial.initialProof,
              terms,
              readAssertionRecord(row.assertion_body),
              authorizedAt,
            );
      const candidate =
        signed ??
        prepareCreationOperation(initial.input, initial.initialProof, terms, row.created_at);
      if (candidate.userOpHash !== row.user_op_hash || candidate.digest !== row.operation_digest)
        throw new Error();
      if (signed && signed.operation.signature !== row.operation_signature) throw new Error();
      const delivery = readCreationOutbox(
        row,
        authorizedAt,
        id,
        candidate.userOpHash,
        initial.input.validUntil,
      );
      return {
        id,
        terms,
        candidate,
        signed,
        authorizedAt,
        expiresAt: initial.input.validUntil,
        gasJson: row.gas_terms_json,
        authTime: row.authorized_auth_time,
        delivery,
      };
    } catch {
      throw new WalletAccessError('WALLET_DATA_INVALID');
    }
  }
  private receipt(
    record: ReturnType<CreationOperationRepository['decode']>,
    observedAt = nowSeconds(),
  ) {
    return Object.freeze({
      initialization_id: record.id,
      state: record.authorizedAt === null ? ('prepared' as const) : ('authorized' as const),
      user_op_hash: record.candidate.userOpHash,
      operation_digest: record.candidate.digest,
      expires_at: record.expiresAt,
      authorization_expired: observedAt >= record.expiresAt,
      delivery_state: record.delivery?.state ?? ('not_requested' as const),
      deployment_assessment: 'not_assessed' as const,
      receive_enabled: false as const,
      spend_enabled: false as const,
    });
  }
  private async load(id: ResourceId<'operation'>) {
    parseResourceId('operation', id);
    const initial = await this.initializations.readAuthorized(id);
    const record = this.decode(await this.select(id).first<Row>(), initial);
    await this.owner();
    return { initial, record };
  }
  async read(id: ResourceId<'operation'>) {
    const { initial, record } = await this.load(id);

    return {
      ...this.receipt(record),
      input: initial.input,
      initialProof: initial.initialProof,
      terms: record.terms,
      candidate: record.candidate,
      signed: record.signed,
    };
  }

  async preview(id: ResourceId<'operation'>) {
    parseResourceId('operation', id);
    const initial = await this.initializations.readAuthorized(id),
      row = await this.select(id, true).first<Row>();
    const record = this.decode(row, initial),
      observedAt = nowSeconds(),
      receipt = this.receipt(record, observedAt);
    const lifecycle = creationLifecycle(row!, record.signed, receipt, observedAt);
    await this.owner();
    const encode = (bytes: Uint8Array) =>
      btoa(String.fromCharCode(...bytes))
        .replaceAll('+', '-')
        .replaceAll('/', '_')
        .replace(/=+$/, '');
    return Object.freeze({
      observed_at: observedAt,
      receipt,
      lifecycle,
      gas_terms: creationGasWire(record.terms),
      initial_assertion: Object.freeze({
        authenticator_data: encode(initial.initialProof.authenticatorData),
        client_data: encode(initial.initialProof.clientDataJSON),
        signature: encode(initial.initialProof.signatureDER),
      }),
    });
  }
  async prepare(id: ResourceId<'operation'>, terms: CreationGasTerms) {
    parseResourceId('operation', id);
    const gasJson = writeGas(terms),
      frozenTerms = readGas(gasJson);
    const initial = await this.initializations.readAuthorized(id);
    const existing = await this.select(id).first<Row>();
    if (existing) {
      const record = this.decode(existing, initial);
      if (record.gasJson !== gasJson) throw new CreationOperationError('CREATION_CONFLICT');
      if (record.authorizedAt === null && nowSeconds() >= record.expiresAt)
        throw new CreationOperationError('CREATION_EXPIRED');
      await this.owner();
      return this.receipt(record);
    }
    const now = nowSeconds();
    if (now >= initial.input.validUntil) throw new CreationOperationError('CREATION_EXPIRED');
    const candidate = prepareCreationOperation(
      initial.input,
      initial.initialProof,
      frozenTerms,
      now,
    );
    const result = await this.db
      .prepare(
        `INSERT INTO account_creation_operations
			(initialization_id,gas_terms_json,user_op_hash,operation_digest,created_at,expires_at)
			SELECT i.id,?,?,?,?,i.expires_at FROM account_initializations i JOIN users u ON u.id = i.user_id
			JOIN webauthn_credentials c ON c.id = i.credential_ref AND c.user_id = u.id
			WHERE i.id = ? AND i.authorized_at IS NOT NULL AND i.expires_at > ? AND i.approval_digest = ?
			AND i.assertion_body = ? AND c.public_key = i.public_key AND c.public_key = ? AND c.rp_id = ? AND c.origin = ? AND ${AUTHORIZED_USER}
			ON CONFLICT(initialization_id) DO NOTHING`,
      )
      .bind(
        gasJson,
        candidate.userOpHash,
        candidate.digest,
        now,
        id,
        now,
        candidate.prepared.digest,
        writeAssertionRecord(initial.initialProof),
        initial.input.publicKey,
        initial.input.scope.rpId,
        initial.input.scope.origin,
        ...this.auth(),
      )
      .run();
    if (!result.success || ![0, 1].includes(result.meta.changes))
      throw new WalletAccessError('WALLET_DATA_INVALID');
    const { record } = await this.load(id);
    if (record.gasJson !== gasJson) throw new CreationOperationError('CREATION_CONFLICT');
    return this.receipt(record);
  }
  async authorize(id: ResourceId<'operation'>, assertion: WebAuthnAssertionBytes) {
    parseResourceId('operation', id);
    const proofJson = writeAssertionRecord(assertion),
      proof = readAssertionRecord(proofJson);
    const initial = await this.initializations.readAuthorized(id);
    const record = this.decode(await this.select(id).first<Row>(), initial);
    const now = nowSeconds();
    if (record.authorizedAt === null && now >= record.expiresAt)
      throw new CreationOperationError('CREATION_EXPIRED');
    let signed;
    try {
      signed = authorizeCreationOperation(
        initial.input,
        initial.initialProof,
        record.terms,
        proof,
        record.authorizedAt ?? now,
      );
    } catch {
      throw new CreationOperationError('INVALID_CREATION_ASSERTION');
    }
    if (record.signed) {
      if (record.signed.operation.signature !== signed.operation.signature)
        throw new CreationOperationError('CREATION_CONFLICT');
      await this.owner();
      return this.receipt(record);
    }
    await this.owner();

    const results = await this.db.batch([
      this.db
        .prepare(
          `UPDATE account_creation_operations SET authorized_at = ?, assertion_body = ?, operation_signature = ?, authorized_auth_time = ?
				WHERE initialization_id = ? AND authorized_at IS NULL AND expires_at > ? AND gas_terms_json = ?
				AND user_op_hash = ? AND operation_digest = ? AND EXISTS (
					SELECT 1 FROM account_initializations i JOIN users u ON u.id = i.user_id
					JOIN webauthn_credentials c ON c.id = i.credential_ref AND c.user_id = u.id
					WHERE i.id = account_creation_operations.initialization_id AND i.assertion_body = ?
					AND i.approval_digest = ? AND c.public_key = i.public_key AND c.public_key = ? AND c.rp_id = ? AND c.origin = ? AND ${AUTHORIZED_USER})`,
        )
        .bind(
          now,
          proofJson,
          signed.operation.signature,
          this.identity.authTime,
          id,
          now,
          record.gasJson,
          signed.userOpHash,
          signed.digest,
          writeAssertionRecord(initial.initialProof),
          signed.prepared.digest,
          initial.input.publicKey,
          initial.input.scope.rpId,
          initial.input.scope.origin,
          ...this.auth(),
        ),
      this.db
        .prepare(
          `INSERT INTO account_creation_outbox (initialization_id,user_op_hash,state,created_at,expires_at)
				SELECT o.initialization_id,o.user_op_hash,'pending',o.authorized_at,o.expires_at
				FROM account_creation_operations o JOIN account_initializations i ON i.id = o.initialization_id
				JOIN users u ON u.id = i.user_id WHERE o.initialization_id = ? AND o.operation_signature = ?
				AND o.user_op_hash = ? AND o.operation_digest = ? AND o.authorized_at IS NOT NULL AND ${AUTHORIZED_USER}
				ON CONFLICT(initialization_id) DO NOTHING`,
        )
        .bind(id, signed.operation.signature, signed.userOpHash, signed.digest, ...this.auth()),
      this.db
        .prepare(
          `INSERT INTO account_creation_jobs(initialization_id)
				SELECT b.initialization_id FROM account_creation_outbox b
				JOIN account_creation_operations o ON o.initialization_id = b.initialization_id
				JOIN account_initializations i ON i.id = o.initialization_id JOIN users u ON u.id = i.user_id
				WHERE o.initialization_id = ? AND o.operation_signature = ? AND o.user_op_hash = ?
				AND o.operation_digest = ? AND o.authorized_at IS NOT NULL AND ${AUTHORIZED_USER}
				ON CONFLICT(initialization_id) DO NOTHING`,
        )
        .bind(id, signed.operation.signature, signed.userOpHash, signed.digest, ...this.auth()),
    ]);
    if (
      results.length !== 3 ||
      results.some((result) => !result.success || ![0, 1].includes(result.meta.changes))
    )
      throw new WalletAccessError('WALLET_DATA_INVALID');
    const { record: stored } = await this.load(id);
    if (stored.signed?.operation.signature !== signed.operation.signature)
      throw new CreationOperationError('CREATION_CONFLICT');
    return this.receipt(stored);
  }
}
