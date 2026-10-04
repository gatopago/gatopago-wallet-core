import { AUTHORIZED_USER, authorizationValues } from '../auth/authorization';
import type { Hex } from 'viem';
import {
  authorizeInitialization,
  loadPinnedCreationProfile,
  prepareInitialization,
  type InitializationInput,
} from '@gatopago/shared/v3/initialization';
import { requireHash } from '@gatopago/shared/v3/deployment';
import { parseResourceId, type ResourceId } from '@gatopago/shared/v3/primitives';
import {
  assertWebAuthnKey,
  assertWebAuthnScope,
  type WebAuthnAssertionBytes,
  type WebAuthnScope,
} from '@gatopago/shared/v3/webauthn';
import type { Principal } from '../auth/principal';
import { WalletAccessError, WalletRepository } from '../accounts/repository';
import { readAssertionRecord, writeAssertionRecord } from '@gatopago/shared/v3/assertion-record';
import {
  parseInitializationCursor,
  parseInitializationHistory,
  parseInitializationPreparation,
} from '@gatopago/shared/v3/initialization-wire';

type Row = Record<string, unknown>;
export interface CreationProfilePin {
  readonly document: string;
  readonly digest: Hex;
}
interface Preparation {
  readonly id: ResourceId<'operation'>;
  readonly credentialRef: ResourceId<'operation'>;
  readonly profileDigest: Hex;
  readonly userSaltCommitment: Hex;
}
export class InitializationError extends Error {
  constructor(
    readonly code:
      | 'PROFILE_UNAVAILABLE'
      | 'INITIALIZATION_EXPIRED'
      | 'INITIALIZATION_CONFLICT'
      | 'INITIALIZATION_LIMIT'
      | 'INITIALIZATION_REQUIRED'
      | 'INVALID_INITIALIZATION_ASSERTION',
  ) {
    super(code);
    this.name = 'InitializationError';
  }
}
const nowSeconds = () => Math.floor(Date.now() / 1000);

/** Internal durable consent workflow, not a public arbitrary-factory provisioning API.
 * Profiles come from the eventual independently admitted release, NEVER HTTP bodies.
 * No profile is admitted by constructing this class. Before public integration, admission
 * must also verify fresh original factory composition/bytecode and the network profile.
 * Each request constructs its own instance; it never creates wallets, broadcasts, or
 * marks deposits/spending enabled merely because a signature was accepted in D1.
 */
export class InitializationRepository {
  private readonly db: D1DatabaseSession;
  private readonly wallets: WalletRepository;
  private readonly scope: WebAuthnScope;
  private readonly profiles: readonly CreationProfilePin[];
  private readonly identity: Principal;
  constructor(
    database: D1Database,
    identity: Principal,
    scope: WebAuthnScope,
    profiles: readonly CreationProfilePin[],
  ) {
    assertWebAuthnScope(scope);
    if (profiles.length > 32) throw new Error('Too many creation profiles');
    this.profiles = Object.freeze(
      profiles.map((profile) => {
        loadPinnedCreationProfile(profile.document, profile.digest);
        return Object.freeze({ document: profile.document, digest: profile.digest });
      }),
    );
    if (new Set(this.profiles.map((profile) => profile.digest)).size !== profiles.length)
      throw new Error('Duplicate creation profile');
    this.scope = Object.freeze({ ...scope });
    this.identity = Object.freeze({ ...identity });
    this.db = database.withSession('first-primary');
    this.wallets = new WalletRepository(database, this.identity);
  }
  private auth() {
    return authorizationValues(this.identity);
  }
  private async owner() {
    if (this.identity.expiresAt <= nowSeconds()) throw new WalletAccessError('UNAUTHENTICATED');
    return (await this.wallets.getSession()).user_id;
  }
  private profile(digest: Hex) {
    const found = this.profiles.find((profile) => profile.digest === digest);
    if (!found) throw new InitializationError('PROFILE_UNAVAILABLE');
    return found;
  }
  private select(id: ResourceId<'operation'>) {
    return this.db
      .prepare(
        `SELECT i.*, c.public_key AS current_key, c.credential_id, c.rp_id, c.origin FROM account_initializations i
			JOIN users u ON u.id = i.user_id JOIN webauthn_credentials c ON c.id = i.credential_ref AND c.user_id = u.id
			WHERE i.id = ? AND ${AUTHORIZED_USER}`,
      )
      .bind(id, ...this.auth());
  }
  private decode(row: Row | null) {
    return InitializationRepository.restoreRecord(row, this.scope, this.profiles);
  }
  /** Pure restoration shared with durable jobs. Caller must select the record through
   * an owned request or an internal job grant; this method grants neither authority. */
  static restoreRecord(
    row: Row | null,
    scope: WebAuthnScope,
    profiles: readonly CreationProfilePin[],
  ) {
    if (!row) throw new WalletAccessError('NOT_FOUND');
    try {
      const id = parseResourceId('operation', row.id),
        credentialRef = parseResourceId('operation', row.credential_ref);
      requireHash(row.profile_sha256);
      requireHash(row.user_salt_commitment);
      requireHash(row.approval_digest);
      if (
        typeof row.public_key !== 'string' ||
        row.public_key !== row.current_key ||
        row.rp_id !== scope.rpId ||
        row.origin !== scope.origin ||
        typeof row.created_at !== 'number' ||
        !Number.isSafeInteger(row.created_at) ||
        typeof row.expires_at !== 'number' ||
        row.expires_at !== row.created_at + 300 ||
        (row.authorized_at === null) !== (row.assertion_signature === null) ||
        (row.authorized_at === null) !== (row.assertion_body === null) ||
        (row.authorized_at !== null &&
          (typeof row.authorized_at !== 'number' ||
            !Number.isSafeInteger(row.authorized_at) ||
            row.authorized_at < row.created_at ||
            row.authorized_at >= row.expires_at))
      )
        throw new Error();
      if (!/^0x[0-9a-f]{256}$(?![\s\S])/.test(row.public_key)) throw new Error();
      const profile = profiles.find((pin) => pin.digest === row.profile_sha256);
      if (!profile) throw new InitializationError('PROFILE_UNAVAILABLE');
      const input: InitializationInput = Object.freeze({
        document: profile.document,
        expectedDigest: profile.digest,
        scope: Object.freeze({ ...scope }),
        publicKey: row.public_key as Hex,
        userSaltCommitment: row.user_salt_commitment,
        validAfter: row.created_at,
        validUntil: row.expires_at,
      });
      const prepared = prepareInitialization(input);
      if (
        prepared.digest !== row.approval_digest ||
        prepared.account.toLowerCase() !== row.expected_address
      )
        throw new Error();
      const initialProof =
        row.authorized_at === null ? null : readAssertionRecord(row.assertion_body);
      if (
        initialProof &&
        authorizeInitialization(input, initialProof, row.authorized_at as number).signature !==
          row.assertion_signature
      )
        throw new Error();
      return {
        id,
        credentialRef,
        input,
        prepared,
        authorizedAt: row.authorized_at,
        signature: row.assertion_signature,
        initialProof,
      };
    } catch (error) {
      if (error instanceof InitializationError) throw error;
      throw new WalletAccessError('WALLET_DATA_INVALID');
    }
  }
  private receipt(attempt: ReturnType<InitializationRepository['decode']>) {
    return Object.freeze({
      initialization_id: attempt.id,
      state: attempt.authorizedAt === null ? ('prepared' as const) : ('authorized' as const),
      approval_digest: attempt.prepared.digest,
      profile_sha256: attempt.prepared.profileDigest,
      account_deployed: false as const,
      receive_enabled: false as const,
      spend_enabled: false as const,
    });
  }
  /** Discovery only: ten owned metadata rows, no proofs, public keys, RPC or writes.
   * Profiles can be unavailable without making a past request silently disappear. */
  async history(after?: string) {
    const cursor = after === undefined ? null : parseInitializationCursor(after);
    const owner = await this.owner(),
      now = nowSeconds();
    const page = await this.db
      .prepare(
        `SELECT i.id, i.credential_ref, i.profile_sha256, i.approval_digest,
			i.created_at, i.expires_at, i.authorized_at,
			EXISTS (SELECT 1 FROM account_creation_operations o WHERE o.initialization_id = i.id) AS has_operation
			FROM account_initializations i JOIN users u ON u.id = i.user_id
			WHERE i.user_id = ? AND ${AUTHORIZED_USER}
			${cursor ? 'AND (i.created_at < ? OR (i.created_at = ? AND i.id < ?))' : ''}
			ORDER BY i.created_at DESC, i.id DESC LIMIT 11`,
      )
      .bind(
        owner,
        ...this.auth(),
        ...(cursor ? [cursor.createdAt, cursor.createdAt, cursor.id] : []),
      )
      .all<Row>();
    if (!page.success || !page.results || page.results.length > 11)
      throw new WalletAccessError('WALLET_DATA_INVALID');
    let result;
    try {
      const data = page.results.slice(0, 10).map((row) => {
        if (
          ![0, 1].includes(row.has_operation as number) ||
          (row.authorized_at !== null &&
            (typeof row.authorized_at !== 'number' ||
              !Number.isSafeInteger(row.authorized_at) ||
              typeof row.created_at !== 'number' ||
              typeof row.expires_at !== 'number' ||
              row.authorized_at < row.created_at ||
              row.authorized_at >= row.expires_at))
        )
          throw new Error();
        return {
          initialization_id: row.id,
          credential_ref: row.credential_ref,
          profile_sha256: row.profile_sha256,
          approval_digest: row.approval_digest,
          created_at: row.created_at,
          expires_at: row.expires_at,
          state:
            row.authorized_at !== null
              ? 'authorized'
              : typeof row.expires_at === 'number' && row.expires_at <= now
                ? 'expired'
                : 'prepared',
          creation_operation_recorded: row.has_operation === 1,
        };
      });
      const last = data.at(-1);
      result = parseInitializationHistory({
        observed_at: now,
        data,
        next_cursor:
          page.results.length > 10 && last
            ? `v1:${String(last.created_at)}:${String(last.initialization_id)}`
            : null,
      });
    } catch {
      throw new WalletAccessError('WALLET_DATA_INVALID');
    }
    await this.owner();
    return result;
  }
  async restore(id: ResourceId<'operation'>) {
    parseResourceId('operation', id);
    await this.owner();
    const row = await this.select(id).first<Row>(),
      attempt = this.decode(row);
    // Include expired unsigned consent for honest history, but never extend it.
    const preparation = this.preparation(row, attempt);
    const operation = await this.db
      .prepare(
        `SELECT EXISTS (SELECT 1 FROM account_creation_operations WHERE initialization_id = ?) AS recorded`,
      )
      .bind(id)
      .first<number>('recorded');
    if (![0, 1].includes(operation as number) || (operation === 1 && attempt.authorizedAt === null))
      throw new WalletAccessError('WALLET_DATA_INVALID');
    await this.owner();
    return Object.freeze({
      preparation,
      user_salt_commitment: attempt.input.userSaltCommitment,
      creation_operation_recorded: operation === 1,
    });
  }
  private preparation(row: Row | null, attempt: ReturnType<InitializationRepository['decode']>) {
    try {
      return parseInitializationPreparation(
        {
          ...this.receipt(attempt),
          credential_ref: attempt.credentialRef,
          credential_id: row?.credential_id,
          public_key: attempt.input.publicKey,
          valid_after: attempt.input.validAfter,
          valid_until: attempt.input.validUntil,
        },
        {
          id: attempt.id,
          credentialRef: attempt.credentialRef,
          document: attempt.input.document,
          profileDigest: attempt.input.expectedDigest,
          userSaltCommitment: attempt.input.userSaltCommitment,
          scope: this.scope,
        },
      );
    } catch {
      throw new WalletAccessError('WALLET_DATA_INVALID');
    }
  }
  /** Owner-only signing metadata. No signature, Firebase subject, deployment document
   * or derived receiving address is returned. Reads neither extend nor execute consent. */
  async readPreparation(id: ResourceId<'operation'>) {
    parseResourceId('operation', id);
    await this.owner();
    const row = await this.select(id).first<Row>(),
      attempt = this.decode(row);
    if (attempt.authorizedAt === null && nowSeconds() >= attempt.input.validUntil)
      throw new InitializationError('INITIALIZATION_EXPIRED');
    const result = this.preparation(row, attempt);
    await this.owner();
    return result;
  }
  /** Internal owned read for exact operation preparation/reconciliation, including after
   * a browser reload. Reading an expired proof does not extend or requeue its authority. */
  async readAuthorized(id: ResourceId<'operation'>) {
    parseResourceId('operation', id);
    await this.owner();
    const attempt = this.decode(await this.select(id).first<Row>());
    if (attempt.authorizedAt === null || !attempt.initialProof)
      throw new InitializationError('INITIALIZATION_REQUIRED');
    await this.owner();
    return {
      input: attempt.input,
      initialProof: attempt.initialProof,
      authorizedAt: attempt.authorizedAt,
    };
  }
  async prepare(request: Preparation) {
    // Detach before any I/O; mutable request objects cannot alter the pending consent.
    const id = parseResourceId('operation', request.id),
      credentialRef = parseResourceId('operation', request.credentialRef);
    const { profileDigest, userSaltCommitment } = request;
    requireHash(profileDigest);
    requireHash(userSaltCommitment);
    const profile = this.profile(profileDigest),
      owner = await this.owner();
    const existing = await this.select(id).first<Row>();
    if (existing) {
      const attempt = this.decode(existing);
      if (
        attempt.credentialRef !== credentialRef ||
        attempt.prepared.profileDigest !== profileDigest ||
        attempt.input.userSaltCommitment !== userSaltCommitment
      )
        throw new InitializationError('INITIALIZATION_CONFLICT');
      if (attempt.authorizedAt === null && nowSeconds() >= attempt.input.validUntil)
        throw new InitializationError('INITIALIZATION_EXPIRED');
      await this.owner();
      return { ...this.receipt(attempt), input: attempt.input };
    }
    const key = await this.db
      .prepare(
        `SELECT c.public_key, c.rp_id, c.origin FROM webauthn_credentials c
			JOIN users u ON u.id = c.user_id WHERE c.id = ? AND ${AUTHORIZED_USER}`,
      )
      .bind(credentialRef, ...this.auth())
      .first<Row>();
    if (!key) throw new WalletAccessError('NOT_FOUND');
    if (
      key.rp_id !== this.scope.rpId ||
      key.origin !== this.scope.origin ||
      typeof key.public_key !== 'string' ||
      !/^0x[0-9a-f]{256}$(?![\s\S])/.test(key.public_key)
    )
      throw new WalletAccessError('WALLET_DATA_INVALID');
    assertWebAuthnKey(this.scope, key.public_key as Hex);
    const now = nowSeconds();
    const input: InitializationInput = {
      document: profile.document,
      expectedDigest: profile.digest,
      scope: this.scope,
      publicKey: key.public_key as Hex,
      userSaltCommitment,
      validAfter: now,
      validUntil: now + 300,
    };
    const prepared = prepareInitialization(input);
    const result = await this.db
      .prepare(
        `INSERT INTO account_initializations
			(id,user_id,credential_ref,profile_sha256,user_salt_commitment,public_key,approval_digest,expected_address,created_at,expires_at)
			SELECT ?,u.id,c.id,?,?,?,?,?,?,? FROM webauthn_credentials c JOIN users u ON u.id = c.user_id
			WHERE c.id = ? AND c.public_key = ? AND c.rp_id = ? AND c.origin = ? AND u.id = ? AND ${AUTHORIZED_USER}
			AND (SELECT count(*) FROM account_initializations i WHERE i.user_id = u.id AND i.created_at > ?) < 24
			AND (SELECT count(*) FROM account_initializations i WHERE i.user_id = u.id AND i.created_at > ?) < 6
			ON CONFLICT(id) DO NOTHING`,
      )
      .bind(
        id,
        profileDigest,
        userSaltCommitment,
        key.public_key,
        prepared.digest,
        prepared.account.toLowerCase(),
        now,
        now + 300,
        credentialRef,
        key.public_key,
        this.scope.rpId,
        this.scope.origin,
        owner,
        ...this.auth(),
        now - 86400,
        now - 600,
      )
      .run();
    if (!result.success || ![0, 1].includes(result.meta.changes))
      throw new WalletAccessError('WALLET_DATA_INVALID');
    await this.owner();
    const stored = await this.select(id).first<Row>();
    if (!stored) throw new InitializationError('INITIALIZATION_LIMIT');
    const attempt = this.decode(stored);
    if (
      attempt.credentialRef !== credentialRef ||
      attempt.prepared.profileDigest !== profileDigest ||
      attempt.input.userSaltCommitment !== userSaltCommitment
    )
      throw new InitializationError('INITIALIZATION_CONFLICT');
    return { ...this.receipt(attempt), input: attempt.input };
  }
  async authorize(id: ResourceId<'operation'>, assertion: WebAuthnAssertionBytes) {
    parseResourceId('operation', id);
    // Public assertion buffers must not change while ownership reads are in flight.
    if (
      !(assertion.authenticatorData instanceof Uint8Array) ||
      assertion.authenticatorData.length > 1024 ||
      !(assertion.clientDataJSON instanceof Uint8Array) ||
      assertion.clientDataJSON.length > 2048 ||
      !(assertion.signatureDER instanceof Uint8Array) ||
      assertion.signatureDER.length > 72
    )
      throw new Error('Invalid assertion size');
    const response = {
      authenticatorData: new Uint8Array(assertion.authenticatorData),
      clientDataJSON: new Uint8Array(assertion.clientDataJSON),
      signatureDER: new Uint8Array(assertion.signatureDER),
    };
    await this.owner();
    const attempt = this.decode(await this.select(id).first<Row>());
    const now = nowSeconds();
    if (attempt.authorizedAt === null && now >= attempt.input.validUntil)
      throw new InitializationError('INITIALIZATION_EXPIRED');
    // An already recorded approval may be replay-read after expiration, but is NOT
    // reauthorized or requeued. The returned receipt never claims execution readiness.
    let proof;
    try {
      proof = authorizeInitialization(attempt.input, response, attempt.authorizedAt ?? now);
    } catch {
      throw new InitializationError('INVALID_INITIALIZATION_ASSERTION');
    }
    if (attempt.authorizedAt !== null) {
      if (attempt.signature !== proof.signature)
        throw new InitializationError('INITIALIZATION_CONFLICT');
      await this.owner();
      return this.receipt(attempt);
    }
    const result = await this.db
      .prepare(
        `UPDATE account_initializations SET authorized_at = ?, assertion_signature = ?, assertion_body = ?
			WHERE id = ? AND authorized_at IS NULL AND expires_at > ? AND approval_digest = ?
			AND EXISTS (SELECT 1 FROM users u JOIN webauthn_credentials c ON c.user_id = u.id
				WHERE u.id = account_initializations.user_id AND c.id = account_initializations.credential_ref
				AND c.public_key = account_initializations.public_key AND c.rp_id = ? AND c.origin = ? AND ${AUTHORIZED_USER})`,
      )
      .bind(
        now,
        proof.signature,
        writeAssertionRecord(response),
        id,
        now,
        proof.digest,
        this.scope.rpId,
        this.scope.origin,
        ...this.auth(),
      )
      .run();
    if (!result.success || ![0, 1].includes(result.meta.changes))
      throw new WalletAccessError('WALLET_DATA_INVALID');
    await this.owner();
    const stored = this.decode(await this.select(id).first<Row>());
    if (stored.authorizedAt === null || stored.signature !== proof.signature)
      throw new InitializationError('INITIALIZATION_CONFLICT');
    return this.receipt(stored);
  }
}
