import type { Hex } from 'viem';
import { Role, SignerKind } from '@gatopago/shared/v3/security-policy';
import { parseNetworkId, parseResourceId, type ResourceId } from '@gatopago/shared/v3/primitives';
import type { WebAuthnScope } from '@gatopago/shared/v3/webauthn';
import type { Principal } from '../auth/principal';
import { AUTHORIZED_USER, authorizationValues } from '../auth/authorization';
import { normalizeDisplayName, registrationProfile } from '../auth/profile';
import { WalletRepository, WalletAccessError, parseWalletAccount } from './repository';
import { inspectWalletAccount, type InspectionProfile } from './inspection';

type Owned = Awaited<ReturnType<WalletRepository['ownedAccount']>>;
export type ReceivingProfile = InspectionProfile & {
  verifier: { address: Hex; runtime_code_hash: Hex };
};
export type ReceivingProfiles = (
  account: Owned,
  signal: AbortSignal,
) => Promise<readonly ReceivingProfile[]>;
export class ProfileError extends Error {
  constructor(
    readonly code: 'USERNAME_UNAVAILABLE' | 'PROFILE_IMMUTABLE' | 'RECEIVING_UNAVAILABLE',
  ) {
    super(code);
    this.name = 'ProfileError';
  }
}
type Profile = {
  user_id: ResourceId<'user'>;
  display_name: string;
  username: string | null;
  username_reserved_until: number | null;
  username_published_at: number | null;
  receiving_wallet_id: ResourceId<'wallet'> | null;
};
const fields =
  'id AS user_id,display_name,username,username_reserved_until,username_published_at,receiving_wallet_id';
const now = () => Math.floor(Date.now() / 1000);

export class ProfileRepository {
  private readonly db: D1DatabaseSession;
  private readonly wallets: WalletRepository;
  constructor(
    private readonly database: D1Database,
    private readonly identity: Principal,
    private readonly scope: WebAuthnScope,
    private readonly profiles: ReceivingProfiles,
  ) {
    this.db = database.withSession('first-primary');
    this.wallets = new WalletRepository(database, identity);
  }
  async read(): Promise<Profile> {
    await this.wallets.getSession();
    const profile = await this.db
      .prepare(`SELECT ${fields} FROM users u WHERE ${AUTHORIZED_USER}`)
      .bind(...authorizationValues(this.identity))
      .first<Profile>();
    if (!profile) throw new WalletAccessError('UNAUTHENTICATED');

    if (
      profile.username_published_at === null &&
      profile.username_reserved_until !== null &&
      profile.username_reserved_until <= now()
    ) {
      return { ...profile, username: null, username_reserved_until: null };
    }
    return profile;
  }
  async rename(name: unknown) {
    const value = normalizeDisplayName(name);
    await this.wallets.getSession();
    const changed = await this.db
      .prepare(`UPDATE users AS u SET display_name = ? WHERE ${AUTHORIZED_USER}`)
      .bind(value, ...authorizationValues(this.identity))
      .run();
    if (changed.meta.changes !== 1) throw new WalletAccessError('UNAUTHENTICATED');
    return this.read();
  }
  async publish(
    input: { username: unknown; wallet_id: unknown; wallet_account_id: unknown },
    signal: AbortSignal,
  ) {
    const { username } = registrationProfile('Profile', input.username);
    const walletId = parseResourceId('wallet', input.wallet_id),
      accountId = parseResourceId('walletAccount', input.wallet_account_id);
    const before = await this.read();
    if (
      before.username_published_at !== null &&
      (before.username !== username || before.receiving_wallet_id !== walletId)
    )
      throw new ProfileError('PROFILE_IMMUTABLE');
    const owned = await this.wallets.ownedAccount(walletId, accountId);
    const evidence = await verifyReceiving(
      this.database,
      before.user_id,
      this.scope,
      owned,
      await this.profiles(owned, signal),
      signal,
    );
    const current = await this.wallets.ownedAccount(walletId, accountId);
    if (JSON.stringify(current) !== JSON.stringify(owned))
      throw new ProfileError('RECEIVING_UNAVAILABLE');
    signal.throwIfAborted();
    const time = now();
    if (time >= evidence.security_expires_at) throw new ProfileError('RECEIVING_UNAVAILABLE');
    try {
      const results = await this.db.batch([
        this.db
          .prepare(
            `UPDATE users SET username = NULL, username_reserved_until = NULL
          WHERE username = ? AND username_published_at IS NULL AND username_reserved_until <= ?`,
          )
          .bind(username, time),
        this.db
          .prepare(
            `UPDATE users AS u SET username = ?, username_reserved_until = NULL,
          username_published_at = COALESCE(username_published_at,?), receiving_wallet_id = ?
          WHERE ${AUTHORIZED_USER} AND (username_published_at IS NULL OR (username = ? AND receiving_wallet_id = ?))
          AND EXISTS (SELECT 1 FROM wallets w JOIN wallet_accounts a ON a.wallet_id = w.id
            WHERE w.id = ? AND w.user_id = u.id AND w.status = 'active' AND a.id = ?
            AND a.address = ? AND a.deployment_manifest_sha256 = ? AND a.deployment_state NOT IN ('unsupported','retired'))`,
          )
          .bind(
            username,
            time,
            walletId,
            ...authorizationValues(this.identity),
            username,
            walletId,
            walletId,
            accountId,
            owned.address,
            owned.deployment_manifest_sha256,
          ),
      ]);
      if (results[1].meta.changes !== 1) {
        await this.wallets.getSession();
        throw new ProfileError('PROFILE_IMMUTABLE');
      }
    } catch (error) {
      if (error instanceof ProfileError || error instanceof WalletAccessError) throw error;
      const occupied = await this.db
        .prepare('SELECT id FROM users WHERE username = ?')
        .bind(username)
        .first<{ id: string }>();
      if (occupied && occupied.id !== before.user_id)
        throw new ProfileError('USERNAME_UNAVAILABLE');
      throw error;
    }
    return this.read();
  }
}

async function verifyReceiving(
  database: D1Database,
  userId: string,
  scope: WebAuthnScope,
  account: Owned,
  profiles: readonly ReceivingProfile[],
  signal: AbortSignal,
) {
  const pins = structuredClone(profiles);
  const evidence = await inspectWalletAccount(account, pins, signal);
  if (evidence.status !== 'recognized' || evidence.security.phase !== 'active_policy')
    throw new ProfileError('RECEIVING_UNAVAILABLE');
  const profile = pins.find((p) => p.digest === account.deployment_manifest_sha256)!;
  const rows = await database
    .withSession('first-primary')
    .prepare(
      `SELECT public_key FROM webauthn_credentials
    WHERE user_id = ? AND rp_id = ? AND origin = ? AND revoked_at IS NULL`,
    )
    .bind(userId, scope.rpId, scope.origin)
    .all<{ public_key: string }>();
  const keys = new Set(rows.results.map((row) => row.public_key));
  const available = evidence.security.policy.signers.filter(
    (s) =>
      s.kind === SignerKind.WEBAUTHN &&
      (s.roles & Role.SPEND) !== 0 &&
      s.verifier === profile.verifier.address &&
      s.verifierCodeHash === profile.verifier.runtime_code_hash &&
      keys.has(s.key),
  );
  if (available.length < evidence.security.policy.spendThreshold)
    throw new ProfileError('RECEIVING_UNAVAILABLE');
  signal.throwIfAborted();
  if (now() >= evidence.security_expires_at) throw new ProfileError('RECEIVING_UNAVAILABLE');
  return evidence;
}

export async function resolveRecipient(
  database: D1Database,
  scope: WebAuthnScope,
  usernameInput: unknown,
  networkInput: unknown,
  profiles: ReceivingProfiles,
  signal: AbortSignal,
) {
  const { username } = registrationProfile('Profile', usernameInput),
    network = parseNetworkId(networkInput);
  const db = database.withSession('first-primary');
  const read = () =>
    db
      .prepare(
        `SELECT a.*,w.account_id,w.initial_security_commitment,w.user_salt_commitment,w.status AS wallet_status,
    u.id AS user_id,u.username,u.display_name,u.username_published_at FROM users u
    JOIN wallets w ON w.id = u.receiving_wallet_id AND w.user_id = u.id
    JOIN wallet_accounts a ON a.wallet_id = w.id AND a.address = w.canonical_address
    WHERE u.username = ? AND u.username_published_at IS NOT NULL AND u.disabled_at IS NULL
    AND w.status = 'active' AND a.network_id = ?`,
      )
      .bind(username, network)
      .first<Record<string, unknown>>();
  const row = await read();
  if (!row) throw new WalletAccessError('NOT_FOUND');
  const account = parseWalletAccount(row),
    userId = parseResourceId('user', row.user_id);
  const evidence = await verifyReceiving(
    database,
    userId,
    scope,
    account,
    await profiles(account, signal),
    signal,
  );
  if (JSON.stringify(await read()) !== JSON.stringify(row))
    throw new ProfileError('RECEIVING_UNAVAILABLE');
  signal.throwIfAborted();
  if (now() >= evidence.security_expires_at) throw new ProfileError('RECEIVING_UNAVAILABLE');
  return {
    username,
    display_name: row.display_name as string,
    network_id: account.network_id,
    address: account.address,
    verified_at: evidence.security_observed_at,
    expires_at: evidence.security_expires_at,
  };
}
