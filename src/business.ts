import {
  bytesToHex,
  getAddress,
  hexToBytes,
  isAddressEqual,
  sha256,
  type Address,
  type Hex,
} from 'viem';
import { parseSiweMessage } from 'viem/siwe';
import { businessKeyResource, businessSignInMessage } from '@gatopago/shared/passkey';
import { messageSigner } from '@gatopago/shared/wallet';
import { currentOwners } from './approvals';
import type { Config } from './config';
import { HttpError, json, rateLimit, readJson } from './http';
import { issueSession } from './session';
import { memberByAddress } from './members';
import { signedInMember } from './profile';

/** How long the console's QR stays valid, and how long after it the console may still collect. */
const REQUEST_SECONDS = 120;
const COLLECT_SECONDS = 60;

/** A Business key: 32-byte Ed25519 public key, in lowercase hex. */
const PUBLIC_KEY = /^0x[0-9a-f]{64}$/;

const now = () => Math.floor(Date.now() / 1000);
/** Hex as the bytes Web Crypto takes. */
const bytes = (hex: string) => new Uint8Array(hexToBytes(hex as Hex));
const random = (bytes: number) => bytesToHex(crypto.getRandomValues(new Uint8Array(bytes)));

interface LoginRow {
  id: string;
  secret_hash: Hex;
  device: string;
  place: string | null;
  expires_at: number;
  member_id: string | null;
  address: string | null;
  collected: number;
  public_key: Hex | null;
}

/**
 * `POST /app/v1/business-login`, from GatoPago Business: a sign-in request to approve from the app.
 * The console shows `approve_url` as a QR and keeps `secret`, the only way to collect the session.
 * With `public_key`, approving it also binds that Business key to the account.
 */
export async function requestBusinessLogin(
  request: Request,
  env: Env,
  config: Config,
): Promise<Response> {
  if (!config.businessOrigin) throw new HttpError(404, 'NOT_FOUND');
  await rateLimit(env, request, 'auth');
  const { device, public_key } = await readJson<{ device?: unknown; public_key?: unknown }>(
    request,
  );
  if (public_key !== undefined && (typeof public_key !== 'string' || !PUBLIC_KEY.test(public_key)))
    throw new HttpError(400, 'INVALID_REQUEST');
  const id = random(16).slice(2);
  const secret = random(32);
  const cf = request.cf as { city?: string; country?: string } | undefined;
  const place = [cf?.city, cf?.country].filter(Boolean).join(', ') || null;
  const expiresAt = now() + REQUEST_SECONDS;
  await env.WALLET_DB.prepare(
    `INSERT INTO business_logins (id, secret_hash, device, place, expires_at, public_key)
     VALUES (?, ?, ?, ?, ?, ?)`,
  )
    .bind(
      id,
      sha256(secret),
      String(device ?? '').slice(0, 60) || 'Navegador',
      place,
      expiresAt,
      public_key ?? null,
    )
    .run();
  return json({
    id,
    secret,
    expires_at: expiresAt,
    approve_url: `${config.webOrigin}/approve?request=${id}`,
  });
}

/**
 * `GET /app/v1/business-login/:id` with `Authorization: Bearer <secret>`: the console waits here.
 * Once approved it receives a session for Business only, a single time.
 */
export async function collectBusinessLogin(
  request: Request,
  env: Env,
  config: Config,
  id: string,
): Promise<Response> {
  const secret = /^Bearer (0x[0-9a-f]{64})$/.exec(request.headers.get('Authorization') ?? '')?.[1];
  const login = await env.WALLET_DB.prepare('SELECT * FROM business_logins WHERE id = ?')
    .bind(id)
    .first<LoginRow>();
  if (!login || !secret || sha256(secret as Hex) !== login.secret_hash)
    throw new HttpError(404, 'NOT_FOUND');
  if (login.collected || now() > login.expires_at + COLLECT_SECONDS)
    return json({ status: 'expired' });
  if (!login.member_id || !login.address)
    return json({ status: now() > login.expires_at ? 'expired' : 'pending' });
  const collected = await env.WALLET_DB.prepare(
    'UPDATE business_logins SET collected = 1 WHERE id = ? AND collected = 0 RETURNING id',
  )
    .bind(id)
    .first();
  if (!collected) return json({ status: 'expired' });
  const member = await memberByAddress(env.WALLET_DB, login.address as Address);
  if (!member) return json({ status: 'expired' });
  const session = await issueSession(config, member, 'business', login.public_key ?? undefined);
  return json({
    status: 'approved',
    token: session.token,
    expires_at: session.expiresAt,
    address: login.address,
  });
}

async function pendingLogin(env: Env, id: string): Promise<LoginRow> {
  const login = await env.WALLET_DB.prepare('SELECT * FROM business_logins WHERE id = ?')
    .bind(id)
    .first<LoginRow>();
  if (!login || login.member_id || now() > login.expires_at)
    throw new HttpError(410, 'LOGIN_EXPIRED');
  return login;
}

/** `GET /app/v1/business-approvals/:id`, from the app: what the member is about to approve. */
export async function readBusinessApproval(
  request: Request,
  env: Env,
  config: Config,
  id: string,
): Promise<Response> {
  await signedInMember(request, env, config);
  const login = await pendingLogin(env, id);
  return json({
    device: login.device,
    place: login.place,
    expires_at: login.expires_at,
    public_key: login.public_key,
  });
}

/**
 * `POST /app/v1/business-approvals/:id`: the member approves the console's sign-in with a SIWE
 * message signed by their passkey, whose nonce is the request: a stolen app session alone cannot.
 * A request with a Business key needs that exact key among the message's resources, and binds it
 * to the account and to the owner that signed.
 */
export async function approveBusinessLogin(
  request: Request,
  env: Env,
  config: Config,
  id: string,
): Promise<Response> {
  const member = await signedInMember(request, env, config);
  const login = await pendingLogin(env, id);
  const body = await readJson<{ message?: unknown; signature?: unknown; initial_owners?: unknown }>(
    request,
  );
  if (typeof body.message !== 'string' || typeof body.signature !== 'string')
    throw new HttpError(400, 'INVALID_REQUEST');
  const message = parseSiweMessage(body.message);
  const domain = new URL(config.webOrigin).host;
  const network = config.networks.get(`eip155:${message.chainId}`);
  if (
    !network ||
    !message.address ||
    !isAddressEqual(message.address, member.address) ||
    message.nonce !== id ||
    message.domain !== domain ||
    message.uri !== config.webOrigin ||
    !message.issuedAt ||
    Math.abs(Date.now() - message.issuedAt.getTime()) > REQUEST_SECONDS * 1000 ||
    (login.public_key && !message.resources?.includes(businessKeyResource(login.public_key)))
  )
    throw new HttpError(400, 'INVALID_MESSAGE');
  // Signed by an owner now, by the approvals Wallet Core verified (see `createSession`).
  const owner = await messageSigner(network.client, {
    account: member.address,
    owners: await currentOwners(env, config, member, body.initial_owners),
    message: body.message,
    signature: body.signature as Hex,
  });
  if (!owner) throw new HttpError(401, 'SIGNATURE_INVALID');
  const bound = login.public_key
    ? await env.WALLET_DB.prepare('SELECT member_id FROM business_keys WHERE public_key = ?')
        .bind(login.public_key)
        .first<string>('member_id')
    : null;
  if (bound && bound !== member.id) throw new HttpError(409, 'BUSINESS_KEY_TAKEN');
  const approved = await env.WALLET_DB.prepare(
    'UPDATE business_logins SET member_id = ?, address = ? WHERE id = ? AND member_id IS NULL AND expires_at >= ? RETURNING id',
  )
    .bind(member.id, getAddress(member.address), id, now())
    .first();
  if (!approved) throw new HttpError(410, 'LOGIN_EXPIRED');
  if (login.public_key)
    await env.WALLET_DB.prepare(
      `INSERT INTO business_keys (public_key, member_id, owner, created_at) VALUES (?, ?, ?, ?)
       ON CONFLICT (public_key) DO UPDATE SET owner = excluded.owner, created_at = excluded.created_at`,
    )
      .bind(login.public_key, member.id, owner.toLowerCase(), now())
      .run();
  return json({ approved: true });
}

/**
 * `POST /app/v1/business-login/key`, from GatoPago Business: `{public_key, nonce, signature}`, the
 * Business key's Ed25519 signature of `businessSignInMessage` over a single-use nonce
 * (`POST /app/v1/auth/nonce`). It counts while the owner that approved it owns the account; the
 * session carries the key, so removing it ends the session too.
 */
export async function signInWithBusinessKey(
  request: Request,
  env: Env,
  config: Config,
): Promise<Response> {
  if (!config.businessOrigin) throw new HttpError(404, 'NOT_FOUND');
  await rateLimit(env, request, 'auth');
  const body = await readJson<{ public_key?: unknown; nonce?: unknown; signature?: unknown }>(
    request,
  );
  if (
    typeof body.public_key !== 'string' ||
    !PUBLIC_KEY.test(body.public_key) ||
    typeof body.nonce !== 'string' ||
    typeof body.signature !== 'string' ||
    !/^0x[0-9a-f]{128}$/.test(body.signature)
  )
    throw new HttpError(400, 'INVALID_REQUEST');
  const nonce = await env.WALLET_DB.prepare(
    'DELETE FROM siwe_nonces WHERE nonce = ? AND expires_at > ? RETURNING nonce',
  )
    .bind(body.nonce, now())
    .first();
  if (!nonce) throw new HttpError(401, 'NONCE_INVALID');
  const key = await env.WALLET_DB.prepare(
    `SELECT members.address, business_keys.owner FROM business_keys
     JOIN members ON members.id = business_keys.member_id WHERE public_key = ?`,
  )
    .bind(body.public_key)
    .first<{ address: Address; owner: Hex }>();
  if (!key) throw new HttpError(404, 'BUSINESS_KEY_UNKNOWN');
  const valid = await crypto.subtle.verify(
    'Ed25519',
    await crypto.subtle.importKey('raw', bytes(body.public_key), 'Ed25519', false, ['verify']),
    bytes(body.signature),
    businessSignInMessage(config.businessOrigin, body.nonce),
  );
  if (!valid) throw new HttpError(401, 'SIGNATURE_INVALID');
  const member = (await memberByAddress(env.WALLET_DB, key.address))!;
  // The owner that approved it was removed: the key goes with it.
  const owners = await currentOwners(env, config, member, undefined);
  if (!owners.some((owner) => owner.toLowerCase() === key.owner)) {
    await env.WALLET_DB.prepare('DELETE FROM business_keys WHERE public_key = ?')
      .bind(body.public_key)
      .run();
    throw new HttpError(404, 'BUSINESS_KEY_UNKNOWN');
  }
  const session = await issueSession(config, member, 'business', body.public_key);
  return json({ token: session.token, expires_at: session.expiresAt, address: member.address });
}

/** `GET /app/v1/business-keys`, from the app: the keys that sign in to Business, newest first. */
export async function readBusinessKeys(request: Request, env: Env, config: Config) {
  const member = await signedInMember(request, env, config);
  const { results } = await env.WALLET_DB.prepare(
    `SELECT public_key, owner, created_at FROM business_keys WHERE member_id = ?
     ORDER BY created_at DESC`,
  )
    .bind(member.id)
    .all();
  return json({ keys: results });
}

/** `DELETE /app/v1/business-keys/:public_key`: the key no longer signs in, and its sessions end. */
export async function deleteBusinessKey(
  request: Request,
  env: Env,
  config: Config,
  publicKey: string,
) {
  const member = await signedInMember(request, env, config);
  await env.WALLET_DB.prepare('DELETE FROM business_keys WHERE public_key = ? AND member_id = ?')
    .bind(publicKey.toLowerCase(), member.id)
    .run();
  return json({});
}
