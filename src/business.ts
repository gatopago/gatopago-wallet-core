import { bytesToHex, isAddressEqual, sha256, type Hex } from 'viem';
import { parseSiweMessage, verifySiweMessage } from 'viem/siwe';
import type { Config } from './config';
import { HttpError, json, rateLimit, readJson } from './http';
import { authenticate, issueSession } from './session';

/** How long the console's QR stays valid, and how long after it the console may still collect. */
const REQUEST_SECONDS = 120;
const COLLECT_SECONDS = 60;

const now = () => Math.floor(Date.now() / 1000);
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
}

/**
 * `POST /app/v1/business-login`, from GatoPago Business: a sign-in request to approve from the app.
 * The console shows `approve_url` as a QR and keeps `secret`, the only way to collect the session.
 */
export async function requestBusinessLogin(
  request: Request,
  env: Env,
  config: Config,
): Promise<Response> {
  if (!config.businessOrigin) throw new HttpError(404, 'NOT_FOUND');
  await rateLimit(env, request, 'auth');
  const { device } = await readJson<{ device?: unknown }>(request);
  const id = random(16).slice(2);
  const secret = random(32);
  const cf = request.cf as { city?: string; country?: string } | undefined;
  const place = [cf?.city, cf?.country].filter(Boolean).join(', ') || null;
  const expiresAt = now() + REQUEST_SECONDS;
  await env.WALLET_DB.prepare(
    'INSERT INTO business_logins (id, secret_hash, device, place, expires_at) VALUES (?, ?, ?, ?, ?)',
  )
    .bind(id, sha256(secret), String(device ?? '').slice(0, 60) || 'Navegador', place, expiresAt)
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
  const session = await issueSession(
    config,
    { id: login.member_id, address: login.address },
    'business',
  );
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
  await authenticate(request, config);
  const login = await pendingLogin(env, id);
  return json({ device: login.device, place: login.place, expires_at: login.expires_at });
}

/**
 * `POST /app/v1/business-approvals/:id`: the member approves the console's sign-in with a SIWE
 * message signed by their passkey, whose nonce is the request: a stolen app session alone cannot.
 */
export async function approveBusinessLogin(
  request: Request,
  env: Env,
  config: Config,
  id: string,
): Promise<Response> {
  const session = await authenticate(request, config);
  await pendingLogin(env, id);
  const body = await readJson<{ message?: unknown; signature?: unknown }>(request);
  if (typeof body.message !== 'string' || typeof body.signature !== 'string')
    throw new HttpError(400, 'INVALID_REQUEST');
  const message = parseSiweMessage(body.message);
  const domain = new URL(config.webOrigin).host;
  const network = config.networks.get(`eip155:${message.chainId}`);
  if (
    !network ||
    !message.address ||
    !isAddressEqual(message.address, session.address) ||
    message.nonce !== id ||
    message.domain !== domain ||
    message.uri !== config.webOrigin ||
    !message.issuedAt ||
    Math.abs(Date.now() - message.issuedAt.getTime()) > REQUEST_SECONDS * 1000
  )
    throw new HttpError(400, 'INVALID_MESSAGE');
  if (
    !(await verifySiweMessage(network.client, {
      message: body.message,
      signature: body.signature as Hex,
      domain,
    }))
  )
    throw new HttpError(401, 'SIGNATURE_INVALID');
  const approved = await env.WALLET_DB.prepare(
    'UPDATE business_logins SET member_id = ?, address = ? WHERE id = ? AND member_id IS NULL AND expires_at >= ? RETURNING id',
  )
    .bind(session.userId, session.address, id, now())
    .first();
  if (!approved) throw new HttpError(410, 'LOGIN_EXPIRED');
  return json({ approved: true });
}
