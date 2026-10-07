import type { Hex } from 'viem';
import { generateSiweNonce, parseSiweMessage, verifySiweMessage } from 'viem/siwe';
import type { Config } from './config';
import { HttpError, json, rateLimit, readJson } from './http';
import { admit, admitOpen, memberByAddress } from './members';
import { issueSession } from './session';

const NONCE_SECONDS = 300;

/** `POST /app/v1/auth/nonce`: a single-use nonce for a SIWE message. */
export async function createNonce(request: Request, env: Env): Promise<Response> {
  await rateLimit(env, request, 'auth');
  const nonce = generateSiweNonce();
  await env.WALLET_DB.prepare('INSERT INTO siwe_nonces (nonce, expires_at) VALUES (?, ?)')
    .bind(nonce, Math.floor(Date.now() / 1000) + NONCE_SECONDS)
    .run();
  return json({ nonce });
}

/**
 * `POST /app/v1/auth/session`: signs in with a SIWE (ERC-4361) message signed by the passkey through
 * the account (ERC-1271, or ERC-6492 before deployment). A new account needs an invitation and a
 * Turnstile token.
 */
export async function createSession(request: Request, env: Env, config: Config): Promise<Response> {
  await rateLimit(env, request, 'auth');
  const body = await readJson<{
    message?: string;
    signature?: Hex;
    invite?: string;
    turnstile?: string;
  }>(request);
  if (typeof body.message !== 'string' || typeof body.signature !== 'string')
    throw new HttpError(400, 'INVALID_REQUEST');

  const message = parseSiweMessage(body.message);
  // The app signs in to the wallet; GatoPago Business, with the same passkeys, gets a session only
  // Flow accepts, and only for existing members.
  const business = !!config.businessOrigin && message.uri === config.businessOrigin;
  const origin = business ? config.businessOrigin! : config.webOrigin;
  const domain = new URL(origin).host;
  const network = config.networks.get(`eip155:${message.chainId}`);
  if (
    !message.address ||
    !message.nonce ||
    !message.issuedAt ||
    !network ||
    message.domain !== domain ||
    message.uri !== origin ||
    Math.abs(Date.now() - message.issuedAt.getTime()) > NONCE_SECONDS * 1000
  )
    throw new HttpError(400, 'INVALID_MESSAGE');

  const nonce = await env.WALLET_DB.prepare(
    'DELETE FROM siwe_nonces WHERE nonce = ? AND expires_at > ? RETURNING nonce',
  )
    .bind(message.nonce, Math.floor(Date.now() / 1000))
    .first();
  if (!nonce) throw new HttpError(401, 'NONCE_INVALID');
  if (
    !(await verifySiweMessage(network.client, {
      message: body.message,
      signature: body.signature,
      domain,
    }))
  )
    throw new HttpError(401, 'SIGNATURE_INVALID');

  let member = await memberByAddress(env.WALLET_DB, message.address);
  if (!member && business) throw new HttpError(403, 'ACCOUNT_NOT_FOUND');
  if (!member) {
    // An invitation sent while sign-up is open still counts for whoever issued it.
    if ((config.inviteOnly && !body.invite) || !body.turnstile)
      throw new HttpError(403, 'INVITE_REQUIRED');
    if (!(await isHuman(config, body.turnstile, request.headers.get('CF-Connecting-IP'))))
      throw new HttpError(403, 'TURNSTILE_FAILED');
    const id = `usr_${crypto.randomUUID()}`;
    if (
      !(await (body.invite
        ? admit(env.WALLET_DB, id, message.address, body.invite)
        : admitOpen(env.WALLET_DB, id, message.address)))
    )
      throw new HttpError(403, body.invite ? 'INVITE_INVALID' : 'ALREADY_MEMBER');
    member = await memberByAddress(env.WALLET_DB, message.address);
  }
  const session = await issueSession(config, member!, business ? 'business' : 'wallet');
  return json({
    token: session.token,
    expires_at: session.expiresAt,
    user_id: member!.id,
    address: message.address,
  });
}

/** `GET /app/v1/auth/signup`: whether new accounts need an invitation now (`INVITE_ONLY`). */
export function readSignup(config: Config): Response {
  return json({ invite_required: config.inviteOnly });
}

async function isHuman(config: Config, token: string, ip: string | null): Promise<boolean> {
  const response = await fetch('https://challenges.cloudflare.com/turnstile/v0/siteverify', {
    method: 'POST',
    body: new URLSearchParams({
      secret: config.turnstileSecret,
      response: token,
      ...(ip ? { remoteip: ip } : {}),
    }),
  });
  if (!response.ok) throw new Error(`Turnstile unavailable: ${response.status}`);
  const result = await response.json<{ success?: boolean; hostname?: string }>();
  return result.success === true && result.hostname === new URL(config.webOrigin).hostname;
}
