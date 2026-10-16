import type { Config } from './config';
import { HttpError, json, rateLimit, readJson } from './http';
import { memberByAddress, memberByUsername, type Member } from './members';
import { authenticate } from './session';

export const USERNAME = /^[a-z][a-z0-9_]{2,29}$/;

/** Social networks a profile may link to; other links could pass for GatoPago on a payment page. */
const SOCIAL_HOSTS = new Set([
  'instagram.com',
  'x.com',
  'twitter.com',
  't.me',
  'tiktok.com',
  'facebook.com',
]);

/** The normalized link, `null` to remove it, or `undefined` when it is not acceptable. */
function socialUrl(value: string): string | null | undefined {
  if (value === '') return null;
  if (value.length > 120 || !URL.canParse(value)) return undefined;
  const url = new URL(value);
  const host = url.hostname.replace(/^www\./, '');
  if (url.protocol !== 'https:' || url.username || url.password || url.port) return undefined;
  if (!SOCIAL_HOSTS.has(host) || url.pathname.length < 2) return undefined;
  return `https://${host}${url.pathname}`;
}

const profile = (member: Member) => ({
  user_id: member.id,
  address: member.address,
  username: member.username,
  display_name: member.displayName,
  social_url: member.socialUrl,
});

/**
 * The member of the wallet session in the request. A session issued before an owner of the account
 * was removed (an earlier generation) no longer counts: it may be that owner's. Nor does one opened
 * with a Business key the member removed since.
 */
export async function signedInMember(
  request: Request,
  env: Env,
  config: Config,
  { business = false }: { business?: boolean } = {},
): Promise<Member> {
  const session = await authenticate(request, config, { business });
  const member = await memberByAddress(env.WALLET_DB, session.address);
  if (!member || session.generation !== member.sessionGeneration)
    throw new HttpError(401, 'UNAUTHENTICATED');
  if (
    session.key &&
    !(await env.WALLET_DB.prepare(
      'SELECT 1 FROM business_keys WHERE public_key = ? AND member_id = ?',
    )
      .bind(session.key, member.id)
      .first())
  )
    throw new HttpError(401, 'UNAUTHENTICATED');
  if (
    session.login &&
    !(await env.WALLET_DB.prepare(
      'SELECT 1 FROM business_logins WHERE id = ? AND member_id = ? AND collected = 1',
    )
      .bind(session.login, member.id)
      .first())
  )
    throw new HttpError(401, 'UNAUTHENTICATED');
  return member;
}

/**
 * `GET /app/v1/auth/session`: whether a session (the wallet's or Business's) still counts, and
 * whose it is. Flow asks it for every session it receives, so a session Wallet Core ended is ended
 * there too.
 */
export async function readSession(request: Request, env: Env, config: Config): Promise<Response> {
  const member = await signedInMember(request, env, config, { business: true });
  return json({ user_id: member.id, address: member.address });
}

/** `GET /app/v1/profile` */
export async function readProfile(request: Request, env: Env, config: Config): Promise<Response> {
  return json(profile(await signedInMember(request, env, config)));
}

/** `PUT /app/v1/profile`: the display name and social link can change; the username is chosen once. */
export async function updateProfile(request: Request, env: Env, config: Config): Promise<Response> {
  const member = await signedInMember(request, env, config);
  const body = await readJson<{ username?: string; display_name?: string; social_url?: string }>(
    request,
  );
  const displayName = body.display_name?.trim();
  if (displayName !== undefined && (displayName.length < 1 || displayName.length > 40))
    throw new HttpError(400, 'INVALID_DISPLAY_NAME');
  const social =
    typeof body.social_url === 'string' ? socialUrl(body.social_url.trim()) : undefined;
  if (body.social_url !== undefined && social === undefined)
    throw new HttpError(400, 'INVALID_SOCIAL_URL');
  if (body.username !== undefined) {
    if (!USERNAME.test(body.username)) throw new HttpError(400, 'INVALID_USERNAME');
    if (member.username !== null && member.username !== body.username)
      throw new HttpError(409, 'USERNAME_ALREADY_SET');
  }
  try {
    await env.WALLET_DB.prepare(
      `UPDATE members SET username = COALESCE(username, ?), display_name = COALESCE(?, display_name),
         social_url = CASE WHEN ? THEN ? ELSE social_url END WHERE id = ?`,
    )
      .bind(
        body.username ?? null,
        displayName ?? null,
        social !== undefined,
        social ?? null,
        member.id,
      )
      .run();
  } catch (error) {
    if (String(error).includes('UNIQUE constraint failed'))
      throw new HttpError(409, 'USERNAME_TAKEN');
    throw error;
  }
  return json(profile((await memberByAddress(env.WALLET_DB, member.address))!));
}

/**
 * `GET /app/v1/recipients/:username`: who receives a payment to `@username`, and where on Stellar
 * (`stellar_address`, null until the cron writes it or with Stellar off).
 */
export async function readRecipient(
  request: Request,
  env: Env,
  username: string,
): Promise<Response> {
  await rateLimit(env, request, 'recipients');
  const member = USERNAME.test(username) ? await memberByUsername(env.WALLET_DB, username) : null;
  if (!member) throw new HttpError(404, 'RECIPIENT_NOT_FOUND');
  return json({
    username: member.username,
    display_name: member.displayName,
    social_url: member.socialUrl,
    address: member.address,
    stellar_address: member.stellarAddress,
  });
}
