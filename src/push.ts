import { importPKCS8, SignJWT } from 'jose';
import { formatUnits } from 'viem';
import type { Budget } from './budget';
import type { Config } from './config';
import { HttpError, json, readJson } from './http';
import { signedInMember } from './profile';

/** Firebase Cloud Messaging tokens are opaque; this bounds what is stored. */
const TOKEN = /^[\w:-]{20,4096}$/;

/** `POST /app/v1/push-tokens`: `{token, language}` of a device that wants payment notifications. */
export async function savePushToken(request: Request, env: Env, config: Config) {
  const member = await signedInMember(request, env, config);
  const body = await readJson<{ token?: unknown; language?: unknown }>(request);
  if (typeof body.token !== 'string' || !TOKEN.test(body.token))
    throw new HttpError(400, 'INVALID_PUSH_TOKEN');
  const language = body.language === 'en' ? 'en' : 'es';
  await env.WALLET_DB.prepare(
    `INSERT INTO push_tokens (token, member_id, language, created_at) VALUES (?, ?, ?, unixepoch())
     ON CONFLICT (token) DO UPDATE SET member_id = excluded.member_id, language = excluded.language`,
  )
    .bind(body.token, member.id, language)
    .run();
  return json({});
}

/** `DELETE /app/v1/push-tokens/:token`: the device stops receiving notifications (sign-out). */
export async function deletePushToken(request: Request, env: Env, config: Config, token: string) {
  const member = await signedInMember(request, env, config);
  await env.WALLET_DB.prepare('DELETE FROM push_tokens WHERE token = ? AND member_id = ?')
    .bind(token, member.id)
    .run();
  return json({});
}

let accessToken: { value: string; expiresAt: number } | null = null;

/** OAuth 2.0 access token of the Firebase service account (JWT bearer grant), reused for an hour. */
async function firebaseAccessToken(account: NonNullable<Config['firebase']>): Promise<string> {
  const now = Math.floor(Date.now() / 1000);
  if (accessToken && accessToken.expiresAt > now + 60) return accessToken.value;
  const assertion = await new SignJWT({
    scope: 'https://www.googleapis.com/auth/firebase.messaging',
  })
    .setProtectedHeader({ alg: 'RS256', typ: 'JWT' })
    .setIssuer(account.clientEmail)
    .setAudience('https://oauth2.googleapis.com/token')
    .setIssuedAt(now)
    .setExpirationTime(now + 3600)
    .sign(await importPKCS8(account.privateKey, 'RS256'));
  const response = await fetch('https://oauth2.googleapis.com/token', {
    method: 'POST',
    headers: { 'Content-Type': 'application/x-www-form-urlencoded' },
    body: new URLSearchParams({
      grant_type: 'urn:ietf:params:oauth:grant-type:jwt-bearer',
      assertion,
    }),
  });
  if (!response.ok) throw new Error(`FIREBASE_AUTH_FAILED: ${response.status}`);
  const { access_token, expires_in } = await response.json<{
    access_token: string;
    expires_in: number;
  }>();
  accessToken = { value: access_token, expiresAt: now + expires_in };
  return access_token;
}

/** How recent a movement must be to be notified: older ones are history, not news. */
export const NOTIFY_SECONDS = 3_600;

/** EVM addresses are kept lowercase; Stellar strkeys as they are. */
const stored = (address: string) => (address.startsWith('0x') ? address.toLowerCase() : address);
const short = (address: string) => `${address.slice(0, 6)}…${address.slice(-4)}`;

/** A movement to tell its receiver about. */
export interface Notice {
  from: string;
  to: string;
  value: bigint;
  coin: { symbol: string; decimals: number };
  /**
   * Set for money that arrived from another network (a CCTP mint, which comes from no one): the
   * network's name, or null when it is not known.
   */
  origin?: string | null;
  /** The movement's id: a device shows one notification per movement, even if it comes twice. */
  tag: string;
}

/**
 * Sends `notice` to every device its receiver enabled. Only the fact and the amount travel: the app
 * reads the details from the chain and the API. `sent` also when nobody is to be told; `retry`
 * when FCM failed for a device; `budget` when the run has no requests left for it.
 */
export async function deliver(
  env: Env,
  config: Config,
  notice: Notice,
  budget: Budget,
): Promise<'sent' | 'retry' | 'budget'> {
  if (!config.firebase) return 'sent';
  // Addresses are EVM accounts or members' Stellar accounts.
  const { results } = await env.WALLET_DB.prepare(
    `SELECT push_tokens.token, push_tokens.language, sender.username AS sender
     FROM members JOIN push_tokens ON push_tokens.member_id = members.id
     LEFT JOIN members AS sender ON sender.address = ?1 OR sender.stellar_address = ?1
     WHERE members.address = ?2 OR members.stellar_address = ?2`,
  )
    .bind(stored(notice.from), stored(notice.to))
    .all<{ token: string; language: string; sender: string | null }>();
  const renewing = !accessToken || accessToken.expiresAt <= Math.floor(Date.now() / 1000) + 60;
  // Every device at once or none: a retry sends to all of them again (the tag keeps it one).
  if (!budget.take(results.length + (renewing && results.length > 0 ? 1 : 0))) return 'budget';
  const amount = Number(formatUnits(notice.value, notice.coin.decimals));
  let outcome: 'sent' | 'retry' = 'sent';
  for (const { token, language, sender } of results) {
    const en = language === 'en';
    // The exact amount, as the app shows a movement: two to six decimals.
    const value = `${amount.toLocaleString(en ? 'en' : 'es', {
      minimumFractionDigits: 2,
      maximumFractionDigits: 6,
    })} ${notice.coin.symbol}`;
    const arrived = notice.origin !== undefined;
    const from = sender ? `@${sender}` : short(notice.from);
    const origin = notice.origin ?? (en ? 'another network' : 'otra red');
    const message = {
      token,
      data: {
        type: 'movement',
        tag: notice.tag,
        title: arrived
          ? en
            ? `${value} arrived`
            : `Llegaron ${value}`
          : en
            ? `You received ${value}`
            : `Recibiste ${value}`,
        body: arrived
          ? en
            ? `From ${origin}`
            : `Desde ${origin}`
          : en
            ? `From ${from}`
            : `De ${from}`,
        // The app opens in the device's language: English is `?lang=en`, as everywhere in it.
        link: en ? '/statement?lang=en' : '/statement',
      },
      webpush: { headers: { Urgency: 'high' } },
    };
    const response = await fetch(
      `https://fcm.googleapis.com/v1/projects/${config.firebase.projectId}/messages:send`,
      {
        method: 'POST',
        headers: {
          Authorization: `Bearer ${await firebaseAccessToken(config.firebase)}`,
          'Content-Type': 'application/json',
        },
        body: JSON.stringify({ message }),
      },
    ).catch(() => null);
    // An uninstalled app or revoked permission leaves a token FCM no longer knows.
    if (response?.status === 404)
      await env.WALLET_DB.prepare('DELETE FROM push_tokens WHERE token = ?').bind(token).run();
    else if (!response?.ok) {
      console.error('FCM send failed', response?.status ?? 'network');
      outcome = 'retry';
    }
  }
  return outcome;
}
