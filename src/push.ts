import { formatUnits } from 'viem';
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

const base64url = (bytes: ArrayBuffer | Uint8Array) =>
  btoa(String.fromCharCode(...new Uint8Array(bytes)))
    .replaceAll('+', '-')
    .replaceAll('/', '_')
    .replace(/=+$/, '');

let accessToken: { value: string; expiresAt: number } | null = null;

/** OAuth 2.0 access token of the Firebase service account (JWT bearer grant), reused for an hour. */
async function firebaseAccessToken(account: NonNullable<Config['firebase']>): Promise<string> {
  const now = Math.floor(Date.now() / 1000);
  if (accessToken && accessToken.expiresAt > now + 60) return accessToken.value;
  const encode = (value: object) => base64url(new TextEncoder().encode(JSON.stringify(value)));
  const unsigned = `${encode({ alg: 'RS256', typ: 'JWT' })}.${encode({
    iss: account.clientEmail,
    scope: 'https://www.googleapis.com/auth/firebase.messaging',
    aud: 'https://oauth2.googleapis.com/token',
    iat: now,
    exp: now + 3600,
  })}`;
  const der = Uint8Array.from(atob(account.privateKey.replace(/-----[^-]+-----|\s/g, '')), (char) =>
    char.charCodeAt(0),
  );
  const key = await crypto.subtle.importKey(
    'pkcs8',
    der,
    { name: 'RSASSA-PKCS1-v1_5', hash: 'SHA-256' },
    false,
    ['sign'],
  );
  const signature = await crypto.subtle.sign(
    'RSASSA-PKCS1-v1_5',
    key,
    new TextEncoder().encode(unsigned),
  );
  const response = await fetch('https://oauth2.googleapis.com/token', {
    method: 'POST',
    headers: { 'Content-Type': 'application/x-www-form-urlencoded' },
    body: new URLSearchParams({
      grant_type: 'urn:ietf:params:oauth:grant-type:jwt-bearer',
      assertion: `${unsigned}.${base64url(signature)}`,
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

/** EVM addresses are kept lowercase; Stellar strkeys as they are. */
const stored = (address: string) => (address.startsWith('0x') ? address.toLowerCase() : address);
const short = (address: string) => `${address.slice(0, 6)}…${address.slice(-4)}`;

/**
 * Notifies members of the transfers they just received, on every device they enabled. Only
 * the fact and the amount travel: the app reads the details from the chain and the API.
 */
export async function notifyReceived(
  env: Env,
  config: Config,
  transfers: readonly {
    from: string;
    to: string;
    value: bigint;
    /** USDC unless said otherwise (AUSD), and its decimals. */
    coin?: { symbol: string; decimals: number };
  }[],
) {
  if (!config.firebase || transfers.length === 0) return;
  for (const transfer of transfers) {
    // Addresses are EVM accounts or members' Stellar accounts.
    const { results } = await env.WALLET_DB.prepare(
      `SELECT push_tokens.token, push_tokens.language, sender.username AS sender
       FROM members JOIN push_tokens ON push_tokens.member_id = members.id
       LEFT JOIN members AS sender ON sender.address =
         COALESCE((SELECT member_address FROM stellar_accounts WHERE address = ?1), ?1)
       WHERE members.address =
         COALESCE((SELECT member_address FROM stellar_accounts WHERE address = ?2), ?2)`,
    )
      .bind(stored(transfer.from), stored(transfer.to))
      .all<{ token: string; language: string; sender: string | null }>();
    const coin = transfer.coin ?? { symbol: 'USDC', decimals: 6 };
    const amount = Number(formatUnits(transfer.value, coin.decimals));
    for (const { token, language, sender } of results) {
      const en = language === 'en';
      const from = sender ? `@${sender}` : short(transfer.from);
      const message = {
        token,
        data: {
          type: 'movement',
          title: en
            ? `You received ${amount.toLocaleString('en', { minimumFractionDigits: 2 })} ${coin.symbol}`
            : `Recibiste ${amount.toLocaleString('es', { minimumFractionDigits: 2 })} ${coin.symbol}`,
          body: en ? `From ${from}` : `De ${from}`,
          link: '/statement',
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
      );
      // An uninstalled app or revoked permission leaves a token FCM no longer knows.
      if (response.status === 404)
        await env.WALLET_DB.prepare('DELETE FROM push_tokens WHERE token = ?').bind(token).run();
      else if (!response.ok) console.error('FCM send failed', response.status);
    }
  }
}
