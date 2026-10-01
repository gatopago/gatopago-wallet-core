import type { AuthBindings } from './config';

type LimitScope = 'ip' | 'global';

export async function privateLimitKey(env: AuthBindings, scope: LimitScope, value: string): Promise<string> {
  const encoder = new TextEncoder();
  const key = await crypto.subtle.importKey('raw', encoder.encode(env.AUTH_RATE_LIMIT_PEPPER),
    { name: 'HMAC', hash: 'SHA-256' }, false, ['sign']);
  const signature = await crypto.subtle.sign('HMAC', key,
    encoder.encode(JSON.stringify(['gatopago-v3-auth', env.GATOPAGO_ENVIRONMENT, scope, value])));
  return [...new Uint8Array(signature)].map((byte) => byte.toString(16).padStart(2, '0')).join('');
}

/** One conditional write, never read-then-increment. Rejections do not extend a hold. */
export async function consumeLimit(db: AuthBindings['WALLET_DB'], scope: LimitScope,
  key: string, now: number, limit: number): Promise<boolean> {
  const window = 3600;
  if (!Number.isSafeInteger(now) || now < 0 || !Number.isSafeInteger(limit) || limit < 1) throw new Error('Invalid quota time');
  const result = await db.prepare(`
    INSERT INTO auth_limits (scope, key_hash, count, reset_at) VALUES (?, ?, 1, ?)
    ON CONFLICT(scope, key_hash) DO UPDATE SET
      count = CASE WHEN reset_at <= ? THEN 1 ELSE count + 1 END,
      reset_at = CASE WHEN reset_at <= ? THEN ? ELSE reset_at END
    WHERE reset_at <= ? OR count < ?
  `).bind(scope, key, now + window, now, now, now + window, now, limit).run();
  if (!result.success || ![0, 1].includes(result.meta.changes)) throw new Error('Quota write failed');
  return result.meta.changes === 1;
}

export async function pruneLimits(db: AuthBindings['WALLET_DB'], now: number): Promise<void> {
  // Bounded work; a malicious request cannot turn cleanup into an unbounded scan.
  const result = await db.prepare(`DELETE FROM auth_limits WHERE rowid IN
    (SELECT rowid FROM auth_limits WHERE reset_at <= ? ORDER BY reset_at LIMIT 256)`)
    .bind(now).run();
  if (!result.success) throw new Error('Quota cleanup failed');
}
