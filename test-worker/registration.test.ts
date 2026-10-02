import { env } from 'cloudflare:workers';
import { applyD1Migrations } from 'cloudflare:test';
import { afterEach, beforeAll, beforeEach, describe, expect, it, vi } from 'vitest';
import { invitationHash } from '../src/auth/invitations';
import { issueInvitation } from './invitations.fixture';
import { createResourceId } from '@gatopago/shared/v3/primitives';
import { RegistrationRepository } from '../src/auth/registration';
import { pruneAuthChallenges } from '../src/auth/retention';
import { registrationProfile } from '../src/auth/profile';
import { credential, generateKey } from './passkey.fixture';

const scope = { rpId: 'gatopago.com', origin: 'https://gatopago.com' };
const repo = () => new RegistrationRepository(env.WALLET_DB, 'production', scope);
const now = () => Math.floor(Date.now() / 1000);
const invite = () => issueInvitation(env.WALLET_DB, 'test-operator', now() + 3600);
async function prepare(username = 'daniel', token?: string) {
  const invitation = token ?? (await invite()).token;
  return repo().prepare({ invite: invitation, name: 'Daniel', username });
}
const counts = async () => {
  const results = await env.WALLET_DB.batch<{ n: number }>(['users', 'webauthn_credentials', 'signup_invites']
    .map(table => env.WALLET_DB.prepare(`SELECT count(*) AS n FROM ${table}${table === 'signup_invites' ? ' WHERE consumed_by IS NOT NULL' : ''}`)));
  return results.map(result => result.results[0].n);
};
beforeAll(async () => { await applyD1Migrations(env.WALLET_DB, env.V3_TEST_MIGRATIONS); });
beforeEach(async () => {
  await env.WALLET_DB.exec('DELETE FROM auth_challenges; DELETE FROM signup_invites; DELETE FROM webauthn_enrollments; DELETE FROM webauthn_credentials; UPDATE users SET username = NULL, username_reserved_until = NULL, username_published_at = NULL, receiving_wallet_id = NULL; DELETE FROM wallets; DELETE FROM users;');
});
afterEach(async () => {
  vi.restoreAllMocks(); await env.WALLET_DB.exec('DROP TRIGGER IF EXISTS reject_invitation_consumption');
});

describe('invitation admission with real WebAuthn and transactional D1', () => {
  it('stores only the invitation hash; preparing does not admit or reserve a username', async () => {
    const issued = await invite(); await prepare('daniel', issued.token);
    expect(await counts()).toEqual([0, 0, 0]);
    const saved = await env.WALLET_DB.prepare('SELECT * FROM signup_invites').first();
    expect(saved).toMatchObject({ token_hash: invitationHash(issued.token), consumed_by: null });
    expect(JSON.stringify(saved)).not.toContain(issued.token);
  });
  it('consumes admission, challenge and proof together and uses the internal ID as Firebase UID', async () => {
    const p = await prepare(), result = await repo().complete(p.request_id, credential(p));
    expect(await counts()).toEqual([1, 1, 1]);
    expect(await env.WALLET_DB.prepare('SELECT * FROM users').first()).toMatchObject({ id: result.userId,
      environment: 'production', username: 'daniel', username_published_at: null, receiving_wallet_id: null });
    expect(await env.WALLET_DB.prepare('SELECT * FROM webauthn_credentials').first()).toMatchObject({
      user_id: result.userId, login_enabled: 1, access_version: 1 });
    await expect(repo().complete(p.request_id, credential(p))).rejects.toThrow('CHALLENGE_UNAVAILABLE');
    expect(await counts()).toEqual([1, 1, 1]);
  });
  it('allows exactly one of two simultaneous registrations using the same invitation', async () => {
    const { token } = await invite();
    const a = await prepare('daniel', token), b = await prepare('second', token);
    const results = await Promise.allSettled([repo().complete(a.request_id, credential(a)), repo().complete(b.request_id, credential(b))]);
    expect(results.filter(result => result.status === 'fulfilled')).toHaveLength(1);
    expect(await counts()).toEqual([1, 1, 1]);
  });
  it('allows one winner for concurrent completion of the same challenge', async () => {
    const p = await prepare(), proof = credential(p);
    const results = await Promise.allSettled([repo().complete(p.request_id, proof), repo().complete(p.request_id, proof)]);
    expect(results.filter(result => result.status === 'fulfilled')).toHaveLength(1);
    expect(await counts()).toEqual([1, 1, 1]);
  });
  it('keeps the losing invitation usable when two users choose the same username', async () => {
    const a = await prepare(), b = await prepare();
    const results = await Promise.allSettled([repo().complete(a.request_id, credential(a)), repo().complete(b.request_id, credential(b))]);
    expect(results.filter(result => result.status === 'fulfilled')).toHaveLength(1);
    expect(results.find(result => result.status === 'rejected')).toMatchObject({ reason: { code: 'USERNAME_UNAVAILABLE' } });
    expect(await counts()).toEqual([1, 1, 1]);
  });
  it.each(['revoked', 'expired'] as const)('rechecks an invitation %s after preparation', async change => {
    const p = await prepare();
    if (change === 'revoked') await env.WALLET_DB.prepare('UPDATE signup_invites SET revoked_at = ?').bind(now()).run();
    else {
      vi.spyOn(Date, 'now').mockReturnValue((now() + 20) * 1000);
      await env.WALLET_DB.prepare('UPDATE signup_invites SET expires_at = ?').bind(now() - 1).run();
    }
    await expect(repo().complete(p.request_id, credential(p))).rejects.toThrow('CHALLENGE_UNAVAILABLE');
    expect(await counts()).toEqual([0, 0, 0]);
  });
  it('does not spend an invitation for a signature from a different key', async () => {
    const p = await prepare();
    await expect(repo().complete(p.request_id, credential(p, { proofKey: generateKey() }))).rejects.toThrow('INVALID_ENROLLMENT');
    expect(await counts()).toEqual([0, 0, 0]);
    await repo().complete(p.request_id, credential(p));
    expect(await counts()).toEqual([1, 1, 1]);
  });
  it.each(['options', 'complete'] as const)('checks invitation expiry on the database clock during %s', async stage => {
    const time = await env.WALLET_DB.prepare('SELECT unixepoch() AS time').first<number>('time');
    if (time === null) throw new Error('Missing database clock');
    vi.spyOn(Date, 'now').mockReturnValue((time - 120) * 1000);
    const { token } = await invite(), attempt = stage === 'complete' ? await prepare('daniel', token) : null;
    await env.WALLET_DB.prepare('UPDATE signup_invites SET expires_at = ?').bind(time - 1).run();
    if (attempt) await expect(repo().complete(attempt.request_id, credential(attempt))).rejects.toThrow('CHALLENGE_UNAVAILABLE');
    else await expect(prepare('daniel', token)).rejects.toThrow('INVITE_UNAVAILABLE');
    expect(await counts()).toEqual([0, 0, 0]);
  });
  it('rolls the entire registration back if consumption fails after inserting the user and credential', async () => {
    const p = await prepare(), proof = credential(p);
    await env.WALLET_DB.exec(`CREATE TRIGGER reject_invitation_consumption BEFORE UPDATE ON signup_invites BEGIN SELECT RAISE(ABORT,'synthetic failure'); END;`);
    await expect(repo().complete(p.request_id, proof)).rejects.toThrow();
    expect(await counts()).toEqual([0, 0, 0]);
    expect(await env.WALLET_DB.prepare('SELECT consumed_at FROM auth_challenges').first()).toEqual({ consumed_at: null });
    await env.WALLET_DB.exec('DROP TRIGGER reject_invitation_consumption');
    await repo().complete(p.request_id, proof); expect(await counts()).toEqual([1, 1, 1]);
  });
  it('reclaims only an expired unpublished username without creating another user for the previous owner', async () => {
    const a = await prepare(), first = await repo().complete(a.request_id, credential(a));
    await env.WALLET_DB.prepare('UPDATE users SET username_reserved_until = ? WHERE id = ?').bind(now() - 1, first.userId).run();
    const b = await prepare(); await repo().complete(b.request_id, credential(b));
    expect(await counts()).toEqual([2, 2, 2]);
    expect(await env.WALLET_DB.prepare('SELECT username FROM users WHERE id = ?').bind(first.userId).first()).toEqual({ username: null });
  });
  it('never recycles a published username when time passes', async () => {
    const a = await prepare(), first = await repo().complete(a.request_id, credential(a)), wallet = createResourceId('wallet');
    await env.WALLET_DB.prepare(`INSERT INTO wallets(id,user_id,status,account_id,initial_security_commitment,user_salt_commitment,canonical_address,created_at)
      VALUES (?,?,'active',?,?,?,?,?)`).bind(wallet, first.userId, `0x${'01'.repeat(32)}`, `0x${'02'.repeat(32)}`,
      `0x${'03'.repeat(32)}`, `0x${'04'.repeat(20)}`, now()).run();
    await env.WALLET_DB.prepare(`UPDATE users SET username_reserved_until = NULL, username_published_at = ?, receiving_wallet_id = ? WHERE id = ?`)
      .bind(now(), wallet, first.userId).run();
    vi.spyOn(Date, 'now').mockReturnValue((now() + 86400 * 365) * 1000);
    const b = await prepare();
    await expect(repo().complete(b.request_id, credential(b))).rejects.toThrow('USERNAME_UNAVAILABLE');
    expect(await counts()).toEqual([1, 1, 1]);
  });
  it('rejects an expired challenge without spending the invitation', async () => {
    const p = await prepare(), proof = credential(p);
    vi.spyOn(Date, 'now').mockReturnValue(p.expires_at * 1000);
    await expect(repo().complete(p.request_id, proof)).rejects.toThrow('CHALLENGE_UNAVAILABLE');
    expect(await counts()).toEqual([0, 0, 0]);
  });
  it('bounds expiry cleanup while preserving users, credentials and consumed invitation history', async () => {
    const p = await prepare(), first = await repo().complete(p.request_id, credential(p));
    const { token } = await invite();
    for (let i = 0; i < 258; i++) await prepare('second', token);
    const future = now() + 90001;
    await pruneAuthChallenges(env.WALLET_DB, future);
    expect(await env.WALLET_DB.prepare('SELECT count(*) AS n FROM auth_challenges').first('n')).toBe(3);
    expect(await env.WALLET_DB.prepare('SELECT token_hash FROM signup_invites WHERE token_hash = ?').bind(invitationHash(token)).first()).not.toBeNull();
    expect(await counts()).toEqual([1, 1, 1]);
    expect(await env.WALLET_DB.prepare('SELECT username FROM users WHERE id = ?').bind(first.userId).first('username')).toBeNull();
    await pruneAuthChallenges(env.WALLET_DB, future);
    expect(await env.WALLET_DB.prepare('SELECT count(*) AS n FROM auth_challenges').first('n')).toBe(0);
    expect(await env.WALLET_DB.prepare('SELECT token_hash FROM signup_invites WHERE token_hash = ?').bind(invitationHash(token)).first()).toBeNull();
    expect(await counts()).toEqual([1, 1, 1]);
  });
  it('purges old enrollment challenges without resetting the daily limit or removing credentials', async () => {
    const p = await prepare(), user = await repo().complete(p.request_id, credential(p)), time = now();
    const old = createResourceId('operation'), recent = createResourceId('operation');
    for (const [id, created] of [[old, time - 86401], [recent, time - 300]] as const) {
      const hash = `0x${id === old ? '01'.repeat(32) : '02'.repeat(32)}`;
      await env.WALLET_DB.prepare(`INSERT INTO webauthn_enrollments(id,user_id,rp_id,origin,challenge,proof_challenge,created_at,expires_at)
        VALUES (?,?,?,?,?,?,?,?)`).bind(id, user.userId, scope.rpId, scope.origin, hash, hash, created, created + 300).run();
    }
    await pruneAuthChallenges(env.WALLET_DB, time);
    expect((await env.WALLET_DB.prepare('SELECT id FROM webauthn_enrollments').all()).results).toEqual([{ id: recent }]);
    expect(await counts()).toEqual([1, 1, 1]);
  });
  it('rejects invalid and system usernames before creating any challenges', async () => {
    for (const username of ['admin', 'support', 'gatopago', 'abc', 'dáñiel', 'daniel/', '_daniel']) {
      await expect(prepare(username)).rejects.toThrow();
    }
    expect(await env.WALLET_DB.prepare('SELECT count(*) AS n FROM auth_challenges').first('n')).toBe(0);
    expect(registrationProfile(' Daniel ', 'DANIEL')).toEqual({ displayName: 'Daniel', username: 'daniel' });
  });
});
