import { env } from 'cloudflare:workers';
import { applyD1Migrations } from 'cloudflare:test';
import { afterEach, beforeAll, beforeEach, describe, expect, it, vi } from 'vitest';
import { createResourceId } from '@gatopago/shared/v3/primitives';
import { WalletRepository } from '../src/accounts/repository';
import { ProfileRepository, resolveRecipient, type ReceivingProfiles } from '../src/accounts/profile';
import { backupScenario } from './backup.fixture';
import { cleanCreationDelivery } from './creationDelivery.fixture';
import { testPrincipal } from './principal.fixture';
import { seedUser } from './user.fixture';

const signal = () => new AbortController().signal;
async function clean() {
  await env.WALLET_DB.exec(`UPDATE users SET username = NULL, username_reserved_until = NULL, username_published_at = NULL, receiving_wallet_id = NULL;
    DELETE FROM account_backup_transactions; DELETE FROM account_backup_outbox; DELETE FROM account_backup_commits; DELETE FROM account_backups;`);
  await cleanCreationDelivery();
}
beforeAll(() => applyD1Migrations(env.WALLET_DB, env.V3_TEST_MIGRATIONS));
beforeEach(async () => { await clean(); vi.spyOn(Date, 'now').mockReturnValue(Date.now()); });
afterEach(async () => { vi.restoreAllMocks(); vi.unstubAllGlobals(); await clean(); });
async function setup() {
  const f = await backupScenario();
  const owned = await new WalletRepository(env.WALLET_DB, f.principal).ownedAccount(f.walletId, f.walletAccountId);
  const profiles = async () => (await f.profiles(owned, signal())).map(profile => ({ ...profile, verifier: f.prepared.profile.webauthn_verifier }));
  const repo = new ProfileRepository(env.WALLET_DB, f.principal, f.configuration.scope, profiles);
  await repo.rename('Daniel');
  const input = { username: 'daniel', wallet_id: f.walletId, wallet_account_id: f.walletAccountId };
  return { ...f, profiles, repo, input, resolve: () => resolveRecipient(env.WALLET_DB, f.configuration.scope, 'daniel', f.prepared.profile.deployment.network_id, profiles, signal()) };
}

describe('Username publication and resolution on real D1 and two synthetic RPCs', () => {
  it('keeps expired reservations private and lets the owner edit their display name without RPC', async () => {
    const identity = testPrincipal('profile'); await seedUser(env.WALLET_DB, identity);
    const profiles = vi.fn(), repo = new ProfileRepository(env.WALLET_DB, identity, { rpId: 'test.invalid', origin: 'https://test.invalid' }, profiles);
    const now = Math.floor(Date.now() / 1000);
    await env.WALLET_DB.prepare('UPDATE users SET username = ?,username_reserved_until = ? WHERE id = ?').bind('daniel', now + 60, identity.userId).run();
    expect(await repo.read()).toMatchObject({ username: 'daniel', receiving_wallet_id: null, username_published_at: null });
    expect(await repo.rename('  Jose\u0301  ')).toMatchObject({ display_name: 'José' });
    vi.spyOn(Date, 'now').mockReturnValue((now + 60) * 1000);
    expect(await repo.read()).toMatchObject({ username: null, username_reserved_until: null });
    await expect(repo.rename('x\nAdmin')).rejects.toThrow(); expect(profiles).not.toHaveBeenCalled();
  });
  it('publishes only after live inspection and resolves the pinned account for the requested network', async () => {
    const f = await setup();
    await expect(f.resolve()).rejects.toMatchObject({ code: 'NOT_FOUND' });
    const profile = await f.repo.publish(f.input, signal());
    expect(profile).toMatchObject({ username: 'daniel', receiving_wallet_id: f.walletId, username_reserved_until: null });
    expect(profile.username_published_at).toBeGreaterThan(0);
    expect(await f.resolve()).toEqual({ username: 'daniel', display_name: 'Daniel', network_id: f.prepared.profile.deployment.network_id,
      address: f.prepared.account.toLowerCase(), verified_at: Math.floor(Date.now() / 1000), expires_at: expect.any(Number) });
    expect(f.fetch.mock.calls.some(([url]) => String(url) === 'https://observer-a.invalid/')).toBe(true);
    expect(f.fetch.mock.calls.some(([url]) => String(url) === 'https://observer-b.invalid/')).toBe(true);
    await expect(resolveRecipient(env.WALLET_DB, f.configuration.scope, 'daniel', 'eip155:1', f.profiles, signal())).rejects.toMatchObject({ code: 'NOT_FOUND' });
  });
  it('does not turn an unfinished creation into a receiving address', async () => {
    const f = await setup(); f.state.creationUntil = BigInt(Math.floor(Date.now() / 1000) + 100);
    await expect(f.repo.publish(f.input, signal())).rejects.toMatchObject({ code: 'RECEIVING_UNAVAILABLE' });
    expect((await f.repo.read()).username_published_at).toBeNull();
  });
  it('does not accept a verified wallet owned by another user', async () => {
    const f = await setup(), other = testPrincipal('other'); await seedUser(env.WALLET_DB, other);
    const repo = new ProfileRepository(env.WALLET_DB, other, f.configuration.scope, f.profiles); f.fetch.mockClear();
    await expect(repo.publish(f.input, signal())).rejects.toMatchObject({ code: 'NOT_FOUND' }); expect(f.fetch).not.toHaveBeenCalled();
  });
  it('requires a registered unrevoked spending factor, including for later public lookups', async () => {
    const f = await setup(); await f.repo.publish(f.input, signal());
    await env.WALLET_DB.prepare('UPDATE webauthn_credentials SET revoked_at = ? WHERE id = ?').bind(Math.floor(Date.now() / 1000), f.credentialRef).run();
    await expect(f.resolve()).rejects.toMatchObject({ code: 'RECEIVING_UNAVAILABLE' });
  });
  it('does not trust the same key under an unapproved verifier', async () => {
    const f = await setup();
    const profiles: ReceivingProfiles = async () => (await f.profiles()).map(profile => ({ ...profile,
      verifier: { ...profile.verifier, runtime_code_hash: `0x${'11'.repeat(32)}` } }));
    const repo = new ProfileRepository(env.WALLET_DB, f.principal, f.configuration.scope, profiles);
    await expect(repo.publish(f.input, signal())).rejects.toMatchObject({ code: 'RECEIVING_UNAVAILABLE' });
  });
  it('discards a publication when access is revoked during provider work', async () => {
    const f = await setup();
    const profiles: ReceivingProfiles = async () => {
      await env.WALLET_DB.prepare('UPDATE users SET disabled_at = ? WHERE id = ?').bind(Math.floor(Date.now() / 1000), f.principal.userId).run();
      return f.profiles();
    };
    const repo = new ProfileRepository(env.WALLET_DB, f.principal, f.configuration.scope, profiles);
    await expect(repo.publish(f.input, signal())).rejects.toMatchObject({ code: 'UNAUTHENTICATED' });
    expect(await env.WALLET_DB.prepare('SELECT username_published_at FROM users WHERE id = ?').bind(f.principal.userId).first('username_published_at')).toBeNull();
  });
  it('retains the published handle and wallet, while allowing display-name edits and idempotent publication', async () => {
    const f = await setup(), first = await f.repo.publish(f.input, signal());
    await expect(f.repo.publish({ ...f.input, username: 'another' }, signal())).rejects.toMatchObject({ code: 'PROFILE_IMMUTABLE' });
    await expect(f.repo.publish({ ...f.input, wallet_id: createResourceId('wallet') }, signal())).rejects.toMatchObject({ code: 'PROFILE_IMMUTABLE' });
    expect(await f.repo.publish(f.input, signal())).toEqual(first);
    await f.repo.rename('Daniel Updated'); expect(await f.resolve()).toHaveProperty('display_name', 'Daniel Updated');
  });
  it('does not take another user’s live reservation and releases only expired private reservations', async () => {
    const f = await setup(), other = testPrincipal('reserved'); await seedUser(env.WALLET_DB, other);
    const now = Math.floor(Date.now() / 1000);
    await env.WALLET_DB.prepare('UPDATE users SET username = ?,username_reserved_until = ? WHERE id = ?').bind('daniel', now + 60, other.userId).run();
    await expect(f.repo.publish(f.input, signal())).rejects.toMatchObject({ code: 'USERNAME_UNAVAILABLE' });
    await env.WALLET_DB.prepare('UPDATE users SET username_reserved_until = ? WHERE id = ?').bind(now, other.userId).run();
    expect(await f.repo.publish(f.input, signal())).toHaveProperty('username', 'daniel');
    expect(await env.WALLET_DB.prepare('SELECT username FROM users WHERE id = ?').bind(other.userId).first('username')).toBeNull();
  });
  it('serializes two different public usernames for the same user', async () => {
    const f = await setup();
    const results = await Promise.allSettled([f.repo.publish(f.input, signal()), f.repo.publish({ ...f.input, username: 'daniel_two' }, signal())]);
    expect(results.filter(result => result.status === 'fulfilled')).toHaveLength(1);
    expect(results.filter(result => result.status === 'rejected')).toHaveLength(1);
    expect(['daniel', 'daniel_two']).toContain((await f.repo.read()).username);
  });
  it('stops resolving disabled users or archived wallets without recycling their username', async () => {
    const f = await setup(); await f.repo.publish(f.input, signal());
    await env.WALLET_DB.prepare("UPDATE wallets SET status = 'archived' WHERE id = ?").bind(f.walletId).run();
    await expect(f.resolve()).rejects.toMatchObject({ code: 'NOT_FOUND' });
    expect(await env.WALLET_DB.prepare('SELECT username FROM users WHERE id = ?').bind(f.principal.userId).first('username')).toBe('daniel');
  });
});
