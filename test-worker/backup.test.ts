import { seedUser } from './user.fixture';
import { env } from 'cloudflare:workers';
import { applyD1Migrations } from 'cloudflare:test';
import { afterEach, beforeAll, beforeEach, describe, expect, it, vi } from 'vitest';
import { prepareBackupEnrollment } from '@gatopago/shared/v3/backup-enrollment';
import { createResourceId } from '@gatopago/shared/v3/primitives';
import { BackupRepository } from '../src/security/backup';
import { backupProofs, readBackupSnapshot } from '../src/security/backupRecord';
import { fixtureHash } from '@gatopago/test-fixtures/v3-inspection';
import { cleanCreationDelivery, deliveryIdentity, deliveryNow } from './creationDelivery.fixture';
import { backupScenario as scenario } from './backup.fixture';

beforeAll(async () => { await applyD1Migrations(env.WALLET_DB, env.V3_TEST_MIGRATIONS); });
async function clean() {
 await env.WALLET_DB.exec('DROP TRIGGER IF EXISTS backup_fail_authorize; DELETE FROM account_backup_transactions; DELETE FROM account_backup_outbox; DELETE FROM account_backups;');
 await cleanCreationDelivery();
}
beforeEach(clean);
afterEach(async () => { vi.restoreAllMocks(); await clean(); });
const signal = () => new AbortController().signal;
const stored = (id: string) => env.WALLET_DB.prepare('SELECT * FROM account_backups WHERE id = ?').bind(id).first();
const count = () => env.WALLET_DB.prepare('SELECT count(*) AS n FROM account_backups').first<number>('n');

describe('durable owned optional backup consent', () => {
 it('reconstructs owned consent across requests without polling, renewal, signatures or readiness on GET', async () => {
  const f = await scenario(), request = f.request(), p = await f.repository().prepare(request, signal());
  expect(p).toMatchObject({ state: 'prepared', backup_assessment: 'not_assessed', receive_enabled: false, spend_enabled: false });
  expect(p.input.observation.security.phase).toBe('active_policy');
  const before = await stored(request.id); f.fetch.mockClear();
  expect(await f.repository().read(request.id)).toEqual(p);
  expect(await f.repository().prepare(request, signal())).toEqual(p);
  expect(await stored(request.id)).toEqual(before); expect(f.fetch).not.toHaveBeenCalled(); expect(await count()).toBe(1);
  expect(p).not.toHaveProperty('authorization_json');
 });
 it('denies network preparation by default; profiles never come from a browser observation', async () => {
  const f = await scenario();
  const repository = new BackupRepository(env.WALLET_DB, f.principal, f.configuration.scope, f.configuration.profiles);
  await expect(repository.prepare(f.request(), signal())).rejects.toMatchObject({ code: 'BACKUP_PROFILE_UNAVAILABLE' });
  expect(await count()).toBe(0); expect(f.fetch).not.toHaveBeenCalled();
 });
 it('competing retries converge on one immutable proposal without a wallet-wide reservation', async () => {
  const f = await scenario(), request = f.request();
  const results = await Promise.all(Array.from({ length: 4 }, () => f.repository().prepare(request, signal())));
  expect(results.every((p) => p.proposal_hash === results[0].proposal_hash)).toBe(true); expect(await count()).toBe(1);
  const other = f.request(); other.nextPolicy.upgradeDelaySeconds += 1;
  expect((await f.repository().prepare(other, signal())).state).toBe('prepared'); expect(await count()).toBe(2);
 });
 it('does not repurpose an idempotency key for different terms', async () => {
  const f = await scenario(), r = f.request(); await f.repository().prepare(r, signal());
  r.nextPolicy.upgradeDelaySeconds += 1;
  await expect(f.repository().prepare(r, signal())).rejects.toMatchObject({ code: 'BACKUP_CONFLICT' }); expect(await count()).toBe(1);
 });
 it('accepts all actual possession proofs and durable work atomically, without activating the account', async () => {
  const f = await scenario(), r = f.request(), p = await f.repository().prepare(r, signal());
  const proof = f.f.assertion(p.proposal_hash), enrollments = await f.proofs(p.input);
  const result = await f.repository().authorize(r.id, proof, enrollments, signal());
  expect(result).toMatchObject({ state: 'authorized', backup_assessment: 'not_assessed', receive_enabled: false, spend_enabled: false });
  expect((await stored(r.id))?.calldata_sha256).toMatch(/^0x[0-9a-f]{64}$/);
  expect(await env.WALLET_DB.prepare('SELECT state,authorized_auth_time FROM account_backup_outbox WHERE operation_id = ?').bind(r.id).first())
   .toEqual({ state: 'pending', authorized_auth_time: f.principal.authTime });
  const before = await stored(r.id); f.fetch.mockClear();
  expect(await f.repository().authorize(r.id, proof, [...enrollments].reverse(), signal())).toEqual(result);
  expect(await stored(r.id)).toEqual(before); expect(f.fetch).not.toHaveBeenCalled();
  expect(prepareBackupEnrollment(p.input, p.valid_after).continuity.factor_independence).toBe('not_assessed');
  expect(await env.WALLET_DB.prepare('SELECT count(*) AS n FROM account_creation_jobs').first('n')).toBe(1);
 });
 it('concurrent authorization retries retain exactly the first complete proof set', async () => {
  const f = await scenario(), r = f.request(), p = await f.repository().prepare(r, signal()), proof = f.f.assertion(p.proposal_hash), enrollments = await f.proofs(p.input);
  const results = await Promise.all(Array.from({ length: 3 }, () => f.repository().authorize(r.id, proof, enrollments, signal())));
  expect(results.every((r) => r.state === 'authorized')).toBe(true);
  await expect(f.repository().authorize(r.id, f.f.assertion(p.proposal_hash, { count: 3 }), enrollments, signal())).rejects.toMatchObject({ code: 'BACKUP_CONFLICT' });
 });
 it('denies other users and mismatched wallet/initialization before RPC', async () => {
  const f = await scenario(), r = f.request(), p = await f.repository().prepare(r, signal()); f.fetch.mockClear();
  const other = deliveryIdentity('backup-other'); await seedUser(env.WALLET_DB, other);
  await expect(f.repository(other).read(r.id)).rejects.toMatchObject({ code: 'NOT_FOUND' });
  await expect(f.repository(other).prepare(f.request(), signal())).rejects.toMatchObject({ code: 'NOT_FOUND' });
  await expect(f.repository(other).authorize(r.id, f.f.assertion(p.proposal_hash), await f.proofs(p.input), signal())).rejects.toMatchObject({ code: 'NOT_FOUND' });
  await expect(f.repository().prepare({ ...f.request(), initializationId: createResourceId('operation') }, signal())).rejects.toMatchObject({ code: 'NOT_FOUND' });
  expect(f.fetch).not.toHaveBeenCalled();
 });
 it.each(['disabled', 'cutoff', 'expired'] as const)('rejects a %s login without changing consent', async (reason) => {
  const f = await scenario(), r = f.request(), p = await f.repository().prepare(r, signal());
  let principal = f.principal;
  if (reason === 'disabled') await env.WALLET_DB.prepare('UPDATE users SET disabled_at = ? WHERE id = ?').bind(deliveryNow(), f.session.user_id).run();
  if (reason === 'cutoff') await env.WALLET_DB.prepare('UPDATE users SET auth_not_before = ? WHERE id = ?').bind(principal.authTime + 1, f.session.user_id).run();
  if (reason === 'expired') principal = { ...principal, expiresAt: deliveryNow() };
  f.fetch.mockClear();
  await expect(f.repository(principal).authorize(r.id, f.f.assertion(p.proposal_hash), await f.proofs(p.input), signal())).rejects.toMatchObject({ code: 'UNAUTHENTICATED' });
  expect((await stored(r.id))?.authorized_at).toBeNull(); expect(f.fetch).not.toHaveBeenCalled();
 });
 it('rechecks a wallet archived during RPC and leaves no preparation behind', async () => {
  const f = await scenario(), reply = f.reply.getMockImplementation()!;
  f.reply.mockImplementationOnce(async (...args) => {
   await env.WALLET_DB.prepare("UPDATE wallets SET status = 'archived' WHERE id = ?").bind(f.walletId).run();
   return reply(...args);
  });
  await expect(f.repository().prepare(f.request(), signal())).rejects.toMatchObject({ code: 'WALLET_DATA_INVALID' }); expect(await count()).toBe(0);
 });
 it('refuses a changed current nonce instead of silently re-signing against a new proposal', async () => {
  const f = await scenario(), r = f.request(), p = await f.repository().prepare(r, signal()); f.state.adminNonce = 1n;
  await expect(f.repository().authorize(r.id, f.f.assertion(p.proposal_hash), await f.proofs(p.input), signal())).rejects.toMatchObject({ code: 'BACKUP_STATE_CHANGED' });
  expect((await stored(r.id))?.authorized_at).toBeNull();
 });
 it('never falls back to stored preparation after RPC failure', async () => {
  const f = await scenario(), r = f.request(), p = await f.repository().prepare(r, signal());
  f.fetch.mockRejectedValue(new Error('synthetic outage'));
  await expect(f.repository().authorize(r.id, f.f.assertion(p.proposal_hash), await f.proofs(p.input), signal())).rejects.toThrow();
  expect((await stored(r.id))?.authorized_at).toBeNull();
 });
 it('rejects missing, duplicate and unrelated proofs without persisting partial authorization', async () => {
  const f = await scenario(), r = f.request(), p = await f.repository().prepare(r, signal()), proofs = await f.proofs(p.input);
  f.fetch.mockClear();
  for (const enrollments of [[], [proofs[0], proofs[0]]]) await expect(f.repository().authorize(r.id, f.f.assertion(p.proposal_hash), enrollments, signal())).rejects.toThrow();
  await expect(f.repository().authorize(r.id, f.f.assertion(fixtureHash('a')), proofs, signal())).rejects.toThrow();
  expect((await stored(r.id))?.authorization_json).toBeNull(); expect(f.fetch).not.toHaveBeenCalled();
 });
 it('rejects the retired recovery role instead of granting it to the initial key', async () => {
  const f = await scenario(), r = f.request();
  r.nextPolicy.signers.find((s) => s.kind === 1)!.roles = 7;
  f.fetch.mockClear();
  await expect(f.repository().prepare(r, signal())).rejects.toThrow();
  expect(f.fetch).not.toHaveBeenCalled(); expect(await count()).toBe(0);
 });
 it('does not renew expired consent, but can read an expired exact authorization as history', async () => {
  const f = await scenario(), first = f.request(), second = f.request();
  const p = await f.repository().prepare(first, signal()); await f.repository().prepare(second, signal());
  const proof = f.f.assertion(p.proposal_hash), proofs = await f.proofs(p.input);
  await f.repository().authorize(first.id, proof, proofs, signal());
  vi.spyOn(Date, 'now').mockReturnValue((p.valid_until + 1) * 1000); f.fetch.mockClear();
  expect((await f.repository().read(second.id)).state).toBe('expired');
  await expect(f.repository().prepare(second, signal())).rejects.toMatchObject({ code: 'BACKUP_EXPIRED' });
  expect((await f.repository().authorize(first.id, proof, proofs, signal())).state).toBe('authorized');
  expect(f.fetch).not.toHaveBeenCalled();
 });
 it('fails atomically on a durable write error and allows an explicit retry', async () => {
  const f = await scenario(), r = f.request(), p = await f.repository().prepare(r, signal()), proof = f.f.assertion(p.proposal_hash), proofs = await f.proofs(p.input);
  await env.WALLET_DB.exec("CREATE TRIGGER backup_fail_authorize BEFORE UPDATE ON account_backups BEGIN SELECT RAISE(ABORT, 'Synthetic failure'); END;");
  await expect(f.repository().authorize(r.id, proof, proofs, signal())).rejects.toThrow(); expect((await stored(r.id))?.authorized_at).toBeNull();
  await env.WALLET_DB.exec('DROP TRIGGER backup_fail_authorize');
  expect((await f.repository().authorize(r.id, proof, proofs, signal())).state).toBe('authorized');
 });
 it('bounds per-owner preparations without introducing a global nonce lock', async () => {
  const f = await scenario();
  for (let i = 0; i < 6; i++) await f.repository().prepare(f.request(), signal());
  await expect(f.repository().prepare(f.request(), signal())).rejects.toMatchObject({ code: 'BACKUP_LIMIT' }); expect(await count()).toBe(6);
 });
 it('schema rejects rewriting proposal terms or partial authorization', async () => {
  const f = await scenario(), r = f.request(); await f.repository().prepare(r, signal());
  await expect(env.WALLET_DB.prepare('UPDATE account_backups SET proposal_hash = ? WHERE id = ?').bind(fixtureHash('a'), r.id).run()).rejects.toThrow();
  await expect(env.WALLET_DB.prepare('UPDATE account_backups SET proposal_expires_at = proposal_expires_at + 1 WHERE id = ?').bind(r.id).run()).rejects.toThrow();
  await expect(env.WALLET_DB.prepare("UPDATE account_backups SET authorization_json = '{}' WHERE id = ?").bind(r.id).run()).rejects.toThrow();
 });
 it('reverifies stored signatures instead of trusting an authorized database flag', async () => {
  const f = await scenario(), r = f.request(), p = await f.repository().prepare(r, signal());
  const unrelated = backupProofs(f.f.assertion(fixtureHash('e')), await f.proofs(p.input));
  await env.WALLET_DB.prepare(`UPDATE account_backups SET authorized_at = created_at, authorization_json = ?,
   authorization_snapshot_json = snapshot_json, calldata_sha256 = ?, authorized_auth_time = ? WHERE id = ?`).bind(unrelated, fixtureHash('a'), f.principal.authTime, r.id).run();
  f.fetch.mockClear();
  await expect(f.repository().read(r.id)).rejects.toMatchObject({ code: 'WALLET_DATA_INVALID' }); expect(f.fetch).not.toHaveBeenCalled();
 });
 it('records the fresh authorization checkpoint independently from the original preparation', async () => {
  const f = await scenario(), r = f.request(), p = await f.repository().prepare(r, signal());
  const before = await stored(r.id);
  await f.repository().authorize(r.id, f.f.assertion(p.proposal_hash), await f.proofs(p.input), signal());
  const after = await stored(r.id);
  expect(after?.snapshot_json).toBe(before?.snapshot_json);
  const confirmation = JSON.parse(String(after?.authorization_snapshot_json)) as { observed_at: number; expires_at: number };
  expect(after?.authorized_at).toBeGreaterThanOrEqual(confirmation.observed_at);
  expect(after?.authorized_at).toBeLessThan(confirmation.expires_at);
  expect((await f.repository().read(r.id)).state).toBe('authorized');
 });
 it('preserves the inspected target when the closing finalized head advances', async () => {
  const f = await scenario(), r = f.request(), p = await f.repository().prepare(r, signal());
  const saved = await stored(r.id);
  const snapshot = JSON.parse(String(saved?.snapshot_json)) as { finality_evidence: {
   checkpoint: { block_number: string; block_hash: string; block_timestamp: string }; target: { block_hash: string } } };
  snapshot.finality_evidence.checkpoint = { ...snapshot.finality_evidence.checkpoint,
   block_number: (BigInt(p.input.observation.checkpoint.block_number) + 1n).toString(), block_hash: fixtureHash('e') };
  expect(readBackupSnapshot(JSON.stringify(snapshot), p.input.initialization).observation.checkpoint).toEqual(p.input.observation.checkpoint);
  snapshot.finality_evidence.target.block_hash = fixtureHash('f');
  expect(() => readBackupSnapshot(JSON.stringify(snapshot), p.input.initialization)).toThrow('Invalid backup finality');
 });
 it('does not retain caller-owned policy or proof buffers across awaits', async () => {
  const f = await scenario(), r = f.request();
  const approvedDeadline = r.proposalValidUntil;
  const pending = f.repository().prepare(r, signal()); r.nextPolicy.adminThreshold = 16;
  r.proposalValidUntil += 1;
  const p = await pending; expect(p.input.nextPolicy.adminThreshold).toBe(1); expect(p.proposal_valid_until).toBe(approvedDeadline);
  const owner = f.f.assertion(p.proposal_hash), enrollments = await f.proofs(p.input);
  const authorization = f.repository().authorize(r.id, owner, enrollments, signal());
  owner.signatureDER.fill(0); enrollments.splice(0);
  expect((await authorization).state).toBe('authorized');
 });
 it('rejects stale finalized evidence during authorization without using the stored snapshot', async () => {
  const f = await scenario(), r = f.request(), p = await f.repository().prepare(r, signal());
  const source = await f.journal.latest(f.id);
  if (source?.result.status !== 'observed' || source.result.finality === 'not_assessed') throw new Error('Expected finality');
  const proofs = await f.proofs(p.input);
  vi.spyOn(Date, 'now').mockReturnValue(source.result.finality_evidence.expires_at * 1000); f.fetch.mockClear();
  await expect(f.repository().authorize(r.id, f.f.assertion(p.proposal_hash), proofs, signal())).rejects.toThrow('SECURITY_FINALITY_UNUSABLE');
  expect((await stored(r.id))?.authorized_at).toBeNull(); expect(f.fetch).not.toHaveBeenCalled();
 });
 it('aborts during inspection without leaving a new preparation', async () => {
  const f = await scenario(), abort = new AbortController(), reply = f.reply.getMockImplementation()!;
  f.reply.mockImplementationOnce(async (...args) => { const result = await reply(...args); abort.abort(); return result; });
  await expect(f.repository().prepare(f.request(), abort.signal)).rejects.toThrow(); expect(await count()).toBe(0);
 });
 it('rejects a reused id with a different proposal deadline without another RPC call', async () => {
  const f = await scenario(), r = f.request(), p = await f.repository().prepare(r, signal()); f.fetch.mockClear();
  await expect(f.repository().prepare({ ...r, proposalValidUntil: r.proposalValidUntil + 1 }, signal())).rejects.toMatchObject({ code: 'BACKUP_CONFLICT' });
  expect((await f.repository().read(r.id)).proposal_valid_until).toBe(p.proposal_valid_until); expect(f.fetch).not.toHaveBeenCalled();
 });
 it('rejects invalid proposal deadlines without persisting a consent', async () => {
  const f = await scenario();
  for (const offset of [0, 300, 604801]) {
   const r = { ...f.request(), proposalValidUntil: deliveryNow() + offset };
   await expect(f.repository().prepare(r, signal())).rejects.toThrow('BACKUP_PROPOSAL_WINDOW_INVALID');
  }
  expect(await count()).toBe(0);
 });
});
