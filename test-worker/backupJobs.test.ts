import { env } from 'cloudflare:workers';
import { applyD1Migrations, createMessageBatch, createExecutionContext, getQueueResult } from 'cloudflare:test';
import { afterEach, beforeAll, beforeEach, describe, expect, it, vi } from 'vitest';
import { createResourceId } from '@gatopago/shared/v3/primitives';
import { BackupJobRepository, parseBackupWake, type BackupWake } from '../src/security/backupJobs';
import { createBackupJobHandlers } from '../src/security/backupJobHandlers';
import { createBackupProcessor } from '../src/security/processBackupJob';
import { dispatchWalletJobs } from '../src/execution/walletJobHandlers';
import { backupObservationScenario, cleanBackupObservations } from './backupObservation.fixture';
import { backupCommitScenario } from './backupCommit.fixture';
import { deliveryNow } from './creationDelivery.fixture';

beforeAll(async () => { await applyD1Migrations(env.WALLET_DB, env.V3_TEST_MIGRATIONS); });
beforeEach(cleanBackupObservations);
afterEach(async () => { vi.restoreAllMocks(); await env.WALLET_DB.exec('DROP TRIGGER IF EXISTS backup_job_failure'); await cleanBackupObservations(); });
const signal = () => new AbortController().signal;
const job = (id: string) => env.WALLET_DB.prepare('SELECT * FROM account_backup_jobs WHERE operation_id = ?').bind(id).first();
async function setup(kind: 'prepare' | 'commit' = 'prepare') {
 const f = await backupObservationScenario(kind), processor = createBackupProcessor(f.configuration);
 const jobs = new BackupJobRepository(env.WALLET_DB, processor.configuration), sent: BackupWake[] = [];
 const send = vi.fn(async (body: BackupWake): Promise<QueueSendResponse> => {
  sent.push(body); return { metadata: { metrics: { backlogCount: sent.length, backlogBytes: 0 } } };
 });
 const bindings = { WALLET_DB: env.WALLET_DB, CREATION_QUEUE_NAME: env.CREATION_QUEUE_NAME, CREATION_JOBS: { send } };
 const handlers = createBackupJobHandlers(() => f.configuration);
 async function consume(bodies: readonly unknown[] = sent) {
  const batch = createMessageBatch(bindings.CREATION_QUEUE_NAME, bodies.map((body, i) => ({ id: `backup-${i}`, timestamp: new Date(), attempts: 1, body })));
  await handlers.queue(batch, bindings); return getQueueResult(batch, createExecutionContext());
 }
 return { ...f, processor, jobs, sent, send, bindings, handlers, consume };
}
describe('backup durable runner', { timeout: 25_000 }, () => {
 it.each(['prepare', 'commit'] as const)('observes %s via queue without a signer and without enabling spending', async (kind) => {
  const f = await setup(kind), message = await f.jobs.reserve(f.id); expect(message).not.toBeNull();
  await f.consume([message]);
  expect(await job(f.id)).toMatchObject({ state: kind === 'prepare' ? 'observed' : 'ready', reason: kind === 'prepare' ? 'proposal_finalized' : null, lease_token: null });
  expect((await f.repository().read(f.grant.backupId)).spend_enabled).toBe(false);
  expect(f.reply.mock.calls.some(([method]) => method === 'eth_sendRawTransaction')).toBe(false);
  f.fetch.mockClear(); await f.consume([message]); expect(f.fetch).not.toHaveBeenCalled();
 });
 it('authorization rolls back when durable job insertion fails', async () => {
  await env.WALLET_DB.exec(`CREATE TRIGGER backup_job_failure BEFORE INSERT ON account_backup_jobs BEGIN SELECT RAISE(ABORT,'synthetic job failure'); END;`);
  await expect(backupCommitScenario()).rejects.toThrow();
  expect(await env.WALLET_DB.prepare('SELECT count(*) AS n FROM account_backups WHERE authorized_at IS NOT NULL').first('n')).toBe(0);
  expect(await env.WALLET_DB.prepare('SELECT count(*) AS n FROM account_backup_outbox').first('n')).toBe(0);
 });
 it('concurrent schedulers and consumers converge on one observation', async () => {
  const f = await setup(); await Promise.all(Array.from({ length: 4 }, () => f.handlers.wake(f.bindings)));
  expect(f.sent).toHaveLength(1); expect(Object.keys(f.sent[0]).sort()).toEqual(['kind','operation_id','schema_version','token']);
  await Promise.all(Array.from({ length: 4 }, () => f.consume()));
  expect(await job(f.id)).toMatchObject({ state: 'observed' });
  expect(await env.WALLET_DB.prepare('SELECT count(*) AS n FROM account_backup_observations').first('n')).toBe(1);
 });
 it('lost enqueue acknowledgement invalidates the old token; cron can recover', async () => {
  const f = await setup(); f.send.mockImplementationOnce(async (body) => { f.sent.push(body); throw new Error('lost response'); });
  await f.handlers.wake(f.bindings); expect(await job(f.id)).toMatchObject({ state: 'ready', failures: 1 });
  f.fetch.mockClear(); await f.consume(); expect(f.fetch).not.toHaveBeenCalled();
  await env.WALLET_DB.prepare('UPDATE account_backup_jobs SET next_attempt_at = 0 WHERE operation_id = ?').bind(f.id).run();
  await f.handlers.wake(f.bindings); expect(f.sent).toHaveLength(2); expect(f.sent[0].token).not.toBe(f.sent[1].token);
  await f.consume(); expect(await job(f.id)).toMatchObject({ state: 'observed' });
 });
 it('SQLite expiry fences a stale consumer even when JavaScript time is behind', async () => {
  const f = await setup(), old = (await f.jobs.reserve(f.id))!; expect(await f.jobs.claim(old)).toBe(true);
  await env.WALLET_DB.prepare('UPDATE account_backup_jobs SET lease_expires_at = 1 WHERE operation_id = ?').bind(f.id).run();
  vi.spyOn(Date, 'now').mockReturnValue(0);
  expect(await f.jobs.finish(old, { state: 'observed', reason: 'proposal_finalized' })).toBe(false);
  const next = (await f.jobs.reserve(f.id))!; expect(next.token).not.toBe(old.token); expect(await f.jobs.claim(next)).toBe(true);
  expect(await f.jobs.fail(old, 'running')).toBe(false); expect((await job(f.id))!.lease_token).toBe(next.token);
 });
 it('scope applies to discovery, claim, finish and fail', async () => {
  const f = await setup(), m = (await f.jobs.reserve(f.id))!;
  const other = new BackupJobRepository(env.WALLET_DB, { ...f.processor.configuration, environment: 'production' as const });
  expect(await other.due()).toEqual([]); expect(await other.claim(m)).toBe(false); expect(await f.jobs.claim(m)).toBe(true);
  expect(await other.finish(m, { state: 'observed', reason: 'proposal_finalized' })).toBe(false);
  expect(await other.fail(m, 'running')).toBe(false);
 });
 it('missing receipts schedule a durable retry, never a second send', async () => {
  const f = await setup(); f.state.missing = true; await f.handlers.wake(f.bindings); await f.consume();
  expect(await job(f.id)).toMatchObject({ state: 'ready', reason: null, lease_token: null });
  expect(Number((await job(f.id))!.next_attempt_at)).toBeGreaterThan(deliveryNow());
  expect(f.reply.mock.calls.some(([m]) => m === 'eth_sendRawTransaction')).toBe(false);
 });
 it('a reverted finalized transaction needs review, not backup', async () => {
  const f = await setup(); f.state.receipt.status = '0x0'; f.state.receipt.logs = [];
  await f.handlers.wake(f.bindings); await f.consume();
  expect(await job(f.id)).toMatchObject({ state: 'review', reason: 'execution_reverted' });
 });
 it('identity revocation after sending does not hide the receipt', async () => {
  const f = await setup(); await env.WALLET_DB.prepare('UPDATE users SET disabled_at = ?').bind(deliveryNow()).run();
  expect(await f.processor.run(env.WALLET_DB, f.id, signal())).toMatchObject({ state: 'observed' });
 });
 it('pending delivery without an admitted sponsor defers without RPC', async () => {
  const f = await backupCommitScenario();
  const configuration = { ...f.configuration, networks: f.configuration.networks.map((n) => ({ ...n, providers: n.providers.map((p) => ({ ...p, operatorId: p.operatorId.replaceAll('_', '-') })) })) };
  const processor = createBackupProcessor(configuration); f.fetch.mockClear();
  expect(await processor.run(env.WALLET_DB, f.request.id, signal())).toMatchObject({ state: 'ready' });
  expect(f.fetch).not.toHaveBeenCalled();
  await env.WALLET_DB.prepare('UPDATE users SET disabled_at = ?').bind(deliveryNow()).run();
  expect(await processor.run(env.WALLET_DB, f.request.id, signal())).toEqual({ state: 'review', reason: 'revoked' });
 });
 it('an aborted invocation does no RPC work', async () => {
  const f = await setup(), controller = new AbortController(); controller.abort();
  await expect(f.processor.run(env.WALLET_DB, f.id, controller.signal)).rejects.toThrow(); expect(f.fetch).not.toHaveBeenCalled();
 });
 it('an old unobserved send stops polling into operational review', async () => {
  const f = await setup(); f.state.missing = true;
  vi.spyOn(Date, 'now').mockReturnValue((deliveryNow() + 86401) * 1000);
  expect(await f.processor.run(env.WALLET_DB, f.id, signal())).toEqual({ state: 'review', reason: 'observation_timeout' });
  expect(f.fetch).not.toHaveBeenCalled();
 });
 it('stale finalized evidence cannot end the job as observed', async () => {
  const f = await setup(); await f.run(); f.state.missing = true;
  vi.spyOn(Date, 'now').mockReturnValue((deliveryNow() + 31) * 1000);
  expect(await f.processor.run(env.WALLET_DB, f.id, signal())).toMatchObject({ state: 'ready' });
 });
 it('retry exhaustion becomes review without an infinite queue loop', async () => {
  const f = await setup();
  for (let i = 0; i < 8; i++) {
   await env.WALLET_DB.prepare('UPDATE account_backup_jobs SET next_attempt_at = 0 WHERE operation_id = ?').bind(f.id).run();
   const m = (await f.jobs.reserve(f.id))!; expect(m).not.toBeNull(); expect(await f.jobs.claim(m)).toBe(true);
   expect(await f.jobs.fail(m, 'running')).toBe(true);
  }
  expect(await job(f.id)).toMatchObject({ state: 'review', failures: 8, reason: 'processing_error' });
  expect(await f.jobs.due()).toEqual([]); expect(await f.jobs.reserve(f.id)).toBeNull();
 });
 it('malformed queue payload cannot supply execution authority', () => {
  const m = { schema_version: 1, kind: 'account_backup', operation_id: createResourceId('operation'), token: createResourceId('operation') };
  expect(parseBackupWake(m)).toEqual(m);
  expect(() => parseBackupWake({ ...m, rpcUrl: 'https://arbitrary.invalid' })).toThrow();
  expect(() => parseBackupWake({ ...m, kind: 'account_creation' })).toThrow();
 });
 it('mixed queue batches cannot acknowledge or retry the other subgroup', async () => {
  const messages = ['account_creation','account_backup','malformed','transfer_observation'].map((kind) => ({ id: kind, timestamp: new Date(), attempts: 1, body: { kind }, ack: vi.fn(), retry: vi.fn() }));
  const realBatch = createMessageBatch(env.CREATION_QUEUE_NAME, []);
  const batch = { queue: env.CREATION_QUEUE_NAME, metadata: realBatch.metadata, messages, ackAll: vi.fn(), retryAll: vi.fn() };
  await dispatchWalletJobs(batch, env, { creation: { queue: async (part) => { part.ackAll(); } },
   backup: { queue: async (part) => { part.retryAll({ delaySeconds: 60 }); } },
   transfer: { queue: async (part) => { part.retryAll({ delaySeconds: 30 }); } } });
  expect(messages[0].ack).toHaveBeenCalledOnce(); expect(messages[2].ack).toHaveBeenCalledOnce();
  expect(messages[1].ack).not.toHaveBeenCalled(); expect(messages[1].retry).toHaveBeenCalledWith({ delaySeconds: 60 });
  expect(messages[3].ack).not.toHaveBeenCalled(); expect(messages[3].retry).toHaveBeenCalledWith({ delaySeconds: 30 });
  expect(batch.ackAll).not.toHaveBeenCalled(); expect(batch.retryAll).not.toHaveBeenCalled();
 });
 it('wrong queue is rejected before any acknowledgement', async () => {
  const batch = createMessageBatch('foreign-queue', []);
  await expect(dispatchWalletJobs(batch, env, { creation: { queue: vi.fn() }, backup: { queue: vi.fn() }, transfer: { queue: vi.fn() } })).rejects.toThrow('UNEXPECTED_WALLET_QUEUE');
 });
});
