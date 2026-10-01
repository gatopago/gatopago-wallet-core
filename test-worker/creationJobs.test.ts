import { env, exports } from 'cloudflare:workers';
import { applyD1Migrations, createMessageBatch, createExecutionContext, getQueueResult } from 'cloudflare:test';
import { afterEach, beforeAll, beforeEach, describe, expect, it, vi } from 'vitest';
import { createResourceId } from '@gatopago/shared/v3/primitives';
import { CreationDeliveryRepository } from '../src/creation/creationDelivery';
import { createCreationJobHandlers } from '../src/creation/creationJobHandlers';
import { CreationJobRepository, parseCreationWake, type CreationWake } from '../src/creation/creationJobs';
import { createCreationProcessor } from '../src/creation/processCreationJob';
import { cleanCreationDelivery, deliveryNow, deliveryOutbox, seedCreationDelivery } from './creationDelivery.fixture';
import { creationJobsScenario } from './creationJobs.fixture';

beforeAll(async () => { await applyD1Migrations(env.WALLET_DB, env.V3_TEST_MIGRATIONS); });
beforeEach(async () => { await cleanCreationDelivery(); vi.spyOn(Date, 'now').mockReturnValue(deliveryNow() * 1000); });
afterEach(async () => { vi.restoreAllMocks(); await env.WALLET_DB.exec('DROP TRIGGER IF EXISTS creation_job_failure'); await cleanCreationDelivery(); });
const job = (id: string) => env.WALLET_DB.prepare('SELECT * FROM account_creation_jobs WHERE initialization_id = ?').bind(id).first();
type Fixture = Awaited<ReturnType<typeof creationJobsScenario>>;
function batch(f: Fixture, bodies: readonly unknown[] = f.sent) {
	return createMessageBatch(f.bindings.CREATION_QUEUE_NAME, bodies.map((body, i) => ({ id: `message-${i}`, timestamp: new Date(), body, attempts: 1 })));
}
async function consume(f: Fixture, bodies: readonly unknown[] = f.sent) {
	const messages = batch(f, bodies);
	await f.handlers.queue(messages, f.bindings);
	return getQueueResult(messages, createExecutionContext());
}
const moveTo = (seconds: number) => vi.spyOn(Date, 'now').mockReturnValue(seconds * 1000);

describe('durable creation jobs: queue + scheduler + economic lifecycle', () => {
	it('a job insert failure rolls back operation authorization AND outbox', async () => {
		await env.WALLET_DB.prepare(`CREATE TRIGGER creation_job_failure BEFORE INSERT ON account_creation_jobs
			BEGIN SELECT RAISE(ABORT, 'synthetic job insert'); END`).run();
		await expect(seedCreationDelivery()).rejects.toThrow();
		expect(await env.WALLET_DB.prepare(`SELECT (SELECT count(*) FROM account_creation_operations WHERE authorized_at IS NOT NULL) AS authorized,
			(SELECT count(*) FROM account_creation_outbox) AS outbox, (SELECT count(*) FROM account_creation_jobs) AS jobs`).first())
			.toEqual({ authorized: 0, outbox: 0, jobs: 0 });
	});
	it('authorization creates the wake-up atomically; scheduler completes bootstrap with no browser', async () => {
		const f = await creationJobsScenario();
		expect(await job(f.id)).toMatchObject({ state: 'ready', lease_token: null });
		await f.handlers.wake(f.bindings);
		expect(f.sent).toHaveLength(1);
		expect(Object.keys(f.sent[0]).sort()).toEqual(['initialization_id','kind','schema_version','token']);
		expect(f.send).toHaveBeenCalledWith(f.sent[0], { contentType: 'json' });
		await consume(f);
		expect(await job(f.id)).toMatchObject({ state: 'complete', reason: 'projected', lease_token: null });
		expect(f.state.sends).toBe(1);
		expect(await f.operations.read(f.id)).toMatchObject({ deployment_assessment: 'not_assessed', receive_enabled: false, spend_enabled: false });
		expect(await env.WALLET_DB.prepare('SELECT count(*) AS n FROM account_creation_projections').first()).toEqual({ n: 1 });
		f.fetch.mockClear(); await f.handlers.wake(f.bindings); await consume(f);
		expect(f.fetch).not.toHaveBeenCalled(); expect(f.sent).toHaveLength(1);
	});
	it('concurrent dispatchers and repeated queue messages converge on one send', async () => {
		const f = await creationJobsScenario();
		await Promise.all(Array.from({ length: 8 }, () => f.handlers.wake(f.bindings)));
		expect(f.sent).toHaveLength(1);
		await Promise.all(Array.from({ length: 6 }, () => consume(f)));
		expect(f.state.sends).toBe(1);
		expect(await job(f.id)).toMatchObject({ state: 'complete', reason: 'projected' });
	});
	it('lost enqueue acknowledgement invalidates the old token and a later sweep recovers', async () => {
		const f = await creationJobsScenario(), send = f.send.getMockImplementation()!;
		f.send.mockImplementationOnce(async (body) => { await send(body); throw new Error('ambiguous enqueue'); });
		await f.handlers.wake(f.bindings);
		expect(await job(f.id)).toMatchObject({ state: 'ready', failures: 1, lease_token: null });
		await consume(f); expect(f.fetch).not.toHaveBeenCalled();
		moveTo(Number((await job(f.id))!.next_attempt_at));
		await f.handlers.wake(f.bindings);
		expect(f.sent).toHaveLength(2); expect(f.sent[0].token).not.toBe(f.sent[1].token);
		await consume(f); expect(f.state.sends).toBe(1);
		expect(await job(f.id)).toMatchObject({ state: 'complete', reason: 'projected' });
	});
	it('scheduler replaces an unconsumed wake-up only after its lease expires', async () => {
		const f = await creationJobsScenario(), jobs = new CreationJobRepository(env.WALLET_DB, f.configuration);
		await f.handlers.wake(f.bindings); await f.handlers.wake(f.bindings);
		expect(f.sent).toHaveLength(1);
		moveTo(Number((await job(f.id))!.lease_expires_at)); await f.handlers.wake(f.bindings);
		expect(f.sent).toHaveLength(2);
		expect(await jobs.claim(f.sent[0])).toBe(false); expect(await jobs.claim(f.sent[1])).toBe(true);
	});
	it('a stale processor cannot clear the lease of its replacement', async () => {
		const f = await creationJobsScenario(), jobs = new CreationJobRepository(env.WALLET_DB, f.configuration);
		await f.handlers.wake(f.bindings); expect(await jobs.claim(f.sent[0])).toBe(true);
		moveTo(Number((await job(f.id))!.lease_expires_at)); await f.handlers.wake(f.bindings);
		expect(await jobs.claim(f.sent[1])).toBe(true);
		expect(await jobs.finish(f.sent[0], { state: 'complete', reason: 'expired' })).toBe(false);
		expect(await jobs.fail(f.sent[0], 'running')).toBe(false);
		expect((await job(f.id))!.lease_token).toBe(f.sent[1].token);
	});
	it('an ambiguous bundler send is observed and never resent', async () => {
		const f = await creationJobsScenario(); f.state.ambiguous = true;
		await f.handlers.wake(f.bindings); await consume(f);
		expect(f.state.sends).toBe(1); expect((await deliveryOutbox(f.id))!.state).toBe('uncertain');
		expect(await job(f.id)).toMatchObject({ state: 'complete', reason: 'projected' });
		await consume(f); expect(f.state.sends).toBe(1);
	});
	it('a worker crash after send marking does not regain send authority', async () => {
		const f = await creationJobsScenario(), delivery = new CreationDeliveryRepository(env.WALLET_DB, f.configuration);
		const claimed = await delivery.claim(f.id); if (!claimed) throw new Error('Expected grant');
		await delivery.beginSend(claimed); f.state.sent = true;
		moveTo(claimed.until);
		await f.handlers.wake(f.bindings); await consume(f);
		expect(f.state.sends).toBe(0); expect((await deliveryOutbox(f.id))!.state).toBe('uncertain');
		expect(await job(f.id)).toMatchObject({ state: 'complete', reason: 'projected' });
	});
	it('missing evidence persists a spaced retry instead of recursively draining or resending', async () => {
		const f = await creationJobsScenario(); f.state.missing = true;
		await f.handlers.wake(f.bindings); await consume(f);
		expect(await job(f.id)).toMatchObject({ state: 'ready', failures: 0 });
		const next = Number((await job(f.id))!.next_attempt_at);
		expect(next).toBeGreaterThan(deliveryNow());
		f.fetch.mockClear(); await f.handlers.wake(f.bindings); await consume(f);
		expect(f.sent).toHaveLength(1); expect(f.fetch).not.toHaveBeenCalled();
		f.state.missing = false; moveTo(next); await f.handlers.wake(f.bindings); await consume(f);
		expect(await job(f.id)).toMatchObject({ state: 'complete', reason: 'projected' }); expect(f.state.sends).toBe(1);
	});
	it('expiry before dispatch performs no provider call and never sends', async () => {
		const f = await creationJobsScenario(); moveTo(f.initial.input.validUntil);
		await f.handlers.wake(f.bindings); await consume(f);
		expect(await job(f.id)).toMatchObject({ state: 'complete', reason: 'expired' });
		expect((await deliveryOutbox(f.id))!.state).toBe('expired'); expect(f.fetch).not.toHaveBeenCalled();
		expect(f.configuration.checkpoint).not.toHaveBeenCalled();
	});
	it('revocation before send goes to review without broadcasting', async () => {
		const f = await creationJobsScenario();
		await env.WALLET_DB.prepare('UPDATE users SET disabled_at = ? WHERE id = ?').bind(deliveryNow(), f.session.user_id).run();
		await f.handlers.wake(f.bindings); await consume(f);
		expect(await job(f.id)).toMatchObject({ state: 'review', reason: 'revoked' }); expect(f.fetch).not.toHaveBeenCalled();
	});
	it('revocation after a send does not suppress reconciliation', async () => {
		const f = await creationJobsScenario(); f.state.missing = true;
		await f.handlers.wake(f.bindings); await consume(f);
		await env.WALLET_DB.prepare('UPDATE users SET disabled_at = ? WHERE id = ?').bind(deliveryNow(), f.session.user_id).run();
		moveTo(Number((await job(f.id))!.next_attempt_at)); f.state.missing = false;
		await f.handlers.wake(f.bindings); await consume(f);
		expect(await job(f.id)).toMatchObject({ state: 'complete', reason: 'projected' }); expect(f.state.sends).toBe(1);
	});
	it('eight processing failures park the job without logging upstream secrets', async () => {
		const f = await creationJobsScenario(), log = vi.spyOn(console, 'warn').mockImplementation(() => {});
		f.configuration.checkpoint.mockRejectedValue(new Error('secret-url-and-signature'));
		for (let i = 0; i < 8; i++) {
			// Preserve grant lifetime in this test: failure counters are the dimension under test.
			await env.WALLET_DB.prepare('UPDATE account_creation_jobs SET next_attempt_at = 0 WHERE initialization_id = ?').bind(f.id).run();
			await f.handlers.wake(f.bindings); await consume(f, [f.sent.at(-1)]);
		}
		expect(await job(f.id)).toMatchObject({ state: 'review', failures: 8, reason: 'processing_error' });
		expect(JSON.stringify(log.mock.calls)).not.toContain('secret-url-and-signature'); expect(f.fetch).not.toHaveBeenCalled();
		await f.handlers.wake(f.bindings); expect(f.sent).toHaveLength(8);
	});
	it('a failed final job acknowledgement recovers an already-projected creation without new RPC', async () => {
		const f = await creationJobsScenario();
		await env.WALLET_DB.prepare(`CREATE TRIGGER creation_job_failure BEFORE UPDATE ON account_creation_jobs
			WHEN NEW.state = 'complete' BEGIN SELECT RAISE(ABORT, 'synthetic job acknowledgement'); END`).run();
		await f.handlers.wake(f.bindings); await consume(f);
		expect(await job(f.id)).toMatchObject({ state: 'ready', failures: 1 });
		await env.WALLET_DB.exec('DROP TRIGGER creation_job_failure');
		moveTo(deliveryNow() + 400); f.fetch.mockClear();
		await f.handlers.wake(f.bindings); await consume(f);
		expect(await job(f.id)).toMatchObject({ state: 'complete', reason: 'projected' }); expect(f.fetch).not.toHaveBeenCalled();
	});
	it('project/profile admission scopes scheduler and consumer, independently of the message', async () => {
		const f = await creationJobsScenario(), message: CreationWake = { kind: 'account_creation', schema_version: 1, initialization_id: f.id, token: createResourceId('operation') };
		for (const config of [{ ...f.configuration, environment: 'production' as const }, { ...f.configuration, profiles: [] }]) {
			const repo = new CreationJobRepository(env.WALLET_DB, config);
			expect(await repo.due()).toEqual([]); expect(await repo.reserve(f.id)).toBeNull(); expect(await repo.claim(message)).toBe(false);
		}
		expect(f.fetch).not.toHaveBeenCalled();
	});
	it('rejects altered bodies and wrong queues without processing any grant', async () => {
		const f = await creationJobsScenario(); await f.handlers.wake(f.bindings);
		for (const bad of [null, { ...f.sent[0], signature: 'untrusted' }, { ...f.sent[0], token: 'x' }, { ...f.sent[0], kind: 'send' }]) {
			expect(() => parseCreationWake(bad)).toThrow(); await consume(f, [bad]);
		}
		const other = createMessageBatch('another-queue', []);
		await expect(f.handlers.queue(other, f.bindings)).rejects.toThrow('UNEXPECTED_CREATION_QUEUE');
		expect(f.fetch).not.toHaveBeenCalled();
	});
	it('closed release does no D1/provider/queue work and exposes no public job endpoint', async () => {
		const f = await creationJobsScenario(), closed = createCreationJobHandlers(() => null);
		await closed.wake(f.bindings); await closed.queue(batch(f), f.bindings);
		expect(f.fetch).not.toHaveBeenCalled(); expect(f.send).not.toHaveBeenCalled();
		f.fetch.mockRestore();
		const response = await exports.default.fetch('https://api.staging.gatopago.com/app/v1/creation-jobs');
		expect(response.status).toBe(404);
	});
	it('configuration is detached; duplicate provider identities are rejected before RPC', async () => {
		const f = await creationJobsScenario(), processor = createCreationProcessor(f.configuration);
		f.configuration.networks[0].providers[1].operatorId = 'provider_a';
		expect(() => createCreationProcessor(f.configuration)).toThrow('CREATION_OBSERVERS_OVERLAP');
		f.configuration.networks[0].transport.url = 'https://evil.invalid/';
		expect(await processor.run(env.WALLET_DB, f.id, new AbortController().signal)).toEqual({ state: 'complete', reason: 'projected' });
	});
	it('a noncooperative checkpoint times out and cannot send when it finally resolves', async () => {
		const f = await creationJobsScenario(), timeout = AbortSignal.timeout.bind(AbortSignal);
		vi.spyOn(AbortSignal, 'timeout').mockImplementation((ms) => timeout(ms === 120_000 ? 250 : ms));
		let release: (() => void) | undefined;
		f.configuration.checkpoint.mockImplementation(() => new Promise((resolve) => { release = () => resolve(f.inspection.input.checkpoint); }));
		await f.handlers.wake(f.bindings); await consume(f);
		expect(await job(f.id)).toMatchObject({ state: 'ready', failures: 1 });
		expect(release).toBeTypeOf('function'); release!();
		await new Promise((resolve) => setTimeout(resolve, 10));
		expect(f.fetch).not.toHaveBeenCalled(); expect(f.state.sends).toBe(0);
	});
	it('unresolved economic evidence is parked after 24h without inventing failure or success', async () => {
		const f = await creationJobsScenario(); f.state.missing = true;
		await f.handlers.wake(f.bindings); await consume(f);
		moveTo(Number((await deliveryOutbox(f.id))!.created_at) + 86400); f.fetch.mockClear();
		await f.handlers.wake(f.bindings); await consume(f);
		expect(await job(f.id)).toMatchObject({ state: 'review', reason: 'observation_timeout' });
		expect((await deliveryOutbox(f.id))!.state).toBe('accepted'); expect(f.fetch).not.toHaveBeenCalled();
		expect(await env.WALLET_DB.prepare('SELECT count(*) AS n FROM account_creation_projections').first()).toEqual({ n: 0 });
	});
	it('an enqueue error cannot release a consumer which already acquired the job', async () => {
		const f = await creationJobsScenario(), jobs = new CreationJobRepository(env.WALLET_DB, f.configuration);
		f.send.mockImplementationOnce(async (message) => {
			f.sent.push(message); expect(await jobs.claim(message)).toBe(true); throw new Error('late enqueue error');
		});
		await f.handlers.wake(f.bindings);
		expect(await job(f.id)).toMatchObject({ state: 'running', lease_token: f.sent[0].token, failures: 0 });
	});
	it('SQL rejects missing leases/terminal reasons and scheduler limits are bounded', async () => {
		const f = await creationJobsScenario(), repo = new CreationJobRepository(env.WALLET_DB, f.configuration);
		await expect(env.WALLET_DB.prepare("UPDATE account_creation_jobs SET state = 'running', lease_token = ?, lease_expires_at = NULL WHERE initialization_id = ?")
			.bind(createResourceId('operation'), f.id).run()).rejects.toThrow();
		await expect(env.WALLET_DB.prepare("UPDATE account_creation_jobs SET state = 'complete' WHERE initialization_id = ?").bind(f.id).run()).rejects.toThrow();
		await expect(repo.due(0)).rejects.toThrow(); await expect(repo.due(51)).rejects.toThrow();
		expect(await repo.due(1)).toEqual([f.id]);
	});
	it('queue retries a D1 claim outage; it acknowledges only after durable processing resumes', async () => {
		const f = await creationJobsScenario(); await f.handlers.wake(f.bindings);
		await env.WALLET_DB.prepare(`CREATE TRIGGER creation_job_failure BEFORE UPDATE ON account_creation_jobs
			WHEN NEW.state = 'running' BEGIN SELECT RAISE(ABORT, 'synthetic claim outage'); END`).run();
		const messages = batch(f), retry = vi.spyOn(messages.messages[0], 'retry'), ack = vi.spyOn(messages.messages[0], 'ack');
		await f.handlers.queue(messages, f.bindings);
		expect(retry).toHaveBeenCalledExactlyOnceWith({ delaySeconds: 60 }); expect(ack).not.toHaveBeenCalled();
		expect(f.fetch).not.toHaveBeenCalled(); expect((await job(f.id))!.state).toBe('queued');
		await env.WALLET_DB.exec('DROP TRIGGER creation_job_failure');
		const resumed = batch(f), acknowledged = vi.spyOn(resumed.messages[0], 'ack');
		await f.handlers.queue(resumed, f.bindings); expect(acknowledged).toHaveBeenCalledTimes(1);
		expect(await job(f.id)).toMatchObject({ state: 'complete', reason: 'projected' });
	});
});
