import { seedUser } from './user.fixture';
import { env } from 'cloudflare:workers';
import { applyD1Migrations, createMessageBatch } from 'cloudflare:test';
import { afterEach, beforeAll, beforeEach, describe, expect, it, vi } from 'vitest';
import { parseCreationPreview } from '@gatopago/shared/v3/creation-operation-wire';
import { CreationOperationRepository } from '../src/creation/creationOperation';
import { InitializationRepository } from '../src/creation/initialization';
import { cleanCreationDelivery, deliveryIdentity, deliveryNow } from './creationDelivery.fixture';
import { creationJobsScenario } from './creationJobs.fixture';

beforeAll(async () => {
  await applyD1Migrations(env.WALLET_DB, env.V3_TEST_MIGRATIONS);
});
beforeEach(async () => {
  await cleanCreationDelivery();
  vi.spyOn(Date, 'now').mockReturnValue(deliveryNow() * 1000);
});
afterEach(async () => {
  vi.restoreAllMocks();
  await cleanCreationDelivery();
});
type Fixture = Awaited<ReturnType<typeof creationJobsScenario>>;
async function finish(f: Fixture) {
  await f.handlers.wake(f.bindings);
  await f.handlers.queue(
    createMessageBatch(
      f.bindings.CREATION_QUEUE_NAME,
      f.sent.map((body, i) => ({
        id: `lifecycle-${i}`,
        timestamp: new Date(),
        body,
        attempts: 1,
      })),
    ),
    f.bindings,
  );
}
async function tables() {
  const names = [
    'account_creation_operations',
    'account_creation_outbox',
    'account_creation_jobs',
    'account_creation_observation_jobs',
    'account_creation_observations',
    'account_creation_projections',
    'wallet_accounts',
    'wallets',
  ];
  return Promise.all(
    names.map((name) =>
      env.WALLET_DB.prepare(`SELECT * FROM ${name}`)
        .all()
        .then((r) => r.results),
    ),
  );
}
function renewed(f: Fixture) {
  return new CreationOperationRepository(
    env.WALLET_DB,
    { ...f.principal, expiresAt: deliveryNow() + 3600 },
    f.configuration.scope,
    f.configuration.profiles,
  );
}

describe('owner creation lifecycle; one durable snapshot, no network side effects', () => {
  it('reads queued authorization without acquiring leases, sending or mutating any lifecycle table', async () => {
    const f = await creationJobsScenario(),
      before = await tables();
    f.fetch.mockClear();
    for (let i = 0; i < 3; i++)
      expect((await f.operations.preview(f.id)).lifecycle).toEqual({
        job_state: 'ready',
        reason: null,
        observation: null,
        bootstrap: null,
        account_readiness: 'not_assessed',
      });
    expect(await tables()).toEqual(before);
    expect(f.fetch).not.toHaveBeenCalled();
    expect(f.send).not.toHaveBeenCalled();
  });
  it('shows the verified projection as historical bootstrap, not current account readiness', async () => {
    const f = await creationJobsScenario();
    await finish(f);
    const before = await tables();
    f.fetch.mockClear();
    f.send.mockClear();
    const preview = await f.operations.preview(f.id);
    expect(preview.receipt).toMatchObject({
      deployment_assessment: 'not_assessed',
      receive_enabled: false,
      spend_enabled: false,
    });
    expect(preview.lifecycle).toMatchObject({
      job_state: 'complete',
      reason: 'projected',
      account_readiness: 'not_assessed',
      observation: { status: 'observed', finality: 'finalized', outcome: 'creation_succeeded' },
      bootstrap: { recorded_at: deliveryNow() },
    });
    const initial = new InitializationRepository(
      env.WALLET_DB,
      f.principal,
      f.configuration.scope,
      f.configuration.profiles,
    );
    const preparation = await initial.readPreparation(f.id);
    expect(
      parseCreationPreview(preview, {
        preparation,
        expected: {
          id: f.id,
          credentialRef: f.credentialRef,
          document: f.configuration.profiles[0].document,
          profileDigest: f.configuration.profiles[0].digest,
          scope: f.configuration.scope,
          userSaltCommitment: f.f.input.userSaltCommitment,
        },
      }).lifecycle,
    ).toEqual(preview.lifecycle);
    expect(await tables()).toEqual(before);
    expect(f.fetch).not.toHaveBeenCalled();
    expect(f.send).not.toHaveBeenCalled();
    const serialized = JSON.stringify(preview.lifecycle);
    for (const privateValue of [
      f.signed.operation.signature,
      f.configuration.networks[0].transport.url,
      f.sent[0].token,
      f.configuration.networks[0].providers[0].url,
      f.principal.userId,
    ])
      expect(serialized).not.toContain(privateValue);
  });
  it('keeps a historical projection after the evidence and signing window expire, without renewing either', async () => {
    const f = await creationJobsScenario();
    await finish(f);
    const before = await f.operations.preview(f.id);
    vi.spyOn(Date, 'now').mockReturnValue((f.signed.prepared.message.validUntil + 3600) * 1000);
    f.fetch.mockClear();
    const after = await renewed(f).preview(f.id);
    expect(after.receipt.authorization_expired).toBe(true);
    expect(after.lifecycle).toEqual(before.lifecycle);
    expect(after.observed_at).toBeGreaterThan(before.observed_at);
    expect(f.fetch).not.toHaveBeenCalled();
  });
  it('reports missing evidence rather than treating bundler acceptance as success', async () => {
    const f = await creationJobsScenario();
    f.state.missing = true;
    await finish(f);
    f.fetch.mockClear();
    expect(await f.operations.preview(f.id)).toMatchObject({
      receipt: { delivery_state: 'accepted' },
      lifecycle: {
        job_state: 'ready',
        bootstrap: null,
        observation: { status: 'not_observed', transaction_hash: null, finality: 'not_assessed' },
      },
    });
    expect(f.fetch).not.toHaveBeenCalled();
  });
  it('an expired pending authorization is not labelled delivered; reads never run the expiry job', async () => {
    const f = await creationJobsScenario();
    vi.spyOn(Date, 'now').mockReturnValue(f.signed.prepared.message.validUntil * 1000);
    expect((await renewed(f).preview(f.id)).receipt).toMatchObject({
      authorization_expired: true,
      delivery_state: 'pending',
    });
    await finish(f);
    expect((await renewed(f).preview(f.id)).lifecycle).toMatchObject({
      job_state: 'complete',
      reason: 'expired',
      observation: null,
      bootstrap: null,
    });
    expect(f.fetch).not.toHaveBeenCalled();
  });
  it.each(['revoked', 'execution_reverted', 'observation_timeout', 'processing_error'])(
    'exposes bounded review reason %s without operational secrets',
    async (reason) => {
      const f = await creationJobsScenario();
      await env.WALLET_DB.prepare(
        "UPDATE account_creation_jobs SET state = 'review', reason = ? WHERE initialization_id = ?",
      )
        .bind(reason, f.id)
        .run();
      expect((await f.operations.preview(f.id)).lifecycle).toMatchObject({
        job_state: 'review',
        reason,
      });
      expect(f.fetch).not.toHaveBeenCalled();
    },
  );
  it('refuses missing job state and inconsistent completion instead of constructing a success', async () => {
    const f = await creationJobsScenario();
    await env.WALLET_DB.prepare(
      "UPDATE account_creation_jobs SET state = 'complete', reason = 'projected' WHERE initialization_id = ?",
    )
      .bind(f.id)
      .run();
    await expect(f.operations.preview(f.id)).rejects.toMatchObject({ code: 'WALLET_DATA_INVALID' });
    await env.WALLET_DB.prepare('DELETE FROM account_creation_jobs WHERE initialization_id = ?')
      .bind(f.id)
      .run();
    await expect(f.operations.preview(f.id)).rejects.toMatchObject({ code: 'WALLET_DATA_INVALID' });
  });
  it('refuses a missing latest head rather than falling back to the prior observation', async () => {
    const f = await creationJobsScenario();
    f.state.missing = true;
    await finish(f);
    await env.WALLET_DB.prepare(
      'UPDATE account_creation_observation_jobs SET lease_epoch = 2, latest_epoch = 2 WHERE initialization_id = ?',
    )
      .bind(f.id)
      .run();
    await expect(f.operations.preview(f.id)).rejects.toMatchObject({ code: 'WALLET_DATA_INVALID' });
  });
  it('another owner cannot read a creation even with its resource ID', async () => {
    const f = await creationJobsScenario(),
      principal = deliveryIdentity('lifecycle-other');
    await seedUser(env.WALLET_DB, principal);
    const other = new CreationOperationRepository(
      env.WALLET_DB,
      principal,
      f.configuration.scope,
      f.configuration.profiles,
    );
    await expect(other.preview(f.id)).rejects.toMatchObject({ code: 'NOT_FOUND' });
    expect(f.fetch).not.toHaveBeenCalled();
  });
  it('revoked or expired login cannot read even a completed result', async () => {
    const f = await creationJobsScenario();
    await finish(f);
    vi.spyOn(Date, 'now').mockReturnValue(f.principal.expiresAt * 1000);
    await expect(f.operations.preview(f.id)).rejects.toMatchObject({ code: 'UNAUTHENTICATED' });
    await env.WALLET_DB.prepare('UPDATE users SET disabled_at = ? WHERE id = ?')
      .bind(deliveryNow(), f.session.user_id)
      .run();
    await expect(renewed(f).preview(f.id)).rejects.toThrow();
  });
});
