import { env, exports } from 'cloudflare:workers';
import {
  applyD1Migrations,
  createMessageBatch,
  createExecutionContext,
  getQueueResult,
} from 'cloudflare:test';
import { afterEach, beforeAll, beforeEach, describe, expect, it, vi } from 'vitest';
import { toHex } from 'viem';
import { generatePrivateKey, privateKeyToAccount } from 'viem/accounts';
import {
  CLIENT_COMPATIBILITY_PATH,
  clientMutationHeaders,
} from '@gatopago/shared/v3/client-release';
import { createWalletWorker } from '../src/index';
import { createWalletRuntime } from '../src/runtime';
import { configureWalletNetworks } from '../src/runtime/config';
import { requireFreshCreationDeployment } from '../src/runtime/finality';
import { runtimeFixture } from '../test/runtime.fixture';
import { creationJobsScenario } from './creationJobs.fixture';
import { cleanCreationDelivery, deliveryNow } from './creationDelivery.fixture';

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

async function composed() {
  const f = await creationJobsScenario(),
    settings = runtimeFixture(f.configuration.profiles[0]);
  const bindings: WalletCoreV3Bindings = { ...env, ...settings.bindings };
  const worker = createWalletWorker(settings.catalog, () => settings.environment);

  const inspect = f.inspection.request.getMockImplementation()!;
  f.inspection.request.mockImplementation(async (input) => {
    const value = await inspect(input);
    return input.method === 'eth_getBlockByNumber'
      ? { ...(value as object), timestamp: toHex(deliveryNow()) }
      : value;
  });
  return { f, settings, bindings, worker };
}

describe('Wallet Core composed entrypoint: real D1, signed grants, synthetic providers', () => {
  it('keeps liveness separate from unconfigured readiness and performs no RPC', async () => {
    const fetch = vi.spyOn(globalThis, 'fetch');
    const live = await exports.default.fetch('https://local.invalid/app/v1/health/live');
    expect(live.status).toBe(200);
    expect(await live.json()).toEqual({ service: 'gatopago-wallet-core', status: 'ok' });
    for (const path of ['/health/live', '/health/ready']) {
      expect((await exports.default.fetch(`https://local.invalid${path}`)).status).toBe(404);
    }

    const settings = runtimeFixture();
    const worker = createWalletWorker({ schema_version: 1, production: [] }, () => ({
      ...settings.environment,
      wallet_enabled: [],
    }));
    const response = await worker.fetch(new Request('https://local.invalid/app/v1/health/ready'), {
      ...env,
      ...settings.bindings,
    });
    expect(response.status).toBe(503);
    expect(await response.json()).toMatchObject({
      configured: false,
      capabilities: { creation: false, transfers: false, backup: false },
    });
    expect(fetch).not.toHaveBeenCalled();
  });
  it('serves passkey login from configured local bindings without a relayer key', async () => {
    const bindings = {
      ...env,
      GATOPAGO_WEB_ORIGIN: 'http://localhost:3000',
      GATOPAGO_API_ORIGIN: 'http://localhost:8787',
      GATOPAGO_BUSINESS_ORIGIN: 'http://localhost:3000',
      GATOPAGO_WALLET_NETWORKS: 'eip155:421614',
      FIREBASE_CUSTOM_TOKEN_SIGNER_JSON: 'synthetic-test-signer',
      PRIVATE_KEY: '',
    };
    const worker = createWalletWorker();
    const request = () =>
      new Request('http://localhost:8787/app/v1/auth/login/options', {
        method: 'POST',
        headers: {
          Origin: bindings.GATOPAGO_WEB_ORIGIN,
          'Content-Type': 'application/json',
          'CF-Connecting-IP': '127.0.0.1',
          ...clientMutationHeaders('production'),
        },
        body: '{}',
      });
    const result = await worker.fetch(request(), bindings);
    expect(result.status).toBe(200);
    expect(await result.json()).toMatchObject({
      scope: { rpId: 'localhost', origin: 'http://localhost:3000' },
    });
    const missing = await worker.fetch(request(), { ...bindings, GATOPAGO_API_ORIGIN: '' });
    expect(missing.status).toBe(503);
  });
  it('reports the configured relay address without revealing keys or endpoint credentials', async () => {
    const { settings, bindings } = await composed();
    const key = generatePrivateKey();
    const catalog = {
      ...settings.catalog,
      production: [
        {
          ...settings.network,
          transport: {
            kind: 'self',
            endpoint: 'observer_a',
            maxGas: '2000000',
            maxFeePerGas: '100000000',
            maxPriorityFeePerGas: '0',
          },
        },
      ],
    };
    const worker = createWalletWorker(catalog, () => settings.environment);
    bindings.PRIVATE_KEY = key;
    const response = await worker.fetch(
      new Request(settings.environment.api_origin + '/app/v1/health/ready'),
      bindings,
    );
    expect(response.status).toBe(200);
    const body = await response.json();
    expect(body).toMatchObject({
      networks: [
        {
          network_id: settings.profile.deployment.network_id,
          transport: 'self',
          relayer_address: privateKeyToAccount(key).address,
        },
      ],
    });
    expect(JSON.stringify(body)).not.toContain(key);
    expect(JSON.stringify(body)).not.toContain('observer-a');
  });
  it('advertises the exact admitted profile through HTTP, without exposing secret endpoints', async () => {
    const { f, settings, bindings, worker } = await composed();
    f.fetch.mockClear();
    const response = await worker.fetch(
      new Request(settings.environment.api_origin + CLIENT_COMPATIBILITY_PATH),
      bindings,
    );
    expect(response.status).toBe(200);
    const body = await response.json();
    expect(body).toMatchObject({
      account_profiles: [
        { generation: '3', contract_manifest_version: settings.profile.deployment.manifest_id },
      ],
    });
    expect(JSON.stringify(body)).not.toContain('observer-');
    const anonymous = new Request(
      settings.environment.api_origin + '/app/v1/account-initializations',
      {
        method: 'POST',
        headers: {
          Origin: settings.environment.web_origin,
          'Content-Type': 'application/json',
          ...clientMutationHeaders('production', {
            generation: '3',
            contract_manifest_version: settings.profile.deployment.manifest_id,
          }),
        },
        body: '{}',
      },
    );
    expect((await worker.fetch(anonymous, bindings)).status).toBe(401);
    expect(f.fetch).not.toHaveBeenCalled();
  });
  it('connects Cron and Queue to creation broadcast, finality and projection with idempotent replay', async () => {
    const { f, settings, bindings, worker } = await composed(),
      messages: unknown[] = [];
    bindings.CREATION_JOBS = {
      send: async (body) => {
        messages.push(body);
        return { metadata: { metrics: { backlogCount: messages.length, backlogBytes: 0 } } };
      },
      sendBatch: env.CREATION_JOBS.sendBatch.bind(env.CREATION_JOBS),
      metrics: env.CREATION_JOBS.metrics,
    };
    await worker.scheduled(
      { cron: '* * * * *', scheduledTime: Date.now(), noRetry() {} },
      bindings,
    );
    expect(messages).toHaveLength(1);
    const batch = () =>
      createMessageBatch(
        bindings.CREATION_QUEUE_NAME,
        messages.map((body, i) => ({
          id: `runtime-${i}`,
          timestamp: new Date(),
          attempts: 1,
          body,
        })),
      );
    const first = batch();
    await worker.queue(first, bindings);
    expect((await getQueueResult(first, createExecutionContext())).ackAll).toBe(false);
    expect(
      await env.WALLET_DB.prepare(
        'SELECT state,reason FROM account_creation_jobs WHERE initialization_id = ?',
      )
        .bind(f.id)
        .first(),
    ).toEqual({ state: 'complete', reason: 'projected' });
    expect(f.state.sends).toBe(1);
    expect(
      await env.WALLET_DB.prepare('SELECT count(*) AS n FROM account_creation_projections').first(
        'n',
      ),
    ).toBe(1);
    await worker.queue(batch(), bindings);
    expect(f.state.sends).toBe(1);
    const runtime = createWalletRuntime(bindings, settings.environment, settings.catalog);
    expect(runtime.capabilities).toEqual({ creation: true, transfers: true, backup: false });
  });
  it('rejects invalid configuration before acknowledging a durable wake-up or exposing an upstream error', async () => {
    const { f, settings, bindings, worker } = await composed();
    bindings.WALLET_RPC_ENDPOINTS = '{private-token';
    const batch = createMessageBatch(bindings.CREATION_QUEUE_NAME, [
      { id: 'wake', timestamp: new Date(), attempts: 1, body: {} },
    ]);
    await expect(worker.queue(batch, bindings)).rejects.toThrow(
      /^WALLET_RUNTIME_CONFIGURATION_INVALID$/,
    );
    const result = await getQueueResult(batch, createExecutionContext());
    expect(result.explicitAcks).toEqual([]);
    expect(f.state.sends).toBe(0);
    const response = await worker.fetch(
      new Request('https://local.invalid/app/v1/health/ready'),
      bindings,
    );
    expect(response.status).toBe(503);
    expect(await response.text()).not.toContain('private-token');
    const identity = await worker.fetch(
      new Request(settings.environment.api_origin + '/app/v1/session', {
        headers: {
          Origin: settings.environment.web_origin,
          ...clientMutationHeaders('production'),
        },
      }),
      bindings,
    );
    expect(identity.status).toBe(401);
  });
  it('refuses creation when independent observers disagree on the finalized checkpoint', async () => {
    const { f, settings, bindings } = await composed();
    const fetch = f.fetch.getMockImplementation()!;
    f.fetch.mockImplementation(async (url, init) => {
      const response = await fetch(url, init);
      const request = JSON.parse(String(init?.body));
      if (String(url).includes('observer-b') && request.method === 'eth_getBlockByNumber') {
        const body = (await response.json()) as { result: { hash: string } };
        body.result.hash = `0x${'a'.repeat(64)}`;
        return Response.json(body);
      }
      return response;
    });
    const [network] = configureWalletNetworks(settings.catalog, settings.environment, bindings);
    await expect(
      requireFreshCreationDeployment(network, AbortSignal.timeout(1000)),
    ).rejects.toThrow('RUNTIME_FINALITY_UNAVAILABLE');
    expect(f.state.sends).toBe(0);
  });
  it('composes the optional sponsor without serializing its signing capability into route profiles', async () => {
    const settings = runtimeFixture(),
      key = generatePrivateKey();
    const bindings = { ...env, ...settings.bindings, WALLET_BACKUP_SIGNER_KEY: key };
    const catalog = {
      ...settings.catalog,
      production: [
        {
          ...settings.network,
          backupSponsor: {
            operator: privateKeyToAccount(key).address,
            maxGas: '1000000',
            maxFeePerGas: '1000000000',
            maxPriorityFeePerGas: '0',
            maxExecutionFee: '1000000000000000',
          },
        },
      ],
    };
    const worker = createWalletWorker(catalog, () => settings.environment);
    const response = await worker.fetch(
      new Request('https://local.invalid/app/v1/health/ready'),
      bindings,
    );
    expect(response.status).toBe(200);
    expect(await response.json()).toMatchObject({
      capabilities: { backup: true, creation: true, transfers: true },
    });
    const fetch = vi.spyOn(globalThis, 'fetch');
    await worker.scheduled(
      { cron: '* * * * *', scheduledTime: Date.now(), noRetry() {} },
      bindings,
    );
    expect(fetch).not.toHaveBeenCalled();
  });
});
