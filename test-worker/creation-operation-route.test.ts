import { testPrincipal } from './principal.fixture';
import { seedUser } from './user.fixture';
import { sponsorshipData } from '@gatopago/shared/v3/paymaster';
import { env, exports } from 'cloudflare:workers';
import { applyD1Migrations } from 'cloudflare:test';
import { afterEach, beforeAll, beforeEach, describe, expect, it, vi } from 'vitest';
import manifests from '@gatopago/environment/environments.json';
import { parseEnvironment } from '@gatopago/environment';
import { clientMutationHeaders } from '@gatopago/shared/v3/client-release';
import { parseCreationPreview } from '@gatopago/shared/v3/creation-operation-wire';
import { createResourceId } from '@gatopago/shared/v3/primitives';
import { createCreationOperationRoute } from '../src/creation/creationOperationRoute';
import { InitializationRepository } from '../src/creation/initialization';
import { initializationFixture } from '@gatopago/test-fixtures/v3-initialization';
import { fixtureHash } from '@gatopago/test-fixtures/v3-inspection';
import { clearIdentityKeys, projectId, testIdentitySigner } from './identity.fixture';
import { createWalletRuntime } from '../src/runtime';
import { runtimeFixture } from '../test/runtime.fixture';
import * as runtimeFinality from '../src/runtime/finality';
import { arbitrumSepolia } from '../src/runtime/catalog';

const creationOperationRoute = createCreationOperationRoute({
  profiles: [],
  async requireFreshDeployment() {
    throw new Error('Unexpected observer');
  },
  async quoteGas() {
    throw new Error('Unexpected quote');
  },
});

const now = () => Math.floor(Date.now() / 1000);
const config = parseEnvironment({
  ...manifests.production,
  status: 'provisioned',
  firebase_project_id: projectId,
  wallet_enabled: ['eip155:84532'],
});
const gas = (maximumGasCharge = 2_250_000_000_000_000n) => ({
  verificationGasLimit: 2_000_000n,
  callGasLimit: 100_000n,
  preVerificationGas: 150_000n,
  maxFeePerGas: 1_000_000_000n,
  maxPriorityFeePerGas: 0n,
  maximumGasCharge,
});
const cap = () => ({ maximum_gas_charge: gas().maximumGasCharge.toString() });
let f: ReturnType<typeof initializationFixture>,
  signer: Awaited<ReturnType<typeof testIdentitySigner>>;
const account = () => ({
  generation: '3',
  contract_manifest_version: f.profile.deployment.manifest_id,
});
const path = (id: string) => `/app/v1/account-initializations/${id}/creation-operation`;
const proof = (digest: `0x${string}`, options: Parameters<typeof f.assertion>[1] = {}) => {
  const p = f.assertion(digest, options),
    b64 = (bytes: Uint8Array) => Buffer.from(bytes).toString('base64url');
  return {
    authenticator_data: b64(p.authenticatorData),
    client_data: b64(p.clientDataJSON),
    signature: b64(p.signatureDER),
  };
};
async function request(
  route: string,
  body: unknown = null,
  method = 'POST',
  subject = 'creation-http-a',
  signal?: AbortSignal,
) {
  return new Request(`${config.api_origin}${route}`, {
    method,
    signal,
    headers: {
      Origin: config.web_origin,
      'Content-Type': 'application/json',
      Authorization: `Bearer ${await signer.token({ sub: subject })}`,
      ...clientMutationHeaders('production', method === 'GET' ? undefined : account()),
    },
    ...(method === 'POST' ? { body: JSON.stringify(body) } : {}),
  });
}
function candidate() {
  const observe = vi.fn(async () => undefined),
    quote = vi.fn(async (_pin: unknown, _initial: unknown, maximum: bigint) => gas(maximum));
  const deps = {
    profiles: [{ ...f.pin, environment: 'production' as const }],
    requireFreshDeployment: observe,
    quoteGas: quote,
  };
  return { run: createCreationOperationRoute(deps), observe, quote, deps };
}
async function start(authorized = true, subject = 'creation-http-a') {
  const principal = testPrincipal(subject);
  const session = await seedUser(env.WALLET_DB, principal);
  const credentialRef = createResourceId('operation'),
    id = createResourceId('operation');
  await env.WALLET_DB.prepare(
    `INSERT INTO webauthn_credentials
		(id,user_id,rp_id,origin,credential_id,public_key,transports_json,aaguid,backup_eligible,backed_up,sign_count,response_hash,created_at)
		VALUES (?,?,?,?,?,?,'["internal"]','00000000-0000-0000-0000-000000000000',0,0,1,?,?)`,
  )
    .bind(
      credentialRef,
      session.user_id,
      f.input.scope.rpId,
      f.input.scope.origin,
      Buffer.from(credentialRef).toString('base64url'),
      f.input.publicKey,
      fixtureHash('1'),
      now(),
    )
    .run();
  const repo = new InitializationRepository(env.WALLET_DB, principal, f.input.scope, [f.pin]);
  const initial = await repo.prepare({
    id,
    credentialRef,
    profileDigest: f.pin.digest,
    userSaltCommitment: f.input.userSaltCommitment,
  });
  if (authorized) await repo.authorize(id, f.assertion(initial.approval_digest));
  const consent = {
    preparation: await repo.readPreparation(id),
    expected: {
      id,
      credentialRef,
      document: f.pin.document,
      profileDigest: f.pin.digest,
      scope: f.input.scope,
      userSaltCommitment: f.input.userSaltCommitment,
    },
  };
  return { id, consent, ...session };
}
const count = () =>
  env.WALLET_DB.prepare('SELECT count(*) AS n FROM account_creation_operations').first<number>('n');
const queued = () => env.WALLET_DB.prepare('SELECT * FROM account_creation_outbox').all();
beforeAll(async () => {
  await applyD1Migrations(env.WALLET_DB, env.V3_TEST_MIGRATIONS);
  signer = await testIdentitySigner();
});
beforeEach(async () => {
  f = initializationFixture();
  await clearIdentityKeys();
  signer.mock();
  await env.WALLET_DB
    .exec(`DROP TRIGGER IF EXISTS creation_http_outbox_fail; DELETE FROM account_creation_outbox; DELETE FROM account_creation_operations;
		DELETE FROM account_initializations; DELETE FROM webauthn_credentials; DELETE FROM webauthn_enrollments;
		DELETE FROM wallet_accounts; DELETE FROM wallets; DELETE FROM users;`);
});
afterEach(async () => {
  vi.restoreAllMocks();
  vi.unstubAllGlobals();
  await env.WALLET_DB.exec('DROP TRIGGER IF EXISTS creation_http_outbox_fail;');
});

describe('first creation operation HTTP boundary (synthetic quote/observer, real JWT/P256/D1)', () => {
  it('restores and authorizes the exact earlier review after the runtime creation ceiling changes', async () => {
    const t = await start(),
      settings = runtimeFixture(f.pin);
    settings.network.creationGas = {
      ...arbitrumSepolia.creationGas,
      verificationGasLimit: '496000',
    };
    const observe = vi
      .spyOn(runtimeFinality, 'requireFreshCreationDeployment')
      .mockResolvedValue(undefined);
    const initialRuntime = createWalletRuntime(
      { ...env, ...settings.bindings },
      config,
      settings.catalog,
    );
    const first = parseCreationPreview(
      await (
        await initialRuntime.creationOperation(await request(path(t.id), {}), env, config)
      ).json(),
      t.consent,
    );
    expect(first.terms.verificationGasLimit).toBe(496000n);
    expect(first.terms.maximumGasCharge).toBe(74600000000000n);
    settings.network.creationGas = { ...arbitrumSepolia.creationGas };
    const updatedRuntime = createWalletRuntime(
      { ...env, ...settings.bindings },
      config,
      settings.catalog,
    );
    const restored = parseCreationPreview(
      await (
        await updatedRuntime.creationOperation(await request(path(t.id), {}), env, config)
      ).json(),
      t.consent,
    );
    expect(restored.terms).toEqual(first.terms);
    expect(restored.candidate).toEqual(first.candidate);
    expect(observe).toHaveBeenCalledOnce();
    expect(
      (
        await updatedRuntime.creationOperation(
          await request(`${path(t.id)}/authorize`, proof(first.candidate.digest)),
          env,
          config,
        )
      ).status,
    ).toBe(200);
    expect((await queued()).results).toHaveLength(1);
  });
  it('prepares automatic server terms and restores exact saved bytes without repricing after a lost response', async () => {
    const t = await start(),
      c = candidate(),
      ceiling = vi.fn(async () => gas().maximumGasCharge);
    const route = createCreationOperationRoute({ ...c.deps, automaticGasCap: ceiling });
    const response = await route(await request(path(t.id), {}), env, config);
    expect(response.status).toBe(200);
    const first = parseCreationPreview(await response.json(), t.consent);
    expect(first.terms.maximumGasCharge).toBe(gas().maximumGasCharge);
    expect((await queued()).results).toHaveLength(0);
    ceiling.mockRejectedValue(new Error('policy unavailable'));
    c.quote.mockRejectedValue(new Error('do not reprice'));
    c.observe.mockClear();
    const repeat = parseCreationPreview(
      await (await route(await request(path(t.id), {}), env, config)).json(),
      t.consent,
    );
    expect(repeat.candidate).toEqual(first.candidate);
    expect(ceiling).toHaveBeenCalledOnce();
    expect(c.quote).toHaveBeenCalledOnce();
    expect(c.observe).not.toHaveBeenCalled();
    c.observe.mockResolvedValue(undefined);
    expect(
      (
        await route(
          await request(`${path(t.id)}/authorize`, proof(first.candidate.digest)),
          env,
          config,
        )
      ).status,
    ).toBe(200);
    expect((await queued()).results).toHaveLength(1);
  });
  it('uses the composed runtime ceiling, not a browser default or an unbounded fee', async () => {
    const t = await start(),
      settings = runtimeFixture(f.pin);
    const observe = vi
      .spyOn(runtimeFinality, 'requireFreshCreationDeployment')
      .mockResolvedValue(undefined);
    const runtime = createWalletRuntime({ ...env, ...settings.bindings }, config, settings.catalog);
    const result = await runtime.creationOperation(await request(path(t.id), {}), env, config);
    expect(result.status).toBe(200);
    const preview = parseCreationPreview(await result.json(), t.consent);
    expect(preview.terms.maximumGasCharge).toBe(preview.candidate.maximumEntryPointCharge);
    expect(preview.terms.maximumGasCharge).toBe(gas().maximumGasCharge);
    expect(observe).toHaveBeenCalledOnce();
    expect((await queued()).results).toHaveLength(0);
  });
  it.each([0n, -1n, 1n << 256n])(
    'refuses invalid automatic ceiling %s without provider observation or persistence',
    async (ceiling) => {
      const t = await start(),
        c = candidate();
      const route = createCreationOperationRoute({
        ...c.deps,
        automaticGasCap: async () => ceiling,
      });
      expect((await route(await request(path(t.id), {}), env, config)).status).toBe(503);
      expect(c.observe).not.toHaveBeenCalled();
      expect(c.quote).not.toHaveBeenCalled();
      expect(await count()).toBe(0);
    },
  );
  it('keeps automatic pricing closed when not configured or when it exceeds the admitted ceiling', async () => {
    const t = await start(),
      c = candidate();
    expect((await c.run(await request(path(t.id), {}), env, config)).status).toBe(503);
    const route = createCreationOperationRoute({ ...c.deps, automaticGasCap: async () => 1n });
    const result = await route(await request(path(t.id), {}), env, config);
    expect(result.status).toBe(503);
    expect(await result.json()).toEqual({ error_code: 'CREATION_UNAVAILABLE' });
    expect(await count()).toBe(0);
    expect((await queued()).results).toHaveLength(0);
  });
  it('requires owner consent before automatic pricing and rejects added caller-selected terms', async () => {
    const t = await start(false),
      c = candidate(),
      ceiling = vi.fn(async () => gas().maximumGasCharge);
    const route = createCreationOperationRoute({ ...c.deps, automaticGasCap: ceiling });
    expect((await route(await request(path(t.id), {}), env, config)).status).toBe(409);
    const unauth = await request(path(t.id), {});
    unauth.headers.delete('Authorization');
    expect((await route(unauth, env, config)).status).toBe(401);
    expect(
      (await route(await request(path(t.id), { paymaster: 'injected' }), env, config)).status,
    ).toBe(400);
    expect(ceiling).not.toHaveBeenCalled();
    expect(c.observe).not.toHaveBeenCalled();
    expect(await count()).toBe(0);
  });
  it('mounts in the replacement entrypoint but keeps the unprovisioned release closed', async () => {
    const id = createResourceId('operation');
    expect((await exports.default.fetch(await request(path(id), cap()))).status).toBe(503);
    expect(
      await (await creationOperationRoute(await request(path(id), cap()), env, config)).json(),
    ).toEqual({ error_code: 'ACCOUNT_VERSION_UNAVAILABLE' });
    expect(await count()).toBe(0);
  });
  it('prepares, recomputes client bytes, authorizes and restores the same operation with one outbox', async () => {
    const t = await start(),
      c = candidate(),
      response = await c.run(await request(path(t.id), cap()), env, config);
    expect(response.status).toBe(200);
    expect(response.headers.get('CDN-Cache-Control')).toBe('no-store');
    const preview = parseCreationPreview(await response.json(), t.consent);
    expect(preview.receipt).toMatchObject({
      state: 'prepared',
      delivery_state: 'not_requested',
      receive_enabled: false,
      deployment_assessment: 'not_assessed',
    });
    expect(preview.candidate.operation).toMatchObject({ nonce: 0n, signature: '0x' });
    const assertion = proof(preview.candidate.digest);
    for (let i = 0; i < 3; i++) {
      const result = await c.run(await request(`${path(t.id)}/authorize`, assertion), env, config);
      expect(result.status).toBe(200);
      expect(await result.json()).toMatchObject({
        state: 'authorized',
        delivery_state: 'pending',
        deployment_assessment: 'not_assessed',
      });
    }
    const read = await c.run(await request(path(t.id), null, 'GET'), env, config),
      raw = await read.json();
    expect(parseCreationPreview(raw, t.consent).receipt.state).toBe('authorized');
    for (const secret of [
      'operation_signature',
      'authorized_auth_time',
      'firebase',
      'lease',
      'document',
      'signed',
    ])
      expect(JSON.stringify(raw)).not.toContain(secret);
    expect(await count()).toBe(1);
    expect((await queued()).results).toHaveLength(1);
    expect(c.quote).toHaveBeenCalledOnce();
    expect(c.observe).toHaveBeenCalledTimes(2);
    expect(await env.WALLET_DB.prepare('SELECT count(*) AS n FROM wallets').first('n')).toBe(0);
  });

  it('persists sponsorship before user consent and restores the exact sponsored bytes on retry', async () => {
    const t = await start(),
      c = candidate();
    const sponsor = {
      terms: (after: number, until: number) => ({
        address: `0x${'12'.repeat(20)}` as const,
        verificationGasLimit: '100000',
        postOpGasLimit: '0',
        data: sponsorshipData(after, until, `0x${'ab'.repeat(65)}`),
      }),
      authorize: vi.fn(async (_operation: unknown, after: number, until: number) =>
        sponsor.terms(after, until),
      ),
    };
    const route = createCreationOperationRoute({
      ...c.deps,
      sponsor: () => sponsor,
      automaticGasCap: async () => 2350000000000000n,
    });
    const body = {};
    const response = await route(await request(path(t.id), body), env, config);
    expect(response.status).toBe(200);
    const preview = parseCreationPreview(await response.json(), t.consent);
    expect(preview.candidate.operation.paymaster).toBe(sponsor.terms(1, 2).address);
    expect(preview.candidate.maximumEntryPointCharge).toBe(2350000000000000n);
    expect(
      (
        await route(
          await request(`${path(t.id)}/authorize`, proof(preview.candidate.digest)),
          env,
          config,
        )
      ).status,
    ).toBe(200);
    const restored = parseCreationPreview(
      await (await route(await request(path(t.id), body), env, config)).json(),
      t.consent,
    );
    expect(restored.candidate.userOpHash).toBe(preview.candidate.userOpHash);
    expect(sponsor.authorize).toHaveBeenCalledOnce();
    expect((await queued()).results).toHaveLength(1);
  });
  it('does not reprice on a lost preparation response or allow a changed cap', async () => {
    const t = await start(),
      c = candidate();
    const first = parseCreationPreview(
      await (await c.run(await request(path(t.id), cap()), env, config)).json(),
      t.consent,
    );
    c.quote.mockImplementation(async () => {
      throw new Error('must not quote again');
    });
    c.observe.mockClear();
    const repeat = parseCreationPreview(
      await (await c.run(await request(path(t.id), cap()), env, config)).json(),
      t.consent,
    );
    expect(repeat.candidate).toEqual(first.candidate);
    expect(c.quote).toHaveBeenCalledOnce();
    expect(c.observe).not.toHaveBeenCalled();
    expect(
      (await c.run(await request(path(t.id), { maximum_gas_charge: '1' }), env, config)).status,
    ).toBe(409);
  });
  it('requires owner login and prior consent before probing providers', async () => {
    const t = await start(false),
      c = candidate(),
      unauth = await request(path(t.id), cap());
    unauth.headers.delete('Authorization');
    expect((await c.run(unauth, env, config)).status).toBe(401);
    expect((await c.run(await request(path(t.id), cap()), env, config)).status).toBe(409);
    await seedUser(env.WALLET_DB, testPrincipal('creation-http-b'));
    for (const method of ['GET', 'POST'])
      expect(
        (await c.run(await request(path(t.id), cap(), method, 'creation-http-b'), env, config))
          .status,
      ).toBe(404);
    expect(c.quote).not.toHaveBeenCalled();
    expect(c.observe).not.toHaveBeenCalled();
    expect(await count()).toBe(0);
  });
  it.each(['factory', 'gas_terms', 'rpc_url', 'paymaster', 'callData', 'profile_sha256'])(
    'rejects caller-selected %s before creating a candidate',
    async (field) => {
      const t = await start(),
        c = candidate();
      expect(
        (await c.run(await request(path(t.id), { ...cap(), [field]: 'injected' }), env, config))
          .status,
      ).toBe(400);
      expect(c.quote).not.toHaveBeenCalled();
      expect(await count()).toBe(0);
    },
  );
  it('rejects malformed amounts, gas exceeding the cap, and a provider changing the cap', async () => {
    const t = await start(),
      c = candidate();
    for (const maximum_gas_charge of ['0', '-1', '01', '1e4', ' 1', 10, (1n << 256n).toString()]) {
      expect(
        (await c.run(await request(path(t.id), { maximum_gas_charge }), env, config)).status,
      ).toBe(400);
    }
    expect(c.quote).not.toHaveBeenCalled();
    const low = await c.run(await request(path(t.id), { maximum_gas_charge: '1' }), env, config);
    expect(low.status).toBe(422);
    expect(await low.json()).toEqual({ error_code: 'CREATION_CAP_TOO_LOW' });
    c.quote.mockImplementation(async () => gas(gas().maximumGasCharge + 1n));
    expect((await c.run(await request(path(t.id), cap()), env, config)).status).toBe(503);
    expect(await count()).toBe(0);
  });
  it('refuses a new authorization without fresh observation, but restores an accepted one without RPC', async () => {
    const t = await start(),
      c = candidate();
    const p = parseCreationPreview(
        await (await c.run(await request(path(t.id), cap()), env, config)).json(),
        t.consent,
      ),
      signed = proof(p.candidate.digest);
    c.observe.mockImplementation(async () => {
      throw new Error('RPC unavailable');
    });
    expect(
      (await c.run(await request(`${path(t.id)}/authorize`, signed), env, config)).status,
    ).toBe(503);
    expect((await queued()).results).toHaveLength(0);
    c.observe.mockResolvedValue(undefined);
    expect(
      (await c.run(await request(`${path(t.id)}/authorize`, signed), env, config)).status,
    ).toBe(200);
    const before = await queued();
    c.observe.mockImplementation(async () => {
      throw new Error('RPC unavailable');
    });
    vi.spyOn(Date, 'now').mockReturnValue((t.consent.preparation.valid_until + 1) * 1000);
    expect(
      (await c.run(await request(`${path(t.id)}/authorize`, signed), env, config)).status,
    ).toBe(200);
    const restored = await c.run(await request(path(t.id), null, 'GET'), env, {
      ...config,
      wallet_enabled: [],
    });
    expect(parseCreationPreview(await restored.json(), t.consent).receipt).toMatchObject({
      state: 'authorized',
      authorization_expired: true,
    });
    expect((await queued()).results).toEqual(before.results);
  });
  it('the consent signature, wrong scope, unverified user and other key cannot sign this operation', async () => {
    const t = await start(),
      c = candidate();
    const p = parseCreationPreview(
      await (await c.run(await request(path(t.id), cap()), env, config)).json(),
      t.consent,
    );
    const other = initializationFixture().assertion(p.candidate.digest);
    const badKey = {
      authenticator_data: Buffer.from(other.authenticatorData).toString('base64url'),
      client_data: Buffer.from(other.clientDataJSON).toString('base64url'),
      signature: Buffer.from(other.signatureDER).toString('base64url'),
    };
    for (const assertion of [
      proof(t.consent.preparation.approval_digest),
      proof(p.candidate.digest, { flags: 1 }),
      proof(p.candidate.digest, { origin: 'https://other.gatopago.com' }),
      badKey,
    ]) {
      expect(
        (await c.run(await request(`${path(t.id)}/authorize`, assertion), env, config)).status,
      ).toBe(400);
    }
    expect((await queued()).results).toHaveLength(0);
  });
  it('revocation during estimation prevents preparation', async () => {
    const t = await start(),
      c = candidate();
    c.quote.mockImplementation(async () => {
      await env.WALLET_DB.prepare('UPDATE users SET disabled_at = ? WHERE id = ?')
        .bind(now(), t.user_id)
        .run();
      return gas();
    });
    expect((await c.run(await request(path(t.id), cap()), env, config)).status).toBe(401);
    expect(await count()).toBe(0);
  });
  it('an aborted in-flight estimate cannot later create an operation', async () => {
    const t = await start(),
      c = candidate(),
      controller = new AbortController();
    let release!: (value: ReturnType<typeof gas>) => void, entered!: () => void;
    const quoting = new Promise<void>((resolve) => {
      entered = resolve;
    });
    c.quote.mockImplementation(
      () =>
        new Promise((resolve) => {
          release = resolve;
          entered();
        }),
    );
    const pending = c.run(
      await request(path(t.id), cap(), 'POST', 'creation-http-a', controller.signal),
      env,
      config,
    );
    await quoting;
    controller.abort();
    expect((await pending).status).toBe(503);
    release(gas());
    await Promise.resolve();
    expect(await count()).toBe(0);
  });
  it('rolls back on outbox failure and recovers through an explicit exact retry', async () => {
    const t = await start(),
      c = candidate(),
      p = parseCreationPreview(
        await (await c.run(await request(path(t.id), cap()), env, config)).json(),
        t.consent,
      );
    await env.WALLET_DB.exec(
      `CREATE TRIGGER creation_http_outbox_fail BEFORE INSERT ON account_creation_outbox BEGIN SELECT RAISE(ABORT, 'test'); END;`,
    );
    const signed = proof(p.candidate.digest);
    expect(
      (await c.run(await request(`${path(t.id)}/authorize`, signed), env, config)).status,
    ).toBe(503);
    expect((await queued()).results).toHaveLength(0);
    await env.WALLET_DB.exec('DROP TRIGGER creation_http_outbox_fail;');
    expect(
      (await c.run(await request(`${path(t.id)}/authorize`, signed), env, config)).status,
    ).toBe(200);
  });
  it('does not expose corrupted proofs or accept expired unsigned operations', async () => {
    const t = await start(),
      c = candidate(),
      p = parseCreationPreview(
        await (await c.run(await request(path(t.id), cap()), env, config)).json(),
        t.consent,
      );
    vi.spyOn(Date, 'now').mockReturnValue(t.consent.preparation.valid_until * 1000);
    expect(
      (
        await c.run(
          await request(`${path(t.id)}/authorize`, proof(p.candidate.digest)),
          env,
          config,
        )
      ).status,
    ).toBe(410);
    expect((await c.run(await request(path(t.id), null, 'GET'), env, config)).status).toBe(200);
    await env.WALLET_DB.prepare(
      'UPDATE account_initializations SET assertion_body = ? WHERE id = ?',
    )
      .bind('{}', t.id)
      .run();
    expect((await c.run(await request(path(t.id), null, 'GET'), env, config)).status).toBe(503);
  });
  it('enforces origin, release, network, methods, query and size boundaries', async () => {
    const t = await start(),
      c = candidate(),
      req = await request(path(t.id), cap());
    req.headers.set('Origin', 'https://other.test');
    expect((await c.run(req, env, config)).status).toBe(403);
    expect(
      (await c.run(await request(path(t.id), cap()), env, { ...config, wallet_enabled: [] }))
        .status,
    ).toBe(503);
    expect((await c.run(await request(`${path(t.id)}?rpc=other`, cap()), env, config)).status).toBe(
      404,
    );
    expect(
      (await c.run(await request(`${path(t.id)}/authorize`, null, 'GET'), env, config)).status,
    ).toBe(405);
    expect(
      (await c.run(await request(path(t.id), { padding: 'a'.repeat(9000) }), env, config)).status,
    ).toBe(413);
    const preflight = await request(path(t.id), null, 'OPTIONS');
    preflight.headers.set('Access-Control-Request-Method', 'GET');
    preflight.headers.set('Access-Control-Request-Headers', 'authorization');
    expect((await c.run(preflight, env, config)).status).toBe(200);
    preflight.headers.set('Access-Control-Request-Headers', 'x-provider');
    expect((await c.run(preflight, env, config)).status).toBe(403);
    expect(c.quote).not.toHaveBeenCalled();
    expect(await count()).toBe(0);
  });
});
