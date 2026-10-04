import { env } from 'cloudflare:workers';
import { applyD1Migrations } from 'cloudflare:test';
import { afterEach, beforeAll, beforeEach, describe, expect, it, vi } from 'vitest';
import {
  bytesToHex,
  decodeFunctionData,
  encodeFunctionResult,
  hexToBytes,
  sha256,
  stringToHex,
  toHex,
} from 'viem';
import { createResourceId } from '@gatopago/shared/v3/primitives';
import { deploymentDocumentDigest } from '@gatopago/shared/v3/deployment';
import { accountSecurityInspectionAbi } from '@gatopago/shared/v3/security-inspection';
import { initializationFixture } from '@gatopago/test-fixtures/v3-initialization';
import { refreshUserAccess } from '../src/auth/access';
import { WalletRepository } from '../src/accounts/repository';
import type { ReceivingProfiles } from '../src/accounts/profile';
import { creationProjectionScenario } from './creationProjection.fixture';
import { cleanCreationDelivery } from './creationDelivery.fixture';
import { seedUser } from './user.fixture';
import { testPrincipal } from './principal.fixture';
import { LoginRepository } from '../src/auth/login';
import { base64url } from '../src/enrollment/verification';
import { identityService } from '../src/auth/service';
import { testIdentitySigner, seedIdentityKeys } from './identity.fixture';
import { parseEnvironment } from '@gatopago/environment';
import manifests from '@gatopago/environment/environments.json';
import * as runtimeModule from '../src/runtime';
import catalog from '../src/runtime/catalog';
import { createWalletWorker } from '../src/index';
import { clientMutationHeaders } from '@gatopago/shared/v3/client-release';
import { runtimeFixture } from '../test/runtime.fixture';

const signal = () => new AbortController().signal;
const now = () => Math.floor(Date.now() / 1000);
beforeAll(() => applyD1Migrations(env.WALLET_DB, env.V3_TEST_MIGRATIONS));
beforeEach(async () => {
  await cleanCreationDelivery();
  vi.spyOn(Date, 'now').mockReturnValue(Date.now());
});
afterEach(async () => {
  vi.restoreAllMocks();
  await env.WALLET_DB.exec('DROP TRIGGER IF EXISTS access_fail_update');
  await cleanCreationDelivery();
});
const credential = (id: string) =>
  env.WALLET_DB.prepare(
    'SELECT login_enabled,access_version,revoked_at FROM webauthn_credentials WHERE id = ?',
  )
    .bind(id)
    .first();
const saved = (id: string) =>
  env.WALLET_DB.prepare('SELECT access_snapshot_json FROM users WHERE id = ?')
    .bind(id)
    .first<string>('access_snapshot_json');

async function setup() {
  const f = await creationProjectionScenario();
  expect(await f.run()).toBe('projected');
  const source = await f.journal.latest(f.id);
  if (source?.result.status !== 'observed' || source.result.finality === 'not_assessed')
    throw new Error('Missing fixture observation');
  const baseline = source.result.finality_evidence;
  let policy = structuredClone(f.prepared.policy),
    height = 100;
  const original = f.reply.getMockImplementation()!;
  const checkpoint = () => ({
    block_number: String(height),
    block_hash: height === 100 ? baseline.checkpoint!.block_hash : toHex(height, { size: 32 }),
    block_timestamp: String(now()),
  });
  f.reply.mockImplementation(async (method, params) => {
    if (method === 'eth_getBlockByNumber' && params[0] !== '0x0') {
      const block = checkpoint();
      return { number: toHex(height), hash: block.block_hash, timestamp: toHex(now()) };
    }
    if (method === 'eth_call') {
      let name;
      try {
        name = decodeFunctionData({
          abi: accountSecurityInspectionAbi,
          data: (params[0] as { data: `0x${string}` }).data,
        }).functionName;
      } catch {
        /* empty */
      }
      if (name === 'securityPolicy')
        return encodeFunctionResult({
          abi: accountSecurityInspectionAbi,
          functionName: name,
          result: { ...policy, mode: 1, signers: [...policy.signers] },
        });
    }
    return original(method, params);
  });
  const profiles = vi.fn(async () => {
    const document = JSON.stringify(f.prepared.profile.deployment),
      block = checkpoint();
    return [
      {
        document,
        digest: deploymentDocumentDigest(document),
        rpcUrls: ['https://observer-a.invalid/', 'https://observer-b.invalid/'] as const,
        verifier: f.prepared.profile.webauthn_verifier,
        finalityPolicy: f.configuration.networks[0].finalityPolicy,
        finalityEvidence: {
          ...baseline,
          assessed_at: now(),
          expires_at: now() + 30,
          target: block,
          checkpoint: block,
        },
      },
    ];
  });
  const sync = () =>
    refreshUserAccess(
      env.WALLET_DB,
      f.session.user_id,
      f.principal.environment,
      f.configuration.scope,
      profiles,
      signal(),
    );
  const advance = () => vi.spyOn(Date, 'now').mockReturnValue((now() + 31) * 1000);
  const replace = (key: `0x${string}`) => {
    advance();
    height++;
    f.state.version++;
    f.state.manifestHash = toHex(height, { size: 32 });
    policy = { ...policy, signers: [{ ...policy.signers[0], key }] };
  };
  return { ...f, sync, profiles, replace, advance };
}

describe('onchain application-access reconciliation', { timeout: 20_000 }, () => {
  it('keeps onboarding access without contacting a chain or enabling unrelated credentials', async () => {
    const principal = testPrincipal('onboarding');
    await seedUser(env.WALLET_DB, principal);
    const profiles = vi.fn();
    const result = await refreshUserAccess(
      env.WALLET_DB,
      principal.userId,
      principal.environment,
      initializationFixture().input.scope,
      profiles,
      signal(),
    );
    expect(result.expiresAt).toBe(now() + 30);
    expect(profiles).not.toHaveBeenCalled();
    expect(await saved(principal.userId)).toBeNull();
    expect(await credential(principal.credentialRef)).toMatchObject({
      login_enabled: 1,
      access_version: 1,
    });
  });
  it('enables the proven onchain passkey and reuses only unexpired evidence', async () => {
    const f = await setup();
    expect(await credential(f.credentialRef)).toMatchObject({ login_enabled: 0 });
    const result = await f.sync();
    expect(result.expiresAt).toBe(now() + 30);
    expect(await credential(f.credentialRef)).toMatchObject({
      login_enabled: 1,
      access_version: 1,
    });
    expect(await credential(f.principal.credentialRef)).toMatchObject({
      login_enabled: 0,
      access_version: 2,
    });
    const before = await saved(f.session.user_id);
    await env.WALLET_DB.exec(
      "CREATE TRIGGER access_fail_update BEFORE UPDATE ON users BEGIN SELECT RAISE(ABORT,'cached access must not write'); END",
    );
    f.profiles.mockClear();
    expect(await f.sync()).toEqual(result);
    expect(f.profiles).not.toHaveBeenCalled();
    expect(await saved(f.session.user_id)).toBe(before);
  });
  it('serves the composed identity projection during an RPC outage but keeps balances and expired access closed', async () => {
    const f = await setup();
    await f.sync();
    const settings = runtimeFixture(f.configuration.profiles[0]);
    const bindings = { ...env, ...settings.bindings };
    const worker = createWalletWorker(settings.catalog, () => settings.environment);
    const account = await env.WALLET_DB.prepare('SELECT id,wallet_id FROM wallet_accounts').first<{
      id: string;
      wallet_id: string;
    }>();
    if (!account) throw new Error('Missing projected account');
    const signer = await testIdentitySigner();
    await seedIdentityKeys(signer.keys, now());
    const request = async (suffix: string) =>
      new Request(
        `${settings.environment.api_origin}/app/v1/wallets/${account.wallet_id}/accounts/${account.id}/${suffix}`,
        {
          headers: {
            Origin: settings.environment.web_origin,
            ...clientMutationHeaders('production'),
            Authorization: `Bearer ${await signer.token({ sub: f.session.user_id, credential_ref: f.credentialRef })}`,
          },
        },
      );
    const before = await saved(f.session.user_id),
      document = JSON.stringify(f.prepared.profile.deployment);
    f.fetch.mockRejectedValue(new Error('Private provider diagnostic'));
    f.fetch.mockClear();
    const context = await worker.fetch(await request('context'), bindings);
    expect(context.status).toBe(200);
    expect(await context.json()).toMatchObject({
      deployment: { document, digest: deploymentDocumentDigest(document) },
      spend_readiness: 'not_assessed',
      receive_enabled: false,
      send_enabled: false,
    });
    expect(f.fetch).not.toHaveBeenCalled();
    const balances = await worker.fetch(await request('balances'), bindings);
    expect(balances.status).toBe(503);
    expect(await balances.json()).toEqual({ error_code: 'SERVICE_UNAVAILABLE' });
    expect(f.fetch).toHaveBeenCalled();
    f.fetch.mockClear();
    expect(await saved(f.session.user_id)).toBe(before);

    f.advance();
    const expired = await worker.fetch(await request('context'), bindings);
    expect(expired.status).toBe(503);
    expect(f.fetch).toHaveBeenCalled();
    expect(await saved(f.session.user_id)).toBe(before);
  });
  it('retains a key while any owned wallet authorizes it, including an archived wallet', async () => {
    const one = await setup(),
      firstFetch = one.fetch.getMockImplementation()!;
    const two = await setup(),
      secondFetch = two.fetch.getMockImplementation()!;
    two.replace(one.f.input.publicKey);
    const profiles: ReceivingProfiles = async (account) => {
      const first = account.address === one.prepared.account.toLowerCase();
      one.fetch.mockImplementation(first ? firstFetch : secondFetch);
      return (first ? one : two).profiles();
    };
    const sync = () =>
      refreshUserAccess(
        env.WALLET_DB,
        one.session.user_id,
        one.principal.environment,
        one.configuration.scope,
        profiles,
        signal(),
      );
    await sync();
    expect(await credential(one.credentialRef)).toMatchObject({
      login_enabled: 1,
      access_version: 1,
    });
    one.replace(initializationFixture().input.publicKey);
    await env.WALLET_DB.prepare(
      "UPDATE wallets SET status = 'archived' WHERE canonical_address = ?",
    )
      .bind(two.prepared.account.toLowerCase())
      .run();
    await sync();
    expect(await credential(one.credentialRef)).toMatchObject({
      login_enabled: 1,
      access_version: 1,
    });
    two.replace(initializationFixture().input.publicKey);
    await sync();
    expect(await credential(one.credentialRef)).toMatchObject({
      login_enabled: 0,
      access_version: 2,
    });
  });
  it('revokes a removed key, rejects old/renewed sessions and enables its authorized replacement', async () => {
    const f = await setup();
    await f.sync();
    const principal = { ...f.principal, credentialRef: f.credentialRef, expiresAt: now() + 3600 };
    expect(await new WalletRepository(env.WALLET_DB, principal).getSession()).toHaveProperty(
      'user_id',
      f.session.user_id,
    );
    const next = initializationFixture(),
      id = createResourceId('operation');
    await env.WALLET_DB.prepare(
      `INSERT INTO webauthn_credentials
      (id,user_id,rp_id,origin,credential_id,public_key,transports_json,aaguid,backup_eligible,backed_up,sign_count,response_hash,created_at)
      VALUES (?,?,?,?,?,?,'[]','00000000-0000-0000-0000-000000000000',0,0,0,?,?)`,
    )
      .bind(
        id,
        f.session.user_id,
        f.configuration.scope.rpId,
        f.configuration.scope.origin,
        id,
        next.input.publicKey,
        toHex(1, { size: 32 }),
        now(),
      )
      .run();
    f.replace(next.input.publicKey);
    await f.sync();
    expect(await credential(f.credentialRef)).toMatchObject({
      login_enabled: 0,
      access_version: 2,
    });
    expect(await credential(id)).toMatchObject({ login_enabled: 1, access_version: 1 });
    for (const accessVersion of [1, 2])
      await expect(
        new WalletRepository(env.WALLET_DB, { ...principal, accessVersion }).getSession(),
      ).rejects.toMatchObject({ code: 'UNAUTHENTICATED' });
    f.replace(f.f.input.publicKey);
    await f.sync();
    expect(await credential(f.credentialRef)).toMatchObject({
      login_enabled: 1,
      access_version: 2,
    });
    await expect(new WalletRepository(env.WALLET_DB, principal).getSession()).rejects.toMatchObject(
      { code: 'UNAUTHENTICATED' },
    );
    expect(
      await new WalletRepository(env.WALLET_DB, { ...principal, accessVersion: 2 }).getSession(),
    ).toHaveProperty('user_id', f.session.user_id);
  });
  it('never enables a locally revoked key even when it remains authorized onchain', async () => {
    const f = await setup();
    await env.WALLET_DB.prepare('UPDATE webauthn_credentials SET revoked_at = ? WHERE id = ?')
      .bind(now(), f.credentialRef)
      .run();
    await f.sync();
    expect(await credential(f.credentialRef)).toMatchObject({
      login_enabled: 0,
      revoked_at: now(),
    });
  });
  it('completes a real WebAuthn login only after verifying the enrolled key onchain', async () => {
    const f = await setup(),
      sync = vi.fn(f.sync);
    const login = new LoginRepository(env.WALLET_DB, f.configuration.scope, sync),
      attempt = await login.prepare();
    const assertion = f.f.assertion(
      bytesToHex(Buffer.from(attempt.options.challenge, 'base64url')),
    );
    const response = {
      credential_id: Buffer.from(f.credentialRef).toString('base64url'),
      authenticator_data: base64url(assertion.authenticatorData),
      client_data: base64url(assertion.clientDataJSON),
      signature: base64url(assertion.signatureDER),
      user_handle: base64url(
        hexToBytes(
          sha256(
            stringToHex(
              `GatoPago V3 WebAuthn user\n${f.configuration.scope.rpId}\n${f.session.user_id}`,
            ),
          ),
        ),
      ),
    };
    await expect(
      login.complete(attempt.request_id, { ...response, signature: base64url(new Uint8Array(64)) }),
    ).rejects.toMatchObject({ code: 'UNAUTHENTICATED' });
    expect(sync).not.toHaveBeenCalled();
    expect(await credential(f.credentialRef)).toMatchObject({ login_enabled: 0 });
    expect(await login.complete(attempt.request_id, response)).toEqual({
      userId: f.session.user_id,
      credentialRef: f.credentialRef,
      accessVersion: 1,
    });
    expect(sync).toHaveBeenCalledOnce();
    await expect(login.complete(attempt.request_id, response)).rejects.toMatchObject({
      code: 'UNAUTHENTICATED',
    });
  });
  it('enforces onchain removal and upstream outages at the private Flow session boundary', async () => {
    const f = await setup();
    await f.sync();
    const signer = await testIdentitySigner();
    await seedIdentityKeys(signer.keys, now());
    const config = parseEnvironment({
      ...manifests.production,
      status: 'provisioned',
      firebase_project_id: 'v3-runtime-test',
    });
    const request = async () =>
      new Request('https://wallet-identity.internal/session', {
        method: 'POST',
        headers: {
          Authorization: `Bearer ${await signer.token({ sub: f.session.user_id, credential_ref: f.credentialRef })}`,
          'X-GatoPago-Environment': 'production',
        },
      });
    const first = await identityService(await request(), env, () => config, f.profiles);
    expect(first.status).toBe(200);
    expect(await first.json()).toMatchObject({ expires_at: now() + 30 });
    const originalProfiles = f.profiles.getMockImplementation()!;
    f.advance();
    f.profiles.mockRejectedValue(new Error('Offline'));
    expect((await identityService(await request(), env, () => config, f.profiles)).status).toBe(
      503,
    );
    f.profiles.mockImplementation(originalProfiles);
    f.replace(initializationFixture().input.publicKey);
    expect((await identityService(await request(), env, () => config, f.profiles)).status).toBe(
      401,
    );
    expect((await identityService(await request(), env, () => config, f.profiles)).status).toBe(
      401,
    );
  });
  it('composes the default Flow identity resolver with evaluated catalog data after access evidence expires', async () => {
    const f = await setup();
    await f.sync();
    f.advance();
    const signer = await testIdentitySigner();
    await seedIdentityKeys(signer.keys, now());
    const config = parseEnvironment({
      ...manifests.production,
      firebase_project_id: 'v3-runtime-test',
    });
    const bindings = {
      ...env,
      PRIVATE_KEY: `0x${'12'.repeat(32)}`,
      WALLET_RPC_ENDPOINTS: JSON.stringify({
        arbitrum_sepolia_offchain: 'https://observer-a.invalid/',
        arbitrum_sepolia_tenderly: 'https://observer-b.invalid/',
      }),
    };
    const create = runtimeModule.createWalletRuntime;
    const composed = vi
      .spyOn(runtimeModule, 'createWalletRuntime')
      .mockImplementation((env, environment, value) => {
        expect(value).toEqual(catalog(environment));

        return { ...create(env, environment, value), receivingProfiles: f.profiles };
      });
    const request = async () =>
      new Request('https://wallet-identity.internal/session', {
        method: 'POST',
        headers: {
          Authorization: `Bearer ${await signer.token({ sub: f.session.user_id, credential_ref: f.credentialRef })}`,
          'X-GatoPago-Environment': 'production',
        },
      });
    const first = await identityService(await request(), bindings, () => config);
    expect(first.status).toBe(200);
    expect(composed).toHaveBeenCalledOnce();
    expect(await first.json()).toMatchObject({
      user_id: f.session.user_id,
      expires_at: now() + 30,
    });
    f.replace(initializationFixture().input.publicKey);
    expect((await identityService(await request(), bindings, () => config)).status).toBe(401);
  });
  it('does not renew expired evidence or revoke credentials when providers fail', async () => {
    const f = await setup();
    await f.sync();
    const before = await saved(f.session.user_id);
    f.advance();
    f.profiles.mockRejectedValue(new Error('Provider unavailable'));
    await expect(f.sync()).rejects.toThrow('Provider unavailable');
    expect(await saved(f.session.user_id)).toBe(before);
    expect(await credential(f.credentialRef)).toMatchObject({
      login_enabled: 1,
      access_version: 1,
    });
  });
  it('stops waiting on cancellation even when the profile provider ignores its signal', async () => {
    const f = await setup(),
      controller = new AbortController();
    let entered!: () => void;
    const started = new Promise<void>((resolve) => {
      entered = resolve;
    });
    const profiles = vi.fn(() => {
      entered();
      return new Promise<Awaited<ReturnType<typeof f.profiles>>>(() => {});
    });
    const work = refreshUserAccess(
      env.WALLET_DB,
      f.session.user_id,
      f.principal.environment,
      f.configuration.scope,
      profiles,
      controller.signal,
    );
    const rejected = expect(work).rejects.toThrow('Cancelled');
    await started;
    controller.abort(new Error('Cancelled'));
    await rejected;
    expect(await saved(f.session.user_id)).toBeNull();
    expect(await credential(f.credentialRef)).toMatchObject({
      login_enabled: 0,
      access_version: 1,
    });
  });
  it('rejects a different policy at the same security version without changing access', async () => {
    const f = await setup();
    f.state.version = 2n;
    await f.sync();
    const before = await saved(f.session.user_id),
      version = f.state.version;
    f.replace(initializationFixture().input.publicKey);
    f.state.version = version;
    await expect(f.sync()).rejects.toMatchObject({ code: 'IDENTITY_UNAVAILABLE' });
    expect(await saved(f.session.user_id)).toBe(before);
    expect(await credential(f.credentialRef)).toMatchObject({
      login_enabled: 1,
      access_version: 1,
    });
  });
  it('cannot overwrite a refresh that committed during its provider work', async () => {
    const f = await setup(),
      resolve = f.profiles.getMockImplementation()!;
    let winner: string | null = null;
    f.profiles.mockImplementationOnce(async () => {
      await refreshUserAccess(
        env.WALLET_DB,
        f.session.user_id,
        f.principal.environment,
        f.configuration.scope,
        resolve,
        signal(),
      );
      winner = await saved(f.session.user_id);
      return resolve();
    });
    await expect(f.sync()).rejects.toMatchObject({ code: 'IDENTITY_UNAVAILABLE' });
    expect(winner).not.toBeNull();
    expect(await saved(f.session.user_id)).toBe(winner);
    expect(await credential(f.credentialRef)).toMatchObject({
      login_enabled: 1,
      access_version: 1,
    });
    expect(await credential(f.principal.credentialRef)).toMatchObject({
      login_enabled: 0,
      access_version: 2,
    });
  });
  it('enforces session expiry using the database clock as well as the request clock', async () => {
    const time = await env.WALLET_DB.prepare('SELECT unixepoch() AS time').first<number>('time');
    if (time === null) throw new Error('Missing database clock');
    const principal = testPrincipal('clock');
    await seedUser(env.WALLET_DB, principal);
    vi.spyOn(Date, 'now').mockReturnValue((time - 60) * 1000);
    await expect(
      new WalletRepository(env.WALLET_DB, { ...principal, expiresAt: time - 1 }).getSession(),
    ).rejects.toMatchObject({ code: 'UNAUTHENTICATED' });
  });
  it('rejects a regressed finalized security version without rewriting access', async () => {
    const f = await setup();
    f.state.version = 2n;
    await f.sync();
    const before = await saved(f.session.user_id);
    f.advance();
    f.state.version = 1n;
    await expect(f.sync()).rejects.toMatchObject({ code: 'IDENTITY_UNAVAILABLE' });
    expect(await saved(f.session.user_id)).toBe(before);
  });
  it('revalidates the account set and user admission after provider work', async () => {
    const f = await setup(),
      resolve = f.profiles.getMockImplementation()!;
    f.profiles.mockImplementation(async () => {
      const result = await resolve();
      await env.WALLET_DB.prepare('UPDATE users SET disabled_at = ? WHERE id = ?')
        .bind(now(), f.session.user_id)
        .run();
      return result;
    });
    await expect(f.sync()).rejects.toMatchObject({ code: 'IDENTITY_UNAVAILABLE' });
    expect(await saved(f.session.user_id)).toBeNull();
    expect(await credential(f.credentialRef)).toMatchObject({ login_enabled: 0 });
  });
  it('rejects an account-set change racing the refresh, without partially enabling keys', async () => {
    const f = await setup(),
      resolve = f.profiles.getMockImplementation()!;
    f.profiles.mockImplementation(async () => {
      const result = await resolve();
      await env.WALLET_DB.prepare("UPDATE wallets SET status = 'archived' WHERE user_id = ?")
        .bind(f.session.user_id)
        .run();
      return result;
    });
    await expect(f.sync()).rejects.toMatchObject({ code: 'IDENTITY_UNAVAILABLE' });
    expect(await saved(f.session.user_id)).toBeNull();
    expect(await credential(f.credentialRef)).toMatchObject({ login_enabled: 0 });
  });
  it('rolls back the snapshot if credential reconciliation fails', async () => {
    const f = await setup();
    await env.WALLET_DB.exec(
      "CREATE TRIGGER access_fail_update BEFORE UPDATE OF login_enabled ON webauthn_credentials BEGIN SELECT RAISE(ABORT,'synthetic failure'); END",
    );
    await expect(f.sync()).rejects.toThrow();
    expect(await saved(f.session.user_id)).toBeNull();
    expect(await credential(f.credentialRef)).toMatchObject({ login_enabled: 0 });
  });
});
