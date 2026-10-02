import { seedUser } from './user.fixture';
import { env, exports } from 'cloudflare:workers';
import { applyD1Migrations } from 'cloudflare:test';
import { afterEach, beforeAll, beforeEach, describe, expect, it, vi } from 'vitest';
import manifests from '@gatopago/environment/environments.json';
import { parseEnvironment } from '@gatopago/environment';
import { clientMutationHeaders } from '@gatopago/shared/v3/client-release';
import { prepareBackupEnrollment } from '@gatopago/shared/v3/backup-enrollment';
import { createResourceId } from '@gatopago/shared/v3/primitives';
import { signerId } from '@gatopago/shared/v3/security-policy';
import type { WebAuthnAssertionBytes } from '@gatopago/shared/v3/webauthn';
import { createBackupRoute } from '../src/security/backupRoute';
import { fixtureHash } from '@gatopago/test-fixtures/v3-inspection';
import { initializationFixture } from '@gatopago/test-fixtures/v3-initialization';
import { backupScenario as rawBackupScenario } from './backup.fixture';
import { refreshUserAccess } from '../src/auth/access';
import { backupCommitScenario as rawCommitScenario } from './backupCommit.fixture';
import { cleanCreationDelivery, deliveryIdentity, deliveryNow } from './creationDelivery.fixture';
import { clearIdentityKeys, projectId, seedIdentityKeys, testIdentitySigner } from './identity.fixture';

const backupRoute = createBackupRoute({ profiles: [], async resolveProfiles() { throw new Error('Unexpected resolver'); } });

// HTTP now authenticates the same passkey that the synthetic wallet authorizes.
async function admitted<T extends Pick<Scenario, 'profiles' | 'prepared' | 'principal' | 'session' | 'configuration' | 'credentialRef' | 'fetch' | 'repository'>>(f: T) {
 const accessProfiles = async (...args: Parameters<Scenario['profiles']>) => (await f.profiles(...args))
  .map(profile => ({ ...profile, verifier: f.prepared.profile.webauthn_verifier }));
 await refreshUserAccess(env.WALLET_DB, f.session.user_id, f.principal.environment, f.configuration.scope, accessProfiles, new AbortController().signal);
 const principal = { ...f.principal, credentialRef: f.credentialRef };
 const repository: Scenario['repository'] = (identity = principal, profiles = f.profiles) => f.repository(identity, profiles);
 f.fetch.mockClear();
 return { ...f, principal, repository };
}
const backupScenario = async () => admitted(await rawBackupScenario());
const backupCommitScenario = async () => admitted(await rawCommitScenario());

const ROOT = '/app/v1/account-backups';
const config = parseEnvironment({ ...manifests.production, status: 'provisioned', firebase_project_id: projectId, wallet_enabled: ['eip155:84532'] });
type Scenario = Awaited<ReturnType<typeof rawBackupScenario>>;
type Route = ReturnType<typeof createBackupRoute>;
let signer: Awaited<ReturnType<typeof testIdentitySigner>>;
const assertion = (p: WebAuthnAssertionBytes) => ({ authenticator_data: Buffer.from(p.authenticatorData).toString('base64url'),
 client_data: Buffer.from(p.clientDataJSON).toString('base64url'), signature: Buffer.from(p.signatureDER).toString('base64url') });
const wire = (r: ReturnType<Scenario['request']>) => ({ request_id: r.id, initialization_id: r.initializationId, wallet_id: r.walletId,
 wallet_account_id: r.walletAccountId, next_policy: r.nextPolicy, proposal_valid_until: r.proposalValidUntil });
const account = (f: Pick<Scenario, 'prepared'>) => ({ generation: '3', contract_manifest_version: f.prepared.profile.deployment.manifest_id });
async function request(f: Pick<Scenario, 'principal' | 'prepared'>, path: string, body: unknown = null, method = 'POST', subject = f.principal.userId, signal?: AbortSignal) {
 return new Request(`${config.api_origin}${path}`, { method, signal, headers: { Origin: config.web_origin, 'Content-Type': 'application/json',
  Authorization: `Bearer ${await signer.token({ sub: subject, auth_time: f.principal.authTime, ...(subject === f.principal.userId ? { credential_ref: f.principal.credentialRef } : {}) })}`,
  ...clientMutationHeaders('production', method === 'GET' ? undefined : account(f)) }, ...(method === 'POST' ? { body: JSON.stringify(body) } : {}) });
}
function candidate(f: Pick<Scenario, 'profiles' | 'configuration' | 'prepared'>) {
 const resolver = vi.fn((...args: Parameters<Scenario['profiles']>) => f.profiles(...args));
 const deps = { profiles: f.configuration.profiles.map((p) => ({ ...p, environment: 'production' as const })),
  resolveProfiles: resolver,
  accessProfiles: async (...args: Parameters<Scenario['profiles']>) => (await f.profiles(...args))
   .map(profile => ({ ...profile, verifier: f.prepared.profile.webauthn_verifier })) };
 return { run: createBackupRoute(deps), resolver, deps };
}
const counts = async () => ({
 backups: await env.WALLET_DB.prepare('SELECT count(*) AS n FROM account_backups').first<number>('n'),
 commits: await env.WALLET_DB.prepare('SELECT count(*) AS n FROM account_backup_commits').first<number>('n'),
});
const backupRow = (id: string) => env.WALLET_DB.prepare('SELECT * FROM account_backups WHERE id = ?').bind(id).first();
const commitRow = (id: string) => env.WALLET_DB.prepare('SELECT * FROM account_backup_commits WHERE id = ?').bind(id).first();
async function prepare(f: Scenario, run: Route) {
 const r = f.request(), response = await run(await request(f, ROOT, wire(r)), env, config);
 expect(response.status).toBe(200);
 const p = await f.repository().read(r.id);
 expect(await response.json()).toEqual(p);
 return { r, p };
}
async function proofs(f: Pick<Scenario, 'proofs' | 'f'>, p: Awaited<ReturnType<ReturnType<Scenario['repository']>['read']>>) {
 const enrollments = await f.proofs(p.input);
 return { owner: assertion(f.f.assertion(p.proposal_hash)), enrollments: enrollments.map((e) => e.kind === 'ecdsa'
  ? { kind: e.kind, signer_index: e.signerIndex, signature: e.signature }
  : { kind: e.kind, signer_index: e.signerIndex, assertion: assertion(e.assertion) }) };
}
beforeAll(async () => { await applyD1Migrations(env.WALLET_DB, env.V3_TEST_MIGRATIONS); signer = await testIdentitySigner(); });
async function clean() {
 await env.WALLET_DB.exec('DELETE FROM account_backup_transactions; DELETE FROM account_backup_outbox; DELETE FROM account_backup_commits; DELETE FROM account_backups;');
 await cleanCreationDelivery();
}
// Keep cryptographic fixtures on a logical clock; expiry tests advance it explicitly.
beforeEach(async () => {
  await clean(); vi.spyOn(Date, 'now').mockReturnValue(Date.now());
  await clearIdentityKeys(); await seedIdentityKeys(signer.keys, deliveryNow());
});
afterEach(async () => { vi.restoreAllMocks(); vi.unstubAllGlobals(); await clean(); });

describe('backup HTTP boundary (actual JWT/P256/ECDSA/D1, synthetic chain only)', { timeout: 15_000 }, () => {
 it('exposes owned progress only through an authenticated no-store GET and never calls the resolver', async () => {
  const f = await backupScenario(), c = candidate(f), { r } = await prepare(f, c.run);
  const path = `${ROOT}/${r.id}/status`; c.resolver.mockClear(); f.fetch.mockClear();
  const before = await counts(), response = await c.run(await request(f, path, null, 'GET'), env, config);
  expect(response.status).toBe(200); expect(response.headers.get('CDN-Cache-Control')).toBe('no-store');
  expect(await response.json()).toMatchObject({ operation_id: r.id, consent_state: 'prepared', delivery_state: 'not_requested' });
  expect((await c.run(await request(f, path, {}), env, config)).status).toBe(405);
  const noAuth = await request(f, path, null, 'GET'); noAuth.headers.delete('Authorization');
  expect((await c.run(noAuth, env, config)).status).toBe(401);
  expect(await counts()).toEqual(before); expect(c.resolver).not.toHaveBeenCalled(); expect(f.fetch).not.toHaveBeenCalled();
 });
 it('checks the parent and owner on nested commit progress', async () => {
  const f = await backupCommitScenario(), c = candidate(f), id = createResourceId('operation');
  await f.repository().prepareCommit(id, f.request.id, new AbortController().signal);
  c.resolver.mockClear(); f.fetch.mockClear();
  expect((await c.run(await request(f, `${ROOT}/${f.request.id}/commits/${id}/status`, null, 'GET'), env, config)).status).toBe(200);
  expect((await c.run(await request(f, `${ROOT}/${createResourceId('operation')}/commits/${id}/status`, null, 'GET'), env, config)).status).toBe(404);
  const other = deliveryIdentity('status-http-other'); await seedUser(env.WALLET_DB, other);
  expect((await c.run(await request(f, `${ROOT}/${f.request.id}/commits/${id}/status`, null, 'GET', other.userId), env, config)).status).toBe(404);
  expect(c.resolver).not.toHaveBeenCalled(); expect(f.fetch).not.toHaveBeenCalled();
 });
 it('mounts every stage but admits no real release or network', async () => {
  const f = await backupScenario(), r = f.request(), id = createResourceId('operation');
  for (const path of [ROOT, `${ROOT}/${r.id}`, `${ROOT}/${r.id}/authorize`, `${ROOT}/${r.id}/commits`, `${ROOT}/${r.id}/commits/${id}`, `${ROOT}/${r.id}/commits/${id}/authorize`]) {
   expect((await exports.default.fetch(await request(f, path, {}))).status).toBe(503);
  }
  expect(await (await backupRoute(await request(f, ROOT, wire(r)), env, config)).json()).toEqual({ error_code: 'ACCOUNT_VERSION_UNAVAILABLE' });
  expect(await counts()).toEqual({ backups: 0, commits: 0 });
 });
 it('prepares and signs once, restoring public review without RPC, renewal or execution', async () => {
  const f = await backupScenario(), c = candidate(f), { r, p } = await prepare(f, c.run), signed = await proofs(f, p);
  const original = await backupRow(r.id); f.fetch.mockClear(); c.resolver.mockClear();
  expect(await (await c.run(await request(f, ROOT, wire(r)), env, config)).json()).toEqual(p);
  const read = await c.run(await request(f, `${ROOT}/${r.id}`, null, 'GET'), env, config);
  expect(read.status).toBe(200); expect(read.headers.get('CDN-Cache-Control')).toBe('no-store');
  expect(read.headers.get('Access-Control-Allow-Origin')).toBe(config.web_origin); expect(await read.json()).toEqual(p);
  expect(await backupRow(r.id)).toEqual(original); expect(f.fetch).not.toHaveBeenCalled(); expect(c.resolver).not.toHaveBeenCalled();
  const result = await c.run(await request(f, `${ROOT}/${r.id}/authorize`, signed), env, config);
  expect(result.status).toBe(200); expect(await result.json()).toMatchObject({ state: 'authorized', backup_assessment: 'not_assessed', receive_enabled: false, spend_enabled: false });
  const authorized = await backupRow(r.id); f.fetch.mockClear(); c.resolver.mockClear();
  for (let n = 0; n < 2; n++) expect((await c.run(await request(f, `${ROOT}/${r.id}/authorize`, signed), env, config)).status).toBe(200);
  const restored = await (await c.run(await request(f, `${ROOT}/${r.id}`, null, 'GET'), env, config)).json();
  for (const field of ['authorization_json', 'signatureDER', 'calldata_sha256', 'rpcUrls', 'authorized_at', 'privateKey', 'assertion_body']) expect(JSON.stringify(restored)).not.toContain(field);
  expect(await backupRow(r.id)).toEqual(authorized); expect(f.fetch).not.toHaveBeenCalled(); expect(c.resolver).not.toHaveBeenCalled();
  expect(await counts()).toEqual({ backups: 1, commits: 0 });
 });
 it('does not replace an accepted signature when two tabs confirm the same proposal', async () => {
  const f = await backupScenario(), c = candidate(f), { r, p } = await prepare(f, c.run), signed = await proofs(f, p);
  const results = await Promise.all(Array.from({ length: 3 }, async () => c.run(await request(f, `${ROOT}/${r.id}/authorize`, signed), env, config)));
  expect(results.map((r) => r.status)).toEqual([200, 200, 200]); const before = await backupRow(r.id);
  const changed = { ...signed, owner: assertion(f.f.assertion(p.proposal_hash, { count: 3 })) };
  expect((await c.run(await request(f, `${ROOT}/${r.id}/authorize`, changed), env, config)).status).toBe(409);
  expect(await backupRow(r.id)).toEqual(before); expect((await counts()).backups).toBe(1);
 });
 it('rejects a changed command under the same request id without renewing it', async () => {
  const f = await backupScenario(), c = candidate(f), { r } = await prepare(f, c.run), before = await backupRow(r.id);
  c.resolver.mockClear(); f.fetch.mockClear();
  expect((await c.run(await request(f, ROOT, { ...wire(r), proposal_valid_until: r.proposalValidUntil + 1 }), env, config)).status).toBe(409);
  expect(await backupRow(r.id)).toEqual(before); expect(c.resolver).not.toHaveBeenCalled(); expect(f.fetch).not.toHaveBeenCalled();
 });
 it('requires a verified existing session and hides all resources from another owner', async () => {
  const f = await backupScenario(), c = candidate(f), { r, p } = await prepare(f, c.run), signed = await proofs(f, p);
  const other = deliveryIdentity('backup-http-b'); await seedUser(env.WALLET_DB, other);
  const noAuth = await request(f, ROOT, wire(f.request())); noAuth.headers.delete('Authorization');
  expect((await c.run(noAuth, env, config)).status).toBe(401);
  const unverified = await request(f, ROOT, wire(f.request())); unverified.headers.set('Authorization', `Bearer ${await signer.token({ firebase: { sign_in_provider: 'google.com' } })}`);
  expect((await c.run(unverified, env, config)).status).toBe(401);
  expect((await c.run(await request(f, ROOT, wire(f.request()), 'POST', 'no-session'), env, config)).status).toBe(409);
  c.resolver.mockClear(); f.fetch.mockClear();
  for (const [path, body, method] of [[`${ROOT}/${r.id}`, null, 'GET'], [`${ROOT}/${r.id}/authorize`, signed, 'POST'], [ROOT, wire(f.request()), 'POST']] as const) {
   expect((await c.run(await request(f, path, body, method, other.userId), env, config)).status).toBe(404);
  }
  expect((await backupRow(r.id))?.authorized_at).toBeNull(); expect(await counts()).toEqual({ backups: 1, commits: 0 });
  expect(c.resolver).not.toHaveBeenCalled(); expect(f.fetch).not.toHaveBeenCalled();
 });
 it('rejects caller-selected execution, authority and extra policy fields before RPC', async () => {
  const f = await backupScenario(), c = candidate(f), r = wire(f.request());
  const bad: unknown[] = ['rpc_url', 'nonce', 'checkpoint', 'callData', 'profile_sha256', 'finality'].map((key) => ({ ...r, [key]: 'injected' }));
  bad.push({ ...r, next_policy: { ...r.next_policy, ignored: true } }, { ...r, next_policy: { ...r.next_policy, mode: 'bootstrap' } },
   { ...r, next_policy: { ...r.next_policy, signers: r.next_policy.signers.map((s) => ({ ...s, secret: 'not-accepted' })) } });
  for (const lifetime of [0, -1, '123', 2 ** 48, 1.25]) bad.push({ ...r, proposal_valid_until: lifetime });
  for (const body of bad) expect((await c.run(await request(f, ROOT, body), env, config)).status).toBe(400);
  expect(c.resolver).not.toHaveBeenCalled(); expect(f.fetch).not.toHaveBeenCalled(); expect(await counts()).toEqual({ backups: 0, commits: 0 });
 });
 it('rejects malformed, missing, unrelated or duplicated proofs before RPC', async () => {
  const f = await backupScenario(), c = candidate(f), { r, p } = await prepare(f, c.run), signed = await proofs(f, p);
  c.resolver.mockClear(); f.fetch.mockClear();
  const bodies = [{ ...signed, owner: { ...signed.owner, signature: `${signed.owner.signature}=` } }, { ...signed, enrollments: [] },
   { ...signed, enrollments: [signed.enrollments[0], signed.enrollments[0]] }, { ...signed, owner: assertion(f.f.assertion(fixtureHash('a'))) },
   { ...signed, enrollments: signed.enrollments.map((e) => ({ ...e, signer_index: 16 })) }, { ...signed, calldata: '0x' }];
  for (const body of bodies) expect((await c.run(await request(f, `${ROOT}/${r.id}/authorize`, body), env, config)).status).toBe(400);
  expect(c.resolver).not.toHaveBeenCalled(); expect(f.fetch).not.toHaveBeenCalled(); expect((await backupRow(r.id))?.authorization_json).toBeNull();
 });
 it('requires possession of an additional WebAuthn factor, not just its public descriptor', async () => {
  const f = await backupScenario(), c = candidate(f), other = initializationFixture(), r = f.request();
  r.nextPolicy = { ...r.nextPolicy, signers: [...r.nextPolicy.signers, { ...f.prepared.policy.signers[0], key: other.input.publicKey }]
   .sort((a, b) => signerId(a).localeCompare(signerId(b))) };
  expect((await c.run(await request(f, ROOT, wire(r)), env, config)).status).toBe(200);
  const p = await f.repository().read(r.id), compiled = prepareBackupEnrollment(p.input, p.valid_after), body = await proofs(f, p);
  // The default fixture signed the new factor's digest with the old passkey: reject it.
  expect((await c.run(await request(f, `${ROOT}/${r.id}/authorize`, body), env, config)).status).toBe(400);
  const valid = { ...body, enrollments: body.enrollments.map((e) => {
   if (e.kind !== 'webauthn') return e;
   const required = compiled.enrollments.find((r) => r.signerIndex === e.signer_index);
   if (!required) throw new Error('Expected WebAuthn enrollment digest');
   return { kind: e.kind, signer_index: e.signer_index, assertion: assertion(other.assertion(required.digest)) };
  }) };
  expect((await c.run(await request(f, `${ROOT}/${r.id}/authorize`, valid), env, config)).status).toBe(200);
 });
 it('validates methods, origins, paths and preflight without auth or network effects', async () => {
  const f = await backupScenario(), c = candidate(f), id = createResourceId('operation');
  for (const path of [`${ROOT}/bad`, `${ROOT}/${id}?rpc=x`, `${ROOT}/${id}/commits/bad`, `${ROOT}/`]) {
   expect((await c.run(await request(f, path, null, 'GET'), env, config)).status).toBe(404);
  }
  expect((await c.run(await request(f, ROOT, null, 'GET'), env, config)).status).toBe(405);
  expect((await c.run(await request(f, `${ROOT}/${id}`, {}, 'POST'), env, config)).status).toBe(405);
  const wrongOrigin = await request(f, ROOT, {}); wrongOrigin.headers.set('Origin', 'https://other.gatopago.com');
  expect((await c.run(wrongOrigin, env, config)).status).toBe(403);
  const options = new Request(`${config.api_origin}${ROOT}`, { method: 'OPTIONS', headers: { Origin: config.web_origin,
   'Access-Control-Request-Method': 'POST', 'Access-Control-Request-Headers': 'authorization,content-type' } });
  expect((await c.run(options, env, config)).status).toBe(200);
  options.headers.set('Access-Control-Request-Headers', 'x-arbitrary-provider'); expect((await c.run(options, env, config)).status).toBe(403);
  expect(c.resolver).not.toHaveBeenCalled(); expect(f.fetch).not.toHaveBeenCalled();
 });
 it('bounds request bodies and does not parse non-JSON or stalled input indefinitely', async () => {
  const f = await backupScenario(), c = candidate(f), oversized = await request(f, ROOT, { padding: 'x'.repeat(17_000) });
  expect((await c.run(oversized, env, config)).status).toBe(413);
  const wrongType = await request(f, ROOT, wire(f.request())); wrongType.headers.set('Content-Type', 'text/plain');
  expect((await c.run(wrongType, env, config)).status).toBe(400);
  const controller = new AbortController(), base = await request(f, ROOT, {}), stream = new ReadableStream<Uint8Array>({ start() { controller.abort(); } });
  const cancelled = new Request(base.url, { method: 'POST', headers: base.headers, signal: controller.signal, body: stream });
  expect((await c.run(cancelled, env, config)).status).toBe(503);
  expect(c.resolver).not.toHaveBeenCalled(); expect(await counts()).toEqual({ backups: 0, commits: 0 });
 });
 it('times out and cancels an unfinished body without reaching RPC or writing a preparation', async () => {
  const f = await backupScenario(), c = candidate(f), base = await request(f, ROOT, {}), cancel = vi.fn();
  const body = new ReadableStream<Uint8Array>({ start(controller) { controller.enqueue(new TextEncoder().encode('{')); }, cancel });
  const stalled = new Request(base.url, { method: 'POST', headers: base.headers, body });
  const response = await c.run(stalled, env, config);
  expect(response.status).toBe(400); expect(cancel).toHaveBeenCalledOnce();
  expect(c.resolver).not.toHaveBeenCalled(); expect(f.fetch).not.toHaveBeenCalled(); expect(await counts()).toEqual({ backups: 0, commits: 0 });
 });
 it('keeps reads available during network disablement, but rejects new monetary consent', async () => {
  const f = await backupScenario(), c = candidate(f), { r, p } = await prepare(f, c.run), disabled = { ...config, wallet_enabled: [] };
  c.resolver.mockClear(); f.fetch.mockClear();
  expect(await (await c.run(await request(f, `${ROOT}/${r.id}`, null, 'GET'), env, disabled)).json()).toEqual(p);
  expect((await c.run(await request(f, `${ROOT}/${r.id}/authorize`, await proofs(f, p)), env, disabled)).status).toBe(503);
  expect(c.resolver).not.toHaveBeenCalled(); expect(f.fetch).not.toHaveBeenCalled();
 });
 it('copies admission and binds resolver output to the owned deployment, not the creation-document digest', async () => {
  const f = await backupScenario(), c = candidate(f), original = f.profiles;
  c.deps.profiles.length = 0;
  c.resolver.mockImplementation(async (owned, signal) => (await original(owned, signal)).map((p) => ({ ...p, digest: f.configuration.profiles[0].digest })));
  expect((await c.run(await request(f, ROOT, wire(f.request())), env, config)).status).toBe(503);
  expect(f.fetch).not.toHaveBeenCalled(); expect(await counts()).toEqual({ backups: 0, commits: 0 });
  c.resolver.mockImplementation(original); expect((await c.run(await request(f, ROOT, wire(f.request())), env, config)).status).toBe(200);
 });
 it('cancels an uncooperative resolver without any later write', async () => {
  const f = await backupScenario(), c = candidate(f), controller = new AbortController();
  let complete!: () => void;
  c.resolver.mockImplementation(async (owned, signal) => { controller.abort(); await new Promise<void>((resolve) => { complete = resolve; }); return f.profiles(owned, signal); });
  expect((await c.run(await request(f, ROOT, wire(f.request()), 'POST', f.principal.userId, controller.signal), env, config)).status).toBe(503);
  complete(); expect(await counts()).toEqual({ backups: 0, commits: 0 });
  expect(f.fetch).not.toHaveBeenCalled();
 });
 it('rechecks revocation during observation and never persists a signature afterwards', async () => {
  const f = await backupScenario(), c = candidate(f), { r, p } = await prepare(f, c.run), signed = await proofs(f, p), original = f.profiles;
  c.resolver.mockImplementation(async (...args) => {
   await env.WALLET_DB.prepare('UPDATE users SET disabled_at = ? WHERE id = ?').bind(deliveryNow(), f.session.user_id).run(); return original(...args);
  });
  expect((await c.run(await request(f, `${ROOT}/${r.id}/authorize`, signed), env, config)).status).toBe(401);
  expect((await backupRow(r.id))?.authorization_json).toBeNull();
 });
});

describe('second backup confirmation over HTTP', { timeout: 15_000 }, () => {
 it('accepts a fresh commit after the first consent window elapsed, preserving the signed proposal deadline', async () => {
  const f = await backupCommitScenario(), c = candidate(f), late = f.backup.valid_until + 900;
  vi.spyOn(Date, 'now').mockReturnValue(late * 1000); f.blocks.get(101)!.block_timestamp = String(late);
  const id = createResourceId('operation'), path = `${ROOT}/${f.request.id}/commits`, original = await backupRow(f.request.id);
  expect((await c.run(await request(f, path, { request_id: id }), env, config)).status).toBe(200);
  const prepared = await commitRow(id); expect(prepared?.valid_after).toBe(late); expect(prepared?.valid_until).toBe(late + 300);
  const digest = prepared?.commit_digest; if (typeof digest !== 'string' || !/^0x[0-9a-f]{64}$/.test(digest)) throw new Error('Expected commit digest');
  expect((await c.run(await request(f, `${path}/${id}/authorize`, assertion(f.f.assertion(digest as `0x${string}`))), env, config)).status).toBe(200);
  expect(await backupRow(f.request.id)).toEqual(original);
 });
 it('prepares and signs a separate commit, with exact retries and private-proof-free reads', async () => {
  const f = await backupCommitScenario(), c = candidate(f), id = createResourceId('operation'), path = `${ROOT}/${f.request.id}/commits`;
  const result = await c.run(await request(f, path, { request_id: id }), env, config);
  expect(result.status).toBe(200); const p = await f.repository().readCommit(id); expect(await result.json()).toEqual(p);
  expect(p.commit_digest).not.toBe(f.backup.proposal_hash);
  const proof = assertion(f.f.assertion(p.commit_digest)), before = await commitRow(id); f.fetch.mockClear(); c.resolver.mockClear();
  expect(await (await c.run(await request(f, path, { request_id: id }), env, config)).json()).toEqual(p);
  expect(await (await c.run(await request(f, `${path}/${id}`, null, 'GET'), env, config)).json()).toEqual(p);
  expect(await commitRow(id)).toEqual(before); expect(c.resolver).not.toHaveBeenCalled(); expect(f.fetch).not.toHaveBeenCalled();
  expect((await c.run(await request(f, `${path}/${id}/authorize`, assertion(f.f.assertion(f.backup.proposal_hash))), env, config)).status).toBe(400);
  expect(c.resolver).not.toHaveBeenCalled();
  const signed = await c.run(await request(f, `${path}/${id}/authorize`, proof), env, config);
  expect(signed.status).toBe(200); expect(await signed.json()).toMatchObject({ state: 'authorized', receive_enabled: false, spend_enabled: false, backup_assessment: 'not_assessed' });
  const authorized = await commitRow(id); f.fetch.mockClear(); c.resolver.mockClear();
  expect((await c.run(await request(f, `${path}/${id}/authorize`, proof), env, config)).status).toBe(200);
  const restored = await (await c.run(await request(f, `${path}/${id}`, null, 'GET'), env, config)).json();
  for (const field of ['assertion_body', 'confirmation_json', 'calldata_sha256', 'signatureDER', 'rpcUrls']) expect(JSON.stringify(restored)).not.toContain(field);
  expect(await commitRow(id)).toEqual(authorized); expect(f.fetch).not.toHaveBeenCalled(); expect(c.resolver).not.toHaveBeenCalled();
  expect(await counts()).toEqual({ backups: 1, commits: 1 });
 });
 it('does not authorize or disclose a commit under another backup path or another login', async () => {
  const f = await backupCommitScenario(), c = candidate(f), id = createResourceId('operation');
  const p = await f.repository().prepareCommit(id, f.request.id, new AbortController().signal), before = await commitRow(id);
  const wrong = createResourceId('operation'), other = deliveryIdentity('foreign-commit-http'); await seedUser(env.WALLET_DB, other);
  for (const [parent, subject] of [[wrong, f.principal.userId], [f.request.id, other.userId]]) {
   const path = `${ROOT}/${parent}/commits/${id}`;
   expect((await c.run(await request(f, path, null, 'GET', subject), env, config)).status).toBe(404);
   expect((await c.run(await request(f, `${path}/authorize`, assertion(f.f.assertion(p.commit_digest)), 'POST', subject), env, config)).status).toBe(404);
  }
  expect(await commitRow(id)).toEqual(before); expect(c.resolver).not.toHaveBeenCalled();
 });
 it('never mistakes recorded consent for a pending proposal onchain', async () => {
  const f = await backupCommitScenario(), c = candidate(f); f.state.pending = false;
  const response = await c.run(await request(f, `${ROOT}/${f.request.id}/commits`, { request_id: createResourceId('operation') }), env, config);
  expect(response.status).toBe(409); expect(await response.json()).toEqual({ error_code: 'BACKUP_PENDING_MISMATCH' });
  expect((await counts()).commits).toBe(0);
 });
 it('does not report RPC failures as invalid signatures or persist a commit without fresh evidence', async () => {
  const f = await backupCommitScenario(), c = candidate(f), id = createResourceId('operation'), path = `${ROOT}/${f.request.id}/commits`;
  await c.run(await request(f, path, { request_id: id }), env, config); const p = await f.repository().readCommit(id);
  f.fetch.mockRejectedValue(new Error('Synthetic private provider error'));
  const response = await c.run(await request(f, `${path}/${id}/authorize`, assertion(f.f.assertion(p.commit_digest))), env, config);
  expect(response.status).toBe(503); expect(await response.json()).toEqual({ error_code: 'BACKUP_UNAVAILABLE' });
  expect((await commitRow(id))?.authorized_at).toBeNull();
 });
 it('keeps expired preparation readable without accepting a late signature or extending it', async () => {
  const f = await backupCommitScenario(), c = candidate(f), id = createResourceId('operation'), path = `${ROOT}/${f.request.id}/commits`;
  await c.run(await request(f, path, { request_id: id }), env, config); const p = await f.repository().readCommit(id), before = await commitRow(id);
  vi.spyOn(Date, 'now').mockReturnValue(p.valid_until * 1000); f.fetch.mockClear(); c.resolver.mockClear();
  f.blocks.get(f.state.head)!.block_timestamp = String(p.valid_until);
  expect(await (await c.run(await request(f, `${path}/${id}`, null, 'GET'), env, config)).json()).toMatchObject({ state: 'expired', valid_until: p.valid_until });
  // Expired access evidence is refreshed even when the consent itself is read-only.
  expect(f.fetch).toHaveBeenCalled(); f.fetch.mockClear();
  expect((await c.run(await request(f, path, { request_id: id }), env, config)).status).toBe(410);
  expect((await c.run(await request(f, `${path}/${id}/authorize`, assertion(f.f.assertion(p.commit_digest))), env, config)).status).toBe(410);
  expect(await commitRow(id)).toEqual(before); expect(c.resolver).not.toHaveBeenCalled(); expect(f.fetch).not.toHaveBeenCalled();
 });
});
