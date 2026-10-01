import { env } from 'cloudflare:workers';
import { applyD1Migrations } from 'cloudflare:test';
import { afterEach, beforeAll, beforeEach, describe, expect, it, vi } from 'vitest';
import { keccak256, parseTransaction, type Hex } from 'viem';
import { generatePrivateKey, privateKeyToAccount } from 'viem/accounts';
import { assessCheckpointFinality } from '@gatopago/shared/v3/finality';
import { deploymentDocumentDigest } from '@gatopago/shared/v3/deployment';
import { createResourceId, type ResourceId } from '@gatopago/shared/v3/primitives';
import { createInspectionClient } from '../src/chainInspection';
import { localBackupSigner, type BackupSigner } from '../src/security/backupSigner';
import { createBackupDeliveryProcessor } from '../src/security/processBackupDelivery';
import { createBackupProcessor } from '../src/security/processBackupJob';
import { fixtureHash } from '@gatopago/test-fixtures/v3-inspection';
import { backupScenario } from './backup.fixture';
import { backupCommitScenario } from './backupCommit.fixture';
import { cleanCreationDelivery, deliveryNow } from './creationDelivery.fixture';

beforeAll(async () => { await applyD1Migrations(env.WALLET_DB, env.V3_TEST_MIGRATIONS); });
async function clean() {
 await env.WALLET_DB.exec(`DROP TRIGGER IF EXISTS backup_processor_fail;
  DELETE FROM account_backup_observations; DELETE FROM account_backup_observation_jobs;
  DELETE FROM account_backup_transactions; DELETE FROM account_backup_outbox;
  DELETE FROM account_backup_commits; DELETE FROM account_backups;`);
 await cleanCreationDelivery();
}
beforeEach(clean);
afterEach(async () => { vi.restoreAllMocks(); await clean(); });
const signal = () => new AbortController().signal;
const stored = (id: string) => env.WALLET_DB.prepare('SELECT * FROM account_backup_outbox WHERE operation_id = ?').bind(id).first();
const transaction = (id: string) => env.WALLET_DB.prepare('SELECT * FROM account_backup_transactions WHERE operation_id = ?').bind(id).first();

/** Actual D1, P-256 consent, ephemeral sponsor ECDSA, pinned code/security inspection
 * and finality assessment. ONLY chain/provider admission and RPC responses are synthetic. */
function harness(f: Pick<Awaited<ReturnType<typeof backupScenario>>, 'configuration' | 'prepared' | 'fetch'>, id: ResourceId<'operation'>) {
 const operator = privateKeyToAccount(generatePrivateKey()), adapter = localBackupSigner(operator);
 const signer = { operator: adapter.operator, sign: vi.fn<BackupSigner['sign']>((...args) => adapter.sign(...args)) };
 const network = f.configuration.networks[0], deployment = f.prepared.profile.deployment;
 const sponsor = { networkId: deployment.network_id, operator: adapter.operator,
  maxGas: 800_000n, maxFeePerGas: 10n, maxPriorityFeePerGas: 1n, maxExecutionFee: 8_000_000n };
 const peers = network.providers.map((p, i) => ({ url: p.url, operatorId: `provider-${i}` }));
 const state = { nonce: '0x0', secondNonce: '0x0', gas: '0x10000', secondGas: '0x20000', loseSend: false };
 const originalFetch = f.fetch.getMockImplementation()!;
 f.fetch.mockImplementation(async (url, init) => {
  const request = JSON.parse(String(init?.body)) as { id: number; method: string; params: unknown[] };
  const second = String(url) === peers[1].url;
  let result: unknown;
  if (request.method === 'eth_getTransactionCount') result = second ? state.secondNonce : state.nonce;
  else if (request.method === 'eth_estimateGas') result = second ? state.secondGas : state.gas;
  else if (request.method === 'eth_getCode' && String(request.params[0]).toLowerCase() === adapter.operator) result = '0x';
  else if (request.method === 'eth_getBalance' && String(request.params[0]).toLowerCase() === adapter.operator) result = '0xffffffffff';
  else if (request.method === 'eth_sendRawTransaction') {
   const raw = request.params[0] as Hex;
   expect(await stored(id)).toMatchObject({ state: 'sending', transaction_hash: keccak256(raw) });
   expect(await transaction(id)).toMatchObject({ serialized_transaction: raw, transaction_hash: keccak256(raw) });
   if (state.loseSend) throw new Error('Synthetic lost acknowledgement');
   result = keccak256(raw);
  } else return originalFetch(url, init);
  return Response.json({ jsonrpc: '2.0', id: request.id, result });
 });
 const finality = vi.fn(async (_profile: { document: string; digest: Hex }, abort: AbortSignal) => {
  const clients = peers.map((p) => createInspectionClient(p.url, abort));
  const head = await clients[0].getBlock({ blockTag: 'finalized' });
  if (!head.hash || head.number === null) throw new Error('Synthetic checkpoint missing');
  return assessCheckpointFinality(clients, { network_id: deployment.network_id, genesis_hash: deployment.genesis_hash,
   block_hash: head.hash, block_number: String(head.number), block_timestamp: String(head.timestamp) }, network.finalityPolicy, abort);
 });
 const config = { environment: f.configuration.environment, scope: { ...f.configuration.scope }, finality,
  networks: [{ document: network.document, digest: network.digest, finalityPolicy: { ...network.finalityPolicy }, providers: peers.map((p) => ({ ...p })), sponsor, signer }] };
 const processor = createBackupDeliveryProcessor(config);
 const sends = () => f.fetch.mock.calls.filter((a) => String(a[1]?.body).includes('eth_sendRawTransaction'));
 return { operator, adapter, signer, state, config, finality, processor, sends, id, run: (abort = signal()) => processor.run(env.WALLET_DB, id, abort) };
}
async function prepareScenario() {
 const f = await backupScenario(), r = f.request(), p = await f.repository().prepare(r, signal());
 await f.repository().authorize(r.id, f.f.assertion(p.proposal_hash), await f.proofs(p.input), signal());
 return { f, h: harness(f, r.id) };
}
async function commitScenario() {
 const f = await backupCommitScenario(), id = createResourceId('operation');
 const p = await f.repository().prepareCommit(id, f.request.id, signal());
 await f.repository().authorizeCommit(id, f.f.assertion(p.commit_digest), signal());
 return { f, p, h: harness(f, id) };
}

describe('private backup coordinator', { timeout: 25_000 }, () => {
 it.each(['prepare','commit'] as const)('runner sends %s once and transfers responsibility to observation', async (kind) => {
  const { f, h } = kind === 'prepare' ? await prepareScenario() : await commitScenario();
  const original = f.fetch.getMockImplementation()!;
  f.fetch.mockImplementation(async (url, init) => {
   const request = JSON.parse(String(init?.body)) as { id: number; method: string };
   if (request.method === 'eth_getTransactionReceipt') return Response.json({ jsonrpc: '2.0', id: request.id, result: null });
   return original(url, init);
  });
  const processor = createBackupProcessor({ ...h.config, networks: h.config.networks.map((n) => ({ ...n, delivery: { sponsor: n.sponsor, signer: n.signer } })) });
  expect(await processor.run(env.WALLET_DB, h.id, signal())).toMatchObject({ state: 'ready' });
  expect(await stored(h.id)).toMatchObject({ state: 'accepted' });
  expect(h.signer.sign).toHaveBeenCalledOnce(); expect(h.sends()).toHaveLength(1);
  const observerOnly = createBackupProcessor({ ...h.config, networks: h.config.networks });
  expect(await observerOnly.run(env.WALLET_DB, h.id, signal())).toMatchObject({ state: 'ready' });
  expect(h.signer.sign).toHaveBeenCalledOnce(); expect(h.sends()).toHaveLength(1);
 });
 it('inspects, reserves the two-provider gas estimate, signs, reinspects and sends once', async () => {
  const { f, h } = await prepareScenario();
  h.signer.sign.mockImplementation(async (id, tx, abort) => {
   expect(await transaction(id)).toMatchObject({ unsigned_hash: tx.unsignedHash, nonce: 0, serialized_transaction: null });
   expect(await stored(id)).toMatchObject({ state: 'pending' });
   expect(tx.request.gas).toBe((131072n * 120n + 99n) / 100n);
   expect(Object.isFrozen(tx.request)).toBe(true);
   return h.adapter.sign(id, tx, abort);
  });
  expect(await h.run()).toBe('accepted'); expect(h.signer.sign).toHaveBeenCalledTimes(1);
  expect(h.finality).toHaveBeenCalledTimes(2); expect(h.sends()).toHaveLength(1);
  expect(await stored(h.id)).toMatchObject({ state: 'accepted' });
  expect((await f.repository().read(h.id)).spend_enabled).toBe(false);
  expect(await h.run()).toBe('not_claimed'); expect(h.sends()).toHaveLength(1);
 });
 it('four concurrent deliveries obtain one sponsor signature and one broadcast', async () => {
  const { h } = await prepareScenario();
  const results = await Promise.all(Array.from({ length: 4 }, () => h.run()));
  expect(results.filter((v) => v === 'accepted')).toHaveLength(1);
  expect(h.signer.sign).toHaveBeenCalledTimes(1); expect(h.sends()).toHaveLength(1);
 });
 it('sends the original reviewed commit even when the finalized head advances', async () => {
  const { f, h } = await commitScenario(); f.state.head = 102;
  expect(await h.run()).toBe('accepted'); expect(h.signer.sign).toHaveBeenCalledTimes(1);
  const saved = await transaction(h.id);
  const parsed = parseTransaction(saved?.serialized_transaction as Hex);
  const consent = await env.WALLET_DB.prepare('SELECT calldata_sha256 FROM account_backup_commits WHERE id = ?').bind(h.id).first();
  expect(deploymentDocumentDigest(parsed.data!)).toBe(consent?.calldata_sha256);
  expect((await stored(f.request.id))?.state).toBe('pending');
 });
 it.each(['before_sign','after_sign'] as const)('stops an admin nonce change %s', async (when) => {
  const { f, h } = await prepareScenario();
  if (when === 'before_sign') f.state.adminNonce = 1n;
  else h.signer.sign.mockImplementation(async (...args) => { const raw = await h.adapter.sign(...args); f.state.adminNonce = 1n; return raw; });
  expect(await h.run()).toBe('deferred'); expect(h.sends()).toHaveLength(0);
  expect(h.signer.sign).toHaveBeenCalledTimes(when === 'before_sign' ? 0 : 1);
  expect((await stored(h.id))?.state).toBe('pending');
 });
 it.each(['missing_proposal','changed_proposal','nonce'] as const)('does not sign a commit with %s', async (failure) => {
  const { f, h } = await commitScenario();
  if (failure === 'missing_proposal') f.state.pending = false;
  if (failure === 'changed_proposal') f.state.proposal = fixtureHash('b');
  if (failure === 'nonce') f.state.nonce = 2n;
  expect(await h.run()).toBe('deferred'); expect(h.signer.sign).not.toHaveBeenCalled(); expect(h.sends()).toHaveLength(0);
 });
 it('rechecks the originally reviewed commit checkpoint after sponsor signing', async () => {
  const { f, h } = await commitScenario();
  h.signer.sign.mockImplementation(async (...args) => {
   const raw = await h.adapter.sign(...args);
   f.state.head = 102; f.blocks.get(101)!.block_hash = fixtureHash('f'); return raw;
  });
  expect(await h.run()).toBe('deferred'); expect(h.sends()).toHaveLength(0);
  expect(await transaction(h.id)).toMatchObject({ serialized_transaction: null });
 });
 it.each(['stale','missing'] as const)('never signs with %s finality', async (failure) => {
  const { h } = await prepareScenario(), read = h.finality.getMockImplementation()!;
  h.finality.mockImplementation(async (...args) => {
   if (failure === 'missing') throw new Error('Synthetic observer unavailable');
   const result = await read(...args); return { ...result, assessed_at: deliveryNow() - 60, expires_at: deliveryNow() - 30 };
  });
  expect(await h.run()).toBe('deferred'); expect(h.signer.sign).not.toHaveBeenCalled(); expect(h.sends()).toHaveLength(0);
 });
 it.each(['nonce','gas','buffer_budget'] as const)('does not sign when sponsor admission checks fail on %s', async (failure) => {
  const { h } = await prepareScenario();
  if (failure === 'nonce') h.state.secondNonce = '0x1';
  if (failure === 'gas') h.state.secondGas = '0x0';
  if (failure === 'buffer_budget') h.state.secondGas = '0xc3500'; // 800k + buffer exceeds ceiling; no clamp.
  expect(await h.run()).toBe('deferred'); expect(h.signer.sign).not.toHaveBeenCalled();
  expect(await transaction(h.id)).toBeNull(); expect(h.sends()).toHaveLength(0);
 });
 it('uses the exact reserved nonce and fees after a sign-only response is lost', async () => {
  const { h } = await prepareScenario();
  h.signer.sign.mockImplementationOnce(async (...args) => { await h.adapter.sign(...args); throw new Error('Synthetic lost signer response'); });
  expect(await h.run()).toBe('deferred'); const reserved = await transaction(h.id);
  vi.spyOn(Date, 'now').mockReturnValue((deliveryNow() + 4) * 1000);
  h.state.secondGas = '0x10000'; // A new quote would differ; reservation must not.
  expect(await h.run()).toBe('accepted'); expect(h.signer.sign).toHaveBeenCalledTimes(2);
  expect(h.signer.sign.mock.calls[0][1].unsigned).toBe(h.signer.sign.mock.calls[1][1].unsigned);
  expect(await transaction(h.id)).toMatchObject({ unsigned_transaction: reserved?.unsigned_transaction, nonce: 0 });
 });
 it('checks DB revocation again after sponsor signing and never sends', async () => {
  const { f, h } = await prepareScenario();
  h.signer.sign.mockImplementation(async (...args) => {
   const raw = await h.adapter.sign(...args);
   await env.WALLET_DB.prepare('UPDATE users SET auth_not_before = ? WHERE id = ?').bind(f.principal.authTime + 1, f.session.user_id).run();
   return raw;
  });
  expect(await h.run()).toBe('lease_lost'); expect(h.sends()).toHaveLength(0);
 });
 it('checks DB revocation after quoting but BEFORE asking for a sponsor signature', async () => {
  const { f, h } = await prepareScenario(), transport = f.fetch.getMockImplementation()!;
  f.fetch.mockImplementation(async (url, init) => {
   const response = await transport(url, init);
   if (String(init?.body).includes('eth_estimateGas')) await env.WALLET_DB.prepare('UPDATE users SET auth_not_before = ? WHERE id = ?')
    .bind(f.principal.authTime + 1, f.session.user_id).run();
   return response;
  });
  expect(await h.run()).toBe('lease_lost'); expect(h.signer.sign).not.toHaveBeenCalled(); expect(h.sends()).toHaveLength(0);
 });
 it('does not renew evidence that expires during sponsor simulation', async () => {
  const { f, h } = await prepareScenario(), transport = f.fetch.getMockImplementation()!;
  const clock = deliveryNow(), time = vi.spyOn(Date, 'now').mockReturnValue(clock * 1000);
  f.fetch.mockImplementation(async (url, init) => {
   const response = await transport(url, init);
   if (String(init?.body).includes('eth_estimateGas')) time.mockReturnValue((clock + 31) * 1000);
   return response;
  });
  expect(await h.run()).toBe('deferred'); expect(h.signer.sign).not.toHaveBeenCalled(); expect(h.sends()).toHaveLength(0);
 });
 it('never sends when the caller cancels during signing', async () => {
  const { h } = await prepareScenario(), controller = new AbortController();
  h.signer.sign.mockImplementation(async (...args) => { const raw = await h.adapter.sign(...args); controller.abort(); return raw; });
  await expect(h.run(controller.signal)).rejects.toMatchObject({ name: 'AbortError' }); expect(h.sends()).toHaveLength(0);
  expect(await transaction(h.id)).toMatchObject({ serialized_transaction: null });
 });
 it('does not sign again if the reserved nonce changed after an interrupted signer', async () => {
  const { h } = await prepareScenario();
  h.signer.sign.mockImplementationOnce(async (...args) => { await h.adapter.sign(...args); throw new Error('Synthetic disconnect'); });
  expect(await h.run()).toBe('deferred'); const reserved = await transaction(h.id);
  vi.spyOn(Date, 'now').mockReturnValue((deliveryNow() + 4) * 1000); h.state.nonce = h.state.secondNonce = '0x1';
  expect(await h.run()).toBe('deferred'); expect(h.signer.sign).toHaveBeenCalledTimes(1);
  expect(await transaction(h.id)).toMatchObject({ unsigned_transaction: reserved?.unsigned_transaction, nonce: 0 });
 });
 it.each(['signer','network','providers','fee','duplicates'] as const)('rejects invalid private %s configuration before RPC', async (invalid) => {
  const { f, h } = await prepareScenario(); f.fetch.mockClear();
  const n = h.config.networks[0];
  if (invalid === 'signer') n.signer.operator = privateKeyToAccount(generatePrivateKey()).address;
  if (invalid === 'network') n.sponsor.networkId = 'eip155:1';
  if (invalid === 'providers') n.providers[1].operatorId = n.providers[0].operatorId;
  if (invalid === 'fee') n.sponsor.maxPriorityFeePerGas = 11n;
  if (invalid === 'duplicates') h.config.networks.push(n);
  expect(() => createBackupDeliveryProcessor(h.config)).toThrow(); expect(f.fetch).not.toHaveBeenCalled();
 });
 it('rejects a signer that returns valid bytes for another transaction', async () => {
  const { h } = await prepareScenario();
  h.signer.sign.mockImplementation(async (_id, tx) => h.operator.signTransaction({ ...tx.request, value: 1n }));
  expect(await h.run()).toBe('deferred'); expect(h.sends()).toHaveLength(0);
  expect(await transaction(h.id)).toMatchObject({ serialized_transaction: null });
 });
 it('retains uncertainty after an RPC disconnect without signing or sending again', async () => {
  const { h } = await prepareScenario(); h.state.loseSend = true;
  expect(await h.run()).toBe('uncertain'); expect(await h.run()).toBe('not_claimed');
  expect(h.signer.sign).toHaveBeenCalledTimes(1); expect(h.sends()).toHaveLength(1);
  expect((await stored(h.id))?.transaction_hash).toMatch(/^0x[0-9a-f]{64}$/);
 });
 it('surfaces send-marker D1 errors rather than treating them as safe preflight retries', async () => {
  const { h } = await prepareScenario();
  await env.WALLET_DB.exec("CREATE TRIGGER backup_processor_fail BEFORE UPDATE ON account_backup_outbox WHEN NEW.state = 'sending' BEGIN SELECT RAISE(ABORT, 'synthetic failure'); END;");
  await expect(h.run()).rejects.toThrow(); expect(h.sends()).toHaveLength(0);
  expect(await stored(h.id)).toMatchObject({ state: 'pending', transaction_hash: null });
 });
 it('pins configuration and captured signer method rather than mutable caller objects', async () => {
  const { h } = await prepareScenario();
  h.config.networks[0].sponsor.maxExecutionFee = 1n;
  h.config.networks[0].providers.length = 0;
  h.config.networks[0].signer.sign = vi.fn(async () => { throw new Error('Must not call replacement'); });
  expect(await h.run()).toBe('accepted'); expect(h.sends()).toHaveLength(1);
 });
 it('does no I/O or signing for an already-aborted job', async () => {
  const { f, h } = await prepareScenario(); f.fetch.mockClear();
  await expect(h.run(AbortSignal.abort())).rejects.toThrow();
  expect(f.fetch).not.toHaveBeenCalled(); expect(h.signer.sign).not.toHaveBeenCalled();
 });
});
