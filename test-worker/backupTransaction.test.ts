import { env } from 'cloudflare:workers';
import { applyD1Migrations } from 'cloudflare:test';
import { afterEach, beforeAll, beforeEach, describe, expect, it, vi } from 'vitest';
import { keccak256, parseTransaction, serializeTransaction, type Hex } from 'viem';
import { generatePrivateKey, privateKeyToAccount } from 'viem/accounts';
import { broadcastBackupTransaction } from '../src/security/backupBroadcast';
import { BackupDeliveryRepository } from '../src/security/backupDelivery';
import { prepareBackupTransaction, verifyBackupTransaction } from '../src/security/backupTransaction';
import { fixtureAddress, fixtureHash } from '@gatopago/test-fixtures/v3-inspection';
import { backupScenario } from './backup.fixture';
import { cleanCreationDelivery } from './creationDelivery.fixture';

beforeAll(async () => { await applyD1Migrations(env.WALLET_DB, env.V3_TEST_MIGRATIONS); });
async function clean() {
 await env.WALLET_DB.exec(`DROP TRIGGER IF EXISTS backup_raw_fail;
  DELETE FROM account_backup_transactions; DELETE FROM account_backup_outbox;
  DELETE FROM account_backup_commits; DELETE FROM account_backups;`);
 await cleanCreationDelivery();
}
beforeEach(clean);
afterEach(async () => { vi.restoreAllMocks(); await clean(); });
const signal = () => new AbortController().signal;
// These transport unit scenarios supply synthetic fresh evidence; the coordinator
// suite separately exercises the real pinned, two-provider security inspection.
const freshEvidence = async () => Math.floor(Date.now() / 1000) + 30;
const row = (id: string) => env.WALLET_DB.prepare('SELECT * FROM account_backup_transactions WHERE operation_id = ?').bind(id).first();
const outbox = (id: string) => env.WALLET_DB.prepare('SELECT * FROM account_backup_outbox WHERE operation_id = ?').bind(id).first();
function fixture() {
 const operator = privateKeyToAccount(generatePrivateKey());
 const policy = { networkId: 'eip155:421614' as const, operator: operator.address,
  maxGas: 800_000n, maxFeePerGas: 10n, maxPriorityFeePerGas: 2n, maxExecutionFee: 8_000_000n };
 const terms = { nonce: 0, gas: 800_000n, maxFeePerGas: 10n, maxPriorityFeePerGas: 1n };
 const call = { account: fixtureAddress('8'), value: 0n, data: '0x12345678' as Hex };
 const prepared = prepareBackupTransaction(policy.networkId, call, policy, terms);
 return { operator, policy, terms, call, prepared };
}

describe('exact operator-funded backup envelope', () => {
 it('signs and verifies a zero-value type-2 transaction without exposing any key', async () => {
  const f = fixture(), raw = await f.operator.signTransaction(f.prepared.request);
  expect(await verifyBackupTransaction(f.prepared, raw)).toEqual({ serialized: raw, hash: keccak256(raw) });
  expect(f.prepared.request).toMatchObject({ value: 0n, chainId: 421614, nonce: 0 });
  expect(Object.isFrozen(f.prepared.request)).toBe(true);
 });
 it.each(['chain','destination','value','data','nonce','gas','fee','priority','accessList','signer','legacy','delegation'] as const)('rejects a valid signature over a different %s', async (field) => {
  const f = fixture();
  const changes = { chain: { chainId: 1 }, destination: { to: fixtureAddress('9') }, value: { value: 1n },
   data: { data: '0x87654321' as Hex }, nonce: { nonce: 1 }, gas: { gas: 800_001n }, fee: { maxFeePerGas: 11n },
   priority: { maxPriorityFeePerGas: 2n }, accessList: { accessList: [{ address: fixtureAddress('8'), storageKeys: [fixtureHash('1')] }] } };
  let raw: Hex;
  if (field === 'legacy') raw = await f.operator.signTransaction({ type: 'legacy', chainId: 421614, to: f.call.account, nonce: 0, gas: 800_000n, gasPrice: 10n, data: f.call.data });
  else if (field === 'delegation') raw = await f.operator.signTransaction({ ...f.prepared.request, type: 'eip7702', authorizationList: [] });
  else if (field === 'signer') raw = await privateKeyToAccount(generatePrivateKey()).signTransaction(f.prepared.request);
  else raw = await f.operator.signTransaction({ ...f.prepared.request, ...changes[field] });
  await expect(verifyBackupTransaction(f.prepared, raw)).rejects.toThrow('BACKUP_TRANSACTION_INVALID');
 });
 it.each(['unsigned','trailing','malformed','oversized','highS'] as const)('rejects %s bytes', async (kind) => {
  const f = fixture(), signed = await f.operator.signTransaction(f.prepared.request), parsed = parseTransaction(signed);
  const raw = kind === 'unsigned' ? f.prepared.unsigned : kind === 'trailing' ? `${signed}00`
   : kind === 'malformed' ? '0x02zz' : kind === 'oversized' ? `0x02${'00'.repeat(50_001)}`
   : serializeTransaction({ ...parsed, s: `0x${'f'.repeat(64)}` });
  await expect(verifyBackupTransaction(f.prepared, raw)).rejects.toThrow('BACKUP_TRANSACTION_INVALID');
 });
 it.each(['network','operator','nonce','gas','fee','priority','cost','value','unsafeChain'] as const)('enforces the private %s constraint', (kind) => {
  const f = fixture();
  const policy = { ...f.policy, ...(kind === 'network' ? { networkId: 'eip155:1' as const } : {}),
   ...(kind === 'operator' ? { operator: `0x${'0'.repeat(40)}` as Hex } : {}), ...(kind === 'cost' ? { maxExecutionFee: 1n } : {}) };
  const terms = { ...f.terms, ...(kind === 'nonce' ? { nonce: -1 } : {}), ...(kind === 'gas' ? { gas: 800_001n } : {}),
   ...(kind === 'fee' ? { maxFeePerGas: 11n } : {}), ...(kind === 'priority' ? { maxPriorityFeePerGas: 11n } : {}) };
  expect(() => prepareBackupTransaction(kind === 'unsafeChain' ? 'eip155:9007199254740992' : f.policy.networkId,
   { ...f.call, value: kind === 'value' ? 1n : 0n }, policy, terms)).toThrow();
 });
});

async function scenario() {
 const f = await backupScenario(), sponsor = fixture();
 async function authorize() {
  const r = f.request(), prepared = await f.repository().prepare(r, signal());
  await f.repository().authorize(r.id, f.f.assertion(prepared.proposal_hash), await f.proofs(prepared.input), signal());
  return r.id;
 }
 const repo = () => new BackupDeliveryRepository(env.WALLET_DB, f.configuration);
 const id = await authorize(), claim = await repo().claim(id);
 if (!claim) throw new Error('Expected backup lease');
 const policy = { ...sponsor.policy, networkId: claim.record.initial.prepared.profile.deployment.network_id };
 const expected = prepareBackupTransaction(policy.networkId, claim.record.signed, policy, sponsor.terms);
 const raw = await sponsor.operator.signTransaction(expected.request), hash = keccak256(raw);
 const peers = [{ operatorId: 'provider-one', url: 'https://backup-a.example/rpc' }, { operatorId: 'provider-two', url: 'https://backup-b.example/rpc' }];
 const reserve = () => repo().reserveTransaction(claim, policy, sponsor.terms);
 const begin = () => repo().beginSend(claim, policy, raw, Math.floor(Date.now() / 1000) + 30);
 const broadcast = (abort = signal()) => broadcastBackupTransaction(repo(), claim, policy, raw, peers, abort, freshEvidence);
 // Setup's chain observation is synthetic. Broadcast tests replace it only AFTER consent.
 const baseFetch = async (_url: unknown, init?: RequestInit): Promise<Response> => {
  const request = JSON.parse(String(init?.body)) as { id: number; method: string; params: unknown[] };
  const responses: Record<string, unknown> = { eth_chainId: `0x${BigInt(expected.request.chainId).toString(16)}`,
   eth_getTransactionCount: '0x0', eth_getCode: '0x', eth_getBalance: '0xffffffffff', eth_estimateGas: '0x10000' };
  if (request.method === 'eth_sendRawTransaction') {
   expect(await row(id)).toMatchObject({ serialized_transaction: raw, transaction_hash: hash });
   expect(await outbox(id)).toMatchObject({ state: 'sending', transaction_hash: hash });
   expect(request.params).toEqual([raw]);
   return Response.json({ jsonrpc: '2.0', id: request.id, result: hash });
  }
  if (!(request.method in responses)) throw new Error('Unexpected RPC method');
  return Response.json({ jsonrpc: '2.0', id: request.id, result: responses[request.method] });
 };
 const install = () => f.fetch.mockImplementation(baseFetch);
 const sent = () => f.fetch.mock.calls.filter((args) => String(args[1]?.body).includes('eth_sendRawTransaction'));
 return { ...f, ...sponsor, policy, id, claim, authorize, repo, expected, raw, hash, peers, reserve, begin, broadcast, baseFetch, install, sent };
}

describe('backup nonce, persistence and bounded broadcast', { timeout: 20_000 }, () => {
 it('reserves an immutable unsigned request before signing, without a send or success marker', async () => {
  const f = await scenario(); expect(await f.reserve()).toEqual(f.expected);
  expect(await f.reserve()).toEqual(f.expected);
  expect(await row(f.id)).toMatchObject({ nonce: 0, unsigned_transaction: f.expected.unsigned, serialized_transaction: null, transaction_hash: null });
  expect(await outbox(f.id)).toMatchObject({ state: 'pending', transaction_hash: null });
  await expect(f.repo().reserveTransaction(f.claim, f.policy, { ...f.terms, nonce: 1 })).rejects.toThrow('BACKUP_SPONSOR_RESERVATION_CONFLICT');
 });
 it('arbitrates the same sponsor nonce for two operations in D1, not process memory', async () => {
  const f = await scenario(), secondId = await f.authorize(), second = await f.repo().claim(secondId);
  if (!second) throw new Error('Expected second lease');
  const results = await Promise.all([f.reserve(), f.repo().reserveTransaction(second, f.policy, f.terms)]);
  expect(results.filter(Boolean)).toHaveLength(1);
  expect(await env.WALLET_DB.prepare('SELECT count(*) AS n FROM account_backup_transactions').first('n')).toBe(1);
 });
 it('keeps the same reservation after a lost signer response and expired lease', async () => {
  const f = await scenario(); await f.reserve(); vi.spyOn(Date, 'now').mockReturnValue(f.claim.until * 1000);
  const next = await f.repo().claim(f.id); if (!next) throw new Error('Expected resumed lease');
  expect(await f.repo().transactionRequest(next, f.policy)).toEqual(f.expected);
  expect(await f.begin()).toBe(false);
  expect(await f.repo().beginSend(next, f.policy, f.raw, Math.floor(Date.now() / 1000) + 30)).toBe(true);
  expect(await row(f.id)).toMatchObject({ transaction_hash: f.hash, nonce: 0 });
 });
 it('does not recycle the nonce automatically after unbroadcast consent expires', async () => {
  const f = await scenario(); await f.reserve(); vi.spyOn(Date, 'now').mockReturnValue(f.claim.record.state.expires * 1000);
  expect(await f.repo().claim(f.id)).toBeNull(); expect(await f.repo().transactionRequest(f.claim, f.policy)).toBeNull();
  expect(await row(f.id)).toMatchObject({ unsigned_hash: f.expected.unsignedHash, nonce: 0 });
 });
 it('cannot send without the reservation, or acknowledge an unrelated hash', async () => {
  const f = await scenario(); expect(await f.begin()).toBe(false);
  await f.reserve(); expect(await f.begin()).toBe(true);
  expect(await f.repo().accepted(f.claim, fixtureHash('f'))).toBe(false);
  expect(await f.repo().accepted(f.claim, f.hash)).toBe(true);
  expect(await outbox(f.id)).toMatchObject({ state: 'accepted', transaction_hash: f.hash });
 });
 it('rejects a mismatched raw transaction without persisting it', async () => {
  const f = await scenario(); await f.reserve();
  const wrong = await f.operator.signTransaction({ ...f.expected.request, value: 1n });
  await expect(f.repo().beginSend(f.claim, f.policy, wrong, Math.floor(Date.now() / 1000) + 30)).rejects.toThrow('BACKUP_TRANSACTION_INVALID');
  expect(await row(f.id)).toMatchObject({ serialized_transaction: null });
  expect(await outbox(f.id)).toMatchObject({ state: 'pending', transaction_hash: null });
 });
 it('rolls raw bytes back with the send marker when D1 fails', async () => {
  const f = await scenario(); await f.reserve();
  await env.WALLET_DB.exec("CREATE TRIGGER backup_raw_fail BEFORE UPDATE ON account_backup_outbox WHEN NEW.state = 'sending' BEGIN SELECT RAISE(ABORT, 'synthetic failure'); END;");
  await expect(f.begin()).rejects.toThrow(); expect(await row(f.id)).toMatchObject({ serialized_transaction: null, transaction_hash: null });
  expect(await outbox(f.id)).toMatchObject({ state: 'pending' });
  await env.WALLET_DB.exec('DROP TRIGGER backup_raw_fail;'); expect(await f.begin()).toBe(true);
 });
 it('preserves a locally known hash across a lost marker acknowledgement and worker restart', async () => {
  const f = await scenario(); await f.reserve(); await f.begin();
  // Caller loses the D1 acknowledgement: no network effect is assumed or retried.
  vi.spyOn(Date, 'now').mockReturnValue(f.claim.until * 1000);
  expect(await f.repo().claim(f.id)).toBeNull();
  expect(await f.repo().observationGrant(f.id)).toMatchObject({ transactionHash: f.hash });
  expect(await outbox(f.id)).toMatchObject({ state: 'uncertain' });
  expect(await f.begin()).toBe(false);
 });
 it('prevents database changes to nonce, bytes, hash and unsupported send markers', async () => {
  const f = await scenario(); await f.reserve();
  await expect(env.WALLET_DB.prepare('UPDATE account_backup_transactions SET nonce = 1 WHERE operation_id = ?').bind(f.id).run()).rejects.toThrow();
  await expect(env.WALLET_DB.prepare("UPDATE account_backup_outbox SET state = 'sending',send_started_at = created_at,transaction_hash = ? WHERE operation_id = ?")
   .bind(f.hash, f.id).run()).rejects.toThrow();
  await f.begin();
  await expect(env.WALLET_DB.prepare('UPDATE account_backup_transactions SET serialized_transaction = ?,transaction_hash = ? WHERE operation_id = ?')
   .bind('0x02aa', fixtureHash('a'), f.id).run()).rejects.toThrow();
 });
 it('rechecks a revoked grant after signing, before any write to the RPC', async () => {
  const f = await scenario(); await f.reserve(); f.install();
  await env.WALLET_DB.prepare('UPDATE users SET auth_not_before = ? WHERE id = ?').bind(f.principal.authTime + 1, f.session.user_id).run();
  expect(await f.broadcast()).toBe('lease_lost'); expect(f.sent()).toHaveLength(0);
  expect(await row(f.id)).toMatchObject({ serialized_transaction: null });
 });
 it('simulates with both providers, persists locally, then broadcasts exactly once', async () => {
  const f = await scenario(); await f.reserve(); f.install(); f.fetch.mockClear();
  expect(await f.broadcast()).toBe('accepted'); expect(f.sent()).toHaveLength(1);
  expect(f.fetch.mock.calls.filter((a) => String(a[1]?.body).includes('eth_estimateGas'))).toHaveLength(2);
  expect(await f.broadcast()).toBe('lease_lost'); expect(f.sent()).toHaveLength(1);
  expect((await f.repository().read(f.id)).spend_enabled).toBe(false);
 });
 it('lets only one of four concurrent senders cross the broadcast boundary', async () => {
  const f = await scenario(); await f.reserve(); f.install(); f.fetch.mockClear();
  const results = await Promise.all(Array.from({ length: 4 }, () => f.broadcast()));
  expect(results.filter((r) => r === 'accepted')).toHaveLength(1);
  expect(results.filter((r) => r === 'lease_lost')).toHaveLength(3); expect(f.sent()).toHaveLength(1);
 });
 it('checks grant revocation again after simulation and before the send marker', async () => {
  const f = await scenario(); await f.reserve(); f.install();
  f.fetch.mockImplementation(async (url, init) => {
   if (String(init?.body).includes('eth_estimateGas')) {
    await env.WALLET_DB.prepare('UPDATE users SET auth_not_before = ? WHERE id = ?').bind(f.principal.authTime + 1, f.session.user_id).run();
   }
   return f.baseFetch(url, init);
  });
  expect(await f.broadcast()).toBe('lease_lost'); expect(f.sent()).toHaveLength(0);
  expect(await row(f.id)).toMatchObject({ serialized_transaction: null });
 });
 it('does not send after a failed D1 marker, and surfaces the failure to its job runner', async () => {
  const f = await scenario(); await f.reserve(); f.install();
  await env.WALLET_DB.exec("CREATE TRIGGER backup_raw_fail BEFORE UPDATE ON account_backup_outbox WHEN NEW.state = 'sending' BEGIN SELECT RAISE(ABORT, 'synthetic failure'); END;");
  await expect(f.broadcast()).rejects.toThrow(); expect(f.sent()).toHaveLength(0);
  expect(await row(f.id)).toMatchObject({ serialized_transaction: null });
  expect(await outbox(f.id)).toMatchObject({ state: 'pending', transaction_hash: null });
 });
 it('keeps the hash and raw transaction when the post-send D1 acknowledgement fails', async () => {
  const f = await scenario(); await f.reserve(); f.install(); f.fetch.mockClear();
  await env.WALLET_DB.exec("CREATE TRIGGER backup_raw_fail BEFORE UPDATE ON account_backup_outbox WHEN NEW.state = 'accepted' BEGIN SELECT RAISE(ABORT, 'synthetic failure'); END;");
  expect(await f.broadcast()).toBe('uncertain'); expect(f.sent()).toHaveLength(1);
  expect(await row(f.id)).toMatchObject({ serialized_transaction: f.raw, transaction_hash: f.hash });
  expect(await outbox(f.id)).toMatchObject({ state: 'uncertain', transaction_hash: f.hash });
 });
 it('does not reinterpret a reduced budget or another operator as permission to reprice or resign', async () => {
  const f = await scenario(); await f.reserve();
  await expect(f.repo().transactionRequest(f.claim, { ...f.policy, maxExecutionFee: 1n })).rejects.toThrow();
  await expect(f.repo().transactionRequest(f.claim, { ...f.policy, operator: fixtureAddress('e') })).rejects.toThrow();
  expect(await row(f.id)).toMatchObject({ unsigned_transaction: f.expected.unsigned, serialized_transaction: null });
 });
 it.each(['wrongHash','rpcError','lostResponse','oversized','wrongId'] as const)('retains exact bytes/hash after %s without broadcast retry', async (failure) => {
  const f = await scenario(); await f.reserve(); f.install(); f.fetch.mockClear();
  f.fetch.mockImplementation(async (url, init) => {
   const request = JSON.parse(String(init?.body)) as { method: string; id: number };
   if (request.method !== 'eth_sendRawTransaction') return f.baseFetch(url, init);
   if (failure === 'lostResponse') throw new Error('Synthetic disconnected RPC');
   if (failure === 'oversized') return new Response('x'.repeat(16_385));
   return Response.json(failure === 'rpcError' ? { jsonrpc: '2.0', id: request.id, error: { code: -32000 } }
    : { jsonrpc: '2.0', id: failure === 'wrongId' ? 999 : request.id, result: failure === 'wrongHash' ? fixtureHash('e') : f.hash });
  });
  expect(await f.broadcast()).toBe('uncertain'); expect(f.sent()).toHaveLength(1);
  expect(await row(f.id)).toMatchObject({ serialized_transaction: f.raw, transaction_hash: f.hash });
  expect(await f.repo().observationGrant(f.id)).toMatchObject({ transactionHash: f.hash });
  expect(await f.repo().claim(f.id)).toBeNull(); expect(await f.broadcast()).toBe('lease_lost'); expect(f.sent()).toHaveLength(1);
 });
 it.each(['chain','nonce','code','balance','estimate','abort'] as const)('does not broadcast when preflight fails on %s', async (failure) => {
  const f = await scenario(); await f.reserve(); f.install(); f.fetch.mockClear();
  f.fetch.mockImplementation(async (url, init) => {
   const request = JSON.parse(String(init?.body)) as { method: string; id: number };
   const bad: Record<string, [string, unknown]> = { chain: ['eth_chainId','0x1'], nonce: ['eth_getTransactionCount','0x1'],
    code: ['eth_getCode','0xef0100'], balance: ['eth_getBalance','0x0'], estimate: ['eth_estimateGas','0xffffff'] };
   if (failure === 'abort') throw new DOMException('Synthetic abort', 'AbortError');
   if (String(url).includes('backup-b') && request.method === bad[failure][0]) return Response.json({ jsonrpc: '2.0', id: request.id, result: bad[failure][1] });
   return f.baseFetch(url, init);
  });
  expect(await f.broadcast()).toBe('deferred'); expect(f.sent()).toHaveLength(0);
  expect(await row(f.id)).toMatchObject({ serialized_transaction: null });
  expect(await outbox(f.id)).toMatchObject({ state: 'pending', lease_token: null, transaction_hash: null });
 });
 it('rejects aliases of one RPC operator and canceled calls before network I/O', async () => {
  const f = await scenario(); await f.reserve(); f.install(); f.fetch.mockClear();
  await expect(broadcastBackupTransaction(f.repo(), f.claim, f.policy, f.raw, [f.peers[0], { ...f.peers[1], operatorId: f.peers[0].operatorId }], signal(), freshEvidence)).rejects.toThrow();
  await expect(broadcastBackupTransaction(f.repo(), f.claim, f.policy, f.raw, [f.peers[0], { ...f.peers[1], url: f.peers[0].url }], signal(), freshEvidence)).rejects.toThrow();
  await expect(f.broadcast(AbortSignal.abort())).rejects.toThrow(); expect(f.fetch).not.toHaveBeenCalled();
 });
 it('requires fresh state evidence after simulation and rejects expired evidence at D1', async () => {
  const f = await scenario(); await f.reserve(); f.install();
  expect(await broadcastBackupTransaction(f.repo(), f.claim, f.policy, f.raw, f.peers, signal(), async () => {
   expect(f.fetch.mock.calls.filter((a) => String(a[1]?.body).includes('eth_estimateGas'))).toHaveLength(2);
   return Math.floor(Date.now() / 1000);
  })).toBe('deferred');
  expect(f.sent()).toHaveLength(0); expect(await row(f.id)).toMatchObject({ serialized_transaction: null });
  expect(await f.repo().beginSend(f.claim, f.policy, f.raw, NaN)).toBe(false);
 });
 it('checks evidence expiry at SQLite even if the caller clock is behind', async () => {
  const f = await scenario(); await f.reserve();
  const expired = Math.floor(Date.now() / 1000) - 1;
  vi.spyOn(Date, 'now').mockReturnValue((expired - 1) * 1000);
  expect(await f.repo().beginSend(f.claim, f.policy, f.raw, expired)).toBe(false);
  expect(await row(f.id)).toMatchObject({ serialized_transaction: null, transaction_hash: null });
  expect(await outbox(f.id)).toMatchObject({ state: 'pending', transaction_hash: null });
 });
});
