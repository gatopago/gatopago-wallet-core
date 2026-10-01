import { afterEach, beforeEach, describe, expect, it, vi } from 'vitest';
import { toHex } from 'viem';
import { createResourceId } from '@gatopago/shared/v3/primitives';
import type { FinalityAssessment } from '@gatopago/shared/v3/finality';
import { inspectOwnedWalletBalances, type BalanceProfile } from '../src/portfolio/balances';
import { WalletAccessError, type WalletRepository } from '../src/accounts/repository';
import { inspectionScenario } from '@gatopago/test-fixtures/v3-inspection';
import { finalityPin, finalityPolicyFixture } from '@gatopago/test-fixtures/v3-finality';

const now = 1_800_000_000;
beforeEach(() => { vi.spyOn(Date, 'now').mockReturnValue(now * 1000); });
afterEach(() => { vi.unstubAllGlobals(); vi.restoreAllMocks(); });
function fixture() {
 const f = inspectionScenario();
 const walletId = createResourceId('wallet'), accountId = createResourceId('walletAccount');
 const owned: Awaited<ReturnType<WalletRepository['ownedAccount']>> = {
  id: accountId, wallet_id: walletId, network_id: f.manifest.network_id,
  generation: 3, deployment_state: 'active', spend_readiness: 'not_assessed', receive_enabled: false,
  address: f.account, account_id: f.state.observation.accountId, initial_security_commitment: f.input.initialSecurityCommitment,
  user_salt_commitment: f.input.userSaltCommitment, deployment_manifest_sha256: f.input.expectedDigest,
 };
 const repository = { ownedAccount: vi.fn<WalletRepository['ownedAccount']>(async () => owned) };
 const b = (n: number) => ({ number: toHex(n), hash: n === 0 ? f.manifest.genesis_hash : toHex(n + 256, { size: 32 }),
  timestamp: toHex(n === 0 ? 0 : now - (120 - n)) });
 const target = (n: number) => ({ block_number: String(n), block_hash: b(n).hash, block_timestamp: String(now - (120 - n)) });
 const pin = finalityPin(finalityPolicyFixture(f.manifest, now));
 const source: FinalityAssessment = { schema_version: 1, status: 'finalized', policy_sha256: pin.digest,
  mechanism: 'op_stack_l1_data_finalized', network_id: f.manifest.network_id, genesis_hash: f.manifest.genesis_hash,
  target: target(100), checkpoint: target(110), assessed_at: now, expires_at: now + 30 };
 const profile: BalanceProfile = { document: f.input.document, digest: f.input.expectedDigest, finalityPolicy: pin, finalityEvidence: source,
  providers: [{ operatorId: 'provider-a', url: 'https://a.example/rpc' }, { operatorId: 'provider-b', url: 'https://b.example/rpc' }],
  assetIds: ['eip155:84532/slip44:60'], assetDisplay: { 'eip155:84532/slip44:60': { symbol: 'ETH', decimals: 18 } } };
 const fetcher = vi.fn(async (_url: RequestInfo | URL, init?: RequestInit) => {
  const call = JSON.parse(String(init?.body)) as { id: number; method: string; params: unknown[] };
  let result: unknown;
  if (call.method === 'eth_chainId') result = toHex(84532);
  else if (call.method === 'eth_getBlockByNumber') {
   const tag = String(call.params[0]); result = b(tag === 'latest' ? 120 : tag === 'finalized' ? 110 : Number(BigInt(tag)));
  } else if (call.method === 'eth_getBalance') {
   expect(call.params[0]).toBe(f.account);
   expect(call.params[1]).toEqual({ blockHash: b(110).hash, requireCanonical: true }); result = '0x123';
  } else throw new Error('Unexpected RPC');
  return Response.json({ jsonrpc: '2.0', id: call.id, result });
 });
 vi.stubGlobal('fetch', fetcher);
 const run = () => inspectOwnedWalletBalances(repository, walletId, accountId, [profile], new AbortController().signal);
 return { f, owned, repository, profile, source, fetcher, run, walletId, accountId };
}
describe('Owned balances with expiring policy-bound finality', () => {
 it('binds the amount to the owned derived address and common finalized checkpoint', async () => {
  const f = fixture(); const result = await f.run();
  expect(result).toMatchObject({ wallet_id: f.walletId, wallet_account_id: f.accountId, finality: 'finalized',
   available_balance: 'not_assessed', spend_readiness: 'not_assessed', expires_at: now + 30,
   checkpoint: { block_number: '110' }, balances: [{ amount_atomic: '291' }] });
  expect(f.repository.ownedAccount).toHaveBeenCalledTimes(2);
 });
 it('does not send any RPC for an account that is not owned', async () => {
  const f = fixture(); f.repository.ownedAccount.mockRejectedValueOnce(new WalletAccessError('NOT_FOUND'));
  await expect(f.run()).rejects.toThrow('NOT_FOUND'); expect(f.fetcher).not.toHaveBeenCalled();
 });
 it('discards balances when ownership or the session is revoked during the read', async () => {
  const f = fixture(); f.repository.ownedAccount.mockResolvedValueOnce(f.owned).mockRejectedValueOnce(new WalletAccessError('UNAUTHENTICATED'));
  await expect(f.run()).rejects.toThrow('UNAUTHENTICATED'); expect(f.fetcher).toHaveBeenCalled();
 });
 it('discards a change in the account projection during the read', async () => {
  const f = fixture(); f.repository.ownedAccount.mockResolvedValueOnce(f.owned).mockResolvedValueOnce({ ...f.owned, deployment_state: 'needs_security_sync' });
  await expect(f.run()).rejects.toThrow('WALLET_DATA_INVALID');
 });
 it.each(['expired', 'pending', 'policy', 'future', 'wrong-address', 'missing-profile'] as const)('rejects %s before RPC', async (fault) => {
  const f = fixture();
  if (fault === 'expired') vi.spyOn(Date, 'now').mockReturnValue((now + 30) * 1000);
  if (fault === 'pending') Object.assign(f.source, { status: 'pending' });
  if (fault === 'policy') Object.assign(f.source, { policy_sha256: toHex(1, { size: 32 }) });
  if (fault === 'future') Object.assign(f.source, { assessed_at: now + 1, expires_at: now + 31 });
  if (fault === 'wrong-address') f.repository.ownedAccount.mockResolvedValueOnce({ ...f.owned, address: `0x${'ab'.repeat(20)}` });
  if (fault === 'missing-profile') Object.assign(f.profile, { digest: toHex(1, { size: 32 }) });
  await expect(f.run()).rejects.toThrow(); expect(f.fetcher).not.toHaveBeenCalled();
 });
 it('does not renew the original evidence after slow reads', async () => {
  const f = fixture(), reply = f.fetcher.getMockImplementation()!;
  f.fetcher.mockImplementation(async (...args) => { vi.spyOn(Date, 'now').mockReturnValue((now + 2) * 1000); return reply(...args); });
  expect((await f.run()).expires_at).toBe(now + 30);
 });
 it('discards evidence expiring while balances are fetched', async () => {
  const f = fixture(), reply = f.fetcher.getMockImplementation()!;
  f.fetcher.mockImplementation(async (...args) => { vi.spyOn(Date, 'now').mockReturnValue((now + 30) * 1000); return reply(...args); });
  await expect(f.run()).rejects.toThrow('BALANCE_FINALITY_UNUSABLE');
 });
 it('detaches trusted configuration before waiting on ownership', async () => {
  const f = fixture(); const task = f.run(); Object.assign(f.profile, { assetIds: [], document: '{}' });
  expect((await task).balances).toHaveLength(1);
 });
});
