import { testPrincipal } from './principal.fixture';
import { env } from 'cloudflare:workers';
import { applyD1Migrations } from 'cloudflare:test';
import { beforeAll, beforeEach, expect, it, vi } from 'vitest';
import { getAddress, keccak256, recoverMessageAddress, slice, type Hex } from 'viem';
import { generatePrivateKey, privateKeyToAccount } from 'viem/accounts';
import { paymasterFields, paymasterSponsorDigest } from '@gatopago/shared/v3/paymaster';
import { createGasSponsor, type SponsorPolicy } from '../src/sponsorship/service';

const chain = vi.hoisted(() => ({ signer: '', ep: '', code: '0x6000', cap: 10000n, deposit: 10000n }));
vi.mock('viem', async (original) => ({ ...await original<typeof import('viem')>(), createPublicClient: () => ({
  getChainId: async () => 421614, getBlock: async () => ({ number: 1n }), getCode: async () => chain.code,
  readContract: async ({ functionName }: { functionName: string }) => ({ ENTRY_POINT: chain.ep, sponsorSigner: chain.signer,
    maxSponsoredGasCost: chain.cap, getDeposit: chain.deposit })[functionName],
}) }));
beforeAll(async () => { await applyD1Migrations(env.WALLET_DB, env.V3_TEST_MIGRATIONS); });
beforeEach(async () => { chain.cap = 10000n; chain.deposit = 10000n; chain.code = '0x6000'; await env.WALLET_DB.exec('DELETE FROM sponsorship_reservations; DELETE FROM users;');
  await env.WALLET_DB.prepare("INSERT INTO users(id,environment,created_at) VALUES (?,'staging',?)")
    .bind(testPrincipal('alice').userId, Math.floor(Date.now() / 1000)).run();
});
function fixture() {
  const key = generatePrivateKey(), signer = privateKeyToAccount(key), now = Math.floor(Date.now() / 1000);
  const ep = getAddress(`0x${'ab'.repeat(20)}`), address = getAddress(`0x${'cd'.repeat(20)}`);
  chain.signer = signer.address; chain.ep = ep;
  const policy: SponsorPolicy = { address, codeHash: keccak256('0x6000'), signer: signer.address, verificationGasLimit: '100', postOpGasLimit: '0',
    maximumCostWei: '10000', dailyGwei: 10, userDailyGwei: 2, userDailyOperations: 2 };
  const identity = testPrincipal('alice', { environment: 'staging', authTime: now, expiresAt: now + 300 });
  const operation = { sender: getAddress(`0x${'ef'.repeat(20)}`), nonce: 0n, callData: '0x1234' as Hex, signature: '0x' as Hex,
    verificationGasLimit: 100n, callGasLimit: 100n, preVerificationGas: 100n, maxFeePerGas: 2n, maxPriorityFeePerGas: 0n };
  const sponsor = createGasSponsor(env.WALLET_DB, identity, policy, key, 421614n, ep, ['https://rpc-a.invalid', 'https://rpc-b.invalid'], AbortSignal.timeout(5000));
  return { sponsor, now, signer, operation };
}
it('signs exact operation terms after reserving, retries once, and never exposes a key', async () => {
  const f = fixture(), first = await f.sponsor.authorize(f.operation, f.now, f.now + 60);
  expect(await f.sponsor.authorize(f.operation, f.now, f.now + 60)).toEqual(first);
  const op = { ...f.operation, ...paymasterFields(first) }, digest = paymasterSponsorDigest(421614n, op);
  expect(await recoverMessageAddress({ message: { raw: digest }, signature: slice(first.data, 12) })).toBe(f.signer.address);
  expect(BigInt(slice(first.data, 0, 6))).toBe(BigInt(f.now - 1));
  expect(await env.WALLET_DB.prepare('SELECT COUNT(*) AS n FROM sponsorship_reservations').first('n')).toBe(1);
  expect(await env.WALLET_DB.prepare('SELECT userop_hash FROM sponsorship_reservations').first('userop_hash')).toMatch(/^0x[0-9a-f]{64}$/);
});
it.each(['code', 'signer', 'entrypoint', 'cap', 'deposit'] as const)('refuses %s mismatch before issuing sponsorship', async fault => {
  const f = fixture();
  if (fault === 'code') chain.code = '0x6001';
  if (fault === 'signer') chain.signer = chain.ep;
  if (fault === 'entrypoint') chain.ep = chain.signer;
  if (fault === 'cap') chain.cap = 0n;
  if (fault === 'deposit') chain.deposit = 0n;
  await expect(f.sponsor.authorize(f.operation, f.now, f.now + 60)).rejects.toThrow('SPONSOR_CHAIN_UNAVAILABLE');
  expect(await env.WALLET_DB.prepare('SELECT COUNT(*) AS n FROM sponsorship_reservations').first('n')).toBe(0);
});
