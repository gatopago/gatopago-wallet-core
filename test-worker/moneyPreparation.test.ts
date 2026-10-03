import { applyD1Migrations } from 'cloudflare:test';
import { env } from 'cloudflare:workers';
import { afterEach, beforeAll, beforeEach, describe, expect, it, vi } from 'vitest';
import * as accounts from '../src/accounts/inspection';
import * as positions from '../src/portfolio/aavePosition';
import * as nonces from '../src/transfers/transferNonce';
import { prepareOwnedMoney } from '../src/money/moneyPreparation';
import { clearMoneyTestRows,moneyOwnedFixture } from './moneyOwned.fixture';
import { seedMoneyDelivery } from './moneyDelivery.fixture';

beforeAll(() => applyD1Migrations(env.WALLET_DB,env.V3_TEST_MIGRATIONS));
beforeEach(() => clearMoneyTestRows(env.WALLET_DB));
afterEach(() => vi.restoreAllMocks());
async function fixture(kind: 'aave_supply'|'aave_withdraw'|'aave_withdraw_and_pay' = 'aave_supply') {
  const s = await moneyOwnedFixture(env.WALLET_DB,kind);
  const account = vi.spyOn(accounts,'inspectOwnedWalletAccount').mockResolvedValue(s.authority);
  const position = vi.spyOn(positions,'inspectOwnedAavePosition').mockResolvedValue(s.position);
  const nonce = vi.spyOn(nonces,'observeTransferNonce').mockResolvedValue(s.nonce);
  const run = () => prepareOwnedMoney(env.WALLET_DB,s.f.identity,s.f.walletId,s.f.accountId,s.f.request,s.f.keys.input.scope,[s.profile],new AbortController().signal);
  return { ...s,account,readPosition:position,readNonce:nonce,run };
}

describe('Fresh owner monetary preparation', () => {
  it.each(['aave_supply','aave_withdraw','aave_withdraw_and_pay'] as const)('observes %s without a signature, reservation or dispatch',async kind => {
    const s = await fixture(kind), result = await s.run();
    expect(result.candidate.request).toEqual(s.f.request);
    expect(result.review.context.budget.position_available_atomic).toBe('100000019');
    expect(result.candidate.operation.signature).toBe('0x');
    expect(result.send_enabled).toBe(false);
    expect(await env.WALLET_DB.prepare('SELECT count(*) AS n FROM money_operations').first('n')).toBe(0);
    expect(await env.WALLET_DB.prepare('SELECT count(*) AS n FROM wallet_spend_locks').first('n')).toBe(0);
    expect(await env.WALLET_DB.prepare('SELECT count(*) AS n FROM user_operation_submissions').first('n')).toBe(0);
  });
  it('rejects an existing spend before the first financial observation',async () => {
    const s = await seedMoneyDelivery(env.WALLET_DB,false);
    const read = vi.spyOn(positions,'inspectOwnedAavePosition');
    const source = { ...s.profile,finalityEvidence:{ schema_version:1 as const,status:'finalized' as const,policy_sha256:s.profile.finalityPolicy.digest,
      mechanism:s.policy.mechanism,network_id:s.f.request.network_id,genesis_hash:s.market.genesis_hash,
      target:{ block_hash:s.f.hash,block_number:s.f.context.checkpoint.block_number,block_timestamp:String(s.f.now) },
      checkpoint:{ block_hash:s.f.hash,block_number:s.f.context.checkpoint.block_number,block_timestamp:String(s.f.now) },assessed_at:s.f.now,expires_at:s.f.now+10 } };
    await expect(prepareOwnedMoney(env.WALLET_DB,s.f.identity,s.f.walletId,s.f.accountId,s.f.request,s.f.keys.input.scope,[source],new AbortController().signal)).rejects.toThrow('ACCOUNT_SPEND_BUSY');
    expect(read).not.toHaveBeenCalled();
  });
  it.each(['disabled','no-gas','pending','foreign','floor','floor-hash','unknown-security','paused','frozen','debt','checkpoint','nonce-account','nonce-stale','position-stale','rpc-failure','session-revoked','closing-floor'])(
    'refuses %s and never reserves funds',async fault => {
      const s = await fixture(); let message = 'MONEY_OBSERVATION_EXPIRED';
      if (fault === 'disabled') { s.profile.features={ ...s.profile.features,aave_supply:false }; message='MONEY_CAPABILITY_UNAVAILABLE'; }
      if (fault === 'no-gas') { s.profile.gasByKind={ ...s.profile.gasByKind,aave_supply:null }; message='MONEY_CAPABILITY_UNAVAILABLE'; }
      if (fault === 'pending') { s.profile.finalityEvidence={ ...s.evidence,status:'pending' }; message='MONEY_PROFILE_UNAVAILABLE'; }
      if (fault === 'foreign') { s.f.identity={ ...s.f.identity,userId:'usr_00000000-0000-4000-8000-000000000000' }; message='SESSION_REQUIRED'; }
      if (fault.startsWith('floor')) {
        await env.WALLET_DB.prepare('INSERT INTO wallet_balance_floors VALUES (?,?,?,?)').bind(s.f.accountId,
          fault==='floor'?(BigInt(s.block.block_number)+1n).toString():s.block.block_number,s.f.hash,s.f.now).run(); message='MONEY_BALANCE_CHECKPOINT_STALE';
      }
      if (fault === 'unknown-security') { s.authority.security.phase='initial'; message='MONEY_ACCOUNT_NOT_ACTIVE'; }
      if (fault === 'paused') { s.position.paused=true; message='MONEY_MARKET_UNAVAILABLE'; }
      if (fault === 'frozen') { s.position.frozen=true; message='MONEY_MARKET_UNAVAILABLE'; }
      if (fault === 'debt') { s.position.debt_base_atomic='1'; message='MONEY_DEBT_NOT_SUPPORTED'; }
      if (fault === 'checkpoint') { s.position.checkpoint={ ...s.block,block_hash:s.f.hash }; message='MONEY_CHECKPOINT_MISMATCH'; }
      if (fault === 'nonce-account') s.nonce.account=s.market.a_token;
      if (fault === 'nonce-stale') s.nonce.observed_at=s.f.now-31;
      if (fault === 'position-stale') s.position.expires_at=s.f.now;
      if (fault === 'rpc-failure') { s.readPosition.mockRejectedValue(new Error('RPC unavailable')); message='MONEY_OBSERVATION_UNAVAILABLE'; }
      if (fault === 'session-revoked') { s.readPosition.mockImplementation(async () => {
        await env.WALLET_DB.prepare('UPDATE users SET disabled_at=?').bind(s.f.now).run(); return s.position;
      }); message='UNAUTHENTICATED'; }
      if (fault === 'closing-floor') { s.readPosition.mockImplementation(async () => {
        await env.WALLET_DB.prepare('INSERT INTO wallet_balance_floors VALUES (?,?,?,?)').bind(s.f.accountId,(BigInt(s.block.block_number)+1n).toString(),s.f.hash,s.f.now).run(); return s.position;
      }); message='MONEY_BALANCE_CHECKPOINT_STALE'; }
      await expect(s.run()).rejects.toThrow(message);
      expect(await env.WALLET_DB.prepare('SELECT count(*) AS n FROM wallet_spend_locks').first('n')).toBe(0);
    });
});
