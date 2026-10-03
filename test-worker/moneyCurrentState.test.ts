import { applyD1Migrations } from 'cloudflare:test';
import { env } from 'cloudflare:workers';
import { afterEach,beforeAll,beforeEach,describe,expect,it,vi } from 'vitest';
import { toHex } from 'viem';
import * as finality from '@gatopago/shared/v3/finality';
import * as inspection from '../src/chainInspection';
import * as positionReader from '../src/portfolio/aavePositionObservation';
import * as nonceReader from '../src/transfers/transferNonce';
import { observeOwnedMoneyCurrent } from '../src/money/moneyCurrentState';
import { clearMoneyTestRows,moneyOwnedFixture } from './moneyOwned.fixture';

beforeAll(() => applyD1Migrations(env.WALLET_DB,env.V3_TEST_MIGRATIONS));
beforeEach(() => clearMoneyTestRows(env.WALLET_DB));
afterEach(() => vi.restoreAllMocks());
async function fixture(kind: 'aave_supply'|'aave_withdraw' = 'aave_supply') {
  const s = await moneyOwnedFixture(env.WALLET_DB,kind), height=BigInt(s.block.block_number)+100n;
  const checkpoint={block_number:height.toString(),block_hash:s.f.hash};
  const oldTag=toHex(BigInt(s.block.block_number)),tag=toHex(height);
  const old={number:oldTag,hash:s.block.block_hash,timestamp:toHex(BigInt(s.f.now))};
  const head={number:tag,hash:checkpoint.block_hash,timestamp:toHex(BigInt(s.f.now))};
  const requests=[0,1].map(index => vi.fn(async ({params}: {method:string;params:readonly unknown[]}) =>
    structuredClone(params[0]==='latest'?{ ...head,number:toHex(height+BigInt(index*2)) }:params[0]===oldTag?old:head)));
  let client=0;
  vi.spyOn(inspection,'createInspectionClient').mockImplementation(() => ({request:requests[client++]}) as unknown as ReturnType<typeof inspection.createInspectionClient>);
  const finalized=vi.spyOn(finality,'assessCheckpointFinality').mockResolvedValue(s.evidence);
  const security={...s.security,checkpoint},position={...s.position,checkpoint,finality:'not_assessed' as const},nonce={...s.nonce,checkpoint};
  const account=vi.spyOn(inspection,'inspectWalletSecurity').mockResolvedValue(security);
  const balance=vi.spyOn(positionReader,'observeAavePosition').mockResolvedValue(position);
  const sequence=vi.spyOn(nonceReader,'observeTransferNonce').mockResolvedValue(nonce);
  const controller=new AbortController();
  const run=()=>observeOwnedMoneyCurrent(env.WALLET_DB,s.f.identity,s.f.walletId,s.f.accountId,s.f.review,s.profile,controller.signal);
  return {...s,checkpoint,oldTag,tag,old,head,requests,finalized,security,position,nonce,account,balance,sequence,controller,run};
}

describe('Current-state admission preserves signed monetary authority',()=>{
  it('selects the common latest height and returns a five-second read without a dispatch',async()=>{
    const s=await fixture(),result=await s.run();
    expect(result).toMatchObject({consent_digest:s.f.candidate.digest,userop_hash:s.f.candidate.userOpHash,nonce:'0',checkpoint:s.checkpoint,send_enabled:false});
    expect(result.expires_at-result.checked_at).toBeLessThanOrEqual(5);
    expect(s.balance).toHaveBeenCalledWith({account:s.f.candidate.account,market:s.profile.market,checkpoint:s.checkpoint},s.profile.providers,expect.any(AbortSignal));
    expect(await env.WALLET_DB.prepare('SELECT count(*) AS n FROM wallet_spend_locks').first('n')).toBe(0);
  });
  it.each(['disabled','changed-gas','expired','orphaned-review','unfinalized-review','head-disagreement','head-stale','unknown-account','security-version','policy','nonce','checkpoint','paused','frozen','debt','usdc','capacity','gas','rpc-failure','floor','closing-head','owner-revoked','stale-observation'])(
    'rejects %s before any financial mutation',async fault=>{
      const s=await fixture();let message='MONEY_CURRENT_STATE_UNAVAILABLE';
      if(fault==='disabled'){s.profile.features={...s.profile.features,aave_supply:false};message='MONEY_CAPABILITY_UNAVAILABLE';}
      if(fault==='changed-gas'){s.profile.gasByKind={...s.profile.gasByKind,aave_supply:{...s.f.context.gas,callGasLimit:101n}};message='MONEY_CAPABILITY_UNAVAILABLE';}
      if(fault==='expired'){vi.spyOn(Date,'now').mockReturnValue(s.f.context.valid_until*1000);message='MONEY_REVIEW_EXPIRED';}
      if(fault==='orphaned-review'){s.old.hash=s.f.hash;message='MONEY_REVIEW_ORPHANED';}
      if(fault==='unfinalized-review'){s.finalized.mockResolvedValue({...s.evidence,status:'pending'});message='MONEY_REVIEW_ORPHANED';}
      if(fault==='head-disagreement'){s.requests[1].mockImplementation(async()=>({...s.head,hash:s.block.block_hash}));message='MONEY_HEAD_DISAGREEMENT';}
      if(fault==='head-stale'){s.head.timestamp=toHex(BigInt(s.f.now-s.policy.max_latest_age_seconds-1));message='MONEY_HEAD_UNAVAILABLE';}
      if(fault==='unknown-account'){s.security.security.phase='initial';message='MONEY_SECURITY_CHANGED';}
      if(fault==='security-version'){s.security.security_version='2';message='MONEY_SECURITY_CHANGED';}
      if(fault==='policy'){s.security.security.policy.upgradeDelaySeconds++;message='MONEY_SECURITY_CHANGED';}
      if(fault==='nonce'){s.nonce.nonce='1';message='MONEY_NONCE_CHANGED';}
      if(fault==='checkpoint'){s.nonce.checkpoint={...s.checkpoint,block_hash:s.block.block_hash};message='MONEY_CHECKPOINT_MISMATCH';}
      if(fault==='paused'){s.position.paused=true;message='MONEY_MARKET_UNAVAILABLE';}
      if(fault==='frozen'){s.position.frozen=true;message='MONEY_MARKET_UNAVAILABLE';}
      if(fault==='debt'){s.position.debt_base_atomic='1';message='MONEY_DEBT_NOT_SUPPORTED';}
      if(fault==='usdc'){s.position.usdc_balance_atomic='19999999';message='MONEY_SUPPLY_FUNDS_INSUFFICIENT';}
      if(fault==='capacity'){s.position.supply_capacity_atomic='19999999';message='MONEY_SUPPLY_FUNDS_INSUFFICIENT';}
      if(fault==='gas'){s.position.native_balance_atomic='299';message='MONEY_GAS_FUNDS_INSUFFICIENT';}
      if(fault==='rpc-failure')s.balance.mockRejectedValue(new Error('Unavailable position'));
      if(fault==='floor'){await env.WALLET_DB.prepare('INSERT INTO wallet_balance_floors VALUES (?,?,?,?)')
        .bind(s.f.accountId,(BigInt(s.checkpoint.block_number)+1n).toString(),s.f.hash,s.f.now).run();message='MONEY_BALANCE_CHECKPOINT_STALE';}
      if(fault==='closing-head'){
        let reads=0;s.requests[0].mockImplementation(async({params})=>{
          if(params[0]===s.oldTag)return s.old;
          if(params[0]==='latest')return s.head;
          return ++reads===1?s.head:{...s.head,hash:s.block.block_hash};
        });message='MONEY_HEAD_ORPHANED';
      }
      if(fault==='owner-revoked'){s.balance.mockImplementation(async()=>{
        await env.WALLET_DB.prepare('UPDATE users SET disabled_at=?').bind(s.f.now).run();return s.position;
      });message='UNAUTHENTICATED';}
      if(fault==='stale-observation'){s.position.expires_at=s.f.now;message='MONEY_CURRENT_STATE_EXPIRED';}
      await expect(s.run()).rejects.toThrow(message);
      expect(await env.WALLET_DB.prepare('SELECT count(*) AS n FROM money_operations').first('n')).toBe(0);
    });
  it.each(['position','liquidity'])('requires sufficient withdrawal %s',async fault=>{
    const s=await fixture('aave_withdraw');
    if(fault==='position')s.position.position_balance_atomic='19999999';else s.position.liquidity_atomic='19999999';
    await expect(s.run()).rejects.toThrow('MONEY_WITHDRAW_FUNDS_INSUFFICIENT');
  });
  it('permits withdrawal from a frozen, active reserve without debt',async()=>{
    const s=await fixture('aave_withdraw');s.position.frozen=true;
    expect(await s.run()).toMatchObject({consent_digest:s.f.candidate.digest,send_enabled:false});
  });
  it('propagates abort instead of renewing an observation',async()=>{
    const s=await fixture();s.balance.mockImplementation(async()=>{s.controller.abort();return s.position;});
    await expect(s.run()).rejects.toMatchObject({name:'AbortError'});
  });
});
