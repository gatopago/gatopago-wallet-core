import { applyD1Migrations } from 'cloudflare:test';
import { env } from 'cloudflare:workers';
import { afterEach,beforeAll,beforeEach,describe,expect,it,vi } from 'vitest';
import * as finality from '@gatopago/shared/v3/finality';
import * as balances from '../src/portfolio/balances';
import * as positions from '../src/portfolio/aavePositionObservation';
import { inspectOwnedAavePosition } from '../src/portfolio/aavePosition';
import { WalletRepository } from '../src/accounts/repository';
import { clearMoneyTestRows,moneyOwnedFixture } from './moneyOwned.fixture';

beforeAll(()=>applyD1Migrations(env.WALLET_DB,env.V3_TEST_MIGRATIONS));
beforeEach(()=>clearMoneyTestRows(env.WALLET_DB));
afterEach(()=>vi.restoreAllMocks());
describe('Owned position reconciles account balances at one finalized block',()=>{
  it.each(['success','position-error','balance-error','balance-mismatch','checkpoint-mismatch','pending-source','stale-source','pending-closing','stale-closing','owner-revoked','stale-position'])(
    'handles %s without treating unavailability as zero',async fault=>{
      const s=await moneyOwnedFixture(env.WALLET_DB),owner=new WalletRepository(env.WALLET_DB,s.f.identity);
      const observation={...s.position,finality:'not_assessed' as const};
      const balance:Awaited<ReturnType<typeof balances.inspectOwnedWalletBalances>>={
        wallet_id:s.f.walletId,wallet_account_id:s.f.accountId,network_id:s.f.request.network_id,address:s.f.candidate.account,
        checkpoint:s.block,observed_at:s.f.now,finality:'finalized',finality_evidence:s.evidence,expires_at:s.f.now+10,
        available_balance:'not_assessed',spend_readiness:'not_assessed',
        balances:[{asset_id:s.f.request.asset_id,amount_atomic:'100000000',symbol:'USDC',decimals:6},
          {asset_id:s.f.context.native_asset_id,amount_atomic:'1000000',symbol:'ETH',decimals:18}]};
      const readPosition=vi.spyOn(positions,'observeAavePosition').mockResolvedValue(observation);
      const readBalance=vi.spyOn(balances,'inspectOwnedWalletBalances').mockResolvedValue(balance);
      const closing=vi.spyOn(finality,'assessCheckpointFinality').mockResolvedValue(s.evidence);
      let error='POSITION_FINALITY_UNUSABLE';
      if(fault==='position-error'){readPosition.mockRejectedValue(new Error('Aave unavailable'));error='POSITION_UNAVAILABLE';}
      if(fault==='balance-error'){readBalance.mockRejectedValue(new Error('USDC unavailable'));error='POSITION_UNAVAILABLE';}
      if(fault==='balance-mismatch'){balance.balances[0].amount_atomic='0';error='POSITION_BALANCE_CHANGED';}
      if(fault==='checkpoint-mismatch'){balance.checkpoint={...s.block,block_hash:s.f.hash};error='POSITION_BALANCE_CHANGED';}
      const pending={...s.evidence,status:'pending' as const,checkpoint:{...s.block,block_hash:s.f.hash,block_number:(BigInt(s.block.block_number)-1n).toString()}};
      const stale={...s.evidence,assessed_at:s.f.now-2,expires_at:s.f.now-1};
      if(fault==='pending-source')s.profile.finalityEvidence=pending;
      if(fault==='stale-source')s.profile.finalityEvidence=stale;
      if(fault==='pending-closing')closing.mockResolvedValue(pending);
      if(fault==='stale-closing')closing.mockResolvedValue(stale);
      if(fault==='stale-position')observation.expires_at=s.f.now;
      if(fault==='owner-revoked'){readPosition.mockImplementation(async()=>{
        await env.WALLET_DB.prepare('UPDATE users SET disabled_at=?').bind(s.f.now).run();return observation;
      });error='UNAUTHENTICATED';}
      const run=()=>inspectOwnedAavePosition(owner,s.f.walletId,s.f.accountId,[s.profile],new AbortController().signal);
      if(fault==='success'){
        expect(await run()).toMatchObject({usdc_balance_atomic:'100000000',position_balance_atomic:'100000019',finality:'finalized',
          available_balance:'not_assessed',spend_readiness:'not_assessed',wallet_account_id:s.f.accountId});
        expect(closing).toHaveBeenCalledOnce();
      }else await expect(run()).rejects.toThrow(error);
      expect(await env.WALLET_DB.prepare('SELECT count(*) AS n FROM wallet_spend_locks').first('n')).toBe(0);
    });
});
