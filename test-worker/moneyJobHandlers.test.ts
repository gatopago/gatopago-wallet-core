import { applyD1Migrations } from 'cloudflare:test';
import { env } from 'cloudflare:workers';
import { afterEach,beforeAll,beforeEach,describe,expect,it,vi } from 'vitest';
import { createResourceId } from '@gatopago/shared/v3/primitives';
import * as expiry from '../src/money/moneyExpiration';
import * as transport from '../src/execution/operationTransport';
import * as reconcile from '../src/money/moneyReconciliation';
import { createMoneyJobHandlers } from '../src/money/moneyJobHandlers';
import { MoneyJobRepository,type MoneyWake } from '../src/money/moneyJobs';
import { dispatchWalletJobs } from '../src/execution/walletJobHandlers';
import { clearMoneyTestRows } from './moneyOwned.fixture';
import { seedMoneyDelivery } from './moneyDelivery.fixture';

beforeAll(()=>applyD1Migrations(env.WALLET_DB,env.V3_TEST_MIGRATIONS));
beforeEach(()=>clearMoneyTestRows(env.WALLET_DB));
afterEach(()=>vi.restoreAllMocks());
async function fixture(){
  const s=await seedMoneyDelivery(env.WALLET_DB),configuration={environment:'production' as const,profiles:[s.profile]};
  const jobs=new MoneyJobRepository(env.WALLET_DB,configuration),send=vi.fn<Queue<MoneyWake>['send']>(async()=>({metadata:{metrics:{backlogCount:0,backlogBytes:0}}}));
  const bindings={...env,CREATION_QUEUE_NAME:'money-test-queue',CREATION_JOBS:{send}};
  const handler=createMoneyJobHandlers(()=>configuration);
  const resume=vi.spyOn(transport,'resumeSubmission').mockResolvedValue(undefined);
  const observation=vi.spyOn(reconcile,'reconcileMoneyJob').mockResolvedValue({state:'waiting'});
  const warning=vi.spyOn(console,'warn').mockImplementation(()=>{});
  return {...s,configuration,jobs,send,bindings,handler,resume,observation,warning};
}
function batch(body:unknown,queue='money-test-queue'){
  const item={id:'synthetic-message',timestamp:new Date(),attempts:1,body,ack:vi.fn(),retry:vi.fn()};
  const value={queue,messages:[item],ackAll:vi.fn(),retryAll:vi.fn()};
  return {item,value:value as unknown as MessageBatch<unknown>,retryAll:value.retryAll};
}
const jobRow=()=>env.WALLET_DB.prepare('SELECT state,failures,reason,lease_token FROM money_jobs').first();

describe('Money scheduling and shared queue recovery',()=>{
  it('has one concurrent enqueue winner and defers a missing receipt without releasing funds',async()=>{
    const s=await fixture();await Promise.all([s.handler.wake(s.bindings),s.handler.wake(s.bindings)]);
    expect(s.send).toHaveBeenCalledTimes(1);
    const wake=s.send.mock.calls[0][0],message=batch(wake);
    await s.handler.queue(message.value,s.bindings);
    expect(message.item.ack).toHaveBeenCalledOnce();expect(message.item.retry).not.toHaveBeenCalled();
    expect(s.resume.mock.calls[0][1]).toBe(s.stored.candidate.userOpHash);
    expect(s.resume.mock.calls[0][2].aborted).toBe(false);
    expect(await jobRow()).toMatchObject({state:'ready',failures:0,lease_token:null});
    expect(await env.WALLET_DB.prepare('SELECT state FROM wallet_spend_locks').first()).toEqual({state:'dispatch_pending'});
  });
  it('records a failed enqueue for cron recovery',async()=>{
    const s=await fixture();s.send.mockRejectedValue(new Error('Synthetic queue outage'));
    await s.handler.wake(s.bindings);
    expect(await jobRow()).toMatchObject({state:'ready',failures:1,lease_token:null});
    expect(s.warning).toHaveBeenCalledWith({event:'v3_money_enqueue_failed',count:1});
  });
  it('retains monetary messages when configuration is unavailable',async()=>{
    const s=await fixture(),wake=(await s.jobs.reserve(s.stored.id))!,message=batch(wake);
    await createMoneyJobHandlers(()=>null).queue(message.value,s.bindings);
    expect(message.retryAll).toHaveBeenCalledWith({delaySeconds:60});expect(message.item.ack).not.toHaveBeenCalled();
    expect(await jobRow()).toMatchObject({state:'queued',failures:0});
  });
  it.each(['malformed','other-kind','wrong-token','observation-error','replay-error','conflict','past-day'])(
    'handles %s without signing or releasing a spend',async fault=>{
      const s=await fixture(),wake=(await s.jobs.reserve(s.stored.id))!;
      let body:unknown=wake;
      if(fault==='malformed')body={...wake,assertion:'forbidden'};
      if(fault==='other-kind')body={...wake,kind:'account_backup'};
      if(fault==='wrong-token')body={...wake,token:createResourceId('operation')};
      if(fault==='observation-error')s.observation.mockRejectedValue(new Error('Observation unavailable'));
      if(fault==='replay-error')s.resume.mockRejectedValue(new Error('Existing raw journal replay failed'));
      if(fault==='conflict')s.observation.mockResolvedValue({state:'review',reason:'conflicting_evidence'});
      if(fault==='past-day')vi.spyOn(Date,'now').mockReturnValue((s.f.now+86401)*1000);
      const message=batch(body);await s.handler.queue(message.value,s.bindings);
      expect(message.item.ack).toHaveBeenCalledOnce();expect(message.item.retry).not.toHaveBeenCalled();
      if(['malformed','other-kind','wrong-token'].includes(fault))expect(s.observation).not.toHaveBeenCalled();
      if(['observation-error','replay-error'].includes(fault))expect(await jobRow()).toMatchObject({state:'ready',failures:1});
      if(['conflict','past-day'].includes(fault))expect(await jobRow()).toMatchObject({state:'review',reason:fault==='conflict'?'conflicting_evidence':'observation_timeout'});
      expect(await env.WALLET_DB.prepare('SELECT state FROM wallet_spend_locks').first()).toEqual({state:'dispatch_pending'});
    });
  it('runs bounded expiry maintenance with flags closed and no login',async()=>{
    const s=await fixture();
    s.configuration.profiles=[{...s.profile,features:{aave_supply:false,aave_withdraw:false,aave_withdraw_and_pay:false}}];
    await env.WALLET_DB.prepare('UPDATE users SET disabled_at=?').bind(s.f.now).run();
    const sweep=vi.spyOn(expiry,'expiredMoneyCandidates').mockResolvedValue([s.stored.id]);
    const expire=vi.spyOn(expiry,'expireUnsubmittedMoney').mockResolvedValue({state:'unchanged'});
    await s.handler.wake(s.bindings);
    expect(sweep).toHaveBeenCalledOnce();expect(expire).toHaveBeenCalledOnce();
    expect(expire.mock.calls[0][1]).toBe('production');expect(expire.mock.calls[0][2]).toBe(s.stored.id);
    expect(expire.mock.calls[0][3].map(profile=>profile.digest)).toEqual(s.configuration.profiles.map(profile=>profile.digest));
    expect(expire.mock.calls[0][4].aborted).toBe(false);
    expect(s.send).toHaveBeenCalledOnce();
  });
  it('rejects the wrong queue before mutating a lease',async()=>{
    const s=await fixture(),wake=(await s.jobs.reserve(s.stored.id))!,message=batch(wake,'another-queue');
    await expect(s.handler.queue(message.value,s.bindings)).rejects.toThrow('UNEXPECTED_MONEY_QUEUE');
    expect(message.item.ack).not.toHaveBeenCalled();expect(await jobRow()).toMatchObject({state:'queued'});
  });
  it('bulk retry for a missing money configuration cannot acknowledge or retry another domain',async()=>{
    const s=await fixture(),items=['account_creation','account_backup','transfer_observation','money_observation'].map(kind=>batch({kind}).item);
    const input={queue:s.bindings.CREATION_QUEUE_NAME,messages:items,ackAll:vi.fn(),retryAll:vi.fn()} as unknown as MessageBatch<unknown>;
    const acknowledge={queue:vi.fn(async(group:MessageBatch<unknown>)=>group.ackAll())};
    await dispatchWalletJobs(input,s.bindings as unknown as WalletCoreV3Bindings,{creation:acknowledge,backup:acknowledge,transfer:acknowledge,money:createMoneyJobHandlers(()=>null)});
    for(const item of items.slice(0,3)){expect(item.ack).toHaveBeenCalledOnce();expect(item.retry).not.toHaveBeenCalled();}
    expect(items[3].ack).not.toHaveBeenCalled();expect(items[3].retry).toHaveBeenCalledWith({delaySeconds:60});
  });
});
