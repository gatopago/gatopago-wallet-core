import { applyD1Migrations } from 'cloudflare:test';
import { env } from 'cloudflare:workers';
import { afterEach,beforeAll,beforeEach,describe,expect,it,vi } from 'vitest';
import { parseEnvironment } from '@gatopago/environment';
import environments from '@gatopago/environment/environments.json';
import { clientMutationHeaders } from '@gatopago/shared/v3/client-release';
import * as session from '../src/auth/session';
import * as delivery from '../src/money/moneyDelivery';
import { MoneyRepository } from '../src/money/moneyRepository';
import { readOwnedMoneyStatus } from '../src/money/moneyStatus';
import { createMoneyRoute } from '../src/money/moneyRoute';
import { clearMoneyTestRows } from './moneyOwned.fixture';
import { seedMoneyDelivery } from './moneyDelivery.fixture';

beforeAll(()=>applyD1Migrations(env.WALLET_DB,env.V3_TEST_MIGRATIONS));
beforeEach(()=>clearMoneyTestRows(env.WALLET_DB));
afterEach(()=>vi.restoreAllMocks());
async function fixture(){
  const s=await seedMoneyDelivery(env.WALLET_DB,false);
  await env.WALLET_DB.prepare('UPDATE users SET auth_not_before=?').bind(s.f.now).run();
  const principal={...s.f.identity,authTime:s.f.now},repository=new MoneyRepository(env.WALLET_DB,principal,s.f.keys.input.scope,s.f.pins);
  return {...s,principal,history:repository};
}

describe('Fresh owner can recover historical money after session revocation',()=>{
  it('reads the previous reference and status without accepting its old mutation authority',async()=>{
    const s=await fixture();
    expect((await s.history.readPreparationHistory(s.f.walletId,s.f.accountId,s.stored.preparation_id)).candidate.digest).toBe(s.stored.candidate.digest);
    expect(await s.history.operationForPreparation(s.f.walletId,s.f.accountId,s.stored.preparation_id)).toBe(s.stored.id);
    expect((await s.history.readOperationHistory(s.f.walletId,s.f.accountId,s.stored.id)).record_sha256).toBe(s.stored.record_sha256);
    const status=await readOwnedMoneyStatus(env.WALLET_DB,s.history,s.f.walletId,s.f.accountId,s.stored.id);
    expect(status).toMatchObject({operation_id:s.stored.id,funds_reserved:true,state:'authorized',send_enabled:false});
    expect(JSON.parse(status.review_json).proofs).toEqual([]);
    await expect(s.history.readPreparation(s.f.walletId,s.f.accountId,s.stored.preparation_id)).rejects.toThrow('MONEY_PREPARATION_NOT_FOUND');
    await expect(s.history.readOperation(s.f.walletId,s.f.accountId,s.stored.id)).rejects.toThrow('MONEY_OPERATION_NOT_FOUND');
    await expect(s.history.beginDelivery(s.f.walletId,s.f.accountId,s.stored.id,s.preflight)).rejects.toThrow('MONEY_OPERATION_NOT_FOUND');
    expect(await env.WALLET_DB.prepare('SELECT state FROM wallet_spend_locks').first()).toEqual({state:'held'});
    expect(await env.WALLET_DB.prepare('SELECT count(*) AS n FROM user_operation_submissions').first('n')).toBe(0);
  });
  it.each(['old-session','disabled-user','expired-session','wrong-owner','wrong-account'])(
    'still refuses historical access with %s',async fault=>{
      const s=await fixture();let principal=s.principal;
      if(fault==='old-session')principal=s.f.identity;
      if(fault==='disabled-user')await env.WALLET_DB.prepare('UPDATE users SET disabled_at=?').bind(s.f.now).run();
      if(fault==='expired-session')principal={...principal,expiresAt:s.f.now};
      if(fault==='wrong-owner')principal={...principal,userId:'usr_00000000-0000-4000-8000-000000000000'};
      const repository=new MoneyRepository(env.WALLET_DB,principal,s.f.keys.input.scope,s.f.pins);
      const account=fault==='wrong-account'?'wac_00000000-0000-4000-8000-000000000000':s.f.accountId;
      await expect(repository.readOperationHistory(s.f.walletId,account,s.stored.id)).rejects.toThrow();
      await expect(repository.operationForPreparation(s.f.walletId,account,s.stored.preparation_id)).rejects.toThrow();
    });
  it('keeps GET recovery available while rejecting POST delivery of the revoked authorization',async()=>{
    const s=await fixture(),config=parseEnvironment({...environments.production,status:'provisioned',firebase_project_id:'v3-runtime-test',wallet_enabled:[s.f.request.network_id]});
    vi.spyOn(session,'verifyAppSession').mockResolvedValue(s.principal);
    const send=vi.spyOn(delivery,'deliverOwnedMoney');
    const resolve=vi.fn(async()=>{throw new Error('History must not perform RPC');});
    const route=createMoneyRoute({profiles:[{...s.profile,environment:'production'}],resolvePreparation:resolve});
    const path=`${config.api_origin}/app/v1/wallets/${s.f.walletId}/accounts/${s.f.accountId}`;
    const preparation=await route(new Request(`${path}/money-preparations/${s.stored.preparation_id}`,{headers:{Origin:config.web_origin}}),env,config);
    expect(preparation.status).toBe(200);expect(await preparation.json()).toMatchObject({operation_id:s.stored.id,send_enabled:false});
    const operation=await route(new Request(`${path}/money-operations/${s.stored.id}`,{headers:{Origin:config.web_origin}}),env,config);
    expect(operation.status).toBe(200);
    const headers={Origin:config.web_origin,'Content-Type':'application/json',...clientMutationHeaders(config.environment,{generation:'3',contract_manifest_version:s.f.keys.profile.deployment.manifest_id})};
    const attempt=await route(new Request(`${path}/money-operations/${s.stored.id}/deliver`,{method:'POST',headers,body:JSON.stringify({money_schema_version:1,consent_digest:s.stored.candidate.digest})}),env,config);
    expect(attempt.status).toBe(404);expect(send).not.toHaveBeenCalled();expect(resolve).not.toHaveBeenCalled();
  });
});
