import { applyD1Migrations } from 'cloudflare:test';
import { env } from 'cloudflare:workers';
import { afterEach,beforeAll,beforeEach,describe,expect,it,vi } from 'vitest';
import { parseEnvironment } from '@gatopago/environment';
import environments from '@gatopago/environment/environments.json';
import * as session from '../src/auth/session';
import * as positions from '../src/portfolio/aavePosition';
import { createMoneyReadRoute } from '../src/money/moneyReadRoute';
import { configureWalletNetworks } from '../src/runtime/config';
import { arbitrumSepolia } from '../src/runtime/catalog';
import { parseMoneyApplication } from '../src/runtime/moneyConfig';
import application from '../config/application.json';
import { clearMoneyTestRows,moneyOwnedFixture } from './moneyOwned.fixture';

beforeAll(()=>applyD1Migrations(env.WALLET_DB,env.V3_TEST_MIGRATIONS));
beforeEach(()=>clearMoneyTestRows(env.WALLET_DB));
afterEach(()=>vi.restoreAllMocks());
describe('Private monetary position and capabilities',()=>{
  it.each(['position','capabilities','origin','query','method','options','foreign','disabled-user','no-config','deployment','rpc-failure','resolver-failure'])(
    'enforces %s without a monetary mutation',async fault=>{
      const s=await moneyOwnedFixture(env.WALLET_DB),config=parseEnvironment({...environments.production,status:'provisioned',firebase_project_id:'v3-runtime-test',wallet_enabled:[s.f.request.network_id]});
      const base=configureWalletNetworks({schema_version:1,production:[arbitrumSepolia]},config,{WALLET_RPC_ENDPOINTS:JSON.stringify({arbitrum_sepolia_offchain:'https://a.example/rpc',arbitrum_sepolia_tenderly:'https://b.example/rpc'}),PRIVATE_KEY:`0x${'01'.repeat(32)}`,WALLET_BACKUP_SIGNER_KEY:''})[0];
      const configuration={application:parseMoneyApplication(application),market:s.profile.market,gasByKind:{aave_supply:null,aave_withdraw:null,aave_withdraw_and_pay:null} as const,
        network:{...base,deployment:s.manifest,transferProfile:{...s.profile,assetIds:[...s.profile.assetIds],providers:s.profile.providers.map(peer=>({...peer})),environment:'production' as const,
          digest:fault==='deployment'?s.f.hash:s.profile.digest}}};
      const resolve=vi.fn(async()=>[s.profile]),read=vi.spyOn(positions,'inspectOwnedAavePosition').mockResolvedValue(s.position);
      const auth=vi.spyOn(session,'verifyAppSession').mockResolvedValue(fault==='foreign'?{...s.f.identity,userId:'usr_00000000-0000-4000-8000-000000000000'}:s.f.identity);
      if(fault==='disabled-user')await env.WALLET_DB.prepare('UPDATE users SET disabled_at=?').bind(s.f.now).run();
      if(fault==='rpc-failure')read.mockRejectedValue(new Error('Synthetic RPC outage'));
      if(fault==='resolver-failure')resolve.mockRejectedValue(new Error('Finality unavailable'));
      const route=createMoneyReadRoute({configuration:fault==='no-config'?null:configuration,accessProfiles:async()=>[],resolveProfiles:resolve});
      const endpoint=fault==='capabilities'?'money-capabilities':'aave-position';
      const headers={Origin:fault==='origin'?'https://wrong.example':config.web_origin,
        'Access-Control-Request-Method':'GET','Access-Control-Request-Headers':'Authorization'};
      const request=new Request(`${config.api_origin}/app/v1/wallets/${s.f.walletId}/accounts/${s.f.accountId}/${endpoint}${fault==='query'?'?account=arbitrary':''}`,
        {method:fault==='method'?'POST':fault==='options'?'OPTIONS':'GET',headers});
      const response=await route(request,env,config);
      const codes:Record<string,number>={origin:403,query:404,method:405,foreign:409,'disabled-user':401,'no-config':503,deployment:503,'rpc-failure':503,'resolver-failure':503};
      expect(response.status).toBe(codes[fault]??200);
      if(fault==='position'){
        const value=await response.json();expect(value).toMatchObject({wallet_id:s.f.walletId,wallet_account_id:s.f.accountId,
          usdc_balance_atomic:'100000000',position_balance_atomic:'100000019',available_balance:'not_assessed'});
        expect(resolve).toHaveBeenCalledOnce();expect(read).toHaveBeenCalledOnce();
      }else if(fault==='capabilities'){
        expect(await response.json()).toMatchObject({wallet_id:s.f.walletId,features:{aave_supply:false,aave_withdraw:false,aave_withdraw_and_pay:false},spend_readiness:'not_assessed'});
        expect(resolve).not.toHaveBeenCalled();expect(read).not.toHaveBeenCalled();
      }else if(!['rpc-failure','resolver-failure'].includes(fault))expect(resolve).not.toHaveBeenCalled();
      if(['origin','query','method','options'].includes(fault))expect(auth).not.toHaveBeenCalled();
      expect(await env.WALLET_DB.prepare('SELECT count(*) AS n FROM money_operations').first('n')).toBe(0);
      expect(await env.WALLET_DB.prepare('SELECT count(*) AS n FROM wallet_spend_locks').first('n')).toBe(0);
    });
});
