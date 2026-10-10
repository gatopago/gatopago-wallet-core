import { DurableObject } from 'cloudflare:workers';
import { bundlerJsonRpc, createBundler, gatopagoGasConfig } from '@gatopago/shared/bundler';
import { walletContracts } from '@gatopago/shared/networks';
import { config, type Config } from './config';
import { enabledNetwork, json, rateLimit, readJson } from './http';

/**
 * ERC-4337 bundler of one network (one instance per network, named by its CAIP-2 id). Sends run one
 * at a time, each reserving the next relayer nonce; estimates, receipts and the rest do not wait
 * behind them.
 */
export class Bundler extends DurableObject<Env> {
  private bundler?: ReturnType<typeof createBundler>;
  private sends: Promise<unknown> = Promise.resolve();

  rpc(networkId: string, body: unknown) {
    const handle = () => bundlerJsonRpc(this.bundlerFor(networkId), body);
    if ((body as { method?: unknown } | null)?.method !== 'eth_sendUserOperation') return handle();
    const run = this.sends.then(handle);
    this.sends = run.catch(() => undefined);
    return run;
  }

  private bundlerFor(networkId: string) {
    if (!this.bundler) {
      const settings = config(this.env);
      const network = enabledNetwork(settings, networkId);
      this.bundler = createBundler({
        chain: network.chain,
        rpcUrl: network.rpcUrl,
        relayerKey: settings.relayerKey,
        paymaster: walletContracts.paymaster,
        gas: gatopagoGasConfig,
        l1Fees: network.l1Fees,
        store: this.ctx.storage,
      });
    }
    return this.bundler;
  }
}

/** `POST /app/v1/bundler/:network`: standard bundler JSON-RPC. Only paymaster-sponsored operations are sent. */
export async function bundle(
  request: Request,
  env: Env,
  config: Config,
  networkId: string,
): Promise<Response> {
  enabledNetwork(config, networkId);
  await rateLimit(env, request, 'bundler');
  const body = await readJson<unknown>(request);
  return json(await env.BUNDLER.get(env.BUNDLER.idFromName(networkId)).rpc(networkId, body));
}
