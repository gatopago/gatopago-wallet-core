import { DurableObject } from 'cloudflare:workers';
import { bundlerJsonRpc, createBundler, gatopagoGasConfig } from '@gatopago/shared/bundler';
import { walletContracts } from '@gatopago/shared/networks';
import { config, type Config } from './config';
import { enabledNetwork, json, rateLimit, readJson } from './http';

/**
 * ERC-4337 bundler of one network (one instance per network, named by its CAIP-2 id). Requests run
 * one at a time: each send uses the next relayer nonce.
 */
export class Bundler extends DurableObject<Env> {
  private bundler?: ReturnType<typeof createBundler>;
  private queue: Promise<unknown> = Promise.resolve();

  rpc(networkId: string, body: unknown) {
    const run = this.queue.then(() => bundlerJsonRpc(this.bundlerFor(networkId), body));
    this.queue = run.catch(() => undefined);
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
