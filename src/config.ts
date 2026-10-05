import { createPublicClient, http, isHex, type Hex, type PublicClient } from 'viem';
import { privateKeyToAccount } from 'viem/accounts';
import { walletNetwork, type WalletNetwork } from '@gatopago/shared/networks';

export interface Network extends WalletNetwork {
  readonly id: string;
  readonly rpcUrl: string;
  readonly client: PublicClient;
}

export interface Config {
  readonly environment: string;
  readonly webOrigin: string;
  readonly networks: ReadonlyMap<string, Network>;
  readonly relayerKey: Hex;
  readonly sponsor: ReturnType<typeof privateKeyToAccount>;
  readonly sessionJwk: JsonWebKey;
  readonly turnstileSecret: string;
  readonly sponsoredOperationsPerDay: number;
}

class ConfigError extends Error {}

const required = (env: Env, name: keyof Env): string => {
  const value = env[name];
  if (typeof value !== 'string' || value.trim() === '')
    throw new ConfigError(`MISSING_${String(name)}`);
  return value;
};

const privateKey = (env: Env, name: 'RELAYER_PRIVATE_KEY' | 'SPONSOR_PRIVATE_KEY'): Hex => {
  const value = required(env, name);
  if (!isHex(value) || value.length !== 66) throw new ConfigError(`INVALID_${name}`);
  return value;
};

const rpcUrl = (value: unknown, id: string): string => {
  if (typeof value !== 'string') throw new ConfigError(`MISSING_RPC_URL ${id}`);
  const url = new URL(value);
  const loopback = ['localhost', '127.0.0.1'].includes(url.hostname);
  if (url.protocol !== 'https:' && !(url.protocol === 'http:' && loopback))
    throw new ConfigError(`INVALID_RPC_URL ${id}`);
  return url.href;
};

/** Every setting the Worker needs, validated together; a missing or invalid one stops the request. */
export function config(env: Env): Config {
  const urls: Record<string, unknown> = JSON.parse(required(env, 'WALLET_RPC_URLS'));
  const networks = new Map<string, Network>();
  for (const id of required(env, 'WALLET_NETWORKS').split(',')) {
    const network = walletNetwork(id.trim());
    const url = rpcUrl(urls[id.trim()], id);
    networks.set(id.trim(), {
      ...network,
      id: id.trim(),
      rpcUrl: url,
      client: createPublicClient({ chain: network.chain, transport: http(url) }),
    });
  }
  const webOrigin = new URL(required(env, 'WEB_ORIGIN')).origin;
  const operations = Number(required(env, 'SPONSORED_OPERATIONS_PER_DAY'));
  if (!Number.isSafeInteger(operations) || operations < 1)
    throw new ConfigError('INVALID_SPONSORED_OPERATIONS_PER_DAY');
  return {
    environment: required(env, 'GATOPAGO_ENVIRONMENT'),
    webOrigin,
    networks,
    relayerKey: privateKey(env, 'RELAYER_PRIVATE_KEY'),
    sponsor: privateKeyToAccount(privateKey(env, 'SPONSOR_PRIVATE_KEY')),
    sessionJwk: JSON.parse(required(env, 'SESSION_PRIVATE_JWK')),
    turnstileSecret: required(env, 'TURNSTILE_SECRET_KEY'),
    sponsoredOperationsPerDay: operations,
  };
}
