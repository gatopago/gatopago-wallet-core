import { createPublicClient, http, isHex, type Hex, type PublicClient } from 'viem';
import { privateKeyToAccount } from 'viem/accounts';
import { walletNetwork, type WalletNetwork } from '@gatopago/shared/networks';

export interface Network extends WalletNetwork {
  readonly id: string;
  readonly rpcUrl: string;
  readonly client: PublicClient;
  /** Where the reconciliation reads Transfer logs (`INDEX_SOURCES`). */
  readonly index: {
    readonly client: PublicClient;
    /** Blocks per `eth_getLogs`: providers cap it (Alchemy's free tier at 10, Monad's RPC at 100). */
    readonly range: bigint;
    /** First block read on a network not read yet; otherwise the latest block. */
    readonly start: bigint | null;
  };
  /** Alchemy Address Activity webhook of this network, when configured. */
  readonly webhook: { readonly id: string; readonly signingKey: string } | null;
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
  /** Alchemy auth token that adds members' addresses to the webhooks. */
  readonly alchemyAuthToken: string | null;
  /** Firebase service account that sends payment notifications through FCM. */
  readonly firebase: { projectId: string; clientEmail: string; privateKey: string } | null;
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

const blockNumber = (value: unknown, name: string, id: string): bigint | null => {
  if (value === undefined) return null;
  if (!Number.isSafeInteger(value) || (value as number) < 0)
    throw new ConfigError(`INVALID_INDEX_${name} ${id}`);
  return BigInt(value as number);
};

function indexSource(
  network: WalletNetwork,
  id: string,
  fallbackUrl: string,
  source: { url?: unknown; range?: unknown; start?: unknown } = {},
): Network['index'] {
  const url = source.url === undefined ? fallbackUrl : rpcUrl(source.url, id);
  const range = blockNumber(source.range, 'RANGE', id) ?? 100n;
  if (range < 1n) throw new ConfigError(`INVALID_INDEX_RANGE ${id}`);
  return {
    client: createPublicClient({ chain: network.chain, transport: http(url) }),
    range,
    start: blockNumber(source.start, 'START', id),
  };
}

function webhook(value: { id?: unknown; signing_key?: unknown } | undefined, id: string) {
  if (value === undefined) return null;
  if (typeof value.id !== 'string' || typeof value.signing_key !== 'string')
    throw new ConfigError(`INVALID_ALCHEMY_WEBHOOK ${id}`);
  return { id: value.id, signingKey: value.signing_key };
}

function firebase(value: string | undefined): Config['firebase'] {
  if (!value) return null;
  const account: Record<string, unknown> = JSON.parse(value);
  const { project_id, client_email, private_key } = account;
  if (
    typeof project_id !== 'string' ||
    typeof client_email !== 'string' ||
    typeof private_key !== 'string'
  )
    throw new ConfigError('INVALID_FIREBASE_SERVICE_ACCOUNT');
  return { projectId: project_id, clientEmail: client_email, privateKey: private_key };
}

/** Every setting the Worker needs, validated together; a missing or invalid one stops the request. */
export function config(env: Env): Config {
  const urls: Record<string, unknown> = JSON.parse(required(env, 'WALLET_RPC_URLS'));
  const sources: Record<string, { url?: unknown; range?: unknown; start?: unknown }> = JSON.parse(
    env.INDEX_SOURCES || '{}',
  );
  const webhooks: Record<string, { id?: unknown; signing_key?: unknown }> = JSON.parse(
    env.ALCHEMY_WEBHOOKS || '{}',
  );
  const networks = new Map<string, Network>();
  for (const id of required(env, 'WALLET_NETWORKS').split(',')) {
    const network = walletNetwork(id.trim());
    const url = rpcUrl(urls[id.trim()], id);
    networks.set(id.trim(), {
      ...network,
      id: id.trim(),
      rpcUrl: url,
      client: createPublicClient({ chain: network.chain, transport: http(url) }),
      index: indexSource(network, id.trim(), url, sources[id.trim()]),
      webhook: webhook(webhooks[id.trim()], id),
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
    alchemyAuthToken: env.ALCHEMY_AUTH_TOKEN || null,
    firebase: firebase(env.FIREBASE_SERVICE_ACCOUNT),
  };
}
