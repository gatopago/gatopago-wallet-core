import { Keypair, rpc } from '@stellar/stellar-sdk';
import { createPublicClient, http, isHex, type Hex, type PublicClient } from 'viem';
import { privateKeyToAccount } from 'viem/accounts';
import {
  stellarNetwork,
  walletNetwork,
  type StellarNetwork,
  type WalletNetwork,
} from '@gatopago/shared/networks';

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
    /**
     * Envio HyperSync, when configured with `ENVIO_API_TOKEN`: it reads instead of `client`, and
     * `since` (the factory's deployment block) is where members' history starts.
     */
    readonly hypersync: {
      readonly url: string;
      readonly token: string;
      readonly since: bigint;
    } | null;
  };
  /** Alchemy Address Activity webhook of this network, when configured. */
  readonly webhook: { readonly id: string; readonly signingKey: string } | null;
}

export interface Config {
  readonly environment: string;
  readonly webOrigin: string;
  /** GatoPago Business (merchant console), or `null` when off. */
  readonly businessOrigin: string | null;
  readonly networks: ReadonlyMap<string, Network>;
  readonly relayerKey: Hex;
  readonly sponsor: ReturnType<typeof privateKeyToAccount>;
  readonly sessionJwk: JsonWebKey;
  readonly turnstileSecret: string;
  readonly sponsoredOperationsPerDay: number;
  /** External requests one cron run may make (Workers Free: 50 per invocation). */
  readonly subrequestsPerRun: number;
  /** `INVITE_ONLY`: whether new accounts need an invitation (Turnstile is always required). */
  readonly inviteOnly: boolean;
  /** Alchemy auth token that adds members' addresses to the webhooks. */
  readonly alchemyAuthToken: string | null;
  /** Firebase service account that sends payment notifications through FCM. */
  readonly firebase: { projectId: string; clientEmail: string; privateKey: string } | null;
  /**
   * Stellar, enabled by `STELLAR_SECRET_KEY`: the key that creates members' Stellar accounts (their
   * addresses derive from it), pays their fees and mints CCTP transfers toward Stellar.
   */
  readonly stellar: {
    readonly id: string;
    readonly network: StellarNetwork;
    readonly server: rpc.Server;
    readonly keypair: Keypair;
  } | null;
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

type IndexSource = {
  url?: unknown;
  range?: unknown;
  start?: unknown;
  hypersync?: unknown;
  since?: unknown;
};

function indexSource(
  network: WalletNetwork,
  id: string,
  fallbackUrl: string,
  envioToken: string | undefined,
  source: IndexSource = {},
): Network['index'] {
  const url = source.url === undefined ? fallbackUrl : rpcUrl(source.url, id);
  const range = blockNumber(source.range, 'RANGE', id) ?? 100n;
  if (range < 1n) throw new ConfigError(`INVALID_INDEX_RANGE ${id}`);
  return {
    client: createPublicClient({ chain: network.chain, transport: http(url) }),
    range,
    start: blockNumber(source.start, 'START', id),
    hypersync:
      source.hypersync === undefined || !envioToken
        ? null
        : {
            url: new URL(rpcUrl(source.hypersync, id)).origin,
            token: envioToken,
            since: blockNumber(source.since, 'SINCE', id) ?? 0n,
          },
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

function stellar(env: Env): Config['stellar'] {
  if (!env.STELLAR_SECRET_KEY) return null;
  const id = required(env, 'STELLAR_NETWORK');
  let keypair: Keypair;
  try {
    keypair = Keypair.fromSecret(env.STELLAR_SECRET_KEY);
  } catch {
    throw new ConfigError('INVALID_STELLAR_SECRET_KEY');
  }
  const network = stellarNetwork(id);
  const url = env.STELLAR_RPC_URL ? rpcUrl(env.STELLAR_RPC_URL, id) : network.rpcUrl;
  return {
    id,
    network,
    keypair,
    server: new rpc.Server(url, { allowHttp: url.startsWith('http:') }),
  };
}

/** Every setting the Worker needs, validated together; a missing or invalid one stops the request. */
export function config(env: Env): Config {
  const urls: Record<string, unknown> = JSON.parse(required(env, 'WALLET_RPC_URLS'));
  const sources: Record<string, IndexSource> = JSON.parse(env.INDEX_SOURCES || '{}');
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
      index: indexSource(network, id.trim(), url, env.ENVIO_API_TOKEN, sources[id.trim()]),
      webhook: webhook(webhooks[id.trim()], id),
    });
  }
  const webOrigin = new URL(required(env, 'WEB_ORIGIN')).origin;
  const subrequestsPerRun = Number(required(env, 'SUBREQUESTS_PER_RUN'));
  if (!Number.isSafeInteger(subrequestsPerRun) || subrequestsPerRun < 5)
    throw new ConfigError('INVALID_SUBREQUESTS_PER_RUN');
  const inviteOnly = required(env, 'INVITE_ONLY');
  if (inviteOnly !== 'on' && inviteOnly !== 'off') throw new ConfigError('INVALID_INVITE_ONLY');
  const operations = Number(required(env, 'SPONSORED_OPERATIONS_PER_DAY'));
  if (!Number.isSafeInteger(operations) || operations < 1)
    throw new ConfigError('INVALID_SPONSORED_OPERATIONS_PER_DAY');
  return {
    environment: required(env, 'GATOPAGO_ENVIRONMENT'),
    webOrigin,
    businessOrigin: env.BUSINESS_ORIGIN ? new URL(env.BUSINESS_ORIGIN).origin : null,
    networks,
    relayerKey: privateKey(env, 'RELAYER_PRIVATE_KEY'),
    sponsor: privateKeyToAccount(privateKey(env, 'SPONSOR_PRIVATE_KEY')),
    sessionJwk: JSON.parse(required(env, 'SESSION_PRIVATE_JWK')),
    turnstileSecret: required(env, 'TURNSTILE_SECRET_KEY'),
    sponsoredOperationsPerDay: operations,
    subrequestsPerRun,
    inviteOnly: inviteOnly === 'on',
    alchemyAuthToken: env.ALCHEMY_AUTH_TOKEN || null,
    firebase: firebase(env.FIREBASE_SERVICE_ACCOUNT),
    stellar: stellar(env),
  };
}
