import {
  HttpError,
  rateLimit as limit,
  readJson as readBody,
  withCors as cors,
} from '@gatopago/shared/http';
import type { Config, Network } from './config';

export { HttpError, json, readBody } from '@gatopago/shared/http';

/** A JSON object body of at most 32 KB. */
export const readJson = <T>(request: Request, limit = 32_768) => readBody<T>(request, limit);

/** Per-client request budget: the client's IP within `scope`. */
export const rateLimit = (env: Env, request: Request, scope: string) =>
  limit(env.RATE_LIMITER, `${scope}:${request.headers.get('CF-Connecting-IP') ?? 'unknown'}`);

export function enabledNetwork(config: Config, id: string): Network {
  const network = config.networks.get(id);
  if (!network) throw new HttpError(404, 'NETWORK_NOT_ENABLED');
  return network;
}

export const withCors = (response: Response, origin: string) =>
  cors(response, origin, {
    methods: 'GET, POST, PUT, DELETE, OPTIONS',
    headers: 'Authorization, Content-Type',
  });
