import { HttpError, readJson as readBody, withCors as cors } from '@gatopago/shared/http';
import type { Config, Network } from './config';

export { HttpError, json, readBody } from '@gatopago/shared/http';

/** A JSON object body of at most 32 KB. */
export const readJson = <T>(request: Request, limit = 32_768) => readBody<T>(request, limit);

/** Per-client request budget (Cloudflare Rate Limiting binding). */
export async function rateLimit(env: Env, request: Request, scope: string): Promise<void> {
  const ip = request.headers.get('CF-Connecting-IP') ?? 'unknown';
  const { success } = await env.RATE_LIMITER.limit({ key: `${scope}:${ip}` });
  if (!success) throw new HttpError(429, 'RATE_LIMITED');
}

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
