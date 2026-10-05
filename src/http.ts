import type { Config, Network } from './config';

/** An expected failure, returned to the client as `{ error_code }`. */
export class HttpError extends Error {
  constructor(
    readonly status: number,
    readonly code: string,
  ) {
    super(code);
  }
}

export function json(body: unknown, status = 200): Response {
  return Response.json(body, {
    status,
    headers: { 'Cache-Control': 'no-store', 'X-Content-Type-Options': 'nosniff' },
  });
}

export async function readJson<T>(request: Request, limit = 32_768): Promise<T> {
  if (!request.headers.get('Content-Type')?.startsWith('application/json'))
    throw new HttpError(415, 'JSON_REQUIRED');
  const text = await request.text();
  if (text.length > limit) throw new HttpError(413, 'BODY_TOO_LARGE');
  try {
    return JSON.parse(text) as T;
  } catch {
    throw new HttpError(400, 'INVALID_JSON');
  }
}

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

export function withCors(response: Response, origin: string): Response {
  const headers = new Headers(response.headers);
  headers.set('Access-Control-Allow-Origin', origin);
  headers.set('Access-Control-Allow-Methods', 'GET, POST, PUT, DELETE, OPTIONS');
  headers.set('Access-Control-Allow-Headers', 'Authorization, Content-Type');
  headers.set('Access-Control-Max-Age', '600');
  headers.set('Vary', 'Origin');
  return new Response(response.body, { status: response.status, headers });
}
