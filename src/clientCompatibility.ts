import type { Environment } from '@gatopago/environment';
import { CLIENT_COMPATIBILITY_PATH, CLIENT_STATUS_HEADER, WALLET_RELEASE_POLICY, mutationCompatibility, publicClientCompatibility, type ReleasePolicy } from '@gatopago/shared/v3/client-release';
import { v3Json } from './http';

export function requireCompatibleMutation(request: Request, config: Environment, scope: 'identity' | 'account', policy: ReleasePolicy = WALLET_RELEASE_POLICY): Response | null {
  const now = Math.floor(Date.now() / 1000);
  const result = mutationCompatibility(request.headers, config.environment, scope, policy, now);
  if (result === 'compatible') return null;
  if (result === 'account-unavailable') return v3Json(503, { error_code: 'ACCOUNT_VERSION_UNAVAILABLE' }, config.web_origin);
  const response = v3Json(409, {
    error_code: 'CLIENT_UPDATE_REQUIRED',
    compatibility: publicClientCompatibility(config.environment, policy, now),
  }, config.web_origin);
  // 409 is an application version conflict; 426 would request an HTTP protocol upgrade.
  response.headers.set(CLIENT_STATUS_HEADER, 'update-required');
  response.headers.set('Access-Control-Expose-Headers', CLIENT_STATUS_HEADER);
  return response;
}

/** Public, read-only build policy. Does not attest operational readiness. */
export function clientCompatibilityRoute(request: Request, config: Environment, policy: ReleasePolicy = WALLET_RELEASE_POLICY): Response {
  const url = new URL(request.url);
  const origin = request.headers.get('Origin');
  if (url.origin !== config.api_origin || (origin !== null && origin !== config.web_origin)) {
    return v3Json(403, { error_code: 'ORIGIN_NOT_ALLOWED' });
  }
  const allowedOrigin = origin === config.web_origin ? origin : undefined;
  if (url.pathname !== CLIENT_COMPATIBILITY_PATH || url.search) return v3Json(404, { error_code: 'NOT_FOUND' }, allowedOrigin);
  if (request.method !== 'GET') {
    const response = v3Json(405, { error_code: 'METHOD_NOT_ALLOWED' }, allowedOrigin);
    response.headers.set('Allow', 'GET');
    return response;
  }
  return v3Json(200, {
    ...publicClientCompatibility(config.environment, policy, Math.floor(Date.now() / 1000)),
    environment_status: config.status,
  }, allowedOrigin);
}
