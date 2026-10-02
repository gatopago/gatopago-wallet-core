import type { Environment } from '@gatopago/environment';
import { CLIENT_COMPATIBILITY_PATH, CLIENT_RELEASE_HEADERS, CLIENT_RELEASE_ID, CLIENT_STATUS_HEADER,
  WALLET_API_VERSION, type AccountReleaseContext } from '@gatopago/shared/v3/client-release';
import { v3Json } from './http';

function currentProtocol(config: Environment, accounts: readonly AccountReleaseContext[]) {
  return { policy_version: 1, environment: config.environment, api_version: WALLET_API_VERSION,
    minimum_mutating_release: CLIENT_RELEASE_ID, accepted_mutating_releases: [CLIENT_RELEASE_ID],
    account_profiles: accounts.map(account => ({ ...account })) };
}

/** Only the current protocol is accepted. Contract admission comes from the route's pinned catalog. */
export function requireCurrentProtocol(request: Request, config: Environment, scope: 'identity' | 'account',
  manifests: readonly string[] = []): Response | null {
  const headers = request.headers;
  const current = headers.get(CLIENT_RELEASE_HEADERS.release) === CLIENT_RELEASE_ID
    && headers.get(CLIENT_RELEASE_HEADERS.api) === WALLET_API_VERSION
    && headers.get(CLIENT_RELEASE_HEADERS.environment) === config.environment;
  const generation = headers.get(CLIENT_RELEASE_HEADERS.generation), manifest = headers.get(CLIENT_RELEASE_HEADERS.manifest);
  if (current) {
    if (scope === 'identity' && generation === 'none' && manifest === 'none') return null;
    if (scope === 'account') {
      if (!manifests.length) return v3Json(503, { error_code: 'ACCOUNT_VERSION_UNAVAILABLE' }, config.web_origin);
      if (generation === '3' && manifest !== null && manifests.includes(manifest)) return null;
    }
  }
  const response = v3Json(409, { error_code: 'CLIENT_UPDATE_REQUIRED',
    compatibility: currentProtocol(config, manifests.map(contract_manifest_version => ({ generation: '3', contract_manifest_version }))),
  }, config.web_origin);
  response.headers.set(CLIENT_STATUS_HEADER, 'update-required');
  response.headers.set('Access-Control-Expose-Headers', CLIENT_STATUS_HEADER);
  return response;
}

/** Declares the current protocol and admitted contracts; no release negotiation or readiness claim. */
export function clientProtocolRoute(request: Request, config: Environment, accounts: readonly AccountReleaseContext[]): Response {
  const url = new URL(request.url), origin = request.headers.get('Origin');
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
  return v3Json(200, { ...currentProtocol(config, accounts), environment_status: config.status }, allowedOrigin);
}
