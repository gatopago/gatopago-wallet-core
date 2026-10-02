import { isIP } from 'node:net';
import type { Environment } from '@gatopago/environment';
import { readJsonBounded, ResponseBodyTooLargeError } from '@gatopago/shared/http';
import { CLIENT_RELEASE_HEADERS } from '@gatopago/shared/v3/client-release';
import { parseNetworkId, parseResourceId } from '@gatopago/shared/v3/primitives';
import { authLimit, validateIdentityConfig, type AuthBindings } from '../auth/config';
import { IdentityError } from '../auth/identity';
import { verifyAppSession } from '../auth/session';
import { RegistrationError } from '../auth/profile';
import { consumeLimit, privateLimitKey } from '../auth/limits';
import { allowMethods, isJsonRequest, v3Json } from '../http';
import { requireCurrentProtocol } from '../clientProtocol';
import { WalletAccessError } from './repository';
import { ProfileError, ProfileRepository, resolveRecipient, type ReceivingProfiles } from './profile';

type Bindings = AuthBindings & Pick<WalletCoreV3Bindings, 'PUBLIC_LOOKUP_IP_REQUESTS_PER_HOUR' | 'PUBLIC_LOOKUP_GLOBAL_REQUESTS_PER_HOUR'>;
const PROFILE = '/app/v1/profile', PUBLISH = `${PROFILE}/username`, RECIPIENT = /^\/app\/v1\/recipients\/([a-z][a-z0-9_]{4,29})$/;
export const isProfilePath = (path: string) => path === PROFILE || path === PUBLISH || RECIPIENT.test(path);
const headers = ['Authorization', 'Content-Type', ...Object.values(CLIENT_RELEASE_HEADERS)];
function object(value: unknown, keys: string[]) {
  if (!value || typeof value !== 'object' || Array.isArray(value) || Object.keys(value).length !== keys.length
    || keys.some(key => !Object.hasOwn(value, key))) throw new RegistrationError('INVALID_REGISTRATION');
  return value as Record<string, unknown>;
}

export async function profileRoute(request: Request, env: Bindings, manifest: Environment, profiles: ReceivingProfiles) {
  let config: Environment;
  try { config = validateIdentityConfig(env, manifest); }
  catch { return v3Json(503, { error_code: 'SERVICE_UNAVAILABLE' }); }
  const url = new URL(request.url), origin = request.headers.get('Origin');
  if (url.origin !== config.api_origin || origin !== config.web_origin) return v3Json(403, { error_code: 'ORIGIN_NOT_ALLOWED' });
  const respond = (status: number, body: object) => v3Json(status, body, origin);
  if (!isProfilePath(url.pathname)) return respond(404, { error_code: 'NOT_FOUND' });
  const recipient = RECIPIENT.exec(url.pathname), publishing = url.pathname === PUBLISH;
  const method = allowMethods(request, origin, recipient ? ['GET'] : publishing ? ['POST'] : ['GET', 'POST'], headers);
  if (method) return method;
  if (recipient ? [...url.searchParams.keys()].some(key => key !== 'network_id') || url.searchParams.getAll('network_id').length !== 1 : !!url.search) {
    return respond(400, { error_code: 'INVALID_REQUEST' });
  }
  if (request.method === 'POST') {
    const incompatible = requireCurrentProtocol(request, config, 'identity'); if (incompatible) return incompatible;
  }
  const signal = AbortSignal.any([request.signal, AbortSignal.timeout(40_000)]), scope = { rpId: config.webauthn_rp_id, origin };
  async function lookupQuota() {
    const ip = request.headers.get('CF-Connecting-IP') ?? '';
    if (!isIP(ip)) return respond(403, { error_code: 'CLIENT_IP_UNAVAILABLE' });
    if (!env.AUTH_RATE_LIMIT_PEPPER || env.AUTH_RATE_LIMIT_PEPPER.length < 32) throw new Error('Lookup limits unavailable');
    const key = await privateLimitKey(env, 'ip', `recipient:${isIP(ip) === 6 ? new URL(`http://[${ip}]`).hostname : ip}`), now = Math.floor(Date.now() / 1000);
    if (!await consumeLimit(env.WALLET_DB, 'ip', key, now, authLimit(env.PUBLIC_LOOKUP_IP_REQUESTS_PER_HOUR))
      || !await consumeLimit(env.WALLET_DB, 'global', 'recipients', now, authLimit(env.PUBLIC_LOOKUP_GLOBAL_REQUESTS_PER_HOUR))) {
      return respond(429, { error_code: 'RATE_LIMITED' });
    }
    return null;
  }
  try {
    if (recipient) {
      if (request.headers.has('Authorization') || request.headers.has('Cookie')) return respond(400, { error_code: 'INVALID_REQUEST' });
      let network;
      try { network = parseNetworkId(url.searchParams.get('network_id')); }
      catch { return respond(400, { error_code: 'INVALID_REQUEST' }); }
      if (!config.wallet_enabled.includes(network)) return respond(404, { error_code: 'NOT_FOUND' });
      const limited = await lookupQuota(); if (limited) return limited;
      return respond(200, await resolveRecipient(env.WALLET_DB, scope, recipient[1], network, profiles, signal));
    }
    const principal = await verifyAppSession(request, env, { rpId: config.webauthn_rp_id, origin: config.web_origin }, profiles);
    const repo = new ProfileRepository(env.WALLET_DB, principal, scope, profiles);
    if (request.method === 'GET') return respond(200, await repo.read());
    if (!isJsonRequest(request)) return respond(400, { error_code: 'INVALID_REQUEST' });
    let input: Record<string, unknown>;
    try {
      input = object(await readJsonBounded(new Response(request.body, { headers: request.headers }), 1024, signal),
        publishing ? ['username', 'wallet_id', 'wallet_account_id'] : ['display_name']);
      if (publishing) { parseResourceId('wallet', input.wallet_id); parseResourceId('walletAccount', input.wallet_account_id); }
    } catch (error) { return respond(error instanceof ResponseBodyTooLargeError ? 413 : 400, { error_code: 'INVALID_REQUEST' }); }
    signal.throwIfAborted();
    if (publishing) { const limited = await lookupQuota(); if (limited) return limited; }
    return respond(200, publishing ? await repo.publish({ username: input.username, wallet_id: input.wallet_id, wallet_account_id: input.wallet_account_id }, signal)
      : await repo.rename(input.display_name));
  } catch (error) {
    if (error instanceof IdentityError) return respond(error.code === 'UNAUTHENTICATED' ? 401 : 503, { error_code: error.code });
    if (error instanceof WalletAccessError) return respond(error.code === 'NOT_FOUND' ? 404 : error.code === 'UNAUTHENTICATED' ? 401 : error.code === 'SESSION_REQUIRED' ? 409 : 503, { error_code: error.code });
    if (error instanceof RegistrationError) return respond(error.code === 'INVALID_REGISTRATION' ? 400 : 409, { error_code: error.code });
    if (error instanceof ProfileError) return respond(error.code === 'RECEIVING_UNAVAILABLE' ? 503 : 409, { error_code: error.code });
    return respond(503, { error_code: 'SERVICE_UNAVAILABLE' });
  }
}
