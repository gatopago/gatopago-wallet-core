import { isIP } from 'node:net';
import type { Environment } from '@gatopago/environment';
import { readJsonBounded, ResponseBodyTooLargeError } from '@gatopago/shared/http';
import { parseResourceId } from '@gatopago/shared/v3/primitives';
import { CLIENT_RELEASE_HEADERS } from '@gatopago/shared/v3/client-release';
import { validateAuthConfig, authLimit, type AuthBindings } from './config';
import { consumeLimit, privateLimitKey } from './limits';
import { verifyHuman } from './providers';
import { RegistrationRepository } from './registration';
import { RegistrationError } from './profile';
import { LoginRepository } from './login';
import { refreshUserAccess } from './access';
import { unavailableAccessProfiles } from './session';
import type { ReceivingProfiles } from '../accounts/profile';
import { createSessionToken } from './customToken';
import { IdentityError } from './identity';
import { EnrollmentError } from '../enrollment/verification';
import { requireCompatibleMutation } from '../clientCompatibility';
import { allowMethods, isJsonRequest, v3Json } from '../http';

const paths = ['/app/v1/auth/register/options', '/app/v1/auth/register/complete',
  '/app/v1/auth/login/options', '/app/v1/auth/login/complete'];
export const isAuthPath = (path: string) => paths.includes(path);
const allowedHeaders = ['Content-Type', ...Object.values(CLIENT_RELEASE_HEADERS)];

function object(value: unknown, fields: string[]): Record<string, unknown> {
  if (!value || typeof value !== 'object' || Array.isArray(value) || Object.keys(value).length !== fields.length
    || !fields.every(field => Object.hasOwn(value, field))) throw new RegistrationError('INVALID_REGISTRATION');
  return value as Record<string, unknown>;
}

export async function authRoute(request: Request, env: AuthBindings, manifest: Environment, accessProfiles: ReceivingProfiles = unavailableAccessProfiles): Promise<Response> {
  let config: Environment;
  try { config = validateAuthConfig(env, manifest); }
  catch { return v3Json(503, { error_code: 'SERVICE_UNAVAILABLE' }); }
  const url = new URL(request.url), origin = request.headers.get('Origin');
  if (url.origin !== config.api_origin || origin !== config.web_origin || !config.webauthn_allowed_origins.includes(origin)) {
    return v3Json(403, { error_code: 'ORIGIN_NOT_ALLOWED' });
  }
  const respond = (status: number, body: object) => v3Json(status, body, origin);
  if (!isAuthPath(url.pathname) || url.search) return respond(404, { error_code: 'NOT_FOUND' });
  const methods = allowMethods(request, origin, ['POST'], allowedHeaders);
  if (methods) return methods;
  const incompatible = requireCompatibleMutation(request, config, 'identity');
  if (incompatible) return incompatible;
  if (!isJsonRequest(request) || request.headers.has('Authorization') || request.headers.has('Cookie')) {
    return respond(400, { error_code: 'INVALID_REQUEST' });
  }
  const rawIp = request.headers.get('CF-Connecting-IP') ?? '';
  if (!isIP(rawIp)) return respond(403, { error_code: 'CLIENT_IP_UNAVAILABLE' });
  const ip = isIP(rawIp) === 6 ? new URL(`http://[${rawIp}]`).hostname : rawIp;
  const signal = AbortSignal.any([request.signal, AbortSignal.timeout(10000)]);
  try {
    const now = Math.floor(Date.now() / 1000), key = await privateLimitKey(env, 'ip', ip);
    if (!await consumeLimit(env.WALLET_DB, 'ip', key, now, authLimit(env.AUTH_IP_REQUESTS_PER_HOUR))
      || !await consumeLimit(env.WALLET_DB, 'global', 'all', now, authLimit(env.AUTH_GLOBAL_REQUESTS_PER_HOUR))) {
      return respond(429, { error_code: 'RATE_LIMITED' });
    }
    let body: unknown;
    try { body = await readJsonBounded(new Response(request.body, { headers: request.headers }), 24576, signal); }
    catch (error) { return respond(error instanceof ResponseBodyTooLargeError ? 413 : 400, { error_code: 'INVALID_REQUEST' }); }
    signal.throwIfAborted();
    const scope = { rpId: config.webauthn_rp_id, origin };
    if (url.pathname === paths[0]) {
      const input = object(body, ['invite', 'name', 'username', 'turnstile_token']);
      if (typeof input.turnstile_token !== 'string' || input.turnstile_token.length < 1 || input.turnstile_token.length > 2048) {
        return respond(400, { error_code: 'INVALID_REQUEST' });
      }
      if (!await verifyHuman(env, config, input.turnstile_token, rawIp, signal)) return respond(403, { error_code: 'HUMAN_VERIFY_FAILED' });
      signal.throwIfAborted();
      return respond(200, await new RegistrationRepository(env.WALLET_DB, config.environment, scope)
        .prepare({ invite: input.invite, name: input.name, username: input.username }));
    }
    const login = new LoginRepository(env.WALLET_DB, scope, userId => refreshUserAccess(env.WALLET_DB, userId, config.environment, scope, accessProfiles, signal));
    if (url.pathname === paths[2]) {
      object(body, []);
      return respond(200, await login.prepare());
    }
    const input = object(body, ['request_id', 'response']);
    let requestId;
    try { requestId = parseResourceId('operation', input.request_id); }
    catch { return respond(400, { error_code: 'INVALID_REQUEST' }); }
    const principal = url.pathname === paths[1]
      ? await new RegistrationRepository(env.WALLET_DB, config.environment, scope).complete(requestId, input.response)
      : await login.complete(requestId, input.response);
    signal.throwIfAborted();
    const token = await createSessionToken(env.FIREBASE_CUSTOM_TOKEN_SIGNER_JSON, env.FIREBASE_PROJECT_ID, principal);
    signal.throwIfAborted();
    return respond(200, { custom_token: token });
  } catch (error) {
    if (error instanceof RegistrationError) return respond(error.code === 'INVALID_REGISTRATION' ? 400 : 409, { error_code: error.code });
    if (error instanceof IdentityError) return respond(error.code === 'UNAUTHENTICATED' ? 401 : 503, { error_code: error.code });
    if (error instanceof EnrollmentError) return respond(400, { error_code: 'INVALID_PASSKEY' });
    return respond(503, { error_code: 'SERVICE_UNAVAILABLE' });
  }
}
