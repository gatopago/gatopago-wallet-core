import type { Environment } from '@gatopago/environment';
import { parseResourceId } from '@gatopago/shared/v3/primitives';
import { CLIENT_RELEASE_HEADERS } from '@gatopago/shared/v3/client-release';
import { readJsonBounded, ResponseBodyTooLargeError } from '@gatopago/shared/http';
import { validateIdentityConfig, type AuthBindings } from '../auth/config';
import { IdentityError } from '../auth/identity';
import { verifyAppSession } from '../auth/session';
import type { ReceivingProfiles } from '../accounts/profile';
import { requireCurrentProtocol } from '../clientProtocol';
import { allowMethods, isJsonRequest, v3Json } from '../http';
import { WalletAccessError } from '../accounts/repository';
import { EnrollmentRepository } from './repository';
import { EnrollmentError, verifyEnrollment } from './verification';

const ROOT = '/app/v1/security/enrollments';
const CREDENTIALS = '/app/v1/security/credentials';
const headers = ['Authorization', 'Content-Type', ...Object.values(CLIENT_RELEASE_HEADERS)];
function credentialReference(path: string) {
  if (!path.startsWith(`${CREDENTIALS}/`)) return null;
  try {
    return parseResourceId('operation', path.slice(CREDENTIALS.length + 1));
  } catch {
    return null;
  }
}
export function isEnrollmentPath(path: string) {
  return (
    path === CREDENTIALS ||
    credentialReference(path) !== null ||
    path === ROOT ||
    /^\/app\/v1\/security\/enrollments\/[^/]+\/complete$(?![\s\S])/.test(path)
  );
}

/** No account provisioning/authorization here. A registered public credential
 * must separately sign Account V3's typed InitializationApproval/EnrollmentProof.
 */
export async function enrollmentRoute(
  request: Request,
  env: AuthBindings,
  manifest: Environment,
  accessProfiles?: ReceivingProfiles,
): Promise<Response> {
  let config: Environment;
  try {
    config = validateIdentityConfig(env, manifest);
  } catch {
    return v3Json(503, { error_code: 'SERVICE_UNAVAILABLE' });
  }
  const url = new URL(request.url),
    origin = request.headers.get('Origin');
  if (
    url.origin !== config.api_origin ||
    origin !== config.web_origin ||
    !config.webauthn_allowed_origins.includes(origin)
  ) {
    return v3Json(403, { error_code: 'ORIGIN_NOT_ALLOWED' });
  }
  const respond = (status: number, body: object) => v3Json(status, body, origin);
  if (!isEnrollmentPath(url.pathname) || url.search)
    return respond(404, { error_code: 'NOT_FOUND' });
  const reference = credentialReference(url.pathname);
  const method = url.pathname === CREDENTIALS || reference !== null ? 'GET' : 'POST';
  const methodResponse = allowMethods(request, origin, [method], headers);
  if (methodResponse) return methodResponse;
  // Identity-level enrollment does not smuggle in a usable contract manifest.
  if (method === 'POST') {
    const incompatible = requireCurrentProtocol(request, config, 'identity');
    if (incompatible) return incompatible;
    if (!isJsonRequest(request)) return respond(400, { error_code: 'INVALID_ENROLLMENT' });
  }
  try {
    const principal = await verifyAppSession(
      request,
      env,
      { rpId: config.webauthn_rp_id, origin: config.web_origin },
      accessProfiles,
    );
    const repository = new EnrollmentRepository(env.WALLET_DB, principal, {
      rpId: config.webauthn_rp_id,
      origin,
    });
    if (method === 'GET') {
      request.signal.throwIfAborted();
      const inventory =
        reference === null
          ? await repository.credentials()
          : await repository.credential(reference);
      request.signal.throwIfAborted();
      return respond(200, inventory);
    }
    let body: unknown;
    try {
      body = await readJsonBounded<unknown>(
        new Response(request.body, { headers: request.headers }),
        24576,
        AbortSignal.any([request.signal, AbortSignal.timeout(5000)]),
      );
    } catch (error) {
      return respond(error instanceof ResponseBodyTooLargeError ? 413 : 400, {
        error_code: 'INVALID_ENROLLMENT',
      });
    }
    request.signal.throwIfAborted();
    if (url.pathname === ROOT) {
      let id;
      try {
        if (
          !body ||
          typeof body !== 'object' ||
          Array.isArray(body) ||
          Object.keys(body).length !== 1 ||
          !('request_id' in body)
        )
          throw new Error();
        id = parseResourceId('operation', body.request_id);
      } catch {
        return respond(400, { error_code: 'INVALID_ENROLLMENT' });
      }
      return respond(200, await repository.prepare(id));
    }
    let id;
    try {
      id = parseResourceId('operation', url.pathname.split('/')[5]);
    } catch {
      return respond(400, { error_code: 'INVALID_ENROLLMENT' });
    }
    const attempt = await repository.read(id);
    if (attempt.completedAt === null && Math.floor(Date.now() / 1000) >= attempt.expiresAt)
      throw new EnrollmentError('ENROLLMENT_EXPIRED');
    const result = await verifyEnrollment(body, attempt);
    request.signal.throwIfAborted();
    return respond(200, await repository.complete(id, result));
  } catch (error) {
    if (error instanceof EnrollmentError) {
      const status = {
        INVALID_ENROLLMENT: 400,
        ENROLLMENT_EXPIRED: 410,
        ENROLLMENT_CONFLICT: 409,
        ENROLLMENT_LIMIT: 429,
      }[error.code];
      return respond(status, { error_code: error.code });
    }
    if (error instanceof IdentityError)
      return respond(error.code === 'UNAUTHENTICATED' ? 401 : 503, { error_code: error.code });
    if (error instanceof WalletAccessError)
      return respond(
        { UNAUTHENTICATED: 401, SESSION_REQUIRED: 409, NOT_FOUND: 404, WALLET_DATA_INVALID: 503 }[
          error.code
        ],
        { error_code: error.code },
      );
    return respond(503, { error_code: 'SERVICE_UNAVAILABLE' });
  }
}
