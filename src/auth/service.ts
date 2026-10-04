import { WorkerEntrypoint } from 'cloudflare:workers';
import type { Environment } from '@gatopago/environment';
import { WalletAccessError } from '../accounts/repository';
import { configuredEnvironment, validateIdentityConfig } from './config';
import { IdentityError } from './identity';
import { verifyAppSession } from './session';
import { createWalletRuntime } from '../runtime';
import catalog from '../runtime/catalog';
import type { ReceivingProfiles } from '../accounts/profile';

export async function identityService(
  request: Request,
  env: WalletCoreV3Bindings,
  environment: (env: WalletCoreV3Bindings) => Environment = configuredEnvironment,
  profiles?: ReceivingProfiles,
): Promise<Response> {
  const reply = (body: object, status = 200) =>
    Response.json(body, { status, headers: { 'Cache-Control': 'no-store' } });
  if (request.url !== 'https://wallet-identity.internal/session' || request.method !== 'POST') {
    return reply({ error_code: 'NOT_FOUND' }, 404);
  }
  if (request.body !== null || request.headers.has('Cookie') || request.headers.has('Origin')) {
    return reply({ error_code: 'UNAUTHENTICATED' }, 401);
  }
  try {
    const config = validateIdentityConfig(env, environment(env));
    if (request.headers.get('X-GatoPago-Environment') !== config.environment) {
      return reply({ error_code: 'IDENTITY_UNAVAILABLE' }, 503);
    }
    const identity = await verifyAppSession(
      request,
      env,
      { rpId: config.webauthn_rp_id, origin: config.web_origin },
      profiles ??
        ((owned, signal) =>
          createWalletRuntime(env, config, catalog(config)).receivingProfiles(owned, signal)),
    );
    return reply({
      user_id: identity.userId,
      environment: config.environment,
      expires_at: identity.expiresAt,
    });
  } catch (error) {
    if (
      (error instanceof IdentityError && error.code === 'UNAUTHENTICATED') ||
      (error instanceof WalletAccessError &&
        ['UNAUTHENTICATED', 'SESSION_REQUIRED'].includes(error.code))
    ) {
      return reply({ error_code: 'UNAUTHENTICATED' }, 401);
    }
    return reply({ error_code: 'IDENTITY_UNAVAILABLE' }, 503);
  }
}

export class WalletIdentity extends WorkerEntrypoint<WalletCoreV3Bindings> {
  override fetch(request: Request): Promise<Response> {
    return identityService(request, this.env);
  }
}
