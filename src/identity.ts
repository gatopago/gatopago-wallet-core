import { WorkerEntrypoint } from 'cloudflare:workers';
import { config } from './config';
import { HttpError, json } from './http';
import { authenticate } from './session';

/**
 * Service binding for GatoPago Flow: `POST https://wallet-identity.internal/session` with the user's
 * `Authorization` header returns who they are, valid for at most 30 seconds.
 */
export class WalletIdentity extends WorkerEntrypoint<Env> {
  override async fetch(request: Request): Promise<Response> {
    if (request.method !== 'POST' || request.url !== 'https://wallet-identity.internal/session')
      return json({ error_code: 'NOT_FOUND' }, 404);
    try {
      const settings = config(this.env);
      if (request.headers.get('X-GatoPago-Environment') !== settings.environment)
        return json({ error_code: 'IDENTITY_UNAVAILABLE' }, 503);
      const session = await authenticate(request, settings, { business: true });
      return json({
        user_id: session.userId,
        environment: settings.environment,
        expires_at: Math.min(session.expiresAt, Math.floor(Date.now() / 1000) + 30),
      });
    } catch (error) {
      if (error instanceof HttpError && error.status === 401)
        return json({ error_code: 'UNAUTHENTICATED' }, 401);
      console.error(error);
      return json({ error_code: 'IDENTITY_UNAVAILABLE' }, 503);
    }
  }
}
