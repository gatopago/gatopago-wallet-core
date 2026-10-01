import { discardResponseBody, readJsonBounded } from '@gatopago/shared/http';
import { isLocalEnvironment, type Environment } from '@gatopago/environment';
import type { AuthBindings } from './config';

function record(value: unknown): value is Record<string, unknown> {
  return value !== null && typeof value === 'object' && !Array.isArray(value);
}

export async function verifyHuman(env: AuthBindings, config: Environment, token: string,
  ip: string, signal: AbortSignal): Promise<boolean> {
  const deadline = AbortSignal.any([signal, AbortSignal.timeout(3000)]);
  const response = await fetch('https://challenges.cloudflare.com/turnstile/v0/siteverify', {
    method: 'POST', redirect: 'manual', signal: deadline,
    body: new URLSearchParams({ secret: env.TURNSTILE_SECRET_KEY, response: token, remoteip: ip }),
  });
  if (!response.ok) { await discardResponseBody(response); throw new Error('Siteverify unavailable'); }
  const data = await readJsonBounded<unknown>(response, 16 * 1024, deadline);
  if (isLocalEnvironment(config) && env.TURNSTILE_SECRET_KEY === '1x0000000000000000000000000000000AA') {
    // Test keys return canned metadata, not the widget's hostname/action.
    return record(data) && data.success === true;
  }
  return record(data) && data.success === true && data.action === 'signup' &&
    data.hostname === new URL(config.web_origin).hostname;
}
