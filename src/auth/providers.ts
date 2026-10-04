import { discardResponseBody, readJsonBounded } from '@gatopago/shared/http';
import { isLocalEnvironment, type Environment } from '@gatopago/environment';
import type { AuthBindings } from './config';

function record(value: unknown): value is Record<string, unknown> {
  return value !== null && typeof value === 'object' && !Array.isArray(value);
}

export async function verifyHuman(
  env: AuthBindings,
  config: Environment,
  token: string,
  ip: string,
  signal: AbortSignal,
): Promise<boolean> {
  const deadline = AbortSignal.any([signal, AbortSignal.timeout(3000)]);
  const response = await fetch('https://challenges.cloudflare.com/turnstile/v0/siteverify', {
    method: 'POST',
    redirect: 'manual',
    signal: deadline,
    body: new URLSearchParams({ secret: env.TURNSTILE_SECRET_KEY, response: token, remoteip: ip }),
  });
  if (!response.ok) {
    await discardResponseBody(response);
    throw new Error('Siteverify unavailable');
  }
  const data = await readJsonBounded<unknown>(response, 16 * 1024, deadline);
  if (
    isLocalEnvironment(config) &&
    env.TURNSTILE_SECRET_KEY === '1x0000000000000000000000000000000AA'
  ) {
    return record(data) && data.success === true;
  }
  const result = record(data) ? data : {};
  const success = result.success === true;
  const actionMatches = result.action === 'signup';
  const hostnameMatches = result.hostname === new URL(config.web_origin).hostname;
  const accepted = success && actionMatches && hostnameMatches;

  if (!accepted) {
    const errors = Array.isArray(result['error-codes']) ? result['error-codes'] : [];

    console.warn({
      event: 'turnstile_verification_failed',
      success,
      action_matches: actionMatches,
      hostname_matches: hostnameMatches,
      error_codes: [
        'missing-input-secret',
        'invalid-input-secret',
        'missing-input-response',
        'invalid-input-response',
        'bad-request',
        'timeout-or-duplicate',
        'internal-error',
      ].filter((code) => errors.includes(code)),
    });
  }

  return accepted;
}
