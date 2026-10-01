import { afterEach, describe, expect, it, vi } from 'vitest';
import { environmentFromVariables } from '@gatopago/environment';
import { configuredEnvironment, validateAuthConfig, type AuthBindings } from '../src/auth/config';
import { verifyHuman } from '../src/auth/providers';

const variables = { GATOPAGO_ENVIRONMENT: 'staging', GATOPAGO_WEB_ORIGIN: 'http://localhost:3000',
  GATOPAGO_API_ORIGIN: 'http://localhost:8787', GATOPAGO_BUSINESS_ORIGIN: 'http://localhost:3000',
  GATOPAGO_WALLET_NETWORKS: 'eip155:421614', FIREBASE_PROJECT_ID: 'v3-local-test' };
const local = environmentFromVariables(variables);
const bindings = { ...variables, WALLET_DB: {} as D1Database, FIREBASE_CUSTOM_TOKEN_SIGNER_JSON: 'synthetic-test-signer',
  TURNSTILE_SECRET_KEY: '1x0000000000000000000000000000000AA', AUTH_RATE_LIMIT_PEPPER: 'synthetic-test-pepper-01234567890123456789',
  AUTH_IP_REQUESTS_PER_HOUR: '120', AUTH_GLOBAL_REQUESTS_PER_HOUR: '2000' } satisfies AuthBindings;
afterEach(() => vi.unstubAllGlobals());

describe('Configured authentication', () => {
  it('resolves Worker bindings and fails closed for missing URLs', () => {
    expect(configuredEnvironment(bindings)).toEqual(local);
    expect(() => configuredEnvironment({ ...bindings, GATOPAGO_API_ORIGIN: undefined })).toThrow();
  });
  it('allows the documented Turnstile test key only when both origins are loopback', () => {
    expect(validateAuthConfig(bindings, local)).toEqual(local);
    expect(() => validateAuthConfig(bindings, { ...local, api_origin: 'https://api.example.test' })).toThrow();
  });
  it('still calls Siteverify and rejects failed test tokens', async () => {
    const mock = vi.fn(async () => Response.json({ success: true, hostname: 'example.com', metadata: { result_with_testing_key: true } }));
    vi.stubGlobal('fetch', mock);
    const signal = new AbortController().signal;
    expect(await verifyHuman(bindings, local, 'XXXX.DUMMY.TOKEN.XXXX', '127.0.0.1', signal)).toBe(true);
    expect(mock).toHaveBeenCalledOnce();
    mock.mockResolvedValue(Response.json({ success: false }));
    expect(await verifyHuman(bindings, local, 'invalid', '127.0.0.1', signal)).toBe(false);
    mock.mockResolvedValue(Response.json({ success: true, hostname: 'example.com', metadata: { result_with_testing_key: true } }));
    expect(await verifyHuman(bindings, { ...local, api_origin: 'https://api.example.test' }, 'dummy', '127.0.0.1', signal)).toBe(false);
  });
});
