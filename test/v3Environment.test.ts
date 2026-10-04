import { describe, expect, it } from 'vitest';
import environments from '@gatopago/environment/environments.json';
import {
  environmentFromVariables,
  apiRouteOwner,
  assertProvisioned,
  parseEnvironment,
} from '@gatopago/environment';

describe('V3 environments and resource routing', () => {
  it('exposes only production, with Arbitrum Sepolia and live payments disabled', () => {
    const production = parseEnvironment(environments.production);
    expect(Object.keys(environments)).toEqual(['production']);
    expect(production.wallet_candidates).toHaveLength(3);
    expect(production.blockchain_tiers).toEqual(['testnet']);
    expect(production.api_modes).toEqual(['test']);
    expect(production.payment_live_enabled).toBe(false);
    expect(production.wallet_enabled).toEqual(['eip155:421614']);
    expect(production.firebase_project_id).toBe('proyecto-prueba-push-firebase');
    expect(() => assertProvisioned(production)).not.toThrow();
  });

  it.each([
    { environment: 'unsupported' },
    { webauthn_rp_id: 'other.test' },
    { webauthn_allowed_origins: ['https://other.gatopago.com'] },
    { webauthn_allowed_origins: ['https://*.vercel.app'] },
    { payment_live_enabled: true },
    { api_modes: ['test', 'live'] },
    { blockchain_tiers: ['mainnet'] },
    { firebase_project_id: 'v3-runtime-test', status: 'unprovisioned' },
    { wallet_enabled: ['eip155:1'] },
    { status: 'unprovisioned', firebase_project_id: null, wallet_enabled: ['eip155:421614'] },
    { unexpected_secret: 'must-not-be-here' },
  ])('rejects origin, mode and resource confusion %j', (override) => {
    expect(() => parseEnvironment({ ...environments.production, ...override })).toThrow();
  });

  it('rejects mutation access for unprovisioned resources', () => {
    const unavailable = parseEnvironment({
      ...environments.production,
      status: 'unprovisioned',
      firebase_project_id: null,
      wallet_enabled: [],
    });
    expect(() => assertProvisioned(unavailable)).toThrow('not provisioned');
  });

  it.each(['wallets', 'transfers'])(
    'routes the collection and children of %s to Wallet Core',
    (resource) => {
      for (const suffix of ['', '/', '/id', '/id/action'])
        expect(apiRouteOwner(`/v1/${resource}${suffix}`)).toBe('wallet-core');
    },
  );
  it.each([
    'health',
    'merchant',
    'organizations',
    'memberships',
    'projects',
    'customers',
    'settlement_accounts',
    'payment_links',
    'payment_intents',
    'quotes',
    'events',
    'webhook_endpoints',
  ])('routes %s to Flow', (resource) => {
    for (const suffix of ['', '/', '/id', '/id/action'])
      expect(apiRouteOwner(`/v1/${resource}${suffix}`)).toBe('flow-core');
  });
  it('does not create a catch-all writer or publish future financial products', () => {
    for (const route of [
      '/v1/unknown',
      '/v1/walletsFake',
      '/v1/financial_accounts',
      '/v1/payouts',
      '/v1/wallets/../payment_intents',
      '/v1/%77allets',
      '//app/v1',
      '/v1/wallets?tenant=other',
    ])
      expect(apiRouteOwner(route)).toBeNull();
    expect(apiRouteOwner('/app/v1/home')).toBe('wallet-core');
    expect(apiRouteOwner('/checkout/v1/link')).toBe('flow-core');
  });
});

describe('Environment variables', () => {
  const variables = {
    GATOPAGO_ENVIRONMENT: 'production',
    GATOPAGO_WEB_ORIGIN: 'http://localhost:3000',
    GATOPAGO_API_ORIGIN: 'http://localhost:8787',
    GATOPAGO_BUSINESS_ORIGIN: 'http://localhost:3000',
    GATOPAGO_WALLET_NETWORKS: 'eip155:421614',
    FIREBASE_PROJECT_ID: 'v3-local-test',
  };
  it('uses configured URLs and derives the passkey RP without a domain map', () => {
    const local = environmentFromVariables(variables);
    expect(local.web_origin).toBe(variables.GATOPAGO_WEB_ORIGIN);
    expect(local.api_origin).toBe(variables.GATOPAGO_API_ORIGIN);
    expect(local.webauthn_rp_id).toBe('localhost');
    const hosted = environmentFromVariables({
      ...variables,
      GATOPAGO_ENVIRONMENT: 'production',
      GATOPAGO_WEB_ORIGIN: 'https://wallet.example.org:8443',
      GATOPAGO_API_ORIGIN: 'https://api.example.org',
      GATOPAGO_BUSINESS_ORIGIN: 'https://business.example.org',
    });
    expect(hosted.webauthn_rp_id).toBe('wallet.example.org');
    expect(hosted.wallet_enabled).toEqual(['eip155:421614']);
  });
  it.each([
    'http://wallet.example.org',
    'https://wallet.example.org/',
    'https://user:pass@wallet.example.org',
    'https://wallet.example.org/path',
    'https://wallet.example.org?override=1',
    'https://wallet.example.org#fragment',
    'https://WALLET.example.org',
    'http://localhost.evil.test:3000',
    'http://127.0.0.1:3000',
  ])('rejects unsafe or noncanonical origin %s', (origin) => {
    expect(() => environmentFromVariables({ ...variables, GATOPAGO_WEB_ORIGIN: origin })).toThrow();
  });
  it('fails closed for missing configuration and duplicate networks', () => {
    expect(() =>
      environmentFromVariables({ ...variables, GATOPAGO_API_ORIGIN: undefined }),
    ).toThrow('GATOPAGO_API_ORIGIN');
    expect(() =>
      environmentFromVariables({
        ...variables,
        GATOPAGO_WALLET_NETWORKS: 'eip155:421614,eip155:421614',
      }),
    ).toThrow();
    const local = environmentFromVariables(variables);
    expect(() => parseEnvironment({ ...local, webauthn_rp_id: 'other.test' })).toThrow();
  });
});
