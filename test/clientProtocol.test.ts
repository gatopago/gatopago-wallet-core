import { describe, expect, it } from 'vitest';
import {
  CLIENT_COMPATIBILITY_PATH,
  CLIENT_RELEASE_HEADERS,
  CLIENT_RELEASE_ID,
  WALLET_API_VERSION,
  clientMutationHeaders,
} from '@gatopago/shared/v3/client-release';
import { clientProtocolRoute, requireCurrentProtocol } from '../src/clientProtocol';
import { runtimeFixture } from './runtime.fixture';

const config = runtimeFixture().environment;
const account = { generation: '3', contract_manifest_version: 'evm-v3-r1' };
const request = (headers: HeadersInit = clientMutationHeaders(config.environment)) =>
  new Request(config.api_origin, { headers });

describe('current client protocol only', () => {
  it('accepts the current identity protocol without enabling a contract', () => {
    expect(requireCurrentProtocol(request(), config, 'identity')).toBeNull();
    expect(requireCurrentProtocol(request(), config, 'account')?.status).toBe(503);
  });
  it.each(['web-v3-e2-r0', 'wallet-client-v3.0', 'v3-test', CLIENT_RELEASE_ID + '-extra', ''])(
    'rejects the obsolete or unknown revision %s',
    (revision) => {
      const headers = new Headers(clientMutationHeaders(config.environment));
      headers.set(CLIENT_RELEASE_HEADERS.release, revision);
      expect(requireCurrentProtocol(request(headers), config, 'identity')?.status).toBe(409);
    },
  );
  it.each(['api', 'environment', 'generation', 'manifest'] as const)(
    'rejects a mismatched %s header',
    (field) => {
      const headers = new Headers(clientMutationHeaders(config.environment));
      headers.set(CLIENT_RELEASE_HEADERS[field], 'unknown');
      expect(requireCurrentProtocol(request(headers), config, 'identity')?.status).toBe(409);
    },
  );
  it('accepts only generation 3 paired with a pinned current manifest', () => {
    const headers = new Headers(clientMutationHeaders(config.environment, account));
    expect(
      requireCurrentProtocol(request(headers), config, 'account', [
        account.contract_manifest_version,
      ]),
    ).toBeNull();
    expect(requireCurrentProtocol(request(headers), config, 'identity')?.status).toBe(409);
    for (const generation of ['2', '4']) {
      headers.set(CLIENT_RELEASE_HEADERS.generation, generation);
      expect(
        requireCurrentProtocol(request(headers), config, 'account', [
          account.contract_manifest_version,
        ])?.status,
      ).toBe(409);
    }
    headers.set(CLIENT_RELEASE_HEADERS.generation, '3');
    expect(
      requireCurrentProtocol(request(headers), config, 'account', ['another-manifest'])?.status,
    ).toBe(409);
  });
  it('declares a single fixed protocol without an acceptance window', async () => {
    const input = new Request(config.api_origin + CLIENT_COMPATIBILITY_PATH);
    const response = (await clientProtocolRoute(input, config, [account]).json()) as {
      account_profiles: (typeof account)[];
    };
    expect(response).toMatchObject({
      api_version: WALLET_API_VERSION,
      minimum_mutating_release: CLIENT_RELEASE_ID,
      accepted_mutating_releases: [CLIENT_RELEASE_ID],
      account_profiles: [account],
    });
    response.account_profiles[0].generation = '2';
    expect(account.generation).toBe('3');
  });
  it.each(['origin', 'query', 'path', 'method'])(
    'validates the public declaration boundary: %s',
    (fault) => {
      const input = new Request(
        config.api_origin +
          (fault === 'path' ? '/unknown' : CLIENT_COMPATIBILITY_PATH) +
          (fault === 'query' ? '?legacy=true' : ''),
        {
          method: fault === 'method' ? 'POST' : 'GET',
          headers: fault === 'origin' ? { Origin: 'https://unknown.invalid' } : {},
        },
      );
      expect(clientProtocolRoute(input, config, [account]).status).toBe(
        fault === 'origin' ? 403 : fault === 'method' ? 405 : 404,
      );
    },
  );
});
