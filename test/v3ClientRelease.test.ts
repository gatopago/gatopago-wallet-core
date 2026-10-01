import { describe, expect, it } from 'vitest';
import { CLIENT_RELEASE_HEADERS, CLIENT_RELEASE_ID, WALLET_RELEASE_POLICY, clientMutationHeaders, isClientUpdateError, mutationCompatibility, publicClientCompatibility,  } from '@gatopago/shared/v3/client-release';

const current = () => new Headers(clientMutationHeaders('staging'));
const policy = WALLET_RELEASE_POLICY;
describe('V3 client release compatibility is not monetary authorization', () => {
  it('permits the current identity protocol but enables no contract profiles', () => {
    expect(mutationCompatibility(current(), 'staging', 'identity', policy, 1000)).toBe('compatible');
    expect(mutationCompatibility(current(), 'staging', 'account', policy, 1000)).toBe('account-unavailable');
    expect(publicClientCompatibility('staging', policy, 1000).account_profiles).toEqual([]);
  });
  it('does not infer version ordering from numbers, arbitrary strings or prefixes', () => {
    for (const id of ['web-v3-e2-r999', CLIENT_RELEASE_ID + '-extra', '', 'x'.repeat(81)]) {
      const headers = current(); headers.set(CLIENT_RELEASE_HEADERS.release, id);
      expect(mutationCompatibility(headers, 'staging', 'identity', policy, 1000)).toBe('update-required');
    }
  });
  it('expires an explicitly allowed N-1 release at its exact deadline without changing newer acceptance', () => {
    const next = { ...policy, releases: [
      { client_release_id: 'web-v3-e2-r0', accepted_until: 1100 }, ...policy.releases,
    ] };
    const headers = current(); headers.set(CLIENT_RELEASE_HEADERS.release, 'web-v3-e2-r0');
    expect(mutationCompatibility(headers, 'staging', 'identity', next, 1099)).toBe('compatible');
    expect(publicClientCompatibility('staging', next, 1099).minimum_mutating_release).toBe('web-v3-e2-r0');
    expect(mutationCompatibility(headers, 'staging', 'identity', next, 1100)).toBe('update-required');
    expect(publicClientCompatibility('staging', next, 1100).minimum_mutating_release).toBe(CLIENT_RELEASE_ID);
    expect(mutationCompatibility(current(), 'staging', 'identity', next, 1100)).toBe('compatible');
  });
  it('allows revocation of every mutation release, including the current one', () => {
    const revoked = { ...policy, releases: [] };
    expect(mutationCompatibility(current(), 'staging', 'identity', revoked, 1000)).toBe('update-required');
    expect(publicClientCompatibility('staging', revoked, 1000).minimum_mutating_release).toBeNull();
  });
  it('requires generation and manifest as a pair, never mixes two supported profiles', () => {
    // Synthetic profiles prove matching only; no endpoint, contract or network is enabled.
    const profiles = { ...policy, account_profiles: [
      { generation: '3', contract_manifest_version: 'evm-v3-r1' },
      { generation: '4', contract_manifest_version: 'evm-v4-r1' },
    ] };
    const headers = new Headers(clientMutationHeaders('staging', profiles.account_profiles[0]));
    expect(mutationCompatibility(headers, 'staging', 'account', profiles, 1000)).toBe('compatible');
    expect(mutationCompatibility(headers, 'staging', 'identity', profiles, 1000)).toBe('update-required');
    headers.set(CLIENT_RELEASE_HEADERS.manifest, 'evm-v4-r1');
    expect(mutationCompatibility(headers, 'staging', 'account', profiles, 1000)).toBe('update-required');
    expect(mutationCompatibility(current(), 'staging', 'account', profiles, 1000)).toBe('update-required');
  });
  it.each([NaN, Infinity, -1, 1000.5])('fails closed with invalid clock %s', (now) => {
    expect(mutationCompatibility(current(), 'staging', 'identity', policy, now)).toBe('update-required');
  });
  it('does not share a mutable policy response between requests', () => {
    const response = publicClientCompatibility('staging', policy, 1000);
    response.accepted_mutating_releases.length = 0;
    expect(publicClientCompatibility('staging', policy, 1000).accepted_mutating_releases).toEqual([CLIENT_RELEASE_ID]);
  });
  it('recognizes only its own error category, without displaying arbitrary provider text', () => {
    expect(isClientUpdateError({ code: 'client/update-required' })).toBe(true);
    for (const other of [null, 'client/update-required', {}, { code: 'auth/unknown' }]) expect(isClientUpdateError(other)).toBe(false);
  });
});
