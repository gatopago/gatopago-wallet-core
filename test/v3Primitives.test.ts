import { describe, expect, it } from 'vitest';
import {
  assertAssetNetwork,
  createResourceId,
  evmChainId,
  parseAtomicAmount,
  parseEvmAssetId,
  parseNetworkId,
  parseResourceId,
  resourcePrefixes,
  UINT256_MAX,
} from '@gatopago/shared/v3/primitives';

describe('V3 identity and monetary wire primitives', () => {
  it('keeps resource identities separate from login subjects and addresses', () => {
    for (const kind of Object.keys(resourcePrefixes) as (keyof typeof resourcePrefixes)[]) {
      const id = createResourceId(kind);
      expect(parseResourceId(kind, id)).toBe(id);
      expect(() => parseResourceId(kind, 'firebase-subject')).toThrow();
      expect(() => parseResourceId(kind, `0x${'ab'.repeat(20)}`)).toThrow();
    }
    expect(() => parseResourceId('wallet', createResourceId('party'))).toThrow();
  });

  it.each(['0', '1', '14358946875', UINT256_MAX.toString()])(
    'retains exact atomic amount %s',
    (value) => {
      expect(parseAtomicAmount(value)).toBe(value);
    },
  );

  it.each([
    1,
    0.1,
    -1,
    '-1',
    '1.0',
    '01',
    '1e18',
    ' 1',
    '1\n',
    '+1',
    '',
    (UINT256_MAX + 1n).toString(),
  ])('rejects lossy or ambiguous amount %s', (value) => {
    expect(() => parseAtomicAmount(value)).toThrow();
  });

  it('represents other ecosystems without pretending to execute them', () => {
    expect(parseNetworkId('stellar:pubnet')).toBe('stellar:pubnet');
    expect(() => evmChainId('stellar:pubnet')).toThrow('Unsupported');
    expect(evmChainId('eip155:84532')).toBe(84532n);
  });

  it.each(['eip155:0', 'eip155:01', 'eip155:1e3', 'eip155:-1', '84532', 'eip155:1/erc20:0x00'])(
    'rejects ambiguous network %s',
    (value) => {
      expect(() => parseNetworkId(value)).toThrow();
    },
  );

  it('does not aggregate or confuse the same token address across chains', () => {
    const token = `eip155:84532/erc20:0x${'ab'.repeat(20)}`;
    expect(parseEvmAssetId(token)).toBe(token);
    expect(() => assertAssetNetwork(token, 'eip155:421614')).toThrow();
    expect(() => parseEvmAssetId(token.toUpperCase())).toThrow();
    expect(parseEvmAssetId('eip155:43113/slip44:9000')).toContain('9000');
    expect(parseEvmAssetId(`eip155:84532/erc721:0x${'ab'.repeat(20)}/42`)).toContain('/42');
    expect(() => parseEvmAssetId(`eip155:84532/erc721:0x${'ab'.repeat(20)}`)).toThrow();
  });
});
