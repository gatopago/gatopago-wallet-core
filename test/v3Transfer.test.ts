import { describe, expect, it } from 'vitest';
import { CLIENT_RELEASE_ID } from '@gatopago/shared/v3/client-release';
import { createResourceId, UINT256_MAX } from '@gatopago/shared/v3/primitives';
import {
  parseTransferRequest,
  resolveMaxTransfer,
  resolveTransferFunding,
} from '@gatopago/shared/v3/transfer';

const valid = () => ({
  schema_version: 1,
  generation: 3,
  wallet_id: createResourceId('wallet'),
  network_id: 'eip155:84532',
  asset_id: `eip155:84532/erc20:0x${'ab'.repeat(20)}`,
  destination: { address: `0x${'cd'.repeat(20)}`, address_type: 'evm_unknown' },
  amount: { kind: 'exact', amount_atomic: '1000000' },
  client_release_id: 'v3-e0-test',
});

describe('V3 transfer request and MAX', () => {
  it('resolves exact and MAX with separate native gas, scoped fees and account budget', () => {
    const request = parseTransferRequest({ ...valid(), amount: { kind: 'max' } });
    const budget = {
      wallet_id: request.wallet_id,
      asset_id: request.asset_id,
      asset_available_atomic: '1000',
      native_available_atomic: '100',
      maximum_native_gas_atomic: '100',
      platform_fee: { asset_id: request.asset_id, amount_atomic: '5' },
    };
    expect(resolveTransferFunding(request, budget)).toEqual({
      amount_atomic: '995',
      asset_debit_atomic: '1000',
      native_remaining_atomic: '0',
    });
    expect(() =>
      resolveTransferFunding(
        { ...request, amount: { kind: 'exact', amount_atomic: '1000' } },
        budget,
      ),
    ).toThrow();
    expect(() =>
      resolveTransferFunding(request, { ...budget, native_available_atomic: '99' }),
    ).toThrow();
    expect(() =>
      resolveTransferFunding(request, { ...budget, wallet_id: createResourceId('wallet') }),
    ).toThrow();
    expect(() =>
      resolveTransferFunding(request, {
        ...budget,
        platform_fee: { ...budget.platform_fee, asset_id: 'eip155:84532/slip44:60' },
      }),
    ).toThrow();
    expect(
      resolveTransferFunding(request, {
        ...budget,
        native_available_atomic: '0',
        maximum_native_gas_atomic: '0',
        platform_fee: { ...budget.platform_fee, amount_atomic: '0' },
      }).amount_atomic,
    ).toBe('1000');
  });
  it('reserves native gas once, refuses conflicting balances and preserves exact requested amount', () => {
    const request = parseTransferRequest({
      ...valid(),
      asset_id: 'eip155:84532/slip44:60',
      amount: { kind: 'max' },
    });
    const budget = {
      wallet_id: request.wallet_id,
      asset_id: request.asset_id,
      asset_available_atomic: '1000',
      native_available_atomic: '1000',
      maximum_native_gas_atomic: '100',
      platform_fee: { asset_id: request.asset_id, amount_atomic: '5' },
    };
    expect(resolveTransferFunding(request, budget)).toEqual({
      amount_atomic: '895',
      asset_debit_atomic: '1000',
      native_remaining_atomic: '0',
    });
    expect(
      resolveTransferFunding(
        { ...request, amount: { kind: 'exact', amount_atomic: '400' } },
        budget,
      ),
    ).toEqual({ amount_atomic: '400', asset_debit_atomic: '505', native_remaining_atomic: '495' });
    expect(() =>
      resolveTransferFunding(request, { ...budget, native_available_atomic: '1001' }),
    ).toThrow();
    expect(() =>
      resolveTransferFunding(request, {
        ...budget,
        platform_fee: { ...budget.platform_fee, amount_atomic: '1000' },
      }),
    ).toThrow();
  });
  it('accepts the real content-addressed web release and retains the API length boundary', () => {
    expect(
      parseTransferRequest({ ...valid(), client_release_id: CLIENT_RELEASE_ID }).client_release_id,
    ).toBe(CLIENT_RELEASE_ID);
    expect(
      parseTransferRequest({ ...valid(), client_release_id: 'a'.repeat(80) }).client_release_id,
    ).toHaveLength(80);
    for (const release of ['a'.repeat(81), '', 'a\n', 'a,b', ' a']) {
      expect(() => parseTransferRequest({ ...valid(), client_release_id: release })).toThrow();
    }
  });
  it('rejects inherited required fields and newline aliases', () => {
    expect(() => parseTransferRequest(Object.create(valid()))).toThrow();
    expect(() =>
      parseTransferRequest({ ...valid(), amount: { kind: 'exact', amount_atomic: '1\n' } }),
    ).toThrow();
    expect(() =>
      parseTransferRequest({
        ...valid(),
        destination: { address: `0x${'cd'.repeat(20)}\n`, address_type: 'evm_unknown' },
      }),
    ).toThrow();
  });
  it('validates before returning an isolated copy', () => {
    const input = valid();
    const result = parseTransferRequest(input);
    input.destination.address = `0x${'ee'.repeat(20)}`;
    expect(result.destination.address).not.toBe(input.destination.address);
  });
  it('represents MAX as intent, never as a fabricated balance', () => {
    expect(parseTransferRequest({ ...valid(), amount: { kind: 'max' } }).amount).toEqual({
      kind: 'max',
    });
    expect(() =>
      parseTransferRequest({ ...valid(), amount: { kind: 'max', amount_atomic: '1' } }),
    ).toThrow();
  });
  it.each([
    { generation: 2 },
    { network_id: 'eip155:421614' },
    { amount: { kind: 'exact', amount_atomic: 1 } },
    { amount: { kind: 'exact', amount_atomic: '0' } },
    { amount: { kind: 'exact', amount_atomic: (UINT256_MAX + 1n).toString() } },
    { tenant_id: 'untrusted' },
    { destination: { address: `0x${'00'.repeat(20)}`, address_type: 'evm_unknown' } },
  ])('rejects mismatched or ambiguous requests %j', (override) => {
    expect(() => parseTransferRequest({ ...valid(), ...override })).toThrow();
  });
  it('sends all ERC20 units when fee is zero, without subtracting native gas', () => {
    expect(resolveMaxTransfer('14358946875', false, '9000000000000', '0')).toBe('14358946875');
  });
  it('reserves explicitly bounded gas and fees in the correct asset', () => {
    expect(resolveMaxTransfer('1000', true, '100', '5')).toBe('895');
    expect(resolveMaxTransfer('1000', false, '100', '5')).toBe('995');
    expect(() => resolveMaxTransfer('100', true, '100', '0')).toThrow();
  });
});
