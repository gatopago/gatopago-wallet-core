import { describe, expect, it } from 'vitest';
import { decodeFunctionData, erc20Abi, getAddress, type Address } from 'viem';
import { createResourceId, UINT256_MAX } from '@gatopago/shared/v3/primitives';
import { parseTransferRequest } from '@gatopago/shared/v3/transfer';
import { compileTransferCalls } from '@gatopago/shared/v3/transfer-calls';
import { executionAbi } from '@gatopago/shared/v3/execution';
import { hashCalls } from '@gatopago/shared/v3/authorizations';

const address = (pair: string) => `0x${pair.repeat(20)}` as Address;
function fixture(native = false) {
  const nativeAsset = 'eip155:84532/slip44:60';
  const request = parseTransferRequest({
    schema_version: 1,
    generation: 3,
    wallet_id: createResourceId('wallet'),
    network_id: 'eip155:84532',
    asset_id: native ? nativeAsset : `eip155:84532/erc20:${address('ab')}`,
    destination: { address: address('cd'), address_type: 'evm_unknown' },
    amount: { kind: 'max' },
    client_release_id: 'v3-test',
  });
  const context = {
    account: address('aa'),
    security_version: 2n,
    native_asset_id: nativeAsset,
    fee_recipient: null as Address | null,
    budget: {
      wallet_id: request.wallet_id,
      asset_id: request.asset_id,
      asset_available_atomic: '1000',
      native_available_atomic: native ? '1000' : '100',
      maximum_native_gas_atomic: '100',
      platform_fee: { asset_id: request.asset_id, amount_atomic: '0' },
    },
  };
  return { request, context };
}
describe('Transfer intent to Account V3 calls', () => {
  it.each([false, true])(
    'compiles MAX with exact native/token accounting (native=%s)',
    (native) => {
      const f = fixture(native);
      const result = compileTransferCalls(f.request, f.context);
      expect(result.funding.amount_atomic).toBe(native ? '900' : '1000');
      expect(result.calls).toHaveLength(1);
      expect(result.calls_hash).toBe(hashCalls(result.calls));
      const decoded = decodeFunctionData({ abi: executionAbi, data: result.calldata });
      expect(decoded.functionName).toBe('execute');
      expect(decoded.args).toEqual([result.calls, 2n]);
      if (native)
        expect(result.calls[0]).toEqual({
          target: getAddress(address('cd')),
          value: 900n,
          data: '0x',
        });
      else {
        expect(result.calls[0].target).toBe(getAddress(address('ab')));
        expect(result.calls[0].value).toBe(0n);
        expect(decodeFunctionData({ abi: erc20Abi, data: result.calls[0].data })).toMatchObject({
          functionName: 'transfer',
          args: [getAddress(address('cd')), 1000n],
        });
      }
    },
  );
  it.each([false, true])(
    'emits an explicit fee call, not hidden recipient subtraction (native=%s)',
    (native) => {
      const f = fixture(native);
      f.context.fee_recipient = address('ef');
      f.context.budget.platform_fee.amount_atomic = '5';
      f.request.amount = { kind: 'exact', amount_atomic: '400' };
      const result = compileTransferCalls(f.request, f.context);
      expect(result.funding.amount_atomic).toBe('400');
      expect(result.calls).toHaveLength(2);
      expect(result.funding.asset_debit_atomic).toBe(native ? '505' : '405');
      if (native) expect(result.calls.map((c) => c.value)).toEqual([400n, 5n]);
      else
        expect(decodeFunctionData({ abi: erc20Abi, data: result.calls[1].data }).args).toEqual([
          getAddress(address('ef')),
          5n,
        ]);
    },
  );
  it('preserves uint256 precision and detaches input', () => {
    const f = fixture();
    f.context.budget.asset_available_atomic = UINT256_MAX.toString();
    const result = compileTransferCalls(f.request, f.context);
    f.request.destination.address = address('ee');
    f.context.budget.asset_available_atomic = '1';
    expect(result.funding.amount_atomic).toBe(UINT256_MAX.toString());
    expect(result.request.destination.address).toBe(address('cd'));
  });
  it.each([
    'self',
    'token-self',
    'token-destination',
    'native-alias',
    'foreign-native',
    'zero-token',
    'fee-missing',
    'fee-unexpected',
    'fee-self',
    'version',
  ])('rejects inconsistent execution context: %s', (fault) => {
    const f = fixture();
    if (fault === 'self') f.request.destination.address = f.context.account;
    if (fault === 'token-self') f.context.account = address('ab');
    if (fault === 'token-destination') f.request.destination.address = address('ab');
    if (fault === 'native-alias') f.request.asset_id = 'eip155:84532/slip44:1';
    if (fault === 'foreign-native') f.context.native_asset_id = 'eip155:1/slip44:60';
    if (fault === 'zero-token') f.request.asset_id = `eip155:84532/erc20:${address('00')}`;
    if (fault === 'fee-missing') f.context.budget.platform_fee.amount_atomic = '1';
    if (fault === 'fee-unexpected') f.context.fee_recipient = address('ef');
    if (fault === 'fee-self') {
      f.context.fee_recipient = f.context.account;
      f.context.budget.platform_fee.amount_atomic = '1';
    }
    if (fault === 'version') f.context.security_version = 0n;
    expect(() => compileTransferCalls(f.request, f.context)).toThrow();
  });
});
