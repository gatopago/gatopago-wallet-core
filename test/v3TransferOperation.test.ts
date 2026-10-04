import { describe, expect, it } from 'vitest';
import { decodeFunctionData, type Address, type Hex, zeroAddress } from 'viem';
import { getUserOperationHash } from 'viem/account-abstraction';
import { createResourceId } from '@gatopago/shared/v3/primitives';
import { parseTransferRequest } from '@gatopago/shared/v3/transfer';
import { prepareTransferOperation } from '@gatopago/shared/v3/transfer-operation';
import { executionAbi } from '@gatopago/shared/v3/execution';

const addr = (s: string) => `0x${s.repeat(20)}` as Address;
const hash = (s: string) => `0x${s.repeat(32)}` as Hex;
function fixture() {
  const now = 1_800_000_000;
  const request = parseTransferRequest({
    schema_version: 1,
    generation: 3,
    wallet_id: createResourceId('wallet'),
    network_id: 'eip155:84532',
    asset_id: `eip155:84532/erc20:${addr('ab')}`,
    destination: { address: addr('cd'), address_type: 'evm_unknown' },
    amount: { kind: 'max' },
    client_release_id: 'v3-test',
  });
  const context = {
    account: addr('aa'),
    account_id: hash('aa'),
    security_version: 2n,
    deployment_digest: hash('bb'),
    policy_hash: hash('dd'),
    native_asset_id: 'eip155:84532/slip44:60',
    fee_recipient: null as Address | null,
    entry_point: addr('ef'),
    nonce: 3n,
    budget: {
      wallet_id: request.wallet_id,
      asset_id: request.asset_id,
      asset_available_atomic: '1000',
      native_available_atomic: '10000',
      maximum_native_gas_atomic: '1000',
      platform_fee: { asset_id: request.asset_id, amount_atomic: '0' },
    },
    gas: {
      verificationGasLimit: 100n,
      callGasLimit: 100n,
      preVerificationGas: 100n,
      maxFeePerGas: 2n,
      maxPriorityFeePerGas: 1n,
    },
    checkpoint: {
      block_number: '123',
      block_hash: hash('cc'),
      observed_at: now - 5,
      expires_at: now + 30,
    },
    valid_until: now + 20,
  };
  return { now, request, context };
}
describe('Unsigned transfer operation and review commitments', () => {
  it('builds a no-factory/no-paymaster unsigned UserOperation with the exact Account call', () => {
    const f = fixture();
    const p = prepareTransferOperation(f.request, f.context, f.now);
    expect(p.operation.signature).toBe('0x');
    expect(p.operation.factory).toBeUndefined();
    expect(p.operation.paymaster).toBeUndefined();
    expect(p.plan).toMatchObject({
      executionMode: 0,
      nonce: 3n,
      paymaster: zeroAddress,
      validAfter: f.now,
      validUntil: f.context.valid_until,
    });
    expect(decodeFunctionData({ abi: executionAbi, data: p.operation.callData }).args).toEqual([
      p.calls,
      2n,
    ]);
    expect(p.userOpHash).toBe(
      getUserOperationHash({
        chainId: 84532,
        entryPointAddress: f.context.entry_point,
        entryPointVersion: '0.9',
        userOperation: p.operation,
      }),
    );
    expect(p.maximumEntryPointCharge).toBe(600n);
    expect(p.funding.amount_atomic).toBe('1000');
    f.context.checkpoint.block_number = '999';
    f.request.amount = { kind: 'exact', amount_atomic: '1' };
    expect(p.checkpoint.block_number).toBe('123');
    expect(p.request.amount.kind).toBe('max');
    expect(Object.isFrozen(p.operation)).toBe(true);
    expect(Object.isFrozen(p.calls[0])).toBe(true);
  });
  it.each([
    'destination',
    'nonce',
    'gas',
    'manifest',
    'policy',
    'block',
    'block-number',
    'native-balance',
    'asset-balance',
    'release',
    'amount-kind',
    'fee',
    'expiry',
    'account-id',
    'security',
  ])('requires a different consent digest when %s changes', (field) => {
    const f = fixture();
    const before = prepareTransferOperation(f.request, f.context, f.now);
    if (field === 'destination') f.request.destination.address = addr('dd');
    if (field === 'nonce') f.context.nonce++;
    if (field === 'gas') f.context.gas.callGasLimit++;
    if (field === 'manifest') f.context.deployment_digest = hash('dd');
    if (field === 'policy') f.context.policy_hash = hash('ee');
    if (field === 'block') f.context.checkpoint.block_hash = hash('dd');
    if (field === 'block-number') f.context.checkpoint.block_number = '124';
    if (field === 'native-balance') f.context.budget.native_available_atomic = '10001';
    if (field === 'asset-balance') f.context.budget.asset_available_atomic = '1001';
    if (field === 'release') f.request.client_release_id = 'v3-other';
    if (field === 'amount-kind') f.request.amount = { kind: 'exact', amount_atomic: '1000' };
    if (field === 'fee') {
      f.context.fee_recipient = addr('dd');
      f.context.budget.platform_fee.amount_atomic = '1';
    }
    if (field === 'expiry') f.context.valid_until--;
    if (field === 'account-id') f.context.account_id = hash('dd');
    if (field === 'security') f.context.security_version++;
    expect(prepareTransferOperation(f.request, f.context, f.now).digest).not.toBe(before.digest);
  });
  it.each([
    'expired',
    'future',
    'long-window',
    'signature-window',
    'nonce-key',
    'gas-cap',
    'priority',
    'entry-point',
    'hash',
  ])('rejects an invalid preparation: %s', (field) => {
    const f = fixture();
    if (field === 'expired') f.context.checkpoint.expires_at = f.now;
    if (field === 'future') f.context.checkpoint.observed_at = f.now + 1;
    if (field === 'long-window') f.context.checkpoint.expires_at = f.now + 61;
    if (field === 'signature-window') f.context.valid_until = f.context.checkpoint.expires_at + 1;
    if (field === 'nonce-key') f.context.nonce = 1n << 64n;
    if (field === 'gas-cap') f.context.budget.maximum_native_gas_atomic = '599';
    if (field === 'priority') f.context.gas.maxPriorityFeePerGas = 3n;
    if (field === 'entry-point') f.context.entry_point = zeroAddress;
    if (field === 'hash') f.context.deployment_digest = '0x';
    expect(() => prepareTransferOperation(f.request, f.context, f.now)).toThrow();
  });
});
