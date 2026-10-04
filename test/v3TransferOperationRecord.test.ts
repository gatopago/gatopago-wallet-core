import { describe, expect, it } from 'vitest';
import { authorizeTransferOperation } from '@gatopago/shared/v3/transfer-authorization';
import { deploymentDocumentDigest } from '@gatopago/shared/v3/deployment';
import { transferFixture } from '@gatopago/test-fixtures/v3-transfer';
import {
  readTransferOperationRecord,
  writeTransferOperationRecord,
} from '../src/transfers/transferOperationRecord';

async function fixture(native = true) {
  const f = transferFixture(native);
  const a = await authorizeTransferOperation(
    f.request,
    f.context,
    f.approval,
    await f.proofs(),
    () => f.now + 1,
  );
  const binding = {
    network_id: a.request.network_id,
    account: a.account,
    account_id: a.plan.accountId,
    entry_point: a.plan.entryPoint,
    userop_hash: a.userOpHash,
    consent_digest: a.digest,
    valid_until: a.plan.validUntil,
  };
  return { a, binding, record: writeTransferOperationRecord(a.operation, binding) };
}
describe('Canonical signed transfer storage', () => {
  it.each([true, false])(
    'round trips the original operation and signed plan (native=%s)',
    async (native) => {
      const f = await fixture(native),
        restored = readTransferOperationRecord(f.record.json, f.record.digest, f.binding);
      expect(restored.operation).toEqual(f.a.operation);
      expect(restored.plan).toEqual(f.a.plan);
      expect(Object.isFrozen(restored.operation)).toBe(true);
    },
  );
  it.each([
    'hash',
    'whitespace',
    'leading-zero',
    'extra-field',
    'calldata',
    'signature',
    'gas',
    'nonce',
  ])('rejects storage damage even when a checksum is recomputed: %s', async (fault) => {
    const f = await fixture();
    let json = f.record.json;
    const raw: Record<string, unknown> = JSON.parse(json);
    if (fault === 'leading-zero') raw.nonce = '00';
    if (fault === 'extra-field') raw.paymaster = `0x${'aa'.repeat(20)}`;
    if (fault === 'calldata') raw.callData = '0x1234';
    if (fault === 'signature') raw.signature = '0x1234';
    if (fault === 'gas') raw.maxFeePerGas = '3';
    if (fault === 'nonce') raw.nonce = '1';
    json = fault === 'whitespace' ? `${json} ` : JSON.stringify(raw);
    const digest = fault === 'hash' ? `0x${'ee'.repeat(32)}` : deploymentDocumentDigest(json);
    expect(() => readTransferOperationRecord(json, digest, f.binding)).toThrow();
  });
  it.each(['network', 'account', 'account-id', 'entrypoint', 'userop', 'consent', 'expiry'])(
    'rejects an unrelated locator binding: %s',
    async (fault) => {
      const f = await fixture(),
        binding = { ...f.binding };
      if (fault === 'network') binding.network_id = 'eip155:421614';
      if (fault === 'account') binding.account = `0x${'ab'.repeat(20)}`;
      if (fault === 'account-id') binding.account_id = `0x${'ee'.repeat(32)}`;
      if (fault === 'entrypoint') binding.entry_point = `0x${'ab'.repeat(20)}`;
      if (fault === 'userop') binding.userop_hash = `0x${'ee'.repeat(32)}`;
      if (fault === 'consent') binding.consent_digest = `0x${'ee'.repeat(32)}`;
      if (fault === 'expiry') binding.valid_until++;
      expect(() => readTransferOperationRecord(f.record.json, f.record.digest, binding)).toThrow();
    },
  );
  it('rejects unsupported fields before serialization instead of dropping them', async () => {
    const f = await fixture();
    expect(() =>
      writeTransferOperationRecord(
        { ...f.a.operation, paymaster: `0x${'ab'.repeat(20)}` },
        f.binding,
      ),
    ).toThrow('TRANSFER_RECORD_UNSUPPORTED_PROFILE');
  });
  it('rejects oversized input before parsing it', async () => {
    const f = await fixture();
    expect(() =>
      readTransferOperationRecord(' '.repeat(180_001), f.record.digest, f.binding),
    ).toThrow('TRANSFER_RECORD_INVALID');
  });
});
