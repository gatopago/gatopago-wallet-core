import { describe, expect, it } from 'vitest';
import { generatePrivateKey, privateKeyToAccount } from 'viem/accounts';
import { getAddress, recoverMessageAddress, slice, type Hex } from 'viem';
import { transferFixture } from '@gatopago/test-fixtures/v3-transfer';
import { authorizeTransferOperation } from '@gatopago/shared/v3/transfer-authorization';
import { prepareTransferOperation } from '@gatopago/shared/v3/transfer-operation';
import { parsePaymasterTerms, paymasterSponsorDigest, sponsorshipData } from '@gatopago/shared/v3/paymaster';
import { readTransferReview, writeTransferReview } from '@gatopago/shared/v3/transfer-review-record';

async function sponsored() {
  const f = transferFixture(false), signer = privateKeyToAccount(generatePrivateKey());
  const context = { ...f.context, budget: { ...f.context.budget, native_available_atomic: '0', maximum_native_gas_atomic: '0' },
    sponsorship: { address: getAddress(`0x${'12'.repeat(20)}`), verificationGasLimit: '100', postOpGasLimit: '0',
      data: sponsorshipData(f.now - 1, f.context.valid_until, `0x${'ff'.repeat(65)}`) } };
  const candidate = prepareTransferOperation(f.request, context, f.now);
  const signature = await signer.signMessage({ message: { raw: paymasterSponsorDigest(84532n, candidate.operation) } });
  context.sponsorship.data = sponsorshipData(f.now - 1, f.context.valid_until, signature);
  const ready = prepareTransferOperation(f.request, context, f.now);
  const approval = { ...f.approval, reviewed_digest: ready.digest, balance_evidence: { ...f.approval.balance_evidence,
    balances: f.approval.balance_evidence.balances.map(b => b.asset_id === context.native_asset_id ? { ...b, amount_atomic: '0' } : b) } };
  return { f, context, ready, approval, signer };
}
describe('bound V3 sponsorship', () => {
  it('authorizes a token transfer with no account ETH and restores sponsored review bytes', async () => {
    const { f, context, ready, approval, signer } = await sponsored();
    const signed = await authorizeTransferOperation(f.request, context, approval, await f.proofs(ready.digest), () => f.now);
    const saved = writeTransferReview(signed.consent_review), restored = await readTransferReview(saved.json, saved.digest);
    expect(restored.operation).toEqual(signed.operation);
    expect(restored.candidate.plan.paymaster).toBe(context.sponsorship.address);
    expect(ready.maximumEntryPointCharge).toBe(800n);
    expect(await recoverMessageAddress({ message: { raw: paymasterSponsorDigest(84532n, ready.operation) },
      signature: slice(context.sponsorship.data, 12) })).toBe(signer.address);
  });
  it('binds paymaster, signature, gas limits and validity to user consent', async () => {
    const { f, context, ready, approval } = await sponsored(), proofs = await f.proofs(ready.digest);
    for (const change of [{ address: getAddress(`0x${'34'.repeat(20)}`) }, { verificationGasLimit: '101' },
      { postOpGasLimit: '1' }, { data: sponsorshipData(f.now - 1, f.context.valid_until + 1, `0x${'ab'.repeat(65)}`) }]) {
      await expect(authorizeTransferOperation(f.request, { ...context, sponsorship: { ...context.sponsorship, ...change } }, approval, proofs, () => f.now)).rejects.toThrow();
    }
  });
  it('never converts missing sponsorship into account funding or accepts partial coverage', async () => {
    const { f, context } = await sponsored();
    expect(() => prepareTransferOperation(f.request, { ...context, sponsorship: undefined }, f.now)).toThrow('reserved gas budget');
    expect(() => prepareTransferOperation(f.request, { ...context, sponsorship: { ...context.sponsorship,
      data: sponsorshipData(f.now, f.context.valid_until - 1, `0x${'ab'.repeat(65)}`) } }, f.now)).toThrow('PAYMASTER_WINDOW_INVALID');
    expect(() => prepareTransferOperation(f.request, { ...context, budget: { ...context.budget, maximum_native_gas_atomic: '1' } }, f.now)).toThrow();
  });
  it('rejects malformed and overflowing sponsorship data', () => {
    const value = { address: `0x${'12'.repeat(20)}` as Hex, verificationGasLimit: '100', postOpGasLimit: '0',
      data: sponsorshipData(1, 2, `0x${'ff'.repeat(65)}`) };
    for (const change of [{ address: `0x${'00'.repeat(20)}` }, { verificationGasLimit: (1n << 120n).toString() },
      { verificationGasLimit: '0' }, { postOpGasLimit: '-1' }, { data: `${value.data}00` }, { data: '0x' }, { extra: true }]) {
      expect(() => parsePaymasterTerms({ ...value, ...change })).toThrow();
    }
  });
});
