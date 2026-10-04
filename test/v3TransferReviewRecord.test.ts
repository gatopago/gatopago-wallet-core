import { describe, expect, it } from 'vitest';
import { deploymentDocumentDigest } from '@gatopago/shared/v3/deployment';
import { authorizeTransferOperation } from '@gatopago/shared/v3/transfer-authorization';
import { prepareTransferOperation } from '@gatopago/shared/v3/transfer-operation';
import {
  readTransferDraft,
  writeTransferDraft,
  readTransferReview,
  writeTransferReview,
} from '@gatopago/shared/v3/transfer-review-record';
import { writeAssertionRecord } from '@gatopago/shared/v3/assertion-record';
import { transferFixture } from '@gatopago/test-fixtures/v3-transfer';

async function fixture(native = true, max = false) {
  const f = transferFixture(native),
    request = { ...f.request, amount: max ? { kind: 'max' as const } : f.request.amount };
  const prepared = prepareTransferOperation(request, f.context, f.now);
  const a = await authorizeTransferOperation(
    request,
    f.context,
    { ...f.approval, reviewed_digest: prepared.digest },
    await f.proofs(prepared.digest),
    () => f.now + 1,
  );
  return { f, a, record: writeTransferReview(a.consent_review) };
}
describe('Historical transfer review and quorum', () => {
  it('keeps unsigned drafts distinct from verified historical consent', async () => {
    const { f, a, record: signed } = await fixture();
    const draft = writeTransferDraft({
      request: f.request,
      context: f.context,
      policy: f.approval.policy,
      scope: f.approval.scope,
      prepared_at: f.now,
    });
    const restored = readTransferDraft(draft.json, draft.digest);
    expect(restored.candidate.digest).toBe(a.digest);
    expect(restored.candidate.operation.signature).toBe('0x');
    expect(writeTransferDraft(restored.review)).toEqual(draft);
    await expect(readTransferReview(draft.json, draft.digest)).rejects.toThrow();
    expect(() => readTransferDraft(signed.json, signed.digest)).toThrow('TRANSFER_DRAFT_INVALID');
    expect(() => readTransferDraft(draft.json + ' ', draft.digest)).toThrow();
  });
  it.each([
    [true, false],
    [false, false],
    [true, true],
  ])('reconstructs exact signed bytes (native=%s, MAX=%s)', async (native, max) => {
    const { a, record } = await fixture(native, max),
      restored = await readTransferReview(record.json, record.digest);
    expect(restored.operation).toEqual(a.operation);
    expect(restored.candidate.digest).toBe(a.digest);
    expect(restored.review.approved_at).toBe(a.consent_review.approved_at);
    expect(restored.candidate.funding).toEqual(a.funding);
    expect(writeTransferReview(restored.review)).toEqual(record);
  });
  it.each([
    'nonce',
    'budget',
    'recipient',
    'threshold',
    'scope',
    'ecdsa',
    'webauthn',
    'prepared-time',
    'expired-approval',
  ])('does not trust a recomputed storage checksum: %s', async (fault) => {
    const { f, record } = await fixture();
    const data: {
      context: {
        nonce: string;
        budget: { asset_available_atomic: string; native_available_atomic: string };
        valid_until: number;
      };
      request: { destination: { address: string } };
      policy: { spendThreshold: number };
      scope: { origin: string };
      proofs: { kind: string; signature: string; assertion: string }[];
      prepared_at: number;
      approved_at: number;
    } = JSON.parse(record.json);
    if (fault === 'nonce') data.context.nonce = '1';
    if (fault === 'budget') {
      data.context.budget.asset_available_atomic = '10001';
      data.context.budget.native_available_atomic = '10001';
    }
    if (fault === 'recipient') data.request.destination.address = `0x${'ab'.repeat(20)}`;
    if (fault === 'threshold') data.policy.spendThreshold = 1;
    if (fault === 'scope') data.scope.origin = 'https://other.example';
    if (fault === 'ecdsa') {
      const proof = data.proofs.find((p) => p.kind === 'ecdsa')!;
      proof.signature = `0x${'11'.repeat(32)}${proof.signature.slice(66)}`;
    }
    if (fault === 'webauthn')
      data.proofs.find((p) => p.kind === 'webauthn')!.assertion = writeAssertionRecord(
        f.f.assertion(`0x${'ee'.repeat(32)}`),
      );
    if (fault === 'prepared-time') data.prepared_at++;
    if (fault === 'expired-approval') data.approved_at = data.context.valid_until;
    const json = JSON.stringify(data);
    await expect(readTransferReview(json, deploymentDocumentDigest(json))).rejects.toThrow();
  });
  it('rejects extra fields, malformed proofs and oversized documents', async () => {
    const { record } = await fixture(),
      original: Record<string, unknown> = JSON.parse(record.json);
    for (const changed of [
      { ...original, secret: 'not-permitted' },
      { ...original, proofs: [] },
    ]) {
      const json = JSON.stringify(changed);
      await expect(readTransferReview(json, deploymentDocumentDigest(json))).rejects.toThrow();
    }
    await expect(readTransferReview(' '.repeat(150_001), record.digest)).rejects.toThrow();
  });
});
