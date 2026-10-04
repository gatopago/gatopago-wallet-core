import { describe, expect, it } from 'vitest';
import { decodeAbiParameters } from 'viem';
import { getUserOperationHash } from 'viem/account-abstraction';
import { createResourceId } from '@gatopago/shared/v3/primitives';
import { authorizationTypes } from '@gatopago/shared/v3/authorizations';
import { authorizeTransferOperation } from '@gatopago/shared/v3/transfer-authorization';

import { transferFixture as fixture } from '@gatopago/test-fixtures/v3-transfer';
describe('Transfer spend consent verification', () => {
  it.each(['later', 'older', 'future', 'invalid'])(
    'checks the timestamp of a re-read reviewed balance: %s',
    async (scenario) => {
      const f = fixture();
      f.approval.balance_evidence.observed_at =
        scenario === 'later'
          ? f.now + 1
          : scenario === 'older'
            ? f.now - 1
            : scenario === 'future'
              ? f.now + 10
              : NaN;
      const task = authorizeTransferOperation(
        f.request,
        f.context,
        f.approval,
        await f.proofs(),
        () => f.now + 5,
      );
      if (scenario === 'later') expect((await task).digest).toBe(f.p.digest);
      else await expect(task).rejects.toThrow();
    },
  );
  it.each([true, false])(
    'accepts a mixed quorum without changing the original hash (native=%s)',
    async (native) => {
      const f = fixture(native);
      const result = await authorizeTransferOperation(
        f.request,
        f.context,
        f.approval,
        await f.proofs(),
        () => f.now + 5,
      );
      expect(result.digest).toBe(f.p.digest);
      expect(result.operation.signature).not.toBe('0x');
      expect(
        getUserOperationHash({
          chainId: Number(f.request.network_id.split(':')[1]),
          entryPointAddress: f.context.entry_point,
          entryPointVersion: '0.9',
          userOperation: result.operation,
        }),
      ).toBe(f.p.userOpHash);
      const [plan, signatures] = decodeAbiParameters(
        [
          { type: 'tuple', components: authorizationTypes.ExecutionPlan },
          {
            type: 'tuple[]',
            components: [
              { name: 'signerIndex', type: 'uint8' },
              { name: 'signature', type: 'bytes' },
            ],
          },
        ],
        result.operation.signature,
      );
      expect(plan).toEqual(f.p.plan);
      expect(signatures).toHaveLength(2);
      expect(signatures[0].signerIndex).toBeLessThan(signatures[1].signerIndex);
    },
  );
  it.each([
    'late',
    'early',
    'duplicate',
    'missing',
    'wrong-index',
    'review',
    'policy',
    'scope',
    'changed-request',
  ])('rejects invalid consent: %s', async (fault) => {
    const f = fixture();
    let proofs = await f.proofs();
    let now = f.now + 1;
    if (fault === 'late') now = f.context.valid_until;
    if (fault === 'early') now = f.now - 1;
    if (fault === 'duplicate') proofs = [proofs[0], proofs[0]];
    if (fault === 'missing') proofs = proofs.slice(0, 1);
    if (fault === 'wrong-index') proofs[0].signerIndex = 99;
    if (fault === 'review') f.approval.reviewed_digest = `0x${'ee'.repeat(32)}`;
    if (fault === 'policy') f.approval.policy.spendThreshold = 1;
    if (fault === 'scope')
      f.approval.scope = { rpId: 'other.example', origin: 'https://other.example' };
    if (fault === 'changed-request') f.request.amount = { kind: 'exact', amount_atomic: '11' };
    await expect(
      authorizeTransferOperation(f.request, f.context, f.approval, proofs, () => now),
    ).rejects.toThrow();
  });
  it('checks expiry again after asynchronous signature verification', async () => {
    const f = fixture();
    let calls = 0;
    await expect(
      authorizeTransferOperation(f.request, f.context, f.approval, await f.proofs(), () =>
        calls++ === 0 ? f.now + 1 : f.context.valid_until,
      ),
    ).rejects.toThrow('TRANSFER_CONSENT_EXPIRED');
  });
  it.each(['nonce', 'entrypoint', 'block', 'stale'])(
    'refuses unrelated nonce evidence: %s',
    async (fault) => {
      const f = fixture();
      const n = f.approval.nonce_evidence;
      if (fault === 'nonce') n.nonce = '1';
      if (fault === 'entrypoint') n.entry_point = `0x${'ee'.repeat(20)}`;
      if (fault === 'block') n.checkpoint = { ...n.checkpoint, block_number: '124' };
      if (fault === 'stale') n.observed_at = f.now - 61;
      await expect(
        authorizeTransferOperation(
          f.request,
          f.context,
          f.approval,
          await f.proofs(),
          () => f.now + 1,
        ),
      ).rejects.toThrow('TRANSFER_NONCE_MISMATCH');
    },
  );
  it.each([true, false])(
    'subtracts explicit holds without counting native gas twice (native=%s)',
    async (native) => {
      const f = fixture(native);
      for (const row of f.approval.balance_evidence.balances) row.amount_atomic = '11000';
      for (const row of f.approval.balance_evidence.reserved) row.amount_atomic = '1000';
      expect(
        (
          await authorizeTransferOperation(
            f.request,
            f.context,
            f.approval,
            await f.proofs(),
            () => f.now + 1,
          )
        ).digest,
      ).toBe(f.p.digest);
    },
  );
  it.each([
    'wallet',
    'address',
    'block',
    'missing-native',
    'duplicate',
    'insufficient',
    'hold',
    'missing-hold',
    'expired',
  ])('refuses a mismatched balance or reservation: %s', async (fault) => {
    const f = fixture(false);
    const e = f.approval.balance_evidence;
    if (fault === 'wallet') e.wallet_id = createResourceId('wallet');
    if (fault === 'address') e.address = `0x${'ee'.repeat(20)}`;
    if (fault === 'block') e.checkpoint = { ...e.checkpoint, block_number: '124' };
    if (fault === 'missing-native') e.balances.pop();
    if (fault === 'duplicate') e.balances.push(e.balances[0]);
    if (fault === 'insufficient') e.balances[0].amount_atomic = '9999';
    if (fault === 'hold') e.reserved[0].amount_atomic = '1';
    if (fault === 'missing-hold') e.reserved.pop();
    if (fault === 'expired') e.expires_at = f.now;
    await expect(
      authorizeTransferOperation(
        f.request,
        f.context,
        f.approval,
        await f.proofs(),
        () => f.now + 1,
      ),
    ).rejects.toThrow();
  });
  it.each([
    'account',
    'network',
    'block',
    'version',
    'bootstrap',
    'finality',
    'genesis',
    'security-expiry',
  ])('refuses mismatched live security evidence: %s', async (fault) => {
    const f = fixture();
    const proofs = await f.proofs();
    const evidence = f.approval.security_evidence;
    if (fault === 'account') evidence.observation.account = `0x${'ee'.repeat(20)}`;
    if (fault === 'network') evidence.observation.network_id = 'eip155:1';
    if (fault === 'block')
      evidence.observation.checkpoint = { ...evidence.observation.checkpoint, block_number: '124' };
    if (fault === 'version') evidence.observation.security_version = '3';
    if (fault === 'bootstrap') evidence.observation.security.phase = 'bootstrap';
    if (fault === 'finality') evidence.finality = { ...evidence.finality, status: 'unavailable' };
    if (fault === 'genesis')
      evidence.finality = { ...evidence.finality, genesis_hash: `0x${'ee'.repeat(32)}` };
    if (fault === 'security-expiry') evidence.expires_at = f.now + 10;
    await expect(
      authorizeTransferOperation(f.request, f.context, f.approval, proofs, () => f.now + 1),
    ).rejects.toThrow();
  });
  it('detaches policy and proof bytes before awaiting verification', async () => {
    const f = fixture();
    const proofs = (await f.proofs()).reverse();
    const task = authorizeTransferOperation(
      f.request,
      f.context,
      f.approval,
      proofs,
      () => f.now + 1,
    );
    f.approval.policy.spendThreshold = 16;
    for (const proof of proofs) if (proof.kind === 'webauthn') proof.assertion.signatureDER.fill(0);
    expect((await task).digest).toBe(f.p.digest);
  });
});
