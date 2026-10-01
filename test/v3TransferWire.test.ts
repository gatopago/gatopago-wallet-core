import { describe, expect, it } from 'vitest';
import { parseTransferConfirmation, parseTransferDelivery } from '@gatopago/shared/v3/transfer-wire';
import { authorizeTransferOperation } from '@gatopago/shared/v3/transfer-authorization';
import { transferFixture } from '@gatopago/test-fixtures/v3-transfer';

describe('Consumer transfer command wire', () => {
  it('decodes public-key proofs that verify the unchanged consent', async () => {
    const f = transferFixture();
    const proofs = (await f.proofs()).map(p => p.kind === 'ecdsa'
      ? { kind: p.kind, signer_index: p.signerIndex, signature: p.signature }
      : { kind: p.kind, signer_index: p.signerIndex, assertion: { authenticator_data: Buffer.from(p.assertion.authenticatorData).toString('base64url'),
        client_data: Buffer.from(p.assertion.clientDataJSON).toString('base64url'), signature: Buffer.from(p.assertion.signatureDER).toString('base64url') } });
    const parsed = parseTransferConfirmation({ consent_digest: f.p.digest, proofs });
    expect(parsed.consent_digest).toBe(f.p.digest);
    expect((await authorizeTransferOperation(f.request, f.context, f.approval, parsed.proofs, () => f.now + 1)).digest).toBe(f.p.digest);
  });
  it.each(['extra', 'none', 'duplicate', 'many', 'negative', 'fraction', 'unknown', 'signature', 'nested-extra', 'binary'])(
    'rejects invalid or expanded command: %s', scenario => {
      const signature = `0x${'11'.repeat(64)}1b`, proof: Record<string, unknown> = { kind: 'ecdsa', signer_index: 0, signature };
      const root: Record<string, unknown> = { consent_digest: `0x${'aa'.repeat(32)}`, proofs: [proof] };
      if (scenario === 'extra') root.budget = { asset_available_atomic: '999999' };
      if (scenario === 'none') root.proofs = [];
      if (scenario === 'duplicate') root.proofs = [proof, proof];
      if (scenario === 'many') root.proofs = Array.from({ length: 17 }, (_, i) => ({ ...proof, signer_index: i }));
      if (scenario === 'negative') proof.signer_index = -1;
      if (scenario === 'fraction') proof.signer_index = 0.5;
      if (scenario === 'unknown') proof.kind = 'external-provider';
      if (scenario === 'signature') proof.signature = '0x00';
      if (scenario === 'nested-extra') proof.policy = {};
      if (scenario === 'binary') root.proofs = [{ signer_index: 0, kind: 'webauthn', assertion: { authenticator_data: '==', client_data: 'AA', signature: 'AA' } }];
      expect(() => parseTransferConfirmation(root)).toThrow();
    });
  it('accepts only a digest for dispatch, never a replacement operation', () => {
    const command = { consent_digest: `0x${'aa'.repeat(32)}` };
    expect(parseTransferDelivery(command)).toEqual(command);
    expect(() => parseTransferDelivery({ ...command, operation: {} })).toThrow();
    expect(() => parseTransferDelivery({ consent_digest: '0x00' })).toThrow();
  });
});
