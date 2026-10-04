import type { Hex } from 'viem';
import { deploymentDocumentDigest, requireHash } from '@gatopago/shared/v3/deployment';
import { moneyFields } from '@gatopago/shared/v3/money-wire';
import { parseResourceId, type ResourceId } from '@gatopago/shared/v3/primitives';
import {
  parseTransferConfirmation,
  serializeTransferConfirmation,
} from '@gatopago/shared/v3/transfer-wire';
import type { MoneyProof } from '@gatopago/shared/v3/money-review-record';

export function parseMoneyConfirmation(value: unknown) {
  const input = moneyFields(value, ['money_schema_version', 'consent_digest', 'proofs']);
  if (input.money_schema_version !== 1) throw new Error('INVALID_MONEY_REQUEST');
  const command = parseTransferConfirmation({
    consent_digest: input.consent_digest,
    proofs: input.proofs,
  });
  if (command.proofs.some((proof) => proof.kind !== 'webauthn'))
    throw new Error('MONEY_CONSUMER_POLICY_REQUIRED');
  return { money_schema_version: 1 as const, ...command };
}
export function moneyConfirmationDigest(
  preparationId: ResourceId<'operation'>,
  consentDigest: Hex,
  proofs: readonly MoneyProof[],
) {
  parseResourceId('operation', preparationId);
  return deploymentDocumentDigest(
    JSON.stringify([1, preparationId, serializeTransferConfirmation(consentDigest, proofs)]),
  );
}
export function parseMoneyDelivery(value: unknown) {
  const input = moneyFields(value, ['money_schema_version', 'consent_digest']);
  if (input.money_schema_version !== 1) throw new Error('INVALID_MONEY_REQUEST');
  requireHash(input.consent_digest);
  return { money_schema_version: 1 as const, consent_digest: input.consent_digest };
}
