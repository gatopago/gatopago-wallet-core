import {
  deploymentDocumentDigest,
  loadPinnedDeploymentManifest,
  requireHash,
} from '@gatopago/shared/v3/deployment';
import { assertFinalityAssessment } from '@gatopago/shared/v3/finality';
import type { ResourceId } from '@gatopago/shared/v3/primitives';
import type { Principal } from '../auth/principal';
import { TransferNonceReservationRepository } from './transferNonceReservation';
import { WalletAccessError, WalletRepository } from '../accounts/repository';
import { writeTransferDraft } from '@gatopago/shared/v3/transfer-review-record';
import type { Hex } from 'viem';
import type { AccountContextProfile } from '../accounts/accountContext';
import { balanceAssetMetadata } from '../portfolio/balances';

function object(value: unknown): Record<string, unknown> {
  if (!value || typeof value !== 'object' || Array.isArray(value))
    throw new Error('TRANSFER_STATUS_INVALID');
  return value as Record<string, unknown>;
}

export async function restoreOwnedTransfer(
  database: D1Database,
  identityInput: Principal,
  walletId: ResourceId<'wallet'>,
  accountId: ResourceId<'walletAccount'>,
  digest: Hex,
  resolveProfiles: () => readonly AccountContextProfile[] = () => [],
) {
  requireHash(digest);
  const identity = Object.freeze({ ...identityInput });
  const stored = await new TransferNonceReservationRepository(
    database,
    identity,
  ).findOwnedByConsent(walletId, accountId, digest);
  if (!stored) {
    await new WalletRepository(database, identity).ownedAccount(walletId, accountId);
    return Object.freeze({
      schema_version: 1,
      consent_digest: digest,
      review_json: null,
      review_sha256: null,
      status: null,
      asset_metadata: null,
      checked_at: Math.floor(Date.now() / 1000),
    });
  }
  const status = await readOwnedTransferStatus(database, identity, walletId, accountId, stored.id);
  if (status.userop_hash !== stored.candidate.userOpHash)
    throw new Error('TRANSFER_STATUS_CHANGED');
  const { request, context, policy, scope, prepared_at } = stored.review;
  const draft = writeTransferDraft({ request, context, policy, scope, prepared_at });

  const profiles = resolveProfiles();
  if (profiles.length > 32) throw new Error('TRANSFER_METADATA_UNAVAILABLE');
  const matches = profiles.filter((p) => p.digest === stored.candidate.deployment_digest);
  if (matches.length !== 1) throw new Error('TRANSFER_METADATA_UNAVAILABLE');
  const profile = matches[0],
    manifest = loadPinnedDeploymentManifest(profile.document, profile.digest);
  if (manifest.network_id !== request.network_id || !profile.assetIds || !profile.assetDisplay)
    throw new Error('TRANSFER_METADATA_UNAVAILABLE');
  const needed = new Set([request.asset_id, context.native_asset_id]);
  const metadata = balanceAssetMetadata({
    assetIds: profile.assetIds,
    assetDisplay: profile.assetDisplay,
  }).filter((a) => needed.has(a.asset_id));
  if (metadata.length !== needed.size) throw new Error('TRANSFER_METADATA_UNAVAILABLE');
  return Object.freeze({
    schema_version: 1,
    consent_digest: digest,
    review_json: draft.json,
    review_sha256: draft.digest,
    status,
    asset_metadata: metadata,
    checked_at: Math.floor(Date.now() / 1000),
  });
}

export async function readOwnedTransferStatus(
  database: D1Database,
  identityInput: Principal,
  walletId: ResourceId<'wallet'>,
  accountId: ResourceId<'walletAccount'>,
  operationId: ResourceId<'operation'>,
) {
  const identity = Object.freeze({ ...identityInput });
  const read = async () => {
    try {
      return await new TransferNonceReservationRepository(database, identity).readOwned(
        walletId,
        accountId,
        operationId,
      );
    } catch (error) {
      if (error instanceof Error && error.message === 'TRANSFER_RESERVATION_NOT_FOUND')
        throw new WalletAccessError('NOT_FOUND');
      throw error;
    }
  };
  const stored = await read();
  const db = database.withSession('first-primary');
  const results = await db.batch<Record<string, unknown>>([
    db.prepare('SELECT * FROM transfer_finality_journal WHERE operation_id = ?').bind(operationId),
    db
      .prepare('SELECT * FROM transfer_finality_conflicts WHERE operation_id = ?')
      .bind(operationId),
    db.prepare('SELECT * FROM transfer_reconciliations WHERE operation_id = ?').bind(operationId),
  ]);
  if (results.some((r) => !r.success)) throw new Error('TRANSFER_STATUS_UNAVAILABLE');
  function evidence(row: Record<string, unknown>) {
    if (
      row.operation_id !== operationId ||
      typeof row.receipt_json !== 'string' ||
      row.receipt_json.length > 8192 ||
      typeof row.evidence_json !== 'string' ||
      row.evidence_json.length > 16384 ||
      deploymentDocumentDigest(row.receipt_json) !== row.receipt_sha256 ||
      deploymentDocumentDigest(row.evidence_json) !== row.evidence_sha256 ||
      typeof row.recorded_at !== 'number' ||
      !Number.isSafeInteger(row.recorded_at) ||
      row.recorded_at <= 0
    )
      throw new Error('TRANSFER_STATUS_INVALID');
    const receipt = object(JSON.parse(row.receipt_json)),
      result = object(JSON.parse(row.evidence_json));
    if (
      JSON.stringify(result.observation) !== row.receipt_json ||
      result.status !== 'observed' ||
      result.operation_id !== operationId ||
      result.userop_hash !== stored.candidate.userOpHash ||
      receipt.userop_hash !== stored.candidate.userOpHash ||
      result.transaction_hash !== receipt.transaction_hash ||
      receipt.consent_digest !== stored.candidate.digest ||
      receipt.network_id !== stored.candidate.request.network_id ||
      receipt.deployment_sha256 !== stored.candidate.deployment_digest ||
      !['execution_succeeded', 'execution_reverted'].includes(String(receipt.outcome))
    )
      throw new Error('TRANSFER_STATUS_INVALID');
    requireHash(receipt.transaction_hash);
    requireHash(receipt.block_hash);
    const finality = object(result.finality_evidence);
    requireHash(finality.genesis_hash);
    if (typeof receipt.block_number !== 'string' || typeof receipt.block_timestamp !== 'string')
      throw new Error('TRANSFER_STATUS_INVALID');
    assertFinalityAssessment(finality, {
      network_id: stored.candidate.request.network_id,
      genesis_hash: finality.genesis_hash,
      block_hash: receipt.block_hash,
      block_number: receipt.block_number,
      block_timestamp: receipt.block_timestamp,
    });
    if (
      finality.status !== 'finalized' ||
      row.recorded_at < finality.assessed_at ||
      row.recorded_at >= finality.expires_at
    ) {
      throw new Error('TRANSFER_STATUS_INVALID');
    }
    return {
      transaction_hash: receipt.transaction_hash,
      outcome:
        receipt.outcome === 'execution_succeeded'
          ? ('execution_succeeded' as const)
          : ('execution_reverted' as const),
      recorded_at: row.recorded_at,
    };
  }
  const saved = results[0].results[0],
    conflict = results[1].results[0];
  const historical = saved ? evidence(saved) : null;
  if (conflict) {
    if (!historical) throw new Error('TRANSFER_STATUS_INVALID');
    evidence(conflict);
  }
  const reconciliation = results[2].results[0];
  if (stored.state === 'reconciled') {
    if (
      !reconciliation ||
      !saved ||
      !historical ||
      conflict ||
      reconciliation.wallet_account_id !== accountId ||
      reconciliation.receipt_sha256 !== saved.receipt_sha256 ||
      typeof reconciliation.proof_json !== 'string' ||
      reconciliation.proof_json.length > 32768 ||
      deploymentDocumentDigest(reconciliation.proof_json) !== reconciliation.proof_sha256
    ) {
      throw new Error('TRANSFER_STATUS_INVALID');
    }
    const proof = object(JSON.parse(reconciliation.proof_json)),
      balances = object(proof.balances),
      checkpoint = object(balances.checkpoint);
    if (
      proof.operation_id !== operationId ||
      proof.wallet_id !== walletId ||
      proof.wallet_account_id !== accountId ||
      proof.userop_hash !== stored.candidate.userOpHash ||
      proof.consent_digest !== stored.candidate.digest ||
      proof.receipt_sha256 !== saved.receipt_sha256 ||
      checkpoint.block_number !== reconciliation.block_number ||
      checkpoint.block_hash !== reconciliation.block_hash ||
      typeof proof.checked_at !== 'number' ||
      typeof proof.expires_at !== 'number' ||
      typeof reconciliation.recorded_at !== 'number' ||
      reconciliation.recorded_at < proof.checked_at ||
      reconciliation.recorded_at >= proof.expires_at
    )
      throw new Error('TRANSFER_STATUS_INVALID');
  } else if (reconciliation) throw new Error('TRANSFER_STATUS_INVALID');
  const current = await read();
  if (
    current.candidate.digest !== stored.candidate.digest ||
    current.candidate.userOpHash !== stored.candidate.userOpHash ||
    current.state !== stored.state
  )
    throw new Error('TRANSFER_STATUS_CHANGED');
  return Object.freeze({
    operation_id: operationId,
    wallet_id: walletId,
    wallet_account_id: accountId,
    network_id: stored.candidate.request.network_id,
    userop_hash: stored.candidate.userOpHash,
    status:
      stored.state === 'reconciled'
        ? ('reconciled' as const)
        : conflict
          ? ('review_required' as const)
          : historical
            ? ('confirmation_recorded' as const)
            : stored.state,
    historical_confirmation: historical,
    settlement: 'not_assessed' as const,
    send_enabled: false as const,
    funds_reserved: stored.state === 'delivery_pending' || stored.state === 'held',
  });
}
