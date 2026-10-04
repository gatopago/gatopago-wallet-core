import type { Environment } from '@gatopago/environment';
import { validateRpcProviders } from '../chainProviders';
import {
  deploymentDocumentDigest,
  loadPinnedDeploymentManifest,
} from '@gatopago/shared/v3/deployment';
import { assessCheckpointFinality } from '@gatopago/shared/v3/finality';
import { createInspectionClient } from '../chainInspection';
import { withDeadline } from '../deadline';

import { inspectOwnedWalletBalances } from '../portfolio/balances';
import { recordTransferJobFinality } from './transferJobFinality';
import { TransferJobRepository, parseTransferWake, type TransferWake } from './transferJobs';
import { writeTransferReview } from '@gatopago/shared/v3/transfer-review-record';

export async function reconcileTransferJob(
  database: D1Database,
  environment: Environment['environment'],
  input: TransferWake,
  profilesInput: Parameters<typeof recordTransferJobFinality>[3],
  signal: AbortSignal,
) {
  const message = parseTransferWake(input),
    profiles = structuredClone(profilesInput);
  const jobs = new TransferJobRepository(database, { environment, profiles });
  return withDeadline(signal, 120_000, async (deadline) => {
    const result = await recordTransferJobFinality(
      database,
      environment,
      message,
      profiles,
      deadline,
    );
    if (result.journal === 'conflict')
      return { state: 'review' as const, reason: 'conflicting_evidence' as const };
    if (
      result.journal !== 'recorded' ||
      result.status !== 'observed' ||
      result.finality_evidence.status !== 'finalized'
    ) {
      return { state: 'waiting' as const };
    }
    const source = await jobs.observationSource(message),
      candidate = source.record.candidate;
    const matching = profiles.filter((p) => p.digest === candidate.deployment_digest);
    if (matching.length !== 1) throw new Error('TRANSFER_JOB_PROFILE');
    const profile = { ...matching[0], assetIds: source.funds.map((f) => f.asset_id) },
      manifest = loadPinnedDeploymentManifest(profile.document, profile.digest);
    const walletId = candidate.request.wallet_id,
      accountId = source.walletAccountId;
    const access = {
      ownedAccount: async (wid: string, aid: string) => {
        const current = await jobs.observationSource(message);
        if (wid !== walletId || aid !== accountId || current.context !== source.context)
          throw new Error('TRANSFER_JOB_CHANGED');
        return {
          network_id: candidate.request.network_id,
          address: candidate.account,
          account_id: candidate.plan.accountId,
          deployment_manifest_sha256: candidate.deployment_digest,
        };
      },
    };
    const balances = await inspectOwnedWalletBalances(
      access,
      walletId,
      accountId,
      [{ ...profile, finalityEvidence: result.finality_evidence }],
      deadline,
    );
    const receipt = result.observation,
      checkpoint = balances.checkpoint,
      required = new Set(source.funds.map((f) => f.asset_id));
    if (
      balances.wallet_id !== walletId ||
      balances.wallet_account_id !== accountId ||
      balances.network_id !== receipt.network_id ||
      balances.address.toLowerCase() !== candidate.account.toLowerCase() ||
      BigInt(checkpoint.block_number) < BigInt(receipt.block_number) ||
      (checkpoint.block_number === receipt.block_number &&
        checkpoint.block_hash !== receipt.block_hash) ||
      balances.balances.length !== required.size ||
      new Set(balances.balances.map((a) => a.asset_id)).size !== required.size ||
      balances.balances.some((a) => !required.has(a.asset_id))
    )
      throw new Error('TRANSFER_JOB_BALANCE');
    const peers = validateRpcProviders(profile.providers);
    const closing = await assessCheckpointFinality(
      peers.map((p) => createInspectionClient(p.url, deadline)),
      { ...receipt, genesis_hash: manifest.genesis_hash },
      profile.finalityPolicy,
      deadline,
    );
    const current = await jobs.observationSource(message),
      now = Math.floor(Date.now() / 1000);
    deadline.throwIfAborted();
    if (
      current.context !== source.context ||
      closing.status !== 'finalized' ||
      !closing.checkpoint ||
      closing.assessed_at > now ||
      now >= closing.expires_at ||
      now < balances.observed_at ||
      now >= balances.expires_at ||
      BigInt(closing.checkpoint.block_number) < BigInt(checkpoint.block_number) ||
      (closing.checkpoint.block_number === checkpoint.block_number &&
        closing.checkpoint.block_hash !== checkpoint.block_hash)
    ) {
      throw new Error('TRANSFER_JOB_BALANCE_CHANGED');
    }
    const proof = {
      operation_id: message.operation_id,
      wallet_id: walletId,
      wallet_account_id: accountId,
      userop_hash: candidate.userOpHash,
      consent_digest: candidate.digest,
      receipt_sha256: deploymentDocumentDigest(JSON.stringify(receipt)),
      balances,
      receipt_finality: closing,
      checked_at: now,
      expires_at: Math.min(balances.expires_at, closing.expires_at),
      settlement: 'not_assessed' as const,
      release_enabled: false as const,
    };
    const json = JSON.stringify(proof);
    if (json.length > 32768) throw new Error('TRANSFER_JOB_PROOF_SIZE');
    const db = database.withSession('first-primary');
    const row = await db
      .prepare(
        `INSERT INTO transfer_reconciliations
      (operation_id,wallet_account_id,receipt_sha256,block_number,block_hash,proof_json,proof_sha256,recorded_at)
      SELECT r.id,r.wallet_account_id,?,?,?,?,?,? FROM transfer_nonce_reservations r
      JOIN transfer_jobs t ON t.operation_id = r.id JOIN wallets w ON w.id = r.wallet_id
      JOIN users u ON u.id = w.user_id
      WHERE r.id = ? AND r.wallet_id = ? AND r.wallet_account_id = ? AND r.state = 'delivery_pending'
      AND t.state = 'running' AND t.lease_token = ? AND t.lease_expires_at > unixepoch()
      AND u.environment = ? AND r.userop_hash = ? AND r.consent_digest = ?
      AND r.deployment_manifest_sha256 = ? AND r.review_sha256 = ?
      ON CONFLICT(operation_id) DO NOTHING RETURNING operation_id`,
      )
      .bind(
        proof.receipt_sha256,
        checkpoint.block_number,
        checkpoint.block_hash,
        json,
        deploymentDocumentDigest(json),
        now,
        message.operation_id,
        walletId,
        accountId,
        message.token,
        environment,
        candidate.userOpHash,
        candidate.digest,
        candidate.deployment_digest,
        writeTransferReview(source.record.review).digest,
      )
      .first<{ operation_id: string }>();

    if (row?.operation_id !== message.operation_id) throw new Error('TRANSFER_JOB_COMMIT_CHANGED');
    return {
      state: 'reconciled' as const,
      operation_id: message.operation_id,
      funds_reserved: false as const,
    };
  });
}
