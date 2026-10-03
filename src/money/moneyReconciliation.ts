import type { Environment } from '@gatopago/environment';
import { deploymentDocumentDigest, loadPinnedDeploymentManifest } from '@gatopago/shared/v3/deployment';
import { assertFinalityAssessment, loadPinnedFinalityPolicy } from '@gatopago/shared/v3/finality';
import { writeMoneyReview } from '@gatopago/shared/v3/money-review-record';
import { withDeadline } from '../deadline';
import { MoneyJobRepository, parseMoneyWake, type MoneyWake } from './moneyJobs';
import { observeMoneySource } from './moneyObservation';
import type { MoneyDeliveryProfile } from './moneyPreflight';

/** Entire proof is read under an internal lease. HTTP bodies cannot insert a
 * receipt/finality journal, move a balance floor or release a spend lock. */
export async function reconcileMoneyJob(database: D1Database, environment: Environment['environment'], input: MoneyWake,
  profilesInput: readonly MoneyDeliveryProfile[], signal: AbortSignal) {
  const message = parseMoneyWake(input), profiles = structuredClone(profilesInput);
  const jobs = new MoneyJobRepository(database, { environment, profiles });
  return withDeadline(signal, 55_000, async deadline => {
    const started = Math.floor(Date.now() / 1000), original = await jobs.observationSource(message);
    const result = await observeMoneySource(database, () => jobs.observationSource(message), profiles, deadline);
    deadline.throwIfAborted();
    if (result.status === 'disagreement') return { state: 'review' as const, reason: 'conflicting_evidence' as const };
    if (result.status !== 'observed' || result.finality.status !== 'finalized' || !result.finality.checkpoint || !result.position) return { state: 'waiting' as const };
    const c = original.record.candidate, current = await jobs.observationSource(message);
    const matching = profiles.filter(p => p.digest === c.deployment_digest && p.market.digest === original.record.review.context.market.digest);
    if (matching.length !== 1 || current.context !== original.context) throw new Error('MONEY_JOB_CHANGED');
    const profile = matching[0], manifest = loadPinnedDeploymentManifest(profile.document, profile.digest);
    const policy = loadPinnedFinalityPolicy(profile.finalityPolicy, manifest), receipt = result.receipt, evidence = result.finality, position = result.position;
    const checkpoint = receipt.outcome === 'outer_transaction_reverted' ? receipt.nonexecution.checkpoint : receipt;
    assertFinalityAssessment(evidence, { ...checkpoint, network_id: manifest.network_id, genesis_hash: manifest.genesis_hash });
    const now = Math.floor(Date.now() / 1000);
    if (receipt.outcome === 'outer_transaction_reverted') {
      if (!('inclusion_finality' in result) || receipt.nonexecution.nonce !== c.plan.nonce.toString()
        || receipt.nonexecution.valid_until !== c.plan.validUntil || BigInt(checkpoint.block_timestamp) <= BigInt(c.plan.validUntil)
        || BigInt(checkpoint.block_timestamp) > BigInt(now)
        || BigInt(checkpoint.block_number) < BigInt(receipt.block_number) || receipt.actual_gas_cost !== '0'
        || receipt.actual_gas_used !== '0') throw new Error('MONEY_RECONCILIATION_NONEXECUTION');
      const inclusion = result.inclusion_finality;
      assertFinalityAssessment(inclusion, { ...receipt, genesis_hash: manifest.genesis_hash });
      if (inclusion.status !== 'finalized' || !inclusion.checkpoint || inclusion.policy_sha256 !== profile.finalityPolicy.digest
        || inclusion.mechanism !== policy.mechanism || inclusion.assessed_at < started || inclusion.assessed_at > now
        || now >= inclusion.expires_at || inclusion.expires_at > inclusion.assessed_at + policy.evidence_ttl_seconds) throw new Error('MONEY_RECONCILIATION_NONEXECUTION');
    }
    if (receipt.userop_hash !== c.userOpHash || receipt.consent_digest !== c.digest || receipt.market_sha256 !== profile.market.digest
      || receipt.deployment_sha256 !== profile.digest || receipt.network_id !== manifest.network_id
      || evidence.policy_sha256 !== profile.finalityPolicy.digest || evidence.mechanism !== policy.mechanism
      || evidence.assessed_at < started || evidence.assessed_at > now || now >= evidence.expires_at
      || evidence.expires_at > evidence.assessed_at + policy.evidence_ttl_seconds || now < policy.valid_from || now >= policy.valid_until
      || position.account.toLowerCase() !== c.account.toLowerCase() || position.market_digest !== profile.market.digest
      || position.checkpoint.block_hash !== checkpoint.block_hash || position.checkpoint.block_number !== checkpoint.block_number
      || now < position.observed_at || now >= position.expires_at) throw new Error('MONEY_RECONCILIATION_EVIDENCE');
    const receiptJson = JSON.stringify(receipt), finalityJson = JSON.stringify('inclusion_finality' in result
      ? { settlement: evidence, inclusion: result.inclusion_finality } : evidence);
    const receiptDigest = deploymentDocumentDigest(receiptJson), finalityDigest = deploymentDocumentDigest(finalityJson);
    if (receiptJson.length > 16384 || finalityJson.length > 16384) throw new Error('MONEY_RECONCILIATION_SIZE');
    const outcome = receipt.outcome === 'execution_succeeded' ? 'reconciled' : 'reverted_confirmed';
    const from = `FROM money_operations r JOIN money_jobs t ON t.operation_id = r.id
      JOIN wallets w ON w.id = r.wallet_id JOIN users u ON u.id = w.user_id
      JOIN wallet_accounts a ON a.id = r.wallet_account_id AND a.wallet_id = w.id AND a.network_id = r.network_id`;
    const where = `r.id = ? AND t.lease_token = ? AND t.state = 'running' AND t.lease_expires_at > unixepoch()
      AND r.state IN ('dispatch_pending','submitted','confirming','review_required') AND r.review_sha256 = ?
      AND r.userop_hash = ? AND r.consent_digest = ? AND r.deployment_manifest_sha256 = ? AND r.market_sha256 = ?
      AND u.environment = ? AND w.account_id = ? AND w.initial_security_commitment = ? AND w.user_salt_commitment = ?
      AND a.address = r.account_address AND a.deployment_manifest_sha256 = r.deployment_manifest_sha256`;
    const access: string[] = [message.operation_id, message.token, writeMoneyReview(original.record.review).digest];
    access.push(c.userOpHash, c.digest, c.deployment_digest, original.record.review.context.market.digest, environment,
      c.plan.accountId, original.initialSecurityCommitment, original.userSaltCommitment);
    const db = database.withSession('first-primary');
    const values = [receiptJson, receiptDigest, finalityJson, finalityDigest];
    const journal = await db.batch<Record<string, unknown>>([
      db.prepare(`INSERT INTO money_finality_journal(operation_id,receipt_json,receipt_sha256,finality_json,finality_sha256,
        block_number,block_hash,outcome,recorded_at) SELECT r.id,?,?,?,?,?,?,?,? ${from} WHERE ${where}
        ON CONFLICT(operation_id) DO NOTHING`).bind(...values, checkpoint.block_number, checkpoint.block_hash, outcome, now, ...access),
      db.prepare(`INSERT INTO money_finality_conflicts(operation_id,receipt_json,receipt_sha256,finality_json,finality_sha256,recorded_at)
        SELECT r.id,?,?,?,?,? ${from} JOIN money_finality_journal j ON j.operation_id = r.id WHERE ${where}
        AND (j.receipt_json != ? OR j.receipt_sha256 != ?) ON CONFLICT(operation_id) DO NOTHING`)
        .bind(...values, now, ...access, receiptJson, receiptDigest),
      db.prepare('SELECT * FROM money_finality_journal WHERE operation_id = ?').bind(message.operation_id),
      db.prepare('SELECT operation_id FROM money_finality_conflicts WHERE operation_id = ?').bind(message.operation_id),
    ]);
    const after = await jobs.observationSource(message); deadline.throwIfAborted();
    if (after.context !== original.context || journal.some(row => !row.success)) throw new Error('MONEY_JOB_CHANGED');
    const saved = journal[2].results[0];
    if (!saved || typeof saved.receipt_json !== 'string' || typeof saved.finality_json !== 'string'
      || deploymentDocumentDigest(saved.receipt_json) !== saved.receipt_sha256
      || deploymentDocumentDigest(saved.finality_json) !== saved.finality_sha256) throw new Error('MONEY_JOB_JOURNAL');
    if (journal[3].results.length || saved.receipt_json !== receiptJson || saved.receipt_sha256 !== receiptDigest) return { state: 'review' as const, reason: 'conflicting_evidence' as const };
    const proof = { schema_version: 1, money_schema_version: 1, operation_id: message.operation_id, userop_hash: c.userOpHash,
      consent_digest: c.digest, receipt_sha256: receiptDigest, position, finality: evidence, checked_at: now,
      expires_at: Math.min(position.expires_at, evidence.expires_at), release_enabled: false };
    const json = JSON.stringify(proof); if (json.length > 32768) throw new Error('MONEY_RECONCILIATION_SIZE');
    const committed = await db.prepare(`INSERT INTO money_reconciliations(operation_id,wallet_account_id,receipt_sha256,
      block_number,block_hash,outcome,proof_json,proof_sha256,recorded_at)
      SELECT r.id,r.wallet_account_id,?,?,?,?,?,?,? ${from} WHERE ${where}
      AND ? > unixepoch() AND NOT EXISTS (SELECT 1 FROM money_finality_conflicts f WHERE f.operation_id = r.id)
      ON CONFLICT(operation_id) DO NOTHING RETURNING operation_id`)
      .bind(receiptDigest, checkpoint.block_number, checkpoint.block_hash, outcome, json, deploymentDocumentDigest(json), now,
        ...access, proof.expires_at).first<{ operation_id: string }>();
    // Reconciliation trigger closes operation, lock, balance floor and job atomically.
    if (committed?.operation_id !== message.operation_id) throw new Error('MONEY_JOB_COMMIT_CHANGED');
    return { state: 'reconciled' as const, outcome, operation_id: message.operation_id, funds_reserved: false as const };
  });
}
