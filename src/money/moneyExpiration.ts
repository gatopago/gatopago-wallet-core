import { isAddressEqual } from 'viem';
import { inspectAccountDeployment } from '@gatopago/shared/v3/account-inspection';
import { deploymentDocumentDigest, loadPinnedDeploymentManifest } from '@gatopago/shared/v3/deployment';
import { assertFinalityAssessment, assessCheckpointFinality, loadPinnedFinalityPolicy } from '@gatopago/shared/v3/finality';
import { parseResourceId, type ResourceId } from '@gatopago/shared/v3/primitives';
import { writeMoneyReview } from '@gatopago/shared/v3/money-review-record';
import { validateRpcProviders } from '../chainProviders';
import { createInspectionClient } from '../chainInspection';
import { withDeadline } from '../deadline';
import { networkFinality } from '../runtime/finality';
import { observeTransferNonce } from '../transfers/transferNonce';
import { readMoneyHistory } from './moneyHistoricalRecord';
import type { MoneyJobScope } from './moneyJobs';
import type { MoneyDeliveryProfile } from './moneyPreflight';

export async function expiredMoneyCandidates(database: D1Database, configuration: MoneyJobScope) {
  if (configuration.environment !== 'production' || configuration.profiles.length > 32) throw new Error('MONEY_EXPIRATION_SCOPE');
  const pins = configuration.profiles.map(p => { loadPinnedDeploymentManifest(p.document, p.digest); return p.digest + ':' + p.market.digest; });
  if (!pins.length) return [];
  const result = await database.withSession('first-primary').prepare(`SELECT r.id FROM money_operations r
    JOIN wallets w ON w.id = r.wallet_id JOIN users u ON u.id = w.user_id
    WHERE r.state = 'authorized' AND r.dispatch_started_at IS NULL AND r.expires_at < unixepoch()
      AND u.environment = ? AND (r.deployment_manifest_sha256 || ':' || r.market_sha256) IN (${pins.map(() => '?').join(',')})
      AND NOT EXISTS (SELECT 1 FROM user_operation_submissions s WHERE s.user_op_hash = r.userop_hash)
    ORDER BY r.expires_at,r.id LIMIT 20`).bind(configuration.environment, ...pins).all<{ id: string }>();
  if (!result.success) throw new Error('MONEY_EXPIRATION_STORAGE');
  return result.results.map(row => parseResourceId('operation', row.id));
}

/** Only a never-dispatched signed operation can expire. The whole proof comes
 * from admitted readers: finalized timestamp past the inclusive contract bound,
 * recognized account and unchanged EntryPoint nonce. No HTTP proof is accepted. */
export async function expireUnsubmittedMoney(database: D1Database, environment: MoneyJobScope['environment'],
  id: ResourceId<'operation'>, profilesInput: readonly MoneyDeliveryProfile[], signal: AbortSignal) {
  parseResourceId('operation', id);
  if (environment !== 'production' || profilesInput.length > 32) throw new Error('MONEY_EXPIRATION_SCOPE');
  const profiles = structuredClone(profilesInput);
  return withDeadline(signal, 45_000, async deadline => {
    const started = Math.floor(Date.now() / 1000);
    const read = () => database.withSession('first-primary').prepare(`SELECT r.*,
      w.account_id AS identity_account_id,w.initial_security_commitment,w.user_salt_commitment
      FROM money_operations r JOIN wallets w ON w.id = r.wallet_id JOIN users u ON u.id = w.user_id
      JOIN wallet_accounts a ON a.id = r.wallet_account_id AND a.wallet_id = w.id AND a.network_id = r.network_id
        AND a.address = r.account_address AND a.deployment_manifest_sha256 = r.deployment_manifest_sha256
      JOIN wallet_spend_locks l ON l.operation_id = r.id AND l.domain = 'money' AND l.state = 'held' AND l.released_at IS NULL
      WHERE r.id = ? AND r.state = 'authorized' AND r.dispatch_started_at IS NULL AND r.expires_at < unixepoch()
        AND w.canonical_address = r.account_address AND u.environment = ?
        AND NOT EXISTS (SELECT 1 FROM user_operation_submissions s WHERE s.user_op_hash = r.userop_hash)`)
      .bind(id, environment).first();
    if (!await read()) return { state: 'unchanged' as const };
    const original = await readMoneyHistory(read), c = original.record.candidate;
    const matches = profiles.filter(p => p.digest === c.deployment_digest && p.market.digest === original.record.review.context.market.digest);
    if (matches.length !== 1) throw new Error('MONEY_EXPIRATION_PROFILE');
    const profile = matches[0], manifest = loadPinnedDeploymentManifest(profile.document, profile.digest);
    const policy = loadPinnedFinalityPolicy(profile.finalityPolicy, manifest), peers = validateRpcProviders(profile.providers);
    const evidence = await networkFinality({ deployment: manifest, providers: peers, finalityPolicy: profile.finalityPolicy }, deadline);
    const checkpoint = evidence.checkpoint;
    if (evidence.status !== 'finalized' || !checkpoint || BigInt(checkpoint.block_timestamp) <= BigInt(c.plan.validUntil)) return { state: 'waiting' as const };
    const clients = peers.map(p => createInspectionClient(p.url, deadline));
    const [accounts, nonce] = await Promise.all([
      Promise.all(clients.map(client => inspectAccountDeployment(client, { document: profile.document, expectedDigest: profile.digest,
        initialSecurityCommitment: original.initialSecurityCommitment, userSaltCommitment: original.userSaltCommitment,
        checkpoint: { block_hash: checkpoint.block_hash, block_number: checkpoint.block_number } }))),
      observeTransferNonce({ network_id: manifest.network_id, genesis_hash: manifest.genesis_hash, account: c.account,
        entry_point: c.plan.entryPoint, entry_point_code_hash: profile.entryPointCodeHash, checkpoint }, peers, deadline),
    ]);
    deadline.throwIfAborted();
    if (accounts.some(account => account.status !== 'recognized' || account.account_id !== c.plan.accountId
      || !isAddressEqual(account.account, c.account)) || JSON.stringify(accounts[0]) !== JSON.stringify(accounts[1])
      || nonce.nonce !== c.plan.nonce.toString() || nonce.checkpoint.block_hash !== checkpoint.block_hash
      || nonce.checkpoint.block_number !== checkpoint.block_number || !isAddressEqual(nonce.account, c.account)
      || !isAddressEqual(nonce.entry_point, c.plan.entryPoint)) throw new Error('MONEY_EXPIRATION_NONCE_OR_ACCOUNT');
    const closing = await assessCheckpointFinality(clients, { ...checkpoint, network_id: manifest.network_id, genesis_hash: manifest.genesis_hash }, profile.finalityPolicy, deadline);
    assertFinalityAssessment(closing, { ...checkpoint, network_id: manifest.network_id, genesis_hash: manifest.genesis_hash });
    const now = Math.floor(Date.now() / 1000), time = Number(checkpoint.block_timestamp);
    if (closing.status !== 'finalized' || !closing.checkpoint || closing.policy_sha256 !== profile.finalityPolicy.digest
      || closing.mechanism !== policy.mechanism || closing.assessed_at < started || closing.assessed_at > now
      || now >= closing.expires_at || closing.expires_at > closing.assessed_at + policy.evidence_ttl_seconds
      || now < policy.valid_from || now >= policy.valid_until || !Number.isSafeInteger(time)
      || (await readMoneyHistory(read)).context !== original.context) throw new Error('MONEY_EXPIRATION_CHANGED');
    const proof = JSON.stringify({ schema_version: 1, operation_id: id, consent_digest: c.digest, userop_hash: c.userOpHash,
      deployment_sha256: profile.digest, market_sha256: profile.market.digest, nonce: nonce.nonce, checkpoint,
      finality: closing, checked_at: now, expires_at: Math.min(now + 5, closing.expires_at) });
    if (proof.length > 16384) throw new Error('MONEY_EXPIRATION_SIZE');
    const digest = deploymentDocumentDigest(proof), db = database.withSession('first-primary');
    const where = `r.id = ? AND r.state = 'authorized' AND r.dispatch_started_at IS NULL AND r.review_sha256 = ?
      AND r.userop_hash = ? AND r.consent_digest = ? AND r.nonce = ? AND r.expires_at < ?
      AND r.deployment_manifest_sha256 = ? AND r.market_sha256 = ? AND ? > unixepoch()
      AND EXISTS (SELECT 1 FROM wallets w JOIN users u ON u.id = w.user_id JOIN wallet_accounts a ON a.wallet_id = w.id
        WHERE w.id = r.wallet_id AND u.environment = ? AND w.account_id = ? AND w.initial_security_commitment = ?
          AND w.user_salt_commitment = ? AND w.canonical_address = r.account_address AND a.id = r.wallet_account_id
          AND a.address = r.account_address AND a.network_id = r.network_id AND a.deployment_manifest_sha256 = r.deployment_manifest_sha256)
      AND EXISTS (SELECT 1 FROM wallet_spend_locks l WHERE l.operation_id = r.id AND l.domain = 'money' AND l.state = 'held' AND l.released_at IS NULL)
      AND NOT EXISTS (SELECT 1 FROM user_operation_submissions s WHERE s.user_op_hash = r.userop_hash)`;
    const access = [id, writeMoneyReview(original.record.review).digest, c.userOpHash, c.digest, nonce.nonce, time,
      profile.digest, profile.market.digest, Math.min(now + 5, closing.expires_at), environment, c.plan.accountId,
      original.initialSecurityCommitment, original.userSaltCommitment];
    deadline.throwIfAborted();
    const results = await db.batch<Record<string, unknown>>([
      db.prepare(`INSERT INTO money_expirations(operation_id,checkpoint_json,checkpoint_sha256,block_timestamp,observed_nonce,recorded_at)
        SELECT r.id,?,?,?,?,? FROM money_operations r WHERE ${where} ON CONFLICT(operation_id) DO NOTHING`)
        .bind(proof, digest, time, nonce.nonce, now, ...access),
      db.prepare(`UPDATE money_operations AS r SET state = 'expired_unsubmitted' WHERE ${where}
        AND EXISTS (SELECT 1 FROM money_expirations e WHERE e.operation_id = r.id AND e.checkpoint_sha256 = ?
          AND e.checkpoint_json = ? AND e.block_timestamp = ? AND e.observed_nonce = r.nonce) RETURNING id`)
        .bind(...access, digest, proof, time),
    ]);
    if (results.some(result => !result.success)) throw new Error('MONEY_EXPIRATION_STORAGE');
    return { state: results[1].results[0]?.id === id ? 'expired_unsubmitted' as const : 'unchanged' as const };
  });
}
