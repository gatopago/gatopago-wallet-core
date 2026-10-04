import { deriveAccountId } from '@gatopago/shared/v3/authorizations';
import { deploymentDocumentDigest, requireHash } from '@gatopago/shared/v3/deployment';
import { readMoneyReview } from '@gatopago/shared/v3/money-review-record';
import { parseResourceId } from '@gatopago/shared/v3/primitives';
import { moneyFunds } from './moneyRepository';

/** Restore an already authorized obligation. This grants no current signing or
 * sending authority and intentionally does not depend on an active login. */
export async function readMoneyHistory(read: () => Promise<Record<string, unknown> | null>) {
  const row = await read();
  if (!row) throw new Error('MONEY_HISTORY_UNAVAILABLE');
  requireHash(row.identity_account_id);
  requireHash(row.initial_security_commitment);
  requireHash(row.user_salt_commitment);
  if (
    deriveAccountId(row.initial_security_commitment, row.user_salt_commitment) !==
    row.identity_account_id
  )
    throw new Error('MONEY_HISTORY_RECORD');
  const record = await readMoneyReview(row.review_json, row.review_sha256),
    candidate = record.candidate;
  const funds = moneyFunds(candidate);
  if (
    candidate.request.wallet_id !== row.wallet_id ||
    candidate.request.wallet_account_id !== row.wallet_account_id ||
    candidate.request.network_id !== row.network_id ||
    candidate.account.toLowerCase() !== row.account_address ||
    candidate.plan.accountId !== row.identity_account_id ||
    candidate.deployment_digest !== row.deployment_manifest_sha256 ||
    candidate.userOpHash !== row.userop_hash ||
    candidate.digest !== row.consent_digest ||
    candidate.operation.nonce.toString() !== row.nonce ||
    candidate.plan.validUntil !== row.expires_at ||
    candidate.plan.entryPoint.toLowerCase() !== row.entry_point ||
    record.review.context.market.digest !== row.market_sha256 ||
    row.funds_json !== funds.json ||
    row.funds_sha256 !== funds.digest ||
    JSON.stringify(await read()) !== JSON.stringify(row)
  )
    throw new Error('MONEY_HISTORY_RECORD');
  return Object.freeze({
    record,
    context: deploymentDocumentDigest(JSON.stringify(row)),
    row,
    walletAccountId: parseResourceId('walletAccount', row.wallet_account_id),
    initialSecurityCommitment: row.initial_security_commitment,
    userSaltCommitment: row.user_salt_commitment,
  });
}
