import type { Hex } from 'viem';
import type { readMoneyReview } from '@gatopago/shared/v3/money-review-record';
import { loadPinnedDeploymentManifest } from '@gatopago/shared/v3/deployment';
import { assessCheckpointFinality, loadPinnedFinalityPolicy } from '@gatopago/shared/v3/finality';
import { validateRpcProviders } from '../chainProviders';
import { createInspectionClient } from '../chainInspection';
import { inspectReceiptAccount } from '../execution/receiptAccount';
import { submissionTransaction } from '../execution/operationTransport';
import { observeAavePosition } from '../portfolio/aavePositionObservation';
import { withDeadline } from '../deadline';
import { verifyMoneyReceipt } from './moneyReceipt';
import type { MoneyDeliveryProfile } from './moneyPreflight';
import { observeMoneyOuterRevert } from './moneyOuterRevert';

export interface MoneyObservationSource {
  readonly record: Awaited<ReturnType<typeof readMoneyReview>>;
  readonly context: string;
  readonly initialSecurityCommitment: Hex;
  readonly userSaltCommitment: Hex;
}

/** Private source is either a real owner or a live internal job lease. A missing
 * receipt, disagreement or RPC failure never proves expiry or releases funds. */
export async function observeMoneySource(
  database: D1Database,
  source: () => Promise<MoneyObservationSource>,
  profilesInput: readonly MoneyDeliveryProfile[],
  signal: AbortSignal,
) {
  const profiles = structuredClone(profilesInput);
  return withDeadline(signal, 45_000, async (deadline) => {
    const original = await source(),
      record = original.record,
      c = record.candidate;
    const matching = profiles.filter(
      (p) =>
        p.digest === c.deployment_digest && p.market.digest === record.review.context.market.digest,
    );
    if (matching.length !== 1) throw new Error('MONEY_OBSERVATION_PROFILE');
    const profile = matching[0],
      manifest = loadPinnedDeploymentManifest(profile.document, profile.digest);
    loadPinnedFinalityPolicy(profile.finalityPolicy, manifest);
    const peers = validateRpcProviders(profile.providers),
      clients = peers.map((p) => createInspectionClient(p.url, deadline));
    async function observe() {
      const transaction = await submissionTransaction(database, c.userOpHash, deadline);
      if (!transaction) return { status: 'not_observed' as const };
      const results = await Promise.allSettled(
        clients.map(async (client) => {
          const raw = await client.request(
            { method: 'eth_getTransactionReceipt', params: [transaction] },
            { retryCount: 0, dedupe: false },
          );
          if (raw === null) return null;
          if (raw && typeof raw === 'object' && 'status' in raw && raw.status === '0x0')
            return { outer: raw };
          const observation = verifyMoneyReceipt(record, transaction, raw);
          const timestamp = await inspectReceiptAccount(client, c, observation, {
            document: profile.document,
            expectedDigest: profile.digest,
            entryPointCodeHash: profile.entryPointCodeHash,
            initialSecurityCommitment: original.initialSecurityCommitment,
            userSaltCommitment: original.userSaltCommitment,
          });
          return { ...observation, block_timestamp: timestamp };
        }),
      );
      deadline.throwIfAborted();
      const [first, second] = results;
      if (first.status !== 'fulfilled' || second.status !== 'fulfilled')
        return { status: 'unavailable' as const };
      if (first.value && 'outer' in first.value) {
        if (!second.value || !('outer' in second.value)) return { status: 'disagreement' as const };
        return observeMoneyOuterRevert(
          database,
          original,
          profile,
          clients,
          [first.value.outer, second.value.outer],
          deadline,
        );
      }
      if (JSON.stringify(first.value) !== JSON.stringify(second.value))
        return { status: 'disagreement' as const };
      if (!first.value) return { status: 'not_observed' as const };
      const receipt = first.value,
        target = { ...receipt, genesis_hash: manifest.genesis_hash };
      const finality = await assessCheckpointFinality(
        clients,
        target,
        profile.finalityPolicy,
        deadline,
      );
      if (finality.status !== 'finalized' || !finality.checkpoint)
        return { status: 'observed' as const, receipt, finality, position: null };
      // Re-observe the position at the inclusion block. Exact principal comes
      // from the scoped USDC/Pool logs; interest-bearing balance deltas differ.
      const position = await observeAavePosition(
        {
          account: c.account,
          market: profile.market,
          checkpoint: { block_hash: receipt.block_hash, block_number: receipt.block_number },
        },
        peers,
        deadline,
      );
      if (
        c.request.kind === 'aave_supply' &&
        receipt.outcome === 'execution_succeeded' &&
        position.allowance_atomic !== '0'
      )
        throw new Error('MONEY_RECEIPT_ALLOWANCE_REMAINING');
      const closing = await assessCheckpointFinality(
        clients,
        target,
        profile.finalityPolicy,
        deadline,
      );
      if (closing.status !== 'finalized' || !closing.checkpoint)
        return { status: 'unavailable' as const };
      const now = Math.floor(Date.now() / 1000);
      if (
        now < position.observed_at ||
        now >= position.expires_at ||
        now >= finality.expires_at ||
        now >= closing.expires_at
      )
        return { status: 'unavailable' as const };
      return { status: 'observed' as const, receipt, finality: closing, position };
    }
    let result: Awaited<ReturnType<typeof observe>>;
    try {
      result = await observe();
    } catch {
      deadline.throwIfAborted();
      result = { status: 'unavailable' };
    }
    const current = await source();
    deadline.throwIfAborted();
    if (current.context !== original.context) throw new Error('MONEY_OBSERVATION_CHANGED');
    return Object.freeze(result);
  });
}
