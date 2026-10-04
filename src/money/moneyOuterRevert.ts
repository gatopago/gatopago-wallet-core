import { isAddressEqual, toHex, type Hex, type PublicClient } from 'viem';
import { inspectAccountDeployment } from '@gatopago/shared/v3/account-inspection';
import { loadPinnedDeploymentManifest, requireHash } from '@gatopago/shared/v3/deployment';
import {
  assertFinalityAssessment,
  assessCheckpointFinality,
  loadPinnedFinalityPolicy,
} from '@gatopago/shared/v3/finality';
import { verifiedSelfSubmission } from '../execution/operationTransport';
import { networkFinality } from '../runtime/finality';
import { observeTransferNonce } from '../transfers/transferNonce';
import { rpcQuantity } from '../portfolio/checkpointReader';
import { observeAavePosition } from '../portfolio/aavePositionObservation';
import type { MoneyObservationSource } from './moneyObservation';
import type { MoneyDeliveryProfile } from './moneyPreflight';

/** No inner UserOperationEvent exists when handleOps itself reverts. The exact
 * private envelope plus finalized expiry and unchanged EntryPoint nonce prove
 * nonexecution. The operator's actual outer gas is not an account charge. */
export async function observeMoneyOuterRevert(
  database: D1Database,
  source: MoneyObservationSource,
  profile: MoneyDeliveryProfile,
  clients: readonly PublicClient[],
  raw: readonly unknown[],
  signal: AbortSignal,
) {
  const started = Math.floor(Date.now() / 1000),
    c = source.record.candidate;
  const manifest = loadPinnedDeploymentManifest(profile.document, profile.digest);
  const policy = loadPinnedFinalityPolicy(profile.finalityPolicy, manifest);
  const envelope = await verifiedSelfSubmission(
    database,
    {
      operation: source.record.operation,
      networkId: c.request.network_id,
      entryPoint: c.plan.entryPoint,
      userOpHash: c.userOpHash,
      validUntil: c.plan.validUntil,
    },
    signal,
  );
  if (!envelope) return { status: 'unavailable' as const };
  const receipts = await Promise.all(
    raw.map(async (input, index) => {
      if (!input || typeof input !== 'object' || Array.isArray(input))
        throw new Error('MONEY_OUTER_RECEIPT');
      const receipt = input as Record<string, unknown>;
      if (
        receipt.status !== '0x0' ||
        receipt.transactionHash !== envelope.transaction_hash ||
        receipt.type !== '0x2' ||
        typeof receipt.from !== 'string' ||
        typeof receipt.to !== 'string' ||
        !isAddressEqual(receipt.from as Hex, envelope.operator) ||
        !isAddressEqual(receipt.to as Hex, c.plan.entryPoint) ||
        receipt.contractAddress !== null ||
        !Array.isArray(receipt.logs) ||
        receipt.logs.length !== 0
      )
        throw new Error('MONEY_OUTER_RECEIPT');
      requireHash(receipt.blockHash);
      const blockNumber = rpcQuantity(receipt.blockNumber),
        transactionIndex = rpcQuantity(receipt.transactionIndex);
      const gas = rpcQuantity(receipt.gasUsed),
        price = rpcQuantity(receipt.effectiveGasPrice),
        l1Gas = rpcQuantity(receipt.gasUsedForL1);
      if (
        gas === 0n ||
        gas > envelope.gas ||
        price === 0n ||
        price > envelope.max_fee_per_gas ||
        l1Gas > gas
      )
        throw new Error('MONEY_OUTER_GAS');
      const block = await clients[index].request(
        { method: 'eth_getBlockByNumber', params: [toHex(blockNumber), false] },
        { retryCount: 0, dedupe: false },
      );
      if (!block || block.hash !== receipt.blockHash || rpcQuantity(block.number) !== blockNumber)
        throw new Error('MONEY_OUTER_BLOCK');
      return {
        block_hash: receipt.blockHash,
        block_number: blockNumber.toString(),
        block_timestamp: rpcQuantity(block.timestamp).toString(),
        transaction_index: transactionIndex.toString(),
        operator: envelope.operator,
        nonce: String(envelope.nonce),
        gas_used: gas.toString(),
        effective_gas_price_atomic: price.toString(),
        gas_used_for_l1: l1Gas.toString(),
        gas_cost_atomic: (gas * price).toString(),
      };
    }),
  );
  signal.throwIfAborted();
  if (receipts.length !== 2 || JSON.stringify(receipts[0]) !== JSON.stringify(receipts[1]))
    return { status: 'disagreement' as const };
  const outer = receipts[0],
    target = { ...outer, network_id: manifest.network_id, genesis_hash: manifest.genesis_hash };
  const inclusion = await assessCheckpointFinality(clients, target, profile.finalityPolicy, signal);
  assertFinalityAssessment(inclusion, target);
  if (inclusion.status !== 'finalized' || !inclusion.checkpoint)
    return { status: 'not_observed' as const };
  const evidence = await networkFinality(
    { deployment: manifest, providers: profile.providers, finalityPolicy: profile.finalityPolicy },
    signal,
  );
  const latest = evidence.checkpoint;
  if (
    evidence.status !== 'finalized' ||
    !latest ||
    BigInt(latest.block_timestamp) <= BigInt(c.plan.validUntil) ||
    BigInt(latest.block_number) < BigInt(outer.block_number)
  )
    return { status: 'not_observed' as const };
  assertFinalityAssessment(evidence, {
    ...evidence.target,
    network_id: manifest.network_id,
    genesis_hash: manifest.genesis_hash,
  });
  // Pick a deterministic checkpoint: the receipt block if already expired, or
  // the first later block past expiry. A newer finality head must not change the
  // immutable receipt digest when a job restarts after writing its journal.
  async function header(number: bigint) {
    const blocks = await Promise.all(
      clients.map(async (client) => {
        const block = await client.request(
          { method: 'eth_getBlockByNumber', params: [toHex(number), false] },
          { retryCount: 0, dedupe: false },
        );
        if (!block || rpcQuantity(block.number) !== number) throw new Error('MONEY_OUTER_BLOCK');
        requireHash(block.hash);
        return {
          block_hash: block.hash,
          block_number: number.toString(),
          block_timestamp: rpcQuantity(block.timestamp).toString(),
        };
      }),
    );
    if (blocks.length !== 2 || JSON.stringify(blocks[0]) !== JSON.stringify(blocks[1]))
      throw new Error('MONEY_OUTER_BLOCK');
    return blocks[0];
  }
  let lower = BigInt(outer.block_number),
    upper = BigInt(latest.block_number),
    steps = 0;
  if (BigInt(outer.block_timestamp) <= BigInt(c.plan.validUntil)) {
    lower++;
    if (lower > upper) throw new Error('MONEY_OUTER_BLOCK');
    while (lower < upper) {
      if (++steps > 64) throw new Error('MONEY_OUTER_SEARCH_LIMIT');
      const mid = (lower + upper) / 2n,
        block = await header(mid);
      if (BigInt(block.block_timestamp) > BigInt(c.plan.validUntil)) upper = mid;
      else lower = mid + 1n;
    }
  }
  const checkpoint = await header(lower);
  if (
    BigInt(checkpoint.block_timestamp) <= BigInt(c.plan.validUntil) ||
    (checkpoint.block_number === outer.block_number && checkpoint.block_hash !== outer.block_hash)
  )
    throw new Error('MONEY_OUTER_BLOCK');
  const [accounts, nonce, position] = await Promise.all([
    Promise.all(
      clients.map((client) =>
        inspectAccountDeployment(client, {
          document: profile.document,
          expectedDigest: profile.digest,
          initialSecurityCommitment: source.initialSecurityCommitment,
          userSaltCommitment: source.userSaltCommitment,
          checkpoint,
        }),
      ),
    ),
    observeTransferNonce(
      {
        network_id: manifest.network_id,
        genesis_hash: manifest.genesis_hash,
        account: c.account,
        entry_point: c.plan.entryPoint,
        entry_point_code_hash: profile.entryPointCodeHash,
        checkpoint,
      },
      profile.providers,
      signal,
    ),
    observeAavePosition(
      { account: c.account, market: profile.market, checkpoint },
      profile.providers,
      signal,
    ),
  ]);
  signal.throwIfAborted();
  if (
    accounts.some(
      (account) =>
        account.status !== 'recognized' ||
        account.account_id !== c.plan.accountId ||
        !isAddressEqual(account.account, c.account),
    ) ||
    JSON.stringify(accounts[0]) !== JSON.stringify(accounts[1]) ||
    nonce.nonce !== c.plan.nonce.toString() ||
    nonce.checkpoint.block_hash !== checkpoint.block_hash ||
    nonce.checkpoint.block_number !== checkpoint.block_number ||
    !isAddressEqual(nonce.account, c.account) ||
    !isAddressEqual(nonce.entry_point, c.plan.entryPoint)
  )
    throw new Error('MONEY_OUTER_NONEXECUTION');
  const closing = await assessCheckpointFinality(
    clients,
    { ...checkpoint, network_id: manifest.network_id, genesis_hash: manifest.genesis_hash },
    profile.finalityPolicy,
    signal,
  );
  const closingInclusion = await assessCheckpointFinality(
    clients,
    target,
    profile.finalityPolicy,
    signal,
  );
  assertFinalityAssessment(closing, {
    ...checkpoint,
    network_id: manifest.network_id,
    genesis_hash: manifest.genesis_hash,
  });
  assertFinalityAssessment(closingInclusion, target);
  const now = Math.floor(Date.now() / 1000);
  signal.throwIfAborted();
  if (
    BigInt(checkpoint.block_timestamp) > BigInt(now) ||
    BigInt(outer.block_timestamp) > BigInt(now)
  )
    throw new Error('MONEY_OUTER_BLOCK');
  for (const proof of [inclusion, evidence, closing, closingInclusion]) {
    if (
      proof.status !== 'finalized' ||
      !proof.checkpoint ||
      proof.policy_sha256 !== profile.finalityPolicy.digest ||
      proof.mechanism !== policy.mechanism ||
      proof.assessed_at < started ||
      proof.assessed_at > now ||
      now >= proof.expires_at ||
      proof.expires_at > proof.assessed_at + policy.evidence_ttl_seconds ||
      now < policy.valid_from ||
      now >= policy.valid_until
    )
      throw new Error('MONEY_OUTER_FINALITY');
  }
  if (
    position.account !== c.account ||
    position.market_digest !== profile.market.digest ||
    position.checkpoint.block_hash !== checkpoint.block_hash ||
    position.checkpoint.block_number !== checkpoint.block_number ||
    now < position.observed_at ||
    now >= position.expires_at
  )
    throw new Error('MONEY_OUTER_POSITION');
  const receipt = Object.freeze({
    schema_version: 1 as const,
    money_schema_version: 1 as const,
    network_id: c.request.network_id,
    market_id: c.request.market_id,
    market_sha256: profile.market.digest,
    deployment_sha256: c.deployment_digest,
    userop_hash: c.userOpHash,
    consent_digest: c.digest,
    transaction_hash: envelope.transaction_hash,
    block_hash: outer.block_hash,
    block_number: outer.block_number,
    block_timestamp: outer.block_timestamp,
    transaction_index: outer.transaction_index,
    kind: c.request.kind,
    amount_atomic: c.request.amount_atomic,
    recipient_address: c.request.recipient_address ?? null,
    outcome: 'outer_transaction_reverted' as const,
    actual_gas_cost: '0',
    actual_gas_used: '0',
    log_indexes: { operation: null, calls: null, pool: null, transfers: [], approvals: [] },
    outer_transaction: {
      operator: outer.operator,
      nonce: outer.nonce,
      gas_used: outer.gas_used,
      effective_gas_price_atomic: outer.effective_gas_price_atomic,
      gas_used_for_l1: outer.gas_used_for_l1,
      gas_cost_atomic: outer.gas_cost_atomic,
    },
    nonexecution: { nonce: nonce.nonce, valid_until: c.plan.validUntil, checkpoint },
    finality: 'not_assessed' as const,
    settlement: 'not_assessed' as const,
  });
  return {
    status: 'observed' as const,
    receipt,
    finality: closing,
    position,
    inclusion_finality: closingInclusion,
  };
}
