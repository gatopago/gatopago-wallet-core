import {
  encodeAbiParameters,
  encodeEventTopics,
  erc20Abi,
  isAddressEqual,
  type Address,
  type Hex,
} from 'viem';
import { aavePoolAbi, loadAaveMarket, marketToken } from '@gatopago/shared/v3/aave-market';
import type { readMoneyReview } from '@gatopago/shared/v3/money-review-record';
import {
  verifyUserOperationReceipt,
  type OperationReceiptLog,
} from '../execution/userOperationReceipt';

const addressTopic = (value: Address) => encodeAbiParameters([{ type: 'address' }], [value]);
const amountData = (value: bigint) => encodeAbiParameters([{ type: 'uint256' }], [value]);
const transferTopic = encodeEventTopics({ abi: erc20Abi, eventName: 'Transfer' })[0];
const approvalTopic = encodeEventTopics({ abi: erc20Abi, eventName: 'Approval' })[0];
const supplyTopic = encodeEventTopics({ abi: aavePoolAbi, eventName: 'Supply' })[0];
const withdrawTopic = encodeEventTopics({ abi: aavePoolAbi, eventName: 'Withdraw' })[0];

/** Verify one recipe's principal effects inside the precise UserOperation slice.
 * Interest-bearing aToken Mint/Burn amounts are deliberately not interpreted as
 * principal. Code/proxy identity, post-position and finality remain mandatory. */
export function verifyMoneyReceipt(
  record: Awaited<ReturnType<typeof readMoneyReview>>,
  transactionHash: Hex,
  input: unknown,
) {
  const candidate = record.candidate,
    market = loadAaveMarket(record.review.context.market),
    token = marketToken(market);
  let base: ReturnType<typeof verifyUserOperationReceipt>;
  try {
    base = verifyUserOperationReceipt(candidate, transactionHash, input);
  } catch (error) {
    if (error instanceof Error && error.message.startsWith('OPERATION_RECEIPT_'))
      throw new Error(error.message.replace('OPERATION_RECEIPT_', 'MONEY_RECEIPT_'), {
        cause: error,
      });
    throw error;
  }
  const amount = BigInt(candidate.request.amount_atomic),
    transferIndexes: string[] = [],
    approvalIndexes: string[] = [];
  const poolEvents = base.scoped.filter(
    (log) =>
      isAddressEqual(log.address, market.pool) &&
      [supplyTopic, withdrawTopic].includes(log.topics[0]),
  );
  const transfers = base.scoped.filter(
    (log) => isAddressEqual(log.address, token) && log.topics[0] === transferTopic,
  );
  const approvals = base.scoped.filter(
    (log) =>
      isAddressEqual(log.address, token) &&
      log.topics[0] === approvalTopic &&
      log.topics[1] === addressTopic(candidate.account),
  );
  const matchesTransfer = (event: OperationReceiptLog, from: Address, to: Address) =>
    event.topics.length === 3 &&
    event.topics[1] === addressTopic(from) &&
    event.topics[2] === addressTopic(to) &&
    event.data === amountData(amount);
  let poolIndex: string | null = null;
  if (base.outcome.success) {
    if (!base.calls || poolEvents.length !== 1 || poolEvents[0].index >= base.calls.index)
      throw new Error('MONEY_RECEIPT_EFFECT_UNPROVEN');
    const event = poolEvents[0];
    poolIndex = event.index.toString();
    if (candidate.request.kind === 'aave_supply') {
      if (
        event.topics.length !== 4 ||
        event.topics[0] !== supplyTopic ||
        event.topics[1] !== addressTopic(token) ||
        event.topics[2] !== addressTopic(candidate.account) ||
        event.topics[3] !== encodeAbiParameters([{ type: 'uint16' }], [0]) ||
        event.data !==
          encodeAbiParameters(
            [{ type: 'address' }, { type: 'uint256' }],
            [candidate.account, amount],
          ) ||
        transfers.length !== 1 ||
        !matchesTransfer(transfers[0], candidate.account, market.a_token) ||
        transfers[0].index >= event.index ||
        approvals.length !== 3
      )
        throw new Error('MONEY_RECEIPT_EFFECT_UNPROVEN');
      approvals.forEach((approval, index) => {
        const expected = index === 1 ? amount : 0n;
        if (
          approval.topics.length !== 3 ||
          approval.topics[2] !== addressTopic(market.pool) ||
          approval.data !== amountData(expected) ||
          (index < 2 && approval.index >= transfers[0].index) ||
          (index === 2 && approval.index <= event.index) ||
          approval.index >= base.calls!.index
        )
          throw new Error('MONEY_RECEIPT_ALLOWANCE_UNPROVEN');
        approvalIndexes.push(approval.index.toString());
      });
    } else {
      const pay = candidate.request.kind === 'aave_withdraw_and_pay',
        recipient = candidate.request.recipient_address;
      if (
        event.topics.length !== 4 ||
        event.topics[0] !== withdrawTopic ||
        event.topics[1] !== addressTopic(token) ||
        event.topics[2] !== addressTopic(candidate.account) ||
        event.topics[3] !== addressTopic(candidate.account) ||
        event.data !== amountData(amount) ||
        transfers.length !== (pay ? 2 : 1) ||
        !matchesTransfer(transfers[0], market.a_token, candidate.account) ||
        transfers[0].index >= event.index ||
        approvals.length !== 0 ||
        (pay &&
          (!recipient ||
            !matchesTransfer(transfers[1], candidate.account, recipient) ||
            transfers[1].index <= event.index))
      )
        throw new Error('MONEY_RECEIPT_EFFECT_UNPROVEN');
    }
    for (const transfer of transfers) {
      if (transfer.index >= base.calls.index) throw new Error('MONEY_RECEIPT_EFFECT_UNPROVEN');
      transferIndexes.push(transfer.index.toString());
    }
  } else if (poolEvents.length || transfers.length || approvals.length)
    throw new Error('MONEY_RECEIPT_REVERT_INCONSISTENT');
  return Object.freeze({
    schema_version: 1 as const,
    money_schema_version: 1 as const,
    network_id: candidate.request.network_id,
    market_id: market.market_id,
    market_sha256: record.review.context.market.digest,
    deployment_sha256: candidate.deployment_digest,
    userop_hash: candidate.userOpHash,
    consent_digest: candidate.digest,
    transaction_hash: transactionHash,
    block_hash: base.blockHash,
    block_number: base.blockNumber.toString(),
    transaction_index: base.transactionIndex.toString(),
    kind: candidate.request.kind,
    amount_atomic: candidate.request.amount_atomic,
    recipient_address: candidate.request.recipient_address ?? null,
    outcome: base.outcome.success
      ? ('execution_succeeded' as const)
      : ('execution_reverted' as const),
    actual_gas_cost: base.outcome.actualGasCost.toString(),
    actual_gas_used: base.outcome.actualGasUsed.toString(),
    log_indexes: {
      operation: base.operation.index.toString(),
      calls: base.calls?.index.toString() ?? null,
      pool: poolIndex,
      transfers: transferIndexes,
      approvals: approvalIndexes,
    },
    finality: 'not_assessed' as const,
    settlement: 'not_assessed' as const,
  });
}
