import {
  encodeAbiParameters,
  encodeEventTopics,
  getAddress,
  isAddress,
  isAddressEqual,
  parseAbi,
  type Address,
  type Hex,
} from 'viem';
import type { readTransferReview } from '@gatopago/shared/v3/transfer-review-record';
import { verifyUserOperationReceipt } from '../execution/userOperationReceipt';

export const transferReceiptAbi = parseAbi([
  'event BeforeExecution()',
  'event UserOperationEvent(bytes32 indexed userOpHash, address indexed sender, address indexed paymaster, uint256 nonce, bool success, uint256 actualGasCost, uint256 actualGasUsed)',
  'event CallsExecuted(bytes32 indexed callsHash, uint64 securityVersion, uint8 executionMode)',
  'event Transfer(address indexed from, address indexed to, uint256 value)',
]);
function address(value: unknown): Address {
  if (typeof value !== 'string' || !isAddress(value, { strict: false }))
    throw new Error('TRANSFER_RECEIPT_INVALID');
  return getAddress(value);
}
const topic = (name: (typeof transferReceiptAbi)[number]['name']) =>
  encodeEventTopics({ abi: transferReceiptAbi, eventName: name })[0];

export function verifyTransferReceipt(
  record: Awaited<ReturnType<typeof readTransferReview>>,
  transactionHash: Hex,
  input: unknown,
) {
  const c = record.candidate;
  let base: ReturnType<typeof verifyUserOperationReceipt>;
  try {
    base = verifyUserOperationReceipt(c, transactionHash, input);
  } catch (error) {
    if (error instanceof Error && error.message.startsWith('OPERATION_RECEIPT_'))
      throw new Error(error.message.replace('OPERATION_RECEIPT_', 'TRANSFER_RECEIPT_'), {
        cause: error,
      });
    throw error;
  }
  const { blockHash, blockNumber, transactionIndex, outcome, scoped, operation: op } = base;
  const calls = base.calls ? [base.calls] : [];
  const token =
    c.request.asset_id === record.review.context.native_asset_id
      ? null
      : address(c.request.asset_id.split('/erc20:')[1]);
  const transferIndexes: string[] = [];
  if (outcome.success && token) {
    const from = encodeAbiParameters([{ type: 'address' }], [c.account]);
    const transfers = scoped.filter(
      (l) =>
        isAddressEqual(l.address, token) &&
        l.topics[0] === topic('Transfer') &&
        l.topics[1] === from,
    );
    const expected = [{ to: c.request.destination.address, amount: c.funding.amount_atomic }];
    if (record.review.context.fee_recipient)
      expected.push({
        to: record.review.context.fee_recipient,
        amount: record.review.context.budget.platform_fee.amount_atomic,
      });
    if (transfers.length !== expected.length) throw new Error('TRANSFER_RECEIPT_ASSET_UNPROVEN');
    transfers.forEach((event, i) => {
      if (
        event.index >= calls[0].index ||
        event.topics.length !== 3 ||
        event.topics[2] !==
          encodeAbiParameters([{ type: 'address' }], [getAddress(expected[i].to)]) ||
        event.data !== encodeAbiParameters([{ type: 'uint256' }], [BigInt(expected[i].amount)])
      )
        throw new Error('TRANSFER_RECEIPT_ASSET_UNPROVEN');
      transferIndexes.push(event.index.toString());
    });
  }
  return Object.freeze({
    schema_version: 1 as const,
    network_id: c.request.network_id,
    deployment_sha256: c.deployment_digest,
    userop_hash: c.userOpHash,
    consent_digest: c.digest,
    transaction_hash: transactionHash,
    block_hash: blockHash,
    block_number: blockNumber.toString(),
    transaction_index: transactionIndex.toString(),
    outcome: outcome.success ? ('execution_succeeded' as const) : ('execution_reverted' as const),
    actual_gas_cost: outcome.actualGasCost.toString(),
    actual_gas_used: outcome.actualGasUsed.toString(),
    log_indexes: Object.freeze({
      operation: op.index.toString(),
      calls: calls[0]?.index.toString() ?? null,
      transfers: Object.freeze(transferIndexes),
    }),
    finality: 'not_assessed' as const,
    settlement: 'not_assessed' as const,
  });
}
