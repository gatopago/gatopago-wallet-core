import { decodeEventLog, encodeAbiParameters, encodeEventTopics, getAddress, isAddress, isAddressEqual, parseAbi, type Address, type Hex } from 'viem';
import { requireHash } from '@gatopago/shared/v3/deployment';
import type { readTransferReview } from '@gatopago/shared/v3/transfer-review-record';

export const transferReceiptAbi = parseAbi([
  'event BeforeExecution()',
  'event UserOperationEvent(bytes32 indexed userOpHash, address indexed sender, address indexed paymaster, uint256 nonce, bool success, uint256 actualGasCost, uint256 actualGasUsed)',
  'event CallsExecuted(bytes32 indexed callsHash, uint64 securityVersion, uint8 executionMode)',
  'event Transfer(address indexed from, address indexed to, uint256 value)',
]);
function row(value: unknown): Record<string, unknown> {
  if (!value || typeof value !== 'object' || Array.isArray(value)) throw new Error('TRANSFER_RECEIPT_INVALID');
  return value as Record<string, unknown>;
}
function quantity(value: unknown) {
  if (typeof value !== 'string' || !/^0x(?:0|[1-9a-f][0-9a-f]{0,63})$(?![\s\S])/.test(value)) throw new Error('TRANSFER_RECEIPT_INVALID');
  return BigInt(value);
}
function bytes(value: unknown, max: number): Hex {
  if (typeof value !== 'string' || value.length > max * 2 + 2 || !/^0x(?:[0-9a-fA-F]{2})*$(?![\s\S])/.test(value)) throw new Error('TRANSFER_RECEIPT_INVALID');
  return value.toLowerCase() as Hex;
}
function address(value: unknown): Address {
  if (typeof value !== 'string' || !isAddress(value, { strict: false })) throw new Error('TRANSFER_RECEIPT_INVALID');
  return getAddress(value);
}
const topic = (name: typeof transferReceiptAbi[number]['name']) => encodeEventTopics({ abi: transferReceiptAbi, eventName: name })[0];

/** Raw execution receipt consistency, not RPC honesty/finality or a database
 * settlement transition. Caller restores the signed review and verifies pinned
 * chain/EntryPoint/account code at the canonical receipt block independently.
 */
export function verifyTransferReceipt(record: Awaited<ReturnType<typeof readTransferReview>>, transactionHash: Hex, input: unknown) {
  requireHash(transactionHash);
  const receipt = row(input), c = record.candidate, plan = c.plan;
  if (receipt.status !== '0x1' || receipt.transactionHash !== transactionHash) throw new Error('TRANSFER_RECEIPT_MISMATCH');
  requireHash(receipt.blockHash);
  const blockHash = receipt.blockHash, blockNumber = quantity(receipt.blockNumber), transactionIndex = quantity(receipt.transactionIndex);
  if (!Array.isArray(receipt.logs) || receipt.logs.length > 2048) throw new Error('TRANSFER_RECEIPT_INVALID');
  let previous = -1n;
  const logs = receipt.logs.map((value: unknown) => {
    const log = row(value), index = quantity(log.logIndex);
    if (log.transactionHash !== transactionHash || log.blockHash !== blockHash || quantity(log.blockNumber) !== blockNumber
      || quantity(log.transactionIndex) !== transactionIndex || log.removed !== false || index <= previous
      || !Array.isArray(log.topics) || log.topics.length > 4) throw new Error('TRANSFER_RECEIPT_INVALID');
    previous = index;
    const topics = log.topics.map(t => { const v = bytes(t, 32); if (v.length !== 66) throw new Error('TRANSFER_RECEIPT_INVALID'); return v; });
    return { address: address(log.address), data: bytes(log.data, 65_536), topics, index };
  });
  const epEvents = logs.filter(l => isAddressEqual(l.address, plan.entryPoint) && l.topics[0] === topic('UserOperationEvent'));
  const matching = epEvents.filter(l => l.topics[1] === c.userOpHash);
  if (matching.length !== 1) throw new Error('TRANSFER_RECEIPT_OPERATION');
  const op = matching[0];
  if (op.topics.length !== 4) throw new Error('TRANSFER_RECEIPT_OPERATION');
  const decoded = decodeEventLog({ abi: transferReceiptAbi, eventName: 'UserOperationEvent', topics: op.topics as [Hex, ...Hex[]], data: op.data, strict: true });
  const outcome = decoded.args;
  if (!isAddressEqual(outcome.sender, c.account) || !isAddressEqual(outcome.paymaster, plan.paymaster) || outcome.nonce !== plan.nonce
    || op.topics[2] !== encodeAbiParameters([{ type: 'address' }], [c.account]) || op.topics[3] !== encodeAbiParameters([{ type: 'address' }], [plan.paymaster])
    || outcome.actualGasUsed === 0n || outcome.actualGasCost > c.maximumEntryPointCharge
    || op.data !== encodeAbiParameters([{ type: 'uint256' }, { type: 'bool' }, { type: 'uint256' }, { type: 'uint256' }],
      [outcome.nonce, outcome.success, outcome.actualGasCost, outcome.actualGasUsed])) throw new Error('TRANSFER_RECEIPT_OPERATION');
  const starts = logs.filter(l => isAddressEqual(l.address, plan.entryPoint) && l.topics[0] === topic('BeforeExecution') && l.index < op.index);
  const start = starts.at(-1);
  if (!start || start.topics.length !== 1 || start.data !== '0x') throw new Error('TRANSFER_RECEIPT_BOUNDARY');
  const lower = epEvents.filter(l => l.index < op.index).reduce((n, l) => l.index > n ? l.index : n, start.index);
  const scoped = logs.filter(l => l.index > lower && l.index < op.index);
  const calls = scoped.filter(l => isAddressEqual(l.address, c.account) && l.topics[0] === topic('CallsExecuted') && l.topics[1] === plan.callsHash);
  if (calls.length !== (outcome.success ? 1 : 0)) throw new Error('TRANSFER_RECEIPT_CALLS');
  if (outcome.success && (calls[0].topics.length !== 2 || calls[0].data !== encodeAbiParameters([{ type: 'uint64' }, { type: 'uint8' }],
    [plan.securityVersion, plan.executionMode]))) throw new Error('TRANSFER_RECEIPT_CALLS');
  const token = c.request.asset_id === record.review.context.native_asset_id ? null : address(c.request.asset_id.split('/erc20:')[1]);
  const transferIndexes: string[] = [];
  if (outcome.success && token) {
    const from = encodeAbiParameters([{ type: 'address' }], [c.account]);
    const transfers = scoped.filter(l => isAddressEqual(l.address, token) && l.topics[0] === topic('Transfer') && l.topics[1] === from);
    const expected = [{ to: c.request.destination.address, amount: c.funding.amount_atomic }];
    if (record.review.context.fee_recipient) expected.push({ to: record.review.context.fee_recipient,
      amount: record.review.context.budget.platform_fee.amount_atomic });
    if (transfers.length !== expected.length) throw new Error('TRANSFER_RECEIPT_ASSET_UNPROVEN');
    transfers.forEach((event, i) => {
      if (event.index >= calls[0].index || event.topics.length !== 3
        || event.topics[2] !== encodeAbiParameters([{ type: 'address' }], [getAddress(expected[i].to)])
        || event.data !== encodeAbiParameters([{ type: 'uint256' }], [BigInt(expected[i].amount)])) throw new Error('TRANSFER_RECEIPT_ASSET_UNPROVEN');
      transferIndexes.push(event.index.toString());
    });
  }
  return Object.freeze({ schema_version: 1 as const, network_id: c.request.network_id, deployment_sha256: c.deployment_digest,
    userop_hash: c.userOpHash, consent_digest: c.digest, transaction_hash: transactionHash, block_hash: blockHash,
    block_number: blockNumber.toString(), transaction_index: transactionIndex.toString(),
    outcome: outcome.success ? 'execution_succeeded' as const : 'execution_reverted' as const,
    actual_gas_cost: outcome.actualGasCost.toString(), actual_gas_used: outcome.actualGasUsed.toString(),
    log_indexes: Object.freeze({ operation: op.index.toString(), calls: calls[0]?.index.toString() ?? null, transfers: Object.freeze(transferIndexes) }),
    finality: 'not_assessed' as const, settlement: 'not_assessed' as const });
}
