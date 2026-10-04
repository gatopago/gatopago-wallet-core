import {
  decodeEventLog,
  encodeAbiParameters,
  encodeEventTopics,
  getAddress,
  isAddress,
  isAddressEqual,
  parseAbi,
  type Address,
  type Hex,
} from 'viem';
import { requireHash } from '@gatopago/shared/v3/deployment';

export const operationReceiptAbi = parseAbi([
  'event BeforeExecution()',
  'event UserOperationEvent(bytes32 indexed userOpHash,address indexed sender,address indexed paymaster,uint256 nonce,bool success,uint256 actualGasCost,uint256 actualGasUsed)',
  'event CallsExecuted(bytes32 indexed callsHash,uint64 securityVersion,uint8 executionMode)',
]);
export interface OperationReceiptBinding {
  readonly account: Address;
  readonly userOpHash: Hex;
  readonly maximumEntryPointCharge: bigint;
  readonly plan: {
    readonly entryPoint: Address;
    readonly paymaster: Address;
    readonly nonce: bigint;
    readonly callsHash: Hex;
    readonly securityVersion: bigint;
    readonly executionMode: number;
  };
}
export interface OperationReceiptLog {
  readonly address: Address;
  readonly data: Hex;
  readonly topics: readonly Hex[];
  readonly index: bigint;
}
function row(value: unknown): Record<string, unknown> {
  if (!value || typeof value !== 'object' || Array.isArray(value))
    throw new Error('OPERATION_RECEIPT_INVALID');
  return value as Record<string, unknown>;
}
function quantity(value: unknown) {
  if (typeof value !== 'string' || !/^0x(?:0|[1-9a-f][0-9a-f]{0,63})$(?![\s\S])/.test(value))
    throw new Error('OPERATION_RECEIPT_INVALID');
  return BigInt(value);
}
function bytes(value: unknown, max: number): Hex {
  if (
    typeof value !== 'string' ||
    value.length > max * 2 + 2 ||
    !/^0x(?:[0-9a-fA-F]{2})*$(?![\s\S])/.test(value)
  )
    throw new Error('OPERATION_RECEIPT_INVALID');
  return value.toLowerCase() as Hex;
}
const topic = (name: (typeof operationReceiptAbi)[number]['name']) =>
  encodeEventTopics({ abi: operationReceiptAbi, eventName: name })[0];

export function verifyUserOperationReceipt(
  binding: OperationReceiptBinding,
  transactionHash: Hex,
  input: unknown,
) {
  requireHash(transactionHash);
  const receipt = row(input),
    c = binding,
    plan = c.plan;
  if (receipt.status !== '0x1' || receipt.transactionHash !== transactionHash)
    throw new Error('OPERATION_RECEIPT_MISMATCH');
  requireHash(receipt.blockHash);
  const blockHash = receipt.blockHash,
    blockNumber = quantity(receipt.blockNumber),
    transactionIndex = quantity(receipt.transactionIndex);
  if (!Array.isArray(receipt.logs) || receipt.logs.length > 2048)
    throw new Error('OPERATION_RECEIPT_INVALID');
  let previous = -1n;
  const logs: OperationReceiptLog[] = receipt.logs.map((value: unknown) => {
    const log = row(value),
      index = quantity(log.logIndex);
    if (
      log.transactionHash !== transactionHash ||
      log.blockHash !== blockHash ||
      quantity(log.blockNumber) !== blockNumber ||
      quantity(log.transactionIndex) !== transactionIndex ||
      log.removed !== false ||
      index <= previous ||
      !Array.isArray(log.topics) ||
      log.topics.length > 4 ||
      typeof log.address !== 'string' ||
      !isAddress(log.address, { strict: false })
    )
      throw new Error('OPERATION_RECEIPT_INVALID');
    previous = index;
    const topics = log.topics.map((value) => {
      const result = bytes(value, 32);
      if (result.length !== 66) throw new Error('OPERATION_RECEIPT_INVALID');
      return result;
    });
    return { address: getAddress(log.address), data: bytes(log.data, 65_536), topics, index };
  });
  const events = logs.filter(
    (log) =>
      isAddressEqual(log.address, plan.entryPoint) && log.topics[0] === topic('UserOperationEvent'),
  );
  const matching = events.filter((log) => log.topics[1] === c.userOpHash);
  if (matching.length !== 1) throw new Error('OPERATION_RECEIPT_OPERATION');
  const operation = matching[0];
  if (operation.topics.length !== 4) throw new Error('OPERATION_RECEIPT_OPERATION');
  const outcome = decodeEventLog({
    abi: operationReceiptAbi,
    eventName: 'UserOperationEvent',
    topics: operation.topics as [Hex, ...Hex[]],
    data: operation.data,
    strict: true,
  }).args;
  if (
    !isAddressEqual(outcome.sender, c.account) ||
    !isAddressEqual(outcome.paymaster, plan.paymaster) ||
    outcome.nonce !== plan.nonce ||
    operation.topics[2] !== encodeAbiParameters([{ type: 'address' }], [c.account]) ||
    operation.topics[3] !== encodeAbiParameters([{ type: 'address' }], [plan.paymaster]) ||
    outcome.actualGasUsed === 0n ||
    outcome.actualGasCost > c.maximumEntryPointCharge ||
    operation.data !==
      encodeAbiParameters(
        [{ type: 'uint256' }, { type: 'bool' }, { type: 'uint256' }, { type: 'uint256' }],
        [outcome.nonce, outcome.success, outcome.actualGasCost, outcome.actualGasUsed],
      )
  )
    throw new Error('OPERATION_RECEIPT_OPERATION');
  const start = logs
    .filter(
      (log) =>
        isAddressEqual(log.address, plan.entryPoint) &&
        log.topics[0] === topic('BeforeExecution') &&
        log.index < operation.index,
    )
    .at(-1);
  if (!start || start.topics.length !== 1 || start.data !== '0x')
    throw new Error('OPERATION_RECEIPT_BOUNDARY');
  const lower = events
    .filter((log) => log.index < operation.index)
    .reduce((value, log) => (log.index > value ? log.index : value), start.index);
  const scoped = logs.filter((log) => log.index > lower && log.index < operation.index);
  const calls = scoped.filter(
    (log) =>
      isAddressEqual(log.address, c.account) &&
      log.topics[0] === topic('CallsExecuted') &&
      log.topics[1] === plan.callsHash,
  );
  if (calls.length !== (outcome.success ? 1 : 0)) throw new Error('OPERATION_RECEIPT_CALLS');
  if (
    outcome.success &&
    (calls[0].topics.length !== 2 ||
      calls[0].data !==
        encodeAbiParameters(
          [{ type: 'uint64' }, { type: 'uint8' }],
          [plan.securityVersion, plan.executionMode],
        ))
  )
    throw new Error('OPERATION_RECEIPT_CALLS');
  return Object.freeze({
    blockHash,
    blockNumber,
    transactionIndex,
    outcome,
    operation,
    calls: calls.length ? calls[0] : null,
    scoped,
  });
}
