import { getAddress, pad, slice, toEventSelector, type Address, type Hex } from 'viem';
import type { Transfer } from './activity';

/**
 * Envio HyperSync (`POST <url>/query`): the Transfer logs of many addresses over a long range of
 * blocks in one request, with the time of each block, where `eth_getLogs` needs a request per
 * group of addresses and short range, and another per block for its time. The same request finds
 * the transactions that send the native coin straight to them, which leave no log.
 */

const TRANSFER = toEventSelector('Transfer(address,address,uint256)');
/** A native-coin transfer has no log: its row uses this index, one per transaction. */
export const NATIVE_LOG_INDEX = -1;
/** Addresses per topic filter of one query. */
const ADDRESSES_PER_FILTER = 500;

/** Block numbers and other quantities: integers or hex strings, both accepted. */
type Quantity = number | string;
interface Batch {
  blocks?: { number: Quantity; timestamp: Quantity }[];
  logs?: {
    block_number: Quantity;
    log_index: Quantity;
    transaction_hash: Hex;
    address: Address;
    topic1: Hex;
    topic2: Hex;
    data: Hex;
  }[];
  transactions?: {
    block_number: Quantity;
    hash: Hex;
    from: Address;
    to: Address | null;
    value: Quantity;
    status: Quantity | null;
  }[];
}

export interface HypersyncSource {
  readonly url: string;
  readonly token: string;
}

/**
 * Transfers of `coins` from or to any of `addresses` from `fromBlock` (up to `toBlock`, exclusive,
 * or the latest block HyperSync has). HyperSync stops a query early at its time or size limit:
 * `nextBlock` is where the next one starts, and `height` the latest block it has.
 */
export async function hypersyncTransfers(
  source: HypersyncSource,
  query: { coins: Address[]; addresses: Address[]; fromBlock: bigint; toBlock?: bigint },
): Promise<{
  transfers: Transfer[];
  times: Map<bigint, number>;
  nextBlock: bigint;
  height: bigint | null;
}> {
  const filters = [];
  const recipients = [];
  for (let i = 0; i < query.addresses.length; i += ADDRESSES_PER_FILTER) {
    const group = query.addresses.slice(i, i + ADDRESSES_PER_FILTER);
    const topics = group.map((address) => pad(address.toLowerCase() as Hex));
    filters.push(
      { address: query.coins, topics: [[TRANSFER], topics, []] },
      { address: query.coins, topics: [[TRANSFER], [], topics] },
    );
    recipients.push({ to: group });
  }
  const response = await fetch(`${source.url}/query`, {
    method: 'POST',
    headers: { 'Content-Type': 'application/json', Authorization: `Bearer ${source.token}` },
    body: JSON.stringify({
      from_block: Number(query.fromBlock),
      ...(query.toBlock === undefined ? {} : { to_block: Number(query.toBlock) }),
      logs: filters,
      transactions: recipients,
      field_selection: {
        block: ['number', 'timestamp'],
        transaction: ['block_number', 'hash', 'from', 'to', 'value', 'status'],
        log: [
          'block_number',
          'log_index',
          'transaction_hash',
          'address',
          'topic1',
          'topic2',
          'data',
        ],
      },
    }),
  });
  if (!response.ok) throw new Error(`HYPERSYNC_FAILED: ${response.status}`);
  const result = await response.json<{
    data: Batch | Batch[];
    next_block: Quantity;
    archive_height?: Quantity | null;
  }>();
  const batches = Array.isArray(result.data) ? result.data : [result.data];
  const times = new Map<bigint, number>();
  for (const block of batches.flatMap((batch) => batch.blocks ?? []))
    times.set(BigInt(block.number), Number(BigInt(block.timestamp)));
  // A transfer between two of the addresses matches both filters: kept once.
  const transfers = new Map<string, Transfer>();
  for (const log of batches.flatMap((batch) => batch.logs ?? [])) {
    const transfer = {
      transactionHash: log.transaction_hash,
      logIndex: Number(BigInt(log.log_index)),
      blockNumber: BigInt(log.block_number),
      token: getAddress(log.address),
      from: getAddress(slice(log.topic1, 12)),
      to: getAddress(slice(log.topic2, 12)),
      value: BigInt(log.data),
    };
    transfers.set(`${transfer.transactionHash}:${transfer.logIndex}`, transfer);
  }
  // Transactions of the logs come along too: only value sent straight to an address, and landed.
  const addresses = new Set(query.addresses.map((address) => address.toLowerCase()));
  for (const transaction of batches.flatMap((batch) => batch.transactions ?? [])) {
    const value = BigInt(transaction.value);
    if (
      !transaction.to ||
      !addresses.has(transaction.to.toLowerCase()) ||
      value === 0n ||
      transaction.status === null ||
      BigInt(transaction.status) !== 1n
    )
      continue;
    transfers.set(`${transaction.hash}:${NATIVE_LOG_INDEX}`, {
      transactionHash: transaction.hash,
      logIndex: NATIVE_LOG_INDEX,
      blockNumber: BigInt(transaction.block_number),
      token: null,
      from: getAddress(transaction.from),
      to: getAddress(transaction.to),
      value,
    });
  }
  return {
    transfers: [...transfers.values()],
    times,
    nextBlock: BigInt(result.next_block),
    height: result.archive_height == null ? null : BigInt(result.archive_height),
  };
}

/** The latest block HyperSync has for a network (`GET <url>/height`). */
export async function hypersyncHeight(source: HypersyncSource): Promise<bigint> {
  const response = await fetch(`${source.url}/height`, {
    headers: { Authorization: `Bearer ${source.token}` },
  });
  if (!response.ok) throw new Error(`HYPERSYNC_FAILED: ${response.status}`);
  return BigInt((await response.json<{ height: Quantity }>()).height);
}
