import {
  getAddress,
  isAddressEqual,
  parseAbiItem,
  zeroAddress,
  type Address,
  type Hex,
} from 'viem';
import { swapPools } from '@gatopago/shared/swap';
import type { Budget } from './budget';
import type { Config, Network } from './config';
import { HttpError, json } from './http';
import { signedInMember } from './profile';

export const transferEvent = parseAbiItem(
  'event Transfer(address indexed from, address indexed to, uint256 value)',
);

/** A USDC Transfer log, from a webhook or from the chain. */
export interface Transfer {
  transactionHash: Hex;
  logIndex: number;
  blockNumber: bigint;
  /** The token contract that emitted it: USDC or another configured coin. */
  token: Address;
  from: Address;
  to: Address;
  value: bigint;
}

/** The coins Wallet Core indexes on `network`: USDC and its configured tokens. */
export function networkCoins(
  network: Network,
): { address: Address; symbol: string; decimals: number }[] {
  return [
    { address: network.usdc, symbol: 'USDC', decimals: 6 },
    ...(network.tokens ?? []).map(({ address, symbol, decimals }) => ({
      address,
      symbol,
      decimals,
    })),
  ];
}

/** The configured coin a Transfer log came from, or null for any other token. */
export const coinOf = (network: Network, token: Address) =>
  networkCoins(network).find((coin) => isAddressEqual(coin.address, token)) ?? null;

/** Ranges read per network and run, so a run stays within the Worker's subrequest budget. */
const ROUNDS = 20;
/** Addresses per `eth_getLogs` topic filter. */
const ADDRESSES_PER_QUERY = 100;
const PAGE = 50;

/**
 * CCTP burns go through the TokenMinter and mints come from zero; the router carries payments;
 * Agora's Instant Settlement pair settles sends into another coin;
 * Aave's aToken holds the USDC saved in Grow; a Uniswap pool is the other side of a swap.
 */
function kind(network: Network, { from, to }: Transfer) {
  const involves = (address: Address) =>
    isAddressEqual(from, address) || isAddressEqual(to, address);
  if (involves(network.paymentRouter)) return 'payment';
  // Agora Instant Settlement: a send settled into the recipient's coin at a fixed price.
  if (network.instantSettlement && involves(network.instantSettlement.pair)) return 'settlement';
  if (network.aave && involves(network.aave.aToken)) return 'earn';
  if (network.uniswap && swapPools(network).some(involves)) return 'swap';
  if (isAddressEqual(from, zeroAddress) || isAddressEqual(to, network.cctp.tokenMinter))
    return 'crosschain';
  return 'transfer';
}

/** Members among `addresses` (lowercase). D1 binds at most 100 parameters per statement. */
export async function membersAmong(env: Env, addresses: Iterable<string>): Promise<Set<string>> {
  const unique = [...new Set(addresses)];
  const members = new Set<string>();
  for (let i = 0; i < unique.length; i += 100) {
    const batch = unique.slice(i, i + 100);
    const { results } = await env.WALLET_DB.prepare(
      `SELECT address FROM members WHERE address IN (${batch.map(() => '?').join(',')})`,
    )
      .bind(...batch)
      .all<{ address: string }>();
    for (const row of results) members.add(row.address);
  }
  return members;
}

/**
 * The transfers involving a member, and the statements that keep them (one each, in order). Rows
 * are keyed by their log, so storing a transfer twice, from a webhook and from the reconciliation,
 * changes nothing.
 */
export async function storeTransfers(
  env: Env,
  network: Network,
  transfers: readonly Transfer[],
  budget?: Budget,
): Promise<{ kept: Transfer[]; statements: D1PreparedStatement[] } | null> {
  const members = await membersAmong(
    env,
    transfers.flatMap(({ from, to }) => [from.toLowerCase(), to.toLowerCase()]),
  );
  const kept = transfers.filter(
    ({ from, to }) => members.has(from.toLowerCase()) || members.has(to.toLowerCase()),
  );
  const times = new Map<bigint, number>();
  const blocks = new Set(kept.map((transfer) => transfer.blockNumber));
  // Each block's timestamp is one request: without room for all of them, nothing is stored yet.
  if (budget && !budget.take(blocks.size)) return null;
  for (const block of blocks)
    times.set(block, Number((await network.client.getBlock({ blockNumber: block })).timestamp));
  const statements = kept.map((transfer) =>
    env.WALLET_DB.prepare(
      `INSERT OR IGNORE INTO transfers (network, transaction_hash, log_index, block_number,
         timestamp, from_address, to_address, amount, kind, token)
       VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`,
    ).bind(
      network.id,
      transfer.transactionHash,
      transfer.logIndex,
      Number(transfer.blockNumber),
      times.get(transfer.blockNumber)!,
      transfer.from.toLowerCase(),
      transfer.to.toLowerCase(),
      transfer.value.toString(),
      kind(network, transfer),
      coinOf(network, transfer.token)?.symbol ?? 'USDC',
    ),
  );
  return { kept, statements };
}

/**
 * Reads, for each network, the members' USDC Transfer events since the last block read: whatever a
 * webhook did not deliver. Only members' addresses are queried, so results stay small.
 */
export async function reconcileTransfers(env: Env, config: Config, budget: Budget): Promise<void> {
  const { results } = await env.WALLET_DB.prepare('SELECT address FROM members').all<{
    address: Address;
  }>();
  const groups: Address[][] = [];
  for (let i = 0; i < results.length; i += ADDRESSES_PER_QUERY)
    groups.push(results.slice(i, i + ADDRESSES_PER_QUERY).map((row) => row.address));
  for (const network of config.networks.values()) {
    if (!budget.take()) return;
    const { client, range, start } = network.index;
    const latest = await client.getBlockNumber();
    const cursor = await env.WALLET_DB.prepare('SELECT block FROM index_cursors WHERE network = ?')
      .bind(network.id)
      .first<number>('block');
    let from = cursor === null ? (start ?? latest) : BigInt(cursor) + 1n;
    for (let round = 0; from <= latest && round < ROUNDS; round++) {
      if (!budget.take(groups.length * 2)) return;
      const to = from + range - 1n < latest ? from + range - 1n : latest;
      const logs = [];
      for (const group of groups)
        for (const args of [{ from: group }, { to: group }])
          logs.push(
            ...(await client.getLogs({
              address: networkCoins(network).map((coin) => coin.address),
              event: transferEvent,
              args,
              fromBlock: from,
              toBlock: to,
            })),
          );
      const stored = await storeTransfers(
        env,
        network,
        logs.map((log) => ({
          transactionHash: log.transactionHash,
          logIndex: log.logIndex,
          blockNumber: log.blockNumber,
          token: log.address,
          from: log.args.from!,
          to: log.args.to!,
          value: log.args.value!,
        })),
        budget,
      );
      // Out of requests: this range is read again on the next run.
      if (!stored) return;
      await env.WALLET_DB.batch([
        ...stored.statements,
        env.WALLET_DB.prepare(
          `INSERT INTO index_cursors (network, block) VALUES (?, ?)
           ON CONFLICT (network) DO UPDATE SET block = excluded.block`,
        ).bind(network.id, Number(to)),
      ]);
      from = to + 1n;
    }
  }
}

interface TransferRow {
  network: string;
  transaction_hash: Hex;
  log_index: number;
  block_number: number;
  timestamp: number;
  from_address: string;
  to_address: string;
  amount: string;
  kind: string;
  token: string;
  username: string | null;
  display_name: string | null;
}

/**
 * `GET /app/v1/activity?before=<next_cursor>`: the member's movements on every network (EVM and
 * Stellar), newest first, with the other party's GatoPago profile when they have one.
 */
export async function readActivity(request: Request, env: Env, config: Config): Promise<Response> {
  const member = await signedInMember(request, env, config);
  const me = member.address.toLowerCase();
  const { results: stellar } = await env.WALLET_DB.prepare(
    'SELECT address FROM stellar_accounts WHERE member_address = ?',
  )
    .bind(me)
    .all<{ address: string }>();
  const mine = [me, ...stellar.map((row) => row.address)];
  const before = new URL(request.url).searchParams.get('before');
  let after: [number, number, number, string] | null = null;
  if (before) {
    const [timestamp, block, index, hash] = before.split('_');
    if (
      !/^\d+$/.test(timestamp) ||
      !/^\d+$/.test(block) ||
      !/^\d+$/.test(index) ||
      !/^(0x)?[0-9a-f]{64}$/.test(hash)
    )
      throw new HttpError(400, 'INVALID_CURSOR');
    after = [Number(timestamp), Number(block), Number(index), hash];
  }
  const n = mine.length;
  const list = mine.map((_, i) => `?${i + 1}`).join(', ');
  const other = `CASE WHEN transfers.from_address IN (${list}) THEN transfers.to_address ELSE transfers.from_address END`;
  const { results } = await env.WALLET_DB.prepare(
    `SELECT transfers.*, members.username, members.display_name FROM transfers
     LEFT JOIN stellar_accounts ON stellar_accounts.address = ${other}
     LEFT JOIN members ON members.address = COALESCE(stellar_accounts.member_address, ${other})
     WHERE (transfers.from_address IN (${list}) OR transfers.to_address IN (${list}))
       AND (?${n + 1} IS NULL OR (transfers.timestamp, transfers.block_number, transfers.log_index,
         transfers.transaction_hash) < (?${n + 1}, ?${n + 2}, ?${n + 3}, ?${n + 4}))
     ORDER BY transfers.timestamp DESC, transfers.block_number DESC, transfers.log_index DESC,
       transfers.transaction_hash DESC
     LIMIT ?${n + 5}`,
  )
    .bind(
      ...mine,
      after?.[0] ?? null,
      after?.[1] ?? null,
      after?.[2] ?? null,
      after?.[3] ?? null,
      PAGE + 1,
    )
    .all<TransferRow>();
  const page = results.slice(0, PAGE);
  const last = page.at(-1);
  return json({
    activity: page.map((row) => {
      const sent = mine.includes(row.from_address);
      const address = sent ? row.to_address : row.from_address;
      // Stellar strkeys stay as they are; a mint comes from no one.
      const counterparty = address.startsWith('0x') ? getAddress(address) : address;
      return {
        id: `${row.network}:${row.transaction_hash}:${row.log_index}`,
        network: row.network,
        transaction_hash: row.transaction_hash,
        timestamp: row.timestamp,
        direction: sent ? 'sent' : 'received',
        kind: row.kind,
        currency: row.token,
        amount: row.amount,
        counterparty: counterparty === zeroAddress ? null : counterparty,
        counterparty_username: row.username,
        counterparty_display_name: row.display_name,
      };
    }),
    next_cursor:
      results.length > PAGE && last
        ? `${last.timestamp}_${last.block_number}_${last.log_index}_${last.transaction_hash}`
        : null,
  });
}
