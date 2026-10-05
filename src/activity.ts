import {
  getAddress,
  isAddressEqual,
  parseAbiItem,
  zeroAddress,
  type Address,
  type Hex,
} from 'viem';
import { swapPools } from '@gatopago/shared/swap';
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
  from: Address;
  to: Address;
  value: bigint;
}

/** Ranges read per network and run, so a run stays within the Worker's subrequest budget. */
const ROUNDS = 20;
/** Addresses per `eth_getLogs` topic filter. */
const ADDRESSES_PER_QUERY = 100;
const PAGE = 50;

/**
 * CCTP burns go through the TokenMinter and mints come from zero; the router carries payments;
 * Aave's aToken holds the USDC saved in Grow; a Uniswap pool is the other side of a swap.
 */
function kind(network: Network, { from, to }: Transfer) {
  const involves = (address: Address) =>
    isAddressEqual(from, address) || isAddressEqual(to, address);
  if (involves(network.paymentRouter)) return 'payment';
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
): Promise<{ kept: Transfer[]; statements: D1PreparedStatement[] }> {
  const members = await membersAmong(
    env,
    transfers.flatMap(({ from, to }) => [from.toLowerCase(), to.toLowerCase()]),
  );
  const kept = transfers.filter(
    ({ from, to }) => members.has(from.toLowerCase()) || members.has(to.toLowerCase()),
  );
  const times = new Map<bigint, number>();
  for (const block of new Set(kept.map((transfer) => transfer.blockNumber)))
    times.set(block, Number((await network.client.getBlock({ blockNumber: block })).timestamp));
  const statements = kept.map((transfer) =>
    env.WALLET_DB.prepare(
      `INSERT OR IGNORE INTO transfers (network, transaction_hash, log_index, block_number,
         timestamp, from_address, to_address, amount, kind) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)`,
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
    ),
  );
  return { kept, statements };
}

/**
 * Reads, for each network, the members' USDC Transfer events since the last block read: whatever a
 * webhook did not deliver. Only members' addresses are queried, so results stay small.
 */
export async function reconcileTransfers(env: Env, config: Config): Promise<void> {
  const { results } = await env.WALLET_DB.prepare('SELECT address FROM members').all<{
    address: Address;
  }>();
  const groups: Address[][] = [];
  for (let i = 0; i < results.length; i += ADDRESSES_PER_QUERY)
    groups.push(results.slice(i, i + ADDRESSES_PER_QUERY).map((row) => row.address));
  for (const network of config.networks.values()) {
    const { client, range, start } = network.index;
    const latest = await client.getBlockNumber();
    const cursor = await env.WALLET_DB.prepare('SELECT block FROM index_cursors WHERE network = ?')
      .bind(network.id)
      .first<number>('block');
    let from = cursor === null ? (start ?? latest) : BigInt(cursor) + 1n;
    for (let round = 0; from <= latest && round < ROUNDS; round++) {
      const to = from + range - 1n < latest ? from + range - 1n : latest;
      const logs = [];
      for (const group of groups)
        for (const args of [{ from: group }, { to: group }])
          logs.push(
            ...(await client.getLogs({
              address: network.usdc,
              event: transferEvent,
              args,
              fromBlock: from,
              toBlock: to,
            })),
          );
      await env.WALLET_DB.batch([
        ...(
          await storeTransfers(
            env,
            network,
            logs.map((log) => ({
              transactionHash: log.transactionHash,
              logIndex: log.logIndex,
              blockNumber: log.blockNumber,
              from: log.args.from!,
              to: log.args.to!,
              value: log.args.value!,
            })),
          )
        ).statements,
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
  username: string | null;
  display_name: string | null;
}

/**
 * `GET /app/v1/activity?before=<next_cursor>`: the member's movements, newest first, with the other
 * party's GatoPago profile when they have one.
 */
export async function readActivity(request: Request, env: Env, config: Config): Promise<Response> {
  const member = await signedInMember(request, env, config);
  const me = member.address.toLowerCase();
  const before = new URL(request.url).searchParams.get('before');
  let after: [number, number, number, string] | null = null;
  if (before) {
    const [timestamp, block, index, hash] = before.split('_');
    if (
      !/^\d+$/.test(timestamp) ||
      !/^\d+$/.test(block) ||
      !/^\d+$/.test(index) ||
      !/^0x[0-9a-f]{64}$/.test(hash)
    )
      throw new HttpError(400, 'INVALID_CURSOR');
    after = [Number(timestamp), Number(block), Number(index), hash];
  }
  const { results } = await env.WALLET_DB.prepare(
    `SELECT transfers.*, members.username, members.display_name FROM transfers
     LEFT JOIN members ON members.address =
       CASE WHEN transfers.from_address = ?1 THEN transfers.to_address ELSE transfers.from_address END
     WHERE (transfers.from_address = ?1 OR transfers.to_address = ?1)
       AND (?2 IS NULL OR (transfers.timestamp, transfers.block_number, transfers.log_index,
         transfers.transaction_hash) < (?2, ?3, ?4, ?5))
     ORDER BY transfers.timestamp DESC, transfers.block_number DESC, transfers.log_index DESC,
       transfers.transaction_hash DESC
     LIMIT ?6`,
  )
    .bind(
      me,
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
      const sent = row.from_address === me;
      const counterparty = getAddress(sent ? row.to_address : row.from_address);
      return {
        id: `${row.network}:${row.transaction_hash}:${row.log_index}`,
        network: row.network,
        transaction_hash: row.transaction_hash,
        timestamp: row.timestamp,
        direction: sent ? 'sent' : 'received',
        kind: row.kind,
        currency: 'USDC',
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
