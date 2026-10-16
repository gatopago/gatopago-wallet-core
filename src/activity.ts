import {
  getAddress,
  isAddressEqual,
  parseAbiItem,
  parseEventLogs,
  zeroAddress,
  type Address,
  type Hex,
} from 'viem';
import { stellarNetworks, walletNetworks } from '@gatopago/shared/networks';
import { swapPools } from '@gatopago/shared/swap';
import type { Budget } from './budget';
import type { Config, Network } from './config';
import { readCursor, readerFailed, saveCursor } from './cursors';
import { HttpError, json } from './http';
import { hypersyncHeight, hypersyncTransfers, NATIVE_LOG_INDEX } from './hypersync';
import { signedInMember } from './profile';
import { NOTIFY_SECONDS } from './push';

export { NATIVE_LOG_INDEX };

export const transferEvent = parseAbiItem(
  'event Transfer(address indexed from, address indexed to, uint256 value)',
);

/**
 * A movement of a member's coins, from a webhook or from the chain: a token's Transfer log, or the
 * value of a transaction sent straight to them in the network's own coin (`token` null, its
 * `logIndex` `NATIVE_LOG_INDEX`).
 */
export interface Transfer {
  transactionHash: Hex;
  logIndex: number;
  blockNumber: bigint;
  /** The token contract that emitted it (USDC or another configured coin), or null for the native coin. */
  token: Address | null;
  from: Address;
  to: Address;
  value: bigint;
}

/** The coins Wallet Core indexes on `network`: USDC and its configured tokens. */
function networkCoins(network: Network): { address: Address; symbol: string; decimals: number }[] {
  return [
    { address: network.usdc, symbol: 'USDC', decimals: 6 },
    ...(network.tokens ?? []).map(({ address, symbol, decimals }) => ({
      address,
      symbol,
      decimals,
    })),
  ];
}

/** The coin stored as `symbol` (`transfers.token`), with its address: `null` for the native coin. */
export function coinBySymbol(network: Network, symbol: string) {
  if (symbol === network.chain.nativeCurrency.symbol)
    return { address: null, ...network.chain.nativeCurrency };
  return networkCoins(network).find((coin) => coin.symbol === symbol) ?? null;
}

/** The coin a transfer moved: a configured token, the native coin (`null`), or null for any other. */
export const coinOf = (
  network: Network,
  token: Address | null,
): { symbol: string; decimals: number } | null =>
  token === null
    ? network.chain.nativeCurrency
    : (networkCoins(network).find((coin) => isAddressEqual(coin.address, token)) ?? null);

/** Ranges read per network and run, so a run stays within the Worker's subrequest budget. */
const ROUNDS = 20;
/**
 * Blocks behind the latest that HyperSync reads are kept for later: Arbitrum, Avalanche and Monad
 * finalize in seconds, so past these a block no longer changes, and a reorg never reaches the table.
 */
const FINALITY_BLOCKS = 64n;
/** Addresses per `eth_getLogs` topic filter. */
const ADDRESSES_PER_QUERY = 100;
const PAGE = 50;

/**
 * CCTP burns go through the TokenMinter and mints come from zero; the router carries payments;
 * Agora's Instant Settlement pair settles sends into another coin;
 * Aave's aToken holds the USDC saved in Grow; a Uniswap pool or its router (which takes and pays the
 * native coin) is the other side of a swap.
 */
function kind(network: Network, { from, to }: Transfer) {
  const involves = (address: Address) =>
    isAddressEqual(from, address) || isAddressEqual(to, address);
  if (involves(network.paymentRouter)) return 'payment';
  // Agora Instant Settlement: a send settled into the recipient's coin at a fixed price.
  if (network.instantSettlement && involves(network.instantSettlement.pair)) return 'settlement';
  if (network.aave && involves(network.aave.aToken)) return 'earn';
  if (network.uniswap && [network.uniswap.router, ...swapPools(network)].some(involves))
    return 'swap';
  if (isAddressEqual(from, zeroAddress) || isAddressEqual(to, network.cctp.tokenMinter))
    return 'crosschain';
  return 'transfer';
}

/** Members among `addresses` (lowercase). D1 binds at most 100 parameters per statement. */
async function membersAmong(env: Env, addresses: Iterable<string>): Promise<Set<string>> {
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
 * changes nothing. A recent one a member received is stored with its notification pending
 * (`sendNotifications`).
 */
export async function storeTransfers(
  env: Env,
  network: Network,
  transfers: readonly Transfer[],
  budget?: Budget,
  /** Block times already known (HyperSync returns them): those blocks are not read again. */
  known: ReadonlyMap<bigint, number> = new Map(),
): Promise<{
  kept: Transfer[];
  statements: D1PreparedStatement[];
  times: Map<bigint, number>;
} | null> {
  const members = await membersAmong(
    env,
    transfers.flatMap(({ from, to }) => [from.toLowerCase(), to.toLowerCase()]),
  );
  // A transfer of nothing moves no money: anyone can make one to put an address in a member's
  // history (address poisoning). It is neither kept nor notified, as on Stellar.
  const kept = transfers.filter(
    ({ from, to, value }) =>
      value > 0n && (members.has(from.toLowerCase()) || members.has(to.toLowerCase())),
  );
  const times = new Map(known);
  const blocks = new Set(
    kept.map((transfer) => transfer.blockNumber).filter((block) => !times.has(block)),
  );
  // Each block's timestamp is one request: without room for all of them, nothing is stored yet.
  if (budget && !budget.take(blocks.size)) return null;
  for (const block of blocks)
    times.set(block, Number((await network.client.getBlock({ blockNumber: block })).timestamp));
  const now = Math.floor(Date.now() / 1000);
  const statements = kept.map((transfer) =>
    env.WALLET_DB.prepare(
      `INSERT OR IGNORE INTO transfers (network, transaction_hash, log_index, block_number,
         timestamp, from_address, to_address, amount, kind, token, notify_at)
       VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`,
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
      members.has(transfer.to.toLowerCase()) &&
        times.get(transfer.blockNumber)! >= now - NOTIFY_SECONDS
        ? now
        : null,
    ),
  );
  return { kept, statements, times };
}

/**
 * Reads, for each network, the members' USDC Transfer events since the last block read: whatever a
 * webhook did not deliver. Only members' addresses are queried, so results stay small. Each network
 * reads with an even part of the requests, and one that fails leaves its blocks for the next run
 * (the webhook still delivers in real time) without holding back the others.
 */
export async function reconcileTransfers(env: Env, config: Config, budget: Budget): Promise<void> {
  // In the order they joined, so a group is the same members from one run to the next.
  const { results } = await env.WALLET_DB.prepare(
    'SELECT address FROM members ORDER BY joined_at, address',
  ).all<{ address: Address }>();
  const networks = [...config.networks.values()];
  for (const [i, network] of networks.entries()) {
    const part = budget.share(networks.length - i);
    // HyperSync also finds native-coin deposits, which leave no log: when it fails, the RPC does
    // not stand in, or the cursor would move past them.
    await (
      network.index.hypersync
        ? reconcileWithHypersync(env, network, results, part)
        : reconcileWithRpc(env, network, results, part)
    ).catch((error: unknown) => readerFailed(env, network.id, error));
  }
}

/** The reconciliation of one network through its RPC's `eth_getLogs`, by groups of members. */
async function reconcileWithRpc(
  env: Env,
  network: Network,
  members: readonly { address: Address }[],
  budget: Budget,
) {
  const groups: Address[][] = [];
  for (let i = 0; i < members.length; i += ADDRESSES_PER_QUERY)
    groups.push(members.slice(i, i + ADDRESSES_PER_QUERY).map((row) => row.address));
  if (!budget.take()) return;
  const { client, range, start } = network.index;
  const latest = await client.getBlockNumber();
  const cursor = await cursorOf(env, network);
  let from = cursor === null ? (start ?? latest) : cursor + 1n;
  if (groups.length === 0) {
    if (from <= latest) await saveCursor(env, network.id, latest).run();
    return;
  }
  // A run that ran out of requests in the middle of a range left where it was in it: the next
  // group to read and the range's last block, so the range is finished exactly as it started.
  const partial = await readProgress(env, `range:${network.id}`);
  let group = partial === null ? 0 : Number(await readProgress(env, `group:${network.id}`));
  for (let round = 0; from <= latest && round < ROUNDS; round++) {
    const to =
      partial !== null && round === 0
        ? partial
        : from + range - 1n < latest
          ? from + range - 1n
          : latest;
    for (; group < groups.length; group++) {
      if (!budget.take(2)) return;
      const logs = [];
      for (const args of [{ from: groups[group] }, { to: groups[group] }])
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
      // Out of requests: this group is read again on the next run.
      if (!stored) return;
      const done = group + 1 === groups.length;
      await env.WALLET_DB.batch([
        ...stored.statements,
        // Once every group read the range, the cursor moves past it.
        ...(done
          ? [saveCursor(env, network.id, to), clearProgress(env, network)]
          : saveProgress(env, network, group + 1, to)),
      ]);
    }
    group = 0;
    from = to + 1n;
  }
}

const messageReceived = parseAbiItem(
  'event MessageReceived(address indexed caller, uint32 sourceDomain, bytes32 indexed nonce, bytes32 sender, uint32 indexed finalityThresholdExecuted, bytes messageBody)',
);

/** The name of the network with CCTP domain `domain`, among those GatoPago knows. */
function cctpNetworkName(domain: number): string | null {
  for (const network of Object.values(walletNetworks))
    if (network.cctp.domain === domain) return network.chain.name;
  for (const network of Object.values(stellarNetworks))
    if (network.cctp.domain === domain) return network.name;
  return null;
}

/**
 * Transfers ready to notify: with their coin and, for USDC that arrived from another network (a
 * CCTP mint, which comes from no one), where it came from: the source domain of the message
 * Circle's MessageTransmitter received in the same transaction. One request per such arrival.
 */
export async function notices(network: Network, transfers: readonly Transfer[], budget?: Budget) {
  return Promise.all(
    transfers.map(async (transfer) => {
      const coin = coinOf(network, transfer.token) ?? undefined;
      const minted =
        transfer.token !== null &&
        isAddressEqual(transfer.token, network.usdc) &&
        isAddressEqual(transfer.from, zeroAddress);
      if (!minted) return { ...transfer, coin };
      if (budget && !budget.take()) return { ...transfer, coin, origin: null };
      const receipt = await network.client
        .getTransactionReceipt({ hash: transfer.transactionHash })
        .catch(() => null);
      if (!receipt) return { ...transfer, coin, origin: null };
      const [message] = parseEventLogs({ abi: [messageReceived], logs: receipt.logs });
      // A USDC mint that no CCTP message brought: an ordinary receipt.
      if (!message) return { ...transfer, coin };
      return { ...transfer, coin, origin: cctpNetworkName(message.args.sourceDomain) };
    }),
  );
}

/** The block the reconciliation of `network` read last, or null before its first run. */
const cursorOf = (env: Env, network: Network) => readProgress(env, network.id);

const readProgress = async (env: Env, key: string) => {
  const value = await readCursor(env, key);
  return value === null ? null : BigInt(value);
};

/** Mid-range progress of the RPC reconciliation: the next member group, and the range's end. */
const saveProgress = (env: Env, network: Network, group: number, to: bigint) => [
  saveCursor(env, `group:${network.id}`, group),
  saveCursor(env, `range:${network.id}`, to),
];

const clearProgress = (env: Env, network: Network) =>
  env.WALLET_DB.prepare('DELETE FROM index_cursors WHERE network IN (?, ?)').bind(
    `group:${network.id}`,
    `range:${network.id}`,
  );

/**
 * The reconciliation of one network through Envio HyperSync: one request reads every member's
 * transfers over as many blocks as HyperSync answers, with their times.
 */
async function reconcileWithHypersync(
  env: Env,
  network: Network,
  members: readonly { address: Address }[],
  budget: Budget,
) {
  const source = network.index.hypersync!;
  const cursor = await cursorOf(env, network);
  let from = cursor === null ? network.index.start : cursor + 1n;
  if (from === null) {
    // First run without a start block: from the latest block on.
    if (budget.take()) await saveCursor(env, network.id, await hypersyncHeight(source)).run();
    return;
  }
  if (members.length === 0) return;
  for (let round = 0; round < ROUNDS; round++) {
    if (!budget.take()) return;
    const page = await hypersyncTransfers(source, {
      coins: networkCoins(network).map((coin) => coin.address),
      addresses: members.map((member) => member.address),
      fromBlock: from,
    });
    if (page.nextBlock <= from) return;
    // The newest blocks could still be reorganized: they are kept for the next run, once final.
    const final = page.height === null ? page.nextBlock - 1n : page.height - FINALITY_BLOCKS;
    const until = page.nextBlock - 1n < final ? page.nextBlock - 1n : final;
    if (until < from) return;
    const stored = await storeTransfers(
      env,
      network,
      page.transfers.filter((transfer) => transfer.blockNumber <= until),
      budget,
      page.times,
    );
    // Out of requests: this range is read again on the next run.
    if (!stored) return;
    await env.WALLET_DB.batch([...stored.statements, saveCursor(env, network.id, until)]);
    if (until < page.nextBlock - 1n) return;
    from = page.nextBlock;
    if (page.height !== null && from > page.height) return;
  }
}

/**
 * Members' history from before they joined, read once on each network through HyperSync: what
 * reached their address (a payment that brought them, say) while the reconciliation was already
 * past those blocks. From the factory's deployment (`since`) up to where the reconciliation is,
 * which goes on from there. Progress is saved per member and network (`history:<network>:<address>`
 * in `index_cursors`), so running out of requests resumes instead of starting over, and the history
 * is marked read per network (`member_networks`): a network added later is read for every member.
 * Each network takes an even part of the requests; members go in random order, so one whose history
 * is slow to finish does not hold back the others.
 */
export async function readMemberHistories(env: Env, config: Config, budget: Budget) {
  const networks = [...config.networks.values()].filter((network) => network.index.hypersync);
  for (const [i, network] of networks.entries())
    await readHistories(env, network, budget.share(networks.length - i));
}

async function readHistories(env: Env, network: Network, budget: Budget) {
  const hypersync = network.index.hypersync!;
  const target = await cursorOf(env, network);
  // Not reconciled yet: there is no "where it is" to read up to; its members wait.
  if (target === null) return;
  const { results } = await env.WALLET_DB.prepare(
    `SELECT members.address FROM members
     LEFT JOIN member_networks ON member_networks.address = members.address
       AND member_networks.network = ?
     WHERE member_networks.history_read IS NOT 1
     ORDER BY random() LIMIT 5`,
  )
    .bind(network.id)
    .all<{ address: Address }>();
  for (const { address } of results) {
    const key = `history:${network.id}:${address.toLowerCase()}`;
    const read = await readCursor(env, key);
    let from = read === null ? hypersync.since : BigInt(read) + 1n;
    while (from <= target) {
      // Out of requests: the next run goes on from the last page saved.
      if (!budget.take()) return;
      const page = await hypersyncTransfers(hypersync, {
        coins: networkCoins(network).map((coin) => coin.address),
        addresses: [address],
        fromBlock: from,
        toBlock: target + 1n,
      });
      const stored = await storeTransfers(env, network, page.transfers, budget, page.times);
      if (!stored) return;
      // HyperSync's archive is behind the reconciliation: try again on a later run.
      if (page.nextBlock <= from) break;
      from = page.nextBlock > target + 1n ? target + 1n : page.nextBlock;
      await env.WALLET_DB.batch([...stored.statements, saveCursor(env, key, from - 1n)]);
    }
    if (from > target)
      await env.WALLET_DB.prepare(
        `INSERT INTO member_networks (address, network, history_read) VALUES (?, ?, 1)
         ON CONFLICT (address, network) DO UPDATE SET history_read = 1`,
      )
        .bind(address, network.id)
        .run();
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
  const stellar = await env.WALLET_DB.prepare('SELECT stellar_address FROM members WHERE id = ?')
    .bind(member.id)
    .first<string | null>('stellar_address');
  const mine = stellar ? [me, stellar] : [me];
  const before = new URL(request.url).searchParams.get('before');
  let after: [number, number, number, string] | null = null;
  if (before) {
    const [timestamp, block, index, hash] = before.split('_');
    if (
      !/^\d+$/.test(timestamp) ||
      !/^\d+$/.test(block) ||
      // A native-coin transfer has no log: its index is negative (`NATIVE_LOG_INDEX` and below).
      !/^-?\d+$/.test(index) ||
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
     LEFT JOIN members ON members.address = ${other} OR members.stellar_address = ${other}
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
