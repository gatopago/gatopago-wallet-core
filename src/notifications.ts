import { getAddress, type Address, type Hex } from 'viem';
import { coinBySymbol, notices } from './activity';
import type { Budget } from './budget';
import type { Config } from './config';
import { deliver, NOTIFY_SECONDS, type Notice } from './push';
import { relayOrigin } from './stellar';

/** Notifications sent per run at most, and how a failed one is retried: 30 s, 1, 2, 4 minutes. */
const BATCH = 20;
const ATTEMPTS = 5;
const RETRY_SECONDS = 30;

interface Pending {
  network: string;
  transaction_hash: string;
  log_index: number;
  block_number: number;
  timestamp: number;
  from_address: string;
  to_address: string;
  amount: string;
  kind: string;
  token: string;
  notify_attempts: number;
}

/**
 * Sends the notifications of stored movements still pending (`transfers.notify_at`), oldest first,
 * within the run's budget. A movement is marked by the statement that stores it, so nothing is
 * lost when a run stops halfway; with nothing pending this is one indexed read. A failed send is
 * retried a few times, then dropped, as is one older than `NOTIFY_SECONDS`: by then the app shows
 * it anyway.
 */
export async function sendNotifications(env: Env, config: Config, budget: Budget) {
  const now = Math.floor(Date.now() / 1000);
  const { results } = await env.WALLET_DB.prepare(
    `SELECT network, transaction_hash, log_index, block_number, timestamp, from_address,
       to_address, amount, kind, token, notify_attempts
     FROM transfers WHERE notify_at <= ? ORDER BY notify_at LIMIT ?`,
  )
    .bind(now, BATCH)
    .all<Pending>();
  for (const pending of results) {
    const notice =
      pending.timestamp >= now - NOTIFY_SECONDS
        ? await noticeOf(env, config, pending, budget)
        : null;
    const outcome = notice ? await deliver(env, config, notice, budget) : 'sent';
    if (outcome === 'budget') return;
    const attempts = pending.notify_attempts + 1;
    await env.WALLET_DB.prepare(
      `UPDATE transfers SET notify_at = ?, notify_attempts = ?
       WHERE network = ? AND transaction_hash = ? AND log_index = ?`,
    )
      .bind(
        outcome === 'retry' && attempts < ATTEMPTS
          ? now + RETRY_SECONDS * 2 ** pending.notify_attempts
          : null,
        attempts,
        pending.network,
        pending.transaction_hash,
        pending.log_index,
      )
      .run();
  }
}

/** What to tell about a stored movement: its coin, and where money from another network came from. */
async function noticeOf(
  env: Env,
  config: Config,
  pending: Pending,
  budget: Budget,
): Promise<Notice | null> {
  const tag = `${pending.network}:${pending.transaction_hash}:${pending.log_index}`;
  const base = {
    from: pending.from_address,
    to: pending.to_address,
    value: BigInt(pending.amount),
    tag,
  };
  const stellar = config.stellar;
  if (stellar && pending.network === stellar.id) {
    const crosschain = [stellar.network.cctp.tokenMessengerMinter, stellar.network.cctp.forwarder];
    // USDC is kept in 6 decimals like every network; XLM in its own 7.
    const coin =
      pending.token === 'XLM' ? { symbol: 'XLM', decimals: 7 } : { symbol: 'USDC', decimals: 6 };
    return crosschain.includes(pending.from_address)
      ? { ...base, coin, origin: await relayOrigin(env, pending.transaction_hash) }
      : { ...base, coin };
  }
  const network = config.networks.get(pending.network);
  const coin = network && coinBySymbol(network, pending.token);
  if (!network || !coin) return null;
  const [notice] = await notices(
    network,
    [
      {
        transactionHash: pending.transaction_hash as Hex,
        logIndex: pending.log_index,
        blockNumber: BigInt(pending.block_number),
        token: coin.address,
        from: getAddress(pending.from_address) as Address,
        to: getAddress(pending.to_address) as Address,
        value: base.value,
      },
    ],
    budget,
  );
  return 'origin' in notice
    ? { ...base, coin: notice.coin ?? coin, origin: notice.origin }
    : { ...base, coin: notice.coin ?? coin };
}
