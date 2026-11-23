import { decodeFunctionData, getAbiItem, type Hex } from 'viem';
import { gatopagoAccountAbi } from '@gatopago/shared/wallet';
import type { Budget } from './budget';
import type { Config, Network } from './config';
import { readCursor, readerFailed, saveCursor } from './cursors';
import { alertChange } from './push';

/** Ranges one run reads per network at most: enough to catch up the minute in between. */
const ROUNDS = 5;
/** Alerts sent per run at most, and how a failed one is retried: 30 s, 1, 2, 4 minutes. */
const BATCH = 20;
const ATTEMPTS = 5;
const RETRY_SECONDS = 30;

const changeEvents = [
  getAbiItem({ abi: gatopagoAccountAbi, name: 'ChangeScheduled' }),
  getAbiItem({ abi: gatopagoAccountAbi, name: 'ChangeApplied' }),
  getAbiItem({ abi: gatopagoAccountAbi, name: 'ChangeCanceled' }),
] as const;
const readLogs = (network: Network, fromBlock: bigint, toBlock: bigint) =>
  network.index.client.getLogs({ events: changeEvents, fromBlock, toBlock, strict: true });
type ChangeLog = Awaited<ReturnType<typeof readLogs>>[number];

/**
 * Every minute: follows the owner changes members' accounts schedule, apply and cancel on each
 * network (`owner_changes`), then tells the members about new ones. Once a change applies on the
 * home network, where sign-in checks the owners, every session of the member ends: one may be a
 * removed key's.
 */
export async function readChanges(env: Env, config: Config, budget: Budget) {
  for (const network of config.networks.values())
    await readNetwork(env, config, network, budget).catch((error: unknown) =>
      readerFailed(env, `changes:${network.id}`, error),
    );
  await sendAlerts(env, config, budget);
}

async function readNetwork(env: Env, config: Config, network: Network, budget: Budget) {
  const reader = `changes:${network.id}`;
  const { client, range, start } = network.index;
  if (!budget.take()) return;
  const latest = await client.getBlockNumber();
  const cursor = await readCursor(env, reader);
  let from = cursor === null ? (start ?? latest) : BigInt(cursor) + 1n;
  const home = network.id === config.home.id;
  for (let round = 0; from <= latest && round < ROUNDS; round++) {
    if (!budget.take()) return;
    const to = from + range - 1n < latest ? from + range - 1n : latest;
    const logs = await readLogs(network, from, to);
    await env.WALLET_DB.batch([
      ...logs.flatMap((log) => statements(env, network.id, home, log)),
      saveCursor(env, reader, to),
    ]);
    from = to + 1n;
  }
}

function statements(env: Env, network: string, home: boolean, log: ChangeLog) {
  const account = log.address.toLowerCase();
  const id = log.args.id;
  if (log.eventName === 'ChangeScheduled')
    return [
      // Only members' accounts, and one alert per change, the first network to schedule it.
      env.WALLET_DB.prepare(
        `INSERT INTO owner_changes (account, network, id, sequence, call, ready_at, alert_at)
         SELECT ?1, ?2, ?3, ?4, ?5, ?6, CASE WHEN EXISTS (
           SELECT 1 FROM owner_changes WHERE account = ?1 AND id = ?3) THEN NULL ELSE unixepoch() END
         WHERE EXISTS (SELECT 1 FROM members WHERE address = ?1)
         ON CONFLICT DO NOTHING`,
      ).bind(
        account,
        network,
        id,
        Number(log.args.sequence),
        log.args.call,
        Number(log.args.readyAt),
      ),
    ];
  const forget = env.WALLET_DB.prepare(
    'DELETE FROM owner_changes WHERE account = ? AND network = ? AND id = ?',
  ).bind(account, network, id);
  if (log.eventName === 'ChangeCanceled' || !home) return [forget];
  return [
    forget,
    env.WALLET_DB.prepare(
      'UPDATE members SET session_generation = session_generation + 1 WHERE address = ?',
    ).bind(account),
  ];
}

/** Sends the alerts still pending, oldest first, as `sendNotifications` does with movements. */
async function sendAlerts(env: Env, config: Config, budget: Budget) {
  const now = Math.floor(Date.now() / 1000);
  const { results } = await env.WALLET_DB.prepare(
    `SELECT account, network, id, call, alert_attempts FROM owner_changes
     WHERE alert_at <= ? ORDER BY alert_at LIMIT ?`,
  )
    .bind(now, BATCH)
    .all<{ account: string; network: string; id: string; call: Hex; alert_attempts: number }>();
  for (const change of results) {
    const { functionName } = decodeFunctionData({ abi: gatopagoAccountAbi, data: change.call });
    const outcome = await alertChange(
      env,
      config,
      {
        account: change.account,
        id: change.id,
        upgrade: functionName === 'upgradeToAndCall',
      },
      budget,
    );
    if (outcome === 'budget') return;
    const attempts = change.alert_attempts + 1;
    await env.WALLET_DB.prepare(
      `UPDATE owner_changes SET alert_at = ?, alert_attempts = ?
       WHERE account = ? AND network = ? AND id = ?`,
    )
      .bind(
        outcome === 'retry' && attempts < ATTEMPTS
          ? now + RETRY_SECONDS * 2 ** change.alert_attempts
          : null,
        attempts,
        change.account,
        change.network,
        change.id,
      )
      .run();
  }
}
