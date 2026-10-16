/**
 * Where each reader stopped (`index_cursors`): a block per network, a ledger on Stellar, and what a
 * run left halfway (a window's next group, a member's history). Each write records when, and a
 * reader that fails records when too (`index_failures`), so the health check shows one that stopped.
 */

export const readCursor = (env: Env, key: string) =>
  env.WALLET_DB.prepare('SELECT block FROM index_cursors WHERE network = ?')
    .bind(key)
    .first<number>('block');

export const saveCursor = (env: Env, key: string, block: number | bigint) =>
  env.WALLET_DB.prepare(
    `INSERT INTO index_cursors (network, block, updated_at) VALUES (?, ?, ?)
     ON CONFLICT (network) DO UPDATE SET block = excluded.block, updated_at = excluded.updated_at`,
  ).bind(key, Number(block), Math.floor(Date.now() / 1000));

/**
 * Ledgers a reader could no longer read (the RPC no longer keeps them): `missed:<reader>` holds the
 * last one, so the history before it is known to be incomplete.
 */
export const missedUntil = (env: Env, reader: string, last: number) =>
  env.WALLET_DB.prepare(
    `INSERT INTO index_cursors (network, block, updated_at) VALUES (?, ?, ?)
     ON CONFLICT (network) DO UPDATE SET block = max(block, excluded.block),
       updated_at = excluded.updated_at`,
  ).bind(`missed:${reader}`, last, Math.floor(Date.now() / 1000));

/** Logs why `reader` failed and records when; it goes on from its cursor on the next run. */
export async function readerFailed(env: Env, reader: string, error: unknown) {
  console.error(error);
  await env.WALLET_DB.prepare(
    `INSERT INTO index_failures (reader, failed_at) VALUES (?, ?)
     ON CONFLICT (reader) DO UPDATE SET failed_at = excluded.failed_at`,
  )
    .bind(reader, Math.floor(Date.now() / 1000))
    .run()
    .catch((failure: unknown) => console.error(failure));
}

/** The slowest reader runs every 10 minutes: one that has not moved in three runs is behind. */
const BEHIND_SECONDS = 1_800;

/**
 * What the health check tells beyond being up: each reader's last block, when it moved and when it
 * failed; those behind (failing since they last moved, or still); ledgers no longer readable; and
 * the notifications still to send.
 */
export async function readersHealth(env: Env) {
  const [cursors, failures, pending] = await env.WALLET_DB.batch<Record<string, unknown>>([
    env.WALLET_DB.prepare(
      `SELECT network AS reader, block, updated_at FROM index_cursors
       WHERE network NOT LIKE 'group:%' AND network NOT LIKE 'range:%'
         AND network NOT LIKE 'history:%'`,
    ),
    env.WALLET_DB.prepare('SELECT reader, failed_at FROM index_failures'),
    env.WALLET_DB.prepare('SELECT count(*) AS count FROM transfers WHERE notify_at IS NOT NULL'),
  ]);
  const now = Math.floor(Date.now() / 1000);
  const readers: Record<
    string,
    { block: number | null; updated_at: number | null; failed_at: number | null }
  > = {};
  const missed: Record<string, number> = {};
  for (const row of cursors.results as { reader: string; block: number; updated_at: number }[])
    if (row.reader.startsWith('missed:')) missed[row.reader.slice(7)] = row.block;
    else readers[row.reader] = { block: row.block, updated_at: row.updated_at, failed_at: null };
  for (const row of failures.results as { reader: string; failed_at: number }[])
    readers[row.reader] = {
      ...(readers[row.reader] ?? { block: null, updated_at: null }),
      failed_at: row.failed_at,
    };
  const behind = Object.keys(readers).filter((reader) => {
    const { updated_at, failed_at } = readers[reader];
    return (
      (failed_at !== null && failed_at >= (updated_at ?? 0)) ||
      (updated_at !== null && updated_at < now - BEHIND_SECONDS)
    );
  });
  return {
    readers,
    behind,
    missed,
    notifications_pending: (pending.results[0] as { count: number }).count,
  };
}
