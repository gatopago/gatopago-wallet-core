import type { Hex } from 'viem';
import { requireHash } from '@gatopago/shared/v3/deployment';
import { parseResourceId } from '@gatopago/shared/v3/primitives';

const unit = 1_000_000_000n;
export function budgetUnits(wei: bigint) {
  const units = (wei + unit - 1n) / unit;
  if (wei < 0n || units > BigInt(Number.MAX_SAFE_INTEGER))
    throw new Error('SPONSOR_BUDGET_INVALID');
  return Number(units);
}

export class SponsorshipBudget {
  private readonly db: D1DatabaseSession;
  constructor(database: D1Database) {
    this.db = database.withSession('first-primary');
  }
  async reserve(
    input: {
      digest: Hex;
      scope: string;
      userId: string;
      maximumWei: bigint;
      validUntil: number;
      dailyGwei: number;
      userDailyGwei: number;
      userDailyOperations: number;
    },
    now = Math.floor(Date.now() / 1000),
  ) {
    const {
      digest,
      scope,
      userId,
      maximumWei,
      validUntil,
      dailyGwei,
      userDailyGwei,
      userDailyOperations,
    } = input;
    requireHash(digest);
    parseResourceId('user', userId);
    const cost = budgetUnits(maximumWei),
      day = Math.floor(now / 86400);
    if (
      ![dailyGwei, userDailyGwei, userDailyOperations, now, validUntil].every(
        Number.isSafeInteger,
      ) ||
      now < 1 ||
      !/^[1-9][0-9]{0,77}:0x[0-9a-f]{40}$/.test(scope) ||
      userDailyGwei <= 0 ||
      dailyGwei < userDailyGwei ||
      userDailyOperations <= 0 ||
      cost <= 0 ||
      cost > userDailyGwei ||
      validUntil <= now ||
      validUntil > now + 600
    )
      throw new Error('SPONSOR_BUDGET_INVALID');
    await this.db
      .prepare(
        `INSERT INTO sponsorship_reservations
      (digest,scope,user_id,day,maximum_gwei,charged_gwei,maximum_wei,valid_until)
      SELECT ?,?,?,?,?,?,?,? WHERE
      (SELECT COALESCE(SUM(charged_gwei),0) FROM sponsorship_reservations WHERE scope=? AND day=?) <= ?
      AND (SELECT COALESCE(SUM(charged_gwei),0) FROM sponsorship_reservations WHERE scope=? AND day=? AND user_id=?) <= ?
      AND (SELECT COUNT(*) FROM sponsorship_reservations WHERE scope=? AND day=? AND user_id=?) < ?
      ON CONFLICT(digest) DO NOTHING`,
      )
      .bind(
        digest,
        scope,
        userId,
        day,
        cost,
        cost,
        maximumWei.toString(),
        validUntil,
        scope,
        day,
        dailyGwei - cost,
        scope,
        day,
        userId,
        userDailyGwei - cost,
        scope,
        day,
        userId,
        userDailyOperations,
      )
      .run();
    const row = await this.db
      .prepare('SELECT * FROM sponsorship_reservations WHERE digest=?')
      .bind(digest)
      .first();
    if (!row) throw new Error('SPONSOR_BUDGET_EXHAUSTED');
    if (
      row.scope !== scope ||
      row.user_id !== userId ||
      row.maximum_wei !== maximumWei.toString() ||
      row.valid_until !== validUntil
    )
      throw new Error('SPONSOR_RESERVATION_CONFLICT');
  }
  async bind(digest: Hex, hash: Hex) {
    requireHash(digest);
    requireHash(hash);
    await this.db
      .prepare(
        'UPDATE sponsorship_reservations SET userop_hash=? WHERE digest=? AND (userop_hash IS NULL OR userop_hash=?)',
      )
      .bind(hash, digest, hash)
      .run();
    const row = await this.db
      .prepare('SELECT userop_hash FROM sponsorship_reservations WHERE digest=?')
      .bind(digest)
      .first();
    if (row?.userop_hash !== hash) throw new Error('SPONSOR_RESERVATION_CONFLICT');
  }

  async settle(hash: Hex, actualWei: bigint, transactionHash: Hex) {
    requireHash(hash);
    requireHash(transactionHash);
    const row = await this.db
      .prepare(
        'SELECT digest,maximum_wei,actual_wei,transaction_hash FROM sponsorship_reservations WHERE userop_hash=?',
      )
      .bind(hash)
      .first<{
        digest: string;
        maximum_wei: string;
        actual_wei: string | null;
        transaction_hash: string | null;
      }>();
    if (!row) return;
    if (
      actualWei < 0n ||
      actualWei > BigInt(row.maximum_wei) ||
      (row.actual_wei !== null &&
        (row.actual_wei !== actualWei.toString() || row.transaction_hash !== transactionHash))
    ) {
      throw new Error('SPONSOR_SETTLEMENT_CONFLICT');
    }
    await this.db
      .prepare(
        `UPDATE sponsorship_reservations SET actual_wei=?,charged_gwei=?,transaction_hash=?
      WHERE digest=? AND actual_wei IS NULL`,
      )
      .bind(actualWei.toString(), budgetUnits(actualWei), transactionHash, row.digest)
      .run();
    const settled = await this.db
      .prepare('SELECT actual_wei,transaction_hash FROM sponsorship_reservations WHERE digest=?')
      .bind(row.digest)
      .first();
    if (
      settled?.actual_wei !== actualWei.toString() ||
      settled.transaction_hash !== transactionHash
    )
      throw new Error('SPONSOR_SETTLEMENT_CONFLICT');
  }
}
