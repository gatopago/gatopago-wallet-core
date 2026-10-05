import type { Address, Hex } from 'viem';

/** A GatoPago user: an onchain account admitted with an invitation. */
export interface Member {
  readonly id: string;
  readonly address: Address;
  readonly initialOwners: readonly Hex[] | null;
  readonly username: string | null;
  readonly displayName: string | null;
}

interface MemberRow {
  id: string;
  address: Address;
  initial_owners: string | null;
  username: string | null;
  display_name: string | null;
}

const member = (row: MemberRow): Member => ({
  id: row.id,
  address: row.address,
  initialOwners: row.initial_owners ? JSON.parse(row.initial_owners) : null,
  username: row.username,
  displayName: row.display_name,
});

const COLUMNS = 'id, address, initial_owners, username, display_name';

export async function memberByAddress(db: D1Database, address: Address): Promise<Member | null> {
  const row = await db
    .prepare(`SELECT ${COLUMNS} FROM members WHERE address = ?`)
    .bind(address.toLowerCase())
    .first<MemberRow>();
  return row && member(row);
}

export async function memberByUsername(db: D1Database, username: string): Promise<Member | null> {
  const row = await db
    .prepare(`SELECT ${COLUMNS} FROM members WHERE username = ?`)
    .bind(username)
    .first<MemberRow>();
  return row && member(row);
}

/**
 * Admits `address` with an unused, unexpired invitation, atomically: the batch fails as a whole if
 * the invitation was consumed concurrently (`members.invite_code` is unique).
 */
export async function admit(
  db: D1Database,
  id: string,
  address: Address,
  invite: string,
): Promise<boolean> {
  const now = Math.floor(Date.now() / 1000);
  try {
    await db.batch([
      db
        .prepare(
          `INSERT INTO members (id, address, invite_code, joined_at)
           SELECT ?, ?, code, ? FROM invites
           WHERE code = ? AND consumed_by IS NULL AND revoked_at IS NULL AND expires_at > ?`,
        )
        .bind(id, address.toLowerCase(), now, invite, now),
      db
        .prepare(
          `UPDATE invites SET consumed_by = ? WHERE code = ? AND EXISTS (SELECT 1 FROM members WHERE id = ?)`,
        )
        .bind(id, invite, id),
    ]);
  } catch (error) {
    if (String(error).includes('UNIQUE constraint failed')) return false;
    throw error;
  }
  return (await db.prepare('SELECT 1 FROM members WHERE id = ?').bind(id).first()) !== null;
}
