import { DatabaseSync } from 'node:sqlite';
import { readFileSync } from 'node:fs';
import { describe, expect, it } from 'vitest';

const migration = (name: string) =>
  readFileSync(new URL(`../migrations/${name}`, import.meta.url), 'utf8');
const hash = `0x${'11'.repeat(32)}`,
  address = `0x${'22'.repeat(20)}`,
  entryPoint = `0x${'33'.repeat(20)}`;
const user = 'usr_11111111-1111-4111-8111-111111111111',
  wallet = 'wal_22222222-2222-4222-8222-222222222222',
  account = 'wac_33333333-3333-4333-8333-333333333333';
function fixture(count: number) {
  const db = new DatabaseSync(':memory:');
  db.exec('PRAGMA foreign_keys = ON');
  for (const name of [
    '0001_initial.sql',
    '0002_production_namespace.sql',
    '0003_plaintext_invitation_codes.sql',
  ])
    db.exec(migration(name));
  db.prepare("INSERT INTO users(id,environment,created_at) VALUES (?,'production',100)").run(user);
  db.prepare(
    "INSERT INTO wallets(id,user_id,status,account_id,initial_security_commitment,user_salt_commitment,canonical_address,created_at) VALUES (?,?,'active',?,?,?,?,100)",
  ).run(wallet, user, hash, hash, hash, address);
  db.prepare(
    "INSERT INTO wallet_accounts(id,wallet_id,network_id,address,deployment_manifest_sha256,deployment_state,created_at) VALUES (?,?,'eip155:421614',?,?,'active',100)",
  ).run(account, wallet, address, hash);
  function insert(nonce: number) {
    const id = `op_44444444-4444-4444-8444-${String(nonce).padStart(12, '0')}`;
    db.prepare(
      `INSERT INTO transfer_nonce_reservations(id,wallet_id,wallet_account_id,network_id,account_address,entry_point,nonce,
      consent_digest,userop_hash,deployment_manifest_sha256,operation_json,operation_sha256,review_json,review_sha256,funds_json,funds_sha256,
      authorized_auth_time,state,created_at,expires_at) VALUES (?,?,?,'eip155:421614',?,?,?,?,?,?,'{}',?,'{}',?,'{}',?,100,'held',100,200)`,
    ).run(
      id,
      wallet,
      account,
      address,
      entryPoint,
      String(nonce),
      `0x${String(nonce).padStart(64, '0')}`,
      hash,
      hash,
      hash,
      hash,
      hash,
    );
    return id;
  }
  const ids = Array.from({ length: count }, (_, nonce) => insert(nonce));
  return { db, ids, insert };
}
describe('Incremental money migration with existing legacy reservations', () => {
  it('preserves every pre-existing row and drains multiple active legacy operations without cancelling them', () => {
    const { db, ids, insert } = fixture(2);
    try {
      const original = db.prepare('SELECT * FROM transfer_nonce_reservations ORDER BY id').all();
      db.exec(migration('0004_money_operations.sql'));
      expect(db.prepare('SELECT * FROM transfer_nonce_reservations ORDER BY id').all()).toEqual(
        original,
      );
      expect(
        db.prepare('SELECT state FROM wallet_spend_locks ORDER BY operation_id').all(),
      ).toEqual([{ state: 'legacy_drain' }, { state: 'legacy_drain' }]);
      expect(() => insert(2)).toThrow('ACCOUNT_SPEND_BUSY');
      db.prepare("UPDATE transfer_nonce_reservations SET state = 'expired' WHERE id = ?").run(
        ids[0],
      );
      expect(() => insert(2)).toThrow('ACCOUNT_SPEND_BUSY');
      db.prepare("UPDATE transfer_nonce_reservations SET state = 'expired' WHERE id = ?").run(
        ids[1],
      );
      insert(2);
      expect(
        db.prepare('SELECT count(*) AS n FROM wallet_spend_locks WHERE released_at IS NULL').get()
          ?.n,
      ).toBe(1);
      expect(
        db.prepare("SELECT count(*) AS n FROM wallet_spend_locks WHERE state = 'released'").get()
          ?.n,
      ).toBe(2);
      expect(db.prepare('PRAGMA foreign_key_check').all()).toEqual([]);
    } finally {
      db.close();
    }
  });
  it('backfills a single active hold and prevents a second even when its nonce differs', () => {
    const { db, insert } = fixture(1);
    try {
      db.exec(migration('0004_money_operations.sql'));
      expect(db.prepare('SELECT domain,state,nonce FROM wallet_spend_locks').get()).toMatchObject({
        domain: 'transfer',
        state: 'held',
        nonce: '0',
      });
      expect(() => insert(1)).toThrow('ACCOUNT_SPEND_BUSY');
    } finally {
      db.close();
    }
  });
});
