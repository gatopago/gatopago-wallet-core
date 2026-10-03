import { readFileSync, readdirSync } from 'node:fs';
import { DatabaseSync } from 'node:sqlite';
import { describe, expect, it } from 'vitest';
import { registrationProfile } from '../src/auth/profile';

const directory = new URL('../migrations/', import.meta.url);
const migrationName = '0005_three_character_usernames.sql';
const migration = readFileSync(new URL(migrationName, directory), 'utf8');
const id = (kind: string, suffix = '1') => `${kind}_00000000-0000-4000-8000-${suffix.padStart(12, '0')}`;
const hash = (byte: string) => `0x${byte.repeat(32)}`;

function previousDatabase() {
  const db = new DatabaseSync(':memory:');
  db.exec('PRAGMA foreign_keys = ON');
  for (const file of readdirSync(directory).filter(file => file.endsWith('.sql') && file < migrationName).sort()) {
    db.exec(readFileSync(new URL(file, directory), 'utf8'));
  }
  return db;
}
function apply(db: DatabaseSync) {
  db.exec('BEGIN');
  try { db.exec(migration); db.exec('COMMIT'); }
  catch (error) { db.exec('ROLLBACK'); throw error; }
}
function snapshot(db: DatabaseSync) {
  const tables = db.prepare("SELECT name FROM sqlite_schema WHERE type='table' AND name NOT LIKE 'sqlite_%' ORDER BY name")
    .all() as { name: string }[];
  return tables.map(({ name }) => ({ name, rows: db.prepare(`SELECT * FROM "${name}" ORDER BY rowid`).all() }));
}
function seed(db: DatabaseSync) {
  const user = id('usr'), wallet = id('wal');
  db.prepare(`INSERT INTO users(id,environment,display_name,username,username_reserved_until,auth_not_before,access_snapshot_json,disabled_at,created_at)
    VALUES (?,'production','Daniel','daniel',301,9,'{}',8,1)`).run(user);
  db.prepare(`INSERT INTO wallets(id,user_id,status,account_id,initial_security_commitment,user_salt_commitment,canonical_address,created_at)
    VALUES (?,?,'active',?,?,?, ?,1)`).run(wallet, user, hash('01'), hash('02'), hash('03'), `0x${'12'.repeat(20)}`);
  db.prepare('UPDATE users SET username_reserved_until=NULL,username_published_at=10,receiving_wallet_id=? WHERE id=?').run(wallet, user);
  db.prepare(`INSERT INTO webauthn_credentials(id,user_id,rp_id,origin,credential_id,public_key,transports_json,aaguid,
    backup_eligible,backed_up,sign_count,response_hash,created_at,login_enabled,access_version)
    VALUES (?,?,'gatopago.com','https://gatopago.com','AQID',?,'[]','synthetic',1,1,4,?,1,1,2)`)
    .run(id('op'), user, `0x${'04'.repeat(128)}`, hash('05'));
  db.prepare(`INSERT INTO webauthn_enrollments(id,user_id,rp_id,origin,challenge,proof_challenge,created_at,expires_at)
    VALUES (?,?,'gatopago.com','https://gatopago.com','challenge','proof',1,301)`).run(id('op', '2'), user);
  db.prepare(`INSERT INTO signup_invites(code,issued_by,created_at,expires_at,consumed_by,consumed_at)
    VALUES ('used','operator',1,101,?,50)`).run(user);
  db.exec("INSERT INTO signup_invites(code,issued_by,created_at,expires_at) VALUES ('next','operator',1,1000)");
  db.prepare(`INSERT INTO auth_challenges(id,purpose,challenge,proof_challenge,rp_id,origin,proposed_user_id,
    invite_code,display_name,username,created_at,expires_at)
    VALUES (?,'register',?,?,'gatopago.com','https://gatopago.com',?,'next','Another','another',1,301)`)
    .run(id('op', '3'), hash('06'), hash('07'), id('usr', '2'));
  db.prepare(`INSERT INTO auth_challenges(id,purpose,challenge,rp_id,origin,created_at,expires_at)
    VALUES (?,'login',?,'gatopago.com','https://gatopago.com',1,301)`).run(id('op', '4'), hash('08'));
}

describe('three-character username migration', () => {
  it('preserves every row, foreign key, receiving wallet and authentication state when rebuilding populated tables', () => {
    const db = previousDatabase();
    try {
      seed(db); const before = snapshot(db);
      apply(db);
      expect(snapshot(db)).toEqual(before);
      expect(db.prepare('PRAGMA foreign_key_check').all()).toEqual([]);
      expect(db.prepare('PRAGMA integrity_check').get()?.integrity_check).toBe('ok');
      expect(db.prepare('PRAGMA foreign_keys').get()?.foreign_keys).toBe(1);
      expect(db.prepare('PRAGMA defer_foreign_keys').get()?.defer_foreign_keys).toBe(0);
      expect(db.prepare("SELECT name FROM sqlite_schema WHERE name LIKE '_users_%' OR name LIKE '_auth_challenges_%' OR name='_username_migration_guard'").all()).toEqual([]);
      expect(db.prepare("SELECT name FROM sqlite_schema WHERE tbl_name='users' AND sql IS NOT NULL ORDER BY name").all().map(row => row.name))
        .toEqual(['users', 'users_production_namespace_insert', 'users_production_namespace_update', 'users_username_reservation']);
      expect(() => db.prepare('DELETE FROM users WHERE id=?').run(id('usr'))).toThrow();
    } finally { db.close(); }
  });
  it('accepts 3–30 characters in both tables while preserving format, uniqueness, reservation and namespace checks', () => {
    const db = previousDatabase();
    try {
      apply(db);
      db.exec("INSERT INTO signup_invites(code,issued_by,created_at,expires_at) VALUES ('next','operator',1,1000)");
      const insert = db.prepare(`INSERT INTO users(id,environment,username,username_reserved_until,created_at) VALUES (?,'production',?,301,1)`);
      const challenge = db.prepare(`INSERT INTO auth_challenges(id,purpose,challenge,proof_challenge,rp_id,origin,proposed_user_id,
        invite_code,display_name,username,created_at,expires_at) VALUES (?,'register',?,?,'gatopago.com','https://gatopago.com',?,'next','Name',?,1,301)`);
      for (const [index, username] of ['ana', 'leo', 'dani', 'a'.repeat(30)].entries()) {
        const suffix = String(index + 10), byte = (index + 20).toString(16);
        insert.run(id('usr', suffix), username);
        challenge.run(id('op', suffix), hash(byte), hash((index + 40).toString(16)), id('usr', String(index + 20)), username);
      }
      for (const username of ['a', 'ab', 'a'.repeat(31), '0ana', 'Ana', 'a-n', 'ábc']) {
        expect(() => insert.run(id('usr', '99'), username)).toThrow();
      }
      for (const username of ['ab', 'a'.repeat(31)]) {
        expect(() => challenge.run(id('op', '99'), hash('60'), hash('61'), id('usr', '98'), username)).toThrow();
      }
      expect(() => insert.run(id('usr', '99'), 'ana')).toThrow();
      expect(() => db.exec(`INSERT INTO users(id,environment,created_at) VALUES ('${id('usr', '99')}','local',1)`)).toThrow();
      expect(() => db.prepare("INSERT INTO users(id,environment,username,created_at) VALUES (?,'production','new',1)").run(id('usr', '99'))).toThrow();
    } finally { db.close(); }
  });
  it('stops and rolls back if replacing users would cascade or mutate a child', () => {
    const db = previousDatabase();
    try {
      seed(db);
      db.exec('CREATE TABLE future_child (user_id TEXT REFERENCES users(id) ON DELETE CASCADE) STRICT');
      db.prepare('INSERT INTO future_child VALUES (?)').run(id('usr'));
      const before = snapshot(db);
      expect(() => apply(db)).toThrow();
      expect(snapshot(db)).toEqual(before);
      expect(db.prepare('PRAGMA foreign_key_check').all()).toEqual([]);
      expect(db.prepare("SELECT sql FROM sqlite_schema WHERE name='users'").get()?.sql).toContain('BETWEEN 5 AND 30');
    } finally { db.close(); }
  });
});

describe('registration username policy', () => {
  it.each(['ana', 'leo', 'dani', 'a'.repeat(30)])('accepts and normalizes %s', username => {
    expect(registrationProfile(' Name ', ` ${username.toUpperCase()} `)).toEqual({ displayName: 'Name', username });
  });
  it.each(['a', 'ab', 'a'.repeat(31), '0ana', '_ana', 'a-n', 'ábc', 'admin', 'support'])('rejects unsupported or reserved %s', username => {
    expect(() => registrationProfile('Name', username)).toThrow();
  });
});
