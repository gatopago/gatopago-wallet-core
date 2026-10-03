import { readFileSync } from 'node:fs';
import { DatabaseSync } from 'node:sqlite';
import { describe, expect, it } from 'vitest';

const baseline = readFileSync(new URL('../migrations/0001_initial.sql', import.meta.url), 'utf8');
const namespace = readFileSync(new URL('../migrations/0002_production_namespace.sql', import.meta.url), 'utf8');
const migration = readFileSync(new URL('../migrations/0003_plaintext_invitation_codes.sql', import.meta.url), 'utf8');
const operationId = 'op_00000000-0000-4000-8000-000000000001';
const userId = 'usr_00000000-0000-4000-8000-000000000001';

function previousDatabase() {
  const db = new DatabaseSync(':memory:');
  db.exec('PRAGMA foreign_keys = ON');
  db.exec(baseline);
  db.exec(namespace);
  return db;
}

describe('plain-text invitation migration (local SQLite only)', () => {
  it('preserves users and login challenges with foreign keys enabled', () => {
    const db = previousDatabase();
    try {
      db.prepare("INSERT INTO users(id,environment,created_at) VALUES (?,'production',1)").run(userId);
      db.prepare(`INSERT INTO auth_challenges(id,purpose,challenge,rp_id,origin,created_at,expires_at)
        VALUES (?,'login',?,'gatopago.com','https://gatopago.com',1,301)`)
        .run(operationId, `0x${'01'.repeat(32)}`);
      db.exec('BEGIN');
      db.exec(migration);
      db.exec('COMMIT');
      expect(db.prepare('SELECT id,environment FROM users').all()).toEqual([{ id: userId, environment: 'production' }]);
      expect(db.prepare('SELECT id,purpose,invite_code,expires_at FROM auth_challenges').all())
        .toEqual([{ id: operationId, purpose: 'login', invite_code: null, expires_at: 301 }]);
      expect(db.prepare('PRAGMA foreign_key_check').all()).toEqual([]);
      expect(db.prepare('PRAGMA integrity_check').get()?.integrity_check).toBe('ok');
      const columns = db.prepare('PRAGMA table_info(signup_invites)').all().map(column => column.name);
      expect(columns).toContain('code');
      expect(columns).not.toContain('token_hash');
      expect(db.prepare("SELECT name FROM sqlite_schema WHERE name GLOB '_*hashed' OR name = '_invitation_codes_guard'").all())
        .toEqual([]);
    } finally { db.close(); }
  });
  it('accepts the direct operator INSERT with no hashes or fixed-length codes', () => {
    const db = previousDatabase();
    try {
      db.exec(migration);
      for (const code of ['123', 'daniel', 'team1', 'a', 'hello world', "O'Brien", 'café 🐈', ' padded ', 'x'.repeat(120)]) {
        db.prepare(`INSERT INTO signup_invites(code,issued_by,created_at,expires_at)
          VALUES (?,'daniel',unixepoch(),unixepoch()+604800)`).run(code);
        expect(db.prepare('SELECT code FROM signup_invites WHERE code = ?').get(code)?.code).toBe(code);
      }
      expect(() => db.prepare(`INSERT INTO signup_invites(code,issued_by,created_at,expires_at)
        VALUES (?,'daniel',1,2)`).run('')).toThrow();
      expect(() => db.prepare(`INSERT INTO signup_invites(code,issued_by,created_at,expires_at)
        VALUES (?,'daniel',1,2)`).run('daniel')).toThrow();
    } finally { db.close(); }
  });
  it('stops before rewriting old hashed invitations instead of losing admission history', () => {
    const db = previousDatabase(), hash = `0x${'01'.repeat(32)}`;
    try {
      db.prepare("INSERT INTO signup_invites(token_hash,issued_by,created_at,expires_at) VALUES (?,'daniel',1,2)").run(hash);
      db.exec('BEGIN');
      expect(() => db.exec(migration)).toThrow();
      db.exec('ROLLBACK');
      expect(db.prepare('SELECT token_hash,issued_by FROM signup_invites').all()).toEqual([{ token_hash: hash, issued_by: 'daniel' }]);
      expect(db.prepare('PRAGMA foreign_key_check').all()).toEqual([]);
    } finally { db.close(); }
  });
});
