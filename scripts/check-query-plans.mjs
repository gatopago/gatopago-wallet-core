import assert from 'node:assert/strict';
import { readFileSync } from 'node:fs';
import { DatabaseSync } from 'node:sqlite';

const db = new DatabaseSync(':memory:');
try {
  db.exec(readFileSync(new URL('../migrations/0001_initial.sql', import.meta.url), 'utf8'));
  const cases = [
    ['expired login challenges', ['auth_challenges_expiry'],
      'SELECT id FROM auth_challenges WHERE expires_at <= ? ORDER BY expires_at LIMIT 256', [1]],
    ['expired private usernames', ['users_username_reservation'],
      `SELECT id FROM users WHERE username_reserved_until <= ? AND username_published_at IS NULL
       ORDER BY username_reserved_until LIMIT 256`, [1]],
    ['enrollment retention', ['webauthn_enrollments_retention'],
      'SELECT id FROM webauthn_enrollments WHERE created_at < ? ORDER BY created_at LIMIT 256', [1]],
    ['unused invitation retention', ['signup_invites_expiry', 'auth_challenges_invite'],
      `SELECT i.token_hash FROM signup_invites i WHERE i.consumed_by IS NULL AND i.expires_at <= ?
       AND NOT EXISTS (SELECT 1 FROM auth_challenges c WHERE c.invite_hash = i.token_hash)
       ORDER BY i.expires_at LIMIT 256`, [1]],
    ['global sponsorship budget', ['sponsorship_budget'],
      'SELECT COALESCE(SUM(charged_gwei),0) FROM sponsorship_reservations WHERE scope = ? AND day = ?', ['scope', 1]],
    ['user sponsorship budget', ['sponsorship_budget'],
      'SELECT COALESCE(SUM(charged_gwei),0),COUNT(*) FROM sponsorship_reservations WHERE scope = ? AND day = ? AND user_id = ?',
      ['scope', 1, 'usr_00000000-0000-4000-8000-000000000001']],
  ];
  for (const [name, indexes, sql, values] of cases) {
    const plan = db.prepare(`EXPLAIN QUERY PLAN ${sql}`).all(...values).map(row => row.detail).join(' | ');
    for (const index of indexes) assert(plan.includes(index), `${name} does not use ${index}: ${plan}`);
    assert(!plan.includes('TEMP B-TREE'), `${name} requires a temporary sort: ${plan}`);
  }
  assert.equal(db.prepare('PRAGMA integrity_check').get().integrity_check, 'ok');
  assert.equal(db.prepare('PRAGMA foreign_key_check').all().length, 0);
  console.log(`Wallet Core query-plan check passed (${cases.length} admission and retention paths).`);
} finally {
  db.close();
}
