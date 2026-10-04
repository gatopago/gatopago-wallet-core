import { readFileSync } from 'node:fs';
import { DatabaseSync } from 'node:sqlite';
import { describe, expect, it } from 'vitest';

const baseline = readFileSync(new URL('../migrations/0001_initial.sql', import.meta.url), 'utf8');
const forward = readFileSync(
  new URL('../migrations/0002_production_namespace.sql', import.meta.url),
  'utf8',
);
const userId = 'usr_00000000-0000-4000-8000-000000000001';
const previousSchema = baseline.replace(
  "CHECK (environment = 'production')",
  'CHECK (length(environment) > 0)',
);

describe('single production identity namespace (local SQLite only)', () => {
  it.each([baseline, previousSchema])(
    'enforces inserts and updates without relabeling existing users',
    (schema) => {
      const db = new DatabaseSync(':memory:');
      try {
        db.exec(schema);
        db.prepare('INSERT INTO users(id,environment,created_at) VALUES (?,?,1)').run(
          userId,
          'production',
        );
        db.exec(forward);
        expect(() =>
          db.prepare('UPDATE users SET environment = ? WHERE id = ?').run('unsupported', userId),
        ).toThrow();
        expect(() =>
          db
            .prepare('INSERT INTO users(id,environment,created_at) VALUES (?,?,1)')
            .run('usr_00000000-0000-4000-8000-000000000002', 'unsupported'),
        ).toThrow();
        expect(db.prepare('SELECT id,environment FROM users').all()).toEqual([
          { id: userId, environment: 'production' },
        ]);
        expect(db.prepare('PRAGMA foreign_key_check').all()).toEqual([]);
      } finally {
        db.close();
      }
    },
  );
  it('stops rather than converting incompatible identities from an existing database', () => {
    const db = new DatabaseSync(':memory:');
    try {
      db.exec(previousSchema);
      db.prepare('INSERT INTO users(id,environment,created_at) VALUES (?,?,1)').run(
        userId,
        'unsupported',
      );
      db.exec('BEGIN');
      expect(() => db.exec(forward)).toThrow();
      db.exec('ROLLBACK');
      expect(
        db.prepare('SELECT environment FROM users WHERE id = ?').get(userId)?.environment,
      ).toBe('unsupported');
    } finally {
      db.close();
    }
  });
});
