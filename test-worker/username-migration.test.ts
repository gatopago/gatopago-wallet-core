import { env } from 'cloudflare:workers';
import { applyD1Migrations } from 'cloudflare:test';
import { beforeAll, expect, it } from 'vitest';
import { RegistrationRepository } from '../src/auth/registration';
import { credential } from './passkey.fixture';
import { issueInvitation } from './invitations.fixture';

const filename = '0005_three_character_usernames.sql';
const scope = { rpId: 'gatopago.com', origin: 'https://gatopago.com' };
beforeAll(async () => {
  await applyD1Migrations(
    env.WALLET_DB,
    env.V3_TEST_MIGRATIONS.filter((migration) => migration.name !== filename),
  );
});

it('rejects unsafe parent rebuilds, then atomically migrates populated D1 and admits a three-character username', async () => {
  const database = env.WALLET_DB;
  const repository = new RegistrationRepository(database, 'production', scope);
  const time = Math.floor(Date.now() / 1000);
  await issueInvitation(database, 'operator', time + 3600, 'old');
  const prepared = await repository.prepare({ invite: 'old', name: 'Daniel', username: 'daniel' });
  const existing = await repository.complete(prepared.request_id, credential(prepared));
  await issueInvitation(database, 'operator', time + 3600, 'new');
  const tables = ['users', 'webauthn_credentials', 'signup_invites', 'auth_challenges'];
  const snapshot = () =>
    Promise.all(
      tables.map((table) => database.prepare(`SELECT * FROM ${table} ORDER BY rowid`).all()),
    );
  const before = (await snapshot()).map((result) => result.results);
  const migration = env.V3_TEST_MIGRATIONS.find((migration) => migration.name === filename);
  expect(migration).toBeDefined();
  await database
    .prepare(
      'CREATE TABLE future_child (user_id TEXT REFERENCES users(id) ON DELETE CASCADE) STRICT',
    )
    .run();
  await database.prepare('INSERT INTO future_child VALUES (?)').bind(existing.userId).run();
  await expect(applyD1Migrations(database, [migration!])).rejects.toThrow(
    'CHECK constraint failed',
  );
  expect(await database.prepare('SELECT user_id FROM future_child').first('user_id')).toBe(
    existing.userId,
  );
  expect((await snapshot()).map((result) => result.results)).toEqual(before);
  expect(
    await database.prepare("SELECT sql FROM sqlite_schema WHERE name='users'").first('sql'),
  ).toContain('BETWEEN 5 AND 30');
  expect(
    await database
      .prepare("SELECT COUNT(*) AS count FROM sqlite_schema WHERE name='_username_migration_guard'")
      .first('count'),
  ).toBe(0);
  await database.prepare('DROP TABLE future_child').run();
  await applyD1Migrations(database, [migration!]);
  expect((await snapshot()).map((result) => result.results)).toEqual(before);
  expect((await database.prepare('PRAGMA foreign_key_check').all()).results).toEqual([]);
  const next = await repository.prepare({ invite: 'new', name: 'Ana', username: 'ana' });
  const admitted = await repository.complete(next.request_id, credential(next));
  expect(
    await database
      .prepare('SELECT username FROM users WHERE id=?')
      .bind(admitted.userId)
      .first('username'),
  ).toBe('ana');
  expect(
    await database
      .prepare('SELECT consumed_by FROM signup_invites WHERE code=?')
      .bind('new')
      .first('consumed_by'),
  ).toBe(admitted.userId);
});
