export async function pruneAuthChallenges(
  database: D1Database,
  now = Math.floor(Date.now() / 1000),
) {
  if (!Number.isSafeInteger(now) || now < 1) throw new Error('Invalid retention time');
  await database.batch([
    database
      .prepare(
        `DELETE FROM auth_challenges WHERE id IN
      (SELECT id FROM auth_challenges WHERE expires_at <= ? ORDER BY expires_at LIMIT 256)`,
      )
      .bind(now),
    database
      .prepare(
        `UPDATE users SET username = NULL, username_reserved_until = NULL
      WHERE id IN (SELECT id FROM users WHERE username_reserved_until <= ?
        AND username_published_at IS NULL ORDER BY username_reserved_until LIMIT 256)`,
      )
      .bind(now),

    database
      .prepare(
        `DELETE FROM webauthn_enrollments WHERE id IN
      (SELECT id FROM webauthn_enrollments WHERE created_at < ? ORDER BY created_at LIMIT 256)`,
      )
      .bind(now - 86400),

    database
      .prepare(
        `DELETE FROM signup_invites WHERE code IN
      (SELECT i.code FROM signup_invites i WHERE i.consumed_by IS NULL AND i.expires_at <= ?
        AND NOT EXISTS (SELECT 1 FROM auth_challenges c WHERE c.invite_code = i.code)
        ORDER BY i.expires_at LIMIT 256)`,
      )
      .bind(now - 86400),
  ]);
}
