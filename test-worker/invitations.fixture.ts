import { invitationCode } from '../src/auth/invitations';

export async function issueInvitation(
  database: D1Database,
  issuer: string,
  expiresAt: number,
  token: string = crypto.randomUUID(),
) {
  await database
    .prepare(`INSERT INTO signup_invites(code,issued_by,created_at,expires_at) VALUES (?,?,?,?)`)
    .bind(invitationCode(token), issuer, Math.floor(Date.now() / 1000), expiresAt)
    .run();
  return { token, expiresAt };
}
