import { base64url } from '../src/enrollment/verification';
import { invitationHash } from '../src/auth/invitations';

/** Synthetic admission; real operator issuance lives in scripts/wallet-invitations.mjs. */
export async function issueInvitation(database: D1Database, issuer: string, expiresAt: number) {
  const token = base64url(crypto.getRandomValues(new Uint8Array(32)));
  await database.prepare(`INSERT INTO signup_invites(token_hash,issued_by,created_at,expires_at) VALUES (?,?,?,?)`)
    .bind(invitationHash(token), issuer, Math.floor(Date.now() / 1000), expiresAt).run();
  return { token, expiresAt };
}
