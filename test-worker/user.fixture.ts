import { initializationFixture } from '@gatopago/test-fixtures/v3-initialization';
import type { Principal } from '../src/auth/principal';
import { WalletRepository } from '../src/accounts/repository';

/** Tests seed an admitted user directly; public session reads never create users. */
export async function seedUser(database: D1Database, identity: Principal) {
  await database
    .prepare(
      `INSERT INTO users(id,environment,created_at)
    VALUES (?,?,?) ON CONFLICT(id) DO NOTHING`,
    )
    .bind(identity.userId, identity.environment, Math.floor(Date.now() / 1000))
    .run();
  const existing = await database
    .prepare('SELECT id FROM webauthn_credentials WHERE id = ?')
    .bind(identity.credentialRef)
    .first();
  if (!existing) {
    const f = initializationFixture();
    await database
      .prepare(
        `INSERT INTO webauthn_credentials
      (id,user_id,rp_id,origin,credential_id,public_key,transports_json,aaguid,backup_eligible,backed_up,sign_count,response_hash,created_at,login_enabled)
      VALUES (?,?,?,?,?,?,'["internal"]','00000000-0000-0000-0000-000000000000',0,0,0,?,?,1)`,
      )
      .bind(
        identity.credentialRef,
        identity.userId,
        f.input.scope.rpId,
        f.input.scope.origin,
        Buffer.from(identity.credentialRef).toString('base64url'),
        f.input.publicKey,
        `0x${'01'.repeat(32)}`,
        Math.floor(Date.now() / 1000),
      )
      .run();
  }
  return new WalletRepository(database, identity).getSession();
}
