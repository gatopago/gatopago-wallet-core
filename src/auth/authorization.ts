import type { Principal } from './principal';

/** Predicate for the authenticated user alias `u`, including credential revocation.
 * Use inside the write transaction as well as before slow RPC/cryptographic work. */
export const AUTHORIZED_USER = `u.environment = ? AND u.id = ?
  AND u.disabled_at IS NULL AND u.auth_not_before <= ? AND ? > unixepoch()
  AND EXISTS (SELECT 1 FROM webauthn_credentials login_key WHERE login_key.id = ?
    AND login_key.user_id = u.id AND login_key.login_enabled = 1
    AND login_key.revoked_at IS NULL AND login_key.access_version = ?)`;

export function authorizationValues(identity: Principal) {
  return [identity.environment, identity.userId, identity.authTime, identity.expiresAt, identity.credentialRef, identity.accessVersion] as const;
}
