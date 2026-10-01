import type { Principal } from './principal';
import { bytesToHex, hexToBytes, sha256, stringToHex, type Hex } from 'viem';
import { createResourceId, parseResourceId, type ResourceId } from '@gatopago/shared/v3/primitives';
import { assertWebAuthnScope, type WebAuthnScope } from '@gatopago/shared/v3/webauthn';
import { base64url, verifyEnrollment } from '../enrollment/verification';
import { invitationHash } from './invitations';
import { registrationProfile, RegistrationError } from './profile';

type Challenge = {
  id: ResourceId<'operation'>; proposed_user_id: ResourceId<'user'>; invite_hash: Hex;
  challenge: Hex; proof_challenge: Hex; display_name: string; username: string;
  created_at: number; expires_at: number; consumed_at: number | null;
};
const nowSeconds = () => Math.floor(Date.now() / 1000);
const unavailable = (): never => { throw new RegistrationError('CHALLENGE_UNAVAILABLE'); };

export class RegistrationRepository {
  private readonly db: D1DatabaseSession;
  constructor(database: D1Database, private readonly environment: Principal['environment'], private readonly scope: WebAuthnScope) {
    assertWebAuthnScope(scope);
    this.db = database.withSession('first-primary');
  }

  async prepare(input: { invite: unknown; name: unknown; username: unknown }) {
    const { displayName, username } = registrationProfile(input.name, input.username);
    const hash = invitationHash(input.invite), now = nowSeconds();
    const id = createResourceId('operation'), userId = createResourceId('user');
    const random = () => bytesToHex(crypto.getRandomValues(new Uint8Array(32)));
    const result = await this.db.prepare(`INSERT INTO auth_challenges
      (id,purpose,challenge,proof_challenge,rp_id,origin,proposed_user_id,invite_hash,display_name,username,created_at,expires_at)
      SELECT ?,'register',?,?,?,?,?,?,?,?,?,? FROM signup_invites
      WHERE token_hash = ? AND revoked_at IS NULL AND consumed_by IS NULL AND expires_at > ? AND expires_at > unixepoch()`)
      .bind(id, random(), random(), this.scope.rpId, this.scope.origin, userId, hash, displayName, username, now, now + 300, hash, now).run();
    if (result.meta.changes !== 1) throw new RegistrationError('INVITE_UNAVAILABLE');
    const attempt = await this.read(id);
    return { request_id: id, expires_at: attempt.expires_at, scope: this.scope, proof_challenge: attempt.proof_challenge,
      options: { challenge: base64url(hexToBytes(attempt.challenge)), rp: { id: this.scope.rpId, name: 'GatoPago' },
        user: { id: base64url(hexToBytes(sha256(stringToHex(`GatoPago V3 WebAuthn user\n${this.scope.rpId}\n${userId}`)))),
          name: username, displayName },
        pubKeyCredParams: [{ type: 'public-key' as const, alg: -7 }], timeout: 60000, attestation: 'none' as const,
        authenticatorSelection: { residentKey: 'required' as const, userVerification: 'required' as const },
        excludeCredentials: [] } };
  }

  private async read(id: ResourceId<'operation'>): Promise<Challenge> {
    const attempt = await this.db.prepare(`SELECT * FROM auth_challenges
      WHERE id = ? AND purpose = 'register' AND rp_id = ? AND origin = ?`)
      .bind(id, this.scope.rpId, this.scope.origin).first<Challenge>();
    if (!attempt || attempt.consumed_at !== null || attempt.expires_at <= nowSeconds()) return unavailable();
    return attempt;
  }

  async complete(requestId: string, submission: unknown) {
    const id = parseResourceId('operation', requestId), attempt = await this.read(id);
    const proof = await verifyEnrollment(submission, { scope: this.scope, challenge: attempt.challenge,
      proofChallenge: attempt.proof_challenge });
    const now = nowSeconds();
    if (now >= attempt.expires_at) return unavailable();
    const userId = attempt.proposed_user_id;
    // The first insert is the admission gate. All following writes depend on that
    // exact user/credential pair, inside the same D1 transaction. Constraint failures
    // roll back the username, credential and invitation together.
    try {
      const result = await this.db.batch([
        this.db.prepare(`UPDATE users SET username = NULL, username_reserved_until = NULL
          WHERE username = ? AND username_published_at IS NULL AND username_reserved_until <= ?`)
          .bind(attempt.username, now),
        this.db.prepare(`INSERT INTO users
          (id,environment,display_name,username,username_reserved_until,created_at)
          SELECT c.proposed_user_id,?,c.display_name,c.username,?,? FROM auth_challenges c
          JOIN signup_invites i ON i.token_hash = c.invite_hash
          WHERE c.id = ? AND c.consumed_at IS NULL AND c.expires_at > ?
          AND c.expires_at > unixepoch() AND i.expires_at > unixepoch()
          AND i.revoked_at IS NULL AND i.consumed_by IS NULL AND i.expires_at > ?`)
          .bind(this.environment, now + 86400, now, id, now, now),
        this.db.prepare(`INSERT INTO webauthn_credentials
          (id,user_id,rp_id,origin,credential_id,public_key,transports_json,aaguid,backup_eligible,backed_up,sign_count,response_hash,created_at,login_enabled)
          SELECT ?,u.id,?,?,?,?,?,?,?,?,?,?,?,1 FROM users u
          JOIN auth_challenges c ON c.proposed_user_id = u.id WHERE u.id = ? AND c.id = ? AND c.consumed_at IS NULL`)
          .bind(id, this.scope.rpId, this.scope.origin, proof.credentialId, proof.publicKey, JSON.stringify(proof.transports),
            proof.aaguid, Number(proof.backupEligible), Number(proof.backedUp), proof.signCount, proof.responseHash, now, userId, id),
        this.db.prepare(`UPDATE auth_challenges SET consumed_at = ? WHERE id = ? AND consumed_at IS NULL
          AND EXISTS (SELECT 1 FROM webauthn_credentials WHERE id = ? AND user_id = ? AND response_hash = ?)`)
          .bind(now, id, id, userId, proof.responseHash),
        this.db.prepare(`UPDATE signup_invites SET consumed_by = ?, consumed_at = ? WHERE token_hash = ?
          AND consumed_by IS NULL AND revoked_at IS NULL AND expires_at > ?
          AND EXISTS (SELECT 1 FROM webauthn_credentials WHERE id = ? AND user_id = ? AND response_hash = ?)`)
          .bind(userId, now, attempt.invite_hash, now, id, userId, proof.responseHash),
      ]);
      if (result.slice(1).some((write) => write.meta.changes !== 1)) return unavailable();
      return { userId, credentialRef: id, accessVersion: 1 };
    } catch (error) {
      if (error instanceof RegistrationError) throw error;
      const conflict = await this.db.prepare('SELECT id FROM users WHERE username = ?').bind(attempt.username).first<{ id: string }>();
      if (conflict && conflict.id !== userId) throw new RegistrationError('USERNAME_UNAVAILABLE');
      throw new RegistrationError('CHALLENGE_UNAVAILABLE');
    }
  }
}
