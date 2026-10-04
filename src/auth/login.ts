import { verifyAuthenticationResponse } from '@simplewebauthn/server';
import { isoCBOR } from '@simplewebauthn/server/helpers';
import { bytesToHex, hexToBytes, sha256, stringToHex, type Hex } from 'viem';
import { createResourceId, parseResourceId } from '@gatopago/shared/v3/primitives';
import {
  assertWebAuthnKey,
  assertWebAuthnScope,
  type WebAuthnScope,
} from '@gatopago/shared/v3/webauthn';
import { base64url, webAuthnBytes } from '../enrollment/verification';
import { IdentityError } from './identity';

type Credential = {
  id: string;
  user_id: string;
  public_key: Hex;
  credential_id: string;
  sign_count: number;
  backup_eligible: number;
  access_version: number;
};
const nowSeconds = () => Math.floor(Date.now() / 1000);
const denied = (): never => {
  throw new IdentityError('UNAUTHENTICATED');
};

export class LoginRepository {
  private readonly db: D1DatabaseSession;
  constructor(
    database: D1Database,
    private readonly scope: WebAuthnScope,
    private readonly refresh?: (userId: string) => Promise<{ expiresAt: number }>,
  ) {
    assertWebAuthnScope(scope);
    this.db = database.withSession('first-primary');
  }

  async prepare() {
    const id = createResourceId('operation'),
      now = nowSeconds();
    const challenge = bytesToHex(crypto.getRandomValues(new Uint8Array(32)));
    await this.db
      .prepare(
        `INSERT INTO auth_challenges(id,purpose,challenge,rp_id,origin,created_at,expires_at)
      VALUES (?,'login',?,?,?,?,?)`,
      )
      .bind(id, challenge, this.scope.rpId, this.scope.origin, now, now + 300)
      .run();
    return {
      request_id: id,
      expires_at: now + 300,
      scope: this.scope,
      options: {
        challenge: base64url(hexToBytes(challenge)),
        rpId: this.scope.rpId,
        userVerification: 'required' as const,
        timeout: 60000,
      },
    };
  }

  async complete(requestId: string, submission: unknown) {
    const id = parseResourceId('operation', requestId);
    const fields = [
      'credential_id',
      'authenticator_data',
      'client_data',
      'signature',
      'user_handle',
    ];
    if (
      !submission ||
      typeof submission !== 'object' ||
      Array.isArray(submission) ||
      Object.keys(submission).length !== fields.length ||
      !fields.every((field) => Object.hasOwn(submission, field))
    )
      return denied();
    const body = submission as Record<string, unknown>;
    const credentialId = base64url(webAuthnBytes(body.credential_id, 1024));
    const auth = webAuthnBytes(body.authenticator_data, 1024),
      client = webAuthnBytes(body.client_data, 2048);
    const signature = webAuthnBytes(body.signature, 72),
      handle = base64url(webAuthnBytes(body.user_handle, 32));
    const attempt = await this.db
      .prepare(
        `SELECT challenge,expires_at FROM auth_challenges WHERE id = ?
      AND purpose = 'login' AND consumed_at IS NULL AND rp_id = ? AND origin = ?`,
      )
      .bind(id, this.scope.rpId, this.scope.origin)
      .first<{ challenge: Hex; expires_at: number }>();
    if (!attempt || attempt.expires_at <= nowSeconds()) return denied();
    const key = await this.db
      .prepare(
        `SELECT c.* FROM webauthn_credentials c JOIN users u ON u.id = c.user_id
      WHERE c.credential_id = ? AND c.rp_id = ? AND c.origin = ?
      AND c.revoked_at IS NULL AND u.disabled_at IS NULL`,
      )
      .bind(credentialId, this.scope.rpId, this.scope.origin)
      .first<Credential>();
    if (!key) return denied();
    const expectedHandle = base64url(
      hexToBytes(
        sha256(stringToHex(`GatoPago V3 WebAuthn user\n${this.scope.rpId}\n${key.user_id}`)),
      ),
    );
    if (handle !== expectedHandle) return denied();
    let counter: number, backedUp: boolean;
    try {
      const data: unknown = JSON.parse(new TextDecoder('utf-8', { fatal: true }).decode(client));
      if (
        !data ||
        typeof data !== 'object' ||
        !('crossOrigin' in data) ||
        data.crossOrigin !== false ||
        'topOrigin' in data
      )
        return denied();
      assertWebAuthnKey(this.scope, key.public_key);
      const raw = hexToBytes(key.public_key);
      const cose = isoCBOR.encode(
        new Map<number, number | Uint8Array>([
          [1, 2],
          [3, -7],
          [-1, 1],
          [-2, raw.slice(64, 96)],
          [-3, raw.slice(96, 128)],
        ]),
      );
      const result = await verifyAuthenticationResponse({
        response: {
          id: credentialId,
          rawId: credentialId,
          type: 'public-key',
          clientExtensionResults: {},
          response: {
            authenticatorData: base64url(auth),
            clientDataJSON: base64url(client),
            signature: base64url(signature),
            userHandle: handle,
          },
        },
        expectedChallenge: base64url(hexToBytes(attempt.challenge)),
        expectedOrigin: this.scope.origin,
        expectedRPID: this.scope.rpId,
        requireUserVerification: true,
        credential: { id: credentialId, publicKey: cose, counter: key.sign_count },
      });
      if (
        !result.verified ||
        Number(result.authenticationInfo.credentialDeviceType === 'multiDevice') !==
          key.backup_eligible
      )
        return denied();
      counter = result.authenticationInfo.newCounter;
      backedUp = result.authenticationInfo.credentialBackedUp;
    } catch {
      return denied();
    }

    if (
      !this.refresh &&
      (await this.db
        .prepare(
          `SELECT 1 FROM users u WHERE u.id = ? AND
      (u.access_snapshot_json IS NOT NULL OR EXISTS (SELECT 1 FROM wallet_accounts a JOIN wallets w ON w.id = a.wallet_id
      WHERE w.user_id = u.id))`,
        )
        .bind(key.user_id)
        .first())
    )
      throw new IdentityError('IDENTITY_UNAVAILABLE');
    const access = this.refresh
      ? await this.refresh(key.user_id)
      : { expiresAt: attempt.expires_at };
    const now = nowSeconds();
    const writes = await this.db.batch([
      this.db
        .prepare(
          `UPDATE auth_challenges SET consumed_at = ? WHERE id = ? AND purpose = 'login'
        AND consumed_at IS NULL AND expires_at > ? AND unixepoch() < ? AND EXISTS (
          SELECT 1 FROM webauthn_credentials c JOIN users u ON u.id = c.user_id
          WHERE c.id = ? AND c.login_enabled = 1 AND c.revoked_at IS NULL AND c.access_version = ?
          AND c.sign_count = ? AND u.disabled_at IS NULL AND u.auth_not_before <= ?)`,
        )
        .bind(now, id, now, access.expiresAt, key.id, key.access_version, key.sign_count, now),
      this.db
        .prepare(
          `UPDATE webauthn_credentials SET sign_count = ?, backed_up = ?
        WHERE id = ? AND sign_count = ? AND access_version = ? AND revoked_at IS NULL AND login_enabled = 1
        AND EXISTS (SELECT 1 FROM auth_challenges WHERE id = ? AND consumed_at = ?)`,
        )
        .bind(counter, Number(backedUp), key.id, key.sign_count, key.access_version, id, now),
    ]);
    if (writes.some((write) => write.meta.changes !== 1)) return denied();
    return {
      userId: parseResourceId('user', key.user_id),
      credentialRef: parseResourceId('operation', key.id),
      accessVersion: key.access_version,
    };
  }
}
