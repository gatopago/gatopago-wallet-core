import type { Principal } from './principal';
import { sha256, stringToHex, type Hex } from 'viem';
import { requireHash } from '@gatopago/shared/v3/deployment';
import { parseResourceId } from '@gatopago/shared/v3/primitives';
import { Role, SignerKind } from '@gatopago/shared/v3/security-policy';
import { assertWebAuthnKey, assertWebAuthnScope, type WebAuthnScope } from '@gatopago/shared/v3/webauthn';
import { inspectWalletAccount } from '../accounts/inspection';
import { parseWalletAccount } from '../accounts/repository';
import type { ReceivingProfiles } from '../accounts/profile';
import { IdentityError } from './identity';
import { abortable } from '../deadline';

const now = () => Math.floor(Date.now() / 1000);
const unavailable = (): never => { throw new IdentityError('IDENTITY_UNAVAILABLE'); };
const denied = (): never => { throw new IdentityError('UNAUTHENTICATED'); };
const ttl = 30;

// Use the same ordered source in the initial read and atomic write. This prevents
// a new/reassigned/reconfigured account from racing a completed RPC inspection.
const accountSet = `SELECT json_group_array(json_object(
  'id',id,'wallet_id',wallet_id,'network_id',network_id,'address',address,
  'deployment_state',deployment_state,'deployment_manifest_sha256',deployment_manifest_sha256,
  'account_id',account_id,'initial_security_commitment',initial_security_commitment,
  'user_salt_commitment',user_salt_commitment,'wallet_status',wallet_status)) FROM (
  SELECT a.*,w.account_id,w.initial_security_commitment,w.user_salt_commitment,w.status AS wallet_status
  FROM wallet_accounts a JOIN wallets w ON w.id = a.wallet_id AND a.address = w.canonical_address
  WHERE w.user_id = ? ORDER BY a.id LIMIT 129)`;

type Checkpoint = { account: string; height: string; hash: string; version: string; policy_hash: string; manifest_hash: string };
type Snapshot = { revision: string; account_set_hash: string; rp_id: string; origin: string;
  observed_at: number; expires_at: number; checkpoints: Checkpoint[]; keys: Hex[] };

function snapshot(json: string | null, scope: WebAuthnScope): Snapshot | null {
  if (json === null) return null;
  try {
    if (json.length > 65536) return unavailable();
    const value: Snapshot = JSON.parse(json);
    if (!value || value.rp_id !== scope.rpId || value.origin !== scope.origin
      || typeof value.revision !== 'string' || !/^[0-9a-f-]{36}$/.test(value.revision)
      || !Number.isSafeInteger(value.observed_at) || value.observed_at <= 0
      || !Number.isSafeInteger(value.expires_at) || value.expires_at <= value.observed_at
      || value.expires_at > value.observed_at + ttl || value.observed_at > now()
      || !Array.isArray(value.checkpoints) || !value.checkpoints.length || value.checkpoints.length > 128
      || !Array.isArray(value.keys) || value.keys.length > 128 || new Set(value.keys).size !== value.keys.length) return unavailable();
    requireHash(value.account_set_hash);
    const accounts = new Set<string>();
    for (const checkpoint of value.checkpoints) {
      parseResourceId('walletAccount', checkpoint.account); requireHash(checkpoint.hash);
      requireHash(checkpoint.policy_hash); requireHash(checkpoint.manifest_hash);
      if (!/^(0|[1-9][0-9]{0,77})$/.test(checkpoint.height) || !/^[1-9][0-9]{0,19}$/.test(checkpoint.version)
        || accounts.has(checkpoint.account)) return unavailable();
      accounts.add(checkpoint.account);
    }
    value.keys.forEach(key => assertWebAuthnKey(scope, key));
    return value;
  } catch { return unavailable(); }
}

/** Refresh application access, never financial authority. Caller must first prove
 * possession (WebAuthn login) or verify a signed session. No public lookup uses it.
 * Only a full, fresh inspection may disable absent keys. RPC failure changes nothing.
 */
export async function refreshUserAccess(database: D1Database, userId: string, environment: Principal['environment'],
  scope: WebAuthnScope, resolve: ReceivingProfiles, signal: AbortSignal): Promise<{ expiresAt: number }> {
  parseResourceId('user', userId); assertWebAuthnScope(scope); signal.throwIfAborted();
  const db = database.withSession('first-primary');
  const [userResult, accountsResult, credentialResult] = await db.batch<Record<string, unknown>>([
    db.prepare(`SELECT access_snapshot_json FROM users WHERE id = ?
      AND environment = ? AND disabled_at IS NULL`).bind(userId, environment),
    db.prepare(`SELECT (${accountSet}) AS accounts_json`).bind(userId),
    db.prepare(`SELECT public_key,login_enabled FROM webauthn_credentials WHERE user_id = ? AND rp_id = ? AND origin = ?
      AND revoked_at IS NULL ORDER BY id LIMIT 129`).bind(userId, scope.rpId, scope.origin),
  ]);
  if (![userResult, accountsResult, credentialResult].every(r => r.success)) return unavailable();
  if (userResult.results.length !== 1) return denied();
  const previousJson = userResult.results[0].access_snapshot_json;
  if (previousJson !== null && typeof previousJson !== 'string') return unavailable();
  const previous = snapshot(previousJson, scope);
  const accountsJson = accountsResult.results[0]?.accounts_json;
  if (typeof accountsJson !== 'string' || accountsJson.length > 131072) return unavailable();
  const records: Record<string, unknown>[] = JSON.parse(accountsJson);
  if (!Array.isArray(records) || records.length > 128 || credentialResult.results.length > 128) return unavailable();
  // A user who has had onchain access cannot return to onboarding by deleting rows.
  if (!records.length) return previous ? unavailable() : { expiresAt: now() + ttl };
  const hash = sha256(stringToHex(accountsJson)), registered = new Set(credentialResult.results.map(r => r.public_key));
  let current = previous;
  if (current && current.account_set_hash === hash && current.expires_at > now()
    && credentialResult.results.every(r => r.login_enabled === Number(current!.keys.some(key => key === r.public_key)))) {
    signal.throwIfAborted();
    return { expiresAt: current.expires_at }; // A cached read performs no writes and never extends expiry.
  }
  if (!current || current.account_set_hash !== hash || current.expires_at <= now()) {
    const keys = new Set<Hex>(), checkpoints: Checkpoint[] = [];
    const started = now(); let expires = started + ttl;
    for (const row of records) {
      // Archiving a wallet hides it in the app; it does not remove its onchain ADMIN.
      const account = parseWalletAccount(row, true);
      const profiles = structuredClone(await abortable(resolve(account, signal), signal));
      const evidence = await abortable(inspectWalletAccount(account, profiles, signal), signal);
      if (evidence.status !== 'recognized' || evidence.security.phase !== 'active_policy') return unavailable();
      const pin = profiles.find(p => p.digest === account.deployment_manifest_sha256)!;
      const checkpoint = { account: account.id, height: evidence.checkpoint.block_number,
        hash: evidence.checkpoint.block_hash, version: evidence.security_version,
        policy_hash: evidence.security.policy_hash, manifest_hash: evidence.security.manifest_hash };
      const prior = previous?.checkpoints.find(c => c.account === account.id);
      if (prior && (BigInt(checkpoint.height) < BigInt(prior.height) || BigInt(checkpoint.version) < BigInt(prior.version)
        || (checkpoint.version === prior.version && (checkpoint.policy_hash !== prior.policy_hash || checkpoint.manifest_hash !== prior.manifest_hash))
        || (checkpoint.height === prior.height && (checkpoint.hash !== prior.hash || checkpoint.version !== prior.version)))) return unavailable();
      checkpoints.push(checkpoint); expires = Math.min(expires, evidence.security_expires_at);
      for (const signer of evidence.security.policy.signers) {
        if (signer.kind !== SignerKind.WEBAUTHN || (signer.roles & Role.ADMIN) === 0
          || signer.verifier !== pin.verifier.address || signer.verifierCodeHash !== pin.verifier.runtime_code_hash || !registered.has(signer.key)) continue;
        assertWebAuthnKey(scope, signer.key); keys.add(signer.key);
      }
    }
    signal.throwIfAborted(); if (now() >= expires) return unavailable();
    current = { revision: crypto.randomUUID(), account_set_hash: hash, rp_id: scope.rpId, origin: scope.origin,
      observed_at: started, expires_at: expires, checkpoints, keys: [...keys].sort() };
  }
  const json = JSON.stringify(current); if (json.length > 65536) return unavailable();
  const keyJson = JSON.stringify(current.keys), time = now();
  signal.throwIfAborted(); if (time >= current.expires_at) return unavailable();
  const writes = await db.batch([
    db.prepare(`UPDATE users SET access_snapshot_json = ? WHERE id = ? AND environment = ? AND disabled_at IS NULL
      AND access_snapshot_json IS ? AND (${accountSet}) = ? AND unixepoch() < ?`)
      .bind(json, userId, environment, previousJson, userId, accountsJson, current.expires_at),
    db.prepare(`UPDATE webauthn_credentials SET
      access_version = access_version + CASE WHEN login_enabled = 1 THEN 1 ELSE 0 END,
      login_enabled = CASE WHEN public_key IN (SELECT value FROM json_each(?)) THEN 1 ELSE 0 END
      WHERE user_id = ? AND rp_id = ? AND origin = ? AND revoked_at IS NULL
      AND login_enabled != CASE WHEN public_key IN (SELECT value FROM json_each(?)) THEN 1 ELSE 0 END
      AND EXISTS (SELECT 1 FROM users WHERE id = ? AND environment = ? AND disabled_at IS NULL
        AND access_snapshot_json = ? AND (${accountSet}) = ? AND unixepoch() < ?)`)
      .bind(keyJson, userId, scope.rpId, scope.origin, keyJson, userId, environment, json, userId, accountsJson, current.expires_at),
  ]);
  if (writes.some(write => !write.success) || writes[0].meta.changes !== 1) return unavailable();
  return { expiresAt: current.expires_at };
}
