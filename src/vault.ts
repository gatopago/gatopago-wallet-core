import type { Config } from './config';
import { HttpError, json, readJson } from './http';
import { signedInMember } from './profile';

/**
 * The member's private vault: Wallet Core keeps only what the app encrypted and can read none of
 * it. A Mera secret vault per passkey wraps the vault's data key; each record (`space`) is
 * encrypted on the device with a key derived from it.
 */

/** Credential ids and ciphertext are canonical unpadded base64url. */
const BASE64URL = /^[A-Za-z0-9_-]+$/;
const SPACE = /^[a-z][a-z0-9-]{0,31}$/;
/** Passkeys that can open one vault, and records it holds. */
const MAX_KEYS = 10;
const MAX_RECORDS = 16;
/** A Mera secret vault is a few hundred bytes; a record up to the request limit. */
const MAX_VAULT_LENGTH = 2_048;
const MAX_CIPHERTEXT_LENGTH = 24_576;

/** `GET /app/v1/vault`: the member's wrapped keys and encrypted records. */
export async function readVault(request: Request, env: Env, config: Config) {
  const member = await signedInMember(request, env, config);
  const [keys, records] = await env.WALLET_DB.batch([
    env.WALLET_DB.prepare(
      'SELECT credential_id, vault FROM vault_keys WHERE member_id = ? ORDER BY created_at',
    ).bind(member.id),
    env.WALLET_DB.prepare(
      'SELECT space, nonce, ciphertext, version FROM vault_records WHERE member_id = ?',
    ).bind(member.id),
  ]);
  return json({
    keys: (keys.results as { credential_id: string; vault: string }[]).map((key) => ({
      credential_id: key.credential_id,
      vault: JSON.parse(key.vault) as unknown,
    })),
    records: records.results,
  });
}

/**
 * `PUT /app/v1/vault/keys`: `{credential_id, vault, create?}`, the Mera secret vault with which
 * that passkey opens the data key. Added once: a key is never replaced, so a session cannot swap
 * it. `create` starts the vault, only while it has no key: two devices starting it at once must
 * not end up with two data keys.
 */
export async function addVaultKey(request: Request, env: Env, config: Config) {
  const member = await signedInMember(request, env, config);
  const {
    credential_id: credential,
    vault,
    create,
  } = await readJson<{ credential_id?: unknown; vault?: unknown; create?: unknown }>(request);
  const text = JSON.stringify(vault ?? null);
  const wrapped = vault as { version?: unknown; credential?: { credentialId?: unknown } } | null;
  if (
    typeof credential !== 'string' ||
    !BASE64URL.test(credential) ||
    credential.length > 512 ||
    wrapped?.version !== 1 ||
    wrapped.credential?.credentialId !== credential ||
    text.length > MAX_VAULT_LENGTH
  )
    throw new HttpError(400, 'INVALID_VAULT_KEY');
  const result = await env.WALLET_DB.prepare(
    `INSERT OR IGNORE INTO vault_keys (member_id, credential_id, vault, created_at)
     SELECT ?1, ?2, ?3, unixepoch()
     WHERE (SELECT count(*) FROM vault_keys WHERE member_id = ?1) < ?4`,
  )
    .bind(member.id, credential, text, create === true ? 1 : MAX_KEYS)
    .run();
  if (result.meta.changes === 0)
    throw new HttpError(409, create === true ? 'VAULT_EXISTS' : 'VAULT_KEY_EXISTS');
  return json({}, 201);
}

/**
 * `PUT /app/v1/vault/records`: `{space, nonce, ciphertext, version}`, where `version` is the one
 * the app read (0 for a new record). Another device that saved first makes it a conflict, so a
 * write never overwrites what it has not seen.
 */
export async function saveVaultRecord(request: Request, env: Env, config: Config) {
  const member = await signedInMember(request, env, config);
  const { space, nonce, ciphertext, version } = await readJson<{
    space?: unknown;
    nonce?: unknown;
    ciphertext?: unknown;
    version?: unknown;
  }>(request);
  if (
    typeof space !== 'string' ||
    !SPACE.test(space) ||
    typeof nonce !== 'string' ||
    nonce.length !== 16 ||
    !BASE64URL.test(nonce) ||
    typeof ciphertext !== 'string' ||
    ciphertext.length > MAX_CIPHERTEXT_LENGTH ||
    !BASE64URL.test(ciphertext) ||
    !Number.isSafeInteger(version) ||
    (version as number) < 0
  )
    throw new HttpError(400, 'INVALID_VAULT_RECORD');
  const statement =
    version === 0
      ? env.WALLET_DB.prepare(
          `INSERT OR IGNORE INTO vault_records
             (member_id, space, nonce, ciphertext, version, updated_at)
           SELECT ?1, ?2, ?3, ?4, 1, unixepoch()
           WHERE (SELECT count(*) FROM vault_records WHERE member_id = ?1) < ?5`,
        ).bind(member.id, space, nonce, ciphertext, MAX_RECORDS)
      : env.WALLET_DB.prepare(
          `UPDATE vault_records SET nonce = ?3, ciphertext = ?4, version = version + 1,
             updated_at = unixepoch()
           WHERE member_id = ?1 AND space = ?2 AND version = ?5`,
        ).bind(member.id, space, nonce, ciphertext, version);
  if ((await statement.run()).meta.changes === 0) throw new HttpError(409, 'VAULT_CHANGED');
  return json({ version: (version as number) + 1 });
}
