import type { Config } from './config';
import { HttpError, json, readJson } from './http';
import { memberByUsername } from './members';
import { signedInMember, USERNAME } from './profile';

/** How long a member's invitation can be used. */
const INVITE_SECONDS = 7 * 86_400;
/** Unambiguous characters for invitation codes (no 0/O, 1/I/L). */
const CODE_ALPHABET = 'ABCDEFGHJKMNPQRSTUVWXYZ23456789';

/** `GET /app/v1/contacts`: the member's saved contacts, newest first. */
export async function readContacts(request: Request, env: Env, config: Config) {
  const member = await signedInMember(request, env, config);
  const { results } = await env.WALLET_DB.prepare(
    `SELECT members.username, members.display_name, members.address FROM contacts
     JOIN members ON members.id = contacts.contact_id
     WHERE contacts.member_id = ? AND members.username IS NOT NULL
     ORDER BY contacts.created_at DESC`,
  )
    .bind(member.id)
    .all();
  return json({ contacts: results });
}

/** `POST /app/v1/contacts`: `{username}` of a member to save. */
export async function addContact(request: Request, env: Env, config: Config) {
  const member = await signedInMember(request, env, config);
  const { username } = await readJson<{ username?: unknown }>(request);
  const contact =
    typeof username === 'string' && USERNAME.test(username)
      ? await memberByUsername(env.WALLET_DB, username)
      : null;
  if (!contact) throw new HttpError(404, 'RECIPIENT_NOT_FOUND');
  if (contact.id === member.id) throw new HttpError(400, 'SELF_CONTACT');
  await env.WALLET_DB.prepare(
    'INSERT OR IGNORE INTO contacts (member_id, contact_id, created_at) VALUES (?, ?, unixepoch())',
  )
    .bind(member.id, contact.id)
    .run();
  return json({
    contact: {
      username: contact.username,
      display_name: contact.displayName,
      address: contact.address,
    },
  });
}

/** `DELETE /app/v1/contacts/:username`. */
export async function removeContact(request: Request, env: Env, config: Config, username: string) {
  const member = await signedInMember(request, env, config);
  await env.WALLET_DB.prepare(
    `DELETE FROM contacts WHERE member_id = ?
     AND contact_id = (SELECT id FROM members WHERE username = ?)`,
  )
    .bind(member.id, username)
    .run();
  return json({});
}

/**
 * `GET /app/v1/invites`: how many people joined with the member's invitations, and the one they
 * can share now, if any.
 */
export async function readInvites(request: Request, env: Env, config: Config) {
  const member = await signedInMember(request, env, config);
  return json(await invites(env, member.id));
}

/** `POST /app/v1/invites`: the member's shareable invitation, issuing one when none is active. */
export async function issueInvite(request: Request, env: Env, config: Config) {
  const member = await signedInMember(request, env, config);
  const current = await invites(env, member.id);
  if (current.code) return json(current);
  const random = crypto.getRandomValues(new Uint8Array(8));
  const code = Array.from(random, (byte) => CODE_ALPHABET[byte % CODE_ALPHABET.length]).join('');
  await env.WALLET_DB.prepare(
    `INSERT INTO invites (code, issued_by, created_at, expires_at)
     VALUES (?, ?, unixepoch(), unixepoch() + ?)`,
  )
    .bind(code, member.id, INVITE_SECONDS)
    .run();
  return json({ ...current, code });
}

async function invites(env: Env, memberId: string) {
  const row = await env.WALLET_DB.prepare(
    `SELECT
       (SELECT COUNT(*) FROM invites WHERE issued_by = ?1 AND consumed_by IS NOT NULL) AS invited,
       (SELECT code FROM invites WHERE issued_by = ?1 AND consumed_by IS NULL
          AND revoked_at IS NULL AND expires_at > unixepoch() ORDER BY created_at DESC LIMIT 1) AS code`,
  )
    .bind(memberId)
    .first<{ invited: number; code: string | null }>();
  return { invited: row?.invited ?? 0, code: row?.code ?? null };
}
