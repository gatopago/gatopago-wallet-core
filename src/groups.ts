import { MAX_PAYOUTS } from '@gatopago/shared/rules';
import type { Config } from './config';
import { HttpError, json, readJson } from './http';
import { signedInMember } from './profile';

/** How many groups a member keeps. */
const MAX_GROUPS = 20;

interface GroupMember {
  who: string;
  amount: string;
  share: string;
}

const text = (value: unknown, max: number) => typeof value === 'string' && value.length <= max;

/** Each person as the form keeps them: @username or address, a fixed amount and a share (%). */
function groupMembers(value: unknown): GroupMember[] {
  if (!Array.isArray(value) || value.length === 0 || value.length > MAX_PAYOUTS)
    throw new HttpError(400, 'INVALID_GROUP');
  return value.map((member: Partial<Record<keyof GroupMember, unknown>>) => {
    if (!text(member?.who, 80) || !text(member.amount, 24) || !text(member.share, 8))
      throw new HttpError(400, 'INVALID_GROUP');
    return { who: member.who, amount: member.amount, share: member.share } as GroupMember;
  });
}

async function groups(env: Env, memberId: string) {
  const { results } = await env.WALLET_DB.prepare(
    // A replaced group is inserted again: the newest row has the highest rowid.
    'SELECT name, members FROM member_groups WHERE member_id = ? ORDER BY rowid DESC',
  )
    .bind(memberId)
    .all<{ name: string; members: string }>();
  return json({
    groups: results.map(({ name, members }) => ({ name, members: JSON.parse(members) })),
  });
}

/** `GET /app/v1/groups`: the member's saved groups of "Group payment", newest first. */
export async function readGroups(request: Request, env: Env, config: Config) {
  const member = await signedInMember(request, env, config);
  return groups(env, member.id);
}

/** `PUT /app/v1/groups`: `{name, members}`; a group with the same name (any case) is replaced. */
export async function saveGroup(request: Request, env: Env, config: Config) {
  const member = await signedInMember(request, env, config);
  const body = await readJson<{ name?: unknown; members?: unknown }>(request);
  const name = typeof body.name === 'string' ? body.name.trim() : '';
  if (!name || name.length > 40) throw new HttpError(400, 'INVALID_GROUP');
  const members = JSON.stringify(groupMembers(body.members));
  // One statement: the limit holds even if two devices save at once.
  const { meta } = await env.WALLET_DB.prepare(
    `INSERT OR REPLACE INTO member_groups (member_id, name, members)
     SELECT ?1, ?2, ?3
     WHERE (SELECT COUNT(*) FROM member_groups WHERE member_id = ?1 AND name <> ?2) < ?4`,
  )
    .bind(member.id, name, members, MAX_GROUPS)
    .run();
  if (meta.changes === 0) throw new HttpError(409, 'GROUPS_FULL');
  return groups(env, member.id);
}

/** `DELETE /app/v1/groups/:name`. */
export async function deleteGroup(request: Request, env: Env, config: Config, name: string) {
  const member = await signedInMember(request, env, config);
  await env.WALLET_DB.prepare('DELETE FROM member_groups WHERE member_id = ? AND name = ?')
    .bind(member.id, name)
    .run();
  return groups(env, member.id);
}
