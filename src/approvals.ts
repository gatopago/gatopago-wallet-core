import { getAddress, isAddressEqual, isHex, type Address, type Hex, type PublicClient } from 'viem';
import { walletContracts } from '@gatopago/shared/networks';
import { gatopagoAccountFactoryAbi, ownersAfter, verifyApproval } from '@gatopago/shared/wallet';
import type { Config } from './config';
import { HttpError, json, rateLimit, readJson } from './http';
import { memberByAddress, type Member } from './members';
import { signedInMember } from './profile';
import { issueSession } from './session';

/**
 * Owner approvals (owner changes, upgrades) applied on one network, kept so they can be applied in
 * order on the others. They are public: applying one still needs sponsorship.
 */
export async function readApprovals(
  request: Request,
  env: Env,
  account: Address,
): Promise<Response> {
  await rateLimit(env, request, 'approvals');
  const member = await memberByAddress(env.WALLET_DB, account);
  if (!member) throw new HttpError(404, 'ACCOUNT_NOT_FOUND');
  return json({ initial_owners: member.initialOwners, approvals: await approvals(env, account) });
}

/**
 * `POST /app/v1/approvals/:account`: stores the account's next approval once verified. One that
 * removes owners also ends every session issued before it (any may be a removed owner's) and
 * answers a new `session` for this device, unless the key that signed it is among the removed.
 */
export async function addApproval(
  request: Request,
  env: Env,
  config: Config,
  account: Address,
): Promise<Response> {
  const member = await signedInMember(request, env, config);
  if (!isAddressEqual(member.address, account)) throw new HttpError(403, 'NOT_ACCOUNT_OWNER');
  const body = await readJson<{ call?: Hex; signature?: Hex; initial_owners?: Hex[] }>(request);
  if (!isHex(body.call) || !isHex(body.signature)) throw new HttpError(400, 'INVALID_REQUEST');

  const client = [...config.networks.values()][0].client;
  const initialOwners =
    member.initialOwners ?? (await provenInitialOwners(client, account, body.initial_owners));
  const previous = await approvals(env, account);
  const signer = await verifyApproval(client, {
    account,
    initialOwners,
    previous: previous.map((approval) => approval.call),
    call: body.call,
    signature: body.signature,
  });
  if (!signer) throw new HttpError(400, 'APPROVAL_INVALID');
  const before = ownersAfter(
    initialOwners,
    previous.map((approval) => approval.call),
  );
  const after = ownersAfter(before, [body.call]);
  const removed = before.filter((owner) => !after.includes(owner));

  const now = Math.floor(Date.now() / 1000);
  // The session generation after removing owners: every earlier session stops counting.
  let generation: number | null = null;
  try {
    const results = await env.WALLET_DB.batch<{ session_generation: number }>([
      ...(removed.length > 0
        ? [
            env.WALLET_DB.prepare(
              `UPDATE members SET session_generation = session_generation + 1 WHERE id = ?
               RETURNING session_generation`,
            ).bind(member.id),
          ]
        : []),
      env.WALLET_DB.prepare(
        'UPDATE members SET initial_owners = ? WHERE address = ? AND initial_owners IS NULL',
      ).bind(JSON.stringify(initialOwners), account.toLowerCase()),
      env.WALLET_DB.prepare(
        'INSERT INTO approvals (account, sequence, call, signature, created_at) VALUES (?, ?, ?, ?, ?)',
      ).bind(account.toLowerCase(), previous.length, body.call, body.signature, now),
    ]);
    if (removed.length > 0) generation = results[0].results[0].session_generation;
  } catch (error) {
    if (String(error).includes('UNIQUE constraint failed'))
      throw new HttpError(409, 'APPROVAL_CONFLICT');
    throw error;
  }
  const session =
    generation !== null && !removed.includes(signer)
      ? await issueSession(config, { ...member, sessionGeneration: generation })
      : null;
  return json(
    {
      sequence: previous.length,
      ...(session && { session: { token: session.token, expires_at: session.expiresAt } }),
    },
    201,
  );
}

async function approvals(env: Env, account: Address) {
  const { results } = await env.WALLET_DB.prepare(
    'SELECT sequence, call, signature FROM approvals WHERE account = ? ORDER BY sequence',
  )
    .bind(account.toLowerCase())
    .all<{ sequence: number; call: Hex; signature: Hex }>();
  return results;
}

/** The account address commits to its initial owners: the factory must derive it from them. */
export async function provenInitialOwners(
  client: PublicClient,
  account: Address,
  owners: Hex[] | undefined,
): Promise<readonly Hex[]> {
  if (!Array.isArray(owners) || owners.length === 0 || !owners.every((owner) => isHex(owner)))
    throw new HttpError(400, 'INITIAL_OWNERS_REQUIRED');
  const derived = await client.readContract({
    address: walletContracts.factory,
    abi: gatopagoAccountFactoryAbi,
    functionName: 'getAddress',
    args: [owners, 0n],
  });
  if (getAddress(derived) !== getAddress(account))
    throw new HttpError(400, 'INITIAL_OWNERS_INVALID');
  return owners;
}

/**
 * The account's owners now: its initial owners (proven against the factory when the database does
 * not know them yet, then kept) and the approved changes.
 */
export async function currentOwners(
  env: Env,
  config: Config,
  member: Member,
  claimedInitialOwners: unknown,
): Promise<Hex[]> {
  const client = [...config.networks.values()][0].client;
  const initialOwners =
    member.initialOwners ??
    (await provenInitialOwners(client, member.address, claimedInitialOwners as Hex[] | undefined));
  if (!member.initialOwners)
    await env.WALLET_DB.prepare(
      'UPDATE members SET initial_owners = ? WHERE address = ? AND initial_owners IS NULL',
    )
      .bind(JSON.stringify(initialOwners), member.address.toLowerCase())
      .run();
  const changes = await approvals(env, member.address);
  return ownersAfter(
    initialOwners,
    changes.map((approval) => approval.call),
  );
}
