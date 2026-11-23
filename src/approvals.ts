import { getAddress, isAddressEqual, isHex, type Address, type Hex, type PublicClient } from 'viem';
import { walletContracts } from '@gatopago/shared/networks';
import { accountOwners, gatopagoAccountFactoryAbi, verifyApproval } from '@gatopago/shared/wallet';
import type { Config } from './config';
import { HttpError, json, rateLimit, readJson } from './http';
import { memberByAddress, type Member } from './members';
import { signedInMember } from './profile';

/**
 * Owner approvals (owner changes, upgrades) applied on one network, kept so they can be applied in
 * order on the others, and the changes they scheduled that are neither applied nor cancelled yet,
 * per network (`readChanges`). All public, as onchain: applying one still needs sponsorship.
 */
export async function readApprovals(
  request: Request,
  env: Env,
  account: Address,
): Promise<Response> {
  await rateLimit(env, request, 'approvals');
  const member = await memberByAddress(env.WALLET_DB, account);
  if (!member) throw new HttpError(404, 'ACCOUNT_NOT_FOUND');
  const { results: changes } = await env.WALLET_DB.prepare(
    `SELECT network, id, sequence, call, ready_at FROM owner_changes WHERE account = ?
     ORDER BY sequence, network`,
  )
    .bind(account.toLowerCase())
    .all();
  return json({
    initial_owners: member.initialOwners,
    approvals: await approvals(env, account),
    changes,
  });
}

/**
 * `POST /app/v1/approvals/:account`: stores the account's next approval once one of the owners it
 * has on the home network signed it. Removing a key only schedules it: the key's sessions end once
 * the account applies it (`readChanges`).
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

  const { client } = config.home;
  const initialOwners =
    member.initialOwners ?? (await provenInitialOwners(client, account, body.initial_owners));
  const previous = await approvals(env, account);
  const owners = await accountOwners(client, {
    account,
    initialOwners,
    calls: previous.map((approval) => approval.call),
  });
  const signer = await verifyApproval(client, {
    account,
    owners,
    sequence: previous.length,
    call: body.call,
    signature: body.signature,
  });
  if (!signer) throw new HttpError(400, 'APPROVAL_INVALID');
  try {
    await env.WALLET_DB.batch([
      env.WALLET_DB.prepare(
        'UPDATE members SET initial_owners = ? WHERE address = ? AND initial_owners IS NULL',
      ).bind(JSON.stringify(initialOwners), account.toLowerCase()),
      env.WALLET_DB.prepare(
        'INSERT INTO approvals (account, sequence, call, signature, created_at) VALUES (?, ?, ?, ?, ?)',
      ).bind(
        account.toLowerCase(),
        previous.length,
        body.call,
        body.signature,
        Math.floor(Date.now() / 1000),
      ),
    ]);
  } catch (error) {
    if (String(error).includes('UNIQUE constraint failed'))
      throw new HttpError(409, 'APPROVAL_CONFLICT');
    throw error;
  }
  return json({ sequence: previous.length }, 201);
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
 * The account's owners on the home network (`accountOwners`), from its initial owners (proven
 * against the factory when the database does not know them yet, then kept) and its approvals.
 */
export async function currentOwners(
  env: Env,
  config: Config,
  member: Member,
  claimedInitialOwners: unknown,
): Promise<Hex[]> {
  const { client } = config.home;
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
  return accountOwners(client, {
    account: member.address,
    initialOwners,
    calls: changes.map((approval) => approval.call),
  });
}
