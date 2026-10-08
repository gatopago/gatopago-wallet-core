import { DurableObject } from 'cloudflare:workers';
import { Address as StellarAddress, scValToNative, xdr, type rpc } from '@stellar/stellar-sdk';
import { isAddressEqual, isHex, recoverMessageAddress, size, type Address, type Hex } from 'viem';
import { crosschainStatus } from '@gatopago/shared/crosschain';
import { XLM_DECIMALS, type StellarNetwork } from '@gatopago/shared/networks';
import {
  burnMessage,
  deployAccountOperation,
  fromStellarUnits,
  mintAndForwardOperation,
  sendStellarOperation,
  signedCallOperation,
  stellarAccountAddress,
  stellarAccountExists,
  stellarKeyApproval,
} from '@gatopago/shared/stellar';
import { keyOwner } from '@gatopago/shared/wallet';
import { currentOwners } from './approvals';
import type { Budget } from './budget';
import { config, type Config } from './config';
import { enabledNetwork, HttpError, json, readJson } from './http';
import { consumeDailyBudget } from './paymaster';
import { signedInMember } from './profile';
import { notifyReceived } from './push';

type Stellar = NonNullable<Config['stellar']>;

/** Ceiling on the fee of one sponsored Stellar transaction, in stroops (0.5 XLM). */
const MAX_FEE = 5_000_000n;
/** Ledgers per `getEvents` window (about 10 minutes) and windows per run. */
const RANGE = 120;
const ROUNDS = 10;
const PAGE = 1_000;
/** How far back the indexer catches up after a pause: a day, within every RPC's retention. */
const CATCH_UP = 17_280;
const RELAY_SECONDS = 2 * 86_400;
/** Longest an Ed25519 key approval may stay valid. */
const APPROVAL_SECONDS = 3_600;

function enabledStellar(config: Config): Stellar {
  if (!config.stellar) throw new HttpError(404, 'STELLAR_NOT_ENABLED');
  return config.stellar;
}

/**
 * Sends the sponsor's Stellar transactions one at a time (one instance): each takes the account's
 * next sequence number.
 */
export class StellarRelayer extends DurableObject<Env> {
  private queue: Promise<unknown> = Promise.resolve();

  /** The transaction hash, or why it failed (as a value: a rejection would cross the RPC uncaught). */
  send(operation: string): Promise<{ hash: string } | { error: string }> {
    const run = this.queue.then(async () => {
      const stellar = enabledStellar(config(this.env));
      const { hash } = await sendStellarOperation(
        stellar.server,
        stellar.network,
        stellar.keypair,
        xdr.Operation.fromXdr(operation, 'base64'),
        { maxFee: MAX_FEE },
      );
      return { hash };
    });
    const result = run.catch((error: unknown) => ({ error: String(error) }));
    this.queue = result;
    return result;
  }
}

async function relay(env: Env, operation: xdr.Operation) {
  const relayer = env.STELLAR_RELAYER.get(env.STELLAR_RELAYER.idFromName('relayer'));
  const result = await relayer.send(operation.toXdr('base64'));
  if ('error' in result) {
    console.error('Stellar send failed', result.error);
    const code = /STELLAR_[A-Z_]+/.exec(result.error)?.[0];
    throw new HttpError(400, code ?? 'STELLAR_OPERATION_FAILED');
  }
  return result;
}

/** The member's Stellar address, registered so the indexer finds its transfers. */
async function stellarAccount(env: Env, stellar: Stellar, member: Address): Promise<string> {
  const account = stellarAccountAddress(stellar.network, stellar.keypair.publicKey(), member);
  await env.WALLET_DB.prepare(
    'INSERT OR IGNORE INTO stellar_accounts (network, address, member_address) VALUES (?, ?, ?)',
  )
    .bind(stellar.id, account, member.toLowerCase())
    .run();
  return account;
}

/** The member's approved Ed25519 keys, with the EVM owner key that approved each. */
async function approvedKeys(env: Env, member: Address) {
  const { results } = await env.WALLET_DB.prepare(
    'SELECT public_key, owner FROM stellar_keys WHERE member_address = ? ORDER BY created_at',
  )
    .bind(member.toLowerCase())
    .all<{ public_key: Hex; owner: Address }>();
  return results;
}

/** The approved keys whose approving key still owns the account (`owners`, `currentOwners`). */
const signingKeys = (keys: { public_key: Hex; owner: Address }[], owners: readonly Hex[]) =>
  keys
    .filter(({ owner }) => owners.some((current) => current.toLowerCase() === keyOwner(owner)))
    .map(({ public_key }) => public_key);

/**
 * `GET /app/v1/stellar`: the signed-in member's Stellar account, whether it exists yet, the
 * sponsor that simulates and pays its transactions, and its approved Ed25519 keys (each counts
 * while its `owner` owns the EVM account).
 */
export async function readStellar(request: Request, env: Env, config: Config): Promise<Response> {
  const stellar = enabledStellar(config);
  const member = await signedInMember(request, env, config);
  const account = await stellarAccount(env, stellar, member.address);
  return json({
    network: stellar.id,
    account,
    deployed: await stellarAccountExists(stellar.server, account),
    sponsor: stellar.keypair.publicKey(),
    keys: await approvedKeys(env, member.address),
  });
}

/**
 * `POST /app/v1/stellar/keys`: an Ed25519 key that also signs for the member's Stellar account
 * (`{public_key, signature, expires_at, initial_owners?}`), approved by an owner key of the EVM
 * account: its EIP-191 signature of `stellarKeyApproval`, valid for at most an hour. A session alone cannot add one, so a stolen token
 * cannot make its own key a signer.
 */
export async function addStellarKey(request: Request, env: Env, config: Config): Promise<Response> {
  const stellar = enabledStellar(config);
  const member = await signedInMember(request, env, config);
  const body = await readJson<{
    public_key?: unknown;
    signature?: unknown;
    expires_at?: unknown;
    initial_owners?: unknown;
  }>(request);
  const now = Math.floor(Date.now() / 1000);
  if (
    !isHex(body.public_key) ||
    size(body.public_key) !== 32 ||
    !isHex(body.signature) ||
    !Number.isSafeInteger(body.expires_at)
  )
    throw new HttpError(400, 'INVALID_REQUEST');
  const expiresAt = body.expires_at as number;
  if (expiresAt <= now || expiresAt > now + APPROVAL_SECONDS)
    throw new HttpError(400, 'APPROVAL_EXPIRED');
  const publicKey = body.public_key.toLowerCase() as Hex;
  const owner = await recoverMessageAddress({
    message: stellarKeyApproval(stellar.network, member.address, publicKey, expiresAt),
    signature: body.signature,
  }).catch(() => null);
  const owners = await currentOwners(env, config, member, body.initial_owners);
  if (!owner || !owners.some((current) => current.toLowerCase() === keyOwner(owner)))
    throw new HttpError(403, 'NOT_AN_OWNER');
  await env.WALLET_DB.prepare(
    `INSERT INTO stellar_keys (member_address, public_key, owner, created_at) VALUES (?, ?, ?, ?)
     ON CONFLICT (member_address, public_key) DO UPDATE SET owner = excluded.owner`,
  )
    .bind(
      member.address.toLowerCase(),
      publicKey,
      owner.toLowerCase(),
      Math.floor(Date.now() / 1000),
    )
    .run();
  return json({ public_key: publicKey }, 201);
}

/**
 * `POST /app/v1/stellar/account`: creates the member's Stellar account, signed by the passkeys that
 * own the EVM account and its approved Ed25519 keys, before its first outgoing operation. Receiving
 * needs no account.
 */
export async function createStellarAccount(
  request: Request,
  env: Env,
  config: Config,
): Promise<Response> {
  const stellar = enabledStellar(config);
  const member = await signedInMember(request, env, config);
  const body = await readJson<{ initial_owners?: unknown }>(request);
  const account = await stellarAccount(env, stellar, member.address);
  if (!(await stellarAccountExists(stellar.server, account))) {
    const owners = await currentOwners(env, config, member, body.initial_owners);
    const keys = signingKeys(await approvedKeys(env, member.address), owners);
    await consumeDailyBudget(env, config, member.address);
    await relay(
      env,
      deployAccountOperation(
        stellar.network,
        stellar.keypair.publicKey(),
        member.address,
        owners,
        keys,
      ),
    );
  }
  return json({ account, deployed: true });
}

/**
 * The calls GatoPago pays for: the account moving its USDC or XLM, letting Circle burn its USDC,
 * burning it toward another network, and changing its own signers.
 */
function sponsorable(network: StellarNetwork, account: string, func: xdr.HostFunction) {
  if (func.type !== 'hostFunctionTypeInvokeContract') return false;
  const { contractAddress, functionName, args } = func.invokeContract;
  const target = StellarAddress.fromScAddress(contractAddress).toString();
  const method = functionName.toString();
  const [first, second] = args.map((arg) => scValToNative(arg) as unknown);
  if (target === network.usdc)
    return (
      first === account &&
      (method === 'transfer' ||
        (method === 'approve' && second === network.cctp.tokenMessengerMinter))
    );
  if (target === network.xlm) return first === account && method === 'transfer';
  if (target === network.cctp.tokenMessengerMinter)
    return method === 'deposit_for_burn_with_hook' && first === account;
  return target === account && (method === 'add_signer' || method === 'remove_signer');
}

/**
 * `POST /app/v1/stellar/submit`: sends a call of the member's Stellar account, signed with one of
 * its passkeys (`{ func, auth }` as base64 XDR), paying its fee within the daily budget.
 */
export async function submitStellar(request: Request, env: Env, config: Config): Promise<Response> {
  const stellar = enabledStellar(config);
  const member = await signedInMember(request, env, config);
  const body = await readJson<{ func?: unknown; auth?: unknown }>(request);
  let func: xdr.HostFunction;
  let auth: xdr.SorobanAuthorizationEntry[];
  try {
    func = xdr.HostFunction.fromXdr(body.func as string, 'base64');
    auth = (body.auth as string[]).map((entry) =>
      xdr.SorobanAuthorizationEntry.fromXdr(entry, 'base64'),
    );
  } catch {
    throw new HttpError(400, 'INVALID_REQUEST');
  }
  const account = await stellarAccount(env, stellar, member.address);
  // The sponsor signs the transaction: no entry may borrow its authority.
  if (
    !sponsorable(stellar.network, account, func) ||
    auth.some((entry) => entry.credentials.type === 'sorobanCredentialsSourceAccount')
  )
    throw new HttpError(403, 'NOT_SPONSORED');
  await consumeDailyBudget(env, config, member.address);
  const { hash } = await relay(env, signedCallOperation(func, auth));
  // Remembered by the nonces the account signed, for `readStellarSubmission`.
  const nonces = auth.flatMap(({ credentials }) =>
    credentials.type === 'sorobanCredentialsSourceAccount'
      ? []
      : [
          (credentials.type === 'sorobanCredentialsAddressWithDelegates'
            ? credentials.value.addressCredentials
            : credentials.value
          ).nonce.toString(),
        ],
  );
  const now = Math.floor(Date.now() / 1000);
  await env.WALLET_DB.batch(
    nonces.map((nonce) =>
      env.WALLET_DB.prepare(
        `INSERT OR IGNORE INTO stellar_submissions (member_address, nonce, transaction_hash, created_at)
         VALUES (?, ?, ?, ?)`,
      ).bind(member.address.toLowerCase(), nonce, hash, now),
    ),
  );
  return json({ transaction_hash: hash });
}

/**
 * `GET /app/v1/stellar/submit?nonce=…`: the transaction that sent the member's call signed with
 * that nonce, or 404 when Wallet Core sent none.
 */
export async function readStellarSubmission(
  request: Request,
  env: Env,
  config: Config,
): Promise<Response> {
  enabledStellar(config);
  const member = await signedInMember(request, env, config);
  const nonce = new URL(request.url).searchParams.get('nonce');
  if (!nonce || !/^-?\d{1,20}$/.test(nonce)) throw new HttpError(400, 'INVALID_REQUEST');
  const hash = await env.WALLET_DB.prepare(
    'SELECT transaction_hash FROM stellar_submissions WHERE member_address = ? AND nonce = ?',
  )
    .bind(member.address.toLowerCase(), nonce)
    .first<string>('transaction_hash');
  if (!hash) throw new HttpError(404, 'NOT_FOUND');
  return json({ transaction_hash: hash });
}

/**
 * `POST /app/v1/stellar/relays`: a CCTP burn the member sent toward Stellar, which the relayer mints
 * once Circle attests it.
 */
export async function requestStellarRelay(
  request: Request,
  env: Env,
  config: Config,
): Promise<Response> {
  enabledStellar(config);
  const member = await signedInMember(request, env, config);
  const body = await readJson<{ network?: string; transaction_hash?: unknown }>(request);
  const network = enabledNetwork(config, body.network ?? '');
  if (!isHex(body.transaction_hash) || size(body.transaction_hash) !== 32)
    throw new HttpError(400, 'INVALID_REQUEST');
  await consumeDailyBudget(env, config, member.address);
  await env.WALLET_DB.prepare(
    `INSERT OR IGNORE INTO stellar_relays (source_network, transaction_hash, member_address, created_at)
     VALUES (?, ?, ?, ?)`,
  )
    .bind(
      network.id,
      body.transaction_hash.toLowerCase(),
      member.address.toLowerCase(),
      Math.floor(Date.now() / 1000),
    )
    .run();
  return json({}, 202);
}

/**
 * `GET /app/v1/stellar/relays?transaction_hash=0x…`: whether the member's burn toward Stellar was
 * minted there (`delivered`, with its Stellar transaction), is still `pending`, or was `rejected`.
 */
export async function readStellarRelay(
  request: Request,
  env: Env,
  config: Config,
): Promise<Response> {
  enabledStellar(config);
  const member = await signedInMember(request, env, config);
  const hash = new URL(request.url).searchParams.get('transaction_hash');
  if (!isHex(hash) || size(hash) !== 32) throw new HttpError(400, 'INVALID_REQUEST');
  const relayed = await env.WALLET_DB.prepare(
    'SELECT relayed_hash FROM stellar_relays WHERE transaction_hash = ? AND member_address = ?',
  )
    .bind(hash.toLowerCase(), member.address.toLowerCase())
    .first<{ relayed_hash: string | null }>();
  if (!relayed) throw new HttpError(404, 'NOT_FOUND');
  const { relayed_hash: stellarHash } = relayed;
  return json(
    stellarHash === null
      ? { status: 'pending', transaction_hash: null }
      : stellarHash === 'rejected'
        ? { status: 'rejected', transaction_hash: null }
        : { status: 'delivered', transaction_hash: stellarHash },
  );
}

/** Every minute: registers members' Stellar addresses, mints attested burns, reads transfers. */
export async function syncStellar(env: Env, config: Config, budget: Budget): Promise<void> {
  const stellar = config.stellar;
  if (!stellar) return;
  await registerAccounts(env, stellar);
  await relayBurns(env, config, stellar, budget);
  await indexTransfers(env, config, stellar, budget);
}

async function registerAccounts(env: Env, stellar: Stellar) {
  const { results } = await env.WALLET_DB.prepare(
    `SELECT address FROM members
     WHERE address NOT IN (SELECT member_address FROM stellar_accounts WHERE network = ?) LIMIT 500`,
  )
    .bind(stellar.id)
    .all<{ address: Address }>();
  if (results.length === 0) return;
  await env.WALLET_DB.batch(
    results.map(({ address }) =>
      env.WALLET_DB.prepare(
        'INSERT OR IGNORE INTO stellar_accounts (network, address, member_address) VALUES (?, ?, ?)',
      ).bind(
        stellar.id,
        stellarAccountAddress(stellar.network, stellar.keypair.publicKey(), address),
        address,
      ),
    ),
  );
}

/** Mints attested burns of members toward Stellar; anyone could, so nothing is lost if it waits. */
async function relayBurns(env: Env, config: Config, stellar: Stellar, budget: Budget) {
  const { results } = await env.WALLET_DB.prepare(
    `SELECT source_network, transaction_hash, member_address FROM stellar_relays
     WHERE relayed_hash IS NULL AND created_at > ? LIMIT 20`,
  )
    .bind(Math.floor(Date.now() / 1000) - RELAY_SECONDS)
    .all<{ source_network: string; transaction_hash: string; member_address: Address }>();
  for (const pending of results) {
    const network = config.networks.get(pending.source_network);
    if (!network) continue;
    // Circle's status, then the mint sent through the relayer.
    if (!budget.take(2)) return;
    const status = await crosschainStatus(
      network,
      pending.transaction_hash,
      AbortSignal.timeout(10_000),
    ).catch(() => null);
    if (!status?.attested) continue;
    const burn = burnMessage(status.attested.message);
    const done = (hash: string) =>
      env.WALLET_DB.prepare(
        `UPDATE stellar_relays SET relayed_hash = ?
         WHERE source_network = ? AND transaction_hash = ? AND member_address = ?`,
      )
        .bind(hash, pending.source_network, pending.transaction_hash, pending.member_address)
        .run();
    // Only the member's own burns toward Stellar.
    if (
      burn.destinationDomain !== stellar.network.cctp.domain ||
      !isAddressEqual(burn.sender, pending.member_address)
    ) {
      await done('rejected');
      continue;
    }
    try {
      const { hash } = await relay(
        env,
        mintAndForwardOperation(
          stellar.network,
          status.attested.message,
          status.attested.attestation,
        ),
      );
      await done(hash);
    } catch {
      // Already minted by someone else, or the network failed: retried until the row expires.
    }
  }
}

/** A Stellar transfer event: USDC in CCTP's 6 decimals, or XLM in its own 7. */
interface StellarTransfer {
  transactionHash: string;
  logIndex: number;
  ledger: number;
  timestamp: number;
  from: string;
  to: string;
  value: bigint;
  coin: { symbol: 'USDC' | 'XLM'; decimals: number };
}

const USDC = { symbol: 'USDC', decimals: 6 } as const;
const XLM = { symbol: 'XLM', decimals: XLM_DECIMALS } as const;

function transferOf(network: StellarNetwork, event: rpc.Api.EventResponse): StellarTransfer | null {
  const [, from, to] = event.topic.map((topic) => scValToNative(topic) as unknown);
  // CAP-67: the amount, or `{ amount, to_muxed_id }` toward a muxed address.
  const data = scValToNative(event.value) as bigint | { amount: bigint };
  const amount = typeof data === 'bigint' ? data : data.amount;
  const coin = event.contractId?.contractId() === network.xlm ? XLM : USDC;
  const value = coin === USDC ? fromStellarUnits(amount) : amount;
  if (typeof from !== 'string' || typeof to !== 'string' || value === 0n) return null;
  return {
    transactionHash: event.txHash,
    // Events are numbered per operation; Soroban transactions have one, classic ones up to 100.
    logIndex: event.operationIndex * 1_000_000 + Number(event.id.split('-')[1]),
    ledger: event.ledger,
    timestamp: Math.floor(Date.parse(event.ledgerClosedAt) / 1000),
    from,
    to,
    value,
    coin,
  };
}

/**
 * Reads USDC and XLM transfer events since the last ledger read and keeps those of members (the RPC
 * cannot filter by many addresses), notifying what they received.
 */
async function indexTransfers(env: Env, config: Config, stellar: Stellar, budget: Budget) {
  const { server, network } = stellar;
  if (!budget.take()) return;
  const latest = (await server.getLatestLedger()).sequence;
  const cursor = await env.WALLET_DB.prepare('SELECT block FROM index_cursors WHERE network = ?')
    .bind(stellar.id)
    .first<number>('block');
  let from = Math.max(cursor === null ? latest : cursor + 1, latest - CATCH_UP);
  const filters = [
    {
      type: 'contract' as const,
      contractIds: [network.usdc, network.xlm],
      topics: [[xdr.ScVal.scvSymbol('transfer').toXdr('base64'), '*', '*', '*']],
    },
  ];
  for (let round = 0; from <= latest && round < ROUNDS; round++) {
    const to = Math.min(from + RANGE - 1, latest);
    const events: rpc.Api.EventResponse[] = [];
    // Out of requests: this window is read again on the next run.
    if (!budget.take()) return;
    let page = await server.getEvents({
      startLedger: from,
      endLedger: to + 1,
      filters,
      limit: PAGE,
    });
    events.push(...page.events);
    while (page.events.length === PAGE) {
      if (!budget.take()) return;
      page = await server.getEvents({ cursor: page.cursor, filters, limit: PAGE });
      events.push(...page.events.filter((event) => event.ledger <= to));
      if (page.events.some((event) => event.ledger > to)) break;
    }
    const transfers = events
      .map((event) => transferOf(network, event))
      .filter((transfer) => transfer !== null);
    const members = await stellarMembers(
      env,
      stellar,
      transfers.flatMap(({ from, to }) => [from, to]),
    );
    const kept = transfers.filter(({ from, to }) => members.has(from) || members.has(to));
    const crosschain = [network.cctp.tokenMessengerMinter, network.cctp.forwarder];
    const results = await env.WALLET_DB.batch([
      ...kept.map((transfer) =>
        env.WALLET_DB.prepare(
          `INSERT OR IGNORE INTO transfers (network, transaction_hash, log_index, block_number,
             timestamp, from_address, to_address, amount, kind, token)
           VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`,
        ).bind(
          stellar.id,
          transfer.transactionHash,
          transfer.logIndex,
          transfer.ledger,
          transfer.timestamp,
          transfer.from,
          transfer.to,
          transfer.value.toString(),
          crosschain.includes(transfer.from) || crosschain.includes(transfer.to)
            ? 'crosschain'
            : 'transfer',
          transfer.coin.symbol,
        ),
      ),
      env.WALLET_DB.prepare(
        `INSERT INTO index_cursors (network, block) VALUES (?, ?)
         ON CONFLICT (network) DO UPDATE SET block = excluded.block`,
      ).bind(stellar.id, to),
    ]);
    await notifyReceived(
      env,
      config,
      kept.filter((transfer, i) => members.has(transfer.to) && results[i].meta.changes > 0),
    );
    from = to + 1;
  }
}

/** Members' Stellar addresses among `addresses`. D1 binds at most 100 parameters per statement. */
async function stellarMembers(env: Env, stellar: Stellar, addresses: string[]) {
  const unique = [...new Set(addresses)];
  const members = new Set<string>();
  for (let i = 0; i < unique.length; i += 99) {
    const batch = unique.slice(i, i + 99);
    const { results } = await env.WALLET_DB.prepare(
      `SELECT address FROM stellar_accounts WHERE network = ? AND address IN (${batch.map(() => '?').join(',')})`,
    )
      .bind(stellar.id, ...batch)
      .all<{ address: string }>();
    for (const row of results) members.add(row.address);
  }
  return members;
}
