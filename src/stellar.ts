import { DurableObject } from 'cloudflare:workers';
import { Address as StellarAddress, scValToNative, StrKey, xdr, rpc } from '@stellar/stellar-sdk';
import {
  bytesToHex,
  decodeEventLog,
  isAddressEqual,
  isHex,
  parseAbiItem,
  recoverMessageAddress,
  size,
  toEventSelector,
  type Address,
  type Hex,
} from 'viem';
import { crosschainStatus } from '@gatopago/shared/crosschain';
import { walletNetworks, XLM_DECIMALS, type StellarNetwork } from '@gatopago/shared/networks';
import {
  burnMessage,
  deployAccountOperation,
  hookRecipient,
  fromStellarUnits,
  mintAndForwardOperation,
  sendStellarOperation,
  signedCallOperation,
  STELLAR_TRANSACTION_SECONDS,
  stellarAccountAddress,
  stellarAccountExists,
  stellarKeyApproval,
} from '@gatopago/shared/stellar';
import { keyOwner } from '@gatopago/shared/wallet';
import { currentOwners } from './approvals';
import { Budget } from './budget';
import { config, type Config, type Network } from './config';
import { enabledNetwork, HttpError, json, readJson } from './http';
import { missedUntil, readCursor, readerFailed, saveCursor } from './cursors';
import { consumeDailyBudget } from './paymaster';
import { signedInMember } from './profile';
import { hypersyncHeight, hypersyncLogs } from './hypersync';
import { NOTIFY_SECONDS } from './push';

type Stellar = NonNullable<Config['stellar']>;

/** Ceiling on the fee of one sponsored Stellar transaction, in stroops (0.5 XLM). */
const MAX_FEE = 5_000_000n;
/** Ledgers per `getEvents` window (about 10 minutes) and windows per run. */
const RANGE = 120;
const ROUNDS = 10;
const PAGE = 1_000;
/** What one `getEvents` takes: filters, and topic patterns in each (the RPC's limits). */
const FILTERS_PER_REQUEST = 5;
const PATTERNS_PER_FILTER = 5;
const RELAY_SECONDS = 2 * 86_400;
/** While a burn toward Stellar is this recent, its attestation is checked every few seconds. */
const FAST_RELAY_SECONDS = 1_800;
const WAKE_MS = 5_000;
/** `eth_getLogs` ranges per network and run when no HyperSync reads the burns toward Stellar. */
const BURN_ROUNDS = 5;
const DEPOSIT_FOR_BURN = parseAbiItem(
  'event DepositForBurn(address indexed burnToken, uint256 amount, address indexed depositor, bytes32 mintRecipient, uint32 destinationDomain, bytes32 destinationTokenMessenger, bytes32 destinationCaller, uint256 maxFee, uint32 indexed minFinalityThreshold, bytes hookData)',
);
/** Longest an Ed25519 key approval may stay valid. */
const APPROVAL_SECONDS = 3_600;

function enabledStellar(config: Config): Stellar {
  if (!config.stellar) throw new HttpError(404, 'STELLAR_NOT_ENABLED');
  return config.stellar;
}

/**
 * Sends the sponsor's Stellar transactions one at a time (one instance): each takes the account's
 * next sequence number. It also mints the burns toward Stellar once Circle attests them: woken when
 * one is recorded, it checks again every few seconds while a recent one waits (the attestation is
 * offchain: no event announces it), and the minute cron wakes it for older ones.
 */
export class StellarRelayer extends DurableObject<Env> {
  private queue: Promise<unknown> = Promise.resolve();

  /**
   * The transaction hash, or why it failed (as a value: a rejection would cross the RPC uncaught).
   * A member's call (`submission`) is recorded as pending before it is broadcast, then confirmed or
   * failed; one whose answer is lost stays pending until `resolveSubmissions` asks the network.
   */
  send(operation: string, submission?: Submission): Promise<{ hash: string } | { error: string }> {
    const run = this.queue.then(async () => {
      const stellar = enabledStellar(config(this.env));
      const recorded = { hash: null as string | null };
      let result;
      try {
        result = await sendStellarOperation(
          stellar.server,
          stellar.network,
          stellar.keypair,
          xdr.Operation.fromXdr(operation, 'base64'),
          {
            maxFee: MAX_FEE,
            onSigned:
              submission &&
              (async (hash) => {
                await recordSubmission(this.env, submission, hash);
                recorded.hash = hash;
              }),
          },
        );
      } catch (error) {
        // Refused or failed by the network: it never landed. An unknown result stays pending.
        if (recorded.hash && !String(error).includes('STELLAR_TRANSACTION_PENDING'))
          await settleSubmission(this.env, recorded.hash, 'failed').catch(() => undefined);
        throw error;
      }
      // Unwritten, it stays pending and the minute cron confirms it by its hash.
      if (recorded.hash)
        await settleSubmission(this.env, recorded.hash, 'confirmed').catch((error: unknown) =>
          console.error(error),
        );
      return { hash: result.hash };
    });
    const result = run.catch((error: unknown) => ({ error: String(error) }));
    this.queue = result;
    return result;
  }

  /** Relays pending burns in a few seconds, unless a relay is already scheduled. */
  async wake() {
    if ((await this.ctx.storage.getAlarm()) === null)
      await this.ctx.storage.setAlarm(Date.now() + WAKE_MS);
  }

  async alarm() {
    const settings = config(this.env);
    if (!settings.stellar) return;
    await relayBurns(
      this.env,
      settings,
      settings.stellar,
      new Budget(settings.subrequestsPerRun),
      async (operation) => sent(await this.send(operation.toXdr('base64'))),
    );
    if (await relaysWaiting(this.env, FAST_RELAY_SECONDS))
      await this.ctx.storage.setAlarm(Date.now() + WAKE_MS);
  }
}

/** Whether a burn toward Stellar recorded in the last `seconds` still waits for its mint. */
const relaysWaiting = async (env: Env, seconds: number) =>
  (await env.WALLET_DB.prepare(
    'SELECT 1 AS waiting FROM stellar_relays WHERE relayed_hash IS NULL AND created_at > ? LIMIT 1',
  )
    .bind(Math.floor(Date.now() / 1000) - seconds)
    .first('waiting')) !== null;

const relayer = (env: Env) => env.STELLAR_RELAYER.get(env.STELLAR_RELAYER.idFromName('relayer'));

/** A member's call, recorded by the nonces it signed (`stellar_submissions`). */
interface Submission {
  member: string;
  nonces: string[];
}

/** Records a member's call as pending before it is broadcast: a nonce already recorded went out. */
async function recordSubmission(env: Env, submission: Submission, hash: string) {
  const now = Math.floor(Date.now() / 1000);
  const results = await env.WALLET_DB.batch(
    submission.nonces.map((nonce) =>
      env.WALLET_DB.prepare(
        `INSERT INTO stellar_submissions (member_address, nonce, transaction_hash, created_at, status)
         VALUES (?, ?, ?, ?, 'pending') ON CONFLICT DO NOTHING RETURNING nonce`,
      ).bind(submission.member, nonce, hash, now),
    ),
  );
  if (results.some(({ results }) => results.length === 0))
    throw new Error('STELLAR_TRANSACTION_PENDING: already sent');
}

const settleSubmission = (env: Env, hash: string, status: 'confirmed' | 'failed') =>
  env.WALLET_DB.prepare(
    `UPDATE stellar_submissions SET status = ? WHERE transaction_hash = ? AND status = 'pending'`,
  )
    .bind(status, hash)
    .run();

/**
 * Members' calls whose answer the relayer lost: the network answers by hash. Past the
 * transaction's time bound, one the network does not know never landed.
 */
async function resolveSubmissions(env: Env, stellar: Stellar, budget: Budget) {
  const { results } = await env.WALLET_DB.prepare(
    `SELECT transaction_hash, MIN(created_at) AS created_at FROM stellar_submissions
     WHERE status = 'pending' AND created_at < ? GROUP BY transaction_hash LIMIT 10`,
  )
    .bind(Math.floor(Date.now() / 1000) - 30)
    .all<{ transaction_hash: string; created_at: number }>();
  for (const { transaction_hash, created_at } of results) {
    if (!budget.take()) return;
    const answer = await stellar.server.getTransaction(transaction_hash);
    const status =
      answer.status === rpc.Api.GetTransactionStatus.SUCCESS
        ? 'confirmed'
        : answer.status === rpc.Api.GetTransactionStatus.FAILED ||
            answer.latestLedgerCloseTime > created_at + STELLAR_TRANSACTION_SECONDS + 30
          ? 'failed'
          : null;
    if (status) await settleSubmission(env, transaction_hash, status);
  }
}

/** The hash of a relayer send, or its failure as an error. */
function sent(result: { hash: string } | { error: string }) {
  if ('error' in result) {
    console.error('Stellar send failed', result.error);
    const code = /STELLAR_[A-Z_]+/.exec(result.error)?.[0];
    throw new HttpError(400, code ?? 'STELLAR_OPERATION_FAILED');
  }
  return result;
}

async function relay(env: Env, operation: xdr.Operation, submission?: Submission) {
  return sent(await relayer(env).send(operation.toXdr('base64'), submission));
}

/** The member's Stellar address: it derives from the sponsor key and the member's EVM address. */
const stellarAccount = (stellar: Stellar, member: Address) =>
  stellarAccountAddress(stellar.network, stellar.keypair.publicKey(), member);

/**
 * The member's approved Ed25519 keys, each with the EVM owner key that approved it and that approval
 * (`stellarKeyApproval` until `expires_at`, signed), so the app can check it too.
 */
async function approvedKeys(env: Env, member: Address) {
  const { results } = await env.WALLET_DB.prepare(
    `SELECT public_key, owner, signature, expires_at FROM stellar_keys
     WHERE member_address = ? ORDER BY created_at`,
  )
    .bind(member.toLowerCase())
    .all<{ public_key: Hex; owner: Address; signature: Hex; expires_at: number }>();
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
  const account = stellarAccount(stellar, member.address);
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
    `INSERT INTO stellar_keys (member_address, public_key, owner, signature, expires_at, created_at)
     VALUES (?, ?, ?, ?, ?, ?)
     ON CONFLICT (member_address, public_key) DO UPDATE SET
       owner = excluded.owner, signature = excluded.signature, expires_at = excluded.expires_at`,
  )
    .bind(
      member.address.toLowerCase(),
      publicKey,
      owner.toLowerCase(),
      body.signature,
      expiresAt,
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
  const account = stellarAccount(stellar, member.address);
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
  const account = stellarAccount(stellar, member.address);
  // The sponsor signs the transaction: no entry may borrow its authority.
  if (
    !sponsorable(stellar.network, account, func) ||
    auth.some((entry) => entry.credentials.type === 'sorobanCredentialsSourceAccount')
  )
    throw new HttpError(403, 'NOT_SPONSORED');
  await consumeDailyBudget(env, config, member.address);
  // Recorded by the nonces the account signed before it goes out, for `readStellarSubmission`.
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
  const { hash } = await relay(env, signedCallOperation(func, auth), {
    member: member.address.toLowerCase(),
    nonces,
  });
  return json({ transaction_hash: hash });
}

/**
 * `GET /app/v1/stellar/submit?nonce=…`: the transaction that carries the member's call signed with
 * that nonce and whether it landed (`pending`, `confirmed` or `failed`), or 404 when Wallet Core
 * never sent it (each call is recorded before it is broadcast).
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
  const submission = await env.WALLET_DB.prepare(
    'SELECT transaction_hash, status FROM stellar_submissions WHERE member_address = ? AND nonce = ?',
  )
    .bind(member.address.toLowerCase(), nonce)
    .first<{ transaction_hash: string; status: string }>();
  if (!submission) throw new HttpError(404, 'NOT_FOUND');
  return json(submission);
}

/**
 * `POST /app/v1/stellar/relays`: a CCTP burn the member sent toward Stellar, which the relayer mints
 * once Circle attests it (seconds after, `StellarRelayer`).
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
  await relayer(env).wake();
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

/**
 * Every minute: registers members' Stellar addresses, finds burns toward them, has the relayer mint
 * what waits, and reads transfers.
 */
export async function syncStellar(env: Env, config: Config, budget: Budget): Promise<void> {
  const stellar = config.stellar;
  if (!stellar) return;
  await registerAccounts(env, stellar);
  await resolveSubmissions(env, stellar, budget).catch((error: unknown) => console.error(error));
  await findBurnsToMembers(env, config, stellar, budget);
  if (await relaysWaiting(env, RELAY_SECONDS)) await relayer(env).wake();
  await indexTransfers(env, stellar, budget).catch((error: unknown) =>
    readerFailed(env, stellar.id, error),
  );
}

/**
 * Writes each new member's Stellar address once, so the indexer and the notices find a member by
 * it without deriving every member's address on each run.
 */
async function registerAccounts(env: Env, stellar: Stellar) {
  const { results } = await env.WALLET_DB.prepare(
    'SELECT address FROM members WHERE stellar_address IS NULL LIMIT 500',
  ).all<{ address: Address }>();
  if (results.length === 0) return;
  await env.WALLET_DB.batch(
    results.map(({ address }) =>
      env.WALLET_DB.prepare('UPDATE members SET stellar_address = ? WHERE address = ?').bind(
        stellarAccount(stellar, address),
        address,
      ),
    ),
  );
}

/**
 * Burns toward members' Stellar accounts sent from any wallet (an exchange, MetaMask): the app
 * records its own, these are found in the DepositForBurn events of each network's TokenMessenger,
 * from the last block read on. They need no finality wait: Circle attests only final burns, and
 * one a reorg drops is never attested. A network whose source fails leaves its blocks for the next
 * run; the others are still read.
 */
async function findBurnsToMembers(env: Env, config: Config, stellar: Stellar, budget: Budget) {
  for (const network of config.networks.values()) {
    const key = `stellar-burns:${network.id}`;
    const read = await burnsToMembers(env, stellar, network, key, budget).catch(
      async (error: unknown) => {
        await readerFailed(env, key, error);
        return true;
      },
    );
    // Out of requests: the next networks wait for the next run.
    if (!read) return;
  }
}

/** One network's part of `findBurnsToMembers`; false when out of requests. */
async function burnsToMembers(
  env: Env,
  stellar: Stellar,
  network: Network,
  key: string,
  budget: Budget,
) {
  const forwarder = bytesToHex(StrKey.decodeContract(stellar.network.cctp.forwarder));
  const cursor = await readCursor(env, key);
  const read = await burnsSince(network, cursor === null ? null : BigInt(cursor) + 1n, budget);
  if (!read) return false;
  const found = read.burns.flatMap(({ transactionHash, args }) => {
    const recipient =
      args.destinationDomain === stellar.network.cctp.domain && args.mintRecipient === forwarder
        ? hookRecipient(args.hookData)
        : null;
    return recipient ? [{ transactionHash, recipient }] : [];
  });
  const members = await stellarMembers(
    env,
    found.map(({ recipient }) => recipient),
  );
  const now = Math.floor(Date.now() / 1000);
  const relays = found.flatMap(({ transactionHash, recipient }) => {
    const member = members.get(recipient);
    return member
      ? [
          env.WALLET_DB.prepare(
            `INSERT OR IGNORE INTO stellar_relays (source_network, transaction_hash, member_address, created_at)
             VALUES (?, ?, ?, ?)`,
          ).bind(network.id, transactionHash.toLowerCase(), member, now),
        ]
      : [];
  });
  const results = await env.WALLET_DB.batch([...relays, saveCursor(env, key, read.to)]);
  if (results.slice(0, relays.length).some(({ meta }) => meta.changes > 0))
    await relayer(env).wake();
  return true;
}

/**
 * The DepositForBurn events of `network` from block `from` on, and the last block read; on the
 * first run (`from` null), none, from the latest block on. Null when out of requests.
 */
async function burnsSince(network: Network, from: bigint | null, budget: Budget) {
  const source = network.index.hypersync;
  if (source) {
    if (!budget.take()) return null;
    if (from === null) return { burns: [], to: await hypersyncHeight(source) };
    const page = await hypersyncLogs(source, {
      address: network.cctp.tokenMessenger,
      topic0: toEventSelector(DEPOSIT_FOR_BURN),
      fromBlock: from,
    });
    return {
      burns: page.logs.map(({ transactionHash, topics, data }) => ({
        transactionHash,
        args: decodeEventLog({ abi: [DEPOSIT_FOR_BURN], topics, data }).args,
      })),
      to: page.nextBlock - 1n,
    };
  }
  const { client, range } = network.index;
  if (!budget.take()) return null;
  const latest = await client.getBlockNumber();
  if (from === null) return { burns: [], to: latest };
  const burns = [];
  let to = from - 1n;
  for (let round = 0; to < latest && round < BURN_ROUNDS && budget.take(); round++) {
    const end = to + range < latest ? to + range : latest;
    const logs = await client.getLogs({
      address: network.cctp.tokenMessenger,
      event: DEPOSIT_FOR_BURN,
      fromBlock: to + 1n,
      toBlock: end,
      strict: true,
    });
    burns.push(...logs.map(({ transactionHash, args }) => ({ transactionHash, args })));
    to = end;
  }
  return { burns, to };
}

/**
 * Mints attested burns toward Stellar that a member sent or that pay a member's Stellar account;
 * anyone could, so nothing is lost if it waits. A burn recorded for two members is minted once.
 */
async function relayBurns(
  env: Env,
  config: Config,
  stellar: Stellar,
  budget: Budget,
  send: (operation: xdr.Operation) => Promise<{ hash: string }>,
) {
  const { results } = await env.WALLET_DB.prepare(
    `SELECT source_network, transaction_hash, member_address FROM stellar_relays
     WHERE relayed_hash IS NULL AND created_at > ? LIMIT 20`,
  )
    .bind(Math.floor(Date.now() / 1000) - RELAY_SECONDS)
    .all<{ source_network: string; transaction_hash: string; member_address: Address }>();
  // Messages minted in this run: a burn registered by its sender and its recipient mints once.
  const minted = new Set<string>();
  for (const pending of results) {
    const network = config.networks.get(pending.source_network);
    if (!network) continue;
    // Circle's status, then the mint sent through the relayer.
    if (!budget.take(2)) return;
    const member = pending.member_address;
    // The member's own burn, also in a transaction that carries several.
    const ours = (message: Hex) => paysMember(stellar, message, member);
    const status = await crosschainStatus(
      network,
      pending.transaction_hash,
      AbortSignal.timeout(10_000),
      ours,
    ).catch(() => null);
    if (!status?.attested || minted.has(status.attested.message)) continue;
    if (!ours(status.attested.message)) {
      // Rejected for this member only: reporting someone else's burn cannot hold back theirs.
      await env.WALLET_DB.prepare(
        `UPDATE stellar_relays SET relayed_hash = 'rejected'
         WHERE source_network = ? AND transaction_hash = ? AND member_address = ?`,
      )
        .bind(pending.source_network, pending.transaction_hash, member)
        .run();
      continue;
    }
    try {
      const { hash } = await send(
        mintAndForwardOperation(
          stellar.network,
          status.attested.message,
          status.attested.attestation,
        ),
      );
      minted.add(status.attested.message);
      // Settled for every member this burn pays (its sender and its recipient), not for another
      // burn of the same transaction.
      const { results: waiting } = await env.WALLET_DB.prepare(
        `SELECT member_address FROM stellar_relays
         WHERE source_network = ? AND transaction_hash = ? AND relayed_hash IS NULL`,
      )
        .bind(pending.source_network, pending.transaction_hash)
        .all<{ member_address: Address }>();
      const paid = waiting.filter((row) =>
        paysMember(stellar, status.attested!.message, row.member_address),
      );
      await env.WALLET_DB.batch(
        paid.map((row) =>
          env.WALLET_DB.prepare(
            `UPDATE stellar_relays SET relayed_hash = ?
             WHERE source_network = ? AND transaction_hash = ? AND member_address = ?`,
          ).bind(hash, pending.source_network, pending.transaction_hash, row.member_address),
        ),
      );
    } catch {
      // Already minted by someone else, or the network failed: retried until the row expires.
    }
  }
}

/** Whether a CCTP burn `message` mints to Stellar for `member`: sent by them, or to their account. */
function paysMember(stellar: Stellar, message: Hex, member: Address) {
  const burn = burnMessage(message);
  return (
    burn.destinationDomain === stellar.network.cctp.domain &&
    (isAddressEqual(burn.sender, member) ||
      burn.recipient ===
        stellarAccountAddress(stellar.network, stellar.keypair.publicKey(), member))
  );
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
 * The `getEvents` requests that find USDC and XLM transfers from or to `accounts`: the RPC matches
 * the addresses, so only members' transfers are read (a testnet window holds hundreds of others,
 * more than a run's CPU can decode).
 */
function transferRequests(network: StellarNetwork, accounts: readonly string[]) {
  const transfer = xdr.ScVal.scvSymbol('transfer').toXdr('base64');
  const patterns = accounts.flatMap((account) => {
    const topic = new StellarAddress(account).toScVal().toXdr('base64');
    return [
      [transfer, topic, '*', '*'],
      [transfer, '*', topic, '*'],
    ];
  });
  const filters = [];
  for (let i = 0; i < patterns.length; i += PATTERNS_PER_FILTER)
    filters.push({
      type: 'contract' as const,
      contractIds: [network.usdc, network.xlm],
      topics: patterns.slice(i, i + PATTERNS_PER_FILTER),
    });
  const requests = [];
  for (let i = 0; i < filters.length; i += FILTERS_PER_REQUEST)
    requests.push(filters.slice(i, i + FILTERS_PER_REQUEST));
  return requests;
}

/**
 * Reads members' USDC and XLM transfer events since the last ledger read, notifying what they
 * received. After a stop it catches up from there, a few windows per run, as far back as the RPC
 * keeps events (about a week on the public one).
 */
export async function indexTransfers(env: Env, stellar: Stellar, budget: Budget) {
  const { server, network } = stellar;
  if (!budget.take()) return;
  // `getHealth`, not `getLatestLedger`: the SDK decodes the whole ledger's metadata for that one.
  const { latestLedger: latest, oldestLedger } = await server.getHealth();
  const cursor = await readCursor(env, stellar.id);
  let from = cursor === null ? latest : cursor + 1;
  // A stop longer than the RPC keeps: the ledgers it no longer has are recorded as missed, not
  // skipped silently, and reading goes on from the oldest it has.
  if (from < oldestLedger) {
    console.error(`Stellar ledgers ${from}-${oldestLedger - 1} are no longer kept by the RPC`);
    await env.WALLET_DB.batch([
      missedUntil(env, stellar.id, oldestLedger - 1),
      clearProgress(env, stellar.id),
    ]);
    from = oldestLedger;
  }
  const { results: accounts } = await env.WALLET_DB.prepare(
    'SELECT stellar_address FROM members WHERE stellar_address IS NOT NULL',
  ).all<{ stellar_address: string }>();
  const requests = transferRequests(
    network,
    accounts.map(({ stellar_address }) => stellar_address),
  );
  // A run that ran out of requests in the middle of a window left where it was in it: the next
  // group of members to read and the window's last ledger, so it goes on instead of starting over.
  const partial = await readCursor(env, `range:${stellar.id}`);
  let group = partial === null ? 0 : ((await readCursor(env, `group:${stellar.id}`)) ?? 0);
  for (let round = 0; from <= latest && round < ROUNDS; round++) {
    const to = partial !== null && round === 0 ? partial : Math.min(from + RANGE - 1, latest);
    for (; group < requests.length; group++) {
      // Out of requests: this group is read again on the next run.
      if (!budget.take()) return;
      const filters = requests[group];
      const events: rpc.Api.EventResponse[] = [];
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
      const done = group + 1 === requests.length;
      await storeStellarTransfers(env, stellar, events, [
        // Once every group read the window, the cursor moves past it.
        ...(done
          ? [saveCursor(env, stellar.id, to), clearProgress(env, stellar.id)]
          : saveProgress(env, stellar.id, group + 1, to)),
      ]);
    }
    // Without members there is nothing to read: the window is passed all the same.
    if (requests.length === 0) await saveCursor(env, stellar.id, to).run();
    group = 0;
    from = to + 1;
  }
}

/** Mid-window progress of the indexer: the next group of members, and the window's end. */
const saveProgress = (env: Env, id: string, group: number, to: number) => [
  saveCursor(env, `group:${id}`, group),
  saveCursor(env, `range:${id}`, to),
];

const clearProgress = (env: Env, id: string) =>
  env.WALLET_DB.prepare('DELETE FROM index_cursors WHERE network IN (?, ?)').bind(
    `group:${id}`,
    `range:${id}`,
  );

/**
 * Keeps the members' transfers among `events`, with `progress` in the same batch; a recent one a
 * member received is stored with its notification pending (`sendNotifications`). A transfer
 * between two members comes in two groups: the second finds it stored and changes nothing.
 */
async function storeStellarTransfers(
  env: Env,
  stellar: Stellar,
  events: rpc.Api.EventResponse[],
  progress: D1PreparedStatement[],
) {
  const { network } = stellar;
  const transfers = events
    .map((event) => transferOf(network, event))
    .filter((transfer) => transfer !== null);
  const members = await stellarMembers(
    env,
    transfers.flatMap(({ from, to }) => [from, to]),
  );
  const kept = transfers.filter(({ from, to }) => members.has(from) || members.has(to));
  const crosschain = [network.cctp.tokenMessengerMinter, network.cctp.forwarder];
  const now = Math.floor(Date.now() / 1000);
  await env.WALLET_DB.batch([
    ...kept.map((transfer) =>
      env.WALLET_DB.prepare(
        `INSERT OR IGNORE INTO transfers (network, transaction_hash, log_index, block_number,
           timestamp, from_address, to_address, amount, kind, token, notify_at)
         VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`,
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
        members.has(transfer.to) && transfer.timestamp >= now - NOTIFY_SECONDS ? now : null,
      ),
    ),
    ...progress,
  ]);
}

/**
 * The network that USDC minted on Stellar came from: Wallet Core relayed that mint itself, from a
 * burn it recorded (`stellar_relays`). Null when the mint was not one of its relays.
 */
export async function relayOrigin(env: Env, transactionHash: string) {
  const source = await env.WALLET_DB.prepare(
    'SELECT source_network FROM stellar_relays WHERE relayed_hash = ?',
  )
    .bind(transactionHash)
    .first<string>('source_network');
  return source && Object.hasOwn(walletNetworks, source)
    ? walletNetworks[source as keyof typeof walletNetworks].chain.name
    : null;
}

/**
 * Members' Stellar addresses among `addresses`, each with the member's EVM address. D1 binds at
 * most 100 parameters per statement.
 */
async function stellarMembers(env: Env, addresses: string[]) {
  const unique = [...new Set(addresses)];
  const members = new Map<string, string>();
  for (let i = 0; i < unique.length; i += 99) {
    const batch = unique.slice(i, i + 99);
    const { results } = await env.WALLET_DB.prepare(
      `SELECT stellar_address, address FROM members
       WHERE stellar_address IN (${batch.map(() => '?').join(',')})`,
    )
      .bind(...batch)
      .all<{ stellar_address: string; address: string }>();
    for (const row of results) members.set(row.stellar_address, row.address);
  }
  return members;
}
