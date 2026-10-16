import {
  decodeEventLog,
  getAddress,
  hexToBytes,
  isAddress,
  isHex,
  keccak256,
  stringToHex,
  type Address,
  type Hex,
} from 'viem';
import { coinOf, NATIVE_LOG_INDEX, storeTransfers, transferEvent, type Transfer } from './activity';
import { Budget } from './budget';
import type { Config, Network } from './config';
import { HttpError, json, readBody } from './http';
import { sendNotifications } from './notifications';

interface ActivityEvent {
  webhookId?: string;
  type?: string;
  event?: {
    activity?: {
      /**
       * `external`: a transaction's own value in the native coin; `internal`: native coin moved by
       * a call inside a transaction (a smart account paying); `token`: a log.
       */
      category?: string;
      /** An internal transfer's call and place in the trace (`call_0_1`): unique in its transaction. */
      typeTraceAddress?: string;
      fromAddress?: string;
      toAddress?: string;
      hash?: string;
      blockNum?: string;
      rawContract?: { rawValue?: string; address?: string | null };
      log?: {
        address: Address;
        topics: [Hex, ...Hex[]];
        data: Hex;
        blockNumber: Hex;
        transactionHash: Hex;
        logIndex: Hex;
        removed: boolean;
      };
    }[];
  };
}

type Activity = NonNullable<NonNullable<ActivityEvent['event']>['activity']>[number];

/**
 * The log index of an internal transfer, which has no log: below `NATIVE_LOG_INDEX`, from 48 bits of
 * the hash of its place in the trace, so two in one transaction never share a row.
 */
const traceIndex = (trace: string) =>
  NATIVE_LOG_INDEX - 1 - Number(BigInt(keccak256(stringToHex(trace)).slice(0, 14)));

/**
 * A transfer of the native coin, or null: a transaction's own value sent straight to an address
 * (Alchemy's `external`), or a call inside a transaction (`internal`), as when a smart account pays:
 * its transaction goes to the EntryPoint. Alchemy reports internal ones on Arbitrum and Avalanche,
 * not on Monad, and only by webhook: the reconciliation reads logs and transactions, not traces.
 */
function nativeTransfer(activity: Activity): Transfer | null {
  const { category, fromAddress, toAddress, hash, blockNum, rawContract, typeTraceAddress } =
    activity;
  const internal = category === 'internal';
  if (
    (category !== 'external' && !(internal && typeTraceAddress)) ||
    rawContract?.address ||
    !fromAddress ||
    !toAddress ||
    !isAddress(fromAddress) ||
    !isAddress(toAddress) ||
    !isHex(hash) ||
    !isHex(blockNum) ||
    !isHex(rawContract?.rawValue) ||
    BigInt(rawContract.rawValue) === 0n
  )
    return null;
  return {
    transactionHash: hash,
    logIndex: internal ? traceIndex(typeTraceAddress!) : NATIVE_LOG_INDEX,
    blockNumber: BigInt(blockNum),
    token: null,
    from: getAddress(fromAddress),
    to: getAddress(toAddress),
    value: BigInt(rawContract.rawValue),
  };
}

async function signedBy(signingKey: string, body: string, signature: string | null) {
  if (!signature || !isHex(`0x${signature}`)) return false;
  const key = await crypto.subtle.importKey(
    'raw',
    new TextEncoder().encode(signingKey),
    { name: 'HMAC', hash: 'SHA-256' },
    false,
    ['verify'],
  );
  return crypto.subtle.verify(
    'HMAC',
    key,
    new Uint8Array(hexToBytes(`0x${signature}`)),
    new TextEncoder().encode(body),
  );
}

/**
 * `POST /app/v1/webhooks/alchemy`: an Address Activity event, signed with its webhook's key. Keeps
 * the members' transfers of the configured coins and of the native coin, sent by a transaction or
 * by a contract, and forgets those a reorg removed.
 */
export async function receiveAlchemyWebhook(
  request: Request,
  env: Env,
  config: Config,
): Promise<Response> {
  // Read up to 1 MB and no further: the signature is checked on these same bytes below.
  const body = await readBody(request, 1_000_000);
  let payload: ActivityEvent;
  try {
    payload = JSON.parse(body);
  } catch {
    throw new HttpError(400, 'INVALID_JSON');
  }
  const network = [...config.networks.values()].find(
    (candidate) => candidate.webhook && candidate.webhook.id === payload.webhookId,
  );
  if (
    !network?.webhook ||
    !(await signedBy(network.webhook.signingKey, body, request.headers.get('X-Alchemy-Signature')))
  )
    throw new HttpError(401, 'INVALID_SIGNATURE');
  if (payload.type !== 'ADDRESS_ACTIVITY') return json({});

  const added: Transfer[] = [];
  const removed: D1PreparedStatement[] = [];
  for (const activity of payload.event?.activity ?? []) {
    const { log } = activity;
    if (!log) {
      const native = nativeTransfer(activity);
      if (native) added.push(native);
      continue;
    }
    if (!coinOf(network, log.address)) continue;
    let args;
    try {
      ({ args } = decodeEventLog({ abi: [transferEvent], topics: log.topics, data: log.data }));
    } catch {
      continue;
    }
    const transfer = {
      transactionHash: log.transactionHash,
      logIndex: Number(log.logIndex),
      blockNumber: BigInt(log.blockNumber),
      token: log.address,
      from: args.from,
      to: args.to,
      value: args.value,
    };
    if (log.removed)
      removed.push(
        env.WALLET_DB.prepare(
          'DELETE FROM transfers WHERE network = ? AND transaction_hash = ? AND log_index = ?',
        ).bind(network.id, transfer.transactionHash, transfer.logIndex),
      );
    else added.push(transfer);
  }
  // Without a budget it always stores.
  const stored = (await storeTransfers(env, network, added))!;
  const statements = [...removed, ...stored.statements];
  if (statements.length === 0) return json({});
  // Webhooks retry and the reconciliation may have stored it first: a stored row is not marked
  // again, so it is notified once.
  await env.WALLET_DB.batch(statements);
  await sendNotifications(env, config, new Budget(config.subrequestsPerRun)).catch(
    (error: unknown) => console.error(error),
  );
  return json({});
}

/**
 * Adds members' addresses to each network's webhook, so their activity is delivered: new members,
 * and all of them when a webhook is replaced or a network added (`member_networks` keeps which
 * webhook has each address). A webhook that fails waits for the next run; the others go on.
 */
export async function watchMembers(env: Env, config: Config, budget: Budget): Promise<void> {
  if (!config.alchemyAuthToken) return;
  for (const network of config.networks.values())
    if (network.webhook)
      await watchOn(env, network, network.webhook.id, config.alchemyAuthToken, budget).catch(
        (error: unknown) => console.error(error),
      );
}

async function watchOn(env: Env, network: Network, webhook: string, token: string, budget: Budget) {
  const { results } = await env.WALLET_DB.prepare(
    `SELECT members.address FROM members
     LEFT JOIN member_networks ON member_networks.address = members.address
       AND member_networks.network = ?
     WHERE member_networks.webhook IS NOT ? LIMIT 1000`,
  )
    .bind(network.id, webhook)
    .all<{ address: string }>();
  if (results.length === 0 || !budget.take()) return;
  const addresses = results.map((row) => row.address);
  const response = await fetch('https://dashboard.alchemy.com/api/update-webhook-addresses', {
    method: 'PATCH',
    headers: { 'Content-Type': 'application/json', 'X-Alchemy-Token': token },
    body: JSON.stringify({
      webhook_id: webhook,
      addresses_to_add: addresses,
      addresses_to_remove: [],
    }),
  });
  if (!response.ok)
    throw new Error(`ALCHEMY_WEBHOOK_UPDATE_FAILED: ${network.id} ${response.status}`);
  // D1 binds at most 100 parameters per statement: the network, the webhook and 98 addresses.
  const statements = [];
  for (let i = 0; i < addresses.length; i += 98) {
    const batch = addresses.slice(i, i + 98);
    statements.push(
      env.WALLET_DB.prepare(
        `INSERT INTO member_networks (address, network, webhook)
         SELECT address, ?1, ?2 FROM members
         WHERE address IN (${batch.map((_, j) => `?${j + 3}`).join(', ')})
         ON CONFLICT (address, network) DO UPDATE SET webhook = excluded.webhook`,
      ).bind(network.id, webhook, ...batch),
    );
  }
  await env.WALLET_DB.batch(statements);
}
