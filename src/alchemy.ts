import { decodeEventLog, hexToBytes, isAddressEqual, isHex, type Address, type Hex } from 'viem';
import { storeTransfers, transferEvent, type Transfer } from './activity';
import type { Config } from './config';
import { HttpError, json } from './http';
import { notifyReceived } from './push';

interface ActivityEvent {
  webhookId?: string;
  type?: string;
  event?: {
    activity?: {
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
 * the USDC transfers involving members and forgets those a reorg removed.
 */
export async function receiveAlchemyWebhook(
  request: Request,
  env: Env,
  config: Config,
): Promise<Response> {
  const body = await request.text();
  if (body.length > 1_000_000) throw new HttpError(413, 'BODY_TOO_LARGE');
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
  for (const { log } of payload.event?.activity ?? []) {
    if (!log || !isAddressEqual(log.address, network.usdc)) continue;
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
  const stored = await storeTransfers(env, network, added);
  const statements = [...removed, ...stored.statements];
  if (statements.length === 0) return json({});
  const results = await env.WALLET_DB.batch(statements);
  // Webhooks retry and the reconciliation may have stored it first: notify new rows only.
  const fresh = stored.kept.filter((_, i) => results[removed.length + i].meta.changes > 0);
  await notifyReceived(env, config, fresh).catch((error: unknown) => console.error(error));
  return json({});
}

/** Adds the addresses of new members to every network's webhook, so their activity is delivered. */
export async function watchMembers(env: Env, config: Config): Promise<void> {
  const webhooks = [...config.networks.values()].flatMap((network) =>
    network.webhook ? [network.webhook.id] : [],
  );
  if (!config.alchemyAuthToken || webhooks.length === 0) return;
  const { results } = await env.WALLET_DB.prepare(
    'SELECT address FROM members WHERE watched = 0 LIMIT 1000',
  ).all<{ address: string }>();
  if (results.length === 0) return;
  const addresses = results.map((row) => row.address);
  for (const webhookId of webhooks) {
    const response = await fetch('https://dashboard.alchemy.com/api/update-webhook-addresses', {
      method: 'PATCH',
      headers: { 'Content-Type': 'application/json', 'X-Alchemy-Token': config.alchemyAuthToken },
      body: JSON.stringify({
        webhook_id: webhookId,
        addresses_to_add: addresses,
        addresses_to_remove: [],
      }),
    });
    if (!response.ok) throw new Error(`ALCHEMY_WEBHOOK_UPDATE_FAILED: ${response.status}`);
  }
  const statements = [];
  for (let i = 0; i < addresses.length; i += 100) {
    const batch = addresses.slice(i, i + 100);
    statements.push(
      env.WALLET_DB.prepare(
        `UPDATE members SET watched = 1 WHERE address IN (${batch.map(() => '?').join(',')})`,
      ).bind(...batch),
    );
  }
  await env.WALLET_DB.batch(statements);
}
