import { createExecutionContext, createScheduledController } from 'cloudflare:test';
import { env, exports } from 'cloudflare:workers';
import { afterEach, beforeEach, describe, expect, it, vi } from 'vitest';
import {
  bytesToHex,
  createPublicClient,
  encodeFunctionData,
  erc20Abi,
  hexToBytes,
  http,
  sha256,
  toHex,
  type Hex,
} from 'viem';
import {
  createBundlerClient,
  createPaymasterClient,
  type WebAuthnAccount,
} from 'viem/account-abstraction';
import { createSiweMessage } from 'viem/siwe';
import { walletContracts, walletNetworks } from '@gatopago/shared/networks';
import {
  gatopagoAccountAbi,
  passkeyOwner,
  signApproval,
  toGatoPagoAccount,
  type GatoPagoAccount,
} from '@gatopago/shared/wallet';
import worker, { WalletIdentity } from '../src/index';

const API = 'https://api.gatopago.com/app/v1';
const FORK_RPC = 'http://127.0.0.1:8711';
const { chain, usdc } = walletNetworks['eip155:421614'];
const client = createPublicClient({ chain, transport: http(FORK_RPC) });

const base64url = (bytes: Uint8Array) =>
  btoa(String.fromCharCode(...bytes))
    .replaceAll('+', '-')
    .replaceAll('/', '_')
    .replace(/=+$/, '');

/** Software passkey producing the same bytes as `navigator.credentials.get`. */
async function softwarePasskey(): Promise<WebAuthnAccount> {
  const keys = (await crypto.subtle.generateKey({ name: 'ECDSA', namedCurve: 'P-256' }, false, [
    'sign',
    'verify',
  ])) as CryptoKeyPair;
  const publicKey = new Uint8Array(
    (await crypto.subtle.exportKey('raw', keys.publicKey)) as ArrayBuffer,
  );
  return {
    id: 'software-passkey',
    publicKey: bytesToHex(publicKey.slice(1)),
    type: 'webAuthn',
    async sign({ hash }) {
      const authenticatorData: Hex = `${sha256(new TextEncoder().encode('gatopago.com'))}0500000000`;
      const clientDataJSON = `{"type":"webauthn.get","challenge":"${base64url(hexToBytes(hash))}","origin":"https://gatopago.com","crossOrigin":false}`;
      const signed = new Uint8Array([
        ...hexToBytes(authenticatorData),
        ...hexToBytes(sha256(new TextEncoder().encode(clientDataJSON))),
      ]);
      const signature = await crypto.subtle.sign(
        { name: 'ECDSA', hash: 'SHA-256' },
        keys.privateKey,
        signed,
      );
      return {
        signature: toHex(new Uint8Array(signature)),
        raw: {} as never,
        webauthn: {
          authenticatorData,
          clientDataJSON,
          challengeIndex: 23,
          typeIndex: 1,
          userVerificationRequired: true,
        },
      };
    },
    async signMessage() {
      throw new Error('unused');
    },
    async signTypedData() {
      throw new Error('unused');
    },
  };
}

const newAccount = async () =>
  toGatoPagoAccount({ client, owner: await softwarePasskey(), contracts: walletContracts });

function api(
  path: string,
  init: { method?: string; body?: unknown; token?: string; headers?: HeadersInit } = {},
) {
  const headers = new Headers(init.headers);
  if (init.token) headers.set('Authorization', `Bearer ${init.token}`);
  if (init.body !== undefined) headers.set('Content-Type', 'application/json');
  return exports.default.fetch(
    new Request(`${API}/${path}`, {
      method: init.method ?? (init.body === undefined ? 'GET' : 'POST'),
      headers,
      body: init.body === undefined ? undefined : JSON.stringify(init.body),
    }),
  );
}

async function siwe(account: GatoPagoAccount) {
  const { nonce } = await (await api('auth/nonce', { method: 'POST' })).json<{ nonce: string }>();
  const message = createSiweMessage({
    domain: 'gatopago.com',
    uri: 'https://gatopago.com',
    address: account.address,
    chainId: chain.id,
    nonce,
    version: '1',
    issuedAt: new Date(),
  });
  return { message, signature: await account.signMessage({ message }) };
}

async function signIn(
  account: GatoPagoAccount,
  extra: { invite?: string; turnstile?: string } = {},
) {
  return api('auth/session', { body: { ...(await siwe(account)), ...extra } });
}

let invites = 0;
async function invite() {
  const code = `invite-${++invites}`;
  await env.WALLET_DB.prepare(
    'INSERT INTO invites (code, issued_by, created_at, expires_at) VALUES (?, ?, ?, ?)',
  )
    .bind(code, 'test', 0, Math.floor(Date.now() / 1000) + 3600)
    .run();
  return code;
}

/** Signs up `account` and returns its session token. */
async function member(account: GatoPagoAccount) {
  const response = await signIn(account, { invite: await invite(), turnstile: 'human' });
  expect(response.status).toBe(200);
  return (await response.json<{ token: string }>()).token;
}

beforeEach(() => {
  const fetch = globalThis.fetch;
  vi.spyOn(globalThis, 'fetch').mockImplementation(async (input, init) => {
    const url = input instanceof Request ? input.url : String(input);
    if (!url.startsWith('https://challenges.cloudflare.com/')) return fetch(input, init);
    const token = new URLSearchParams(String(init?.body)).get('response');
    return Response.json({ success: token === 'human', hostname: 'gatopago.com' });
  });
});
afterEach(() => vi.restoreAllMocks());

describe('routing', () => {
  it('answers health, unknown routes and CORS preflight', async () => {
    expect(await (await api('health')).json()).toEqual({ status: 'ok' });
    expect((await api('nothing')).status).toBe(404);
    const preflight = await api('profile', {
      method: 'OPTIONS',
      headers: { Origin: 'https://gatopago.com' },
    });
    expect(preflight.status).toBe(204);
    expect(preflight.headers.get('Access-Control-Allow-Origin')).toBe('https://gatopago.com');
    const foreign = await api('profile', {
      method: 'OPTIONS',
      headers: { Origin: 'https://evil.example' },
    });
    expect(foreign.headers.get('Access-Control-Allow-Origin')).toBeNull();
  });
});

describe('sign-in with Ethereum', () => {
  it('admits an undeployed account with an invitation, then signs it in with the account alone', async () => {
    const account = await newAccount();
    expect(await client.getCode({ address: account.address })).toBeUndefined();
    expect(await (await signIn(account)).json()).toEqual({ error_code: 'INVITE_REQUIRED' });
    const code = await invite();
    expect(await (await signIn(account, { invite: code, turnstile: 'robot' })).json()).toEqual({
      error_code: 'TURNSTILE_FAILED',
    });

    const joined = await signIn(account, { invite: code, turnstile: 'human' });
    expect(joined.status).toBe(200);
    const session = await joined.json<{ token: string; user_id: string; address: string }>();
    expect(session.user_id).toMatch(/^usr_/);
    expect(session.address).toBe(account.address);

    const again = await (await signIn(account)).json<{ user_id: string }>();
    expect(again.user_id).toBe(session.user_id);
    expect(
      await (await signIn(await newAccount(), { invite: code, turnstile: 'human' })).json(),
    ).toEqual({
      error_code: 'INVITE_INVALID',
    });
  });

  it('rejects a reused nonce and a signature from another account', async () => {
    const account = await newAccount();
    await member(account);
    const signed = await siwe(account);
    expect((await api('auth/session', { body: signed })).status).toBe(200);
    expect(await (await api('auth/session', { body: signed })).json()).toEqual({
      error_code: 'NONCE_INVALID',
    });

    const forged = await siwe(account);
    const signature = await (await newAccount()).signMessage({ message: forged.message });
    expect(await (await api('auth/session', { body: { ...forged, signature } })).json()).toEqual({
      error_code: 'SIGNATURE_INVALID',
    });
  });

  it('identifies the session for Flow through WalletIdentity', async () => {
    const token = await member(await newAccount());
    const identity = new WalletIdentity(createExecutionContext(), env);
    const ask = (authorization: string, environment = 'production') =>
      identity.fetch(
        new Request('https://wallet-identity.internal/session', {
          method: 'POST',
          headers: { Authorization: authorization, 'X-GatoPago-Environment': environment },
        }),
      );
    const answer = await (
      await ask(`Bearer ${token}`)
    ).json<{ user_id: string; expires_at: number }>();
    expect(answer.user_id).toMatch(/^usr_/);
    expect(answer.expires_at).toBeLessThanOrEqual(Math.floor(Date.now() / 1000) + 30);
    expect((await ask('Bearer not.a.token')).status).toBe(401);
    expect((await ask(`Bearer ${token}`, 'staging')).status).toBe(503);
  });
});

describe('profile', () => {
  it('sets the username once and resolves recipients by it', async () => {
    const account = await newAccount();
    const token = await member(account);
    const address = account.address.toLowerCase();
    expect((await api('profile')).status).toBe(401);
    const updated = await api('profile', {
      method: 'PUT',
      token,
      body: { username: 'gato_1', display_name: ' Gato ' },
    });
    expect(await updated.json()).toMatchObject({
      username: 'gato_1',
      display_name: 'Gato',
      address,
    });
    expect(
      await (await api('profile', { method: 'PUT', token, body: { username: 'gato_2' } })).json(),
    ).toEqual({
      error_code: 'USERNAME_ALREADY_SET',
    });
    const rival = await member(await newAccount());
    expect(
      await (
        await api('profile', { method: 'PUT', token: rival, body: { username: 'gato_1' } })
      ).json(),
    ).toEqual({ error_code: 'USERNAME_TAKEN' });
    expect(await (await api('recipients/gato_1')).json()).toEqual({
      username: 'gato_1',
      display_name: 'Gato',
      address,
    });
    expect((await api('recipients/nobody')).status).toBe(404);
  });
});

describe('sponsored operations', () => {
  const bundlerFor = (account: GatoPagoAccount, token: string) => {
    const transport = (service: string) =>
      http(`${API}/${service}/eip155:${chain.id}`, {
        fetchFn: (url, init) => exports.default.fetch(new Request(url, init)),
        fetchOptions: { headers: { Authorization: `Bearer ${token}` } },
      });
    return createBundlerClient({
      account,
      client,
      transport: transport('bundler'),
      paymaster: createPaymasterClient({ transport: transport('paymaster') }),
    });
  };
  const approveNothing = {
    to: usdc,
    data: encodeFunctionData({ abi: erc20Abi, functionName: 'approve', args: [usdc, 0n] }),
  };

  it('deploys the account and runs its calls, within the daily budget', async () => {
    const account = await newAccount();
    const bundler = bundlerFor(account, await member(account));
    const hash = await bundler.sendUserOperation({ calls: [approveNothing] });
    expect((await bundler.waitForUserOperationReceipt({ hash })).success).toBe(true);
    expect(await client.getCode({ address: account.address })).toBeDefined();

    await env.WALLET_DB.prepare('UPDATE sponsorship_usage SET operations = 50 WHERE account = ?')
      .bind(account.address.toLowerCase())
      .run();
    await expect(bundler.sendUserOperation({ calls: [approveNothing] })).rejects.toThrow(/429/);
  });

  it('sponsors only the signed-in account', async () => {
    const account = await newAccount();
    await member(account);
    const intruder = await member(await newAccount());
    await expect(
      bundlerFor(account, intruder).sendUserOperation({ calls: [approveNothing] }),
    ).rejects.toThrow(/403/);
  });
});

describe('approvals', () => {
  it('stores approvals verified against the account owners, in order', async () => {
    const account = await newAccount();
    const token = await member(account);
    const backup = passkeyOwner(
      walletContracts.webAuthnVerifier,
      (await softwarePasskey()).publicKey,
    );
    const call = encodeFunctionData({
      abi: gatopagoAccountAbi,
      functionName: 'addOwners',
      args: [[backup]],
    });
    const signature = await signApproval(account, 0n, call);
    const body = { call, signature, initial_owners: account.initialOwners };
    const path = `approvals/${account.address}`;

    expect((await api(path, { token: await member(await newAccount()), body })).status).toBe(403);
    expect(
      await (await api(path, { token, body: { ...body, initial_owners: [backup] } })).json(),
    ).toEqual({
      error_code: 'INITIAL_OWNERS_INVALID',
    });
    const stored = await api(path, { token, body });
    expect(stored.status).toBe(201);
    expect(await stored.json()).toEqual({ sequence: 0 });
    expect(await (await api(path, { token, body })).json()).toEqual({
      error_code: 'APPROVAL_INVALID',
    });
    expect(await (await api(path)).json()).toEqual({
      initial_owners: account.initialOwners,
      approvals: [{ sequence: 0, call, signature }],
    });
  });
});

describe('scheduled', () => {
  it('forgets expired nonces and old sponsorship counters', async () => {
    await env.WALLET_DB.batch([
      env.WALLET_DB.prepare("INSERT INTO siwe_nonces (nonce, expires_at) VALUES ('expired', 1)"),
      env.WALLET_DB.prepare(
        "INSERT INTO sponsorship_usage (account, day, operations) VALUES ('0x0', 1, 1)",
      ),
    ]);
    await worker.scheduled(createScheduledController(), env);
    expect(
      await env.WALLET_DB.prepare("SELECT 1 FROM siwe_nonces WHERE nonce = 'expired'").first(),
    ).toBeNull();
    expect(
      await env.WALLET_DB.prepare("SELECT 1 FROM sponsorship_usage WHERE account = '0x0'").first(),
    ).toBeNull();
  });
});
