import { createExecutionContext, createScheduledController } from 'cloudflare:test';
import { env, exports } from 'cloudflare:workers';
import { afterEach, beforeEach, describe, expect, it, vi } from 'vitest';
import {
  bytesToHex,
  createPublicClient,
  createTestClient,
  encodeFunctionData,
  erc20Abi,
  hexToBytes,
  http,
  parseEther,
  sha256,
  toHex,
  walletActions,
  type Hex,
  type Log,
} from 'viem';
import {
  createBundlerClient,
  createPaymasterClient,
  type WebAuthnAccount,
} from 'viem/account-abstraction';
import { generatePrivateKey, privateKeyToAccount } from 'viem/accounts';
import { createSiweMessage } from 'viem/siwe';
import { Keypair, nativeToScVal, rpc, Address as StellarAddress, xdr } from '@stellar/stellar-sdk';
import { stellarNetworks, walletContracts, walletNetworks } from '@gatopago/shared/networks';
import {
  addSignerOperation,
  prepareStellarCall,
  signStellarAuth,
  stellarAccountAddress,
  stellarAccountExists,
  stellarKeyApproval,
  transferOperation,
  type StellarKey,
} from '@gatopago/shared/stellar';
import { swapPools } from '@gatopago/shared/swap';
import {
  gatopagoAccountAbi,
  keyOwner,
  passkeyOwner,
  signApproval,
  toGatoPagoAccount,
  type GatoPagoAccount,
} from '@gatopago/shared/wallet';
import worker, { WalletIdentity } from '../src/index';
import { coinOf } from '../src/activity';
import type { Network } from '../src/config';

const API = 'https://api.gatopago.com/app/v1';
/** The real fetch, for mocks that only answer some services. */
const realFetch = globalThis.fetch;
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

/** Each test account signs in from its own address, as people do, within the per-IP rate limit. */
const from = (account: GatoPagoAccount) => ({ 'CF-Connecting-IP': account.address });

async function siwe(account: GatoPagoAccount) {
  const { nonce } = await (
    await api('auth/nonce', { method: 'POST', headers: from(account) })
  ).json<{ nonce: string }>();
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
  return api('auth/session', {
    body: { ...(await siwe(account)), ...extra },
    headers: from(account),
  });
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

  it('admits anyone who passes Turnstile while sign-up is open, and says which mode is on', async () => {
    const open = { ...env, INVITE_ONLY: 'off' };
    const call = async (path: string, init: RequestInit = {}) =>
      worker.fetch!(
        new Request(`${API}/${path}`, init) as Parameters<NonNullable<typeof worker.fetch>>[0],
        open,
      );
    expect(await (await api('auth/signup')).json()).toEqual({ invite_required: true });
    expect(await (await call('auth/signup')).json()).toEqual({ invite_required: false });

    const account = await newAccount();
    const headers = { ...from(account), 'Content-Type': 'application/json' };
    const signed = async (extra: Record<string, string>) =>
      call('auth/session', {
        method: 'POST',
        headers,
        body: JSON.stringify({ ...(await siwe(account)), ...extra }),
      });
    // Turnstile is still required; no invitation is.
    expect(await (await signed({})).json()).toEqual({ error_code: 'INVITE_REQUIRED' });
    const joined = await signed({ turnstile: 'human' });
    expect(joined.status).toBe(200);
    expect(
      await env.WALLET_DB.prepare(
        `SELECT invites.issued_by FROM members JOIN invites ON invites.code = members.invite_code
         WHERE members.address = ?`,
      )
        .bind(account.address.toLowerCase())
        .first('issued_by'),
    ).toBe('open-signup');
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

describe('GatoPago Business sign-in', () => {
  const identity = (token: string) =>
    new WalletIdentity(createExecutionContext(), env).fetch(
      new Request('https://wallet-identity.internal/session', {
        method: 'POST',
        headers: { Authorization: `Bearer ${token}`, 'X-GatoPago-Environment': 'production' },
      }),
    );

  it('signs the console in once the member approves its QR with their passkey', async () => {
    const account = await newAccount();
    const token = await member(account);
    const request = await (
      await api('business-login', { body: { device: 'Chrome · Windows' }, headers: from(account) })
    ).json<{ id: string; secret: string; approve_url: string }>();
    expect(request.approve_url).toBe(`https://gatopago.com/approve?request=${request.id}`);
    const collect = (secret = request.secret) =>
      api(`business-login/${request.id}`, { token: secret });
    expect(await (await collect()).json()).toEqual({ status: 'pending' });
    // The id in the QR is not enough to collect the session.
    expect((await collect(`0x${'0'.repeat(64)}`)).status).toBe(404);
    expect(await (await api(`business-approvals/${request.id}`, { token })).json()).toMatchObject({
      device: 'Chrome · Windows',
    });

    const approval = async (signer: GatoPagoAccount, nonce = request.id) => {
      const message = createSiweMessage({
        domain: 'gatopago.com',
        uri: 'https://gatopago.com',
        address: account.address,
        chainId: chain.id,
        nonce,
        version: '1',
        issuedAt: new Date(),
      });
      return { message, signature: await signer.signMessage({ message }) };
    };
    const approve = async (body: unknown) =>
      (await api(`business-approvals/${request.id}`, { token, body })).json();
    expect(await approve(await approval(account, 'another1request'))).toEqual({
      error_code: 'INVALID_MESSAGE',
    });
    expect(await approve(await approval(await newAccount()))).toEqual({
      error_code: 'SIGNATURE_INVALID',
    });
    expect(await approve(await approval(account))).toEqual({ approved: true });
    expect(await approve(await approval(account))).toEqual({ error_code: 'LOGIN_EXPIRED' });

    const session = await (await collect()).json<{ status: string; token: string }>();
    expect(session.status).toBe('approved');
    expect(await (await collect()).json()).toEqual({ status: 'expired' });
    // A Business session works for Flow, never for the wallet.
    expect((await identity(session.token)).status).toBe(200);
    expect((await api('profile', { token: session.token })).status).toBe(401);
  });

  it('signs in with the same passkey on the console, for members only', async () => {
    const siweBusiness = async (account: GatoPagoAccount) => {
      const { nonce } = await (
        await api('auth/nonce', { method: 'POST', headers: from(account) })
      ).json<{ nonce: string }>();
      const message = createSiweMessage({
        domain: 'business.gatopago.com',
        uri: 'https://business.gatopago.com',
        address: account.address,
        chainId: chain.id,
        nonce,
        version: '1',
        issuedAt: new Date(),
      });
      return api('auth/session', {
        body: { message, signature: await account.signMessage({ message }) },
        headers: from(account),
      });
    };
    const stranger = await newAccount();
    expect(await (await siweBusiness(stranger)).json()).toEqual({
      error_code: 'ACCOUNT_NOT_FOUND',
    });
    const account = await newAccount();
    await member(account);
    const { token } = await (await siweBusiness(account)).json<{ token: string }>();
    expect((await identity(token)).status).toBe(200);
    expect((await api('profile', { token })).status).toBe(401);
    const preflight = await api('business-login', {
      method: 'OPTIONS',
      headers: { Origin: 'https://business.gatopago.com' },
    });
    expect(preflight.headers.get('Access-Control-Allow-Origin')).toBe(
      'https://business.gatopago.com',
    );
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
      social_url: null,
      address,
    });
    expect((await api('recipients/nobody')).status).toBe(404);
  });

  it('links only to known social networks', async () => {
    const token = await member(await newAccount());
    const save = async (social_url: unknown) =>
      (await api('profile', { method: 'PUT', token, body: { social_url } })).json();
    expect(await save('https://www.instagram.com/gato?utm=1')).toMatchObject({
      social_url: 'https://instagram.com/gato',
    });
    for (const link of ['https://gatopago.example/x', 'http://x.com/gato', 'https://x.com/'])
      expect(await save(link)).toEqual({ error_code: 'INVALID_SOCIAL_URL' });
    expect(await save('')).toMatchObject({ social_url: null });
  });

  it('keeps the card early-access survey', async () => {
    const token = await member(await newAccount());
    expect(await (await api('card-interest', { token })).json()).toEqual({ interest: null });
    const answers = {
      country: ' Bolivia ',
      use_case: 'travel',
      monthly_spend: '100-500',
      card_preference: 'both',
      wallet_pay: 'essential',
    };
    expect(
      await (
        await api('card-interest', {
          method: 'PUT',
          token,
          body: { ...answers, wallet_pay: 'maybe' },
        })
      ).json(),
    ).toEqual({ error_code: 'INVALID_ANSWER' });
    await api('card-interest', { method: 'PUT', token, body: answers });
    await api('card-interest', { method: 'PUT', token, body: { ...answers, use_case: 'daily' } });
    expect(await (await api('card-interest', { token })).json()).toMatchObject({
      interest: { ...answers, country: 'Bolivia', use_case: 'daily' },
    });
  });
});

describe('contacts and invitations', () => {
  it('saves members to pay them, and forgets them', async () => {
    const token = await member(await newAccount());
    const friend = await newAccount();
    const friendToken = await member(friend);
    await api('profile', { method: 'PUT', token: friendToken, body: { username: 'friend_1' } });
    const contacts = async () =>
      (await (await api('contacts', { token })).json<{ contacts: unknown[] }>()).contacts;

    expect(await contacts()).toEqual([]);
    expect((await api('contacts', { token, body: { username: 'nobody_here' } })).status).toBe(404);
    expect(
      await (await api('contacts', { token: friendToken, body: { username: 'friend_1' } })).json(),
    ).toEqual({ error_code: 'SELF_CONTACT' });
    expect((await api('contacts', { token, body: { username: 'friend_1' } })).status).toBe(200);
    await api('contacts', { token, body: { username: 'friend_1' } });
    expect(await contacts()).toEqual([
      {
        username: 'friend_1',
        display_name: null,
        address: friend.address.toLowerCase(),
      },
    ]);
    await api('contacts/friend_1', { method: 'DELETE', token });
    expect(await contacts()).toEqual([]);
  });

  it('issues one shareable invitation at a time and counts who joined with it', async () => {
    const token = await member(await newAccount());
    expect(await (await api('invites', { token })).json()).toEqual({ invited: 0, code: null });
    const { code } = await (
      await api('invites', { method: 'POST', token })
    ).json<{ code: string }>();
    expect(code).toMatch(/^[A-HJ-NP-Z2-9]{8}$/);
    expect(await (await api('invites', { method: 'POST', token })).json()).toEqual({
      invited: 0,
      code,
    });

    const joined = await signIn(await newAccount(), { invite: code, turnstile: 'human' });
    expect(joined.status).toBe(200);
    expect(await (await api('invites', { token })).json()).toEqual({ invited: 1, code: null });
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

describe('activity', () => {
  // Holds Aave's testnet USDC on Arbitrum Sepolia.
  const HOLDER = '0x460b97bd498e1157530aeb3086301d5225b91216';
  const anvil = createTestClient({ chain, mode: 'anvil', transport: http(FORK_RPC) }).extend(
    walletActions,
  );
  const reconcile = () =>
    worker.scheduled(createScheduledController({ cron: '*/10 * * * *' }), env);

  async function pay(from: Hex, to: Hex, amount: bigint) {
    await anvil.impersonateAccount({ address: from });
    await anvil.setBalance({ address: from, value: parseEther('1') });
    const hash = await anvil.writeContract({
      account: from,
      chain,
      address: usdc,
      abi: erc20Abi,
      functionName: 'transfer',
      args: [to, amount],
    });
    return client.waitForTransactionReceipt({ hash });
  }

  /** Delivers `logs` as Alchemy would: an Address Activity event signed with the webhook's key. */
  async function deliver(logs: Log[], removed = false, signingKey = 'test-signing-key') {
    const body = JSON.stringify({
      webhookId: 'wh_test',
      id: 'whevt_test',
      type: 'ADDRESS_ACTIVITY',
      event: {
        network: 'ARB_SEPOLIA',
        activity: logs.map((log) => ({
          category: 'token',
          log: {
            address: log.address,
            topics: log.topics,
            data: log.data,
            blockHash: log.blockHash,
            blockNumber: toHex(log.blockNumber!),
            transactionHash: log.transactionHash,
            transactionIndex: toHex(log.transactionIndex!),
            logIndex: toHex(log.logIndex!),
            removed,
          },
        })),
      },
    });
    const key = await crypto.subtle.importKey(
      'raw',
      new TextEncoder().encode(signingKey),
      { name: 'HMAC', hash: 'SHA-256' },
      false,
      ['sign'],
    );
    const signature = new Uint8Array(
      await crypto.subtle.sign('HMAC', key, new TextEncoder().encode(body)),
    );
    return exports.default.fetch(
      new Request(`${API}/webhooks/alchemy`, {
        method: 'POST',
        headers: {
          'Content-Type': 'application/json',
          'X-Alchemy-Signature': bytesToHex(signature).slice(2),
        },
        body,
      }),
    );
  }

  it('knows which coin a Transfer log moved: USDC or a configured token, never another', () => {
    const monad = walletNetworks['eip155:10143'] as unknown as Network;
    expect(coinOf(monad, monad.usdc)).toMatchObject({ symbol: 'USDC', decimals: 6 });
    expect(coinOf(monad, '0xa9012a055bd4e0eDfF8Ce09f960291C09D5322dC')).toMatchObject({
      symbol: 'AUSD',
      decimals: 6,
    });
    expect(coinOf(monad, '0x0000000000000000000000000000000000000bad')).toBeNull();
  });

  it("indexes members' USDC transfers and lists them newest first", async () => {
    const alice = await newAccount(),
      bob = await newAccount();
    const [aliceToken, bobToken] = [await member(alice), await member(bob)];
    await api('profile', { method: 'PUT', token: bobToken, body: { username: 'bob_activity' } });
    await reconcile();
    await pay(HOLDER, alice.address, 5_000_000n);
    await pay(alice.address, bob.address, 1_500_000n);
    await reconcile();
    await reconcile();

    const { activity, next_cursor } = await (
      await api('activity', { token: aliceToken })
    ).json<{
      activity: Record<string, unknown>[];
      next_cursor: string | null;
    }>();
    expect(next_cursor).toBeNull();
    expect(activity).toMatchObject([
      {
        direction: 'sent',
        kind: 'transfer',
        currency: 'USDC',
        amount: '1500000',
        counterparty: bob.address,
        counterparty_username: 'bob_activity',
      },
      { direction: 'received', amount: '5000000', counterparty_username: null },
    ]);
    const forBob = await (
      await api('activity', { token: bobToken })
    ).json<{
      activity: Record<string, unknown>[];
    }>();
    expect(forBob.activity).toMatchObject([
      { direction: 'received', amount: '1500000', counterparty: alice.address },
    ]);
    expect((await api('activity')).status).toBe(401);
    expect((await api('activity?before=nope', { token: aliceToken })).status).toBe(400);
  });

  it('keeps what a signed webhook delivers and forgets what a reorg removed', async () => {
    const carol = await newAccount();
    const token = await member(carol);
    // HOLDER is Aave's aToken: an ordinary wallet in between makes this a plain transfer.
    const wallet = '0x000000000000000000000000000000000000ca11';
    await pay(HOLDER, wallet, 2_000_000n);
    const { logs } = await pay(wallet, carol.address, 2_000_000n);
    const activity = async () =>
      (await (await api('activity', { token })).json<{ activity: unknown[] }>()).activity;

    expect((await deliver(logs, false, 'forged-key')).status).toBe(401);
    expect(await activity()).toEqual([]);
    expect((await deliver(logs)).status).toBe(200);
    expect((await deliver(logs)).status).toBe(200);
    expect(await activity()).toMatchObject([
      { direction: 'received', amount: '2000000', kind: 'transfer' },
    ]);
    await deliver(logs, true);
    expect(await activity()).toEqual([]);

    // USDC sent to Circle's TokenMinter is a CCTP burn: a crossing to another network.
    const burn = await pay(
      carol.address,
      walletNetworks['eip155:421614'].cctp.tokenMinter,
      500_000n,
    );
    await deliver(burn.logs);
    expect(await activity()).toMatchObject([{ direction: 'sent', kind: 'crosschain' }]);

    // USDC sent to Aave's aToken is saved in Grow.
    const saved = await pay(carol.address, walletNetworks['eip155:421614'].aave.aToken, 100_000n);
    await deliver(saved.logs);
    expect(await activity()).toMatchObject([
      { direction: 'sent', kind: 'earn' },
      { kind: 'crosschain' },
    ]);

    // USDC paid into a Uniswap pool is a swap.
    const [pool] = swapPools(walletNetworks['eip155:421614']);
    await deliver((await pay(carol.address, pool, 100_000n)).logs);
    expect(await activity()).toMatchObject([
      { direction: 'sent', kind: 'swap' },
      { kind: 'earn' },
      { kind: 'crosschain' },
    ]);
  });

  it('notifies the receiver once per movement and forgets tokens FCM no longer knows', async () => {
    const erin = await newAccount();
    const token = await member(erin);
    expect((await api('push-tokens', { token, body: { token: 'not a token' } })).status).toBe(400);
    const device = `fcm-device-${'x'.repeat(40)}`;
    expect(
      (await api('push-tokens', { token, body: { token: device, language: 'es' } })).status,
    ).toBe(200);
    const sent: { message: { token: string; data: Record<string, string> } }[] = [];
    let fcmStatus = 200;
    vi.spyOn(globalThis, 'fetch').mockImplementation(async (input, init) => {
      const url = String(input);
      if (url === 'https://oauth2.googleapis.com/token')
        return Response.json({ access_token: 'google-token', expires_in: 3600 });
      if (url === 'https://fcm.googleapis.com/v1/projects/gatopago-test/messages:send') {
        expect(new Headers(init?.headers).get('Authorization')).toBe('Bearer google-token');
        sent.push(JSON.parse(String(init?.body)));
        return new Response(null, { status: fcmStatus });
      }
      return realFetch(input, init);
    });

    const { logs } = await pay(HOLDER, erin.address, 3_000_000n);
    await deliver(logs);
    await deliver(logs);
    expect(sent).toHaveLength(1);
    expect(sent[0].message.token).toBe(device);
    expect(sent[0].message.data).toMatchObject({
      type: 'movement',
      title: 'Recibiste 3,00 USDC',
      link: '/statement',
    });

    fcmStatus = 404;
    await deliver((await pay(HOLDER, erin.address, 1_000_000n)).logs);
    expect(
      await env.WALLET_DB.prepare('SELECT 1 FROM push_tokens WHERE token = ?').bind(device).first(),
    ).toBeNull();
  });

  it("adds new members' addresses to the webhooks once", async () => {
    const dave = await newAccount();
    await member(dave);
    const updates: { webhook_id: string; addresses_to_add: string[] }[] = [];
    vi.spyOn(globalThis, 'fetch').mockImplementation(async (input, init) => {
      if (String(input) !== 'https://dashboard.alchemy.com/api/update-webhook-addresses')
        return realFetch(input, init);
      expect(new Headers(init?.headers).get('X-Alchemy-Token')).toBe('test-auth-token');
      updates.push(JSON.parse(String(init?.body)));
      return Response.json({});
    });
    const watch = () => worker.scheduled(createScheduledController({ cron: '* * * * *' }), env);
    await watch();
    expect(updates).toHaveLength(1);
    expect(updates[0].webhook_id).toBe('wh_test');
    expect(updates[0].addresses_to_add).toContain(dave.address.toLowerCase());
    await watch();
    expect(updates).toHaveLength(1);
  });
});

describe('stellar', () => {
  const testnet = stellarNetworks['stellar:testnet'];
  const server = new rpc.Server(testnet.rpcUrl);
  const sponsor = Keypair.fromSecret(env.STELLAR_SECRET_KEY).publicKey();
  const minute = () => worker.scheduled(createScheduledController({ cron: '* * * * *' }), env);
  const hostFunction = (operation: xdr.Operation) => {
    if (operation.body.type !== 'invokeHostFunction') throw new Error('not a contract call');
    return operation.body.invokeHostFunctionOp.hostFunction;
  };
  /** Answers the Alchemy webhook update the minute cron sends for new members. */
  const alchemy = (url: string) =>
    url === 'https://dashboard.alchemy.com/api/update-webhook-addresses' ? Response.json({}) : null;

  it("creates the member's account and pays only for its own calls, signed by its passkeys", async () => {
    const passkey = await softwarePasskey();
    const account = await toGatoPagoAccount({ client, owner: passkey, contracts: walletContracts });
    const token = await member(account);
    const stellar = await (await api('stellar', { token })).json<{ account: string }>();
    expect(stellar).toEqual({
      network: 'stellar:testnet',
      account: stellarAccountAddress(testnet, sponsor, account.address),
      deployed: false,
      sponsor,
      keys: [],
    });

    // The account is not deployed on EVM: its initial owners must be proven.
    expect((await api('stellar/account', { token, body: {} })).status).toBe(400);
    const owner = passkeyOwner(walletContracts.webAuthnVerifier, passkey.publicKey);
    const created = await api('stellar/account', { token, body: { initial_owners: [owner] } });
    expect(await created.json()).toEqual({ account: stellar.account, deployed: true });
    expect(await stellarAccountExists(server, stellar.account)).toBe(true);

    let lastNonce: string | null = null;
    const submit = async (operation: xdr.Operation, key: WebAuthnAccount | null) => {
      // Without a key, the call is sent as built: the server must refuse it before simulating.
      const call = key
        ? await prepareStellarCall(server, testnet, sponsor, operation)
        : { func: hostFunction(operation), auth: [], latestLedger: 0 };
      const auth = key
        ? await signStellarAuth(testnet, call.auth, {
            owner: key,
            validUntil: call.latestLedger + 60,
          })
        : [];
      const [credentials] = auth.map((entry) => entry.credentials);
      if (credentials && credentials.type !== 'sorobanCredentialsSourceAccount')
        lastNonce = (
          credentials.type === 'sorobanCredentialsAddressWithDelegates'
            ? credentials.value.addressCredentials
            : credentials.value
        ).nonce.toString();
      return api('stellar/submit', {
        token,
        body: { func: call.func.toXdr('base64'), auth: auth.map((entry) => entry.toXdr('base64')) },
      });
    };
    const backup = await softwarePasskey();
    const addBackup = addSignerOperation(
      testnet,
      stellar.account,
      passkeyOwner(walletContracts.webAuthnVerifier, backup.publicKey),
    );
    // A passkey that does not own the account cannot, even sponsored.
    const forged = await submit(addBackup, await softwarePasskey());
    expect(forged.status).toBe(400);
    const added = await submit(addBackup, passkey);
    expect(added.status).toBe(200);
    const { transaction_hash } = await added.json<{ transaction_hash: string }>();
    expect(transaction_hash).toMatch(/^[0-9a-f]{64}$/);
    // A lost answer is found by the signed nonce, only by its member.
    const nonce = lastNonce!;
    expect(await (await api(`stellar/submit?nonce=${nonce}`, { token })).json()).toEqual({
      transaction_hash,
    });
    expect((await api('stellar/submit?nonce=1', { token })).status).toBe(404);
    const stranger = await member(await newAccount());
    expect((await api(`stellar/submit?nonce=${nonce}`, { token: stranger })).status).toBe(404);
    // The sponsor's own funds are not the member's to move.
    const theft = await submit(transferOperation(testnet, sponsor, stellar.account, 1n), null);
    expect(await theft.json()).toEqual({ error_code: 'NOT_SPONSORED' });
  });

  it('lets an owner key approve its Ed25519 key, which then signs for the Stellar account', async () => {
    // A Mera account: its EVM owner is a key, and its Stellar key derives from the same passkey.
    const meraKey = privateKeyToAccount(generatePrivateKey());
    const account = await toGatoPagoAccount({ client, owner: meraKey, contracts: walletContracts });
    const token = await member(account);
    const keypair = Keypair.random();
    const ed25519: StellarKey = {
      type: 'ed25519',
      publicKey: bytesToHex(keypair.rawPublicKey()),
      signMessage: async (message) => keypair.sign(message as Parameters<typeof keypair.sign>[0]),
    };
    const initial_owners = [keyOwner(meraKey.address)];
    const approve = async (
      signer: typeof meraKey,
      expires_at = Math.floor(Date.now() / 1000) + 600,
    ) =>
      api('stellar/keys', {
        token,
        body: {
          public_key: ed25519.publicKey,
          signature: await signer.signMessage({
            message: stellarKeyApproval(testnet, account.address, ed25519.publicKey, expires_at),
          }),
          expires_at,
          initial_owners,
        },
      });
    // An expired approval is refused, even from an owner.
    expect(await (await approve(meraKey, Math.floor(Date.now() / 1000) - 1)).json()).toEqual({
      error_code: 'APPROVAL_EXPIRED',
    });
    // A key that does not own the account cannot approve it, even with the member's session.
    expect(await (await approve(privateKeyToAccount(generatePrivateKey()))).json()).toEqual({
      error_code: 'NOT_AN_OWNER',
    });
    expect((await approve(meraKey)).status).toBe(201);
    const stellar = await (
      await api('stellar', { token })
    ).json<{ account: string; keys: { public_key: string; owner: string }[] }>();
    expect(stellar.keys).toEqual([
      { public_key: ed25519.publicKey, owner: meraKey.address.toLowerCase() },
    ]);

    expect((await api('stellar/account', { token, body: { initial_owners } })).status).toBe(200);
    const backup = await softwarePasskey();
    const call = await prepareStellarCall(
      server,
      testnet,
      sponsor,
      addSignerOperation(
        testnet,
        stellar.account,
        passkeyOwner(walletContracts.webAuthnVerifier, backup.publicKey),
      ),
    );
    const auth = await signStellarAuth(testnet, call.auth, {
      owner: ed25519,
      validUntil: call.latestLedger + 60,
    });
    const added = await api('stellar/submit', {
      token,
      body: { func: call.func.toXdr('base64'), auth: auth.map((entry) => entry.toXdr('base64')) },
    });
    expect(added.status).toBe(200);
  });

  it("mints members' burns toward Stellar, never someone else's", async () => {
    const token = await member(await newAccount());
    const burn = `0x${'cd'.repeat(32)}`;
    const relay = (network: string) =>
      api('stellar/relays', { token, body: { network, transaction_hash: burn } });
    const status = async (token: string) =>
      (await api(`stellar/relays?transaction_hash=${burn}`, { token })).json();
    expect((await relay('eip155:1')).status).toBe(404);
    expect((await relay('eip155:421614')).status).toBe(202);
    expect(await status(token)).toEqual({ status: 'pending', transaction_hash: null });
    // Another member does not see it.
    expect(await status(await member(await newAccount()))).toEqual({ error_code: 'NOT_FOUND' });
    // Attested, but burned by 0x75…, not by this member (the 10b check's message).
    const message =
      '0x00000001000000030000001b738d171da655afc22ca3e9bcea81ff84454200ce440c0d5254da12654a3f63c10000000000000000000000008fe6b999dc680ccfdd5bf7eb0974218be2542daada6f9ee0786c812344d82817ef19b648b4af120f8bd10bf658e6b99eacff24b83de86ac50b47eaf2840fe23e48179551660fd1072fba6f445d4a6bd7af4ab93e000003e8000003e80000000100000000000000000000000075faf114eafb1bdbe2f0316df893fd58ce46aa4d3de86ac50b47eaf2840fe23e48179551660fd1072fba6f445d4a6bd7af4ab93e00000000000000000000000000000000000000000000000000000000000f424000000000000000000000000075464f762bc50d0a0b127ab5a085504bf102bb880000000000000000000000000000000000000000000000000000000000000082000000000000000000000000000000000000000000000000000000000000008200000000000000000000000000000000000000000000000000000000004d5c6a000000000000000000000000000000000000000000000000000000000000003843435942413344484d584f5a49484e4a4b43325644505144345758593347345457575042324155353747543551474942555141444e543351';
    vi.spyOn(globalThis, 'fetch').mockImplementation(async (input, init) => {
      const url = input instanceof Request ? input.url : String(input);
      if (url === `https://iris-api-sandbox.circle.com/v2/messages/3?transactionHash=${burn}`)
        return Response.json({ messages: [{ status: 'complete', message, attestation: '0x01' }] });
      return alchemy(url) ?? realFetch(input, init);
    });
    await minute();
    expect(
      await env.WALLET_DB.prepare(
        'SELECT relayed_hash FROM stellar_relays WHERE transaction_hash = ?',
      )
        .bind(burn)
        .first('relayed_hash'),
    ).toBe('rejected');
    expect(await status(token)).toEqual({ status: 'rejected', transaction_hash: null });
  });

  it('lists Stellar transfers with the activity and notifies the receiver', async () => {
    const [alice, bob] = [await newAccount(), await newAccount()];
    const [aliceToken, bobToken] = [await member(alice), await member(bob)];
    const stellarOf = async (token: string) =>
      (await (await api('stellar', { token })).json<{ account: string }>()).account;
    const [from, to] = [await stellarOf(aliceToken), await stellarOf(bobToken)];
    await api('push-tokens', {
      token: bobToken,
      body: { token: `fcm-bob-${'x'.repeat(40)}`, language: 'es' },
    });

    const hash = 'ef'.repeat(32);
    const stranger = Keypair.random().publicKey();
    const transfer = (between: [string, string], id: number, ledger: number) => ({
      type: 'contract',
      ledger,
      ledgerClosedAt: '2026-10-06T12:00:00Z',
      contractId: testnet.usdc,
      id: `0021678426519777280-000000000${id}`,
      operationIndex: 0,
      transactionIndex: 0,
      txHash: hash,
      inSuccessfulContractCall: true,
      topic: [
        xdr.ScVal.scvSymbol('transfer'),
        new StellarAddress(between[0]).toScVal(),
        new StellarAddress(between[1]).toScVal(),
        xdr.ScVal.scvString('USDC:GBBD47IF6LWK7P7MDEVSCWR7DPUWV3NY3DTQEVFL4NAT4AQH3ZLLFLA5'),
      ].map((topic) => topic.toXdr('base64')),
      value: nativeToScVal(25_000_005n, { type: 'i128' }).toXdr('base64'),
    });
    const sent: { message: { data: Record<string, string> } }[] = [];
    let delivered = false;
    vi.spyOn(globalThis, 'fetch').mockImplementation(async (input, init) => {
      const url = input instanceof Request ? input.url : String(input);
      if (url === 'https://oauth2.googleapis.com/token')
        return Response.json({ access_token: 'google-token', expires_in: 3600 });
      if (url === 'https://fcm.googleapis.com/v1/projects/gatopago-test/messages:send') {
        sent.push(JSON.parse(String(init?.body)));
        return new Response(null, { status: 200 });
      }
      if (url.startsWith(testnet.rpcUrl)) {
        const request =
          input instanceof Request ? await input.clone().json() : JSON.parse(String(init?.body));
        if (request.method === 'getEvents') {
          const { startLedger } = request.params;
          const events = delivered
            ? []
            : [
                transfer([from, to], 0, startLedger),
                transfer([stranger, stranger], 1, startLedger),
              ];
          delivered = true;
          return Response.json({
            jsonrpc: '2.0',
            id: request.id,
            result: {
              events,
              cursor: '0',
              latestLedger: startLedger,
              oldestLedger: 1,
              latestLedgerCloseTime: '0',
              oldestLedgerCloseTime: '0',
            },
          });
        }
      }
      return alchemy(url) ?? realFetch(input, init);
    });
    // Read from the latest ledger, where the mocked RPC places the transfers.
    await env.WALLET_DB.prepare(
      "DELETE FROM index_cursors WHERE network = 'stellar:testnet'",
    ).run();
    await minute();
    await minute();

    // 2.5000005 USDC: the seventh decimal does not cross networks.
    const { activity } = await (
      await api('activity', { token: bobToken })
    ).json<{
      activity: object[];
    }>();
    expect(activity).toEqual([
      expect.objectContaining({
        network: 'stellar:testnet',
        transaction_hash: hash,
        direction: 'received',
        kind: 'transfer',
        amount: '2500000',
        counterparty: from,
      }),
    ]);
    const { activity: sentByAlice } = await (
      await api('activity', { token: aliceToken })
    ).json<{
      activity: { direction: string }[];
    }>();
    expect(sentByAlice.map((row) => row.direction)).toEqual(['sent']);
    expect(sent).toHaveLength(1);
    expect(sent[0].message.data.title).toBe('Recibiste 2,50 USDC');
  });
});
