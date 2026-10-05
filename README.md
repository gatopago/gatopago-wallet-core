# GatoPago Wallet Core

Cloudflare Worker behind `api.gatopago.com` for GatoPago smart accounts (ERC-4337, EntryPoint v0.9).

Accounts live onchain: the address, its passkey owners and its funds belong to the contracts in
[`protocol`](../protocol). This Worker only signs users in, sponsors their gas and relays their
operations. Losing its database loses no funds and no access: a user can still sign every
operation with their passkey and send it through any ERC-4337 bundler.

## API

| Route | |
|---|---|
| `GET /app/v1/health` | 200 when every setting is valid |
| `POST /app/v1/auth/nonce` | Nonce for a Sign-In with Ethereum (ERC-4361) message |
| `POST /app/v1/auth/session` | `{message, signature, invite?, turnstile?}`: the account signs the SIWE message (ERC-1271, or ERC-6492 before deployment); returns an ES256 session token. New accounts need an invitation and Turnstile |
| `GET`/`PUT /app/v1/profile` | Display name, social link and username (chosen once) |
| `GET`/`PUT /app/v1/card-interest` | Early-access survey for a future GatoPago Card |
| `GET /app/v1/activity?before=` | The member's USDC movements, newest first, 50 per page |
| `GET`/`POST /app/v1/contacts`, `DELETE /app/v1/contacts/:username` | Members saved to pay in one tap |
| `GET`/`POST /app/v1/invites` | People who joined with the member's invitations; `POST` issues one to share (single use, 7 days) |
| `POST /app/v1/push-tokens`, `DELETE /app/v1/push-tokens/:token` | Devices (FCM tokens) that receive payment notifications |
| `POST /app/v1/webhooks/alchemy` | Alchemy Address Activity events (signed) |
| `GET /app/v1/recipients/:username` | Address that receives payments to `@username` |
| `GET`/`POST /app/v1/approvals/:account` | Signed owner changes, verified before storing, to apply on every network |
| `POST /app/v1/paymaster/:network` | ERC-7677 paymaster service: sponsors the signed-in account's operations, within gas ceilings and `SPONSORED_OPERATIONS_PER_DAY` |
| `POST /app/v1/bundler/:network` | ERC-4337 bundler JSON-RPC, one Durable Object per network |

`:network` is a CAIP-2 id from `WALLET_NETWORKS`: `eip155:421614` (Arbitrum Sepolia),
`eip155:43113` (Avalanche Fuji), `eip155:10143` (Monad testnet). GatoPago Flow identifies users
through the `WalletIdentity` service binding.

The D1 database (`migrations/`) holds members (invitation gate and profile), invitations, SIWE
nonces, approvals, daily sponsorship counters and card survey answers.

Members' USDC movements (`transfers`) are the activity history, a cache of the chain that can be
rebuilt by reading it again:

- **Alchemy Address Activity webhooks** deliver them as they happen (`POST /app/v1/webhooks/alchemy`,
  verified with each webhook's signing key; a reorg's `removed` event deletes the row). Configure
  one webhook per network in `ALCHEMY_WEBHOOKS`; every minute the Worker adds new members'
  addresses to them with `ALCHEMY_AUTH_TOKEN`. To add a network's webhook later, set
  `members.watched = 0` so every address is added again.
- **Reconciliation**, every 10 minutes, reads the members' Transfer events that a webhook missed,
  querying only their addresses. `INDEX_SOURCES` sets per network the RPC it reads (Alchemy's free
  tier allows only 10 blocks per `eth_getLogs`, so a public RPC can serve here), the blocks per
  query (default 100) and the first block on a network not read yet (default: the latest), e.g.
  `{"eip155:421614": {"url": "https://sepolia-rollup.arbitrum.io/rpc", "range": 10000, "start": 123}}`.

## Setup

Node 24, pnpm 11 and, for tests, Foundry's `anvil`.

```sh
pnpm install --frozen-lockfile
pnpm wrangler d1 create gatopago-wallet   # paste the id into wrangler.jsonc
pnpm db:migrate
```

Secrets (`pnpm wrangler secret put <NAME>`, described in `.dev.vars.example`):

| Secret | |
|---|---|
| `WALLET_RPC_URLS` | JSON map of CAIP-2 id to RPC URL |
| `RELAYER_PRIVATE_KEY` | Sends bundles; needs native gas on every network (refunded from the paymaster deposit) |
| `SPONSOR_PRIVATE_KEY` | The paymaster's sponsor signer |
| `SESSION_PRIVATE_JWK` | ES256 private JWK, e.g. `node -e "console.log(JSON.stringify(require('crypto').generateKeyPairSync('ec',{namedCurve:'P-256'}).privateKey.export({format:'jwk'})))"` |
| `TURNSTILE_SECRET_KEY` | Cloudflare Turnstile |
| `ALCHEMY_WEBHOOKS` | Optional. `{"<network>": {"id", "signing_key"}}` of each Address Activity webhook |
| `ALCHEMY_AUTH_TOKEN` | Optional. Alchemy dashboard token that adds members' addresses to the webhooks |
| `FIREBASE_SERVICE_ACCOUNT` | Optional. Firebase service account JSON; members are notified through FCM of the USDC they receive |

Then `pnpm run deploy`. Invitations are created in the D1 console:

```sql
INSERT INTO invites (code, issued_by, created_at, expires_at)
VALUES ('daniel', 'operator', unixepoch(), unixepoch() + 604800);
```

## Tests

`pnpm test` runs the Worker in workerd against a local D1 and an anvil fork of Arbitrum Sepolia
(override with `ARBITRUM_SEPOLIA_RPC`), where the deployed contracts sign in, deploy and sponsor
real accounts with a software passkey. `pnpm typecheck`, `pnpm lint` and `pnpm build` complete the
checks.

`@gatopago/shared` comes from `vendor/`, built by `protocol`.
