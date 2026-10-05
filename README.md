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
| `GET`/`PUT /app/v1/profile` | Display name and username (chosen once) |
| `GET /app/v1/recipients/:username` | Address that receives payments to `@username` |
| `GET`/`POST /app/v1/approvals/:account` | Signed owner changes, verified before storing, to apply on every network |
| `POST /app/v1/paymaster/:network` | ERC-7677 paymaster service: sponsors the signed-in account's operations, within gas ceilings and `SPONSORED_OPERATIONS_PER_DAY` |
| `POST /app/v1/bundler/:network` | ERC-4337 bundler JSON-RPC, one Durable Object per network |

`:network` is a CAIP-2 id from `WALLET_NETWORKS`: `eip155:421614` (Arbitrum Sepolia),
`eip155:43113` (Avalanche Fuji), `eip155:10143` (Monad testnet). GatoPago Flow identifies users
through the `WalletIdentity` service binding.

The D1 database (`migrations/0001_wallet.sql`) holds members (invitation gate and profile),
invitations, SIWE nonces, approvals and daily sponsorship counters.

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
