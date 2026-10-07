# GatoPago Wallet Core

Cloudflare Worker behind `api.gatopago.com` for GatoPago smart accounts (ERC-4337, EntryPoint v0.9).

Accounts live onchain: the address, its passkey owners and its funds belong to the contracts in
[`protocol`](../protocol). This Worker only signs users in, sponsors their gas and relays their
operations. Losing its database loses no funds and no access: a user can still sign every
operation with their passkey and send it through any ERC-4337 bundler.

## API

| Route                                                              |                                                                                                                                                                                                                                                                                                                                    |
| ------------------------------------------------------------------ | ---------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| `GET /app/v1/health`                                               | 200 when every setting is valid                                                                                                                                                                                                                                                                                                    |
| `POST /app/v1/auth/nonce`                                          | Nonce for a Sign-In with Ethereum (ERC-4361) message                                                                                                                                                                                                                                                                               |
| `GET /app/v1/auth/signup`                                          | `{invite_required}`: whether new accounts need an invitation now (`INVITE_ONLY`)                                                                                                                                                                                                                                                   |
| `POST /app/v1/auth/session`                                        | `{message, signature, invite?, turnstile?}`: the account signs the SIWE message (ERC-1271, or ERC-6492 before deployment); returns an ES256 session token. New accounts need Turnstile and, while `INVITE_ONLY=on`, an invitation                                                                                                  |
| `GET`/`PUT /app/v1/profile`                                        | Display name, social link and username (chosen once)                                                                                                                                                                                                                                                                               |
| `GET`/`PUT /app/v1/card-interest`                                  | Early-access survey for a future GatoPago Card                                                                                                                                                                                                                                                                                     |
| `GET /app/v1/activity?before=`                                     | The member's USDC movements, newest first, 50 per page                                                                                                                                                                                                                                                                             |
| `GET`/`POST /app/v1/contacts`, `DELETE /app/v1/contacts/:username` | Members saved to pay in one tap                                                                                                                                                                                                                                                                                                    |
| `GET`/`POST /app/v1/invites`                                       | People who joined with the member's invitations; `POST` issues one to share (single use, 7 days)                                                                                                                                                                                                                                   |
| `POST /app/v1/push-tokens`, `DELETE /app/v1/push-tokens/:token`    | Devices (FCM tokens) that receive payment notifications                                                                                                                                                                                                                                                                            |
| `POST /app/v1/webhooks/alchemy`                                    | Alchemy Address Activity events (signed)                                                                                                                                                                                                                                                                                           |
| `GET /app/v1/recipients/:username`                                 | Address that receives payments to `@username`                                                                                                                                                                                                                                                                                      |
| `GET`/`POST /app/v1/approvals/:account`                            | Signed owner changes, verified before storing, to apply on every network                                                                                                                                                                                                                                                           |
| `POST /app/v1/paymaster/:network`                                  | ERC-7677 paymaster service: sponsors the signed-in account's operations, within gas ceilings and `SPONSORED_OPERATIONS_PER_DAY`                                                                                                                                                                                                    |
| `POST /app/v1/bundler/:network`                                    | ERC-4337 bundler JSON-RPC, one Durable Object per network                                                                                                                                                                                                                                                                          |
| `GET /app/v1/stellar`                                              | The member's Stellar account, whether it exists, the sponsor that simulates and pays its transactions, and its approved Ed25519 `keys` (404 when Stellar is off)                                                                                                                                                                   |
| `POST /app/v1/stellar/account`                                     | `{initial_owners?}`: creates the member's Stellar account, signed by the EVM account's passkeys and approved Ed25519 keys                                                                                                                                                                                                          |
| `POST /app/v1/stellar/keys`                                        | `{public_key, signature, expires_at, initial_owners?}`: an Ed25519 key (Mera's Stellar key) that also signs for the Stellar account, approved by an owner key of the EVM account (EIP-191 signature of `stellarKeyApproval`, valid for at most an hour); it counts while that key owns the account. A session alone cannot add one |
| `POST /app/v1/stellar/submit`                                      | `{func, auth}` (base64 XDR): sends a call of the member's Stellar account signed with a passkey, paying its fee. Only moving its USDC, letting Circle burn it, burning it toward another network and changing its signers                                                                                                          |
| `GET /app/v1/stellar/submit?nonce=…`                               | The transaction that sent the member's call signed with that authorization nonce (404 if none): how the app finds out a call whose answer it lost                                                                                                                                                                                  |
| `POST /app/v1/stellar/relays`                                      | `{network, transaction_hash}`: a CCTP burn of the member toward Stellar, minted there once attested                                                                                                                                                                                                                                |
| `GET /app/v1/stellar/relays?transaction_hash=0x…`                  | Whether the member's burn toward Stellar is `pending`, `delivered` (with its Stellar transaction) or `rejected`                                                                                                                                                                                                                    |

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

Stellar is optional (`STELLAR_SECRET_KEY`; see `@gatopago/shared/stellar`). Its key creates each
member's Stellar account (the address derives from it and the EVM account, so it receives before
existing), pays the fees of the calls members sign and mints CCTP transfers toward Stellar, which
Circle's Forwarding Service does not reach. Transactions go out one at a time through the
`StellarRelayer` Durable Object. Every minute the Worker registers members' Stellar addresses
(`stellar_accounts`), mints attested burns members reported (`stellar_relays`, only burns sent by
that member) and reads the USDC transfer events since the last ledger into `transfers`, with
amounts in 6 decimals like every network, notifying what members received. Each call it sends is
remembered by its authorization nonces (`stellar_submissions`, 30 days): the network forgets a
nonce when its five-minute signature expires, so this is how a lost answer is never paid twice.
Without the key the routes answer 404 and nothing runs; history and funds stay on Stellar.

## Setup

Node 24, pnpm 11 and, for tests, Foundry's `anvil`.

```sh
pnpm install --frozen-lockfile
pnpm wrangler d1 create gatopago-wallet   # paste the id into wrangler.jsonc
pnpm db:migrate
```

## Configuration

Plain settings live in `wrangler.jsonc` (`vars`); secrets are set with
`pnpm wrangler secret put <NAME>` (or `… < file` for a file) and listed in `.dev.vars.example`.
`/app/v1/health` answers 503 while any required one is missing or invalid.

| Name                           | Kind             | What it is                                                                                                                                                                               | How to get it                                                                                                                                                                                                              |
| ------------------------------ | ---------------- | ---------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- | -------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| `GATOPAGO_ENVIRONMENT`         | var              | Deployment name (`production`); sessions are bound to it                                                                                                                                 | Fixed per deployment                                                                                                                                                                                                       |
| `WEB_ORIGIN`                   | var              | The web app's origin: the only one CORS allows and SIWE messages name                                                                                                                    | `https://gatopago.com`                                                                                                                                                                                                     |
| `WALLET_NETWORKS`              | var              | CAIP-2 ids of the networks accounts use                                                                                                                                                  | Networks with GatoPago's contracts (`protocol/deployments`)                                                                                                                                                                |
| `SPONSORED_OPERATIONS_PER_DAY` | var              | Sponsored operations per account and day                                                                                                                                                 | Policy; `50` today                                                                                                                                                                                                         |
| `SUBREQUESTS_PER_RUN`          | var              | External requests one cron run may make; jobs stop there and resume from their cursors on the next run                                                                                   | Workers Free allows 50 per invocation: `45`. Workers Paid: up to `1000`                                                                                                                                                    |
| `INVITE_ONLY`                  | var              | `on`: new accounts need an invitation. `off`: anyone who passes Turnstile joins (an invitation still counts when used); existing members are never affected. The app reads it at runtime | `on`; `off` while judges or an open beta must join. Change it in `wrangler.jsonc` and deploy                                                                                                                               |
| `INDEX_SOURCES`                | var              | Per network, the RPC `url`, blocks per query (`range`) and first block (`start`) the reconciliation reads                                                                                | Public RPCs and the most each accepts per `eth_getLogs` (Arbitrum 1000, Fuji 2048, Monad 100). Not Alchemy's free tier, which allows 10                                                                                    |
| `WALLET_RPC_URLS`              | secret           | `{"<network>": "<url>"}`: RPC for the bundler, paymaster and reads                                                                                                                       | Alchemy app _GatoPago-server_ (no domain restriction) with every network enabled: `https://arb-sepolia.g.alchemy.com/v2/<key>`, `https://avax-fuji.g.alchemy.com/v2/<key>`, `https://monad-testnet.g.alchemy.com/v2/<key>` |
| `RELAYER_PRIVATE_KEY`          | secret           | Sends bundles and pays their gas, refunded from the paymaster deposit                                                                                                                    | A dedicated key (`cast wallet new`); fund it with native gas on every network                                                                                                                                              |
| `SPONSOR_PRIVATE_KEY`          | secret           | Signs gas sponsorships                                                                                                                                                                   | The paymaster's sponsor signer (`DeployWallet.s.sol`, `GATOPAGO_SPONSOR_SIGNER`)                                                                                                                                           |
| `SESSION_PRIVATE_JWK`          | secret           | ES256 key that signs sessions; Flow verifies them with its public part                                                                                                                   | `node -e "console.log(JSON.stringify(require('crypto').generateKeyPairSync('ec',{namedCurve:'P-256'}).privateKey.export({format:'jwk'})))"`; Flow's `SESSION_PUBLIC_JWK` is the same JWK without `d`                       |
| `TURNSTILE_SECRET_KEY`         | secret           | Verifies the sign-up challenge                                                                                                                                                           | Cloudflare → Turnstile → the widget's secret key (the web uses its site key)                                                                                                                                               |
| `ALCHEMY_WEBHOOKS`             | secret, optional | `{"<network>": {"id", "signing_key"}}` of each Address Activity webhook, to receive movements as they happen                                                                             | Alchemy → Webhooks → one _Address Activity_ webhook per network, URL `https://api.gatopago.com/app/v1/webhooks/alchemy`; each one's ID (`wh_…`) and _signing key_                                                          |
| `ALCHEMY_AUTH_TOKEN`           | secret, optional | Adds new members' addresses to those webhooks                                                                                                                                            | Alchemy → Webhooks → _Auth token_ (top right)                                                                                                                                                                              |
| `FIREBASE_SERVICE_ACCOUNT`     | secret, optional | Sends payment notifications through FCM                                                                                                                                                  | Firebase → Project settings → Service accounts → _Generate new private key_; upload the JSON with `pnpm wrangler secret put FIREBASE_SERVICE_ACCOUNT < key.json` and delete the file                                       |
| `STELLAR_NETWORK`              | var              | CAIP-2 id of the Stellar network                                                                                                                                                         | `stellar:testnet` (the networks in `@gatopago/shared/networks`)                                                                                                                                                            |
| `STELLAR_SECRET_KEY`           | secret, optional | Enables Stellar: creates members' Stellar accounts, pays their fees, relays CCTP toward Stellar. Members' Stellar addresses derive from it: never change it once they have one           | A new Stellar key (`node -e "console.log(require('@stellar/stellar-sdk').Keypair.random().secret())"`); fund its public key with XLM (testnet: `https://friendbot.stellar.org?addr=<G…>`)                                  |
| `STELLAR_RPC_URL`              | secret, optional | Stellar RPC (default: the network's public RPC)                                                                                                                                          | A Stellar RPC provider, if the public one falls short                                                                                                                                                                      |

Bindings in `wrangler.jsonc`: `WALLET_DB` (D1), `RATE_LIMITER`, and the `BUNDLER` and
`STELLAR_RELAYER` Durable Objects.

Then `pnpm run deploy`. Invitations are created in the D1 console:

```sql
INSERT INTO invites (code, issued_by, created_at, expires_at)
VALUES ('daniel', 'operator', unixepoch(), unixepoch() + 604800);
```

## Tests

`pnpm test` runs the Worker in workerd against a local D1 and an anvil fork of Arbitrum Sepolia
(override with `ARBITRUM_SEPOLIA_RPC`), where the deployed contracts sign in, deploy and sponsor
real accounts with a software passkey. Stellar has no forks: those tests use testnet, with a sponsor
funded by Friendbot on each run. `pnpm typecheck`, `pnpm lint` and `pnpm build` complete the
checks.

`@gatopago/shared` comes from `vendor/`, built by `protocol`.
