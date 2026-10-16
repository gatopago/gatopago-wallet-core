# GatoPago Wallet Core

Cloudflare Worker behind `api.gatopago.com` for GatoPago smart accounts (ERC-4337, EntryPoint v0.9).

Accounts live onchain: the address, its passkey owners and its funds belong to the contracts in
[`protocol`](../protocol). This Worker only signs users in, sponsors their gas and relays their
operations. Losing its database loses no funds and no access: a user can still sign every
operation with their passkey and send it through any ERC-4337 bundler.

## API

| Route                                                                   |                                                                                                                                                                                                                                                                                                                                                                                                                          |
| ----------------------------------------------------------------------- | ------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------ |
| `GET /app/v1/health`                                                    | 200 when every setting is valid, with each reader's last block, when it moved and failed, those `behind`, ledgers `missed` and notifications pending                                                                                                                                                                                                                                                                     |
| `POST /app/v1/auth/nonce`                                               | Nonce for a Sign-In with Ethereum (ERC-4361) message                                                                                                                                                                                                                                                                                                                                                                     |
| `GET /app/v1/auth/signup`                                               | `{invite_required}`: whether new accounts need an invitation now (`INVITE_ONLY`)                                                                                                                                                                                                                                                                                                                                         |
| `POST /app/v1/auth/session`                                             | `{message, signature, initial_owners, invite?, turnstile?}`: the account signs the SIWE message (ERC-1271, or ERC-6492 before deployment), and the signer must be an owner now by the approvals Wallet Core verified, whatever a network still behind a removal accepts; returns an ES256 session token carrying the member's session generation. New accounts need Turnstile and, while `INVITE_ONLY=on`, an invitation |
| `GET /app/v1/auth/session`                                              | Whether a session (the wallet's or Business's) still counts, and whose it is (`{user_id, address}`); 401 once it ended. Flow asks it for every session it receives                                                                                                                                                                                                                                                       |
| `POST /app/v1/business-login`                                           | From GatoPago Business: `{device, public_key?}`, a sign-in request whose `approve_url` the console shows as a QR; with `public_key` (its Business key), approving it also binds that key to the account                                                                                                                                                                                                                  |
| `GET /app/v1/business-login/:id`                                        | With `Authorization: Bearer <secret>`: `pending`, `expired`, or the Business session once approved, a single time                                                                                                                                                                                                                                                                                                        |
| `GET`/`POST /app/v1/business-approvals/:id`                             | From the app: what the member approves (device, place, `public_key`), and the approval, a SIWE message whose nonce is the request and whose resources name the exact Business key, if any                                                                                                                                                                                                                                |
| `POST /app/v1/business-login/key`                                       | `{public_key, nonce, signature}`: the Business key's Ed25519 signature over a single-use nonce (`businessSignInMessage`); a session that carries the key, while the owner that approved it owns the account                                                                                                                                                                                                              |
| `GET /app/v1/business-keys`, `DELETE /app/v1/business-keys/:public_key` | The member's Business keys; removing one ends the sessions it opened                                                                                                                                                                                                                                                                                                                                                     |
| `GET`/`PUT /app/v1/profile`                                             | Display name, social link and username (chosen once)                                                                                                                                                                                                                                                                                                                                                                     |
| `GET`/`PUT /app/v1/card-interest`                                       | Early-access survey for a future GatoPago Card (the waitlist)                                                                                                                                                                                                                                                                                                                                                            |
| `GET`/`PUT /app/v1/groups`, `DELETE /app/v1/groups/:name`               | Groups saved in "Group payment": `PUT` takes `{name, members}` (a name in any case replaces that group; up to 20 groups of 10 people) and every route answers `{groups}`, newest first                                                                                                                                                                                                                                   |
| `GET /app/v1/activity?before=`                                          | The member's USDC movements, newest first, 50 per page                                                                                                                                                                                                                                                                                                                                                                   |
| `GET`/`POST /app/v1/contacts`, `DELETE /app/v1/contacts/:username`      | Members saved to pay in one tap                                                                                                                                                                                                                                                                                                                                                                                          |
| `GET`/`POST /app/v1/invites`                                            | People who joined with the member's invitations; `POST` issues one to share (single use, 7 days)                                                                                                                                                                                                                                                                                                                         |
| `POST /app/v1/push-tokens`, `DELETE /app/v1/push-tokens/:token`         | Devices (FCM tokens) that receive payment notifications                                                                                                                                                                                                                                                                                                                                                                  |
| `POST /app/v1/webhooks/alchemy`                                         | Alchemy Address Activity events (signed)                                                                                                                                                                                                                                                                                                                                                                                 |
| `GET /app/v1/recipients/:username`                                      | Address that receives payments to `@username`, and its Stellar account (`stellar_address`, null until the cron writes it)                                                                                                                                                                                                                                                                                                |
| `GET`/`POST /app/v1/approvals/:account`                                 | Signed owner changes, verified before storing, to apply on every network. One that removes owners ends every earlier session of the member and answers a new `session` for the device that signed it (unless it removed its own key)                                                                                                                                                                                     |
| `POST /app/v1/paymaster/:network`                                       | ERC-7677 paymaster service: sponsors the signed-in account's operations, within gas ceilings, `SPONSORED_OPERATIONS_PER_DAY` and `SPONSORED_GAS_PER_DAY`                                                                                                                                                                                                                                                                 |
| `POST /app/v1/bundler/:network`                                         | ERC-4337 bundler JSON-RPC, one Durable Object per network                                                                                                                                                                                                                                                                                                                                                                |
| `GET /app/v1/stellar`                                                   | The member's Stellar account, whether it exists, the sponsor that simulates and pays its transactions, and its approved Ed25519 `keys`, each with its approval (`signature`, `expires_at`) so the app checks it before signing the key in (404 when Stellar is off)                                                                                                                                                      |
| `POST /app/v1/stellar/account`                                          | `{initial_owners?}`: creates the member's Stellar account, signed by the EVM account's passkeys and approved Ed25519 keys                                                                                                                                                                                                                                                                                                |
| `POST /app/v1/stellar/keys`                                             | `{public_key, signature, expires_at, initial_owners?}`: an Ed25519 key (Mera's Stellar key) that also signs for the Stellar account, approved by an owner key of the EVM account (EIP-191 signature of `stellarKeyApproval`, valid for at most an hour); it counts while that key owns the account. A session alone cannot add one                                                                                       |
| `POST /app/v1/stellar/submit`                                           | `{func, auth}` (base64 XDR): sends a call of the member's Stellar account signed with a passkey, paying its fee. Only moving its USDC or XLM, letting Circle burn its USDC, burning it toward another network and changing its signers                                                                                                                                                                                   |
| `GET /app/v1/stellar/submit?nonce=…`                                    | The transaction that sent the member's call signed with that authorization nonce (404 if none): how the app finds out a call whose answer it lost                                                                                                                                                                                                                                                                        |
| `POST /app/v1/stellar/relays`                                           | `{network, transaction_hash}`: a CCTP burn of the member toward Stellar, minted there seconds after Circle attests it                                                                                                                                                                                                                                                                                                    |
| `GET /app/v1/stellar/relays?transaction_hash=0x…`                       | Whether the burn toward Stellar the member sent or receives is `pending`, `delivered` (with its Stellar transaction) or `rejected`                                                                                                                                                                                                                                                                                       |

`:network` is a CAIP-2 id from `WALLET_NETWORKS`: `eip155:421614` (Arbitrum Sepolia),
`eip155:43113` (Avalanche Fuji), `eip155:10143` (Monad testnet). GatoPago Flow asks Wallet Core
about every session token it receives (`GET /app/v1/auth/session`, through a service binding).

The D1 database starts from `migrations/0001_schema.sql`, and every change is a new migration (it
is never reset): members (profile, invitation and Stellar address, and per network the webhook that
has their address and whether their earlier history was read), invitations, SIWE nonces, approvals, daily sponsorship counters, contacts,
saved groups, card survey answers, push devices, movements and Stellar's relays, submissions and approved keys. An
approval that removes an owner moves the member's session generation: wallet sessions carry it, so
every earlier one stops counting.

Members' movements (`transfers`) are the activity history, a cache of the chain that can be
rebuilt by reading it again: transfers of USDC and the network's configured tokens, and the native
coin (ETH, AVAX, MON) sent to a member, in a transaction of its own (no log: its row has
`log_index` -1) or inside one, as a smart account pays (a negative `log_index` from its place in
the trace). A transfer of nothing is not kept: anyone can make one to place an address in a
member's history.

- **Alchemy Address Activity webhooks** deliver them as they happen (tokens as logs, the native
  coin as `external` and `internal` activity; `POST /app/v1/webhooks/alchemy`,
  verified with each webhook's signing key; a reorg's `removed` event deletes the row). Alchemy
  reports `internal` transfers on Arbitrum and Avalanche, not on Monad, and only the webhook reads
  them: native coin a smart account pays on Monad, or that a missed webhook carried, is not listed.
  Configure one webhook per network in `ALCHEMY_WEBHOOKS`; every minute the Worker adds members'
  addresses to them with `ALCHEMY_AUTH_TOKEN`: new members, and all of them when a webhook is
  replaced or a network added (`member_networks.webhook`).
- **Reconciliation**, every 10 minutes, reads the members' Transfer events that a webhook missed,
  querying only their addresses, and notifies those from the last hour. It takes half of the run's
  requests at most, each network an even part, and a network that fails leaves its blocks for the
  next run without stopping the others. `INDEX_SOURCES` sets per network the RPC it reads (Alchemy's free
  tier allows only 10 blocks per `eth_getLogs`, so a public RPC can serve here), the blocks per
  query (default 100) and the first block on a network not read yet (default: the latest), e.g.
  `{"eip155:421614": {"url": "https://sepolia-rollup.arbitrum.io/rpc", "range": 10000, "start": 123}}`.
- **Envio HyperSync** (optional, `ENVIO_API_TOKEN`): a network whose `INDEX_SOURCES` entry names a
  `hypersync` URL is reconciled through it instead: one request reads every member's transfers over
  as many blocks as it answers, with each block's time, where `eth_getLogs` needs two requests per
  hundred members, a short range and one more request per block. The same request finds the native
  coin sent to members (transactions to them that moved value and succeeded), which the RPC path
  cannot. If it fails, the blocks wait for its next run: the RPC does not stand in, or the cursor
  would move past those deposits. It also reads, once per member and network, their transfers from
  the factory's deployment (`since`) up to where the reconciliation is: a payment that reached their
  address before they joined, which the reconciliation had already passed
  (`member_networks.history_read`, so a network added later is read for everyone).

Stellar is optional (`STELLAR_SECRET_KEY`; see `@gatopago/shared/stellar`). Its key creates each
member's Stellar account (the address derives from it and the EVM account, so it receives before
existing), pays the fees of the calls members sign and mints CCTP transfers toward Stellar, which
Circle's Forwarding Service does not reach. Transactions go out one at a time through the
`StellarRelayer` Durable Object, which also mints the burns toward Stellar (`stellar_relays`):
a burn the app reports wakes it, and while one from the last 30 minutes waits it asks Circle every
5 seconds (the attestation is offchain, so no event or webhook announces it). It mints burns the
member sent or that pay the member's Stellar account, each once. Every minute the Worker registers
new members' Stellar addresses (`members.stellar_address`), finds burns toward them sent from any wallet (the
TokenMessenger's `DepositForBurn` events, through HyperSync or `eth_getLogs`, cursor
`stellar-burns:<network>`), wakes the relayer for older ones and reads the USDC and XLM transfer
events since the last ledger into `transfers`, with USDC in 6 decimals like every network,
notifying what members received. After a stop it catches up from its cursor, a few windows per run,
as far back as the RPC keeps events (about a week on the public one); ledgers it no longer keeps
are recorded as missed (`missed:<network>` in `index_cursors`, shown by the health check). Each call it sends is
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
`/app/v1/health` answers 503 while any required one is missing or invalid. Being up is not
enough: it also says which readers are `behind` (they failed since they last moved, or have not
moved in half an hour).

| Name                           | Kind             | What it is                                                                                                                                                                                                      | How to get it                                                                                                                                                                                                              |
| ------------------------------ | ---------------- | --------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- | -------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| `GATOPAGO_ENVIRONMENT`         | var              | Deployment name (`production`); sessions are bound to it                                                                                                                                                        | Fixed per deployment                                                                                                                                                                                                       |
| `WEB_ORIGIN`                   | var              | The web app's origin: the only one CORS allows and SIWE messages name                                                                                                                                           | `https://gatopago.com`                                                                                                                                                                                                     |
| `WALLET_NETWORKS`              | var              | CAIP-2 ids of the networks accounts use, the home network first (owners are read there)                                                                                                                         | Networks with GatoPago's contracts (`protocol/deployments`)                                                                                                                                                                |
| `SPONSORED_OPERATIONS_PER_DAY` | var              | Sponsored operations per account and day                                                                                                                                                                        | Policy; `50` today                                                                                                                                                                                                         |
| `SPONSORED_GAS_PER_DAY`        | var              | Gas an account's sponsored EVM operations may declare per day (their limits added up), at least the 3,000,000 one operation may declare                                                                         | Policy; `20000000` today (about 50 ordinary operations)                                                                                                                                                                    |
| `SUBREQUESTS_PER_RUN`          | var              | External requests one cron run may make; jobs stop there and resume from their cursors on the next run                                                                                                          | Workers Free allows 50 per invocation: `45`. Workers Paid: up to `1000`                                                                                                                                                    |
| `INVITE_ONLY`                  | var              | `on`: new accounts need an invitation. `off`: anyone who passes Turnstile joins (an invitation still counts when used); existing members are never affected. The app reads it at runtime                        | `on`; `off` while judges or an open beta must join. Change it in `wrangler.jsonc` and deploy                                                                                                                               |
| `INDEX_SOURCES`                | var              | Per network, the RPC `url`, blocks per query (`range`) and first block (`start`) the reconciliation reads; with `ENVIO_API_TOKEN`, its HyperSync URL (`hypersync`) and the factory's deployment block (`since`) | Public RPCs and the most each accepts per `eth_getLogs` (Arbitrum 1000, Fuji 2048, Monad 100). Not Alchemy's free tier, which allows 10                                                                                    |
| `WALLET_RPC_URLS`              | secret           | `{"<network>": "<url>"}`: RPC for the bundler, paymaster and reads                                                                                                                                              | Alchemy app _GatoPago-server_ (no domain restriction) with every network enabled: `https://arb-sepolia.g.alchemy.com/v2/<key>`, `https://avax-fuji.g.alchemy.com/v2/<key>`, `https://monad-testnet.g.alchemy.com/v2/<key>` |
| `RELAYER_PRIVATE_KEY`          | secret           | Sends bundles and pays their gas, refunded from the paymaster deposit                                                                                                                                           | A dedicated key (`cast wallet new`); fund it with native gas on every network                                                                                                                                              |
| `SPONSOR_PRIVATE_KEY`          | secret           | Signs gas sponsorships                                                                                                                                                                                          | The paymaster's sponsor signer (`DeployWallet.s.sol`, `GATOPAGO_SPONSOR_SIGNER`)                                                                                                                                           |
| `SESSION_PRIVATE_JWK`          | secret           | ES256 key that signs sessions                                                                                                                                                                                   | `node -e "console.log(JSON.stringify(require('crypto').generateKeyPairSync('ec',{namedCurve:'P-256'}).privateKey.export({format:'jwk'})))"`                                                                                |
| `TURNSTILE_SECRET_KEY`         | secret           | Verifies the sign-up challenge                                                                                                                                                                                  | Cloudflare → Turnstile → the widget's secret key (the web uses its site key)                                                                                                                                               |
| `ALCHEMY_WEBHOOKS`             | secret, optional | `{"<network>": {"id", "signing_key"}}` of each Address Activity webhook, to receive movements as they happen                                                                                                    | Alchemy → Webhooks → one _Address Activity_ webhook per network, URL `https://api.gatopago.com/app/v1/webhooks/alchemy`; each one's ID (`wh_…`) and _signing key_                                                          |
| `ALCHEMY_AUTH_TOKEN`           | secret, optional | Adds new members' addresses to those webhooks                                                                                                                                                                   | Alchemy → Webhooks → _Auth token_ (top right)                                                                                                                                                                              |
| `FIREBASE_SERVICE_ACCOUNT`     | secret, optional | Sends payment notifications through FCM                                                                                                                                                                         | Firebase → Project settings → Service accounts → _Generate new private key_; upload the JSON with `pnpm wrangler secret put FIREBASE_SERVICE_ACCOUNT < key.json` and delete the file                                       |
| `STELLAR_NETWORK`              | var              | CAIP-2 id of the Stellar network                                                                                                                                                                                | `stellar:testnet` (the networks in `@gatopago/shared/networks`)                                                                                                                                                            |
| `STELLAR_SECRET_KEY`           | secret, optional | Enables Stellar: creates members' Stellar accounts, pays their fees, relays CCTP toward Stellar. Members' Stellar addresses derive from it: never change it once they have one                                  | A new Stellar key (`node -e "console.log(require('@stellar/stellar-sdk').Keypair.random().secret())"`); fund its public key with XLM (testnet: `https://friendbot.stellar.org?addr=<G…>`)                                  |
| `STELLAR_RPC_URL`              | secret, optional | Stellar RPC (default: the network's public RPC)                                                                                                                                                                 | A Stellar RPC provider, if the public one falls short                                                                                                                                                                      |
| `ENVIO_API_TOKEN`              | secret, optional | Reads the networks with a `hypersync` source in `INDEX_SOURCES` through Envio HyperSync, and members' earlier history                                                                                           | envio.dev → API tokens (the free plan has one per account)                                                                                                                                                                 |

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
real accounts with a software passkey. Stellar has no forks: the `stellar` tests use testnet, with
a sponsor Friendbot funds before them; the rest run without it (`pnpm test -t <name>` picks some).
`pnpm typecheck`, `pnpm lint` and `pnpm build` complete the checks.

`@gatopago/shared` comes from `vendor/`, built by `protocol`.
