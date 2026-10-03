# GatoPago Wallet Core

Identidad, credenciales, Account V3, seguridad, balances y transferencias.
Este proyecto posee `WALLET_DB`, sus migraciones y jobs. No importa código de
Web, Flow o contratos.

Desde esta carpeta, con Node 24, pnpm 11.23.0 y Foundry 1.7.1 (Anvil para pruebas):

```sh
pnpm install --frozen-lockfile
pnpm verify
pnpm dev
```

`verify` comprueba tipos Wrangler, TypeScript, lint, código sin uso/ciclos, índices SQL, logs, unitarias,
runtime workerd/D1 y bundle dry-run. Las pruebas Anvil leen snapshots propios de
`@gatopago/contract-artifacts`, no compilan Solidity ni necesitan otro repo.

Para desarrollo, copiar `.env.example` a `.env` y configurar los secretos sólo
aquí siguiendo `RUNTIME.md`. `.dev.vars.example` contiene placeholders vacíos
para generar tipos y empaquetar; no configura un runtime operativo.
Las credenciales del operador no son autoridad para modificar signers.

## Invitation codes

Operators choose the invitation code and store it directly as text in
`signup_invites.code`. Codes are matched exactly, including case and spaces;
there is no fixed length, alphabet, random generator or hash to calculate.
For example, `123`, `daniel` and `team1` are valid codes. Codes must be nonempty
and unique. Expiry, revocation and single-use admission remain enforced.
Predictable codes can be guessed; keep them private if admission is restricted.

After applying `0003_plaintext_invitation_codes.sql`, create a seven-day invite
in the Wallet Core D1 console:

```sql
INSERT INTO signup_invites (code, issued_by, created_at, expires_at)
VALUES ('daniel', 'operator', unixepoch(), unixepoch() + 604800);

SELECT code, issued_by, expires_at, consumed_by, revoked_at
FROM signup_invites ORDER BY created_at DESC LIMIT 20;
```

Registration remains rate-limited and requires Turnstile and a verified passkey.
The Web form and `#invite=daniel` links accept the same plain text; URL-encode
codes containing spaces or URL delimiters. The existing request-body size limit
still applies. Do not log invitation codes or publish database exports.

The new migration preserves users, credentials and login challenges. It stops
if old hashed invitations exist: their original text cannot be recovered from a
hash, so an operator must explicitly resolve those records before migration.
Coordinate the migration, Wallet Core deployment and Web deployment; the new
runtime requires the new columns. Local tests do not update production D1.

Los snapshots de protocolo y pruebas viven en `vendor/`, con versiones y SHA-256.
Nunca se regeneran durante build/test/deploy. Una actualización es explícita:
revisar el paquete nuevo y su compatibilidad, actualizar manifiesto/lockfile,
verificar y publicar este proyecto por separado.

`X-GatoPago-Client-Release` identifica la revisión del protocolo
`wallet-client-v3.1`, no una build de Web. Sólo se acepta esa revisión con la
API y el entorno actuales y la pareja generación/manifiesto admitida. Las firmas,
nonces, permisos y evidencia siguen siendo la autoridad monetaria.

```sh
pnpm deploy:dry-run
```

Estos comandos no publican. Un deploy real requiere autorización independiente
y un commit limpio de este proyecto; cambios de otros repos no lo bloquean.
No ejecutar Wrangler directo para evadir el guard.

## Production deployment

`wrangler.remote.jsonc` is the only remote deployment configuration:
`api.gatopago.com`, `gatopago-wallet-core`, and production environment records.
Local development uses isolated local D1 and queues; production hosting does
not authorize mainnet or live funds.

Production queue identities:

| Queue | ID |
| --- | --- |
| `gatopago-wallet-core-jobs` | `167dadefcaf745c69bfcf268130adc60` |
| `gatopago-wallet-core-jobs-dlq` | `ac1119ef6d084485915bc67e2fc25ce4` |

For an in-place name transition, pause delivery, rename the bound queues
without replacing their IDs, messages or settings, publish the Worker, verify
bindings, and resume delivery. The deploy script checks both target queues
exist before publishing; dry-run does not.

The new Worker also requires the additive `0004_money_operations.sql` schema:
its scheduler continues to read money jobs even when all money flags are closed.
Apply the migration before publishing this Worker, preserving the existing
tables and in-flight transfers. The deployment script reads the remote migration
ledger and compares all money tables, indexes and triggers with an in-memory
SQLite reference before any upload. Missing or changed objects block deployment;
the check never applies a migration or reads user rows. Run
`pnpm check:deployment-schema` independently for this read-only preflight.
`pnpm deploy:dry-run` remains local and performs no remote schema query.

`WALLET_DB` uses database `gatopago-wallet-core`, ID
`48996f36-0c69-4b0c-af75-b73e88b4f09b`.
D1 database names cannot be renamed in place. A replacement requires explicit
authorization, an export, schema/data verification and a coordinated binding
change. See [D1 migration guidance](https://developers.cloudflare.com/d1/reference/migrations/).

The database replacement was verified on 2026-10-02 against all 33 source
tables, schema and foreign keys. Temporary migration entrypoints have been
removed. Private SQL exports, audit records and the deployment commit bundle
are preserved outside this repository in `../.operations-backups/2026-10-02/`.

SDK snapshots 3.2.1 accept only the `production` namespace. Development uses
loopback origins and isolated local resources, not another deployment target.
The fresh SQL baseline now permits only production identities. Existing
databases must apply `0002_production_namespace.sql` explicitly: it rejects
incompatible records instead of relabeling them. This local cleanup does not
apply remote migrations or publish a Worker.

`WalletIdentity` es la interfaz privada consumida por Flow cuando recibe una
sesión Consumer. No expone la base ni exige que Flow tenga estas fuentes.

## Arbitrum monetary programs

`config/application.json` selects the money schema, account profile, market
and three feature flags. Public market pins and bounded gas policies live in
`config/markets` and `config/money-gas.json`; RPC credentials and signing keys
remain private bindings. All three features are currently disabled.

The owner-only money routes prepare, confirm, deliver and read the same signed
operation. Migration `0004_money_operations.sql` adds a spend lock shared with
existing transfers, durable jobs and evidence-based reconciliation/expiration.
It has been tested locally and has not been applied remotely.

GET recovery requires a current valid owner and can show an older operation
after session revocation. Confirm/deliver retain the original authorization
epoch check. Timeouts and closing a session retain unresolved reservations.

An outer `handleOps` failure is reconciled only against the exact private signed
envelope, agreement between both receipt readers, finalized inclusion and a
finalized post-expiry checkpoint with the original EntryPoint nonce unchanged.
The post-expiry checkpoint is deterministic so restarting a job preserves its
immutable receipt digest. The receipt separates the account's zero charge from
the operator's observed outer gas, including the Nitro L1 gas component. Bundler
locators, missing journals and consumed nonces retain the unresolved reservation.

See [cross-repository evidence](../protocol/docs/arbitrum-delivery/STATUS.md).

`pnpm inspect:passkey-runtime` performs a separate read-only check against the
two public Arbitrum Sepolia RPCs. It checks chain/genesis and deployed code pins,
native P256 and the V3 verifier with positive/negative vectors, then simulates
the exact creation UserOperation with synthetic balances only in `eth_call`.
The reviewed self-transport creation ceiling is 750,000 verification gas:
496,000 failed with AA13 on both RPCs; 750,000 passed. Earlier prepared reviews
keep their stored terms and require their own exact simulation before delivery.
The inspection uses public scalar 1, creates no credential or public account,
and does not establish hardware-passkey access, a receipt or bundler admission.
