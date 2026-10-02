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

`verify` comprueba tipos Wrangler, TypeScript, lint, índices SQL, logs, unitarias,
runtime workerd/D1 y bundle dry-run. Las pruebas Anvil leen snapshots propios de
`@gatopago/contract-artifacts`, no compilan Solidity ni necesitan otro repo.

Configurar los secretos sólo aquí siguiendo `.dev.vars.example` y `RUNTIME.md`.
Las credenciales del operador no son autoridad para modificar signers.

Los snapshots de protocolo y pruebas viven en `vendor/`, con versiones y SHA-256.
Nunca se regeneran durante build/test/deploy. Una actualización es explícita:
revisar el paquete nuevo y su compatibilidad, actualizar manifiesto/lockfile,
verificar y publicar este proyecto por separado.

`X-GatoPago-Client-Release` identifica la revisión del protocolo
`wallet-client-v3.1`, no una build de Web. Se conservan allowlist/revocación,
ventanas de aceptación, API/entorno y pareja generación/manifiesto. Las firmas,
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

`WALLET_DB` retains ID `f9aa958c-2c16-4fed-b3e4-a76d9160eb33`.
The binding uses the ID directly. D1 database names cannot be renamed;
the existing dashboard label is retained. Do not create, delete or migrate a
database to change that label. See [D1 migration guidance](https://developers.cloudflare.com/d1/reference/migrations/).
Historical package snapshots, signed fixtures and applied SQL migrations are
not deployment configurations and remain unchanged.

`WalletIdentity` es la interfaz privada consumida por Flow cuando recibe una
sesión Consumer. No expone la base ni exige que Flow tenga estas fuentes.
