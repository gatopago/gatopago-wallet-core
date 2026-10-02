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

`WALLET_DB` uses database `gatopago-wallet-core`, ID
`48996f36-0c69-4b0c-af75-b73e88b4f09b`.
D1 database names cannot be renamed in place. A replacement requires explicit
authorization, an export, schema/data verification and a coordinated binding
change. See [D1 migration guidance](https://developers.cloudflare.com/d1/reference/migrations/).

The database replacement was verified on 2026-10-02 against all 33 source
tables, schema and foreign keys. Temporary migration entrypoints have been
removed. Private SQL exports, audit records and the deployment commit bundle
are preserved outside this repository in `../.operations-backups/2026-10-02/`.

SDK snapshots 3.1.1 accept only the `production` namespace. Development uses
loopback origins and isolated local resources, not another deployment target.
The fresh SQL baseline now permits only production identities. Existing
databases must apply `0002_production_namespace.sql` explicitly: it rejects
incompatible records instead of relabeling them. This local cleanup does not
apply remote migrations or publish a Worker.

`WalletIdentity` es la interfaz privada consumida por Flow cuando recibe una
sesión Consumer. No expone la base ni exige que Flow tenga estas fuentes.
