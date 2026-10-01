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
pnpm deploy:dry-run --staging
```

Estos comandos no publican. Un deploy real requiere autorización independiente
y un commit limpio de este proyecto; cambios de otros repos no lo bloquean.
No ejecutar Wrangler directo para evadir el guard.

`WalletIdentity` es la interfaz privada consumida por Flow cuando recibe una
sesión Consumer. No expone la base ni exige que Flow tenga estas fuentes.
