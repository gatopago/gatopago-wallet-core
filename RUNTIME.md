# Configuración del runtime

`src/runtime` conecta creación, primer respaldo, balances y transferencias a las rutas, Cron y Queue del Worker. Cada invocación valida su catálogo y construye sus clientes; no conserva evidencia ni clientes con secretos en estado global.

## Datos públicos y secretos

`src/runtime/catalog.ts` define el perfil de Arbitrum Sepolia, sus observadores, activos y presupuestos. Importa el mismo perfil contractual que Web desde `@gatopago/shared/v3/wallet-release`. La red se habilita con `GATOPAGO_WALLET_NETWORKS`; el label del entorno no selecciona URLs ni habilita mainnet. Cada entrada admite exactamente estos campos:

| Campo | Contenido |
|---|---|
| `creationProfile` | `document` JSON serializado y su `digest`; incluye deployment desplegado, code hashes, EntryPoint y parámetros de creación |
| `finalityPolicy` | `document` y `digest` de la política vigente para esa red y genesis |
| `rpc` | Dos objetos `{operatorId, endpoint}` con operadores y hosts distintos |
| `transport` | `{kind: "bundler", endpoint}` o `{kind: "self", endpoint, maxGas, maxFeePerGas, maxPriorityFeePerGas}` |
| `assets` | Mapa de CAIP-19 a `{symbol, decimals}`, entre 1 y 32 activos de esa red; incluye exactamente un activo nativo |
| `creationGas`, `transferGas` | `verificationGasLimit`, `callGasLimit`, `preVerificationGas`, `maxFeePerGas`, `maxPriorityFeePerGas`, como strings decimales |
| `backupSponsor` | `null`, o `{operator, maxGas, maxFeePerGas, maxPriorityFeePerGas, maxExecutionFee}`, con importes como strings decimales |
| `paymaster` | `null`, o la política de patrocinio descrita abajo; el campo es obligatorio |

`WALLET_RPC_ENDPOINTS` es un binding secreto JSON que asocia esos nombres a URLs HTTPS. Puede incluir las credenciales del proveedor; nunca pertenece al catálogo ni a la respuesta de compatibilidad. `WALLET_BACKUP_SIGNER_KEY` es opcional: sólo firma el envío de cambios de seguridad previamente autorizados por el usuario y debe corresponder al `operator` revisado. Sin esa clave, el primer respaldo no se ofrece como capacidad de envío; creación y transferencias pueden operar.

Los límites de gas son techos revisados, no estimaciones de una operación sin firma. Antes de enviar, el transporte debe simular la operación firmada exacta dentro de sus límites. Actualizar esos techos no modifica una autorización existente. Las transferencias actuales no cobran tarifa de plataforma. Los importes de gas se expresan en unidades de gas; tarifas en wei/gas y cargos máximos en wei.

## Admisión

1. Obtener el manifiesto real de contratos y verificar sus hashes, EntryPoint y capacidades del transporte elegido.
2. Configurar los orígenes, Firebase y `GATOPAGO_WALLET_NETWORKS` en los bindings del Worker. `wallet_enabled` debe coincidir con las redes del catálogo; sólo se permite una entrada por red.
3. Configurar los bindings privados en ese mismo entorno y revisar los presupuestos de `src/runtime/catalog.ts`. Los nombres de endpoints no permiten alterar las direcciones contractuales fijadas.
4. Ejecutar `pnpm verify` desde Wallet Core. No requiere descriptor ni build de Web. La creación del cliente debe usar un perfil contractual admitido por el protocolo/API, sin depender de que ambos proyectos tengan la misma build.
5. Hacer el smoke en testnet: creación con passkey, transferencia, recibo finalizado y primer respaldo si su sponsor está habilitado.

La elección del checkpoint consulta `finalized` en ambos RPC y verifica red, genesis, antigüedad, hash y ascendencia. La creación vuelve a comprobar la composición contractual en ese checkpoint. El desacuerdo, un perfil vencido o configuración inválida impiden operar. No se sustituye `finalized` por `latest` para conseguir un resultado exitoso.

`GET /app/v1/health/live` sólo indica vida del Worker. `GET /app/v1/health/ready` devuelve capacidades configuradas, redes, transporte y dirección pública del relayer, con 503 si el catálogo está vacío o es inválido. No publica claves ni endpoints privados, no realiza RPC ni certifica disponibilidad financiera. Las operaciones hacen sus propias comprobaciones frescas. Identidad e historial almacenado no requieren que los proveedores financieros estén configurados correctamente.

Las pruebas de composición usan D1 real de workerd, firmas efímeras y respuestas RPC sintéticas. Comprueban creación por Cron/Queue, replay, finality y rechazo de configuración inválida. No son evidencia de un despliegue público.

## Arbitrum Sepolia desplegado

El perfil de Arbitrum Sepolia llega en el snapshot `@gatopago/shared/v3/wallet-release`; los artefactos contractuales de prueba están en `@gatopago/contract-artifacts`. `node scripts/check-vendor.mjs` verifica los SHA-256 de los paquetes conservados en `vendor/`. Este repositorio consume esos snapshots y no regenera perfiles ni compila contratos. El campo `build_info_sha256` identifica el JSON de salida de Foundry original; `source_tree_sha256` identifica el mapa ordenado de fuentes y sus hashes de los metadatos del compilador.

El mapa privado de endpoints debe proporcionar:

| Nombre | Proveedor |
|---|---|
| `arbitrum_sepolia_offchain` | `https://sepolia-rollup.arbitrum.io/rpc`, Offchain Labs |
| `arbitrum_sepolia_tenderly` | `https://arbitrum-sepolia.gateway.tenderly.co`, Tenderly |

El transporte seleccionado es `self`: Wallet Core envía `EntryPoint.handleOps` mediante el primer RPC. No requiere un endpoint de bundler. Los dos RPC verifican la simulación, el nonce y el saldo de la EOA operativa. `PRIVATE_KEY` aporta una clave dedicada, distinta de las claves de respaldo y paymaster; esa EOA necesita ETH de prueba para adelantar gas. Los límites firmados de verificación siguen siendo 496.000 gas; el techo de la transacción externa es 2.000.000 y no amplía el límite autorizado por el usuario. Este perfil no configura paymaster ni sponsor de respaldo: la cuenta necesita ETH de prueba para creación y transferencias.

La política usa el tag `finalized` de Arbitrum, con vigencia del 26/09 al 25/12/2026. Permite hasta dos horas de antigüedad del bloque finalizado y dos minutos del último bloque; no sustituye el checkpoint por un bloque reciente si el despliegue aún no está finalizado.

Inspección real, explícita y sólo de lectura, mediante los adaptadores del Worker:

```sh
V3_LIVE_RPC=1 pnpm exec vitest run --config vitest.config.ts test/live-deployment.test.ts
```

Esta prueba comprueba la composición contractual en ambos RPC al mismo checkpoint finalizado. No crea cuentas ni envía UserOperations y no sustituye el smoke con passkey y el transporte seleccionado.

## Patrocinio propio

`src/sponsorship/service.ts` conecta `GatoPagoPaymaster` a creación y transferencias.
El transporte puede ser el relayer propio o un endpoint ERC-4337; no se usa la API
de patrocinio ni el SDK de Pimlico. `@gatopago/shared/v3/paymaster` define el formato y el
digest exacto que verifica el contrato. No cambia Account V3 ni su autoridad.

El catálogo admite `paymaster: null` (paga la cuenta) o esta política pública:

```ts
paymaster: {
  address, codeHash, signer, // Datos verificados del despliegue del paymaster.
  verificationGasLimit: '100000', postOpGasLimit: '0',
  maximumCostWei: '1000000000000000',
  dailyGwei: 10000000, userDailyGwei: 1000000, userDailyOperations: 10,
}
```

Los límites del ejemplo son ilustrativos, no una política activada. La clave
correspondiente a `signer` se suministra únicamente mediante
`WALLET_PAYMASTER_SIGNER_KEY`; debe estar separada de owner y deployer. Antes de
emitir cada autorización se comprueban en ambos RPC la red, el bytecode,
EntryPoint, signer, límite contractual distinto de cero y depósito suficiente
para esa operación. La estimación de la operación firmada sigue siendo obligatoria.

Orden: comprobar propiedad y operación → reservar presupuesto → firmar patrocinio
→ mostrar operación exacta → firma del usuario → estimar/enviar → confirmar con
los observadores existentes → registrar coste real. Un error de patrocinio nunca
convierte silenciosamente una operación en gasto de ETH del usuario.

El esquema nuevo `migrations/0001_initial.sql` incluye patrocinio. Cada reserva
referencia al usuario interno mediante una clave foránea; su presupuesto no cambia
al añadir o retirar una passkey. La reserva es un solo
`INSERT` condicional, atómico incluso entre Workers. Limita coste global, coste
por usuario y número de autorizaciones por usuario, por día UTC de emisión.
Los presupuestos usan gwei enteros, redondeados hacia arriba; firmas y costes
reales conservan wei exactos. Un retry de la misma autorización no reserva dos
veces. Los errores, timeouts y caducidades conservan la reserva máxima: caducar
no prueba que una operación no se haya ejecutado. Sólo un recibo finalizado,
validado por los observadores existentes, ajusta el cargo al gasto real, incluso
si la ejecución revirtió. No hay liberación automática por timeout.

Mantener depósito y stake del paymaster, saldo de la EOA del relayer o bundler y RPC
operativos sigue siendo responsabilidad del despliegue. Un presupuesto no
reemplaza al depósito ni garantiza aceptación por el transporte.

El catálogo de Arbitrum Sepolia mantiene `paymaster: null` hasta desplegarlo,
verificar su runtime/configuración y provisionar su clave. Las pruebas locales
ya ejecutan creación y transferencia reales mediante EntryPoint con el paymaster
propio, sin prefondo de gas de la cuenta; esto no equivale a un smoke público.

## Transporte y operaciones pendientes

Creación y transferencias usan `execution/operationTransport.ts`: simulación,
envío y localización de transacción. `self` ejecuta `handleOps` dentro del Worker;
`bundler` implementa los métodos ERC-4337. Cambiar `transport` en el catálogo sólo
selecciona el transporte de nuevos envíos. No cambia contratos ni firmas del cliente.

Una tabla `user_operation_submissions` fija el transporte y su endpoint privado por
UserOperation. Para `self` conserva el nonce, los bytes firmados y el hash de la
transacción antes del primer broadcast. Una restricción única por red/operador/nonce
arbitra invocaciones concurrentes; no se depende de memoria del Worker. Las claves
privadas nunca se escriben en D1. Este registro es interno y no se expone por HTTP.

Después de un timeout, los jobs pueden reenviar exactamente los mismos bytes,
incluso después de vencer el consentimiento. La caducidad de la UserOperation no
elimina el nonce pendiente de la transacción externa de la EOA. EntryPoint mantiene
la validación del plazo firmado: si ya venció, la transacción puede revertir y
consumir gas del operador, pero consumir ese nonce permite avanzar a las posteriores.
No se extiende el consentimiento, no se vuelve a firmar, no se genera otra
transacción, no se suben comisiones ni se cambia el endpoint registrado.
La observación continúa con el transporte
registrado aunque el catálogo ya seleccione otro; el resultado económico y la
finalidad siguen verificándose con los dos RPC independientes. Una simulación de
`handleOps` no garantiza que la ejecución interna termine correctamente.

El Cron recupera el journal de transporte aunque el job económico haya terminado
en revisión. Consulta el nonce `latest` de los dos RPC del operador admitido y
usa el menor como filtro conservador; reenvía como máximo 20 envelopes por red,
en orden de nonce, con un deadline de 30 segundos. Esta recuperación no utiliza
claves privadas, no modifica el journal, no libera reservas y no certifica pagos,
saldos ni finalidad. Las lecturas HTTP de estado no reenvían nada.

No se reciclan nonces ni se borran estas filas por antigüedad. Esta versión no
incorpora sustitución automática de comisiones ni cancelación de transacciones.
Si la EOA no tiene ETH, el endpoint falla permanentemente o las comisiones fijas
quedan bajo el mínimo de la red, el reenvío no garantiza inclusión: el Cron informa
atención pendiente y se necesita intervención operativa. No se declara resuelta
una reserva económica sólo porque haya avanzado el nonce externo.
