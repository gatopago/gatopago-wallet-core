import { isProfilePath, profileRoute } from './accounts/profileRoute';
import { configuredEnvironment } from './auth/config';
import { isAuthPath, authRoute } from './auth/route';
import { CLIENT_COMPATIBILITY_PATH } from '@gatopago/shared/v3/client-release';
import { clientProtocolRoute } from './clientProtocol';
import { isWalletReadPath, walletReadRoute } from './accounts/route';
import { enrollmentRoute, isEnrollmentPath } from './enrollment/route';
import { isInitializationPath } from './creation/initializationRoute';
import { isCreationOperationPath } from './creation/creationOperationRoute';
import { dispatchWalletJobs } from './execution/walletJobHandlers';
import { isBackupPath } from './security/backupRoute';
import { isTransferCommandPath } from './transfers/transferRoute';
import { isMoneyReadPath } from './money/moneyReadRoute';
import { isMoneyCommandPath } from './money/moneyRoute';
import { pruneAuthChallenges } from './auth/retention';
import { pruneLimits } from './auth/limits';
import { parseResourceId } from '@gatopago/shared/v3/primitives';

import catalog from './runtime/catalog';
import { createWalletRuntime } from './runtime';

// The environment resolver is also explicit for in-process composition tests.
export function createWalletWorker(configuration?: unknown, environment = configuredEnvironment) {
  return {
    async scheduled(_controller: ScheduledController, env: WalletCoreV3Bindings): Promise<void> {
      await Promise.all([pruneAuthChallenges(env.WALLET_DB), pruneLimits(env.WALLET_DB, Math.floor(Date.now() / 1000))]);
      const config = environment(env);
      const { jobs, recoverRelay } = createWalletRuntime(env, config, configuration ?? catalog(config));
      const results = await Promise.allSettled([recoverRelay(env.WALLET_DB), jobs.creation.wake(env), jobs.backup.wake(env), jobs.transfer.wake(env), jobs.money.wake(env)]);
      if (results.some((result) => result.status === 'rejected')) throw new Error('WALLET_SCHEDULER_FAILED');
    },
    async queue(batch: MessageBatch<unknown>, env: WalletCoreV3Bindings): Promise<void> {
      const config = environment(env);
      const runtime = createWalletRuntime(env, config, configuration ?? catalog(config));
      await dispatchWalletJobs(batch, env, runtime.jobs);
    },
    async fetch(request: Request, env: WalletCoreV3Bindings, ctx?: ExecutionContext): Promise<Response> {
      const path = new URL(request.url).pathname;
      if (path === '/app/v1/health/live') return Response.json({ service: 'gatopago-wallet-core', status: 'ok' },
        { headers: { 'Cache-Control': 'no-store' } });
      if (path !== '/app/v1/health/ready' && !isProfilePath(path) && !isAuthPath(path) && path !== CLIENT_COMPATIBILITY_PATH && !isWalletReadPath(path) && !isEnrollmentPath(path) && !isInitializationPath(path) && !isCreationOperationPath(path) && !isBackupPath(path) && !isTransferCommandPath(path) && !isMoneyReadPath(path) && !isMoneyCommandPath(path)) return Response.json({ error_code: 'NOT_FOUND' },
        { status: 404, headers: { 'Cache-Control': 'no-store' } });
      try {
        const config = environment(env);
        let runtime: ReturnType<typeof createWalletRuntime> | undefined;
        const walletRuntime = () => runtime ??= createWalletRuntime(env, config, configuration ?? catalog(config));
        // Identity and stored history remain readable if financial configuration is
        // unavailable. Resolve providers only for the authenticated chain-read path.
        if (isProfilePath(path)) return await profileRoute(request, env, config,
          (owned, signal) => walletRuntime().receivingProfiles(owned, signal));
        if (isAuthPath(path)) return await authRoute(request, env, config,
          (owned, signal) => walletRuntime().receivingProfiles(owned, signal));
        if (isEnrollmentPath(path)) return await enrollmentRoute(request, env, config,
          (owned, signal) => walletRuntime().receivingProfiles(owned, signal));
        if (isWalletReadPath(path)) return await walletReadRoute(request, env, config,
          (owned, signal) => walletRuntime().balanceProfiles(owned, signal),
          (owned, signal) => walletRuntime().receivingProfiles(owned, signal),
          () => walletRuntime().accountContextProfiles);
        const resolved = walletRuntime();
        if (isMoneyReadPath(path)) return await resolved.moneyRead(request, env, config);
        if (isMoneyCommandPath(path)) {
          const response = await resolved.money(request, env, config);
          if (ctx && response.ok && request.method === 'POST' && path.endsWith('/deliver')) ctx.waitUntil(resolved.jobs.money.wake(env).catch(() => {
            console.warn({ event: 'v3_money_wake_failed' });
          }));
          return response;
        }
        if (path === '/app/v1/health/ready') return Response.json({ service: 'gatopago-wallet-core', configured: resolved.configured,
          capabilities: resolved.capabilities, networks: resolved.networks },
          { status: resolved.configured ? 200 : 503, headers: { 'Cache-Control': 'no-store' } });
        if (isTransferCommandPath(path)) return await resolved.transfer(request, env, config);
        if (isBackupPath(path)) return await resolved.backup(request, env, config);
        if (isCreationOperationPath(path)) {
          const response = await resolved.creationOperation(request, env, config);
          if (ctx && response.ok && request.method === 'POST' && path.endsWith('/authorize')) {
            const id = parseResourceId('operation', path.split('/')[4]);
            // A best-effort wake-up is not part of financial authorization. Cron
            // recovers the durable job if this notification fails or is interrupted.
            ctx.waitUntil(resolved.jobs.creation.wake(env, id).catch(() => {
              console.warn({ event: 'v3_creation_wake_failed' });
            }));
          }
          return response;
        }
        if (isInitializationPath(path)) return await resolved.initialization(request, env, config);
        return clientProtocolRoute(request, config, resolved.accountProfiles);
      }
      catch { return Response.json({ error_code: 'SERVICE_UNAVAILABLE' }, { status: 503,
        headers: { 'Cache-Control': 'no-store', 'Retry-After': '60' } }); }
    },
  } satisfies ExportedHandler<WalletCoreV3Bindings>;

}
export default createWalletWorker();
export { WalletIdentity } from './auth/service';
