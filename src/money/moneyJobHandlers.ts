import type { Environment } from '@gatopago/environment';
import { resumeSubmission } from '../execution/operationTransport';
import { withDeadline } from '../deadline';
import { reconcileMoneyJob } from './moneyReconciliation';
import { MoneyJobRepository, parseMoneyWake, type MoneyWake } from './moneyJobs';
import type { MoneyDeliveryProfile } from './moneyPreflight';
import { expiredMoneyCandidates, expireUnsubmittedMoney } from './moneyExpiration';

type Configuration = { readonly environment: Environment['environment']; readonly profiles: readonly MoneyDeliveryProfile[] };
type Bindings = Pick<WalletCoreV3Bindings, 'WALLET_DB' | 'CREATION_QUEUE_NAME'> & { readonly CREATION_JOBS: Pick<Queue<MoneyWake>, 'send'> };

/** Existing queue with an explicit money discriminator. Turning off new money
 * capabilities never removes the obligation to observe a historical dispatch. */
export function createMoneyJobHandlers(resolve: (env: Bindings) => Configuration | null) {
  return {
    async wake(env: Bindings) {
      const config = resolve(env); if (!config?.profiles.length) return;
      const jobs = new MoneyJobRepository(env.WALLET_DB, config); let failed = 0;
      // Bounded maintenance is independent of login and new-operation flags.
      // Dispatched/uncertain operations cannot enter this expiry path.
      const maintenanceDeadline = AbortSignal.timeout(20_000);
      for (const id of await expiredMoneyCandidates(env.WALLET_DB, config)) {
        if (maintenanceDeadline.aborted) break;
        try { await expireUnsubmittedMoney(env.WALLET_DB, config.environment, id, config.profiles, maintenanceDeadline); }
        catch { failed++; }
      }
      for (const id of await jobs.due(20)) {
        const message = await jobs.reserve(id); if (!message) continue;
        try { await env.CREATION_JOBS.send(message, { contentType: 'json' }); }
        catch { failed++; await jobs.fail(message, 'queued'); }
      }
      if (failed) console.warn({ event: 'v3_money_enqueue_failed', count: failed });
    },
    async queue(batch: MessageBatch<unknown>, env: Bindings) {
      if (batch.queue !== env.CREATION_QUEUE_NAME) throw new Error('UNEXPECTED_MONEY_QUEUE');
      const config = resolve(env); if (!config?.profiles.length) { batch.retryAll({ delaySeconds: 60 }); return; }
      const profiles = structuredClone(config.profiles), jobs = new MoneyJobRepository(env.WALLET_DB, { ...config, profiles });
      let failed = 0, malformed = 0, review = 0;
      for (const item of batch.messages) {
        let message;
        try { message = parseMoneyWake(item.body); } catch { malformed++; item.ack(); continue; }
        try {
          if (!await jobs.claim(message)) { item.ack(); continue; }
          try {
            const source = await jobs.observationSource(message);
            if (Math.floor(Date.now() / 1000) >= source.startedAt + 86400) {
              if (await jobs.review(message, 'observation_timeout')) review++;
            } else {
              const outcome = await withDeadline(new AbortController().signal, 60_000, async signal => {
                // Only replay an already journaled raw transaction. A crash before
                // journaling remains uncertain; this job cannot sign a new send.
                await resumeSubmission(env.WALLET_DB, source.record.candidate.userOpHash, signal);
                return reconcileMoneyJob(env.WALLET_DB, config.environment, message, profiles, signal);
              });
              if (outcome.state === 'waiting') await jobs.defer(message, 30);
              if (outcome.state === 'review' && await jobs.review(message, outcome.reason)) review++;
            }
          } catch { failed++; await jobs.fail(message, 'running'); }
          item.ack();
        } catch { failed++; item.retry({ delaySeconds: 60 }); }
      }
      if (failed || malformed || review) console.warn({ event: 'v3_money_job_attention', failed, malformed, review });
    },
  };
}
