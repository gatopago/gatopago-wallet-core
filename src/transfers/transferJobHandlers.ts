import { resumeSubmission } from '../execution/operationTransport';
import type { Environment } from '@gatopago/environment';
import { withDeadline } from '../deadline';
import { reconcileTransferJob } from './transferJobReconciliation';
import { TransferJobRepository, parseTransferWake, type TransferWake } from './transferJobs';

type Configuration = {
  readonly environment: Environment['environment'];
  readonly profiles: Parameters<typeof reconcileTransferJob>[3];
};
type Bindings = Pick<WalletCoreV3Bindings, 'WALLET_DB' | 'CREATION_QUEUE_NAME'> & {
  readonly CREATION_JOBS: Pick<Queue<TransferWake>, 'send'>;
};
export function createTransferJobHandlers(resolve: (env: Bindings) => Configuration | null) {
  return {
    async wake(env: Bindings) {
      const config = resolve(env);
      if (!config || !config.profiles.length) return;
      const jobs = new TransferJobRepository(env.WALLET_DB, config);
      let failed = 0;
      for (const id of await jobs.due(20)) {
        const message = await jobs.reserve(id);
        if (!message) continue;
        try {
          await env.CREATION_JOBS.send(message, { contentType: 'json' });
        } catch {
          failed++;
          await jobs.fail(message, 'queued');
        }
      }
      if (failed) console.warn({ event: 'v3_transfer_enqueue_failed', count: failed });
    },
    async queue(batch: MessageBatch<unknown>, env: Bindings) {
      if (batch.queue !== env.CREATION_QUEUE_NAME) throw new Error('UNEXPECTED_TRANSFER_QUEUE');
      const config = resolve(env);
      if (!config || !config.profiles.length) {
        batch.ackAll();
        return;
      }
      const profiles = structuredClone(config.profiles),
        environment = config.environment;
      const jobs = new TransferJobRepository(env.WALLET_DB, { environment, profiles });
      let failed = 0,
        malformed = 0,
        review = 0;
      for (const item of batch.messages) {
        let message;
        try {
          message = parseTransferWake(item.body);
        } catch {
          malformed++;
          item.ack();
          continue;
        }
        try {
          if (!(await jobs.claim(message))) {
            item.ack();
            continue;
          }
          try {
            const source = await jobs.observationSource(message);
            if (Math.floor(Date.now() / 1000) >= source.startedAt + 86400) {
              if (await jobs.review(message, 'observation_timeout')) review++;
            } else {
              const outcome = await withDeadline(
                new AbortController().signal,
                120_000,
                async (signal) => {
                  await resumeSubmission(env.WALLET_DB, source.record.candidate.userOpHash, signal);
                  return reconcileTransferJob(
                    env.WALLET_DB,
                    environment,
                    message,
                    profiles,
                    signal,
                  );
                },
              );
              if (outcome.state === 'waiting') await jobs.defer(message, 30);
              if (outcome.state === 'review' && (await jobs.review(message, outcome.reason)))
                review++;
              // Reconciliation itself atomically finishes the durable job.
            }
          } catch {
            failed++;
            await jobs.fail(message, 'running');
          }
          item.ack();
        } catch {
          failed++;
          item.retry({ delaySeconds: 60 });
        }
      }
      if (failed || malformed || review)
        console.warn({ event: 'v3_transfer_job_attention', failed, malformed, review });
    },
  };
}
