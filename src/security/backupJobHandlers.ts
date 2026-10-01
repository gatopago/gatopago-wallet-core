import { withDeadline } from '../deadline';
import { BackupJobRepository, parseBackupWake, type BackupWake } from './backupJobs';
import { createBackupProcessor, type BackupJobConfiguration } from './processBackupJob';

type Bindings = Pick<WalletCoreV3Bindings, 'WALLET_DB' | 'CREATION_QUEUE_NAME'> & {
 readonly CREATION_JOBS: Pick<Queue<BackupWake>, 'send'>;
};
export function createBackupJobHandlers(resolve: (env: Bindings) => BackupJobConfiguration | null) {
 return {
  async wake(env: Bindings) {
   const config = resolve(env); if (!config || !config.networks.length) return;
   const processor = createBackupProcessor(config), jobs = new BackupJobRepository(env.WALLET_DB, processor.configuration);
   let failed = 0;
   for (const id of await jobs.due(20)) {
    const message = await jobs.reserve(id); if (!message) continue;
    try { await env.CREATION_JOBS.send(message, { contentType: 'json' }); }
    catch { failed++; await jobs.fail(message, 'queued'); }
   }
   if (failed) console.warn({ event: 'v3_backup_enqueue_failed', count: failed });
  },
  async queue(batch: MessageBatch<unknown>, env: Bindings) {
   if (batch.queue !== env.CREATION_QUEUE_NAME) throw new Error('UNEXPECTED_BACKUP_QUEUE');
   const config = resolve(env); if (!config || !config.networks.length) { batch.ackAll(); return; }
   const processor = createBackupProcessor(config), jobs = new BackupJobRepository(env.WALLET_DB, processor.configuration);
   let failed = 0, malformed = 0, review = 0;
   for (const item of batch.messages) {
    let message;
    try { message = parseBackupWake(item.body); } catch { malformed++; item.ack(); continue; }
    try {
     if (!await jobs.claim(message)) { item.ack(); continue; }
     try {
      const outcome = await withDeadline(new AbortController().signal, 120_000,
       (signal) => processor.run(env.WALLET_DB, message.operation_id, signal));
      if (await jobs.finish(message, outcome) && outcome.state === 'review') review++;
     } catch { failed++; await jobs.fail(message, 'running'); }
     item.ack();
    } catch { failed++; item.retry({ delaySeconds: 60 }); }
   }
   if (failed || malformed || review) console.warn({ event: 'v3_backup_job_attention', failed, malformed, review });
  },
 };
}
