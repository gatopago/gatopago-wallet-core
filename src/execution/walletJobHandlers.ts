type Handlers = { queue(batch: MessageBatch<unknown>, env: WalletCoreV3Bindings): Promise<void> };

export async function dispatchWalletJobs(
  batch: MessageBatch<unknown>,
  env: WalletCoreV3Bindings,
  handlers: { creation: Handlers; backup: Handlers; transfer: Handlers; money?: Handlers },
) {
  if (batch.queue !== env.CREATION_QUEUE_NAME) throw new Error('UNEXPECTED_WALLET_QUEUE');
  const isBackup = (m: Message<unknown>) =>
    m.body !== null &&
    typeof m.body === 'object' &&
    Reflect.get(m.body, 'kind') === 'account_backup';
  const isTransfer = (m: Message<unknown>) =>
    m.body !== null &&
    typeof m.body === 'object' &&
    Reflect.get(m.body, 'kind') === 'transfer_observation';
  const isMoney = (m: Message<unknown>) =>
    m.body !== null &&
    typeof m.body === 'object' &&
    Reflect.get(m.body, 'kind') === 'money_observation';
  const subset = (messages: readonly Message<unknown>[]): MessageBatch<unknown> => ({
    queue: batch.queue,
    metadata: batch.metadata,
    messages,
    ackAll: () => {
      for (const m of messages) m.ack();
    },
    retryAll: (options) => {
      for (const m of messages) m.retry(options);
    },
  });
  const creation = batch.messages.filter((m) => !isBackup(m) && !isTransfer(m) && !isMoney(m)),
    backup = batch.messages.filter(isBackup);
  const transfer = batch.messages.filter(isTransfer);
  const money = batch.messages.filter(isMoney);
  if (creation.length) await handlers.creation.queue(subset(creation), env);
  if (backup.length) await handlers.backup.queue(subset(backup), env);
  if (transfer.length) await handlers.transfer.queue(subset(transfer), env);
  if (money.length) {
    if (handlers.money) await handlers.money.queue(subset(money), env);
    else for (const message of money) message.retry({ delaySeconds: 60 });
  }
}
