import { isAddress, type LocalAccount } from 'viem';
import type { ResourceId } from '@gatopago/shared/v3/primitives';
import { verifyBackupTransaction, type prepareBackupTransaction } from './backupTransaction';

type Transaction = ReturnType<typeof prepareBackupTransaction>;
export interface BackupSigner {
  readonly operator: Transaction['operator'];

  readonly sign: (
    operationId: ResourceId<'operation'>,
    transaction: Transaction,
    signal: AbortSignal,
  ) => Promise<unknown>;
}

export function localBackupSigner(
  account: Pick<LocalAccount, 'address' | 'signTransaction'>,
): BackupSigner {
  if (!isAddress(account.address, { strict: false }) || /^0x0{40}$/i.test(account.address))
    throw new Error('BACKUP_SIGNER_INVALID');
  const operator = account.address.toLowerCase() as Transaction['operator'];
  const sign = account.signTransaction.bind(account);
  return Object.freeze({
    operator,
    async sign(
      _operationId: ResourceId<'operation'>,
      transaction: Transaction,
      signal: AbortSignal,
    ) {
      signal.throwIfAborted();
      if (transaction.operator !== operator) throw new Error('BACKUP_SIGNER_INVALID');
      try {
        const raw = await sign(Object.freeze({ ...transaction.request }));
        signal.throwIfAborted();
        return (await verifyBackupTransaction(transaction, raw)).serialized;
      } catch {
        throw new Error('BACKUP_SIGNER_FAILED');
      }
    },
  });
}
