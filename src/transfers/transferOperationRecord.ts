import { readExecutionOperationRecord, writeExecutionOperationRecord } from '../execution/executionOperationRecord';

function legacyError(error: unknown): never {
  if (error instanceof Error && error.message.startsWith('EXECUTION_RECORD_')) throw new Error(error.message.replace('EXECUTION_RECORD_', 'TRANSFER_RECORD_'));
  throw error;
}
/** Legacy transfer names retain their error contract over the common V3 codec. */
export function readTransferOperationRecord(...args: Parameters<typeof readExecutionOperationRecord>) {
  try { return readExecutionOperationRecord(...args); } catch (error) { return legacyError(error); }
}
export function writeTransferOperationRecord(...args: Parameters<typeof writeExecutionOperationRecord>) {
  try { return writeExecutionOperationRecord(...args); } catch (error) { return legacyError(error); }
}
