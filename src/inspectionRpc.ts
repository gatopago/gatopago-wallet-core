import { readJsonBounded, discardResponseBody } from '@gatopago/shared/http';
import { withDeadline } from './deadline';

type Read = { method: string; params?: readonly unknown[] };
type Entry = {
  id: number;
  payload: string;
  key: string;
  resolve: (value: unknown) => void;
  reject: (reason: unknown) => void;
};
const methods = new Set([
  'eth_chainId',
  'eth_getBlockByNumber',
  'eth_getCode',
  'eth_call',
  'eth_getTransactionReceipt',
  'eth_getTransactionByHash',
]);
const maximumBatch = 32;

export function inspectionRpc(url: string, signal: AbortSignal, batch: boolean) {
  let requestId = 0;
  let queue: Entry[] = [];
  const pending = new Map<string, Promise<unknown>>();

  async function exchange(entries: readonly Entry[]): Promise<unknown[]> {
    return withDeadline(signal, 5000, async (timeout) => {
      const batched = entries.length > 1;
      const response = await fetch(url, {
        method: 'POST',
        redirect: 'manual',
        signal: timeout,
        headers: { 'Content-Type': 'application/json', Accept: 'application/json' },
        body: batched ? `[${entries.map((entry) => entry.payload).join(',')}]` : entries[0].payload,
      });
      if (!response.ok) {
        await discardResponseBody(response);
        throw new Error('Inspection RPC unavailable');
      }

      const body = await readJsonBounded<unknown>(response, batched ? 524_288 : 131_072, timeout);
      const rows =
        batched && Array.isArray(body) ? body : !batched && !Array.isArray(body) ? [body] : [];
      if (rows.length !== entries.length) throw new Error('Invalid inspection RPC envelope');
      const expected = new Set(entries.map((entry) => entry.id));
      const values = new Map<number, unknown>();
      for (const row of rows) {
        if (
          !row ||
          typeof row !== 'object' ||
          Array.isArray(row) ||
          !('jsonrpc' in row) ||
          row.jsonrpc !== '2.0' ||
          !('id' in row) ||
          typeof row.id !== 'number' ||
          !expected.has(row.id) ||
          values.has(row.id) ||
          !('result' in row) ||
          'error' in row
        )
          throw new Error('Invalid inspection RPC envelope');
        values.set(row.id, row.result);
      }
      timeout.throwIfAborted();
      return entries.map((entry) => values.get(entry.id));
    });
  }

  async function flush() {
    const entries = queue;
    queue = [];
    try {
      const values = await exchange(entries);

      for (const entry of entries) pending.delete(entry.key);
      entries.forEach((entry, index) => entry.resolve(values[index]));
    } catch (error) {
      for (const entry of entries) {
        pending.delete(entry.key);
        entry.reject(error);
      }
    }
  }

  return {
    async request({ method, params = [] }: Read): Promise<unknown> {
      if (!methods.has(method)) throw new Error('Inspection RPC method is read-only');
      signal.throwIfAborted();
      const key = JSON.stringify({ method, params });
      if (batch && pending.has(key)) return pending.get(key)!;
      if (batch && queue.length >= maximumBatch) throw new Error('Inspection RPC batch limit');
      const id = ++requestId;

      const payload = `{"jsonrpc":"2.0","id":${id},${key.slice(1)}`;
      if (!batch) return (await exchange([{ id, payload, key, resolve() {}, reject() {} }]))[0];
      const work = new Promise<unknown>((resolve, reject) => {
        queue.push({ id, payload, key, resolve, reject });
      });
      pending.set(key, work);
      if (queue.length === 1)
        queueMicrotask(() => {
          flush().catch(() => {});
        });
      return work;
    },
  };
}
