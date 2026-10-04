export async function withDeadline<T>(
  parent: AbortSignal,
  milliseconds: number,
  action: (signal: AbortSignal) => Promise<T>,
): Promise<T> {
  parent.throwIfAborted();
  if (!Number.isSafeInteger(milliseconds) || milliseconds < 1 || milliseconds > 120_000)
    throw new Error('INVALID_DEADLINE');
  const controller = new AbortController();
  const cancel = () => controller.abort(parent.reason);
  parent.addEventListener('abort', cancel, { once: true });
  const timer = setTimeout(
    () => controller.abort(new DOMException('Operation timed out', 'TimeoutError')),
    milliseconds,
  );
  try {
    const value = await action(controller.signal);
    controller.signal.throwIfAborted();
    return value;
  } finally {
    clearTimeout(timer);
    parent.removeEventListener('abort', cancel);
  }
}

export function abortable<T>(work: Promise<T>, signal: AbortSignal): Promise<T> {
  return new Promise((resolve, reject) => {
    const abort = () => {
      signal.removeEventListener('abort', abort);
      reject(signal.reason);
    };
    signal.addEventListener('abort', abort, { once: true });
    work.then(
      (value) => {
        signal.removeEventListener('abort', abort);
        resolve(value);
      },
      (error: unknown) => {
        signal.removeEventListener('abort', abort);
        reject(error);
      },
    );
    if (signal.aborted) abort();
  });
}
