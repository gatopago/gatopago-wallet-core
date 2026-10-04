export type RpcRead = { id: number; method: string; params: readonly unknown[] };

/** Synthetic HTTP provider supports both single requests and real JSON-RPC batches. */
export async function rpcReply(
  init: RequestInit | undefined,
  read: (request: RpcRead) => Promise<unknown>,
) {
  init?.signal?.throwIfAborted();
  const body = JSON.parse(String(init?.body)) as RpcRead | RpcRead[];
  const reply = async (request: RpcRead) => ({
    jsonrpc: '2.0',
    id: request.id,
    result: await read(request),
  });
  return Response.json(
    Array.isArray(body) ? await Promise.all(body.map(reply)) : await reply(body),
  );
}
