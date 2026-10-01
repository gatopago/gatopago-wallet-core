import { encodeFunctionData, isAddress, keccak256, zeroAddress, type Address, type Hex } from 'viem';
import { privateKeyToAccount } from 'viem/accounts';
import { entryPoint09Abi, formatUserOperationRequest, getUserOperationHash, toPackedUserOperation, type UserOperation } from 'viem/account-abstraction';
import { discardResponseBody, readJsonBounded } from '@gatopago/shared/http';
import { requireHash } from '@gatopago/shared/v3/deployment';
import { evmChainId, type NetworkId } from '@gatopago/shared/v3/primitives';
import { rpcEndpoint, validateRpcProviders, type RpcProvider } from '../chainProviders';
import { quoteBackupTransaction } from '../security/backupRpc';
import { prepareBackupTransaction, verifyBackupTransaction, type BackupSponsorPolicy } from '../security/backupTransaction';

export type OperationTransport = { readonly kind: 'bundler'; readonly url: string }
  | { readonly kind: 'self'; readonly url: string; readonly providers: readonly RpcProvider[]; readonly policy: BackupSponsorPolicy };
export interface TransportOperation {
  readonly operation: UserOperation<'0.9'>;
  readonly networkId: NetworkId;
  readonly entryPoint: Address;
  readonly userOpHash: Hex;
  readonly validUntil: number;
}
function transportQuantity(value: unknown): bigint {
  if (typeof value !== 'string' || !/^0x(?:0|[1-9a-f][0-9a-f]{0,63})$(?![\s\S])/.test(value)) throw new Error('TRANSPORT_QUANTITY');
  return BigInt(value);
}
async function rpc(url: string, method: string, params: readonly unknown[], signal: AbortSignal) {
  signal.throwIfAborted();
  const deadline = AbortSignal.any([signal, AbortSignal.timeout(5000)]);
  const body = JSON.stringify({ jsonrpc: '2.0', id: 1, method, params });
  if (body.length > 200_000) throw new Error('TRANSPORT_REQUEST_SIZE');
  const response = await fetch(rpcEndpoint(url), { method: 'POST', redirect: 'manual', signal: deadline,
    headers: { 'Content-Type': 'application/json', Accept: 'application/json' }, body });
  if (!response.ok) { await discardResponseBody(response); throw new Error('TRANSPORT_UNAVAILABLE'); }
  const result = await readJsonBounded<unknown>(response, method === 'eth_getUserOperationReceipt' ? 262_144 : 16_384, deadline);
  if (!result || typeof result !== 'object' || Array.isArray(result) || !('jsonrpc' in result) || result.jsonrpc !== '2.0'
    || !('id' in result) || result.id !== 1 || !('result' in result) || 'error' in result) throw new Error('TRANSPORT_RESPONSE');
  return result.result;
}
function validate(input: TransportOperation) {
  requireHash(input.userOpHash);
  if (!Number.isSafeInteger(input.validUntil) || input.validUntil <= Math.floor(Date.now() / 1000)) throw new Error('TRANSPORT_EXPIRED');
  const chainId = Number(evmChainId(input.networkId));
  if (!Number.isSafeInteger(chainId) || input.operation.authorization
    || getUserOperationHash({ userOperation: input.operation, chainId, entryPointAddress: input.entryPoint,
      entryPointVersion: '0.9' }) !== input.userOpHash) throw new Error('TRANSPORT_OPERATION');
}
function calldata(input: TransportOperation, beneficiary: Address) {
  return encodeFunctionData({ abi: entryPoint09Abi, functionName: 'handleOps', args: [
    [toPackedUserOperation(input.operation)], beneficiary,
  ] });
}
export async function simulateOperation(config: OperationTransport, input: TransportOperation, signal: AbortSignal) {
  validate(input);
  if (config.kind === 'self') {
    // handleOps simulates the exact signed gas limits; the outer transaction has
    // a separate operator budget. Success here is not proof of inner execution.
    await quoteBackupTransaction({ account: input.entryPoint, data: calldata(input, config.policy.operator), value: 0n },
      config.policy, config.providers, signal);
    signal.throwIfAborted(); validate(input);
    return Object.fromEntries((['verificationGasLimit', 'callGasLimit', 'preVerificationGas'] as const).map(key =>
      [key, input.operation[key].toString()]));
  }
  if (transportQuantity(await rpc(config.url, 'eth_chainId', [], signal)) !== evmChainId(input.networkId)) throw new Error('TRANSPORT_CHAIN');
  const points = await rpc(config.url, 'eth_supportedEntryPoints', [], signal);
  if (!Array.isArray(points) || points.length > 32
    || !points.every(p => typeof p === 'string' && isAddress(p, { strict: false })) || !points.some(p => typeof p === 'string'
    && p.toLowerCase() === input.entryPoint.toLowerCase())) throw new Error('TRANSPORT_ENTRYPOINT');
  const result = await rpc(config.url, 'eth_estimateUserOperationGas', [formatUserOperationRequest(input.operation), input.entryPoint], signal);
  if (!result || typeof result !== 'object' || Array.isArray(result)) throw new Error('TRANSPORT_ESTIMATE');
  const estimates: Record<string, string> = {};
  for (const key of ['verificationGasLimit', 'callGasLimit', 'preVerificationGas'] as const) {
    const amount = transportQuantity(Reflect.get(result, key));
    if (amount === 0n || amount > input.operation[key]) throw new Error('TRANSPORT_GAS_EXCEEDED');
    estimates[key] = amount.toString();
  }
  for (const key of ['paymasterVerificationGasLimit', 'paymasterPostOpGasLimit'] as const) {
    if (key in result && transportQuantity(Reflect.get(result, key)) > (input.operation[key] ?? 0n)) throw new Error('TRANSPORT_PAYMASTER_GAS');
  }
  signal.throwIfAborted(); validate(input);
  return estimates;
}

type Submission = { user_op_hash: Hex; payload_hash: Hex; kind: 'self' | 'bundler'; endpoint: string;
  network_id: NetworkId; operator: Address | null; nonce: number | null; raw_transaction: Hex | null;
  transaction_hash: Hex | null; valid_until: number };
async function read(database: D1Database, hash: Hex) {
  return database.withSession('first-primary').prepare('SELECT * FROM user_operation_submissions WHERE user_op_hash = ?')
    .bind(hash).first<Submission>();
}
/** Called only after the domain's durable dispatch grant. The immutable journal
 * pins transport and bytes. A process crash or provider switch never allocates a
 * second transaction for the same signed operation. No key is stored in D1. */
export async function sendOperation(database: D1Database, config: OperationTransport, input: TransportOperation,
  signal: AbortSignal, signerKey?: Hex) {
  validate(input); signal.throwIfAborted();
  const payloadHash = keccak256(calldata(input, zeroAddress));
  let stored = await read(database, input.userOpHash);
  if (!stored) {
    const db = database.withSession('first-primary');
    if (config.kind === 'bundler') {
      await db.prepare(`INSERT INTO user_operation_submissions
        (user_op_hash,payload_hash,kind,endpoint,network_id,valid_until)
        VALUES (?,?,'bundler',?,?,?) ON CONFLICT(user_op_hash) DO NOTHING`)
        .bind(input.userOpHash, payloadHash, rpcEndpoint(config.url), input.networkId, input.validUntil).run();
    } else {
      if (!signerKey) throw new Error('RELAYER_SIGNER_MISSING');
      const account = privateKeyToAccount(signerKey);
      if (account.address.toLowerCase() !== config.policy.operator.toLowerCase()) throw new Error('RELAYER_SIGNER_MISMATCH');
      const call = { account: input.entryPoint, data: calldata(input, config.policy.operator), value: 0n };
      const quoted = await quoteBackupTransaction(call, config.policy, config.providers, signal);
      // Concurrent HTTP/Queue invocations may quote the same chain nonce. A unique
      // D1 constraint arbitrates the reservation; losers sign again BEFORE any I/O
      // that can broadcast. Never release/reuse a reserved nonce on a timeout.
      for (let attempt = 0; attempt < 8; attempt++) {
        validate(input); signal.throwIfAborted();
        const row = await db.prepare(`SELECT max(nonce) AS nonce FROM user_operation_submissions
          WHERE network_id = ? AND operator = ?`).bind(input.networkId, config.policy.operator.toLowerCase()).first<{ nonce: number | null }>();
        const nonce = Math.max(quoted.request.nonce, (row?.nonce ?? -1) + 1);
        const request = prepareBackupTransaction(input.networkId, call, config.policy, { ...quoted.request, nonce });
        const signed = await verifyBackupTransaction(request, await account.signTransaction(request.request));
        validate(input); signal.throwIfAborted();
        const result = await db.prepare(`INSERT INTO user_operation_submissions
          (user_op_hash,payload_hash,kind,endpoint,network_id,operator,nonce,raw_transaction,transaction_hash,valid_until)
          VALUES (?,?,'self',?,?,?,?,?,?,?) ON CONFLICT DO NOTHING`)
          .bind(input.userOpHash, payloadHash, rpcEndpoint(config.url), input.networkId, request.operator, nonce,
            signed.serialized, signed.hash, input.validUntil).run();
        if (!result.success) throw new Error('TRANSPORT_STORAGE');
        if (await read(database, input.userOpHash)) break;
      }
    }
    stored = await read(database, input.userOpHash);
  }
  if (!stored || stored.payload_hash !== payloadHash || stored.network_id !== input.networkId
    || stored.valid_until !== input.validUntil) throw new Error('TRANSPORT_SUBMISSION_CONFLICT');
  validate(input); signal.throwIfAborted();
  if (stored.kind === 'self') {
    await broadcast(stored, signal);
  } else {
    const hash = await rpc(stored.endpoint, 'eth_sendUserOperation', [formatUserOperationRequest(input.operation), input.entryPoint], signal);
    if (hash !== input.userOpHash) throw new Error('TRANSPORT_HASH');
  }
  return input.userOpHash;
}
async function broadcast(stored: Submission, signal: AbortSignal) {
  if (!stored.raw_transaction || !stored.transaction_hash || keccak256(stored.raw_transaction) !== stored.transaction_hash) throw new Error('RELAYER_TRANSACTION');
  if (transportQuantity(await rpc(stored.endpoint, 'eth_chainId', [], signal)) !== evmChainId(stored.network_id)) throw new Error('TRANSPORT_CHAIN');
  const hash = await rpc(stored.endpoint, 'eth_sendRawTransaction', [stored.raw_transaction], signal);
  if (hash !== stored.transaction_hash) throw new Error('TRANSPORT_HASH');
}
/** Private job recovery only, after checking the domain's dispatch grant/lease.
 * An expired UserOperation still leaves an outer EOA nonce outstanding. Replaying
 * the exact envelope may revert in EntryPoint, consuming that nonce, but cannot
 * extend the signed authorization. Never signs, reprices or allocates a nonce.
 * Public receipt reads do not call this function. */
export async function resumeSubmission(database: D1Database, hash: Hex, signal: AbortSignal) {
  requireHash(hash);
  const stored = await read(database, hash);
  if (stored?.kind === 'self') {
    try {
      const consumed = transportQuantity(await rpc(stored.endpoint, 'eth_getTransactionCount', [stored.operator, 'latest'], signal));
      if (stored.nonce === null || !Number.isSafeInteger(stored.nonce)) throw new Error('RELAYER_NONCE');
      if (BigInt(stored.nonce) >= consumed) await broadcast(stored, signal);
    } catch { signal.throwIfAborted(); }
  }
}

/** Private Cron transport recovery, independent of a domain job's timeout/review.
 * Only admitted operators are scanned, at most 20 envelopes per invocation in
 * nonce order. A confirmed nonce is a retry filter, NEVER financial evidence:
 * no balance, reservation, receipt or success state is changed here. Inconsistent
 * peers cause extra identical replays rather than skipping an unconsumed nonce. */
export async function recoverSelfSubmissions(database: D1Database,
  config: Extract<OperationTransport, { kind: 'self' }>, signal: AbortSignal) {
  signal.throwIfAborted();
  const operator = config.policy.operator.toLowerCase(), network = config.policy.networkId;
  const db = database.withSession('first-primary');
  const exists = await db.prepare(`SELECT 1 FROM user_operation_submissions
    WHERE kind = 'self' AND network_id = ? AND operator = ? LIMIT 1`).bind(network, operator).first();
  if (!exists) return;
  const peers = validateRpcProviders(config.providers);
  const counts = await Promise.all(peers.map(async peer => {
    if (transportQuantity(await rpc(peer.url, 'eth_chainId', [], signal)) !== evmChainId(network)) throw new Error('TRANSPORT_CHAIN');
    return transportQuantity(await rpc(peer.url, 'eth_getTransactionCount', [operator, 'latest'], signal));
  }));
  const consumed = counts[0] < counts[1] ? counts[0] : counts[1];
  if (consumed > BigInt(Number.MAX_SAFE_INTEGER)) throw new Error('RELAYER_NONCE');
  const rows = await db.prepare(`SELECT * FROM user_operation_submissions
    WHERE kind = 'self' AND network_id = ? AND operator = ? AND nonce >= ?
    ORDER BY nonce LIMIT 20`).bind(network, operator, Number(consumed)).all<Submission>();
  if (!rows.success) throw new Error('TRANSPORT_STORAGE');
  let failed = 0;
  for (const stored of rows.results) {
    signal.throwIfAborted();
    try { await broadcast(stored, signal); }
    catch { signal.throwIfAborted(); failed++; }
  }
  if (failed) console.warn({ event: 'v3_relayer_recovery_pending', count: failed });
}
/** Read-only transaction locator; callers still verify receipt and finality
 * through two independent execution RPCs. Uses the persisted transport even after
 * changing current providers. null means a recorded but not yet located send. */
export async function submissionTransaction(database: D1Database, hash: Hex, signal: AbortSignal) {
  requireHash(hash);
  const stored = await read(database, hash);
  if (!stored) return undefined;
  if (stored.kind === 'self') {
    requireHash(stored.transaction_hash);
    return stored.transaction_hash;
  }
  return await bundlerTransaction(stored.endpoint, hash, signal) ?? null;
}
export async function bundlerTransaction(url: string, hash: Hex, signal: AbortSignal) {
  const result = await rpc(url, 'eth_getUserOperationReceipt', [hash], signal);
  if (result === null) return undefined;
  if (!result || typeof result !== 'object' || !('userOpHash' in result) || result.userOpHash !== hash
    || !('receipt' in result) || !result.receipt || typeof result.receipt !== 'object' || !('transactionHash' in result.receipt)) throw new Error('TRANSPORT_RECEIPT');
  requireHash(result.receipt.transactionHash);
  if (/^0x0{64}$/.test(result.receipt.transactionHash)) throw new Error('TRANSPORT_RECEIPT');
  return result.receipt.transactionHash;
}
