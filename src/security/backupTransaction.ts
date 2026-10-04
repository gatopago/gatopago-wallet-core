import {
  isAddress,
  keccak256,
  parseTransaction,
  recoverTransactionAddress,
  serializeTransaction,
  type Hex,
  type TransactionSerializableEIP1559,
} from 'viem';
import { evmChainId, UINT256_MAX, type NetworkId } from '@gatopago/shared/v3/primitives';

/** Private operator budget, not a user fee authorization or a creation UserOperation grant.
 * maxExecutionFee bounds gas * maxFeePerGas only. Networks with additional L1/operator
 * fees require their separate admission/budget policy before this transport is enabled. */
export interface BackupSponsorPolicy {
  readonly networkId: NetworkId;
  readonly operator: Hex;
  readonly maxGas: bigint;
  readonly maxFeePerGas: bigint;
  readonly maxPriorityFeePerGas: bigint;
  readonly maxExecutionFee: bigint;
}
export interface BackupTransactionTerms {
  readonly nonce: number;
  readonly gas: bigint;
  readonly maxFeePerGas: bigint;
  readonly maxPriorityFeePerGas: bigint;
}
type Call = { readonly account: Hex; readonly value: bigint; readonly data: Hex };
const invalid = () => new Error('BACKUP_TRANSACTION_INVALID');
function uint(value: bigint, positive = false) {
  if (typeof value !== 'bigint' || value < (positive ? 1n : 0n) || value > UINT256_MAX)
    throw invalid();
}
function bytes(value: unknown): asserts value is Hex {
  if (
    typeof value !== 'string' ||
    value.length > 100_002 ||
    !/^0x(?:[0-9a-f]{2})+$(?![\s\S])/.test(value)
  )
    throw invalid();
}

/** Only type-2 direct calls. No contract creation, access list, blob, 7702 authorization,
 * user value, automatic nonce selection, repricing or chain-specific serializer fallback. */
export function prepareBackupTransaction(
  networkId: NetworkId,
  call: Call,
  policy: BackupSponsorPolicy,
  terms: BackupTransactionTerms,
) {
  const chain = evmChainId(networkId);
  if (
    networkId !== policy.networkId ||
    chain > BigInt(Number.MAX_SAFE_INTEGER) ||
    !isAddress(policy.operator, { strict: false }) ||
    /^0x0{40}$/i.test(policy.operator) ||
    !isAddress(call.account, { strict: false }) ||
    /^0x0{40}$/i.test(call.account) ||
    policy.operator.toLowerCase() === call.account.toLowerCase() ||
    call.value !== 0n ||
    !Number.isSafeInteger(terms.nonce) ||
    terms.nonce < 0
  )
    throw invalid();
  bytes(call.data);
  if (call.data.length < 10) throw invalid();
  for (const v of [
    policy.maxGas,
    policy.maxFeePerGas,
    policy.maxExecutionFee,
    terms.gas,
    terms.maxFeePerGas,
  ])
    uint(v, true);
  uint(policy.maxPriorityFeePerGas);
  uint(terms.maxPriorityFeePerGas);
  if (
    terms.gas > policy.maxGas ||
    terms.maxFeePerGas > policy.maxFeePerGas ||
    terms.maxPriorityFeePerGas > policy.maxPriorityFeePerGas ||
    terms.maxPriorityFeePerGas > terms.maxFeePerGas ||
    terms.gas * terms.maxFeePerGas > policy.maxExecutionFee
  )
    throw invalid();
  const request = Object.freeze({
    type: 'eip1559',
    chainId: Number(chain),
    to: call.account.toLowerCase() as Hex,
    data: call.data,
    value: 0n,
    nonce: terms.nonce,
    gas: terms.gas,
    maxFeePerGas: terms.maxFeePerGas,
    maxPriorityFeePerGas: terms.maxPriorityFeePerGas,
  } satisfies TransactionSerializableEIP1559);
  const unsigned = serializeTransaction(request);
  bytes(unsigned);
  return Object.freeze({
    networkId,
    operator: policy.operator.toLowerCase() as Hex,
    request,
    unsigned,
    unsignedHash: keccak256(unsigned),
  });
}

/** Verify the bytes returned by a sign-only adapter, not its claimed address/hash.
 * Errors deliberately exclude raw transactions, RPC credentials and signer diagnostics. */
export async function verifyBackupTransaction(
  expected: ReturnType<typeof prepareBackupTransaction>,
  raw: unknown,
) {
  try {
    bytes(raw);
    if (!raw.startsWith('0x02')) throw invalid();
    const tx = parseTransaction(raw);
    if (
      tx.type !== 'eip1559' ||
      !tx.r ||
      !tx.s ||
      (tx.yParity !== 0 && tx.yParity !== 1) ||
      BigInt(tx.r) === 0n ||
      BigInt(tx.s) === 0n ||
      BigInt(tx.s) > 0x7fffffffffffffffffffffffffffffff5d576e7357a4501ddfe92f46681b20a0n ||
      serializeTransaction(tx) !== raw ||
      serializeTransaction({
        ...tx,
        r: undefined,
        s: undefined,
        v: undefined,
        yParity: undefined,
      }) !== expected.unsigned ||
      (
        await recoverTransactionAddress({ serializedTransaction: raw as `0x02${string}` })
      ).toLowerCase() !== expected.operator
    )
      throw invalid();
    return Object.freeze({ serialized: raw, hash: keccak256(raw) });
  } catch {
    throw invalid();
  }
}
