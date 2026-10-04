import { paymasterFields, parsePaymasterTerms } from '@gatopago/shared/v3/paymaster';
import { decodeAbiParameters, decodeFunctionData, getAddress, zeroAddress, type Hex } from 'viem';
import { getUserOperationHash, type UserOperation } from 'viem/account-abstraction';
import {
  authorizationDigest,
  authorizationTypes,
  hashCalls,
} from '@gatopago/shared/v3/authorizations';
import { deploymentDocumentDigest, requireHash } from '@gatopago/shared/v3/deployment';
import { encodeExecutionSignature, executionAbi } from '@gatopago/shared/v3/execution';
import { evmChainId, parseAtomicAmount } from '@gatopago/shared/v3/primitives';

type Operation = UserOperation<'0.9'>;
export type ExecutionRecordBinding = Readonly<{
  network_id: string;
  account: string;
  account_id: Hex;
  entry_point: string;
  userop_hash: Hex;
  consent_digest: Hex;
  valid_until: number;
}>;
const gasFields = [
  'verificationGasLimit',
  'callGasLimit',
  'preVerificationGas',
  'maxFeePerGas',
  'maxPriorityFeePerGas',
] as const;
const keys = ['sender', 'nonce', 'callData', ...gasFields, 'signature'];
const sponsorKeys = [
  'paymaster',
  'paymasterVerificationGasLimit',
  'paymasterPostOpGasLimit',
  'paymasterData',
];
const recordKeys = (value: object) =>
  Object.hasOwn(value, 'paymaster') ? [...keys, ...sponsorKeys] : keys;
const maxRecordLength = 180_000;

function bytes(value: unknown, max: number): Hex {
  if (
    typeof value !== 'string' ||
    value.length > 2 + max * 2 ||
    !/^0x(?:[0-9a-f]{2})+$(?![\s\S])/.test(value)
  ) {
    throw new Error('EXECUTION_RECORD_INVALID');
  }
  return value as Hex;
}
function encode(operation: Operation) {
  return JSON.stringify({
    sender: operation.sender,
    nonce: operation.nonce.toString(),
    callData: operation.callData,
    verificationGasLimit: operation.verificationGasLimit.toString(),
    callGasLimit: operation.callGasLimit.toString(),
    preVerificationGas: operation.preVerificationGas.toString(),
    maxFeePerGas: operation.maxFeePerGas.toString(),
    maxPriorityFeePerGas: operation.maxPriorityFeePerGas.toString(),
    signature: operation.signature,
    ...(operation.paymaster
      ? {
          paymaster: operation.paymaster,
          paymasterVerificationGasLimit: operation.paymasterVerificationGasLimit!.toString(),
          paymasterPostOpGasLimit: operation.paymasterPostOpGasLimit!.toString(),
          paymasterData: operation.paymasterData,
        }
      : {}),
  });
}

/** Byte-integrity and cross-field checks only, NOT fresh quorum/policy/funds
 * verification. The private sender must revalidate those before any broadcast.
 * Hashes detect corruption; a database hash is not an independent attestation.
 */
export function readExecutionOperationRecord(
  json: unknown,
  digest: unknown,
  binding: ExecutionRecordBinding,
) {
  requireHash(digest);
  if (
    typeof json !== 'string' ||
    json.length > maxRecordLength ||
    deploymentDocumentDigest(json) !== digest
  ) {
    throw new Error('EXECUTION_RECORD_INVALID');
  }
  const raw: unknown = JSON.parse(json);
  if (
    !raw ||
    typeof raw !== 'object' ||
    Array.isArray(raw) ||
    Object.keys(raw).length !== recordKeys(raw).length ||
    recordKeys(raw).some((key) => !Object.hasOwn(raw, key))
  )
    throw new Error('EXECUTION_RECORD_INVALID');
  const field = (name: string): unknown => Reflect.get(raw, name);
  const number = (name: string) => BigInt(parseAtomicAmount(field(name)));
  const sender = field('sender');
  if (typeof sender !== 'string' || getAddress(sender) !== sender)
    throw new Error('EXECUTION_RECORD_INVALID');
  const operation: Operation = Object.freeze({
    sender: getAddress(sender),
    nonce: number('nonce'),
    callData: bytes(field('callData'), 16_000),
    verificationGasLimit: number('verificationGasLimit'),
    callGasLimit: number('callGasLimit'),
    preVerificationGas: number('preVerificationGas'),
    maxFeePerGas: number('maxFeePerGas'),
    maxPriorityFeePerGas: number('maxPriorityFeePerGas'),
    signature: bytes(field('signature'), 70_000),
    ...(Object.hasOwn(raw, 'paymaster')
      ? paymasterFields(
          parsePaymasterTerms({
            address: field('paymaster'),
            verificationGasLimit: field('paymasterVerificationGasLimit'),
            postOpGasLimit: field('paymasterPostOpGasLimit'),
            data: field('paymasterData'),
          }),
        )
      : {}),
  });
  if (
    encode(operation) !== json ||
    operation.nonce >= 1n << 64n ||
    gasFields.some(
      (key) =>
        operation[key] >= 1n << 120n || (key !== 'maxPriorityFeePerGas' && operation[key] === 0n),
    ) ||
    operation.maxPriorityFeePerGas > operation.maxFeePerGas
  )
    throw new Error('EXECUTION_RECORD_INVALID');
  const chainId = evmChainId(binding.network_id);
  if (chainId > BigInt(Number.MAX_SAFE_INTEGER)) throw new Error('EXECUTION_RECORD_INVALID');
  const entryPoint = getAddress(binding.entry_point);
  const [plan, signatures] = decodeAbiParameters(
    [
      { type: 'tuple', components: authorizationTypes.ExecutionPlan },
      {
        type: 'tuple[]',
        components: [
          { name: 'signerIndex', type: 'uint8' },
          { name: 'signature', type: 'bytes' },
        ],
      },
    ],
    operation.signature,
  );
  if (
    encodeExecutionSignature(plan, signatures) !== operation.signature ||
    signatures.length < 1 ||
    signatures.length > 32 ||
    signatures.some(
      (s, index) =>
        s.signature === '0x' || (index > 0 && s.signerIndex <= signatures[index - 1].signerIndex),
    )
  ) {
    throw new Error('EXECUTION_RECORD_INVALID');
  }
  const call = decodeFunctionData({ abi: executionAbi, data: operation.callData });
  if (
    call.functionName !== 'execute' ||
    plan.callsHash !== hashCalls(call.args[0]) ||
    plan.securityVersion !== call.args[1] ||
    plan.generation !== 3 ||
    plan.executionMode !== 0 ||
    plan.securityVersion === 0n ||
    plan.paymaster !== (operation.paymaster ?? zeroAddress) ||
    plan.validAfter < 1 ||
    plan.validUntil <= plan.validAfter ||
    plan.validUntil !== binding.valid_until ||
    plan.validUntil > 0x7fffffffffff ||
    plan.accountId !== binding.account_id ||
    plan.nonce !== operation.nonce ||
    plan.entryPoint !== entryPoint ||
    operation.sender !== getAddress(binding.account) ||
    plan.userOpHash !== binding.userop_hash ||
    getUserOperationHash({
      chainId: Number(chainId),
      entryPointAddress: entryPoint,
      entryPointVersion: '0.9',
      userOperation: operation,
    }) !== binding.userop_hash ||
    authorizationDigest('ExecutionPlan', chainId, operation.sender, plan) !== binding.consent_digest
  ) {
    throw new Error('EXECUTION_RECORD_BINDING_MISMATCH');
  }
  return Object.freeze({ operation, plan: Object.freeze(plan) });
}

/** Only already-deployed operations with explicitly encoded sponsorship are supported. Reject
 * factory/delegation fields instead of silently omitting authority.
 */
export function writeExecutionOperationRecord(
  operation: Operation,
  binding: ExecutionRecordBinding,
) {
  if (
    Object.keys(operation).length !== recordKeys(operation).length ||
    recordKeys(operation).some((key) => !Object.hasOwn(operation, key))
  ) {
    throw new Error('EXECUTION_RECORD_UNSUPPORTED_PROFILE');
  }
  const json = encode(operation),
    digest = deploymentDocumentDigest(json);
  readExecutionOperationRecord(json, digest, binding);
  return Object.freeze({ json, digest });
}
