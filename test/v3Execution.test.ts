import { readFileSync } from 'node:fs';
import { describe, expect, it } from 'vitest';
import {
  decodeAbiParameters,
  decodeFunctionData,
  encodeFunctionData,
  getAddress,
  zeroAddress,
  zeroHash,
  type Abi,
} from 'viem';
import {
  authorizationTypes,
  hashCalls,
  type AccountCall,
  type ExecutionPlan,
} from '@gatopago/shared/v3/authorizations';
import {
  encodeAccountExecution,
  encodeDirectExecution,
  encodeExecutionSignature,
  executionAbi,
} from '@gatopago/shared/v3/execution';

const account = getAddress(`0x${'ab'.repeat(20)}`);
const calls: AccountCall[] = [
  { target: getAddress(`0x${'cd'.repeat(20)}`), value: 42n, data: '0x1234' },
];
const signatures = [{ signerIndex: 0, signature: '0xabcd' as const }];
const plan: ExecutionPlan = {
  accountId: zeroHash,
  generation: 3,
  securityVersion: 1n,
  executionMode: 1,
  entryPoint: zeroAddress,
  userOpHash: zeroHash,
  callsHash: hashCalls(calls),
  assetLimitsHash: zeroHash,
  feePolicyHash: zeroHash,
  paymaster: zeroAddress,
  previewHash: zeroHash,
  nonce: 0n,
  validAfter: 1,
  validUntil: 100,
};

describe('V3 executable CALL encoding', () => {
  it('matches the compiled Solidity executor ABI, including the signature envelope shape', () => {
    const artifact = JSON.parse(
      readFileSync(
        new URL(import.meta.resolve('@gatopago/contract-artifacts/AccountV3Execution.json')),
        'utf8',
      ),
    ) as { abi: Abi };
    const data = encodeAccountExecution(account, calls, 1n);
    expect(data).toBe(
      encodeFunctionData({ abi: artifact.abi, functionName: 'execute', args: [calls, 1n] }),
    );
    expect(encodeDirectExecution(account, calls, plan, signatures)).toBe(
      encodeFunctionData({
        abi: artifact.abi,
        functionName: 'executeSigned',
        args: [calls, plan, signatures],
      }),
    );
    expect(decodeFunctionData({ abi: executionAbi, data }).args).toEqual([calls, 1n]);
  });
  it('rejects self/zero targets, missing batches, excess calls and invalid versions before a gesture', () => {
    for (const batch of [
      [],
      Array.from({ length: 33 }, () => calls[0]),
      [{ ...calls[0], target: account }],
      [{ ...calls[0], target: zeroAddress }],
    ]) {
      expect(() => encodeAccountExecution(account, batch, 1n)).toThrow();
    }
    expect(() => encodeAccountExecution(account, calls, 0n)).toThrow();
    expect(() => encodeAccountExecution(account, calls, 1n << 64n)).toThrow();
    expect(() =>
      encodeAccountExecution(
        account,
        Array.from({ length: 32 }, () => calls[0]),
        1n,
      ),
    ).not.toThrow();
  });
  it('cannot reinterpret a UserOp plan as a direct relay or silently replace its calls', () => {
    for (const changed of [
      { executionMode: 0 },
      { entryPoint: account },
      { paymaster: account },
      { userOpHash: `0x${'ef'.repeat(32)}` as const },
      { callsHash: zeroHash },
      { validAfter: 0 },
      { validUntil: 1 },
      { validUntil: 0x800000000000 },
    ])
      expect(() =>
        encodeDirectExecution(account, calls, { ...plan, ...changed }, signatures),
      ).toThrow();
  });
  it('keeps the plan and votes in signature, not in the callData hashed by EntryPoint', () => {
    const opPlan = { ...plan, executionMode: 0, entryPoint: account };
    const encoded = encodeExecutionSignature(opPlan, signatures);
    const decoded = decodeAbiParameters(
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
      encoded,
    );
    expect(decoded).toEqual([opPlan, signatures]);
  });
});
