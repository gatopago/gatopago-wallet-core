import { afterEach, describe, expect, it, vi } from 'vitest';
import {
  createPublicClient,
  custom,
  encodeAbiParameters,
  encodeEventTopics,
  keccak256,
  toHex,
  zeroHash,
  type Hex,
} from 'viem';
import { authorizeTransferOperation } from '@gatopago/shared/v3/transfer-authorization';
import { prepareTransferOperation } from '@gatopago/shared/v3/transfer-operation';
import {
  readTransferReview,
  writeTransferReview,
} from '@gatopago/shared/v3/transfer-review-record';
import { transferReceiptAbi, verifyTransferReceipt } from '../src/transfers/transferReceipt';
import { transferFixture } from '@gatopago/test-fixtures/v3-transfer';
import * as accountReader from '@gatopago/shared/v3/account-inspection';
import { observeTransferReceipt } from '../src/transfers/transferReceiptObservation';

afterEach(() => vi.restoreAllMocks());

async function fixture(native = true, success = true, fee = false) {
  const f = transferFixture(native),
    context = {
      ...f.context,
      fee_recipient: fee ? f.request.destination.address : null,
      budget: {
        ...f.context.budget,
        platform_fee: { asset_id: f.request.asset_id, amount_atomic: fee ? '7' : '0' },
      },
    };
  const prepared = prepareTransferOperation(f.request, context, f.now);
  const a = await authorizeTransferOperation(
    f.request,
    context,
    { ...f.approval, reviewed_digest: prepared.digest },
    await f.proofs(prepared.digest),
    () => f.now + 1,
  );
  const saved = writeTransferReview(a.consent_review),
    record = await readTransferReview(saved.json, saved.digest);
  const tx = `0x${'11'.repeat(32)}` as const,
    block = `0x${'22'.repeat(32)}` as const;
  const base = {
    transactionHash: tx,
    blockHash: block,
    blockNumber: '0x7c',
    transactionIndex: '0x0',
    removed: false,
  };
  const log = (
    name: (typeof transferReceiptAbi)[number]['name'],
    address: string,
    data: Hex,
    extra: Hex[] = [],
  ) => {
    const first = encodeEventTopics({ abi: transferReceiptAbi, eventName: name })[0];
    if (!first) throw new Error('Missing event topic');
    return { ...base, address, data, topics: [first, ...extra], logIndex: '0x0' };
  };
  const accountTopic = encodeAbiParameters([{ type: 'address' }], [a.account]);
  const eventData = (nonce = a.plan.nonce, ok = success, cost = 100n) =>
    encodeAbiParameters(
      [{ type: 'uint256' }, { type: 'bool' }, { type: 'uint256' }, { type: 'uint256' }],
      [nonce, ok, cost, 50n],
    );
  const logs = [log('BeforeExecution', a.plan.entryPoint, '0x')];
  if (success && !native)
    logs.push(
      log(
        'Transfer',
        a.request.asset_id.split('/erc20:')[1],
        encodeAbiParameters([{ type: 'uint256' }], [10n]),
        [accountTopic, encodeAbiParameters([{ type: 'address' }], [a.request.destination.address])],
      ),
    );
  if (success && !native && fee)
    logs.push(
      log(
        'Transfer',
        a.request.asset_id.split('/erc20:')[1],
        encodeAbiParameters([{ type: 'uint256' }], [7n]),
        [accountTopic, encodeAbiParameters([{ type: 'address' }], [a.request.destination.address])],
      ),
    );
  if (success)
    logs.push(
      log(
        'CallsExecuted',
        a.account,
        encodeAbiParameters([{ type: 'uint64' }, { type: 'uint8' }], [a.plan.securityVersion, 0]),
        [a.plan.callsHash],
      ),
    );
  logs.push(
    log('UserOperationEvent', a.plan.entryPoint, eventData(), [
      a.userOpHash,
      accountTopic,
      zeroHash,
    ]),
  );
  const reindex = () =>
    logs.forEach((l, i) => {
      l.logIndex = toHex(i);
    });
  reindex();
  const receipt = { ...base, status: '0x1', logs };
  return {
    f,
    a,
    record,
    receipt,
    tx,
    log,
    reindex,
    eventData,
    run: () => verifyTransferReceipt(record, tx, receipt),
  };
}

describe('Transfer receipt evidence bound to one signed operation', () => {
  it.each([
    'valid',
    'missing',
    'code',
    'late',
    'changed-block',
    'changed-time',
    'unknown-account',
    'wrong-pin',
  ])('observes receipt and canonical pinned state: %s', async (fault) => {
    const f = await fixture(),
      code: Hex = '0x6001';
    const profile = {
      document: f.f.approval.security_evidence.document,
      expectedDigest: f.a.deployment_digest,
      initialSecurityCommitment: f.f.f.initial.message.initialSecurityCommitment,
      userSaltCommitment: f.f.f.input.initialization.userSaltCommitment,
      entryPointCodeHash: keccak256(code),
    };
    if (fault === 'wrong-pin') profile.expectedDigest = `0x${'ff'.repeat(32)}`;
    const inspect = vi
      .spyOn(accountReader, 'inspectAccountDeployment')
      .mockImplementation(async (_client, input) => {
        expect(input.checkpoint).toEqual({ block_hash: f.receipt.blockHash, block_number: '124' });
        const base = f.f.approval.security_evidence.observation;
        return fault === 'unknown-account' ? { ...base, status: 'not_deployed' as const } : base;
      });
    let headers = 0;
    const request = vi.fn(
      async ({ method, params }: { method: string; params?: readonly unknown[] }) => {
        if (method === 'eth_getTransactionReceipt') return fault === 'missing' ? null : f.receipt;
        if (method === 'eth_getBlockByNumber') {
          headers++;
          return {
            number: '0x7c',
            hash:
              fault === 'changed-block' && headers === 2
                ? `0x${'ff'.repeat(32)}`
                : f.receipt.blockHash,
            timestamp: toHex(
              BigInt(
                fault === 'late'
                  ? f.a.plan.validUntil + 1
                  : f.f.now + (fault === 'changed-time' && headers === 2 ? 3 : 2),
              ),
            ),
          };
        }
        if (method === 'eth_getCode') {
          expect(params).toEqual([
            f.a.plan.entryPoint,
            { blockHash: f.receipt.blockHash, requireCanonical: true },
          ]);
          return fault === 'code' ? '0x6002' : code;
        }
        throw new Error('Unexpected RPC');
      },
    );
    const client = createPublicClient({ transport: custom({ request }, { retryCount: 0 }) });
    const result = observeTransferReceipt(client, f.record, f.tx, profile);
    if (fault === 'valid')
      expect(await result).toMatchObject({
        outcome: 'execution_succeeded',
        block_timestamp: String(f.f.now + 2),
        finality: 'not_assessed',
      });
    else if (fault === 'missing') {
      expect(await result).toBeNull();
      expect(inspect).not.toHaveBeenCalled();
    } else await expect(result).rejects.toThrow();
    if (fault === 'wrong-pin') expect(request).not.toHaveBeenCalled();
  });
  it.each([true, false])('checks native=%s delivery without asserting finality', async (native) => {
    const f = await fixture(native);
    expect(f.run()).toMatchObject({
      outcome: 'execution_succeeded',
      actual_gas_cost: '100',
      userop_hash: f.a.userOpHash,
      consent_digest: f.a.digest,
      finality: 'not_assessed',
      settlement: 'not_assessed',
    });
  });
  it('distinguishes a reverted operation from a successful bundle transaction', async () => {
    const f = await fixture(false, false);
    expect(f.run()).toMatchObject({
      outcome: 'execution_reverted',
      actual_gas_cost: '100',
      log_indexes: { calls: null, transfers: [] },
    });
  });
  it.each([
    'missing-transfer',
    'wrong-token',
    'wrong-amount',
    'wrong-recipient',
    'missing-calls',
    'calls-version',
    'nonce',
    'gas',
    'success',
    'removed',
    'block',
    'duplicate',
    'trailing-data',
    'boundary',
  ])('rejects %s rather than marking the payment complete', async (fault) => {
    const f = await fixture(false),
      logs = f.receipt.logs,
      op = logs[3];
    if (fault === 'missing-transfer') logs.splice(1, 1);
    if (fault === 'wrong-token') logs[1].address = `0x${'33'.repeat(20)}`;
    if (fault === 'wrong-amount') logs[1].data = encodeAbiParameters([{ type: 'uint256' }], [9n]);
    if (fault === 'wrong-recipient') logs[1].topics[2] = zeroHash;
    if (fault === 'missing-calls') logs.splice(2, 1);
    if (fault === 'calls-version')
      logs[2].data = encodeAbiParameters([{ type: 'uint64' }, { type: 'uint8' }], [99n, 0]);
    if (fault === 'nonce') op.data = f.eventData(1n);
    if (fault === 'gas') op.data = f.eventData(0n, true, f.a.maximumEntryPointCharge + 1n);
    if (fault === 'success') op.data = f.eventData(0n, false);
    if (fault === 'removed') op.removed = true;
    if (fault === 'block') op.blockNumber = '0x7d';
    if (fault === 'duplicate') logs.push({ ...op });
    if (fault === 'trailing-data') op.data = `${op.data}00`;
    if (fault === 'boundary') logs.shift();
    f.reindex();
    expect(f.run).toThrow();
  });
  it('does not count identical CallsExecuted from an earlier operation in the bundle', async () => {
    const f = await fixture(),
      logs = f.receipt.logs;
    const previous = {
      ...logs[2],
      topics: [logs[2].topics[0], `0x${'44'.repeat(32)}` as Hex, ...logs[2].topics.slice(2)],
    };
    logs.splice(1, 0, { ...logs[1] }, previous);
    f.reindex();
    expect(f.run()).toMatchObject({
      outcome: 'execution_succeeded',
      log_indexes: { calls: '3', operation: '4' },
    });
  });
  it.each(['valid', 'missing', 'changed'])(
    'checks the separate fee event even for the same recipient: %s',
    async (fault) => {
      const f = await fixture(false, true, true);
      if (fault === 'missing') f.receipt.logs.splice(2, 1);
      if (fault === 'changed')
        f.receipt.logs[2].data = encodeAbiParameters([{ type: 'uint256' }], [8n]);
      f.reindex();
      if (fault === 'valid') expect(f.run().log_indexes.transfers).toEqual(['1', '2']);
      else expect(f.run).toThrow('TRANSFER_RECEIPT_ASSET_UNPROVEN');
    },
  );
  it('uses the latest BeforeExecution when a transaction contains two bundles', async () => {
    const f = await fixture(),
      logs = f.receipt.logs;
    logs.splice(0, 0, { ...logs[0] });
    f.reindex();
    expect(f.run().outcome).toBe('execution_succeeded');
  });
});
