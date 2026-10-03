import { vi } from 'vitest';
import { encodeFunctionData, keccak256, toHex, zeroAddress, type Hex, type PublicClient } from 'viem';
import { privateKeyToAccount } from 'viem/accounts';
import { entryPoint09Abi, toPackedUserOperation } from 'viem/account-abstraction';
import { deploymentDocumentDigest } from '@gatopago/shared/v3/deployment';
import { finalityPolicyFixture } from '@gatopago/test-fixtures/v3-finality';
import * as finality from '@gatopago/shared/v3/finality';
import * as inspection from '@gatopago/shared/v3/account-inspection';
import * as chain from '../src/chainInspection';
import * as runtime from '../src/runtime/finality';
import * as nonceReader from '../src/transfers/transferNonce';
import * as positionReader from '../src/portfolio/aavePositionObservation';
import { observeMoneySource } from '../src/money/moneyObservation';
import { observeMoneyOuterRevert } from '../src/money/moneyOuterRevert';
import type { MoneyDeliveryProfile } from '../src/money/moneyPreflight';
import { createMoneyReceiptFixture } from './moneyReceipt.fixture';

export async function moneyOuterFixture(lateReceipt = false) {
  const now = Math.floor(Date.now() / 1000), clock = vi.spyOn(Date, 'now').mockReturnValue((now - 90) * 1000);
  const f = await createMoneyReceiptFixture('aave_supply'); clock.mockRestore();
  const c = f.record.candidate, operator = privateKeyToAccount(`0x${'12'.repeat(32)}`);
  const data = (beneficiary: Hex) => encodeFunctionData({ abi: entryPoint09Abi, functionName: 'handleOps', args: [
    [toPackedUserOperation(f.record.operation)], beneficiary] });
  const raw = await operator.signTransaction({ type: 'eip1559', chainId: 421614, to: c.plan.entryPoint,
    value: 0n, data: data(operator.address), nonce: 7, gas: 100_000n, maxFeePerGas: 20n, maxPriorityFeePerGas: 0n });
  const stored = { kind: 'self', user_op_hash: c.userOpHash, payload_hash: keccak256(data(zeroAddress)),
    endpoint: 'https://original.example/rpc', network_id: c.request.network_id, operator: operator.address.toLowerCase(),
    nonce: 7, raw_transaction: raw, transaction_hash: keccak256(raw), valid_until: c.plan.validUntil };
  const db = { withSession: () => ({ prepare: (sql: string) => {
    if (!sql.startsWith('SELECT * FROM user_operation_submissions')) throw new Error('Unexpected DB mutation');
    return { bind: () => ({ first: async () => stored }) };
  } }) } as unknown as D1Database;
  const policy = { ...finalityPolicyFixture(f.market, now), mechanism: 'arbitrum_l1_data_finalized' as const };
  const document = JSON.stringify(policy);
  const profile: MoneyDeliveryProfile = { document: f.f.deploymentDocument, digest: f.f.deployment, market: f.f.context.market,
    entryPointCodeHash: f.f.keys.profile.entry_point_code_hash, finalityPolicy: { document, digest: deploymentDocumentDigest(document) },
    providers: [{ operatorId: 'one', url: 'https://one.example/rpc' }, { operatorId: 'two', url: 'https://two.example/rpc' }],
    transport: { kind: 'bundler', url: 'https://changed.example/rpc' }, assetIds: [c.request.asset_id], assetDisplay: {},
    features: { aave_supply: false, aave_withdraw: false, aave_withdraw_and_pay: false },
    gasByKind: { aave_supply: null, aave_withdraw: null, aave_withdraw_and_pay: null } };
  const hash = (number: number) => `0x${number.toString(16).padStart(64, '0')}` as Hex;
  const block = (number: number) => ({ block_number: String(number), block_hash: hash(number),
    block_timestamp: String(number < 130 ? c.plan.validUntil - 1 : c.plan.validUntil + 1) });
  const outerBlock = block(lateReceipt ? 140 : 124), latest = block(200);
  const receipt = { status: '0x0', type: '0x2', from: operator.address, to: c.plan.entryPoint, contractAddress: null,
    transactionHash: stored.transaction_hash, blockHash: outerBlock.block_hash, blockNumber: toHex(BigInt(outerBlock.block_number)),
    transactionIndex: '0x0', gasUsed: '0x3e8', effectiveGasPrice: '0xa', gasUsedForL1: '0xc8', logs: [] };
  const requests = [vi.fn(async (input: { method: string; params: unknown[] }) => {
    if (input.method === 'eth_getTransactionReceipt') return structuredClone(receipt);
    const point = block(Number(BigInt(String(input.params[0]))));
    return { number: toHex(BigInt(point.block_number)), hash: point.block_hash, timestamp: toHex(BigInt(point.block_timestamp)) };
  }), vi.fn()]; requests[1].mockImplementation(requests[0].getMockImplementation()!);
  const clients = requests.map(request => ({ request }) as unknown as PublicClient);
  let index = 0; vi.spyOn(chain, 'createInspectionClient').mockImplementation(() => clients[index++] as ReturnType<typeof chain.createInspectionClient>);
  const assessment = (target: typeof latest) => ({ schema_version: 1 as const, status: 'finalized' as const,
    network_id: c.request.network_id, genesis_hash: f.market.genesis_hash, policy_sha256: profile.finalityPolicy.digest,
    mechanism: policy.mechanism, target: { block_number: target.block_number, block_hash: target.block_hash, block_timestamp: target.block_timestamp },
    checkpoint: { ...latest }, assessed_at: now, expires_at: now + 10 });
  const final = vi.spyOn(finality, 'assessCheckpointFinality').mockImplementation(async (_clients, target) => assessment(target));
  const head = vi.spyOn(runtime, 'networkFinality').mockResolvedValue(assessment(latest));
  const account = vi.spyOn(inspection, 'inspectAccountDeployment').mockImplementation(async (_client, input) => ({
    status: 'recognized', account: c.account, account_id: c.plan.accountId, network_id: c.request.network_id,
    manifest_id: f.f.keys.profile.deployment.manifest_id, manifest_sha256: profile.digest, checkpoint: input.checkpoint,
    implementation: f.f.keys.profile.deployment.components.implementation.address, security_version: '1',
    storage_layout_hash: f.f.keys.profile.deployment.storage_layout_hash, spend_readiness: 'not_assessed' }));
  const nonce = vi.spyOn(nonceReader, 'observeTransferNonce').mockImplementation(async input => ({ network_id: c.request.network_id,
    account: c.account, entry_point: c.plan.entryPoint, checkpoint: input.checkpoint, nonce: c.plan.nonce.toString(), observed_at: now }));
  const position = vi.spyOn(positionReader, 'observeAavePosition').mockImplementation(async input => ({
    network_id: c.request.network_id, market_id: f.market.market_id, market_digest: profile.market.digest, asset_id: c.request.asset_id,
    a_token: f.market.a_token, account: c.account, checkpoint: input.checkpoint, observed_at: now, expires_at: now + 10,
    usdc_balance_atomic: '100000000', native_balance_atomic: '1000000', position_balance_atomic: '0', scaled_position_atomic: '0',
    liquidity_index_ray: '1000000000000000000000000000', debt_base_atomic: '0', liquidity_atomic: '100000000', supply_capacity_atomic: null,
    allowance_atomic: '0', active: true, frozen: false, paused: false, finality: 'not_assessed', spend_readiness: 'not_assessed' }));
  const source = { record: f.record, context: 'unchanged', initialSecurityCommitment: f.f.initial.message.initialSecurityCommitment,
    userSaltCommitment: f.f.initial.message.userSaltCommitment }, controller = new AbortController();
  return { ...f, c, now, stored, db, profile, receipt, clients, requests, final, head, account, nonce, position,
    source, latest, block, assessment, controller,
    run: () => observeMoneyOuterRevert(db, source, profile, clients, [receipt, structuredClone(receipt)], controller.signal),
    observed: () => observeMoneySource(db, async () => source, [profile], controller.signal) };
}
