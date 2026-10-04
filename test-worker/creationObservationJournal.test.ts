import { env } from 'cloudflare:workers';
import { applyD1Migrations } from 'cloudflare:test';
import { afterEach, beforeAll, beforeEach, describe, expect, it, vi } from 'vitest';
import { encodeAbiParameters, toHex } from 'viem';
import { deploymentDocumentDigest } from '@gatopago/shared/v3/deployment';
import { CreationDeliveryRepository } from '../src/creation/creationDelivery';
import { CreationObservationJournal } from '../src/creation/creationObservationJournal';
import { processCreationObservation } from '../src/creation/processCreationObservation';
import { creationInspectionScenario } from '@gatopago/test-fixtures/v3-creation-inspection';
import { creationReceiptScenario } from '@gatopago/test-fixtures/v3-creation-receipt';
import { fixtureHash } from '@gatopago/test-fixtures/v3-inspection';
import { finalityPin, finalityPolicyFixture } from '@gatopago/test-fixtures/v3-finality';
import {
  cleanCreationDelivery,
  deliveryNow,
  deliveryOutbox,
  seedCreationDelivery,
} from './creationDelivery.fixture';

const at = (now: number) => vi.spyOn(Date, 'now').mockReturnValue(now * 1000);
beforeAll(async () => {
  await applyD1Migrations(env.WALLET_DB, env.V3_TEST_MIGRATIONS);
});
beforeEach(async () => {
  at(deliveryNow());
  await cleanCreationDelivery();
});
afterEach(async () => {
  vi.restoreAllMocks();
  await cleanCreationDelivery();
});

async function scenario(sent = true) {
  const inspection = creationInspectionScenario(),
    document = inspection.input.document;
  const f = await seedCreationDelivery(undefined, {
    document,
    digest: deploymentDocumentDigest(document),
  });
  const evidence = creationReceiptScenario(false, f.signed),
    delivery = new CreationDeliveryRepository(env.WALLET_DB, f.configuration);
  if (sent) {
    const claim = await delivery.claim(f.id);
    if (!claim) throw new Error('Expected delivery claim');
    await delivery.beginSend(claim);
    await delivery.accepted(claim, f.signed.userOpHash);
  }
  const configuration = {
    environment: f.configuration.environment,
    scope: f.configuration.scope,
    networks: [
      {
        document,
        digest: f.configuration.profiles[0].digest,
        transport: { kind: 'bundler' as const, url: 'https://bundler.invalid/' },
        finalityPolicy: finalityPin(
          finalityPolicyFixture(inspection.profile.deployment, deliveryNow()),
        ),
        providers: [
          { operatorId: 'provider_a', url: 'https://observer-a.invalid/' },
          { operatorId: 'provider_b', url: 'https://observer-b.invalid/' },
        ],
      },
    ],
  };
  const hint = vi.fn((): unknown => ({
    userOpHash: f.signed.userOpHash,
    receipt: evidence.receipt,
  }));
  const reply = vi.fn(
    async (_url: string, request: { method: string; params: readonly unknown[] }) =>
      evidence.request(request),
  );
  const calls: string[] = [];
  const fetch = vi.spyOn(globalThis, 'fetch').mockImplementation(async (url, init) => {
    init?.signal?.throwIfAborted();
    if (typeof init?.body !== 'string') throw new Error('Expected RPC body');
    const request = JSON.parse(init.body);
    calls.push(request.method);
    if (String(url) === 'https://bundler.invalid/')
      return Response.json({ jsonrpc: '2.0', id: request.id, result: hint() });
    if (!['https://observer-a.invalid/', 'https://observer-b.invalid/'].includes(String(url)))
      throw new Error('Unexpected external destination');
    return Response.json({
      jsonrpc: '2.0',
      id: request.id,
      result: await reply(String(url), request),
    });
  });
  const journal = () => new CreationObservationJournal(env.WALLET_DB, f.configuration);
  const run = (signal = new AbortController().signal) =>
    processCreationObservation(env.WALLET_DB, f.id, configuration, signal);
  const head = () =>
    env.WALLET_DB.prepare(
      'SELECT * FROM account_creation_observation_jobs WHERE initialization_id = ?',
    )
      .bind(f.id)
      .first();
  const records = async () =>
    (
      await env.WALLET_DB.prepare(
        'SELECT * FROM account_creation_observations WHERE initialization_id = ? ORDER BY lease_epoch',
      )
        .bind(f.id)
        .all()
    ).results;
  return { ...f, evidence, configuration, journal, run, hint, reply, fetch, calls, head, records };
}
const unknownResult = () => ({
  status: 'not_observed' as const,
  transaction_hash: null,
  provider_ids: ['provider_a', 'provider_b'],
  finality: 'not_assessed' as const,
  account_readiness: 'not_assessed' as const,
});

describe('durable creation observation journal and service in real D1', () => {
  it('persists independent receipt evidence across repository instances without activating or resending', async () => {
    const f = await scenario(),
      outbox = await deliveryOutbox(f.id);
    expect(await f.run()).toBe('observed');
    expect(await f.journal().latest(f.id)).toMatchObject({
      epoch: 1,
      result: {
        status: 'observed',
        finality: 'finalized',
        finality_evidence: { mechanism: 'op_stack_l1_data_finalized' },
        observation: {
          user_op_hash: f.signed.userOpHash,
          actual_gas_cost: '12345',
          outcome: 'creation_succeeded',
        },
      },
    });
    expect(await f.records()).toHaveLength(1);
    expect(await deliveryOutbox(f.id)).toEqual(outbox);
    expect(
      await env.WALLET_DB.prepare('SELECT count(*) AS n FROM wallet_accounts').first('n'),
    ).toBe(0);
    expect(f.calls.some((method) => method.startsWith('eth_send'))).toBe(false);
    expect(await f.journal().due()).toEqual([]);
  });
  it('eight competing observers perform only one RPC observation and one append', async () => {
    const f = await scenario();
    const results = await Promise.all(Array.from({ length: 8 }, () => f.run()));
    expect(results.filter((r) => r === 'observed')).toHaveLength(1);
    expect(results.filter((r) => r === 'idle')).toHaveLength(7);
    expect(f.hint).toHaveBeenCalledTimes(1);
    expect(await f.records()).toHaveLength(1);
  });
  it('never observes an unsent grant or creates a journal for it', async () => {
    const f = await scenario(false);
    expect(await f.run()).toBe('idle');
    expect(await f.head()).toBeNull();
    expect(await f.journal().due()).toEqual([]);
    expect(f.fetch).not.toHaveBeenCalled();
  });
  it('finds lost wake-ups, permits observation after grant expiry and session revocation', async () => {
    const f = await scenario();
    at(f.initial.input.validUntil + 600);
    await env.WALLET_DB.prepare(
      'UPDATE users SET disabled_at = ?, auth_not_before = ? WHERE id = ?',
    )
      .bind(deliveryNow(), deliveryNow(), f.session.user_id)
      .run();
    expect(await f.journal().due()).toEqual([f.id]);
    expect(await f.run()).toBe('observed');
    expect((await deliveryOutbox(f.id))?.state).toBe('accepted');
  });
  it('rejects unsupported namespaces before internal observation or sweep', async () => {
    const f = await scenario();
    expect(
      () =>
        new CreationObservationJournal(env.WALLET_DB, {
          ...f.configuration,
          profiles: f.configuration.networks,
          environment: 'unsupported' as never,
        }),
    ).toThrow();
    expect(f.fetch).not.toHaveBeenCalled();
  });
  it('expired workers cannot append or overwrite a newer lease, even after its completion', async () => {
    const f = await scenario(),
      first = await f.journal().claim(f.id);
    if (!first) throw new Error('Expected lease');
    at(first.until);
    const second = await f.journal().claim(f.id);
    if (!second) throw new Error('Expected replacement lease');
    expect(await f.journal().append(second, unknownResult())).toBe(true);
    expect(await f.journal().append(first, unknownResult())).toBe(false);
    expect(await f.journal().append(second, unknownResult())).toBe(false);
    expect(await f.records()).toHaveLength(1);
    expect(await f.journal().latest(f.id)).toMatchObject({
      epoch: 2,
      result: { status: 'not_observed' },
    });
  });
  it('rolls back the append if updating the head fails; the same live lease can retry', async () => {
    const f = await scenario(),
      claim = await f.journal().claim(f.id);
    if (!claim) throw new Error('Expected lease');
    await env.WALLET_DB.prepare(
      `CREATE TRIGGER observation_fail_head BEFORE UPDATE OF latest_epoch ON account_creation_observation_jobs
			BEGIN SELECT RAISE(ABORT, 'Synthetic interrupted head'); END;`,
    ).run();
    await expect(f.journal().append(claim, unknownResult())).rejects.toThrow();
    expect(await f.records()).toHaveLength(0);
    expect(await f.journal().latest(f.id)).toBeNull();
    await env.WALLET_DB.exec('DROP TRIGGER observation_fail_head');
    expect(await f.journal().append(claim, unknownResult())).toBe(true);
  });
  it('concurrent duplicate completions append and advance the head exactly once', async () => {
    const f = await scenario(),
      claim = await f.journal().claim(f.id);
    if (!claim) throw new Error('Expected lease');
    const completions = await Promise.all(
      Array.from({ length: 8 }, () => f.journal().append(claim, unknownResult())),
    );
    expect(completions.filter(Boolean)).toHaveLength(1);
    expect(await f.records()).toHaveLength(1);
  });
  it('a slow RPC response cannot commit after lease expiry; the next observer can recover', async () => {
    const f = await scenario(),
      valid = f.reply.getMockImplementation()!;
    f.reply.mockImplementationOnce(async (url, request) => {
      at(deliveryNow() + 60);
      return valid(url, request);
    });
    expect(await f.run()).toBe('lease_lost');
    expect(await f.records()).toHaveLength(0);
    expect(await f.journal().due()).toEqual([f.id]);
    expect(await f.run()).toBe('observed');
    expect(await f.journal().latest(f.id)).toMatchObject({ epoch: 2 });
  });
  it('records a reverted UserOperation inside a successful outer transaction without retrying it', async () => {
    const f = await scenario(),
      receipt = f.evidence.receipt;
    const logs = receipt.logs.filter((_log, index) => index !== 3).map((log) => ({ ...log }));
    logs[3].data = encodeAbiParameters(
      [{ type: 'uint256' }, { type: 'bool' }, { type: 'uint256' }, { type: 'uint256' }],
      [0n, false, 12345n, 123n],
    );
    f.evidence.state.receipt = { ...receipt, logs };
    expect(await f.run()).toBe('observed');
    expect(await f.journal().latest(f.id)).toMatchObject({
      result: { observation: { outcome: 'execution_reverted' } },
    });
    expect((await deliveryOutbox(f.id))?.state).toBe('accepted');
    expect(f.calls.some((method) => method.startsWith('eth_send'))).toBe(false);
  });
  it('persists RPC disagreement without publishing either provider result as an observation', async () => {
    const f = await scenario(),
      valid = f.reply.getMockImplementation()!;
    f.reply.mockImplementation(async (url, request) =>
      url === 'https://observer-b.invalid/' && request.method === 'eth_getTransactionReceipt'
        ? null
        : valid(url, request),
    );
    expect(await f.run()).toBe('disagreement');
    const record = await f.journal().latest(f.id);
    expect(record).toMatchObject({ result: { status: 'disagreement', finality: 'not_assessed' } });
    expect(record?.result).not.toHaveProperty('observation');
    expect(await f.journal().knownTransaction(f.id)).toBeUndefined();
  });
  it('replaces current success with uncertainty but retains history and a verified transaction hint', async () => {
    const f = await scenario();
    await f.run();
    at(deliveryNow() + 31);
    f.reply.mockRejectedValue(new Error('private-rpc-url/token'));
    expect(await f.run()).toBe('unavailable');
    expect(await f.journal().latest(f.id)).toMatchObject({ result: { status: 'unavailable' } });
    expect(await f.records()).toHaveLength(2);
    expect(await f.journal().knownTransaction(f.id)).toBe(f.evidence.transactionHash);
    expect(JSON.stringify(await f.records())).not.toMatch(/private-rpc|https:/);
  });
  it('can recover observation without the bundler, including after an intervening unavailable result', async () => {
    const f = await scenario();
    await f.run();
    const valid = f.reply.getMockImplementation()!;
    at(deliveryNow() + 31);
    f.reply.mockRejectedValue(new Error('Offline'));
    expect(await f.run()).toBe('unavailable');
    at(deliveryNow() + 301);
    f.reply.mockImplementation(valid);
    f.hint.mockImplementation(() => {
      throw new Error('Bundler disappeared');
    });
    expect(await f.run()).toBe('observed');
    expect(f.hint).toHaveBeenCalledTimes(1);
  });
  it('does not retain an unverified bundler hint as the next candidate', async () => {
    const f = await scenario();
    f.evidence.state.missing = true;
    expect(await f.run()).toBe('not_observed');
    expect(await f.journal().knownTransaction(f.id)).toBeUndefined();
    at(deliveryNow() + 11);
    f.evidence.state.missing = false;
    expect(await f.run()).toBe('observed');
    expect(f.hint).toHaveBeenCalledTimes(2);
  });
  it('records missing previously observed receipts without deleting history or permitting resend', async () => {
    const f = await scenario();
    await f.run();
    at(deliveryNow() + 31);
    f.evidence.state.missing = true;
    expect(await f.run()).toBe('not_observed');
    expect(await f.journal().latest(f.id)).toMatchObject({ result: { status: 'not_observed' } });
    expect(await f.records()).toHaveLength(2);
    expect((await deliveryOutbox(f.id))?.state).toBe('accepted');
  });
  it('never rewrites a finalized receipt identity, even if both RPCs subsequently agree on another block', async () => {
    const f = await scenario();
    await f.run();
    at(deliveryNow() + 31);
    const hash = fixtureHash('d'),
      receipt = f.evidence.receipt;
    f.evidence.state.receipt = {
      ...receipt,
      blockHash: hash,
      logs: receipt.logs.map((log) => ({ ...log, blockHash: hash })),
    };
    f.evidence.inspection.state.blockHash = hash;
    expect(await f.run()).toBe('observed');
    const records = await f.records();
    expect(records).toHaveLength(2);
    expect(JSON.parse(String(records[0].result_json)).observation.block_hash).not.toBe(hash);
    expect(await f.journal().latest(f.id)).toMatchObject({
      result: { finality: 'reorg_detected', observation: { block_hash: hash } },
    });
    expect((await f.journal().lastFinalizedReceipt(f.id))?.block_hash).not.toBe(hash);
  });
  it('checks the grant again at commit and rejects a changed operation signature', async () => {
    const f = await scenario(),
      claim = await f.journal().claim(f.id);
    if (!claim) throw new Error('Expected lease');
    await env.WALLET_DB.prepare(
      "UPDATE account_creation_operations SET operation_signature = '0xab' WHERE initialization_id = ?",
    )
      .bind(f.id)
      .run();
    expect(await f.journal().append(claim, unknownResult())).toBe(false);
    expect(await f.records()).toHaveLength(0);
  });
  it.each(['amount', 'time', 'log_order', 'identity', 'extra_field', 'readiness'] as const)(
    'rejects malformed %s journal input before persisting it',
    async (fault) => {
      const f = await scenario();
      await f.run();
      const valid = await f.journal().latest(f.id);
      if (!valid || valid.result.status !== 'observed')
        throw new Error('Expected observed evidence');

      const bad = JSON.parse(JSON.stringify(valid.result));
      if (fault === 'amount') bad.observation.actual_gas_cost = '-1';
      if (fault === 'time') bad.observation.block_timestamp = '0';
      if (fault === 'log_order') bad.observation.log_indexes.operation = '0';
      if (fault === 'identity') bad.observation.user_op_hash = fixtureHash('9');
      if (fault === 'extra_field') bad.observation.provider_url = 'https://private.invalid/secret';
      if (fault === 'readiness') bad.account_readiness = 'active';
      at(deliveryNow() + 31);
      const claim = await f.journal().claim(f.id);
      if (!claim) throw new Error('Expected lease');
      await expect(f.journal().append(claim, bad)).rejects.toThrow();
      expect(await f.records()).toHaveLength(1);
    },
  );
  it('does not accept a corrupted grant before RPC I/O', async () => {
    const f = await scenario();
    await env.WALLET_DB.prepare(
      'UPDATE account_creation_operations SET user_op_hash = ? WHERE initialization_id = ?',
    )
      .bind(fixtureHash('9'), f.id)
      .run();
    await expect(f.run()).rejects.toThrow();
    expect(f.fetch).not.toHaveBeenCalled();
  });
  it('enforces immutable records and fails closed if the head points to missing evidence', async () => {
    const f = await scenario();
    await f.run();
    await expect(
      env.WALLET_DB.prepare(
        'UPDATE account_creation_observations SET observed_at = observed_at WHERE initialization_id = ?',
      )
        .bind(f.id)
        .run(),
    ).rejects.toThrow();
    await env.WALLET_DB.prepare(
      'DELETE FROM account_creation_observations WHERE initialization_id = ?',
    )
      .bind(f.id)
      .run();
    await expect(f.journal().latest(f.id)).rejects.toThrow();
  });
  it('cancellation before claiming has no durable or external effect', async () => {
    const f = await scenario(),
      controller = new AbortController();
    controller.abort();
    await expect(f.run(controller.signal)).rejects.toThrow();
    expect(await f.head()).toBeNull();
    expect(f.fetch).not.toHaveBeenCalled();
  });
  it('requires the pinned finality policy before acquiring a durable lease or querying RPC', async () => {
    const f = await scenario();
    f.configuration.networks[0].finalityPolicy.document += ' ';
    await expect(f.run()).rejects.toThrow('pin mismatch');
    expect(await f.head()).toBeNull();
    expect(f.fetch).not.toHaveBeenCalled();
  });
  it('records pending finality separately from successful creation and later advances only the evidence', async () => {
    const f = await scenario(),
      valid = f.reply.getMockImplementation()!;
    f.reply.mockImplementation(async (url, request) =>
      request.method === 'eth_getBlockByNumber' &&
      ['finalized', '0x63'].includes(String(request.params[0]))
        ? {
            number: '0x63',
            hash: fixtureHash('e'),
            timestamp: toHex(f.evidence.state.timestamp - 1n),
          }
        : valid(url, request),
    );
    expect(await f.run()).toBe('observed');
    expect(await f.journal().latest(f.id)).toMatchObject({
      result: {
        status: 'observed',
        finality: 'pending',
        account_readiness: 'not_assessed',
        observation: { outcome: 'creation_succeeded' },
        finality_evidence: { checkpoint: { block_number: '99' } },
      },
    });
    expect(await f.journal().lastFinalizedReceipt(f.id)).toBeNull();
    at(deliveryNow() + 31);
    f.reply.mockImplementation(valid);
    expect(await f.run()).toBe('observed');
    expect(await f.journal().latest(f.id)).toMatchObject({
      result: { finality: 'finalized', account_readiness: 'not_assessed' },
    });
    expect(
      await env.WALLET_DB.prepare('SELECT count(*) AS n FROM wallet_accounts').first('n'),
    ).toBe(0);
    expect(await f.records()).toHaveLength(2);
    expect(f.calls.some((m) => m.startsWith('eth_send'))).toBe(false);
  });
  it.each(['unavailable', 'stale', 'anchor_changed'] as const)(
    'persists %s finality without replacing receipt evidence with a success shortcut',
    async (fault) => {
      const f = await scenario(),
        valid = f.reply.getMockImplementation()!;
      f.reply.mockImplementation(async (url, request) => {
        if (request.method === 'eth_getBlockByNumber' && request.params[0] === 'finalized') {
          if (fault === 'unavailable') throw new Error('upstream URL with credential');
          if (fault === 'anchor_changed' && url.includes('observer-b'))
            return {
              number: '0x65',
              hash: fixtureHash('d'),
              timestamp: toHex(f.evidence.state.timestamp),
            };
        }
        if (
          fault === 'anchor_changed' &&
          request.method === 'eth_getBlockByNumber' &&
          request.params[0] === 'latest'
        ) {
          return {
            number: '0x65',
            hash: fixtureHash('d'),
            timestamp: toHex(f.evidence.state.timestamp),
          };
        }
        if (
          fault === 'anchor_changed' &&
          request.method === 'eth_getBlockByNumber' &&
          request.params[0] === '0x65'
        ) {
          return {
            number: '0x65',
            hash: fixtureHash('9'),
            timestamp: toHex(f.evidence.state.timestamp),
          };
        }
        return valid(url, request);
      });
      if (fault === 'stale') {
        const policy = JSON.parse(f.configuration.networks[0].finalityPolicy.document);
        policy.valid_until = deliveryNow();
        f.configuration.networks[0].finalityPolicy = finalityPin(policy);
      }
      expect(await f.run()).toBe('observed');

      expect(await f.journal().latest(f.id)).toMatchObject({
        result: {
          finality: fault === 'anchor_changed' ? 'reorg_detected' : fault,
          finality_evidence: { checkpoint: null },
          observation: { outcome: 'creation_succeeded' },
        },
      });
      expect(await f.journal().lastFinalizedReceipt(f.id)).toBeNull();
      expect(JSON.stringify(await f.records())).not.toMatch(/credential|upstream URL/);
    },
  );
  it('preserves the finalized identity across an unavailable poll and further contradictory observations', async () => {
    const f = await scenario();
    await f.run();
    const original = await f.journal().lastFinalizedReceipt(f.id);
    const valid = f.reply.getMockImplementation()!;
    at(deliveryNow() + 31);
    f.reply.mockRejectedValue(new Error('Unavailable'));
    await f.run();
    at(deliveryNow() + 301);
    f.reply.mockImplementation(valid);
    const receipt = f.evidence.receipt,
      hash = fixtureHash('d');
    f.evidence.inspection.state.blockHash = hash;
    f.evidence.state.receipt = {
      ...receipt,
      blockHash: hash,
      logs: receipt.logs.map((l) => ({ ...l, blockHash: hash })),
    };
    await f.run();
    expect(await f.journal().latest(f.id)).toMatchObject({
      result: { finality: 'reorg_detected' },
    });
    expect(await f.journal().lastFinalizedReceipt(f.id)).toEqual(original);
    at(deliveryNow() + 31);
    await f.run();
    expect(await f.journal().latest(f.id)).toMatchObject({
      result: { finality: 'reorg_detected' },
    });
    expect(await f.journal().lastFinalizedReceipt(f.id)).toEqual(original);
  });
  it.each(['target', 'status', 'future_time', 'old_time', 'checkpoint', 'extra'] as const)(
    'rejects journal finality %s corruption',
    async (fault) => {
      const f = await scenario();
      await f.run();
      const record = await f.journal().latest(f.id);
      if (!record || record.result.status !== 'observed') throw new Error('Expected observation');
      const bad = JSON.parse(JSON.stringify(record.result));
      at(deliveryNow() + 31);
      const claim = await f.journal().claim(f.id);
      if (!claim) throw new Error('Expected claim');
      bad.finality_evidence.assessed_at = deliveryNow();
      bad.finality_evidence.expires_at = deliveryNow() + 30;
      if (fault === 'target') bad.finality_evidence.target.block_hash = fixtureHash('9');
      if (fault === 'status') bad.finality = 'pending';
      if (fault === 'future_time') {
        bad.finality_evidence.assessed_at += 1;
        bad.finality_evidence.expires_at += 1;
      }
      if (fault === 'old_time') {
        bad.finality_evidence.assessed_at -= 1;
        bad.finality_evidence.expires_at -= 1;
      }
      if (fault === 'checkpoint') bad.finality_evidence.checkpoint.block_number = '99';
      if (fault === 'extra') bad.finality_evidence.provider_url = 'https://secret.invalid/';
      await expect(f.journal().append(claim, bad)).rejects.toThrow();
      expect(await f.records()).toHaveLength(1);
    },
  );
});
