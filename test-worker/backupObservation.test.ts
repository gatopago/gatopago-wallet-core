import { env } from 'cloudflare:workers';
import { applyD1Migrations } from 'cloudflare:test';
import { afterEach, beforeAll, beforeEach, describe, expect, it, vi } from 'vitest';
import { toHex } from 'viem';
import { BackupDeliveryRepository } from '../src/security/backupDelivery';
import { reconcileBackupObservation } from '../src/security/backupObservation';
import { BackupObservationJournal } from '../src/security/backupObservationJournal';
import { backupObservationJson } from '../src/security/backupObservationRecord';
import { verifyBackupReceipt } from '../src/security/backupReceipt';
import { fixtureHash } from '@gatopago/test-fixtures/v3-inspection';
import { backupObservationScenario, cleanBackupObservations } from './backupObservation.fixture';
import { deliveryNow } from './creationDelivery.fixture';

beforeAll(async () => {
  await applyD1Migrations(env.WALLET_DB, env.V3_TEST_MIGRATIONS);
});
beforeEach(cleanBackupObservations);
afterEach(async () => {
  vi.restoreAllMocks();
  await cleanBackupObservations();
});
const signal = () => new AbortController().signal;
const at = (time: number) => vi.spyOn(Date, 'now').mockReturnValue(time * 1000);
const verify = (f: Awaited<ReturnType<typeof backupObservationScenario>>) =>
  verifyBackupReceipt(f.grant, f.state.tx, f.state.receipt, f.block.block_timestamp);
const count = () =>
  env.WALLET_DB.prepare('SELECT count(*) AS n FROM account_backup_observations').first<number>('n');

describe('backup observations, real local D1 and signatures', { timeout: 20_000 }, () => {
  it.each(['prepare', 'commit'] as const)(
    'verifies and persists %s without enabling the account or sending again',
    async (kind) => {
      const f = await backupObservationScenario(kind);
      const before = await env.WALLET_DB.prepare(
        'SELECT * FROM account_backup_outbox WHERE operation_id = ?',
      )
        .bind(f.id)
        .first();
      expect(verify(f).outcome).toBe(kind === 'prepare' ? 'proposal_prepared' : 'backup_committed');
      expect(await f.journal().due()).toEqual([f.id]);
      expect(await f.run()).toBe('observed');
      const latest = await f.journal().latest(f.id);
      expect(latest?.result).toMatchObject({
        status: 'observed',
        finality: 'finalized',
        account_readiness: 'not_assessed',
        observation: {
          operation_id: f.id,
          execution_gas_cost: '1000000',
          installed_manifest_hash: kind === 'prepare' ? null : f.grant.signed.expectedManifestHash,
        },
      });
      expect(await f.journal().lastFinalizedReceipt(f.id)).toEqual(
        latest?.result.status === 'observed' ? latest.result.observation : null,
      );
      expect(await f.journal().due()).toEqual([]);
      expect(await f.run()).toBe('idle');
      expect(
        await env.WALLET_DB.prepare('SELECT * FROM account_backup_outbox WHERE operation_id = ?')
          .bind(f.id)
          .first(),
      ).toEqual(before);
      expect((await f.repository().read(f.grant.backupId)).spend_enabled).toBe(false);
      expect(f.reply.mock.calls.some(([method]) => method === 'eth_sendRawTransaction')).toBe(
        false,
      );
    },
  );
  it('restores sent bytes after consent expiry and identity revocation, with no current sponsor configuration', async () => {
    const f = await backupObservationScenario();
    await env.WALLET_DB.prepare('UPDATE users SET disabled_at = ? WHERE id = ?')
      .bind(deliveryNow(), f.session.user_id)
      .run();
    at(f.grant.backup.message.validUntil + 60);
    expect(await f.delivery.observationGrant(f.id)).toEqual(f.grant);
    expect(await f.delivery.claim(f.id)).toBeNull();
    expect(verify(f).outcome).toBe('proposal_prepared');
  });
  it.each([
    'nonce',
    'value',
    'gas',
    'maxFeePerGas',
    'maxPriorityFeePerGas',
    'chainId',
    'input',
    'from',
    'to',
    'hash',
    'r',
    's',
    'yParity',
    'blockHash',
    'transactionIndex',
  ] as const)('rejects an altered transaction %s', async (field) => {
    const f = await backupObservationScenario();
    const wrong = {
      ...f.state.tx,
      [field]:
        field === 'from' || field === 'to'
          ? `0x${'1'.repeat(40)}`
          : field === 'input'
            ? '0x12345678'
            : ['hash', 'r', 's', 'blockHash'].includes(field)
              ? fixtureHash('a')
              : '0x9',
    };
    expect(() =>
      verifyBackupReceipt(f.grant, wrong, f.state.receipt, f.block.block_timestamp),
    ).toThrow('BACKUP_RECEIPT_INVALID');
  });
  it('accepts the standard parity alias and an empty access list, rejects extra transaction capabilities', async () => {
    const f = await backupObservationScenario();
    expect(
      verifyBackupReceipt(
        f.grant,
        { ...f.state.tx, yParity: undefined, v: f.state.tx.yParity, accessList: [] },
        f.state.receipt,
        f.block.block_timestamp,
      ),
    ).toEqual(verify(f));
    for (const extra of [
      { v: '0x25' },
      { accessList: [{}] },
      { authorizationList: [] },
      { blobVersionedHashes: [] },
      { maxFeePerBlobGas: '0x0' },
    ]) {
      expect(() =>
        verifyBackupReceipt(
          f.grant,
          { ...f.state.tx, ...extra },
          f.state.receipt,
          f.block.block_timestamp,
        ),
      ).toThrow();
    }
  });
  it.each([
    'from',
    'to',
    'type',
    'transactionHash',
    'contractAddress',
    'gasUsed',
    'effectiveGasPrice',
  ] as const)('rejects altered receipt %s', async (field) => {
    const f = await backupObservationScenario();
    const wrong = {
      ...f.state.receipt,
      [field]: ['from', 'to', 'contractAddress'].includes(field)
        ? `0x${'1'.repeat(40)}`
        : field === 'transactionHash'
          ? fixtureHash('a')
          : '0xffffffffff',
    };
    expect(() =>
      verifyBackupReceipt(f.grant, f.state.tx, wrong, f.block.block_timestamp),
    ).toThrow();
  });
  it.each([
    'extra',
    'missing',
    'emitter',
    'proposal',
    'trailing',
    'removed',
    'index',
    'block',
    'topic',
  ] as const)('rejects %s event evidence', async (change) => {
    const f = await backupObservationScenario('commit'),
      r = structuredClone(f.state.receipt);
    if (change === 'extra') r.logs.push({ ...r.logs[1], logIndex: '0x6' });
    if (change === 'missing') r.logs.pop();
    if (change === 'emitter') r.logs[0].address = `0x${'1'.repeat(40)}`;
    if (change === 'proposal') r.logs[0].topics[1] = fixtureHash('a');
    if (change === 'trailing') r.logs[0].data = `${r.logs[0].data}00`;
    if (change === 'removed') r.logs[0].removed = true;
    if (change === 'index') r.logs[1].logIndex = r.logs[0].logIndex;
    if (change === 'block') r.logs[1].blockHash = fixtureHash('a');
    if (change === 'topic') r.logs[1].topics.push(fixtureHash('a'));
    expect(() => verifyBackupReceipt(f.grant, f.state.tx, r, f.block.block_timestamp)).toThrow();
  });
  it('checks the original acknowledgement and installed manifest, not just event names', async () => {
    const f = await backupObservationScenario('commit');
    f.state.receipt.logs[1].data = fixtureHash('a');
    expect(() => verify(f)).toThrow();
    f.state.receipt.logs[1].data = f.grant.commit!.message.acknowledgementsHash;
    f.state.receipt.logs[0].topics[2] = fixtureHash('a');
    expect(() => verify(f)).toThrow();
  });
  it('requires prepare readyAt to equal inclusion time and uses an exclusive consent deadline', async () => {
    const f = await backupObservationScenario();
    expect(() =>
      verifyBackupReceipt(
        f.grant,
        f.state.tx,
        f.state.receipt,
        String(Number(f.block.block_timestamp) + 1),
      ),
    ).toThrow();
    expect(() =>
      verifyBackupReceipt(
        f.grant,
        f.state.tx,
        f.state.receipt,
        String(f.grant.backup.message.validUntil),
      ),
    ).toThrow();
  });
  it('records an exact reverted transaction, including one mined after consent expired', async () => {
    const f = await backupObservationScenario('commit');
    f.state.receipt.status = '0x0';
    f.state.receipt.logs = [];
    expect(
      verifyBackupReceipt(
        f.grant,
        f.state.tx,
        f.state.receipt,
        String(f.grant.commit!.message.validUntil + 10),
      ),
    ).toMatchObject({
      outcome: 'execution_reverted',
      installed_manifest_hash: null,
      account_readiness: 'not_assessed',
    });
    expect(await f.run()).toBe('observed');
    expect((await f.journal().latest(f.id))?.result).toMatchObject({
      observation: { outcome: 'execution_reverted' },
    });
  });
  it('does not treat a missing receipt as permission to rebroadcast', async () => {
    const f = await backupObservationScenario();
    f.state.missing = true;
    expect(await f.run()).toBe('not_observed');
    expect(await count()).toBe(1);
    expect(await f.delivery.claim(f.id)).toBeNull();
    expect(await f.journal().lastFinalizedReceipt(f.id)).toBeNull();
  });
  it('requires a full exact transaction, not just its receipt/hash', async () => {
    const f = await backupObservationScenario();
    f.state.missingTransaction = true;
    expect(await f.run()).toBe('unavailable');
  });
  it('records disagreement when only one provider sees the receipt', async () => {
    const f = await backupObservationScenario(),
      original = f.fetch.getMockImplementation()!;
    f.fetch.mockImplementation(async (url, init) => {
      const request = JSON.parse(String(init?.body)) as { id: number; method: string };
      if (String(url).includes('observer-b') && request.method === 'eth_getTransactionReceipt')
        return Response.json({ jsonrpc: '2.0', id: request.id, result: null });
      return original(url, init);
    });
    expect(await f.run()).toBe('disagreement');
    expect((await f.journal().latest(f.id))?.result.finality).toBe('not_assessed');
  });
  it('validates profile and provider independence before RPC', async () => {
    const f = await backupObservationScenario(),
      network = f.configuration.networks[0];
    await expect(
      reconcileBackupObservation(
        f.grant,
        { ...network, providers: [network.providers[0], network.providers[0]] },
        signal(),
      ),
    ).rejects.toThrow();
    await expect(
      reconcileBackupObservation(f.grant, { ...network, digest: fixtureHash('a') }, signal()),
    ).rejects.toThrow();
    expect(f.fetch).not.toHaveBeenCalled();
  });
  it('requires the admitted proxy implementation at the receipt block', async () => {
    const f = await backupObservationScenario();
    f.evidence.state.proxyCode = '0x6000';
    expect(await f.run()).toBe('unavailable');
  });
  it('drains a provider failure without storing diagnostics or credentials', async () => {
    const f = await backupObservationScenario();
    f.reply.mockRejectedValue(new Error('https://private.example/?key=sensitive'));
    expect(await f.run()).toBe('unavailable');
    expect(JSON.stringify(await f.journal().latest(f.id))).not.toContain('sensitive');
  });
  it('rechecks the canonical block after inspection', async () => {
    const f = await backupObservationScenario(),
      original = f.reply.getMockImplementation()!;
    let blocks = 0;
    f.reply.mockImplementation(async (method, params) => {
      const result = await original(method, params);
      if (method === 'eth_getBlockByNumber' && params[0] === '0x65' && ++blocks > 4)
        return { ...(result as object), hash: fixtureHash('a') };
      return result;
    });
    expect(await f.run()).toBe('unavailable');
  });
  it('one of four concurrent observers obtains the durable lease', async () => {
    const f = await backupObservationScenario();
    const results = await Promise.all(Array.from({ length: 4 }, () => f.run()));
    expect(results.filter((v) => v === 'observed')).toHaveLength(1);
    expect(await count()).toBe(1);
  });
  it('rejects expired/duplicate lease writers and reclaims an interrupted observer', async () => {
    const f = await backupObservationScenario(),
      first = await f.journal().claim(f.id);
    if (!first) throw new Error('lease');
    const result = await reconcileBackupObservation(
      first.grant,
      f.configuration.networks[0],
      signal(),
    );
    at(first.until);
    expect(await f.journal().append(first, result)).toBe(false);
    const second = await f.journal().claim(f.id);
    expect(second?.token).not.toBe(first.token);
    expect(await f.journal().append(first, result)).toBe(false);
  });
  it('rolls back the record and head together when D1 fails, then allows the same valid lease', async () => {
    const f = await backupObservationScenario(),
      journal = f.journal(),
      claim = await journal.claim(f.id);
    if (!claim) throw new Error('lease');
    const result = await reconcileBackupObservation(
      claim.grant,
      f.configuration.networks[0],
      signal(),
    );
    await env.WALLET_DB.exec(
      "CREATE TRIGGER backup_observation_fail BEFORE UPDATE OF latest_epoch ON account_backup_observation_jobs BEGIN SELECT RAISE(ABORT, 'synthetic failure'); END;",
    );
    await expect(journal.append(claim, result)).rejects.toThrow();
    expect(await count()).toBe(0);
    expect(await journal.latest(f.id)).toBeNull();
    await env.WALLET_DB.exec('DROP TRIGGER backup_observation_fail;');
    expect(await journal.append(claim, result)).toBe(true);
    expect(await journal.append(claim, result)).toBe(false);
    expect(await count()).toBe(1);
  });
  it('preserves history but never replaces a new unavailable state with an older success', async () => {
    const f = await backupObservationScenario();
    await f.run();
    const old = await f.journal().lastFinalizedReceipt(f.id);
    at(deliveryNow() + 300);
    f.state.missingTransaction = true;
    expect(await f.run()).toBe('unavailable');
    expect((await f.journal().latest(f.id))?.result.status).toBe('unavailable');
    expect(await f.journal().lastFinalizedReceipt(f.id)).toEqual(old);
    expect(await count()).toBe(2);
    await expect(
      env.WALLET_DB.exec('UPDATE account_backup_observations SET observed_at = observed_at + 1;'),
    ).rejects.toThrow('append-only');
  });
  it('marks a rewritten previously finalized block as reorg_detected, even after a missing observation', async () => {
    const f = await backupObservationScenario('commit');
    await f.run();
    at(deliveryNow() + 300);
    f.state.missing = true;
    await f.run();
    at(deliveryNow() + 20);
    f.state.missing = false;
    f.block.block_hash = fixtureHash('f');
    f.state.tx.blockHash = fixtureHash('f');
    f.state.receipt.blockHash = fixtureHash('f');
    for (const log of f.state.receipt.logs) log.blockHash = fixtureHash('f');
    expect(await f.run()).toBe('observed');
    expect((await f.journal().latest(f.id))?.result.finality).toBe('reorg_detected');
  });
  it('rejects inclusion at or before the checkpoint reviewed before signing', async () => {
    const f = await backupObservationScenario('commit');
    f.state.tx.blockNumber = toHex(BigInt(f.grant.afterCheckpoint));
    f.state.receipt.blockNumber = f.state.tx.blockNumber;
    for (const log of f.state.receipt.logs) log.blockNumber = f.state.tx.blockNumber;
    expect(() => verify(f)).toThrow();
  });
  it('does not silently rewrite gas evidence inside a previously finalized block', async () => {
    const f = await backupObservationScenario();
    await f.run();
    at(deliveryNow() + 300);
    f.state.receipt.gasUsed = toHex(200_001);
    expect(await f.run()).toBe('observed');
    expect((await f.journal().latest(f.id))?.result.finality).toBe('reorg_detected');
  });
  it('does not equate a receipt with finality when the finality policy has expired', async () => {
    const f = await backupObservationScenario();
    at(deliveryNow() + 3600);
    expect(await f.run()).toBe('observed');
    expect((await f.journal().latest(f.id))?.result.finality).not.toBe('finalized');
  });
  it('rejects storage-shape drift and invented readiness', async () => {
    const f = await backupObservationScenario(),
      result = await reconcileBackupObservation(f.grant, f.configuration.networks[0], signal());
    expect(result.status).toBe('observed');
    expect(() =>
      backupObservationJson({ ...result, account_readiness: 'ready' }, f.grant),
    ).toThrow();
    expect(() => backupObservationJson({ ...result, unexpected: true }, f.grant)).toThrow();
    if (result.status === 'observed') {
      expect(() =>
        backupObservationJson(
          { ...result, observation: { ...result.observation, gas_used: toHex(200_000) } },
          f.grant,
        ),
      ).toThrow();
      expect(() =>
        backupObservationJson(
          {
            ...result,
            observation: { ...result.observation, installed_manifest_hash: fixtureHash('a') },
          },
          f.grant,
        ),
      ).toThrow();
    }
  });
  it('rejects another environment and unbounded discovery', async () => {
    const f = await backupObservationScenario(),
      other = { ...f.configuration, environment: 'unsupported' as never };
    expect(() => new BackupObservationJournal(env.WALLET_DB, other)).toThrow();
    const journal = new BackupObservationJournal(env.WALLET_DB, f.configuration);
    for (const limit of [0, 51, 1.5, NaN]) await expect(journal.due(limit)).rejects.toThrow();
    await expect(
      new BackupDeliveryRepository(env.WALLET_DB, {
        ...f.configuration,
        profiles: [],
      }).observationGrant(f.id),
    ).rejects.toThrow();
  });
  it('an already cancelled job does not claim or perform I/O', async () => {
    const f = await backupObservationScenario(),
      abort = new AbortController();
    abort.abort();
    await expect(f.run(abort.signal)).rejects.toThrow();
    expect(f.fetch).not.toHaveBeenCalled();
    expect(await count()).toBe(0);
  });
});
