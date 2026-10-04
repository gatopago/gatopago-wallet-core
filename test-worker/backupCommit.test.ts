import { seedUser } from './user.fixture';
import { env } from 'cloudflare:workers';
import { applyD1Migrations } from 'cloudflare:test';
import { afterEach, beforeAll, beforeEach, describe, expect, it, vi } from 'vitest';
import { authorizeBackupCommit, prepareBackupCommit } from '@gatopago/shared/v3/backup-enrollment';
import { deploymentDocumentDigest } from '@gatopago/shared/v3/deployment';
import type { FinalityAssessment } from '@gatopago/shared/v3/finality';
import { createResourceId } from '@gatopago/shared/v3/primitives';
import { BackupRepository } from '../src/security/backup';
import { writeAssertionRecord } from '@gatopago/shared/v3/assertion-record';
import { WalletRepository } from '../src/accounts/repository';
import { fixtureHash } from '@gatopago/test-fixtures/v3-inspection';
import { initializationFixture } from '@gatopago/test-fixtures/v3-initialization';
import { backupScenario } from './backup.fixture';
import { backupCommitScenario as scenario } from './backupCommit.fixture';
import { cleanCreationDelivery, deliveryIdentity, deliveryNow } from './creationDelivery.fixture';

beforeAll(async () => {
  await applyD1Migrations(env.WALLET_DB, env.V3_TEST_MIGRATIONS);
});
async function clean() {
  await env.WALLET_DB.exec(
    'DROP TRIGGER IF EXISTS commit_fail_authorize; DELETE FROM account_backup_transactions; DELETE FROM account_backup_outbox; DELETE FROM account_backup_commits; DELETE FROM account_backups;',
  );
  await cleanCreationDelivery();
}
beforeEach(clean);
afterEach(async () => {
  vi.restoreAllMocks();
  await clean();
});
const signal = () => new AbortController().signal;
const count = () =>
  env.WALLET_DB.prepare('SELECT count(*) AS n FROM account_backup_commits').first<number>('n');
const stored = (id: string) =>
  env.WALLET_DB.prepare('SELECT * FROM account_backup_commits WHERE id = ?').bind(id).first();

describe('owned durable second backup consent', { timeout: 15_000 }, () => {
  it('requires previously signed backup and a currently observed pending proposal', async () => {
    const f = await backupScenario(),
      r = f.request();
    await f.repository().prepare(r, signal());
    await expect(
      f.repository().prepareCommit(createResourceId('operation'), r.id, signal()),
    ).rejects.toMatchObject({ code: 'BACKUP_REQUIRED' });
    expect(await count()).toBe(0);
  });
  it('does not infer a pending onchain proposal from the first authorization', async () => {
    const f = await scenario();
    f.state.pending = false;
    await expect(
      f.repository().prepareCommit(createResourceId('operation'), f.request.id, signal()),
    ).rejects.toThrow('BACKUP_PENDING_MISMATCH');
    expect(await count()).toBe(0);
  });
  it('persists a separate digest and restores the exact review without RPC or renewal', async () => {
    const f = await scenario(),
      id = createResourceId('operation'),
      p = await f.repository().prepareCommit(id, f.request.id, signal());
    expect(p.commit_digest).not.toBe(p.proposal_hash);
    expect(p.valid_until).toBe(p.valid_after + 300);
    expect(p.valid_until).toBeLessThan(f.backup.proposal_valid_until);
    expect(p.observation.checkpoint.block_number).toBe('101');
    expect(p).toMatchObject({
      state: 'prepared',
      receive_enabled: false,
      spend_enabled: false,
      backup_assessment: 'not_assessed',
    });
    f.fetch.mockClear();
    const before = await stored(id);
    expect(await f.repository().readCommit(id)).toEqual(p);
    expect(await f.repository().prepareCommit(id, f.request.id, signal())).toEqual(p);
    expect(await stored(id)).toEqual(before);
    expect(f.fetch).not.toHaveBeenCalled();
  });
  it('authorizes only the second real P-256 assertion and persists both freshness checks', async () => {
    const f = await scenario(),
      id = createResourceId('operation'),
      p = await f.repository().prepareCommit(id, f.request.id, signal());
    const proof = f.f.assertion(p.commit_digest);
    expect(await f.repository().authorizeCommit(id, proof, signal())).toMatchObject({
      state: 'authorized',
      spend_enabled: false,
    });
    const record = await stored(id);
    expect(record?.confirmation_json).toContain('acknowledgement');
    expect(record?.calldata_sha256).toMatch(/^0x[0-9a-f]{64}$/);
    f.fetch.mockClear();
    expect((await f.repository().readCommit(id)).state).toBe('authorized');
    expect((await f.repository().authorizeCommit(id, proof, signal())).state).toBe('authorized');
    expect(f.fetch).not.toHaveBeenCalled();
    expect(await stored(id)).toEqual(record);
  });
  it('permits legitimate finalized head advancement without changing the signed acknowledgement', async () => {
    const f = await scenario(),
      id = createResourceId('operation'),
      p = await f.repository().prepareCommit(id, f.request.id, signal());
    f.state.head = 102;
    expect(
      (await f.repository().authorizeCommit(id, f.f.assertion(p.commit_digest), signal())).state,
    ).toBe('authorized');
    const restored = await f.repository().readCommit(id);
    expect(restored.commit_digest).toBe(p.commit_digest);
    expect(restored.observation.checkpoint.block_number).toBe('101');
    const confirmation = JSON.parse(String((await stored(id))?.confirmation_json)) as {
      acknowledgement: FinalityAssessment;
    };
    expect(confirmation.acknowledgement.target.block_number).toBe('101');
    expect(confirmation.acknowledgement.checkpoint?.block_number).toBe('102');
  });
  it('rejects an orphaned reviewed block even if the latest proposal and nonce match', async () => {
    const f = await scenario(),
      id = createResourceId('operation'),
      p = await f.repository().prepareCommit(id, f.request.id, signal());
    f.state.head = 102;
    f.blocks.get(101)!.block_hash = fixtureHash('f');
    await expect(
      f.repository().authorizeCommit(id, f.f.assertion(p.commit_digest), signal()),
    ).rejects.toMatchObject({ code: 'BACKUP_STATE_CHANGED' });
    expect((await stored(id))?.authorized_at).toBeNull();
  });
  it.each(['missing', 'nonce', 'proposal', 'window'] as const)(
    'rejects a changed pending %s before committing a signature',
    async (change) => {
      const f = await scenario(),
        id = createResourceId('operation'),
        p = await f.repository().prepareCommit(id, f.request.id, signal());
      if (change === 'missing') f.state.pending = false;
      if (change === 'nonce') f.state.nonce = 2n;
      if (change === 'proposal') f.state.proposal = fixtureHash('f');
      if (change === 'window') f.state.validUntil -= 1;
      await expect(
        f.repository().authorizeCommit(id, f.f.assertion(p.commit_digest), signal()),
      ).rejects.toThrow('BACKUP_PENDING_MISMATCH');
      expect((await stored(id))?.authorized_at).toBeNull();
    },
  );
  it('cannot reuse the prepare signature or an assertion from another passkey', async () => {
    const f = await scenario(),
      id = createResourceId('operation'),
      p = await f.repository().prepareCommit(id, f.request.id, signal());
    f.fetch.mockClear();
    await expect(
      f.repository().authorizeCommit(id, f.f.assertion(f.backup.proposal_hash), signal()),
    ).rejects.toThrow();
    await expect(
      f
        .repository()
        .authorizeCommit(id, initializationFixture().assertion(p.commit_digest), signal()),
    ).rejects.toThrow();
    expect((await stored(id))?.assertion_body).toBeNull();
    expect(f.fetch).not.toHaveBeenCalled();
  });
  it('keeps concurrent preparation/authorization retries idempotent', async () => {
    const f = await scenario(),
      id = createResourceId('operation');
    const prepared = await Promise.all(
      Array.from({ length: 3 }, () => f.repository().prepareCommit(id, f.request.id, signal())),
    );
    expect(prepared.every((p) => p.commit_digest === prepared[0].commit_digest)).toBe(true);
    expect(await count()).toBe(1);
    const proof = f.f.assertion(prepared[0].commit_digest);
    const signed = await Promise.all(
      Array.from({ length: 3 }, () => f.repository().authorizeCommit(id, proof, signal())),
    );
    expect(signed.every((p) => p.state === 'authorized')).toBe(true);
    await expect(
      f
        .repository()
        .authorizeCommit(id, f.f.assertion(prepared[0].commit_digest, { count: 3 }), signal()),
    ).rejects.toMatchObject({ code: 'BACKUP_CONFLICT' });
  });
  it('does not expose or mutate another owner’s confirmation', async () => {
    const f = await scenario(),
      id = createResourceId('operation'),
      p = await f.repository().prepareCommit(id, f.request.id, signal());
    const other = deliveryIdentity('other-commit');
    await seedUser(env.WALLET_DB, other);
    f.fetch.mockClear();
    await expect(f.repository(other).readCommit(id)).rejects.toMatchObject({ code: 'NOT_FOUND' });
    await expect(
      f.repository(other).prepareCommit(createResourceId('operation'), f.request.id, signal()),
    ).rejects.toMatchObject({ code: 'NOT_FOUND' });
    await expect(
      f.repository(other).authorizeCommit(id, f.f.assertion(p.commit_digest), signal()),
    ).rejects.toMatchObject({ code: 'NOT_FOUND' });
    expect(f.fetch).not.toHaveBeenCalled();
  });
  it('fails closed when the login is revoked during fresh inspection', async () => {
    const f = await scenario(),
      id = createResourceId('operation'),
      p = await f.repository().prepareCommit(id, f.request.id, signal()),
      original = f.reply.getMockImplementation()!;
    f.reply.mockImplementationOnce(async (...args) => {
      await env.WALLET_DB.prepare('UPDATE users SET disabled_at = ? WHERE id = ?')
        .bind(deliveryNow(), f.session.user_id)
        .run();
      return original(...args);
    });
    await expect(
      f.repository().authorizeCommit(id, f.f.assertion(p.commit_digest), signal()),
    ).rejects.toMatchObject({ code: 'UNAUTHENTICATED' });
    expect((await stored(id))?.authorized_at).toBeNull();
  });
  it('does not renew an expired second consent or reauthorize an old signature', async () => {
    const f = await scenario(),
      a = createResourceId('operation'),
      b = createResourceId('operation');
    const p = await f.repository().prepareCommit(a, f.request.id, signal());
    const second = await f.repository().prepareCommit(b, f.request.id, signal());
    const proof = f.f.assertion(p.commit_digest);
    await f.repository().authorizeCommit(a, proof, signal());

    const clock = vi.spyOn(Date, 'now').mockReturnValue((second.valid_until - 1) * 1000);
    f.fetch.mockClear();
    expect((await f.repository().readCommit(b)).state).toBe('prepared');
    clock.mockReturnValue(second.valid_until * 1000);
    expect((await f.repository().readCommit(b)).state).toBe('expired');
    await expect(f.repository().prepareCommit(b, f.request.id, signal())).rejects.toMatchObject({
      code: 'BACKUP_EXPIRED',
    });
    expect((await f.repository().authorizeCommit(a, proof, signal())).state).toBe('authorized');
    expect(f.fetch).not.toHaveBeenCalled();
  });
  it('confirms after delayed finality with fresh consent, without extending either stored deadline', async () => {
    const f = await scenario();
    const late = f.backup.valid_until + 900;
    vi.spyOn(Date, 'now').mockReturnValue(late * 1000);
    f.blocks.get(101)!.block_timestamp = String(late);
    f.fetch.mockClear();
    const id = createResourceId('operation'),
      p = await f.repository().prepareCommit(id, f.request.id, signal());
    expect(p.valid_after).toBe(late);
    expect(p.valid_until).toBe(late + 300);
    expect(p.proposal_hash).toBe(f.backup.proposal_hash);
    expect(f.fetch).toHaveBeenCalled();
    await expect(
      f.repository().authorizeCommit(id, f.f.assertion(f.backup.proposal_hash), signal()),
    ).rejects.toThrow();
    expect(
      (await f.repository().authorizeCommit(id, f.f.assertion(p.commit_digest), signal())).state,
    ).toBe('authorized');
    const before = await stored(id);
    f.fetch.mockClear();
    expect((await f.repository().readCommit(id)).state).toBe('authorized');
    expect(await stored(id)).toEqual(before);
    expect(f.fetch).not.toHaveBeenCalled();
    expect((await f.repository().read(f.request.id)).valid_until).toBe(f.backup.valid_until);
    expect((await f.repository().read(f.request.id)).proposal_valid_until).toBe(
      f.backup.proposal_valid_until,
    );
  });
  it('still rejects new confirmation when the signed proposal deadline itself expires', async () => {
    const f = await scenario(),
      late = f.backup.proposal_valid_until;
    vi.spyOn(Date, 'now').mockReturnValue(late * 1000);
    f.fetch.mockClear();
    const repository = f.repository({ ...f.principal, expiresAt: late + 3600, authTime: late });
    await expect(
      repository.prepareCommit(createResourceId('operation'), f.request.id, signal()),
    ).rejects.toMatchObject({ code: 'BACKUP_EXPIRED' });
    expect(await count()).toBe(0);
    expect(f.fetch).not.toHaveBeenCalled();
  });
  it('copies assertion buffers before I/O and never accepts half a durable write', async () => {
    const f = await scenario(),
      id = createResourceId('operation'),
      p = await f.repository().prepareCommit(id, f.request.id, signal());
    await env.WALLET_DB.exec(
      "CREATE TRIGGER commit_fail_authorize BEFORE UPDATE ON account_backup_commits BEGIN SELECT RAISE(ABORT, 'Synthetic failure'); END;",
    );
    await expect(
      f.repository().authorizeCommit(id, f.f.assertion(p.commit_digest), signal()),
    ).rejects.toThrow();
    expect((await stored(id))?.authorized_at).toBeNull();
    await env.WALLET_DB.exec('DROP TRIGGER commit_fail_authorize');
    const proof = f.f.assertion(p.commit_digest),
      pending = f.repository().authorizeCommit(id, proof, signal());
    proof.signatureDER.fill(0);
    expect((await pending).state).toBe('authorized');
  });
  it('does not use stored state when either provider fails', async () => {
    const f = await scenario(),
      id = createResourceId('operation'),
      p = await f.repository().prepareCommit(id, f.request.id, signal());
    f.fetch.mockRejectedValue(new Error('Synthetic outage'));
    await expect(
      f.repository().authorizeCommit(id, f.f.assertion(p.commit_digest), signal()),
    ).rejects.toThrow();
    expect((await stored(id))?.authorized_at).toBeNull();
  });
  it('has no global reservation and caps per-owner pending consent volume', async () => {
    const f = await scenario();
    for (let i = 0; i < 6; i++)
      await f.repository().prepareCommit(createResourceId('operation'), f.request.id, signal());
    await expect(
      f.repository().prepareCommit(createResourceId('operation'), f.request.id, signal()),
    ).rejects.toMatchObject({ code: 'BACKUP_LIMIT' });
    expect(await count()).toBe(6);
  });
  it('denies all networks without the internal resolver and cancels without preparing', async () => {
    const f = await scenario(),
      repository = new BackupRepository(
        env.WALLET_DB,
        f.principal,
        f.configuration.scope,
        f.configuration.profiles,
      );
    await expect(
      repository.prepareCommit(createResourceId('operation'), f.request.id, signal()),
    ).rejects.toMatchObject({ code: 'BACKUP_PROFILE_UNAVAILABLE' });
    const abort = new AbortController();
    abort.abort();
    await expect(
      f.repository().prepareCommit(createResourceId('operation'), f.request.id, abort.signal),
    ).rejects.toThrow();
    expect(await count()).toBe(0);
  });
  it('keeps the independently compiled commit digest consistent after a restart', async () => {
    const f = await scenario(),
      id = createResourceId('operation');
    await f.repository().prepareCommit(id, f.request.id, signal());
    const restored = await f.repository().readCommit(id);
    expect(
      prepareBackupCommit(
        restored.input,
        restored.observation,
        restored.valid_after,
        restored.valid_until,
        restored.valid_after,
      ).digest,
    ).toBe(restored.commit_digest);
  });
  it('does not change the admitted RPCs when the resolver result mutates during inspection', async () => {
    const f = await scenario(),
      id = createResourceId('operation'),
      p = await f.repository().prepareCommit(id, f.request.id, signal());
    const owned = await new WalletRepository(env.WALLET_DB, f.principal).ownedAccount(
      f.walletId,
      f.walletAccountId,
    );
    const supplied = (await f.profiles(owned, signal())).map((profile) => ({ ...profile }));
    const admittedUrls = new Set(supplied[0].rpcUrls);
    const reply = f.reply.getMockImplementation()!;
    f.reply.mockImplementationOnce(async (...args) => {
      supplied[0].rpcUrls = ['https://changed.invalid/rpc', 'https://other.invalid/rpc'];
      return reply(...args);
    });
    f.fetch.mockClear();
    expect(
      (
        await f
          .repository(f.principal, async () => supplied)
          .authorizeCommit(id, f.f.assertion(p.commit_digest), signal())
      ).state,
    ).toBe('authorized');
    expect(f.fetch.mock.calls.length).toBeGreaterThan(0);
    expect(f.fetch.mock.calls.every(([url]) => admittedUrls.has(String(url)))).toBe(true);
  });
  it('keeps confirmation terms immutable and rejects partial durable proof records', async () => {
    const f = await scenario(),
      id = createResourceId('operation');
    await f.repository().prepareCommit(id, f.request.id, signal());
    await expect(
      env.WALLET_DB.prepare('UPDATE account_backup_commits SET commit_digest = ? WHERE id = ?')
        .bind(fixtureHash('a'), id)
        .run(),
    ).rejects.toThrow();
    await expect(
      env.WALLET_DB.prepare("UPDATE account_backup_commits SET assertion_body = '{}' WHERE id = ?")
        .bind(id)
        .run(),
    ).rejects.toThrow();
    expect((await stored(id))?.authorized_at).toBeNull();
  });
  it('reverifies the persisted assertion and calldata instead of trusting an authorized flag', async () => {
    const f = await scenario(),
      a = createResourceId('operation'),
      b = createResourceId('operation');
    const p = await f.repository().prepareCommit(a, f.request.id, signal());
    const q = await f.repository().prepareCommit(b, f.request.id, signal());
    await f.repository().authorizeCommit(a, f.f.assertion(p.commit_digest), signal());
    const original = await stored(a),
      wrong = initializationFixture().assertion(q.commit_digest);
    const signed = authorizeBackupCommit(
      q.input,
      q.observation,
      q.valid_after,
      q.valid_until,
      f.f.assertion(q.commit_digest),
      q.valid_after,
    );

    await env.WALLET_DB.prepare(
      `UPDATE account_backup_commits SET authorized_at = ?, assertion_body = ?, confirmation_json = ?, calldata_sha256 = ?, authorized_auth_time = ? WHERE id = ?`,
    )
      .bind(
        original?.authorized_at,
        writeAssertionRecord(wrong),
        original?.confirmation_json,
        deploymentDocumentDigest(signed.data),
        f.principal.authTime,
        b,
      )
      .run();
    f.fetch.mockClear();
    await expect(f.repository().readCommit(b)).rejects.toMatchObject({
      code: 'WALLET_DATA_INVALID',
    });
    expect(f.fetch).not.toHaveBeenCalled();
  });
  it('cancels a confirmation during inspection without persisting its signature', async () => {
    const f = await scenario(),
      id = createResourceId('operation'),
      p = await f.repository().prepareCommit(id, f.request.id, signal());
    const abort = new AbortController(),
      reply = f.reply.getMockImplementation()!;
    f.reply.mockImplementationOnce(async (...args) => {
      const result = await reply(...args);
      abort.abort();
      return result;
    });
    await expect(
      f.repository().authorizeCommit(id, f.f.assertion(p.commit_digest), abort.signal),
    ).rejects.toThrow();
    expect((await stored(id))?.authorized_at).toBeNull();
  });
});
