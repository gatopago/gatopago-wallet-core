import { env } from 'cloudflare:workers';
import { applyD1Migrations } from 'cloudflare:test';
import { afterEach, beforeAll, beforeEach, describe, expect, it, vi } from 'vitest';
import { keccak256 } from 'viem';
import { generatePrivateKey, privateKeyToAccount } from 'viem/accounts';
import {
  authorizeBackupEnrollment,
  authorizeBackupCommit,
} from '@gatopago/shared/v3/backup-enrollment';
import { createResourceId } from '@gatopago/shared/v3/primitives';
import { BackupDeliveryRepository, type BackupDeliveryClaim } from '../src/security/backupDelivery';
import { prepareBackupTransaction } from '../src/security/backupTransaction';
import { fixtureHash } from '@gatopago/test-fixtures/v3-inspection';
import { initializationFixture } from '@gatopago/test-fixtures/v3-initialization';
import { backupScenario } from './backup.fixture';
import { backupCommitScenario } from './backupCommit.fixture';
import { cleanCreationDelivery, deliveryNow } from './creationDelivery.fixture';

beforeAll(async () => {
  await applyD1Migrations(env.WALLET_DB, env.V3_TEST_MIGRATIONS);
});
async function clean() {
  await env.WALLET_DB
    .exec(`DROP TRIGGER IF EXISTS backup_fail_outbox; DROP TRIGGER IF EXISTS backup_fail_delivery;
  DELETE FROM account_backup_transactions; DELETE FROM account_backup_outbox; DELETE FROM account_backup_commits; DELETE FROM account_backups;`);
  await cleanCreationDelivery();
}

beforeEach(async () => {
  await clean();
  vi.spyOn(Date, 'now').mockReturnValue(Date.now());
});
afterEach(async () => {
  vi.restoreAllMocks();
  await clean();
});
const signal = () => new AbortController().signal;
const at = (time: number) => vi.spyOn(Date, 'now').mockReturnValue(time * 1000);
const stored = (id: string) =>
  env.WALLET_DB.prepare('SELECT * FROM account_backup_outbox WHERE operation_id = ?')
    .bind(id)
    .first();
const count = () =>
  env.WALLET_DB.prepare('SELECT count(*) AS n FROM account_backup_outbox').first<number>('n');
async function scenario() {
  const f = await backupScenario(),
    r = f.request(),
    p = await f.repository().prepare(r, signal());
  const owner = f.f.assertion(p.proposal_hash),
    proofs = await f.proofs(p.input);
  const authorize = () => f.repository().authorize(r.id, owner, proofs, signal());
  const repo = () => new BackupDeliveryRepository(env.WALLET_DB, f.configuration);
  const operator = privateKeyToAccount(generatePrivateKey());
  const terms = { nonce: 0, gas: 800_000n, maxFeePerGas: 10n, maxPriorityFeePerGas: 1n };
  const policy = (lease: BackupDeliveryClaim) => ({
    operator: operator.address,
    networkId: lease.record.initial.prepared.profile.deployment.network_id,
    maxGas: 800_000n,
    maxFeePerGas: 10n,
    maxPriorityFeePerGas: 1n,
    maxExecutionFee: 8_000_000n,
  });
  const raw = (lease: BackupDeliveryClaim) =>
    operator.signTransaction(
      prepareBackupTransaction(policy(lease).networkId, lease.record.signed, policy(lease), terms)
        .request,
    );
  const beginSend = async (lease: BackupDeliveryClaim) => {
    if (!(await repo().reserveTransaction(lease, policy(lease), terms))) return false;
    return repo().beginSend(lease, policy(lease), await raw(lease), deliveryNow() + 30);
  };
  return {
    ...f,
    r,
    p,
    owner,
    proofs,
    authorize,
    repo,
    beginSend,
    hash: async (lease: BackupDeliveryClaim) => keccak256(await raw(lease)),
  };
}
async function authorized() {
  const f = await scenario();
  await f.authorize();
  f.fetch.mockClear();
  return f;
}
async function claim(f: Awaited<ReturnType<typeof scenario>>) {
  const lease = await f.repo().claim(f.r.id);
  if (!lease) throw new Error('Expected delivery lease');
  return lease;
}

describe('durable backup delivery, actual D1 and cryptographic proofs', { timeout: 15_000 }, () => {
  it('does not create delivery work for a proposal or GET', async () => {
    const f = await scenario();
    expect(await count()).toBe(0);
    await f.repository().read(f.r.id);
    expect(await count()).toBe(0);
    await expect(f.repo().claim(f.r.id)).rejects.toMatchObject({ code: 'NOT_FOUND' });
  });
  it('commits one pending job with the exact authorized call and no readiness', async () => {
    const f = await authorized(),
      before = await stored(f.r.id);
    expect(before).toMatchObject({
      kind: 'prepare',
      backup_id: f.r.id,
      state: 'pending',
      authorized_auth_time: f.principal.authTime,
    });
    expect(before).not.toHaveProperty('authorization_json');
    expect(before).not.toHaveProperty('firebase_subject');
    const lease = await claim(f),
      signed = await authorizeBackupEnrollment(f.p.input, f.owner, f.proofs, f.p.valid_after);
    expect(lease.record.signed).toEqual(signed);
    expect(lease.record.signed.account_readiness).toBe('not_assessed');
    expect(await f.repo().observationGrant(f.r.id)).toBeNull();
    expect(f.fetch).not.toHaveBeenCalled();
  });
  it('rolls back authorization if the durable insertion fails; retry creates one job', async () => {
    const f = await scenario();
    await env.WALLET_DB.exec(
      `CREATE TRIGGER backup_fail_outbox BEFORE INSERT ON account_backup_outbox BEGIN SELECT RAISE(ABORT, 'synthetic failure'); END;`,
    );
    await expect(f.authorize()).rejects.toThrow();
    expect(await count()).toBe(0);
    expect(
      await env.WALLET_DB.prepare(
        'SELECT authorized_at,authorization_json,authorized_auth_time FROM account_backups WHERE id = ?',
      )
        .bind(f.r.id)
        .first(),
    ).toEqual({ authorized_at: null, authorization_json: null, authorized_auth_time: null });
    await env.WALLET_DB.exec('DROP TRIGGER backup_fail_outbox;');
    await f.authorize();
    await f.authorize();
    expect(await count()).toBe(1);
  });
  it('lost HTTP responses and four concurrent authorizations never reset or duplicate a job', async () => {
    const f = await scenario();
    await Promise.all(Array.from({ length: 4 }, () => f.authorize()));
    expect(await count()).toBe(1);
    const lease = await claim(f);
    await f.beginSend(lease);
    const before = await stored(f.r.id);
    await f.authorize();
    expect(await stored(f.r.id)).toEqual(before);
    expect((await f.repository().read(f.r.id)).state).toBe('authorized');
  });
  it('six competing workers receive one lease and one send marker', async () => {
    const f = await authorized();
    const claims = (
      await Promise.all(Array.from({ length: 6 }, () => f.repo().claim(f.r.id)))
    ).filter((v) => v !== null);
    expect(claims).toHaveLength(1);
    const markers = await Promise.all(Array.from({ length: 4 }, () => f.beginSend(claims[0])));
    expect(markers.filter(Boolean)).toHaveLength(1);
    expect((await stored(f.r.id))?.attempt_count).toBe(1);
  });
  it('reclaims an interrupted preflight but rejects stale lease writers', async () => {
    const f = await authorized(),
      first = await claim(f);
    at(first.until);
    const second = await claim(f);
    expect(second.token).not.toBe(first.token);
    expect(await f.beginSend(first)).toBe(false);
    expect(await f.repo().retryBeforeSend(first)).toBe(false);
    expect(await f.beginSend(second)).toBe(true);
    expect(await f.repo().uncertain(first)).toBe(false);
    expect((await stored(f.r.id))?.state).toBe('sending');
  });
  it('turns a crashed send into uncertainty, never into a new automatic send', async () => {
    const f = await authorized(),
      lease = await claim(f);
    await f.beginSend(lease);
    at(lease.until);
    expect(await f.repo().due()).toEqual([f.r.id]);
    expect(await f.repo().claim(f.r.id)).toBeNull();
    expect(await stored(f.r.id)).toMatchObject({
      state: 'uncertain',
      lease_token: null,
      lease_expires_at: null,
    });
    expect(await f.repo().claim(f.r.id)).toBeNull();
    expect(await f.repo().due()).toEqual([]);
    expect(await f.repo().retryBeforeSend(lease)).toBe(false);
    expect(await f.repo().observationGrant(f.r.id)).toMatchObject({
      id: f.r.id,
      kind: 'prepare',
      transactionHash: await f.hash(lease),
    });
  });
  it('keeps an acknowledged hash as a hint, without implying finalized policy or spend readiness', async () => {
    const f = await authorized(),
      lease = await claim(f);
    await f.beginSend(lease);
    expect(await f.repo().accepted(lease, await f.hash(lease))).toBe(true);
    expect(await f.repo().accepted(lease, fixtureHash('9'))).toBe(false);
    expect(await f.repo().uncertain(lease)).toBe(false);
    expect(await f.repo().observationGrant(f.r.id)).toMatchObject({
      transactionHash: await f.hash(lease),
      signed: { account_readiness: 'not_assessed' },
    });
    expect((await f.repository().read(f.r.id)).spend_enabled).toBe(false);
  });
  it('rejects malformed hashes and late acknowledgements without reopening a send', async () => {
    const f = await authorized(),
      lease = await claim(f);
    await f.beginSend(lease);
    await expect(f.repo().accepted(lease, '0x12')).rejects.toThrow();
    at(lease.until);
    expect(await f.repo().accepted(lease, fixtureHash('8'))).toBe(false);
    expect(await f.repo().uncertain(lease)).toBe(true);
  });
  it('expires only never-sent consent; uncertain work remains observable after deadline and revocation', async () => {
    const f = await authorized(),
      lease = await claim(f);
    await f.beginSend(lease);
    await f.repo().uncertain(lease);
    await env.WALLET_DB.prepare('UPDATE users SET disabled_at = ? WHERE id = ?')
      .bind(deliveryNow(), f.session.user_id)
      .run();
    at(f.p.valid_until + 60);
    expect(await f.repo().claim(f.r.id)).toBeNull();
    expect(await f.repo().observationGrant(f.r.id)).toMatchObject({ id: f.r.id });
    expect((await stored(f.r.id))?.state).toBe('uncertain');
  });
  it('expires a pending authorization without a fresh RPC or extended signature', async () => {
    const f = await authorized();
    at(f.p.valid_until);
    expect(await f.repo().due()).toEqual([f.r.id]);
    expect(await f.repo().claim(f.r.id)).toBeNull();
    expect((await stored(f.r.id))?.state).toBe('expired');
    expect(await f.repo().observationGrant(f.r.id)).toBeNull();
    expect(f.fetch).not.toHaveBeenCalled();
  });
  it('uses the recorded grant after JWT expiry, without fabricating or renewing a session', async () => {
    const f = await scenario();
    at(deliveryNow());
    const principal = { ...f.principal, expiresAt: deliveryNow() + 5 };
    await f.repository(principal).authorize(f.r.id, f.owner, f.proofs, signal());
    at(principal.expiresAt + 1);
    await expect(f.repository(principal).read(f.r.id)).rejects.toMatchObject({
      code: 'UNAUTHENTICATED',
    });
    const lease = await claim(f);
    expect(lease.record.authTime).toBe(principal.authTime);
    expect(await f.beginSend(lease)).toBe(true);
  });
  it('reconstructs against detached configuration, not a caller-mutated profile list', async () => {
    const f = await authorized(),
      config = {
        ...f.configuration,
        profiles: [...f.configuration.profiles],
        scope: { ...f.configuration.scope },
      };
    const repo = new BackupDeliveryRepository(env.WALLET_DB, config);
    config.profiles.length = 0;
    config.scope.origin = 'https://other.example';
    expect((await repo.claim(f.r.id))?.record.signed.account).toBe(f.prepared.account);
  });
  it('does not trust a database authorized flag or outbox checksum in place of valid signatures', async () => {
    const f = await scenario();
    const { backupProofs } = await import('../src/security/backupRecord');
    const wrong = backupProofs(f.f.assertion(fixtureHash('e')), f.proofs);
    await env.WALLET_DB.prepare(
      `UPDATE account_backups SET authorized_at = created_at,authorization_json = ?,
   authorization_snapshot_json = snapshot_json,calldata_sha256 = ?,authorized_auth_time = ? WHERE id = ?`,
    )
      .bind(wrong, fixtureHash('a'), f.principal.authTime, f.r.id)
      .run();
    await expect(f.repo().claim(f.r.id)).rejects.toMatchObject({ code: 'WALLET_DATA_INVALID' });
    expect((await stored(f.r.id))?.attempt_count).toBe(0);
  });
  it('backs off before sending with exactly the original call', async () => {
    const f = await authorized(),
      first = await claim(f);
    expect(await f.repo().retryBeforeSend(first)).toBe(true);
    expect(await f.repo().claim(f.r.id)).toBeNull();
    expect(await f.repo().due()).toEqual([]);
    at(deliveryNow() + 2);
    const second = await claim(f);
    expect(second.record.signed).toEqual(first.record.signed);
    await f.beginSend(second);
    expect(await f.repo().retryBeforeSend(second)).toBe(false);
  });
  it('caps pre-send attempts, then still expires the exhausted authorization', async () => {
    const f = await authorized();
    await env.WALLET_DB.prepare(
      'UPDATE account_backup_outbox SET attempt_count = 31 WHERE operation_id = ?',
    )
      .bind(f.r.id)
      .run();
    const last = await claim(f);
    await f.repo().retryBeforeSend(last);
    at(deliveryNow() + 31);
    expect(await f.repo().claim(f.r.id)).toBeNull();
    expect(await f.repo().due()).toEqual([]);
    at(f.p.valid_until);
    expect(await f.repo().due()).toEqual([f.r.id]);
    await f.repo().claim(f.r.id);
    expect((await stored(f.r.id))?.state).toBe('expired');
  });
  it.each(['disabled', 'cutoff', 'archived', 'network'] as const)(
    'rejects a %s grant before leasing',
    async (change) => {
      const f = await authorized();
      if (change === 'disabled')
        await env.WALLET_DB.prepare('UPDATE users SET disabled_at = ? WHERE id = ?')
          .bind(deliveryNow(), f.session.user_id)
          .run();
      if (change === 'cutoff')
        await env.WALLET_DB.prepare('UPDATE users SET auth_not_before = ? WHERE id = ?')
          .bind(f.principal.authTime + 1, f.session.user_id)
          .run();
      if (change === 'archived')
        await env.WALLET_DB.prepare("UPDATE wallets SET status = 'archived' WHERE id = ?")
          .bind(f.walletId)
          .run();
      if (change === 'network')
        await env.WALLET_DB.prepare(
          "UPDATE wallet_accounts SET deployment_state = 'needs_security_sync' WHERE address = ?",
        )
          .bind(f.prepared.account.toLowerCase())
          .run();
      await expect(f.repo().claim(f.r.id)).rejects.toThrow('BACKUP_GRANT_REVOKED');
      expect((await stored(f.r.id))?.attempt_count).toBe(0);
    },
  );
  it.each(['disabled', 'cutoff', 'key', 'archived', 'initialization'] as const)(
    'rechecks %s at the actual send boundary',
    async (change) => {
      const f = await authorized(),
        lease = await claim(f);
      if (change === 'disabled')
        await env.WALLET_DB.prepare('UPDATE users SET disabled_at = ? WHERE id = ?')
          .bind(deliveryNow(), f.session.user_id)
          .run();
      if (change === 'cutoff')
        await env.WALLET_DB.prepare('UPDATE users SET auth_not_before = ? WHERE id = ?')
          .bind(f.principal.authTime + 1, f.session.user_id)
          .run();
      if (change === 'key')
        await env.WALLET_DB.prepare('UPDATE webauthn_credentials SET public_key = ? WHERE id = ?')
          .bind(initializationFixture().input.publicKey, f.credentialRef)
          .run();
      if (change === 'archived')
        await env.WALLET_DB.prepare("UPDATE wallets SET status = 'archived' WHERE id = ?")
          .bind(f.walletId)
          .run();
      if (change === 'initialization')
        await env.WALLET_DB.prepare(
          "UPDATE account_initializations SET assertion_body = '{}' WHERE id = ?",
        )
          .bind(f.id)
          .run();
      expect(await f.beginSend(lease)).toBe(false);
      expect((await stored(f.r.id))?.state).toBe('pending');
    },
  );
  it('rejects another environment, missing profiles, wrong RP and unbounded sweeps', async () => {
    const f = await authorized();
    expect(
      () =>
        new BackupDeliveryRepository(env.WALLET_DB, {
          ...f.configuration,
          environment: 'unsupported' as never,
        }),
    ).toThrow();
    await expect(
      new BackupDeliveryRepository(env.WALLET_DB, { ...f.configuration, profiles: [] }).claim(
        f.r.id,
      ),
    ).rejects.toMatchObject({ code: 'PROFILE_UNAVAILABLE' });
    await expect(
      new BackupDeliveryRepository(env.WALLET_DB, {
        ...f.configuration,
        scope: { rpId: 'example.org', origin: 'https://example.org' },
      }).claim(f.r.id),
    ).rejects.toThrow();
    for (const n of [0, 51, 1.5, NaN]) await expect(f.repo().due(n)).rejects.toThrow();
    expect(await f.repo().due(1)).toEqual([f.r.id]);
  });
  it('does not swallow D1 failures after a send marker', async () => {
    const f = await authorized(),
      lease = await claim(f);
    await f.beginSend(lease);
    at(lease.until);
    await env.WALLET_DB.exec(
      "CREATE TRIGGER backup_fail_delivery BEFORE UPDATE ON account_backup_outbox BEGIN SELECT RAISE(ABORT, 'synthetic failure'); END;",
    );
    await expect(f.repo().claim(f.r.id)).rejects.toThrow();
    expect((await stored(f.r.id))?.state).toBe('sending');
    await env.WALLET_DB.exec('DROP TRIGGER backup_fail_delivery;');
    await f.repo().claim(f.r.id);
    expect((await stored(f.r.id))?.state).toBe('uncertain');
  });
  it('database constraints prevent identity replacement or reopening uncertain delivery', async () => {
    const f = await authorized();
    await expect(
      env.WALLET_DB.prepare(
        'UPDATE account_backup_outbox SET lease_token = ? WHERE operation_id = ?',
      )
        .bind(createResourceId('operation'), f.r.id)
        .run(),
    ).rejects.toThrow();
    await expect(
      env.WALLET_DB.prepare(
        'UPDATE account_backup_outbox SET lease_expires_at = ? WHERE operation_id = ?',
      )
        .bind(deliveryNow() + 30, f.r.id)
        .run(),
    ).rejects.toThrow();
    await expect(
      env.WALLET_DB.prepare(
        'UPDATE account_backup_outbox SET next_attempt_at = 1 WHERE operation_id = ?',
      )
        .bind(f.r.id)
        .run(),
    ).rejects.toThrow();
    const lease = await claim(f);
    await f.beginSend(lease);
    await f.repo().uncertain(lease);
    await expect(
      env.WALLET_DB.prepare(
        "UPDATE account_backup_outbox SET state = 'pending',send_started_at = NULL WHERE operation_id = ?",
      )
        .bind(f.r.id)
        .run(),
    ).rejects.toThrow();
    await expect(
      env.WALLET_DB.prepare(
        'UPDATE account_backup_outbox SET calldata_sha256 = ? WHERE operation_id = ?',
      )
        .bind(fixtureHash('5'), f.r.id)
        .run(),
    ).rejects.toThrow();
    await expect(
      env.WALLET_DB.prepare(
        'UPDATE account_backup_outbox SET expires_at = expires_at + 100 WHERE operation_id = ?',
      )
        .bind(f.r.id)
        .run(),
    ).rejects.toThrow();
  });
  it('a separately authorized commit gets its own exact call and job, not another prepare', async () => {
    const f = await backupCommitScenario(),
      id = createResourceId('operation'),
      p = await f.repository().prepareCommit(id, f.request.id, signal());
    const proof = f.f.assertion(p.commit_digest);
    expect(await count()).toBe(1);
    await f.repository().authorizeCommit(id, proof, signal());
    expect(await count()).toBe(2);
    const repo = new BackupDeliveryRepository(env.WALLET_DB, f.configuration),
      lease = await repo.claim(id);
    expect(lease?.record.signed).toEqual(
      authorizeBackupCommit(
        p.input,
        p.observation,
        p.valid_after,
        p.valid_until,
        proof,
        p.valid_after,
      ),
    );
    expect(await stored(id)).toMatchObject({
      kind: 'commit',
      backup_id: f.request.id,
      commit_id: id,
      state: 'pending',
    });
    await f.repository().authorizeCommit(id, proof, signal());
    expect(await count()).toBe(2);
  });
  it('a failed commit job insert rolls back ONLY the second authorization', async () => {
    const f = await backupCommitScenario(),
      id = createResourceId('operation'),
      p = await f.repository().prepareCommit(id, f.request.id, signal());
    await env.WALLET_DB.exec(
      "CREATE TRIGGER backup_fail_outbox BEFORE INSERT ON account_backup_outbox BEGIN SELECT RAISE(ABORT, 'synthetic failure'); END;",
    );
    await expect(
      f.repository().authorizeCommit(id, f.f.assertion(p.commit_digest), signal()),
    ).rejects.toThrow();
    expect((await f.repository().readCommit(id)).state).toBe('prepared');
    expect((await f.repository().read(f.request.id)).state).toBe('authorized');
    expect(await count()).toBe(1);
  });
});
