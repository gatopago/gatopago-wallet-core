import { applyD1Migrations } from 'cloudflare:test';
import { env } from 'cloudflare:workers';
import { afterEach, beforeAll, beforeEach, describe, expect, it, vi } from 'vitest';
import * as accountInspection from '@gatopago/shared/v3/account-inspection';
import * as finality from '@gatopago/shared/v3/finality';
import {
  deploymentDocumentDigest,
  loadPinnedDeploymentManifest,
} from '@gatopago/shared/v3/deployment';
import * as runtimeFinality from '../src/runtime/finality';
import * as nonceReader from '../src/transfers/transferNonce';
import { expiredMoneyCandidates, expireUnsubmittedMoney } from '../src/money/moneyExpiration';
import { seedMoneyDelivery } from './moneyDelivery.fixture';

beforeAll(() => applyD1Migrations(env.WALLET_DB, env.V3_TEST_MIGRATIONS));
beforeEach(async () => {
  await env.WALLET_DB
    .exec(`DELETE FROM money_reconciliations; DELETE FROM money_finality_conflicts; DELETE FROM money_finality_journal; DELETE FROM money_expirations;
    DELETE FROM money_operations; DELETE FROM money_preparations; DELETE FROM user_operation_submissions;
    DELETE FROM transfer_reconciliations; DELETE FROM wallet_balance_floors; DELETE FROM transfer_finality_conflicts;
    DELETE FROM transfer_finality_journal; DELETE FROM transfer_nonce_reservations; DELETE FROM wallet_accounts;
    DELETE FROM wallets; DELETE FROM webauthn_credentials; DELETE FROM users;`);
});
afterEach(() => vi.restoreAllMocks());
async function fixture(expired = true) {
  const realNow = Date.now();
  const clock = vi.spyOn(Date, 'now').mockReturnValue(expired ? realNow - 90_000 : realNow);
  const s = await seedMoneyDelivery(env.WALLET_DB, false, expired);
  clock.mockRestore();
  const now = Math.floor(Date.now() / 1000),
    c = s.stored.candidate;
  const block = {
    block_hash: s.f.hash,
    block_number: (BigInt(c.checkpoint.block_number) + 100n).toString(),
    block_timestamp: String(now - 1),
  };
  const evidence: finality.FinalityAssessment = {
    schema_version: 1,
    status: 'finalized',
    policy_sha256: s.profile.finalityPolicy.digest,
    mechanism: 'arbitrum_l1_data_finalized',
    network_id: c.request.network_id,
    genesis_hash: s.market.genesis_hash,
    target: block,
    checkpoint: block,
    assessed_at: now,
    expires_at: now + 10,
  };
  const manifest = loadPinnedDeploymentManifest(s.profile.document, s.profile.digest);
  const recognized: Awaited<ReturnType<typeof accountInspection.inspectAccountDeployment>> = {
    status: 'recognized',
    account: c.account,
    account_id: c.plan.accountId,
    network_id: c.request.network_id,
    manifest_id: manifest.manifest_id,
    manifest_sha256: s.profile.digest,
    checkpoint: { block_number: block.block_number, block_hash: block.block_hash },
    spend_readiness: 'not_assessed',
    implementation: manifest.components.implementation.address,
    security_version: '1',
    storage_layout_hash: manifest.storage_layout_hash,
  };
  const source = vi.spyOn(runtimeFinality, 'networkFinality').mockResolvedValue(evidence);
  const account = vi
    .spyOn(accountInspection, 'inspectAccountDeployment')
    .mockResolvedValue(recognized);
  const sequence = vi
    .spyOn(nonceReader, 'observeTransferNonce')
    .mockResolvedValue({
      network_id: c.request.network_id,
      account: c.account,
      entry_point: c.plan.entryPoint,
      checkpoint: recognized.checkpoint,
      nonce: '0',
      observed_at: now,
    });
  const closing = vi.spyOn(finality, 'assessCheckpointFinality').mockResolvedValue(evidence);
  return {
    ...s,
    now,
    block,
    evidence,
    source,
    account,
    recognized,
    sequence,
    closing,
    run: () =>
      expireUnsubmittedMoney(
        env.WALLET_DB,
        'production',
        s.stored.id,
        [s.profile],
        new AbortController().signal,
      ),
  };
}
const lock = () =>
  env.WALLET_DB.prepare('SELECT state,release_reason FROM wallet_spend_locks').first();

describe('Never-dispatched monetary expiry with finalized nonce proof', () => {
  it('atomically saves proof and releases once; a repeated sweep is inert', async () => {
    const s = await fixture();
    expect(
      await expiredMoneyCandidates(env.WALLET_DB, {
        environment: 'production',
        profiles: [s.profile],
      }),
    ).toEqual([s.stored.id]);
    expect(await s.run()).toEqual({ state: 'expired_unsubmitted' });
    expect(await lock()).toEqual({ state: 'released', release_reason: 'expired_unsubmitted' });
    const row = await env.WALLET_DB.prepare('SELECT * FROM money_expirations').first();
    expect(row?.checkpoint_sha256).toBe(deploymentDocumentDigest(String(row?.checkpoint_json)));
    expect(JSON.parse(String(row?.checkpoint_json))).toMatchObject({
      userop_hash: s.stored.candidate.userOpHash,
      nonce: '0',
      checkpoint: s.block,
    });
    expect(await s.run()).toEqual({ state: 'unchanged' });
    expect(s.source).toHaveBeenCalledTimes(1);
  });
  it('retains proof obligations after disabling the login and new recipes', async () => {
    const s = await fixture();
    await env.WALLET_DB.prepare('UPDATE users SET disabled_at = ?,auth_not_before = ?')
      .bind(s.now, s.now)
      .run();
    const profile = {
      ...s.profile,
      features: { aave_supply: false, aave_withdraw: false, aave_withdraw_and_pay: false },
    };
    expect(
      await expireUnsubmittedMoney(
        env.WALLET_DB,
        'production',
        s.stored.id,
        [profile],
        new AbortController().signal,
      ),
    ).toEqual({ state: 'expired_unsubmitted' });
  });
  it.each(['not-expired', 'dispatched', 'journaled', 'wrong-environment', 'empty-scope'])(
    'does not inspect or release %s',
    async (fault) => {
      const s = await fixture(fault !== 'not-expired');
      if (fault === 'dispatched')
        await env.WALLET_DB.prepare(
          "UPDATE money_operations SET state = 'dispatch_pending',dispatch_started_at = ?",
        )
          .bind(s.f.now + 1)
          .run();
      if (fault === 'journaled')
        await env.WALLET_DB.prepare(
          `INSERT INTO user_operation_submissions(user_op_hash,payload_hash,kind,endpoint,network_id,valid_until)
      VALUES (?,?,'bundler','https://bundler.example/rpc','eip155:421614',?)`,
        )
          .bind(s.stored.candidate.userOpHash, s.f.hash, s.stored.candidate.plan.validUntil)
          .run();
      if (fault === 'wrong-environment')
        await expect(
          Reflect.apply(expireUnsubmittedMoney, null, [
            env.WALLET_DB,
            'staging',
            s.stored.id,
            [s.profile],
            new AbortController().signal,
          ]),
        ).rejects.toThrow();
      else if (fault === 'empty-scope')
        await expect(
          expireUnsubmittedMoney(
            env.WALLET_DB,
            'production',
            s.stored.id,
            [],
            new AbortController().signal,
          ),
        ).rejects.toThrow();
      else expect(await s.run()).toEqual({ state: 'unchanged' });
      expect(s.source).not.toHaveBeenCalled();
      expect((await lock())?.state).not.toBe('released');
    },
  );
  it('waits until the finalized timestamp exceeds the inclusive validity bound', async () => {
    const s = await fixture(),
      atBound = { ...s.block, block_timestamp: String(s.stored.candidate.plan.validUntil) };
    s.source.mockResolvedValue({ ...s.evidence, target: atBound, checkpoint: atBound });
    expect(await s.run()).toEqual({ state: 'waiting' });
    expect(s.sequence).not.toHaveBeenCalled();
    expect((await lock())?.state).toBe('held');
  });
  it.each([
    'changed-nonce',
    'unknown-account',
    'account-disagreement',
    'pending-closing',
    'stale-closing',
    'wrong-policy',
    'dispatch-race',
    'abort',
  ])('preserves the reservation with %s', async (fault) => {
    const s = await fixture();
    if (fault === 'changed-nonce')
      s.sequence.mockResolvedValue({
        network_id: s.stored.candidate.request.network_id,
        account: s.stored.candidate.account,
        entry_point: s.stored.candidate.plan.entryPoint,
        checkpoint: s.recognized.checkpoint,
        nonce: '1',
        observed_at: s.now,
      });
    if (fault === 'unknown-account') s.account.mockRejectedValue(new Error('unexpected code'));
    if (fault === 'account-disagreement')
      s.account.mockResolvedValueOnce({ ...s.recognized, security_version: '2' });
    if (fault === 'pending-closing')
      s.closing.mockResolvedValue({
        ...s.evidence,
        status: 'pending',
        checkpoint: { ...s.block, block_number: '1', block_timestamp: '1' },
      });
    if (fault === 'stale-closing')
      s.closing.mockResolvedValue({
        ...s.evidence,
        assessed_at: s.now - 20,
        expires_at: s.now - 10,
      });
    if (fault === 'wrong-policy')
      s.closing.mockResolvedValue({ ...s.evidence, policy_sha256: s.f.hash });
    if (fault === 'dispatch-race')
      s.closing.mockImplementation(async () => {
        await env.WALLET_DB.prepare(
          "UPDATE money_operations SET state = 'dispatch_pending',dispatch_started_at = ?",
        )
          .bind(s.f.now + 1)
          .run();
        return s.evidence;
      });
    if (fault === 'abort')
      await expect(
        expireUnsubmittedMoney(
          env.WALLET_DB,
          'production',
          s.stored.id,
          [s.profile],
          AbortSignal.abort(),
        ),
      ).rejects.toThrow();
    else
      await expect(s.run()).rejects.toThrow(
        fault === 'unknown-account'
          ? 'unexpected code'
          : fault === 'dispatch-race'
            ? 'MONEY_HISTORY_UNAVAILABLE'
            : ['changed-nonce', 'account-disagreement'].includes(fault)
              ? 'MONEY_EXPIRATION_NONCE_OR_ACCOUNT'
              : 'MONEY_EXPIRATION_CHANGED',
      );
    expect((await lock())?.state).not.toBe('released');
    expect(
      await env.WALLET_DB.prepare('SELECT count(*) AS n FROM money_expirations').first(),
    ).toEqual({ n: 0 });
  });
});
