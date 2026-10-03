import { applyD1Migrations } from 'cloudflare:test';
import { env } from 'cloudflare:workers';
import { beforeAll, beforeEach, afterEach, describe, expect, it, vi } from 'vitest';
import { MoneyRepository } from '../src/money/moneyRepository';
import { seedMoneyFixture } from './money.fixture';
import { writeMoneyDraft, writeMoneyReview } from '@gatopago/shared/v3/money-review-record';
import { writeAssertionRecord } from '@gatopago/shared/v3/assertion-record';
import { WalletAccessError } from '../src/accounts/repository';
import { createResourceId } from '@gatopago/shared/v3/primitives';
import { deploymentDocumentDigest } from '@gatopago/shared/v3/deployment';
import { moneyConfirmationDigest } from '../src/money/moneyWire';
import { writeExecutionOperationRecord } from '../src/execution/executionOperationRecord';

beforeAll(() => applyD1Migrations(env.WALLET_DB, env.V3_TEST_MIGRATIONS));
beforeEach(async () => {
  await env.WALLET_DB.exec(`DELETE FROM money_reconciliations; DELETE FROM money_finality_conflicts; DELETE FROM money_finality_journal; DELETE FROM money_expirations;
    DELETE FROM money_operations; DELETE FROM money_preparations; DELETE FROM user_operation_submissions;
    DELETE FROM transfer_reconciliations; DELETE FROM wallet_balance_floors; DELETE FROM transfer_finality_conflicts;
    DELETE FROM transfer_finality_journal; DELETE FROM transfer_nonce_reservations; DELETE FROM wallet_accounts;
    DELETE FROM wallets; DELETE FROM webauthn_credentials; DELETE FROM users;`);
});
afterEach(() => vi.restoreAllMocks());
const repository = (f: Awaited<ReturnType<typeof seedMoneyFixture>>) => new MoneyRepository(env.WALLET_DB, f.identity, f.keys.input.scope, f.pins);
function prepared(f: Awaited<ReturnType<typeof seedMoneyFixture>>) {
  return { candidate: f.candidate, review: f.review, send_enabled: false as const };
}
function authorized(f: Awaited<ReturnType<typeof seedMoneyFixture>>, preparationId: ReturnType<typeof createResourceId<'operation'>>) {
  const proofs = [{ signerIndex: 0, kind: 'webauthn' as const, assertion: f.keys.assertion(f.candidate.digest) }];
  const review = { ...f.review, approved_at: f.now, proofs }, record = writeMoneyReview(review);
  const fingerprint = moneyConfirmationDigest(preparationId, f.candidate.digest, proofs);
  // Synthetic current-head data only. RPC admission is covered separately.
  const fresh = { consent_digest: f.candidate.digest, userop_hash: f.candidate.userOpHash, record_sha256: record.digest,
    checkpoint: f.context.checkpoint, checked_at: f.now, expires_at: f.now + 5, security_version: '1',
    usdc_balance_atomic: '100000000', position_balance_atomic: '100000000', native_balance_atomic: '1000000', nonce: '0', send_enabled: false as const };
  return { review, fresh, fingerprint };
}
async function deliveryFixture() {
  const f = await seedMoneyFixture(env.WALLET_DB), repo = repository(f), draft = await repo.savePreparation(prepared(f), 'prepare');
  const signed = authorized(f, draft.id), stored = await repo.authorizeOperation(f.walletId, f.accountId, draft.id, signed.review, 'confirm', signed.fingerprint, signed.fresh);
  const c = stored.candidate, plan = c.plan;
  const payload = writeExecutionOperationRecord(stored.operation, { network_id: c.request.network_id, account: c.account,
    account_id: plan.accountId, entry_point: plan.entryPoint, userop_hash: c.userOpHash, consent_digest: c.digest, valid_until: plan.validUntil });
  const preflight = { ...signed.fresh, operation_id: stored.id, operation_sha256: payload.digest,
    simulation: { userop_hash: c.userOpHash, consent_digest: c.digest, operation_sha256: payload.digest,
      gas: { verificationGasLimit: '100', callGasLimit: '100', preVerificationGas: '100' }, observed_at: f.now,
      expires_at: f.now + 5, send_enabled: false as const } };
  return { f, repo, stored, preflight };
}
describe('Durable owner-bound money preparations in workerd', () => {
  it('stores a canonical review and restores its exact bytes without a send grant', async () => {
    const f = await seedMoneyFixture(env.WALLET_DB), stored = await repository(f).savePreparation(prepared(f), 'prepare-1');
    const encoded = writeMoneyDraft(f.review);
    expect(stored).toMatchObject({ state: 'prepared', record_json: encoded.json, record_sha256: encoded.digest, send_enabled: false });
    expect(stored.candidate.digest).toBe(f.candidate.digest);
    expect(await env.WALLET_DB.prepare('SELECT count(*) AS n FROM wallet_spend_locks').first()).toEqual({ n: 0 });
  });
  it('keeps one preparation across concurrent equal requests', async () => {
    const f = await seedMoneyFixture(env.WALLET_DB);
    const values = await Promise.all([repository(f).savePreparation(prepared(f), 'same-key'), repository(f).savePreparation(prepared(f), 'same-key')]);
    expect(values[0].id).toBe(values[1].id);
    expect(await env.WALLET_DB.prepare('SELECT count(*) AS n FROM money_preparations').first()).toEqual({ n: 1 });
  });
  it('retains the expired result for an idempotency key and rejects another request under that key', async () => {
    const f = await seedMoneyFixture(env.WALLET_DB), stored = await repository(f).savePreparation(prepared(f), 'expired-key');
    vi.spyOn(Date, 'now').mockReturnValue((f.context.valid_until + 1) * 1000);
    const prior = await repository(f).findPreparation(f.walletId, f.accountId, 'expired-key', f.request);
    expect(prior).toMatchObject({ id: stored.id, state: 'expired_unsigned', send_enabled: false });
    await expect(repository(f).findPreparation(f.walletId, f.accountId, 'expired-key', { ...f.request, amount_atomic: '1' })).rejects.toThrow('MONEY_IDEMPOTENCY_CONFLICT');
  });
  it('does not accept an extra field or invalid key as another spelling of the same request', async () => {
    const f = await seedMoneyFixture(env.WALLET_DB);
    await expect(repository(f).findPreparation(f.walletId, f.accountId, 'bad key', f.request)).rejects.toThrow('MONEY_IDEMPOTENCY_KEY_INVALID');
    await expect(repository(f).findPreparation(f.walletId, f.accountId, 'key', { ...f.request, calls: [] })).rejects.toThrow();
    expect(await env.WALLET_DB.prepare('SELECT count(*) AS n FROM money_preparations').first()).toEqual({ n: 0 });
  });
  it('rejects foreign ownership and revoked credentials without exposing stored reviews', async () => {
    const f = await seedMoneyFixture(env.WALLET_DB), stored = await repository(f).savePreparation(prepared(f), 'owned');
    await expect(repository(f).readPreparation(createResourceId('wallet'), f.accountId, stored.id)).rejects.toBeInstanceOf(WalletAccessError);
    await env.WALLET_DB.prepare('UPDATE webauthn_credentials SET revoked_at = ? WHERE id = ?').bind(f.now, f.identity.credentialRef).run();
    await expect(repository(f).readPreparation(f.walletId, f.accountId, stored.id)).rejects.toBeInstanceOf(WalletAccessError);
  });
  it('rejects a stored review replaced with a differently scoped but checksummed record', async () => {
    const f = await seedMoneyFixture(env.WALLET_DB), stored = await repository(f).savePreparation(prepared(f), 'scope');
    const alternate = { ...f.review, scope: { rpId: 'evil.example', origin: 'https://evil.example' } };
    const encoded = writeMoneyDraft(alternate);
    // Drop the immutability guard only inside this synthetic corruption test.
    await env.WALLET_DB.exec('DROP TRIGGER money_preparation_immutable');
    try {
      await env.WALLET_DB.prepare('UPDATE money_preparations SET review_json = ?,review_sha256 = ? WHERE id = ?').bind(encoded.json, encoded.digest, stored.id).run();
      await expect(repository(f).readPreparation(f.walletId, f.accountId, stored.id)).rejects.toThrow('MONEY_REVIEW_MISMATCH');
    } finally {
      await env.WALLET_DB.exec("CREATE TRIGGER money_preparation_immutable BEFORE UPDATE ON money_preparations BEGIN SELECT RAISE(ABORT, 'immutable money preparation'); END");
    }
  });
  it('does not consider an assertion or a replacement checksum a dispatch grant', async () => {
    const f = await seedMoneyFixture(env.WALLET_DB), assertion = writeAssertionRecord(f.keys.assertion(f.candidate.digest));
    expect(deploymentDocumentDigest(JSON.stringify(assertion))).toMatch(/^0x[0-9a-f]{64}$/);
    await repository(f).savePreparation(prepared(f), 'unsigned');
    expect(await env.WALLET_DB.prepare('SELECT count(*) AS n FROM money_operations').first()).toEqual({ n: 0 });
    expect(await env.WALLET_DB.prepare('SELECT count(*) AS n FROM money_jobs').first()).toEqual({ n: 0 });
  });
  it('verifies an ephemeral P256 signature and reserves without broadcasting or creating a delivery job', async () => {
    const f = await seedMoneyFixture(env.WALLET_DB), draft = await repository(f).savePreparation(prepared(f), 'prepare');
    const signed = authorized(f, draft.id), stored = await repository(f).authorizeOperation(f.walletId, f.accountId, draft.id, signed.review, 'confirm', signed.fingerprint, signed.fresh);
    expect(stored).toMatchObject({ state: 'authorized', preparation_id: draft.id, send_enabled: false });
    expect(stored.operation.signature).not.toBe('0x');
    expect(await env.WALLET_DB.prepare('SELECT domain,state FROM wallet_spend_locks').first()).toEqual({ domain: 'money', state: 'held' });
    expect(await env.WALLET_DB.prepare('SELECT count(*) AS n FROM money_jobs').first()).toEqual({ n: 0 });
    expect(await env.WALLET_DB.prepare('SELECT count(*) AS n FROM user_operation_submissions').first()).toEqual({ n: 0 });
    const restarted = await repository(f).readOperation(f.walletId, f.accountId, stored.id);
    expect(restarted.operation).toEqual(stored.operation);
  });
  it('keeps the original signature and ID across concurrent duplicate confirmations', async () => {
    const f = await seedMoneyFixture(env.WALLET_DB), draft = await repository(f).savePreparation(prepared(f), 'prepare'), signed = authorized(f, draft.id);
    const confirm = () => repository(f).authorizeOperation(f.walletId, f.accountId, draft.id, signed.review, 'confirm', signed.fingerprint, signed.fresh);
    const [a, b] = await Promise.all([confirm(), confirm()]);
    expect(a.id).toBe(b.id); expect(a.operation.signature).toBe(b.operation.signature);
    expect(await env.WALLET_DB.prepare('SELECT count(*) AS n FROM money_operations').first()).toEqual({ n: 1 });
    await expect(repository(f).findConfirmation(f.walletId, f.accountId, 'confirm', f.hash)).rejects.toThrow('MONEY_IDEMPOTENCY_CONFLICT');
  });
  it('rejects an invalid signature before writing an operation or acquiring a lock', async () => {
    const f = await seedMoneyFixture(env.WALLET_DB), draft = await repository(f).savePreparation(prepared(f), 'prepare'), signed = authorized(f, draft.id);
    signed.review.proofs[0].assertion.signatureDER[20] ^= 1;
    signed.fresh.record_sha256 = writeMoneyReview(signed.review).digest;
    await expect(repository(f).authorizeOperation(f.walletId, f.accountId, draft.id, signed.review, 'confirm', signed.fingerprint, signed.fresh)).rejects.toThrow();
    expect(await env.WALLET_DB.prepare('SELECT count(*) AS n FROM wallet_spend_locks').first()).toEqual({ n: 0 });
  });
  it('cannot use a stale current-head result as a reservation grant', async () => {
    const f = await seedMoneyFixture(env.WALLET_DB), draft = await repository(f).savePreparation(prepared(f), 'prepare'), signed = authorized(f, draft.id);
    vi.spyOn(Date, 'now').mockReturnValue((f.now + 5) * 1000);
    await expect(repository(f).authorizeOperation(f.walletId, f.accountId, draft.id, signed.review, 'confirm', signed.fingerprint, signed.fresh)).rejects.toThrow('MONEY_CONFIRMATION_CHANGED');
    expect(await env.WALLET_DB.prepare('SELECT count(*) AS n FROM money_operations').first()).toEqual({ n: 0 });
  });
  it('has one durable delivery winner with its job and dispatch lock before a send', async () => {
    const { f, repo, stored, preflight } = await deliveryFixture();
    // Concurrent readers can detect a changed row and reject. Regardless, only
    // one UPDATE may create a send grant; all other outcomes are historical.
    const outcomes = await Promise.allSettled([repo.beginDelivery(f.walletId, f.accountId, stored.id, preflight),
      repository(f).beginDelivery(f.walletId, f.accountId, stored.id, preflight)]);
    expect(outcomes.filter(r => r.status === 'fulfilled' && r.value.won), JSON.stringify(outcomes.map(r => r.status === 'rejected'
      ? { error: r.reason instanceof Error ? r.reason.message : 'unknown' } : { won: r.value.won }))).toHaveLength(1);
    expect(await env.WALLET_DB.prepare('SELECT state FROM money_operations').first()).toEqual({ state: 'dispatch_pending' });
    expect(await env.WALLET_DB.prepare('SELECT state FROM wallet_spend_locks').first()).toEqual({ state: 'dispatch_pending' });
    expect(await env.WALLET_DB.prepare('SELECT state,failures FROM money_jobs').first()).toEqual({ state: 'ready', failures: 0 });
    expect(await env.WALLET_DB.prepare('SELECT count(*) AS n FROM user_operation_submissions').first()).toEqual({ n: 0 });
    expect(await repository(f).beginDelivery(f.walletId, f.accountId, stored.id, preflight)).toMatchObject({ won: false });
  });
  it.each(['signature-bytes', 'stale-simulation', 'changed-version', 'revoked-session', 'stale-floor'])(
    'does not dispatch with %s', async fault => {
      const { f, repo, stored, preflight } = await deliveryFixture();
      if (fault === 'signature-bytes') preflight.simulation.operation_sha256 = f.hash;
      if (fault === 'stale-simulation') preflight.simulation.expires_at = f.now;
      if (fault === 'changed-version') preflight.security_version = '2';
      if (fault === 'revoked-session') await env.WALLET_DB.prepare('UPDATE webauthn_credentials SET revoked_at = ? WHERE id = ?').bind(f.now, f.identity.credentialRef).run();
      if (fault === 'stale-floor') await env.WALLET_DB.prepare('INSERT INTO wallet_balance_floors VALUES (?,?,?,?)')
        .bind(f.accountId, (BigInt(preflight.checkpoint.block_number) + 1n).toString(), f.hash, f.now).run();
      await expect(repo.beginDelivery(f.walletId, f.accountId, stored.id, preflight)).rejects.toThrow();
      expect(await env.WALLET_DB.prepare('SELECT state FROM money_operations').first()).toEqual({ state: 'authorized' });
      expect(await env.WALLET_DB.prepare('SELECT state FROM wallet_spend_locks').first()).toEqual({ state: 'held' });
      expect(await env.WALLET_DB.prepare('SELECT count(*) AS n FROM money_jobs').first()).toEqual({ n: 0 });
    });
});
