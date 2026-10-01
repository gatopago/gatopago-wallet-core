import { env } from 'cloudflare:workers';
import { applyD1Migrations } from 'cloudflare:test';
import { afterEach, beforeAll, beforeEach, describe, expect, it, vi } from 'vitest';
import { parseBackupPreview, parseBackupReceipt, parseBackupCommitPreview, parseBackupCommitReceipt } from '@gatopago/shared/v3/backup-wire';
import { createResourceId } from '@gatopago/shared/v3/primitives';
import { InitializationRepository } from '../src/creation/initialization';
import { backupScenario } from './backup.fixture';
import { backupCommitScenario } from './backupCommit.fixture';
import { cleanCreationDelivery } from './creationDelivery.fixture';

type Scenario = Awaited<ReturnType<typeof backupScenario>>;
async function selection(f: Pick<Scenario, 'principal' | 'configuration' | 'id' | 'credentialRef' | 'f'>, r: ReturnType<Scenario['request']>) {
 const initializations = new InitializationRepository(env.WALLET_DB, f.principal, f.configuration.scope, f.configuration.profiles);
 const preparation = await initializations.readPreparation(f.id);
 return { backupId: r.id, walletId: r.walletId, walletAccountId: r.walletAccountId, nextPolicy: r.nextPolicy,
  proposalValidUntil: r.proposalValidUntil, consent: { preparation,
   expected: { id: f.id, credentialRef: f.credentialRef, document: f.configuration.profiles[0].document,
    profileDigest: f.configuration.profiles[0].digest, userSaltCommitment: f.f.input.userSaltCommitment, scope: f.configuration.scope } } };
}
const signal = () => new AbortController().signal;
async function json(value: object) { return Response.json(value).json(); }
async function clean() {
 await env.WALLET_DB.exec('DELETE FROM account_backup_transactions; DELETE FROM account_backup_outbox; DELETE FROM account_backup_commits; DELETE FROM account_backups;');
 await cleanCreationDelivery();
}
beforeAll(async () => { await applyD1Migrations(env.WALLET_DB, env.V3_TEST_MIGRATIONS); });
// Advance expiry cases explicitly; host scheduling must not age signed fixtures.
beforeEach(async () => { await clean(); vi.spyOn(Date, 'now').mockReturnValue(Date.now()); });
afterEach(async () => { vi.restoreAllMocks(); vi.unstubAllGlobals(); await clean(); });

describe('Web backup decoder against real D1 repository responses (synthetic RPC)', () => {
 it('rebuilds actual prepare/read/authorization receipts without trusting returned configuration', async () => {
  const f = await backupScenario(), r = f.request(), chosen = await selection(f, r);
  const prepared = await f.repository().prepare(r, signal()), raw = await json(prepared);
  const review = parseBackupPreview(raw, chosen);
  expect(review.compiled.digest).toBe(prepared.proposal_hash);
  expect(review.compiled.initial.account).toBe(f.prepared.account);
  const receipt = await f.repository().authorize(r.id, f.f.assertion(review.compiled.digest), await f.proofs(review.input), signal());
  expect(parseBackupReceipt(await json(receipt), chosen, raw)).toEqual(receipt);
  f.fetch.mockClear();
  const restored = await json(await f.repository().read(r.id));
  expect(parseBackupPreview(restored, chosen).receipt.state).toBe('authorized');
  expect(f.fetch).not.toHaveBeenCalled();
  expect(new TextEncoder().encode(JSON.stringify(restored)).length).toBeLessThan(32768);
 });
 it('rebuilds a separate pending-proposal checkpoint and validates actual commit receipts', async () => {
  const f = await backupCommitScenario(), chosen = await selection(f, f.request), id = createResourceId('operation');
  const parent = await json(await f.repository().read(f.request.id));
  const prepared = await f.repository().prepareCommit(id, f.request.id, signal()), raw = await json(prepared);
  const review = parseBackupCommitPreview(raw, chosen, parent, id);
  expect(review.compiled.digest).toBe(prepared.commit_digest);
  const receipt = await f.repository().authorizeCommit(id, f.f.assertion(review.compiled.digest), signal());
  expect(parseBackupCommitReceipt(await json(receipt), chosen, parent, raw, id)).toEqual(receipt);
  expect(receipt.receive_enabled).toBe(false); expect(receipt.spend_enabled).toBe(false);
  f.fetch.mockClear();
  const restored = await json(await f.repository().readCommit(id));
  expect(parseBackupCommitPreview(restored, chosen, parent, id).receipt.state).toBe('authorized');
  expect(f.fetch).not.toHaveBeenCalled();
  expect(new TextEncoder().encode(JSON.stringify(restored)).length).toBeLessThan(32768);
 });
});
