import { testPrincipal } from './principal.fixture';
import { seedUser } from './user.fixture';
import { sponsorshipData } from '@gatopago/shared/v3/paymaster';
import { env } from 'cloudflare:workers';
import { applyD1Migrations, createMessageBatch, createExecutionContext, getQueueResult } from 'cloudflare:test';
import { afterEach, beforeAll, beforeEach, describe, expect, it, vi } from 'vitest';
import { createResourceId } from '@gatopago/shared/v3/primitives';
import { authorizeTransferOperation } from '@gatopago/shared/v3/transfer-authorization';
import { prepareTransferOperation } from '@gatopago/shared/v3/transfer-operation';
import { deploymentDocumentDigest } from '@gatopago/shared/v3/deployment';
import { transferFixture } from '@gatopago/test-fixtures/v3-transfer';
import type { Principal } from '../src/auth/principal';
import { WalletRepository } from '../src/accounts/repository';
import { TransferNonceReservationRepository } from '../src/transfers/transferNonceReservation';
import { observeOwnedTransferDelivery, type TransferDeliveryProfile } from '../src/transfers/transferDeliveryObservation';
import * as finalityReader from '@gatopago/shared/v3/finality';
import * as securityReader from '../src/accounts/inspection';
import * as balanceReader from '../src/portfolio/balances';
import * as nonceReader from '../src/transfers/transferNonce';
import * as deliveryReader from '../src/transfers/transferDeliveryObservation';
import * as simulationReader from '../src/transfers/transferSimulation';
import { preflightOwnedTransfer, type TransferPreflightProfile } from '../src/transfers/transferPreflight';
import { writeTransferOperationRecord } from '../src/transfers/transferOperationRecord';
import * as preflightReader from '../src/transfers/transferPreflight';
import { deliverOwnedTransfer } from '../src/transfers/transferDelivery';
import { formatUserOperationRequest } from 'viem/account-abstraction';
import { observeOwnedTransfer, observeTransferJob } from '../src/transfers/transferObservation';
import * as receiptReader from '../src/transfers/transferReceiptObservation';
import * as transferObserver from '../src/transfers/transferObservation';
import { recordOwnedTransferFinality } from '../src/transfers/transferReconciliation';
import { readOwnedTransferStatus } from '../src/transfers/transferStatus';
import { walletReadRoute } from '../src/accounts/route';
import * as sessionVerifier from '../src/auth/session';
import manifests from '@gatopago/environment/environments.json';
import { parseEnvironment } from '@gatopago/environment';
import { observeTransferReconciliationBalance } from '../src/transfers/transferBalanceReconciliation';
import { reconcileOwnedTransfer } from '../src/transfers/transferReconciliationCommit';
import { TransferJobRepository, parseTransferWake, type TransferWake } from '../src/transfers/transferJobs';
import { recordTransferJobFinality } from '../src/transfers/transferJobFinality';
import { reconcileTransferJob } from '../src/transfers/transferJobReconciliation';
import { createTransferJobHandlers } from '../src/transfers/transferJobHandlers';
import { prepareOwnedTransfer, type TransferPreparationTerms } from '../src/transfers/transferPreparation';
import { TransferPreparationRepository } from '../src/transfers/transferPreparations';
import { confirmOwnedTransfer } from '../src/transfers/transferConfirmation';
import * as chainReader from '../src/chainInspection';
import * as rawBalanceReader from '../src/portfolio/balanceObservation';
import * as preparationCoordinator from '../src/transfers/transferPreparation';
import * as confirmationCoordinator from '../src/transfers/transferConfirmation';
import * as deliveryCoordinator from '../src/transfers/transferDelivery';
import { createTransferRoute } from '../src/transfers/transferRoute';
import { CLIENT_RELEASE_HEADERS, clientMutationHeaders, WALLET_RELEASE_POLICY } from '@gatopago/shared/v3/client-release';

beforeAll(() => applyD1Migrations(env.WALLET_DB, env.V3_TEST_MIGRATIONS));
beforeEach(async () => {
  // Ephemeral test binding only. No remote resources or user accounts.
  await env.WALLET_DB.exec(`DELETE FROM user_operation_submissions; DELETE FROM transfer_reconciliations; DELETE FROM wallet_balance_floors; DELETE FROM transfer_finality_conflicts; DELETE FROM transfer_finality_journal; DELETE FROM transfer_nonce_reservations; DELETE FROM wallet_accounts;
    DELETE FROM wallets; DELETE FROM webauthn_credentials; DELETE FROM users;`);
});
afterEach(async () => {
  vi.restoreAllMocks(); vi.unstubAllGlobals();
  await env.WALLET_DB.exec('DROP TRIGGER IF EXISTS transfer_job_test_failure');
});

async function setup(native = true) {
  const f = transferFixture(native);
  const clock = vi.spyOn(Date, 'now').mockReturnValue((f.now + 1) * 1000);
  const identity: Principal = testPrincipal('owner', { environment: 'staging' });
  const session = await seedUser(env.WALLET_DB, identity);
  const accountId = createResourceId('walletAccount');
  await env.WALLET_DB.batch([
    env.WALLET_DB.prepare(`INSERT INTO wallets(id,user_id,status,account_id,initial_security_commitment,user_salt_commitment,canonical_address,created_at)
      VALUES (?,?,'active',?,?,?,?,?)`).bind(f.request.wallet_id, session.user_id, f.context.account_id,
        f.f.initial.message.initialSecurityCommitment, f.f.initial.message.userSaltCommitment, f.context.account.toLowerCase(), f.now),
    env.WALLET_DB.prepare(`INSERT INTO wallet_accounts(id,wallet_id,network_id,address,deployment_manifest_sha256,deployment_state,created_at)
      VALUES (?,?,?,?,?,'active',?)`).bind(accountId, f.request.wallet_id, f.request.network_id,
        f.context.account.toLowerCase(), f.context.deployment_digest, f.now),
  ]);
  async function signed(amount = '10', expires = f.context.valid_until, options: {
    nonce?: bigint; max?: boolean; reserved?: { asset_id: string; amount_atomic: string }[];
  } = {}) {
    const request = { ...f.request, amount: options.max ? { kind: 'max' as const } : { kind: 'exact' as const, amount_atomic: amount } };
    const reserved = options.reserved ?? f.approval.balance_evidence.reserved;
    const available = (id: string) => (10000n - BigInt(reserved.find(row => row.asset_id === id)!.amount_atomic)).toString();
    const context = { ...f.context, valid_until: expires, nonce: options.nonce ?? f.context.nonce,
      budget: { ...f.context.budget, asset_available_atomic: available(request.asset_id), native_available_atomic: available(f.context.native_asset_id) } };
    const p = prepareTransferOperation(request, context, f.now);
    return authorizeTransferOperation(request, context, { ...f.approval, reviewed_digest: p.digest,
      balance_evidence: { ...f.approval.balance_evidence, reserved }, nonce_evidence: { ...f.approval.nonce_evidence, nonce: context.nonce.toString() } },
      await f.proofs(p.digest), () => Math.floor(Date.now() / 1000));
  }
  const repository = () => new TransferNonceReservationRepository(env.WALLET_DB, identity);
  return { f, clock, identity, session, accountId, signed, repository };
}
const rows = () => env.WALLET_DB.prepare('SELECT * FROM transfer_nonce_reservations ORDER BY created_at,id').all();

async function deliveryProof(s: Awaited<ReturnType<typeof setup>>, a: Awaited<ReturnType<Awaited<ReturnType<typeof setup>>['signed']>>,
  id: ReturnType<typeof createResourceId<'operation'>>) {
  const snapshot = await s.repository().deliveryFundsSnapshot(a.request.wallet_id, s.accountId, id);
  const payload = writeTransferOperationRecord(a.operation, { network_id: a.request.network_id, account: a.account,
    account_id: a.plan.accountId, entry_point: a.plan.entryPoint, userop_hash: a.userOpHash, consent_digest: a.digest, valid_until: a.plan.validUntil });
  return { operation_id: id, userop_hash: a.userOpHash, consent_digest: a.digest, checked_at: snapshot.observed_at,
    expires_at: snapshot.expires_at, reservation_fingerprint: snapshot.fingerprint, reservation_observed_at: snapshot.observed_at,
    simulation: { userop_hash: a.userOpHash, consent_digest: a.digest, operation_sha256: payload.digest,
      observed_at: snapshot.observed_at, expires_at: snapshot.expires_at } };
}

describe('V3 pre-delivery nonce reservation with real D1', () => {
  it.each(['prepare', 'read', 'confirm', 'deliver', 'origin', 'method', 'query', 'version', 'wallet', 'extra-fields',
    'too-large', 'foreign', 'disabled-network', 'no-profile', 'options', 'bad-cors', 'asset', 'delivery-digest', 'confirm-release', 'deliver-release'])(
    'enforces the authenticated transfer HTTP boundary: %s', async scenario => {
      const s = await setup(), f = s.f;
      const config = parseEnvironment({ ...manifests.staging, status: 'provisioned', firebase_project_id: 'v3-runtime-test',
        wallet_enabled: scenario === 'disabled-network' ? [] : [f.request.network_id] });
      // Session admission is exercised with real JWT/WebAuthn/RPC in access.test.ts.
      vi.spyOn(sessionVerifier, 'verifyAppSession').mockResolvedValue(scenario === 'foreign' ? { ...s.identity, userId: 'other' } : s.identity);
      const prepared = { candidate: f.p, context: f.context, approval: f.approval, wallet_account_id: s.accountId, send_enabled: false as const };
      const saved = await new TransferPreparationRepository(env.WALLET_DB, s.identity, f.approval.scope, [f.context.deployment_digest]).save(prepared);
      const authorization = await s.signed(), held = await s.repository().reserve(s.accountId, authorization);
      const root = `/app/v1/wallets/${f.request.wallet_id}/accounts/${s.accountId}`;
      const otherAsset = `${f.request.network_id}/erc20:0x${'ab'.repeat(20)}`;
      const profile = { environment: 'staging' as const, document: f.approval.security_evidence.document,
        digest: f.context.deployment_digest, finalityPolicy: f.approval.security_evidence.finality_policy,
        entryPointCodeHash: `0x${'ee'.repeat(32)}` as const, transport: { kind: 'bundler' as const, url: 'https://bundler.example/rpc' },
        providers: [{ operatorId: 'provider-a', url: 'https://a.example/rpc' }, { operatorId: 'provider-b', url: 'https://b.example/rpc' }],
        assetIds: [f.request.asset_id, otherAsset], assetDisplay: { [f.request.asset_id]: { symbol: 'ETH', decimals: 18 }, [otherAsset]: { symbol: 'USDC', decimals: 6 } } };
      const account = { generation: '3', contract_manifest_version: f.f.initial.profile.deployment.manifest_id };
      const resolve = vi.fn(async () => ({ finalityEvidence: f.approval.security_evidence.finality, terms: {
        request: f.request, wallet_account_id: s.accountId, deployment_digest: f.context.deployment_digest,
        native_asset_id: f.context.native_asset_id, gas: f.context.gas, maximum_native_gas_atomic: '1000',
        platform_fee: f.context.budget.platform_fee, fee_recipient: null, observed_at: f.now, expires_at: f.now + 20 } }));
      const route = createTransferRoute({ profiles: scenario === 'no-profile' ? [] : [profile], resolvePreparation: resolve,
        releasePolicy: { ...WALLET_RELEASE_POLICY, releases: [{ client_release_id: 'v3-test', accepted_until: null },
          { client_release_id: 'v3-other', accepted_until: null }], account_profiles: [account] } });
      const prepareSpy = vi.spyOn(preparationCoordinator, 'prepareOwnedTransfer').mockResolvedValue(prepared);
      const confirmSpy = vi.spyOn(confirmationCoordinator, 'confirmOwnedTransfer').mockResolvedValue({ ...held, preparation_id: saved.id, consent_digest: f.p.digest });
      const deliverSpy = vi.spyOn(deliveryCoordinator, 'deliverOwnedTransfer').mockResolvedValue({ operation_id: held.id,
        userop_hash: f.p.userOpHash, delivery: 'accepted', settlement: 'unconfirmed' });
      let path = `${root}/transfer-preparations`, method = 'POST';
      let body: unknown = scenario === 'wallet' ? { ...f.request, wallet_id: createResourceId('wallet') }
        : scenario === 'extra-fields' ? { ...f.request, balance: '1000000000' }
          : scenario === 'asset' ? { ...f.request, asset_id: `${f.request.network_id}/erc20:0x${'cc'.repeat(20)}` } : f.request;
      if (scenario === 'read') { path += `/${saved.id}`; method = 'GET'; }
      if (scenario.startsWith('confirm')) {
        path += `/${saved.id}/confirm`;
        body = { consent_digest: f.p.digest, proofs: (await f.proofs()).map(p => p.kind === 'ecdsa'
          ? { signer_index: p.signerIndex, kind: p.kind, signature: p.signature }
          : { signer_index: p.signerIndex, kind: p.kind, assertion: { authenticator_data: Buffer.from(p.assertion.authenticatorData).toString('base64url'),
            client_data: Buffer.from(p.assertion.clientDataJSON).toString('base64url'), signature: Buffer.from(p.assertion.signatureDER).toString('base64url') } }) };
      }
      if (scenario.startsWith('deliver')) { path = `${root}/transfers/${held.id}/deliver`; body = { consent_digest: scenario === 'delivery-digest' ? `0x${'ee'.repeat(32)}` : f.p.digest }; }
      if (scenario === 'method') method = 'GET';
      if (scenario === 'options' || scenario === 'bad-cors') method = 'OPTIONS';
      const headers = new Headers({ Origin: scenario === 'origin' ? 'https://wrong.example' : config.web_origin,
        'Content-Type': 'application/json', Authorization: 'Bearer synthetic', ...clientMutationHeaders('staging', account),
        'Access-Control-Request-Method': 'POST', 'Access-Control-Request-Headers': scenario === 'bad-cors' ? 'X-Untrusted' : 'Authorization, Content-Type' });
      headers.set(CLIENT_RELEASE_HEADERS.release, scenario === 'version' ? 'outdated' : scenario.endsWith('-release') ? 'v3-other' : 'v3-test');
      const response = await route(new Request(`${config.api_origin}${path}${scenario === 'query' ? '?rpc=override' : ''}`, { method, headers,
        ...(method === 'POST' ? { body: scenario === 'too-large' ? ' '.repeat(8193) : JSON.stringify(body) } : {}) }),
        { ...env, FIREBASE_PROJECT_ID: 'v3-runtime-test' }, config);
      const expected = { origin: 403, method: 405, query: 404, version: 409, wallet: 400, 'extra-fields': 400,
        'too-large': 413, foreign: 409, 'disabled-network': 503, 'no-profile': 503, 'bad-cors': 403, asset: 400, 'delivery-digest': 409,
        'confirm-release': 409, 'deliver-release': 409 };
      expect(response.status).toBe(scenario === 'deliver' ? 202 : Object.hasOwn(expected, scenario) ? Reflect.get(expected, scenario) : 200);
      expect(response.headers.get('Cache-Control')).toBe('no-store');
      const result = await response.json<Record<string, unknown>>();
      expect(JSON.stringify(result)).not.toContain('https://a.example'); expect(JSON.stringify(result)).not.toContain(authorization.operation.signature);
      if (scenario === 'prepare' || scenario === 'read') { expect(result.preparation_id).toBe(saved.id); expect(result.send_enabled).toBe(false); }
      expect(prepareSpy).toHaveBeenCalledTimes(scenario === 'prepare' ? 1 : 0);
      expect(confirmSpy).toHaveBeenCalledTimes(scenario === 'confirm' ? 1 : 0);
      expect(deliverSpy).toHaveBeenCalledTimes(scenario === 'deliver' ? 1 : 0);
      expect(resolve).toHaveBeenCalledTimes(scenario === 'prepare' ? 1 : 0);
      if (scenario === 'prepare') expect(prepareSpy.mock.calls[0][5][0].assetIds).toEqual([f.request.asset_id]);
    });
  it.each(['native', 'token', 'retry', 'digest', 'proof', 'nonce', 'balance', 'security', 'rpc', 'finality',
    'expired', 'revoked', 'holds', 'draft-deleted'])(
    'confirms the stored review using independent observations and real signatures: %s', async scenario => {
      const s = await setup(scenario !== 'token'), f = s.f;
      const drafts = new TransferPreparationRepository(env.WALLET_DB, s.identity, f.approval.scope, [f.context.deployment_digest]);
      const saved = await drafts.save({ candidate: f.p, context: f.context, approval: f.approval,
        wallet_account_id: s.accountId, send_enabled: false });
      const profile = { document: f.approval.security_evidence.document, digest: f.context.deployment_digest,
        finalityPolicy: f.approval.security_evidence.finality_policy, entryPointCodeHash: `0x${'ee'.repeat(32)}` as const,
        providers: [{ operatorId: 'provider-a', url: 'https://a.example/rpc' }, { operatorId: 'provider-b', url: 'https://b.example/rpc' }],
        assetIds: f.approval.balance_evidence.balances.map(row => row.asset_id),
        assetDisplay: Object.fromEntries(f.approval.balance_evidence.balances.map(row => [row.asset_id, { symbol: 'TEST', decimals: 18 }])) };
      const fetcher = vi.fn(async (_: unknown, init?: RequestInit) => {
        const body: { id: number; method: string; params: unknown[] } = JSON.parse(String(init?.body));
        expect(body.method).toBe('eth_getBlockByNumber');
        return Response.json({ jsonrpc: '2.0', id: body.id, result: { number: body.params[0], hash: f.context.checkpoint.block_hash,
          timestamp: `0x${(f.now - 10).toString(16)}` } });
      });
      vi.stubGlobal('fetch', fetcher);
      vi.spyOn(finalityReader, 'assessCheckpointFinality').mockImplementation(async () => {
        if (scenario === 'finality') throw new Error('finality unavailable');
        return { ...f.approval.security_evidence.finality, assessed_at: f.now + 1, expires_at: f.now + 30 };
      });
      vi.spyOn(chainReader, 'inspectWalletSecurity').mockImplementation(async () => {
        if (scenario === 'rpc') throw new Error('RPC unavailable');
        if (scenario === 'expired') s.clock.mockReturnValue((f.now + 31) * 1000);
        if (scenario === 'revoked') await env.WALLET_DB.prepare('UPDATE users SET disabled_at = ?').bind(f.now + 1).run();
        if (scenario === 'draft-deleted') await env.WALLET_DB.prepare('DELETE FROM transfer_preparations WHERE id = ?').bind(saved.id).run();
        return { ...f.approval.security_evidence.observation, providers_agree: true,
          security_version: scenario === 'security' ? '3' : '2' };
      });
      vi.spyOn(rawBalanceReader, 'observeAccountBalances').mockResolvedValue({ network_id: f.request.network_id,
        address: f.context.account, checkpoint: f.context.checkpoint, observed_at: f.now + 1,
        finality: 'not_assessed', spend_readiness: 'not_assessed',
        balances: f.approval.balance_evidence.balances.map(row => ({ ...row, amount_atomic: scenario === 'balance' ? '9999' : '10000' })) });
      vi.spyOn(nonceReader, 'observeTransferNonce').mockResolvedValue({ ...f.approval.nonce_evidence,
        observed_at: f.now + 1, nonce: scenario === 'nonce' ? '1' : '0' });
      if (scenario === 'holds') await s.repository().reserve(s.accountId, await s.signed('11'));
      const proofs = await f.proofs();
      const invoke = () => confirmOwnedTransfer(env.WALLET_DB, s.identity, f.request.wallet_id, s.accountId, saved.id,
        scenario === 'digest' ? `0x${'dd'.repeat(32)}` : f.p.digest, scenario === 'proof' ? proofs.slice(0, 1) : proofs,
        f.approval.scope, [profile], new AbortController().signal);
      if (['native', 'token', 'retry'].includes(scenario)) {
        const result = await invoke();
        expect(result.state).toBe('held'); expect(result.send_enabled).toBe(false); expect(result.preparation_id).toBe(saved.id);
        const restored = await s.repository().readOwned(f.request.wallet_id, s.accountId, result.id);
        expect(restored.candidate.digest).toBe(f.p.digest); expect(restored.operation.signature).not.toBe('0x');
        expect(restored.plan.validUntil).toBe(f.context.valid_until);
        if (scenario === 'retry') {
          const count = fetcher.mock.calls.length;
          expect(await invoke()).toEqual(result); expect(fetcher).toHaveBeenCalledTimes(count);
        }
      } else {
        await expect(invoke()).rejects.toThrow();
        if (['digest', 'proof'].includes(scenario)) expect(fetcher).not.toHaveBeenCalled();
      }
      expect((await rows()).results).toHaveLength(['native', 'token', 'retry', 'holds'].includes(scenario) ? 1 : 0);
    });
  it.each(['roundtrip', 'concurrent', 'immutable', 'expired', 'wrong-owner', 'wrong-account', 'scope', 'profile',
    'revoked', 'revoked-new-login', 'revoked-during-read', 'capacity', 'changed-candidate'])(
    'persists owned unsigned preparation without locking money: %s', async scenario => {
      const s = await setup(), f = s.f;
      const prepared = { candidate: f.p, context: f.context, approval: f.approval,
        wallet_account_id: s.accountId, send_enabled: false as const };
      const repo = (identity = s.identity, scope = f.approval.scope, pins = [f.context.deployment_digest]) =>
        new TransferPreparationRepository(env.WALLET_DB, identity, scope, pins);
      const saved = await repo().save(prepared);
      expect(saved.candidate.digest).toBe(f.p.digest); expect(saved.send_enabled).toBe(false);
      if (scenario === 'concurrent') {
        const repeated = await Promise.all([repo().save(prepared), repo().save(prepared)]);
        expect(repeated.map(r => r.id)).toEqual([saved.id, saved.id]);
      } else if (scenario === 'immutable') {
        await expect(env.WALLET_DB.prepare('UPDATE transfer_preparations SET expires_at = expires_at + 1 WHERE id = ?')
          .bind(saved.id).run()).rejects.toThrow('immutable transfer preparation');
      } else if (scenario === 'changed-candidate') {
        await expect(repo().save({ ...prepared, candidate: { ...f.p, digest: `0x${'aa'.repeat(32)}` } })).rejects.toThrow();
      } else if (scenario === 'revoked-during-read') {
        const original = WalletRepository.prototype.ownedAccount;
        let calls = 0;
        vi.spyOn(WalletRepository.prototype, 'ownedAccount').mockImplementation(async function (this: WalletRepository, ...args) {
          const result = await original.apply(this, args);
          if (++calls === 2) await env.WALLET_DB.prepare('UPDATE users SET auth_not_before = ?').bind(f.now + 1).run();
          return result;
        });
        await expect(repo({ ...s.identity, authTime: f.now + 1 }).readOwned(f.request.wallet_id, s.accountId, saved.id))
          .rejects.toThrow('TRANSFER_PREPARATION_CHANGED');
      } else if (scenario === 'capacity') {
        for (let i = 11; i < 26; i++) {
          const request = { ...f.request, amount: { kind: 'exact' as const, amount_atomic: String(i) } };
          const candidate = prepareTransferOperation(request, f.context, f.now);
          await repo().save({ ...prepared, candidate, approval: { ...f.approval, reviewed_digest: candidate.digest } });
        }
        const request = { ...f.request, amount: { kind: 'exact' as const, amount_atomic: '26' } };
        const candidate = prepareTransferOperation(request, f.context, f.now);
        await expect(repo().save({ ...prepared, candidate, approval: { ...f.approval, reviewed_digest: candidate.digest } }))
          .rejects.toThrow('TRANSFER_PREPARATION_CAPACITY_OR_CHANGED');
        expect((await repo().save(prepared)).id).toBe(saved.id);
      } else if (scenario !== 'roundtrip') {
        if (scenario === 'expired') s.clock.mockReturnValue(f.context.valid_until * 1000);
        if (scenario.startsWith('revoked')) await env.WALLET_DB.prepare('UPDATE users SET auth_not_before = ?')
          .bind(f.now + 1).run();
        const identity = scenario === 'wrong-owner' ? { ...s.identity, userId: 'other' }
          : scenario === 'revoked-new-login' ? { ...s.identity, authTime: f.now + 1 } : s.identity;
        const reader = repo(identity, scenario === 'scope' ? { rpId: 'different.example', origin: 'https://different.example' } : f.approval.scope,
          scenario === 'profile' ? [] : [f.context.deployment_digest]);
        await expect(reader.readOwned(f.request.wallet_id, scenario === 'wrong-account' ? createResourceId('walletAccount') : s.accountId, saved.id))
          .rejects.toThrow();
      } else {
        expect((await repo().readOwned(f.request.wallet_id, s.accountId, saved.id)).review).toEqual({ request: f.request, context: f.context,
          policy: f.approval.policy, scope: f.approval.scope, prepared_at: f.now });
      }
      expect((await rows()).results).toHaveLength(0);
    });
  it.each(['sponsored-token', 'sponsor-failure-token', 'native', 'token', 'max-native', 'max-token', 'reserved', 'nonce-mismatch', 'security-mismatch',
    'balance-mismatch', 'rpc-failure', 'terms-expired', 'terms-request', 'terms-account', 'profile',
    'session-revoked', 'holds-changed', 'expired-during-read', 'input-mutated'])(
    'prepares an owned unsigned review from internal readers: %s', async scenario => {
      const s = await setup(!scenario.includes('token')), f = s.f;
      const request = scenario.startsWith('max') ? { ...f.request, amount: { kind: 'max' as const } } : structuredClone(f.request);
      const terms: TransferPreparationTerms = { request: structuredClone(request), wallet_account_id: s.accountId,
        deployment_digest: f.context.deployment_digest, native_asset_id: f.context.native_asset_id, gas: f.context.gas,
        maximum_native_gas_atomic: '1000', platform_fee: f.context.budget.platform_fee, fee_recipient: null,
        observed_at: f.now, expires_at: f.now + 20 };
      const profile = { document: f.approval.security_evidence.document, digest: f.context.deployment_digest,
        finalityPolicy: f.approval.security_evidence.finality_policy, finalityEvidence: f.approval.security_evidence.finality,
        entryPointCodeHash: `0x${'ee'.repeat(32)}` as const,
        providers: [{ operatorId: 'provider-a', url: 'https://a.example/rpc' }, { operatorId: 'provider-b', url: 'https://b.example/rpc' }],
        assetIds: f.approval.balance_evidence.balances.map(row => row.asset_id),
        assetDisplay: Object.fromEntries(f.approval.balance_evidence.balances.map(row => [row.asset_id, { symbol: 'TEST', decimals: 18 }])) };
      if (scenario === 'reserved') await s.repository().reserve(s.accountId, await s.signed());
      if (scenario === 'terms-expired') terms.expires_at = f.now;
      if (scenario === 'terms-request') terms.request.amount = { kind: 'exact', amount_atomic: '11' };
      if (scenario === 'terms-account') terms.wallet_account_id = createResourceId('walletAccount');
      if (scenario === 'profile') profile.assetIds = [];
      const securitySpy = vi.spyOn(securityReader, 'inspectOwnedWalletAccount').mockImplementation(async () => {
        if (scenario === 'session-revoked') await env.WALLET_DB.prepare('UPDATE users SET disabled_at = ?').bind(f.now + 1).run();
        if (scenario === 'expired-during-read') s.clock.mockReturnValue((f.now + 21) * 1000);
        if (scenario === 'input-mutated') {
          request.amount = { kind: 'exact', amount_atomic: '9999' };
          terms.maximum_native_gas_atomic = '9999'; profile.entryPointCodeHash = `0x${'aa'.repeat(32)}`;
        }
        return { ...f.approval.security_evidence.observation, wallet_id: f.request.wallet_id, wallet_account_id: s.accountId,
          account_id: scenario === 'security-mismatch' ? `0x${'aa'.repeat(32)}` : f.context.account_id,
          security_version: '2', finality: 'finalized', providers_agree: true,
          finality_evidence: f.approval.security_evidence.finality, security_observed_at: f.now, security_expires_at: f.now + 30 };
      });
      vi.spyOn(balanceReader, 'inspectOwnedWalletBalances').mockImplementation(async () => {
        if (scenario === 'rpc-failure') throw new Error('unavailable');
        return { ...f.approval.balance_evidence, wallet_account_id: s.accountId,
          address: scenario === 'balance-mismatch' ? f.request.destination.address : f.context.account,
          balances: f.approval.balance_evidence.balances.map(row => ({ ...row, symbol: 'TEST', decimals: 18,
            ...(scenario.startsWith('sponsor') && row.asset_id === f.context.native_asset_id ? { amount_atomic: '0' } : {}) })),
          finality: 'finalized', available_balance: 'not_assessed', spend_readiness: 'not_assessed' };
      });
      vi.spyOn(nonceReader, 'observeTransferNonce').mockResolvedValue({ ...f.approval.nonce_evidence,
        checkpoint: { ...f.approval.nonce_evidence.checkpoint,
          block_hash: scenario === 'nonce-mismatch' ? `0x${'dd'.repeat(32)}` : f.context.checkpoint.block_hash } });
      if (scenario === 'holds-changed') {
        const original = TransferNonceReservationRepository.prototype.reservedFunds;
        let reads = 0;
        vi.spyOn(TransferNonceReservationRepository.prototype, 'reservedFunds').mockImplementation(async function (this: TransferNonceReservationRepository, ...args) {
          const result = await original.apply(this, args);
          return ++reads === 2 ? result.map(row => ({ ...row, amount_atomic: '1' })) : result;
        });
      }
      const sponsor = { terms: (after: number, until: number) => ({ address: `0x${'12'.repeat(20)}` as const,
        verificationGasLimit: '100', postOpGasLimit: '0', data: sponsorshipData(after, until, `0x${'ab'.repeat(65)}`) }),
        authorize: vi.fn(async (_operation: unknown, after: number, until: number) => {
          if (scenario === 'sponsor-failure-token') throw new Error('SPONSOR_BUDGET_EXHAUSTED');
          return { ...sponsor.terms(after, until), data: sponsorshipData(after, until, `0x${'cd'.repeat(65)}`) };
        }) };
      const invoke = () => prepareOwnedTransfer(env.WALLET_DB, s.identity, s.accountId, request, f.approval.scope,
        [profile], terms, new AbortController().signal, scenario.startsWith('sponsor') ? sponsor : undefined);
      if (['sponsored-token', 'native', 'token', 'max-native', 'max-token', 'reserved', 'input-mutated'].includes(scenario)) {
        const result = await invoke();
        if (scenario === 'sponsored-token') {
          expect(result.context.budget.maximum_native_gas_atomic).toBe('0');
          expect(result.context.budget.native_available_atomic).toBe('0');
          expect(result.candidate.operation.paymasterData).toBe(sponsorshipData(f.now + 1, f.now + 20, `0x${'cd'.repeat(65)}`));
          expect(sponsor.authorize).toHaveBeenCalledOnce();
        }
        expect(result.send_enabled).toBe(false); expect(result.candidate.operation.signature).toBe('0x');
        expect(result.candidate.funding.amount_atomic).toBe(scenario === 'max-native' ? '9000' : scenario === 'max-token' ? '10000' : '10');
        expect(result.context.budget.asset_available_atomic).toBe(scenario === 'reserved' ? '8990' : '10000');
        expect(result.context.valid_until).toBe(f.now + 20);
        // Composition output can pass the existing independent cryptographic authorization,
        // but preparing alone neither writes a hold nor broadcasts an operation.
        const authorized = await authorizeTransferOperation(result.candidate.request, result.context, result.approval,
          await f.proofs(result.candidate.digest));
        expect(authorized.digest).toBe(result.candidate.digest);
      } else {
        await expect(invoke()).rejects.toThrow();
        if (scenario.startsWith('terms') || scenario === 'profile') expect(securitySpy).not.toHaveBeenCalled();
      }
      expect((await rows()).results).toHaveLength(scenario === 'reserved' ? 1 : 0);
    });
  it.each(['receipt','missing','disabled-session','expired-consent','lost-lease','wrong-token','corrupt-record',
    'journal','journal-disabled','journal-conflict','journal-concurrent','journal-stale','journal-lost',
    'reconcile','reconcile-disabled','reconcile-reverted','reconcile-catalog','reconcile-floor','reconcile-account','reconcile-expired','reconcile-lease','reconcile-conflict',
    'reconcile-queue','reconcile-queue-disabled','reconcile-queue-wait','reconcile-queue-timeout'])(
    'observes transfers under job authority without a fabricated login: %s', async scenario => {
      const s = await setup(), a = await s.signed(), held = await s.repository().reserve(s.accountId, a);
      await s.repository().beginDelivery(a.request.wallet_id, s.accountId, await deliveryProof(s, a, held.id));
      const profile = { document: s.f.approval.security_evidence.document, digest: a.deployment_digest,
        finalityPolicy: s.f.approval.security_evidence.finality_policy, entryPointCodeHash: `0x${'ee'.repeat(32)}` as const,
        providers: [{ operatorId: 'provider-a', url: 'https://a.example/rpc' }, { operatorId: 'provider-b', url: 'https://b.example/rpc' }],
        assetIds: [a.request.asset_id], assetDisplay: { [a.request.asset_id]: { symbol: 'ETH', decimals: 18 } },
        transport: { kind: 'bundler' as const, url: 'https://bundler.example/rpc' } };
      if (scenario === 'reconcile-catalog') profile.assetIds.push(`${a.request.network_id}/erc20:0x${'ab'.repeat(20)}`);
      const jobs = new TransferJobRepository(env.WALLET_DB, { environment: s.identity.environment, profiles: [profile] });
      const message = (await jobs.reserve(held.id))!; expect(await jobs.claim(message)).toBe(true);
      const transaction = `0x${'11'.repeat(32)}` as const;
      const block = { block_hash: a.checkpoint.block_hash, block_number: a.checkpoint.block_number, block_timestamp: String(s.f.now + 1) };
      const receiptSpy = vi.spyOn(receiptReader, 'observeTransferReceipt').mockResolvedValue({ schema_version: 1, network_id: a.request.network_id,
        deployment_sha256: a.deployment_digest, userop_hash: a.userOpHash, consent_digest: a.digest, transaction_hash: transaction,
        ...block, transaction_index: '0', outcome: scenario === 'reconcile-reverted' ? 'execution_reverted' : 'execution_succeeded', actual_gas_cost: '100', actual_gas_used: '50',
        log_indexes: { operation: '2', calls: '1', transfers: [] }, finality: 'not_assessed', settlement: 'not_assessed' });
      vi.spyOn(finalityReader, 'assessCheckpointFinality').mockResolvedValue({ ...s.f.approval.security_evidence.finality,
        target: block, checkpoint: block, assessed_at: s.f.now + 1, expires_at: scenario === 'journal-stale' ? s.f.now + 1 : s.f.now + 6 });
      const fetcher = vi.fn(async () => {
        if (['lost-lease','journal-lost'].includes(scenario)) await env.WALLET_DB.prepare('UPDATE transfer_jobs SET lease_expires_at = 1 WHERE operation_id = ?').bind(held.id).run();
        return Response.json({ jsonrpc: '2.0', id: 1, result: ['missing','expired-consent','reconcile-queue-wait'].includes(scenario) ? null
          : { userOpHash: a.userOpHash, receipt: { transactionHash: transaction } } });
      });
      vi.stubGlobal('fetch', fetcher);
      if (['disabled-session','journal-disabled','reconcile-disabled','reconcile-queue-disabled'].includes(scenario)) await env.WALLET_DB.prepare('UPDATE users SET disabled_at = ?,auth_not_before = ?')
        .bind(s.f.now + 1, s.f.now + 1).run();
      if (scenario === 'expired-consent') s.clock.mockReturnValue((s.identity.expiresAt + 100) * 1000);
      if (scenario === 'corrupt-record') await env.WALLET_DB.prepare("UPDATE transfer_nonce_reservations SET operation_sha256 = ? WHERE id = ?")
        .bind(`0x${'dd'.repeat(32)}`, held.id).run();
      const invoke = () => observeTransferJob(env.WALLET_DB, s.identity.environment,
        scenario === 'wrong-token' ? { ...message, token: createResourceId('operation') } : message, [profile], new AbortController().signal);
      if (scenario.startsWith('reconcile')) {
        vi.spyOn(balanceReader, 'inspectOwnedWalletBalances').mockImplementation(async (_access, _wallet, _account, profiles) => {
          if (scenario === 'reconcile-catalog') expect(profiles[0].assetIds).toEqual([a.request.asset_id]);
          if (scenario === 'reconcile-lease') await env.WALLET_DB.prepare('UPDATE transfer_jobs SET lease_expires_at = 1').run();
          if (scenario === 'reconcile-floor') await env.WALLET_DB.prepare('INSERT INTO wallet_balance_floors VALUES (?,?,?,?)')
            .bind(s.accountId, (BigInt(block.block_number) + 1n).toString(), block.block_hash, s.f.now + 1).run();
          if (scenario === 'reconcile-conflict') await env.WALLET_DB.prepare('INSERT INTO transfer_finality_conflicts SELECT * FROM transfer_finality_journal').run();
          return { wallet_id: a.request.wallet_id, wallet_account_id: scenario === 'reconcile-account' ? createResourceId('walletAccount') : s.accountId,
            network_id: a.request.network_id, address: a.account, checkpoint: block,
            balances: [{ asset_id: a.request.asset_id, amount_atomic: '9876', symbol: 'ETH', decimals: 18 }],
            observed_at: s.f.now + 1, expires_at: scenario === 'reconcile-expired' ? s.f.now + 1 : s.f.now + 6,
            spend_readiness: 'not_assessed', finality: 'finalized', available_balance: 'not_assessed',
            finality_evidence: { ...s.f.approval.security_evidence.finality, target: block, checkpoint: block,
              assessed_at: s.f.now + 1, expires_at: s.f.now + 6 } };
        });
        const reconcile = () => reconcileTransferJob(env.WALLET_DB, s.identity.environment, message, [profile], new AbortController().signal);
        if (scenario.startsWith('reconcile-queue')) {
          await env.WALLET_DB.prepare('UPDATE transfer_jobs SET lease_expires_at = 1').run();
          const sent: TransferWake[] = [];
          const send = vi.fn(async (body: TransferWake): Promise<QueueSendResponse> => {
            sent.push(body); return { metadata: { metrics: { backlogCount: sent.length, backlogBytes: 0 } } };
          });
          const bindings = { WALLET_DB: env.WALLET_DB, CREATION_QUEUE_NAME: env.CREATION_QUEUE_NAME, CREATION_JOBS: { send } };
          const handlers = createTransferJobHandlers(() => ({ environment: s.identity.environment, profiles: [profile] }));
          await Promise.all([handlers.wake(bindings), handlers.wake(bindings)]); expect(sent).toHaveLength(1);
          const consume = async () => {
            const batch = createMessageBatch(bindings.CREATION_QUEUE_NAME, sent.map(body => ({ id: 'transfer-fixture', timestamp: new Date(), attempts: 1, body })));
            await handlers.queue(batch, bindings); await getQueueResult(batch, createExecutionContext());
          };
          if (scenario === 'reconcile-queue-timeout') s.clock.mockReturnValue((s.f.now + 86402) * 1000);
          await consume();
          const expected = scenario === 'reconcile-queue-wait' ? 'ready' : scenario === 'reconcile-queue-timeout' ? 'review' : 'reconciled';
          expect(await env.WALLET_DB.prepare('SELECT * FROM transfer_jobs WHERE operation_id = ?').bind(held.id).first())
            .toMatchObject({ state: expected, lease_token: null });
          expect((await rows()).results[0].state).toBe(expected === 'reconciled' ? 'reconciled' : 'delivery_pending');
          if (scenario === 'reconcile-queue-timeout') expect(fetcher).not.toHaveBeenCalled();
          fetcher.mockClear(); await consume(); expect(fetcher).not.toHaveBeenCalled();
          return;
        }
        if (['reconcile','reconcile-disabled','reconcile-reverted','reconcile-catalog'].includes(scenario)) {
          expect(await reconcile()).toMatchObject({ state: 'reconciled', funds_reserved: false });
          expect((await rows()).results[0].state).toBe('reconciled');
          expect(await env.WALLET_DB.prepare('SELECT * FROM transfer_jobs WHERE operation_id = ?').bind(held.id).first())
            .toMatchObject({ state: 'reconciled', lease_token: null, lease_expires_at: null });
          expect((await env.WALLET_DB.prepare('SELECT * FROM transfer_reconciliations').all()).results).toHaveLength(1);
          const saved = await env.WALLET_DB.prepare('SELECT receipt_json FROM transfer_finality_journal').first();
          expect(JSON.parse(String(saved?.receipt_json)).outcome).toBe(scenario === 'reconcile-reverted' ? 'execution_reverted' : 'execution_succeeded');
          await expect(reconcile()).rejects.toThrow();
          return;
        }
        await expect(reconcile()).rejects.toThrow();
      } else if (scenario.startsWith('journal')) {
        const record = () => recordTransferJobFinality(env.WALLET_DB, s.identity.environment, message, [profile], new AbortController().signal);
        if (scenario === 'journal-lost') {
          await expect(record()).rejects.toThrow();
        } else if (scenario === 'journal-stale') {
          expect(await record()).toMatchObject({ journal: 'not_recorded' });
        } else {
          const first = await record(); expect(first.journal).toBe('recorded');
          if (first.status !== 'observed') throw new Error('missing fixture observation');
          if (scenario === 'journal-concurrent') expect((await Promise.all([record(), record()])).map(r => r.journal)).toEqual(['recorded','recorded']);
          if (scenario === 'journal-conflict') {
            receiptSpy.mockResolvedValue({ ...first.observation, actual_gas_used: '51' });
            expect((await record()).journal).toBe('conflict');
            receiptSpy.mockResolvedValue(first.observation);
            expect((await record()).journal).toBe('conflict');
            expect((await env.WALLET_DB.prepare('SELECT * FROM transfer_finality_conflicts').all()).results).toHaveLength(1);
          }
          const rows = (await env.WALLET_DB.prepare('SELECT * FROM transfer_finality_journal').all()).results;
          expect(rows).toHaveLength(1);
          expect(rows[0].receipt_json).toBe(JSON.stringify(first.observation));
          expect(deploymentDocumentDigest(String(rows[0].evidence_json))).toBe(rows[0].evidence_sha256);
        }
        if (['journal-lost','journal-stale'].includes(scenario)) {
          expect((await env.WALLET_DB.prepare('SELECT * FROM transfer_finality_journal').all()).results).toHaveLength(0);
        }
      } else if (['lost-lease','wrong-token','corrupt-record'].includes(scenario)) {
        await expect(invoke()).rejects.toThrow();
        if (scenario !== 'lost-lease') expect(fetcher).not.toHaveBeenCalled();
      } else expect(await invoke()).toMatchObject({ status: ['missing','expired-consent'].includes(scenario) ? 'not_observed' : 'observed',
        userop_hash: a.userOpHash, settlement: 'not_assessed' });
      expect((await rows()).results[0]).toMatchObject({ state: 'delivery_pending', delivery_dispatched_at: null });
      expect((await env.WALLET_DB.prepare('SELECT * FROM transfer_reconciliations').all()).results).toHaveLength(0);
    });
  it('rolls back the delivery claim if durable follow-up cannot be inserted', async () => {
    const s = await setup(), a = await s.signed(), held = await s.repository().reserve(s.accountId, a);
    expect((await env.WALLET_DB.prepare('SELECT * FROM transfer_jobs').all()).results).toHaveLength(0);
    await env.WALLET_DB.exec("CREATE TRIGGER transfer_job_test_failure BEFORE INSERT ON transfer_jobs BEGIN SELECT RAISE(ABORT,'synthetic storage failure'); END;");
    await expect(s.repository().beginDelivery(a.request.wallet_id, s.accountId, await deliveryProof(s, a, held.id))).rejects.toThrow();
    expect((await rows()).results[0]).toMatchObject({ state: 'held', delivery_token_sha256: null });
    expect((await env.WALLET_DB.prepare('SELECT * FROM transfer_jobs').all()).results).toHaveLength(0);
  });
  it.each(['single-winner','lease-expiry','scope','disabled-login','defer','review','exhaustion','payload'])(
    'durable transfer observation scheduling: %s', async scenario => {
      const s = await setup(), a = await s.signed(), held = await s.repository().reserve(s.accountId, a);
      await s.repository().beginDelivery(a.request.wallet_id, s.accountId, await deliveryProof(s, a, held.id));
      const config = { environment: s.identity.environment,
        profiles: [{ document: s.f.approval.security_evidence.document, digest: a.deployment_digest }] };
      const jobs = new TransferJobRepository(env.WALLET_DB, config);
      const row = () => env.WALLET_DB.prepare('SELECT * FROM transfer_jobs WHERE operation_id = ?').bind(held.id).first();
      expect(await jobs.due()).toEqual([held.id]);
      if (scenario === 'single-winner') {
        const messages = await Promise.all(Array.from({ length: 4 }, () => jobs.reserve(held.id)));
        expect(messages.filter(Boolean)).toHaveLength(1);
        const message = messages.find(m => m !== null)!;
        expect((await Promise.all(Array.from({ length: 4 }, () => jobs.claim(message)))).filter(Boolean)).toHaveLength(1);
      } else {
        const message = (await jobs.reserve(held.id))!;
        expect(Object.keys(message).sort()).toEqual(['schema_version','kind','operation_id','token'].sort());
        if (scenario === 'scope') {
          const other = new TransferJobRepository(env.WALLET_DB, { ...config, environment: 'production' as const });
          expect(await other.due()).toEqual([]); expect(await other.reserve(held.id)).toBeNull();
          expect(await other.claim(message)).toBe(false); expect(await jobs.claim(message)).toBe(true);
          expect(await other.defer(message, 30)).toBe(false); expect(await other.review(message, 'observation_timeout')).toBe(false);
          expect(await other.fail(message, 'running')).toBe(false);
          expect(await new TransferJobRepository(env.WALLET_DB, { ...config, profiles: [] }).due()).toEqual([]);
        } else if (scenario === 'payload') {
          expect(parseTransferWake(message)).toEqual(message);
          for (const extra of [{ rpcUrl: 'https://example.test' }, { signature: a.operation.signature }, { firebaseToken: 'synthetic' }]) {
            expect(() => parseTransferWake({ ...message, ...extra })).toThrow();
          }
          expect(() => parseTransferWake({ ...message, kind: 'account_creation' })).toThrow();
        } else {
          if (scenario === 'disabled-login') await env.WALLET_DB.prepare('UPDATE users SET disabled_at = ?').bind(s.f.now).run();
          expect(await jobs.claim(message)).toBe(true);
          if (scenario === 'lease-expiry') {
            await env.WALLET_DB.prepare('UPDATE transfer_jobs SET lease_expires_at = 1 WHERE operation_id = ?').bind(held.id).run();
            s.clock.mockReturnValue(0);
            expect(await jobs.defer(message, 30)).toBe(false); expect(await jobs.review(message, 'observation_timeout')).toBe(false);
            const newer = (await jobs.reserve(held.id))!; expect(newer.token).not.toBe(message.token);
            expect(await jobs.claim(newer)).toBe(true); expect(await jobs.fail(message, 'running')).toBe(false);
            expect((await row())?.lease_token).toBe(newer.token);
          } else if (scenario === 'review') {
            expect(await jobs.review(message, 'conflicting_evidence')).toBe(true);
            expect(await row()).toMatchObject({ state: 'review', reason: 'conflicting_evidence', lease_token: null });
            expect(await jobs.due()).toEqual([]);
          } else if (scenario === 'exhaustion') {
            expect(await jobs.fail(message, 'running')).toBe(true);
            for (let i = 1; i < 8; i++) {
              await env.WALLET_DB.prepare('UPDATE transfer_jobs SET next_attempt_at = 0 WHERE operation_id = ?').bind(held.id).run();
              const retry = (await jobs.reserve(held.id))!; expect(await jobs.claim(retry)).toBe(true);
              expect(await jobs.fail(retry, 'running')).toBe(true);
            }
            expect(await row()).toMatchObject({ state: 'review', failures: 8, reason: 'processing_error' });
            expect(await jobs.due()).toEqual([]);
          } else {
            expect(await jobs.defer(message, 30)).toBe(true);
            expect(await row()).toMatchObject({ state: 'ready', lease_token: null });
            expect(await jobs.due()).toEqual([]); expect(await jobs.claim(message)).toBe(false);
          }
        }
      }
      expect((await rows()).results[0].state).toBe('delivery_pending');
      expect((await rows()).results[0].delivery_dispatched_at).toBeNull();
    });
  it.each(['older', 'equal', 'newer', 'different-hash', 'large-height'])(
    'checks the persisted balance floor atomically when reserving: %s', async fault => {
      const s = await setup(), a = await s.signed();
      const height = BigInt(a.checkpoint.block_number);
      const block = fault === 'older' ? height - 1n : fault === 'newer' ? height + 1n : fault === 'large-height' ? 2n ** 80n : height;
      await env.WALLET_DB.prepare('INSERT INTO wallet_balance_floors VALUES (?,?,?,?)').bind(s.accountId, block.toString(),
        fault === 'different-hash' ? `0x${'aa'.repeat(32)}` : a.checkpoint.block_hash, s.f.now).run();
      if (fault === 'older' || fault === 'equal') await expect(s.repository().reserve(s.accountId, a)).resolves.toMatchObject({ state: 'held' });
      else { await expect(s.repository().reserve(s.accountId, a)).rejects.toThrow(); expect((await rows()).results).toHaveLength(0); }
    });
  it.each(['claim','dispatch'])('rejects a floor advance between preflight and %s', async stage => {
    const s = await setup(), a = await s.signed(), held = await s.repository().reserve(s.accountId, a);
    const proof = await deliveryProof(s, a, held.id);
    const claim = stage === 'dispatch' ? await s.repository().beginDelivery(a.request.wallet_id, s.accountId, proof) : null;
    await env.WALLET_DB.prepare('INSERT INTO wallet_balance_floors VALUES (?,?,?,?)').bind(s.accountId,
      (BigInt(a.checkpoint.block_number) + 1n).toString(), `0x${'ab'.repeat(32)}`, s.f.now).run();
    if (claim) await expect(s.repository().consumeDelivery(a.request.wallet_id, s.accountId, held.id, claim.claim_token)).rejects.toThrow();
    else await expect(s.repository().beginDelivery(a.request.wallet_id, s.accountId, proof)).rejects.toThrow();
    const row = (await rows()).results[0]; expect(row.delivery_dispatched_at).toBeNull();
    expect(row.state).toBe(stage === 'dispatch' ? 'delivery_pending' : 'held');
  });
  it('prevents floor regression and same-height hash replacement in D1', async () => {
    const s = await setup(), a = await s.signed();
    await env.WALLET_DB.prepare('INSERT INTO wallet_balance_floors VALUES (?,?,?,?)').bind(s.accountId, '1000', a.checkpoint.block_hash, s.f.now).run();
    await expect(env.WALLET_DB.prepare("UPDATE wallet_balance_floors SET block_number = '999'").run()).rejects.toThrow();
    await expect(env.WALLET_DB.prepare('UPDATE wallet_balance_floors SET block_hash = ?').bind(`0x${'aa'.repeat(32)}`).run()).rejects.toThrow();
    await env.WALLET_DB.prepare("UPDATE wallet_balance_floors SET block_number = '1001'").run();
    expect((await env.WALLET_DB.prepare('SELECT block_number FROM wallet_balance_floors').first())?.block_number).toBe('1001');
  });
  it.each(['held', 'pending', 'foreign', 'query', 'post', 'origin', 'invalid-id', 'missing-id'])(
    'exposes only an owned read-only transfer status over HTTP: %s', async fault => {
      const s = await setup(), a = await s.signed(), held = await s.repository().reserve(s.accountId, a);
      if (fault === 'pending') await s.repository().beginDelivery(a.request.wallet_id, s.accountId, await deliveryProof(s, a, held.id));
      const config = parseEnvironment({ ...manifests.staging, status: 'provisioned', firebase_project_id: 'v3-runtime-test' });
      vi.spyOn(sessionVerifier, 'verifyAppSession').mockResolvedValue(fault === 'foreign'
        ? { ...s.identity, userId: 'another-user' } : s.identity);
      const request = new Request(`${config.api_origin}/app/v1/wallets/${a.request.wallet_id}/accounts/${s.accountId}/transfers/${fault === 'invalid-id' ? 'wrong' : fault === 'missing-id' ? createResourceId('operation') : held.id}${fault === 'query' ? '?rpc=https://evil.example' : ''}`,
        { method: fault === 'post' ? 'POST' : 'GET', headers: { Origin: fault === 'origin' ? 'https://evil.example' : config.web_origin } });
      const response = await walletReadRoute(request, { ...env, FIREBASE_PROJECT_ID: 'v3-runtime-test' }, config, async () => []);
      expect(response.status).toBe(fault === 'query' || fault === 'invalid-id' ? 400 : fault === 'post' ? 405
        : fault === 'origin' ? 403 : fault === 'foreign' ? 409 : fault === 'missing-id' ? 404 : 200);
      expect(response.headers.get('Cache-Control')).toContain('no-store');
      const body = await response.json<Record<string, unknown>>();
      if (response.ok) {
        expect(body.status).toBe(fault === 'pending' ? 'delivery_pending' : 'held');
        expect(body.historical_confirmation).toBeNull(); expect(body.funds_reserved).toBe(true);
        expect(body.send_enabled).toBe(false); expect(body.settlement).toBe('not_assessed');
        expect(Object.keys(body).sort()).toEqual(['operation_id','wallet_id','wallet_account_id','network_id','userop_hash',
          'status','historical_confirmation','settlement','send_enabled','funds_reserved'].sort());
      }
      expect(JSON.stringify(body)).not.toContain(a.operation.signature);
      expect((await rows()).results[0].state).toBe(fault === 'pending' ? 'delivery_pending' : 'held');
    });
  it.each(['recorded', 'concurrent', 'conflict', 'concurrent-conflict', 'unavailable', 'expired', 'revoked', 'wrong-operation',
    'balance-current','balance-old','balance-account','balance-assets','balance-expired','balance-reorg',
    'balance-commit','balance-commit-floor','balance-commit-hash'])(
    'preserves immutable finality separately from reservation release: %s', async fault => {
      const s = await setup(), a = await s.signed(), held = await s.repository().reserve(s.accountId, a);
      await s.repository().beginDelivery(a.request.wallet_id, s.accountId, await deliveryProof(s, a, held.id));
      const transaction = `0x${'11'.repeat(32)}` as const;
      const profile: TransferDeliveryProfile = { document: s.f.approval.security_evidence.document, digest: a.deployment_digest,
        finalityPolicy: s.f.approval.security_evidence.finality_policy, entryPointCodeHash: `0x${'ee'.repeat(32)}`,
        providers: [{ operatorId: 'provider-a', url: 'https://a.example/rpc' }, { operatorId: 'provider-b', url: 'https://b.example/rpc' }],
        assetIds: [a.request.asset_id], assetDisplay: { [a.request.asset_id]: { symbol: 'ETH', decimals: 18 } } };
      const block = { block_hash: a.checkpoint.block_hash, block_number: a.checkpoint.block_number, block_timestamp: String(s.f.now + 1) };
      const result = { operation_id: held.id, userop_hash: a.userOpHash, transaction_hash: transaction,
        provider_ids: ['provider-a', 'provider-b'], settlement: 'not_assessed' as const, status: 'observed' as const,
        observation: { schema_version: 1 as const, network_id: a.request.network_id, deployment_sha256: a.deployment_digest,
          userop_hash: a.userOpHash, consent_digest: a.digest, transaction_hash: transaction, ...block,
          transaction_index: '0', outcome: 'execution_succeeded' as const, actual_gas_cost: '100', actual_gas_used: '50',
          log_indexes: { operation: '2', calls: '1', transfers: [] }, finality: 'not_assessed' as const, settlement: 'not_assessed' as const },
        finality_evidence: { ...s.f.approval.security_evidence.finality, target: block, checkpoint: block,
          assessed_at: s.f.now + 1, expires_at: s.f.now + 6 },
      };
      const observer = vi.spyOn(transferObserver, 'observeOwnedTransfer').mockResolvedValue(result);
      const invoke = () => recordOwnedTransferFinality(env.WALLET_DB, s.identity, a.request.wallet_id, s.accountId, held.id,
        undefined, [profile], new AbortController().signal);
      const journal = () => env.WALLET_DB.prepare('SELECT * FROM transfer_finality_journal').all();
      if (fault === 'expired') {
        observer.mockResolvedValue({ ...result, finality_evidence: { ...result.finality_evidence, assessed_at: s.f.now - 5, expires_at: s.f.now } });
        await expect(invoke()).rejects.toThrow();
      } else if (fault === 'wrong-operation') {
        observer.mockResolvedValue({ ...result, userop_hash: transaction });
        await expect(invoke()).rejects.toThrow();
      } else if (fault === 'revoked') {
        observer.mockImplementation(async () => {
          await env.WALLET_DB.prepare('UPDATE users SET disabled_at = ? WHERE id = ?').bind(s.f.now + 1, s.session.user_id).run();
          return result;
        });
        await expect(invoke()).rejects.toThrow();
      } else {
        const first = await invoke(); expect(first.journal).toBe('recorded');
        const saved = (await journal()).results[0];
        if (fault.startsWith('balance-')) {
          const checkpoint = fault === 'balance-old' ? { ...block, block_number: (BigInt(block.block_number) - 1n).toString() } : block;
          vi.spyOn(balanceReader, 'inspectOwnedWalletBalances').mockResolvedValue({
            wallet_id: a.request.wallet_id, wallet_account_id: fault === 'balance-account' ? createResourceId('walletAccount') : s.accountId,
            network_id: a.request.network_id, address: a.account, checkpoint,
            balances: fault === 'balance-assets' ? [] : [{ asset_id: a.request.asset_id, amount_atomic: '9876', symbol: 'ETH', decimals: 18 }],
            observed_at: s.f.now + 1, expires_at: fault === 'balance-expired' ? s.f.now + 1 : s.f.now + 6,
            spend_readiness: 'not_assessed', finality: 'finalized', finality_evidence: result.finality_evidence, available_balance: 'not_assessed',
          });
          vi.spyOn(finalityReader, 'assessCheckpointFinality').mockResolvedValue(fault === 'balance-reorg'
            ? { ...result.finality_evidence, status: 'reorg_detected', checkpoint: null, expires_at: s.f.now + 1 } : result.finality_evidence);
          const check = () => observeTransferReconciliationBalance(env.WALLET_DB, s.identity, a.request.wallet_id, s.accountId,
            held.id, undefined, [profile], new AbortController().signal);
          if (fault.startsWith('balance-commit')) {
            const commit = () => reconcileOwnedTransfer(env.WALLET_DB, s.identity, a.request.wallet_id, s.accountId,
              held.id, undefined, [profile], new AbortController().signal);
            await expect(env.WALLET_DB.prepare("UPDATE transfer_nonce_reservations SET state = 'reconciled' WHERE id = ?")
              .bind(held.id).run()).rejects.toThrow();
            if (fault !== 'balance-commit') {
              await env.WALLET_DB.prepare('INSERT INTO wallet_balance_floors VALUES (?,?,?,?)').bind(s.accountId,
                fault === 'balance-commit-floor' ? (BigInt(block.block_number) + 1n).toString() : block.block_number,
                fault === 'balance-commit-hash' ? `0x${'aa'.repeat(32)}` : block.block_hash, s.f.now + 1).run();
              const before = await env.WALLET_DB.prepare('SELECT * FROM wallet_balance_floors').all();
              await expect(commit()).rejects.toThrow();
              expect((await env.WALLET_DB.prepare('SELECT * FROM transfer_reconciliations').all()).results).toHaveLength(0);
              expect((await env.WALLET_DB.prepare('SELECT * FROM wallet_balance_floors').all()).results).toEqual(before.results);
            } else {
              expect(await commit()).toMatchObject({ reservation: 'reconciled', funds_reserved: false, send_enabled: false });
              expect((await rows()).results[0].state).toBe('reconciled');
              expect(await env.WALLET_DB.prepare('SELECT * FROM transfer_jobs WHERE operation_id = ?').bind(held.id).first())
                .toMatchObject({ state: 'reconciled', lease_token: null, lease_expires_at: null });
              const evidence = await env.WALLET_DB.prepare('SELECT * FROM transfer_reconciliations').first();
              expect(evidence?.receipt_sha256).toBe(saved.receipt_sha256);
              expect(deploymentDocumentDigest(String(evidence?.proof_json))).toBe(evidence?.proof_sha256);
              expect((await env.WALLET_DB.prepare('SELECT * FROM wallet_balance_floors').first())?.block_number).toBe(block.block_number);
              expect((await s.repository().reservedFunds(a.request.wallet_id, s.accountId, [a.request.asset_id]))[0].amount_atomic).toBe('0');
              expect(await readOwnedTransferStatus(env.WALLET_DB, s.identity, a.request.wallet_id, s.accountId, held.id))
                .toMatchObject({ status: 'reconciled', funds_reserved: false, historical_confirmation: { transaction_hash: transaction } });
              await expect(s.repository().reserve(s.accountId, a)).rejects.toThrow();
              await expect(commit()).rejects.toThrow();
              expect((await env.WALLET_DB.prepare('SELECT * FROM transfer_reconciliations').all()).results).toHaveLength(1);
              await expect(env.WALLET_DB.prepare("UPDATE transfer_nonce_reservations SET state = 'delivery_pending' WHERE id = ?")
                .bind(held.id).run()).rejects.toThrow();
              await expect(env.WALLET_DB.prepare('UPDATE transfer_reconciliations SET recorded_at = recorded_at + 1').run()).rejects.toThrow();
              return;
            }
          } else if (fault === 'balance-current') {
            const proof = await check(); expect(proof.release_enabled).toBe(false);
            expect(proof.balances.balances[0].amount_atomic).toBe('9876');
            expect(proof.receipt_sha256).toBe(saved.receipt_sha256);
          } else await expect(check()).rejects.toThrow();
        }
        if (fault === 'concurrent') expect((await Promise.all([invoke(), invoke()])).map(r => r.journal)).toEqual(['recorded', 'recorded']);
        if (fault === 'conflict' || fault === 'concurrent-conflict') {
          observer.mockResolvedValue({ ...result, observation: { ...result.observation, actual_gas_used: '51' } });
          if (fault === 'concurrent-conflict') expect((await Promise.all([invoke(), invoke()])).map(r => r.journal)).toEqual(['conflict', 'conflict']);
          else expect((await invoke()).journal).toBe('conflict');
          const conflicts = await env.WALLET_DB.prepare('SELECT * FROM transfer_finality_conflicts').all();
          expect(conflicts.results).toHaveLength(1);
          expect(JSON.parse(String(conflicts.results[0].receipt_json)).actual_gas_used).toBe('51');
          observer.mockResolvedValue(result);
          expect((await invoke()).journal).toBe('conflict');
          observer.mockResolvedValue({ ...result, observation: { ...result.observation, actual_gas_used: '52' } });
          expect((await invoke()).journal).toBe('conflict');
          expect((await env.WALLET_DB.prepare('SELECT * FROM transfer_finality_conflicts').all()).results).toEqual(conflicts.results);
          await expect(env.WALLET_DB.prepare('UPDATE transfer_finality_conflicts SET recorded_at = recorded_at + 1').run()).rejects.toThrow();
        }
        if (fault === 'unavailable') {
          observer.mockResolvedValue({ operation_id: held.id, userop_hash: a.userOpHash, transaction_hash: null,
            provider_ids: ['provider-a', 'provider-b'], settlement: 'not_assessed', status: 'unavailable' });
          expect((await invoke()).journal).toBe('not_recorded');
        }
        expect((await journal()).results).toEqual([saved]);
        const status = await readOwnedTransferStatus(env.WALLET_DB, s.identity, a.request.wallet_id, s.accountId, held.id);
        expect(status.status).toBe(['conflict', 'concurrent-conflict'].includes(fault) ? 'review_required' : 'confirmation_recorded');
        expect(status.historical_confirmation?.transaction_hash).toBe(transaction);
        expect(status.funds_reserved).toBe(true); expect(status.settlement).toBe('not_assessed');
        await expect(env.WALLET_DB.prepare('UPDATE transfer_finality_journal SET recorded_at = recorded_at + 1').run()).rejects.toThrow();
      }
      expect((await journal()).results).toHaveLength(['expired', 'revoked', 'wrong-operation'].includes(fault) ? 0 : 1);
      expect((await rows()).results[0].state).toBe('delivery_pending');
    });
  it.each(['valid', 'missing', 'wrong-operation', 'zero-hash', 'invalid-envelope', 'rpc-error', 'oversized',
    'transport-error', 'revoked', 'known-transaction', 'missing-profile'])(
    'uses the bundler only as a bounded transaction locator: %s', async fault => {
      const s = await setup(), a = await s.signed(), held = await s.repository().reserve(s.accountId, a);
      await s.repository().beginDelivery(a.request.wallet_id, s.accountId, await deliveryProof(s, a, held.id));
      const transaction = `0x${'11'.repeat(32)}` as const;
      const profile = { document: s.f.approval.security_evidence.document, digest: a.deployment_digest,
        finalityPolicy: s.f.approval.security_evidence.finality_policy, entryPointCodeHash: `0x${'ee'.repeat(32)}` as const,
        providers: [{ operatorId: 'provider-a', url: 'https://a.example/rpc' }, { operatorId: 'provider-b', url: 'https://b.example/rpc' }],
        assetIds: [a.request.asset_id], assetDisplay: { [a.request.asset_id]: { symbol: 'ETH', decimals: 18 } },
        transport: fault === 'missing-profile' ? undefined : { kind: 'bundler' as const, url: 'https://bundler.example/rpc' } };
      const fetcher = vi.fn(async (url: string, init: RequestInit) => {
        expect(url).toBe(profile.transport?.url); expect(init.redirect).toBe('manual');
        expect(JSON.parse(String(init.body))).toEqual({ jsonrpc: '2.0', id: 1, method: 'eth_getUserOperationReceipt', params: [a.userOpHash] });
        if (fault === 'transport-error') throw new Error('private provider credentials');
        if (fault === 'revoked') await env.WALLET_DB.prepare('UPDATE users SET disabled_at = ? WHERE id = ?')
          .bind(s.f.now + 1, s.session.user_id).run();
        if (fault === 'rpc-error') return Response.json({ error: 'private provider credentials' }, { status: 503 });
        if (fault === 'oversized') return new Response('x'.repeat(262_145));
        return Response.json({ jsonrpc: '2.0', id: fault === 'invalid-envelope' ? 2 : 1,
          result: fault === 'missing' ? null : { userOpHash: fault === 'wrong-operation' ? transaction : a.userOpHash,
            success: true, receipt: { transactionHash: fault === 'zero-hash' ? `0x${'00'.repeat(32)}` : transaction,
              status: '0x1', logs: [] } } });
      });
      vi.stubGlobal('fetch', fetcher);
      const receipt = vi.spyOn(receiptReader, 'observeTransferReceipt').mockImplementation(async (_client, _record, hash) => {
        expect(hash).toBe(transaction); return null;
      });
      const finality = vi.spyOn(finalityReader, 'assessCheckpointFinality');
      const invoke = () => observeOwnedTransfer(env.WALLET_DB, s.identity, a.request.wallet_id, s.accountId, held.id,
        fault === 'known-transaction' ? transaction : undefined, [profile], new AbortController().signal);
      if (fault === 'revoked') await expect(invoke()).rejects.toThrow();
      else {
        const result = await invoke();
        expect(result.status).toBe(['valid', 'missing', 'known-transaction'].includes(fault) ? 'not_observed' : 'unavailable');
        expect(result.settlement).toBe('not_assessed');
        expect(result.transaction_hash).toBe(['valid', 'known-transaction'].includes(fault) ? transaction : null);
        expect(JSON.stringify(result)).not.toContain('private provider');
      }
      expect(fetcher).toHaveBeenCalledTimes(['known-transaction', 'missing-profile'].includes(fault) ? 0 : 1);
      expect(receipt).toHaveBeenCalledTimes(['valid', 'known-transaction', 'revoked'].includes(fault) ? 2 : 0);
      expect(finality).not.toHaveBeenCalled();
      expect((await rows()).results[0].state).toBe('delivery_pending');
    });
  it.each(['observed', 'missing', 'disagreement', 'rpc-error', 'revoked', 'expired-finality', 'held', 'late-observation'])(
    'composes owned receipt quorum without releasing funds: %s', async fault => {
      const s = await setup(), a = await s.signed(), held = await s.repository().reserve(s.accountId, a);
      if (fault !== 'held') await s.repository().beginDelivery(a.request.wallet_id, s.accountId, await deliveryProof(s, a, held.id));
      const profile: TransferDeliveryProfile = { document: s.f.approval.security_evidence.document, digest: a.deployment_digest,
        finalityPolicy: s.f.approval.security_evidence.finality_policy, entryPointCodeHash: `0x${'ee'.repeat(32)}`,
        providers: [{ operatorId: 'provider-a', url: 'https://a.example/rpc' }, { operatorId: 'provider-b', url: 'https://b.example/rpc' }],
        assetIds: [a.request.asset_id], assetDisplay: { [a.request.asset_id]: { symbol: 'ETH', decimals: 18 } } };
      const transaction = `0x${'11'.repeat(32)}` as const;
      // Composition fixtures only: raw receipt/code verification is exercised by v3TransferReceipt.test.ts.
      const observation: NonNullable<Awaited<ReturnType<typeof receiptReader.observeTransferReceipt>>> = {
        schema_version: 1, network_id: a.request.network_id, deployment_sha256: a.deployment_digest,
        userop_hash: a.userOpHash, consent_digest: a.digest, transaction_hash: transaction,
        block_hash: a.checkpoint.block_hash, block_number: a.checkpoint.block_number, block_timestamp: String(s.f.now),
        transaction_index: '0', outcome: 'execution_succeeded', actual_gas_cost: '100', actual_gas_used: '50',
        log_indexes: { operation: '2', calls: '1', transfers: [] }, finality: 'not_assessed', settlement: 'not_assessed',
      };
      let calls = 0;
      const receipt = vi.spyOn(receiptReader, 'observeTransferReceipt').mockImplementation(async (_client, record, hash, pin) => {
        expect(record.candidate.digest).toBe(a.digest); expect(hash).toBe(transaction);
        expect(pin.initialSecurityCommitment).toBe(s.f.f.initial.message.initialSecurityCommitment);
        calls++;
        if (fault === 'rpc-error') throw new Error('private provider diagnostic');
        if (fault === 'revoked') await env.WALLET_DB.prepare('UPDATE users SET disabled_at = ? WHERE id = ?')
          .bind(s.f.now + 1, s.session.user_id).run();
        if (fault === 'missing') return null;
        return fault === 'disagreement' && calls === 2 ? { ...observation, actual_gas_used: '51' } : observation;
      });
      if (fault === 'late-observation') s.clock.mockReturnValue((a.plan.validUntil + 1) * 1000);
      const now = Math.floor(Date.now() / 1000);
      const finality = vi.spyOn(finalityReader, 'assessCheckpointFinality').mockResolvedValue({
        ...s.f.approval.security_evidence.finality, assessed_at: now, expires_at: fault === 'expired-finality' ? now : now + 5,
      });
      const invoke = () => observeOwnedTransfer(env.WALLET_DB, s.identity, a.request.wallet_id, s.accountId, held.id,
        transaction, [profile], new AbortController().signal);
      if (fault === 'held' || fault === 'revoked') await expect(invoke()).rejects.toThrow();
      else {
        const result = await invoke();
        expect(result.status).toBe(fault === 'missing' ? 'not_observed' : fault === 'disagreement' ? 'disagreement'
          : fault === 'rpc-error' || fault === 'expired-finality' ? 'unavailable' : 'observed');
        expect(result.settlement).toBe('not_assessed');
        expect(JSON.stringify(result)).not.toContain('private provider');
      }
      expect(receipt).toHaveBeenCalledTimes(fault === 'held' ? 0 : 2);
      if (['held', 'missing', 'disagreement', 'rpc-error'].includes(fault)) expect(finality).not.toHaveBeenCalled();
      expect((await rows()).results[0].state).toBe(fault === 'held' ? 'held' : 'delivery_pending');
    });
  it('consumes the private delivery token once across concurrent requests', async () => {
    const s = await setup(), a = await s.signed(), held = await s.repository().reserve(s.accountId, a);
    const claim = await s.repository().beginDelivery(a.request.wallet_id, s.accountId, await deliveryProof(s, a, held.id));
    await expect(s.repository().consumeDelivery(a.request.wallet_id, s.accountId, held.id, `0x${'ab'.repeat(32)}`)).rejects.toThrow();
    expect((await rows()).results[0].delivery_dispatched_at).toBeNull();
    const competing = await Promise.allSettled([s.repository().consumeDelivery(a.request.wallet_id, s.accountId, held.id, claim.claim_token),
      s.repository().consumeDelivery(a.request.wallet_id, s.accountId, held.id, claim.claim_token)]);
    expect(competing.filter(r => r.status === 'fulfilled')).toHaveLength(1);
    expect((await rows()).results[0].delivery_dispatched_at).toBe(s.f.now + 1);
    expect((await rows()).results[0].state).toBe('delivery_pending');
  });
  it('does not consume a claim after the preflight deadline even while the signature remains valid', async () => {
    const s = await setup(), a = await s.signed(), held = await s.repository().reserve(s.accountId, a);
    const claim = await s.repository().beginDelivery(a.request.wallet_id, s.accountId, await deliveryProof(s, a, held.id));
    s.clock.mockReturnValue(claim.expires_at * 1000);
    await expect(s.repository().consumeDelivery(a.request.wallet_id, s.accountId, held.id, claim.claim_token)).rejects.toThrow();
    expect((await rows()).results[0].delivery_dispatched_at).toBeNull();
    expect((await rows()).results[0].state).toBe('delivery_pending');
  });
  it.each(['accepted', 'timeout', 'wrong-hash', 'rpc-error', 'abort'])(
    'persists dispatch before a single bundler request and keeps outcome %s unconfirmed', async fault => {
      const s = await setup(), a = await s.signed(), held = await s.repository().reserve(s.accountId, a);
      const proof = await deliveryProof(s, a, held.id);
      const profile: TransferPreflightProfile = { document: s.f.approval.security_evidence.document, digest: a.deployment_digest,
        finalityPolicy: s.f.approval.security_evidence.finality_policy, entryPointCodeHash: `0x${'ee'.repeat(32)}`,
        providers: [{ operatorId: 'provider-a', url: 'https://a.example/rpc' }, { operatorId: 'provider-b', url: 'https://b.example/rpc' }],
        assetIds: [a.request.asset_id], assetDisplay: { [a.request.asset_id]: { symbol: 'ETH', decimals: 18 } }, transport: { kind: 'bundler' as const, url: 'https://bundler.example/rpc' } };
      vi.spyOn(preflightReader, 'preflightOwnedTransfer').mockResolvedValue({ ...proof, operation: a.operation,
        checkpoint: s.f.approval.security_evidence.finality.target, simulation: { ...proof.simulation, gas: {}, send_enabled: false }, send_enabled: false });
      const controller = new AbortController();
      const fetcher = vi.fn(async (_url: RequestInfo | URL, init?: RequestInit) => {
        expect((await rows()).results[0].delivery_dispatched_at).toBe(s.f.now + 1);
        expect(JSON.parse(String(init?.body))).toEqual({ jsonrpc: '2.0', id: 1, method: 'eth_sendUserOperation',
          params: [formatUserOperationRequest(a.operation), a.plan.entryPoint] });
        if (fault === 'timeout') throw new DOMException('Timeout', 'TimeoutError');
        if (fault === 'abort') controller.abort();
        return Response.json({ jsonrpc: '2.0', id: 1, result: fault === 'wrong-hash' ? `0x${'ee'.repeat(32)}` : a.userOpHash,
          ...(fault === 'rpc-error' ? { error: { code: -32500, message: 'rejected' } } : {}) });
      });
      vi.stubGlobal('fetch', fetcher);
      const result = await deliverOwnedTransfer(env.WALLET_DB, s.identity, a.request.wallet_id, s.accountId, held.id, [profile], controller.signal);
      expect(result).toEqual({ operation_id: held.id, userop_hash: a.userOpHash,
        delivery: fault === 'accepted' ? 'accepted' : 'uncertain', settlement: 'unconfirmed' });
      expect(fetcher).toHaveBeenCalledTimes(1);
      await expect(deliverOwnedTransfer(env.WALLET_DB, s.identity, a.request.wallet_id, s.accountId, held.id, [profile], new AbortController().signal))
        .rejects.toThrow('TRANSFER_DELIVERY_ALREADY_CLAIMED');
      expect(fetcher).toHaveBeenCalledTimes(1);
      expect((await rows()).results[0].state).toBe('delivery_pending');
    });
  it('grants a single durable delivery claim and keeps uncertain funds after signed expiry', async () => {
    const s = await setup(), a = await s.signed(), held = await s.repository().reserve(s.accountId, a);
    const proof = await deliveryProof(s, a, held.id);
    const competing = await Promise.allSettled([s.repository().beginDelivery(a.request.wallet_id, s.accountId, proof),
      s.repository().beginDelivery(a.request.wallet_id, s.accountId, proof)]);
    expect(competing.filter(r => r.status === 'fulfilled')).toHaveLength(1);
    const won = competing.find(r => r.status === 'fulfilled');
    if (!won || won.status !== 'fulfilled') throw new Error('Expected one claim');
    const row = (await rows()).results[0];
    expect(row.state).toBe('delivery_pending');
    expect(row.delivery_token_sha256).toBe(deploymentDocumentDigest(won.value.claim_token));
    expect(JSON.stringify(row)).not.toContain(won.value.claim_token);
    await expect(s.repository().beginDelivery(a.request.wallet_id, s.accountId, proof)).rejects.toThrow('TRANSFER_DELIVERY_ALREADY_CLAIMED');
    s.clock.mockReturnValue((a.plan.validUntil + 1) * 1000);
    expect((await s.repository().readOwned(a.request.wallet_id, s.accountId, held.id)).state).toBe('delivery_pending');
    expect(await s.repository().reservedFunds(a.request.wallet_id, s.accountId, [a.request.asset_id]))
      .toEqual([{ asset_id: a.request.asset_id, amount_atomic: '1010' }]);
    await expect(s.repository().deliveryFundsSnapshot(a.request.wallet_id, s.accountId, held.id)).rejects.toThrow();
    const reserved = [{ asset_id: a.request.asset_id, amount_atomic: '1010' }];
    await expect(s.repository().reserve(s.accountId, await s.signed('20', s.f.now + 30, { nonce: 0n, reserved })))
      .rejects.toThrow('TRANSFER_RESERVATION_CONCURRENT_CHANGE');
    await s.repository().reserve(s.accountId, await s.signed('20', s.f.now + 30, { nonce: 1n, reserved }));
    expect((await s.repository().readOwned(a.request.wallet_id, s.accountId, held.id)).state).toBe('delivery_pending');
    expect(await s.repository().reservedFunds(a.request.wallet_id, s.accountId, [a.request.asset_id]))
      .toEqual([{ asset_id: a.request.asset_id, amount_atomic: '2030' }]);
  });
  it('rejects a delivery claim if another reservation changed the funds snapshot', async () => {
    const s = await setup(), a = await s.signed(), held = await s.repository().reserve(s.accountId, a);
    const proof = await deliveryProof(s, a, held.id);
    const reserved = await s.repository().reservedFunds(a.request.wallet_id, s.accountId, [a.request.asset_id]);
    await s.repository().reserve(s.accountId, await s.signed('20', undefined, { nonce: 1n, reserved }));
    await expect(s.repository().beginDelivery(a.request.wallet_id, s.accountId, proof)).rejects.toThrow('TRANSFER_DELIVERY_CONCURRENT_CHANGE');
    expect((await rows()).results.every(r => r.state === 'held')).toBe(true);
  });
  it.each(['expired', 'wrong-simulation', 'nan-time', 'foreign-wallet'])(
    'does not mutate a hold when delivery preflight is %s', async fault => {
      const s = await setup(), a = await s.signed(), held = await s.repository().reserve(s.accountId, a);
      const proof = await deliveryProof(s, a, held.id);
      if (fault === 'expired') s.clock.mockReturnValue(proof.expires_at * 1000);
      if (fault === 'wrong-simulation') proof.simulation.operation_sha256 = `0x${'dd'.repeat(32)}`;
      if (fault === 'nan-time') proof.checked_at = NaN;
      await expect(s.repository().beginDelivery(fault === 'foreign-wallet' ? createResourceId('wallet') : a.request.wallet_id, s.accountId, proof)).rejects.toThrow();
      expect((await rows()).results[0].state).toBe('held');
      expect((await rows()).results[0].delivery_token_sha256).toBeNull();
    });
  it.each(['success', 'simulation-failed', 'stale-simulation', 'wrong-signed-bytes', 'wrong-operation'])(
    'requires both current observation and exact-byte simulation: %s', async fault => {
      const s = await setup(), a = await s.signed(), held = await s.repository().reserve(s.accountId, a), now = s.f.now + 1;
      const payload = writeTransferOperationRecord(a.operation, { network_id: a.request.network_id, account: a.account,
        account_id: a.plan.accountId, entry_point: a.plan.entryPoint, userop_hash: a.userOpHash, consent_digest: a.digest, valid_until: a.plan.validUntil });
      const profile: TransferPreflightProfile = { document: s.f.approval.security_evidence.document, digest: a.deployment_digest,
        finalityPolicy: s.f.approval.security_evidence.finality_policy, entryPointCodeHash: `0x${'ee'.repeat(32)}`,
        providers: [{ operatorId: 'provider-a', url: 'https://a.example/rpc' }, { operatorId: 'provider-b', url: 'https://b.example/rpc' }],
        assetIds: [a.request.asset_id], assetDisplay: { [a.request.asset_id]: { symbol: 'ETH', decimals: 18 } }, transport: { kind: 'bundler' as const, url: 'https://bundler.example/rpc' } };
      vi.spyOn(deliveryReader, 'observeOwnedTransferDelivery').mockResolvedValue({ userop_hash: a.userOpHash, consent_digest: a.digest,
        operation: a.operation, operation_id: fault === 'wrong-operation' ? createResourceId('operation') : held.id,
        checkpoint: s.f.approval.security_evidence.finality.target, checked_at: now, expires_at: now + 5,
        reservation_fingerprint: 'synthetic-private-snapshot', reservation_observed_at: now, send_enabled: false });
      vi.spyOn(simulationReader, 'simulateTransferOperation').mockImplementation(async () => {
        if (fault === 'simulation-failed') throw new Error('rejected');
        return { userop_hash: a.userOpHash, consent_digest: a.digest,
          operation_sha256: fault === 'wrong-signed-bytes' ? `0x${'dd'.repeat(32)}` : payload.digest,
          gas: { verificationGasLimit: '100', callGasLimit: '100', preVerificationGas: '100' },
          observed_at: now, expires_at: fault === 'stale-simulation' ? now : now + 4, send_enabled: false };
      });
      const result = preflightOwnedTransfer(env.WALLET_DB, s.identity, a.request.wallet_id, s.accountId, held.id, [profile], new AbortController().signal);
      if (fault === 'success') {
        const checked = await result;
        expect(checked.operation).toEqual(a.operation); expect(checked.expires_at).toBe(now + 4); expect(checked.send_enabled).toBe(false);
      } else await expect(result).rejects.toThrow();
      expect((await rows()).results[0].state).toBe('held');
    });
  it('does not contact RPC without an owned reservation and a matching admitted profile', async () => {
    const s = await setup(), a = await s.signed();
    const held = await s.repository().reserve(s.accountId, a);
    const fetcher = vi.fn(); vi.stubGlobal('fetch', fetcher);
    await expect(observeOwnedTransferDelivery(env.WALLET_DB, s.identity, s.f.request.wallet_id, s.accountId,
      held.id, [], new AbortController().signal)).rejects.toThrow('TRANSFER_DELIVERY_PROFILE_UNAVAILABLE');
    expect(fetcher).not.toHaveBeenCalled();
  });
  it.each(['success', 'balance-failure', 'spent-nonce', 'revoked-owner', 'aborted'])(
    'composes owned delivery checks with synthetic observers and real D1: %s', async fault => {
      const s = await setup(), a = await s.signed(), held = await s.repository().reserve(s.accountId, a);
      const now = s.f.now + 1, checkpoint = { block_number: '124', block_hash: `0x${'dd'.repeat(32)}` as const, block_timestamp: String(s.f.now) };
      const source = { ...s.f.approval.security_evidence.finality, assessed_at: now, expires_at: now + 30, checkpoint };
      const closing = { ...source, target: checkpoint };
      const profile: TransferDeliveryProfile = { document: s.f.approval.security_evidence.document, digest: a.deployment_digest,
        finalityPolicy: s.f.approval.security_evidence.finality_policy, entryPointCodeHash: `0x${'ee'.repeat(32)}`,
        providers: [{ operatorId: 'provider-a', url: 'https://a.example/rpc' }, { operatorId: 'provider-b', url: 'https://b.example/rpc' }],
        assetIds: [a.request.asset_id], assetDisplay: { [a.request.asset_id]: { symbol: 'ETH', decimals: 18 } } };
      vi.spyOn(finalityReader, 'assessCheckpointFinality').mockResolvedValue(source);
      vi.spyOn(securityReader, 'inspectOwnedWalletAccount').mockResolvedValue({ ...s.f.approval.security_evidence.observation,
        checkpoint, wallet_id: a.request.wallet_id, wallet_account_id: s.accountId, finality: 'finalized', finality_evidence: closing,
        security_observed_at: now, security_expires_at: now + 30, providers_agree: true });
      vi.spyOn(nonceReader, 'observeTransferNonce').mockResolvedValue({ ...s.f.approval.nonce_evidence,
        checkpoint, observed_at: now, nonce: fault === 'spent-nonce' ? '1' : '0' });
      vi.spyOn(balanceReader, 'inspectOwnedWalletBalances').mockImplementation(async () => {
        if (fault === 'balance-failure') throw new Error('unavailable');
        if (fault === 'revoked-owner') await env.WALLET_DB.prepare("UPDATE wallets SET status = 'archived' WHERE id = ?").bind(a.request.wallet_id).run();
        return { ...s.f.approval.balance_evidence, wallet_account_id: s.accountId, checkpoint, observed_at: now, expires_at: now + 30,
          balances: s.f.approval.balance_evidence.balances.map(b => ({ ...b, symbol: 'ETH', decimals: 18 })),
          spend_readiness: 'not_assessed', finality: 'finalized', finality_evidence: closing, available_balance: 'not_assessed' };
      });
      const fetcher = vi.fn(async (_url: RequestInfo | URL, init?: RequestInit) => {
        const call: { id: number; method: string } = JSON.parse(String(init?.body));
        expect(call.method).toBe('eth_getBlockByNumber');
        return Response.json({ jsonrpc: '2.0', id: call.id, result: { number: '0x7b', hash: a.checkpoint.block_hash,
          timestamp: `0x${BigInt(source.target.block_timestamp).toString(16)}` } });
      });
      vi.stubGlobal('fetch', fetcher);
      const controller = new AbortController(); if (fault === 'aborted') controller.abort();
      const result = observeOwnedTransferDelivery(env.WALLET_DB, s.identity, a.request.wallet_id, s.accountId, held.id, [profile], controller.signal);
      if (fault === 'success') {
        const checked = await result;
        expect(checked.operation).toEqual(a.operation); expect(checked.send_enabled).toBe(false);
        expect(checked.reservation_fingerprint).toContain(held.id);
        expect(checked.checkpoint).toEqual(checkpoint);
        expect((await rows()).results[0].state).toBe('held');
      } else await expect(result).rejects.toThrow();
      if (fault === 'aborted') expect(fetcher).not.toHaveBeenCalled();
    });
  it('snapshots own and total live funds without granting delivery or changing the reservation', async () => {
    const s = await setup(), a = await s.signed();
    const held = await s.repository().reserve(s.accountId, a);
    const reserved = await s.repository().reservedFunds(s.f.request.wallet_id, s.accountId, [s.f.request.asset_id]);
    const b = await s.signed('20', undefined, { nonce: 1n, reserved });
    await s.repository().reserve(s.accountId, b);
    const before = await rows();
    const snapshot = await s.repository().deliveryFundsSnapshot(s.f.request.wallet_id, s.accountId, held.id);
    expect(snapshot.own_funds).toEqual(a.funding_reservation);
    expect(snapshot.total_reserved).toEqual([{ asset_id: s.f.request.asset_id, amount_atomic: '2030' }]);
    expect(snapshot.fingerprint).toContain(held.id);
    expect(snapshot.send_enabled).toBe(false);
    expect(snapshot.expires_at).toBe(s.f.now + 6);
    expect((await rows()).results).toEqual(before.results);
    s.clock.mockReturnValue(a.plan.validUntil * 1000);
    await expect(s.repository().deliveryFundsSnapshot(s.f.request.wallet_id, s.accountId, held.id)).rejects.toThrow('TRANSFER_RESERVATION_EXPIRED');
  });
  it('atomically rejects concurrent stale budgets even when both nonces differ', async () => {
    const s = await setup();
    const a = await s.signed('6000'), b = await s.signed('6000', undefined, { nonce: 1n });
    const results = await Promise.allSettled([s.repository().reserve(s.accountId, a), s.repository().reserve(s.accountId, b)]);
    expect(results.filter(r => r.status === 'fulfilled')).toHaveLength(1);
    expect((await rows()).results).toHaveLength(1);
    const held = await s.repository().reservedFunds(s.f.request.wallet_id, s.accountId, [s.f.request.asset_id]);
    expect(held).toEqual([{ asset_id: s.f.request.asset_id, amount_atomic: '7000' }]);
    const fresh = await s.signed('2000', undefined, { nonce: 2n, reserved: held });
    await expect(s.repository().reserve(s.accountId, fresh)).resolves.toMatchObject({ state: 'held' });
    expect(await s.repository().reservedFunds(s.f.request.wallet_id, s.accountId, [s.f.request.asset_id]))
      .toEqual([{ asset_id: s.f.request.asset_id, amount_atomic: '10000' }]);
    expect((await rows()).results).toHaveLength(2);
  });
  it('requires a fresh quote after another hold, rather than silently reducing the transfer', async () => {
    const s = await setup(), a = await s.signed(), stale = await s.signed('10', undefined, { nonce: 1n });
    await s.repository().reserve(s.accountId, a);
    await expect(s.repository().reserve(s.accountId, stale)).rejects.toThrow('TRANSFER_FUNDS_CHANGED');
    expect((await rows()).results).toHaveLength(1);
  });
  it('reserves all available native funds for MAX including its bounded gas budget', async () => {
    const s = await setup(), a = await s.signed('0', undefined, { max: true });
    expect(a.funding.amount_atomic).toBe('9000');
    await s.repository().reserve(s.accountId, a);
    expect(await s.repository().reservedFunds(s.f.request.wallet_id, s.accountId, [s.f.request.asset_id]))
      .toEqual([{ asset_id: s.f.request.asset_id, amount_atomic: '10000' }]);
  });
  it('rejects an internally inconsistent hold before writing it', async () => {
    const s = await setup(), a = await s.signed();
    await expect(s.repository().reserve(s.accountId, { ...a,
      funding_reservation: a.funding_reservation.map(row => ({ ...row, debit_atomic: '1' })) })).rejects.toThrow('TRANSFER_FUNDS_INVALID');
    expect((await rows()).results).toHaveLength(0);
  });
  it('reserves ERC20 and native gas separately and releases expired holds on read without deleting history', async () => {
    const s = await setup(false), a = await s.signed();
    await s.repository().reserve(s.accountId, a);
    const assets = [s.f.request.asset_id, s.f.context.native_asset_id];
    expect(await s.repository().reservedFunds(s.f.request.wallet_id, s.accountId, assets)).toEqual([
      { asset_id: assets[0], amount_atomic: '10' }, { asset_id: assets[1], amount_atomic: '1000' },
    ]);
    s.clock.mockReturnValue(a.plan.validUntil * 1000);
    expect(await s.repository().reservedFunds(s.f.request.wallet_id, s.accountId, assets))
      .toEqual(assets.map(asset_id => ({ asset_id, amount_atomic: '0' })));
    expect((await rows()).results).toHaveLength(1);
  });
  it('does not allow repricing an existing funds hold', async () => {
    const s = await setup(), a = await s.signed(); await s.repository().reserve(s.accountId, a);
    await expect(env.WALLET_DB.prepare("UPDATE transfer_nonce_reservations SET funds_json = '[]'").run()).rejects.toThrow();
    expect(await s.repository().reservedFunds(s.f.request.wallet_id, s.accountId, [s.f.request.asset_id]))
      .toEqual([{ asset_id: s.f.request.asset_id, amount_atomic: '1010' }]);
  });
  it('reverifies the stored consent even if its checksum was replaced', async () => {
    const s = await setup(), a = await s.signed(), result = await s.repository().reserve(s.accountId, a);
    const stored = (await rows()).results[0];
    const data: { context: { nonce: string } } = JSON.parse(String(stored.review_json));
    data.context.nonce = '1';
    const json = JSON.stringify(data);
    await env.WALLET_DB.prepare('UPDATE transfer_nonce_reservations SET review_json = ?,review_sha256 = ? WHERE id = ?')
      .bind(json, deploymentDocumentDigest(json), result.id).run();
    await expect(s.repository().readOwned(s.f.request.wallet_id, s.accountId, result.id)).rejects.toThrow();
    await expect(s.repository().reserve(s.accountId, a)).rejects.toThrow();
  });
  it('returns one stable locator across concurrent retries, never a send grant', async () => {
    const s = await setup(), a = await s.signed();
    const results = await Promise.all(Array.from({ length: 5 }, () => s.repository().reserve(s.accountId, a)));
    expect(new Set(results.map(r => r.id)).size).toBe(1);
    expect(results[0]).toMatchObject({ state: 'held', send_enabled: false, expires_at: a.plan.validUntil });
    expect((await rows()).results).toHaveLength(1);
    expect(await s.repository().reserve(s.accountId, a)).toEqual(results[0]);
    const restored = await s.repository().readOwned(s.f.request.wallet_id, s.accountId, results[0].id);
    expect(restored.operation).toEqual(a.operation); expect(restored.plan).toEqual(a.plan);
    expect(restored.send_enabled).toBe(false);
  });
  it('preserves the first envelope when another valid quorum signs the identical consent', async () => {
    const s = await setup(), a = await s.signed();
    const first = await s.repository().reserve(s.accountId, a);
    const proofs = await Promise.all(s.f.f.keys.map(async key => ({ kind: 'ecdsa' as const,
      signerIndex: s.f.approval.policy.signers.findIndex(member => member.key === key.address.toLowerCase()),
      signature: await key.sign({ hash: a.digest }) })));
    const b = await authorizeTransferOperation(s.f.request, s.f.context, s.f.approval, proofs, () => s.f.now + 1);
    expect(b.digest).toBe(a.digest); expect(b.operation.signature).not.toBe(a.operation.signature);
    expect(await s.repository().reserve(s.accountId, b)).toEqual(first);
    expect((await s.repository().readOwned(s.f.request.wallet_id, s.accountId, first.id)).operation.signature).toBe(a.operation.signature);
  });
  it('restores expired history without renewing its deadline or changing stored state', async () => {
    const s = await setup(), a = await s.signed(), result = await s.repository().reserve(s.accountId, a);
    const before = await rows(); s.clock.mockReturnValue(a.plan.validUntil * 1000);
    expect(await s.repository().readOwned(s.f.request.wallet_id, s.accountId, result.id)).toMatchObject({ state: 'expired', send_enabled: false });
    expect((await rows()).results).toEqual(before.results);
  });
  it.each(['foreign', 'other-account', 'corrupt', 'nonce', 'manifest'])('refuses an unrelated or damaged stored envelope: %s', async fault => {
    const s = await setup(), a = await s.signed(), result = await s.repository().reserve(s.accountId, a);
    let repository = s.repository(), accountId = s.accountId;
    if (fault === 'foreign') repository = new TransferNonceReservationRepository(env.WALLET_DB, { ...s.identity, userId: 'other' });
    if (fault === 'other-account') accountId = createResourceId('walletAccount');
    if (fault === 'corrupt') await env.WALLET_DB.prepare("UPDATE transfer_nonce_reservations SET operation_json = '{}' WHERE id = ?").bind(result.id).run();
    if (fault === 'nonce') await env.WALLET_DB.prepare("UPDATE transfer_nonce_reservations SET nonce = '1' WHERE id = ?").bind(result.id).run();
    if (fault === 'manifest') await env.WALLET_DB.prepare('UPDATE transfer_nonce_reservations SET deployment_manifest_sha256 = ? WHERE id = ?')
      .bind(`0x${'ee'.repeat(32)}`, result.id).run();
    await expect(repository.readOwned(s.f.request.wallet_id, accountId, result.id)).rejects.toThrow();
  });
  it('allows exactly one of two independently signed spends with the same nonce', async () => {
    const s = await setup(), a = await s.signed(), b = await s.signed('11');
    const results = await Promise.allSettled([s.repository().reserve(s.accountId, a), s.repository().reserve(s.accountId, b)]);
    expect(results.filter(r => r.status === 'fulfilled')).toHaveLength(1);
    expect(results.filter(r => r.status === 'rejected')).toHaveLength(1);
    expect((await rows()).results).toHaveLength(1);
  });
  it('releases only expired never-dispatched claims and retains their history', async () => {
    const s = await setup(), a = await s.signed('10', s.f.now + 3);
    const first = await s.repository().reserve(s.accountId, a);
    s.clock.mockReturnValue((s.f.now + 4) * 1000);
    const b = await s.signed('11');
    const next = await s.repository().reserve(s.accountId, b);
    expect(next.id).not.toBe(first.id);
    const records = (await rows()).results;
    expect(records).toHaveLength(2);
    expect(records.find(r => r.id === first.id)?.state).toBe('expired');
    expect(records.find(r => r.id === next.id)?.state).toBe('held');
    await expect(s.repository().reserve(s.accountId, a)).rejects.toThrow('TRANSFER_RESERVATION_INVALID');
  });
  it('rolls back expiry when the next insert fails', async () => {
    const s = await setup(), a = await s.signed('10', s.f.now + 3);
    await s.repository().reserve(s.accountId, a);
    s.clock.mockReturnValue((s.f.now + 4) * 1000);
    const b = await s.signed('11');
    await env.WALLET_DB.exec(`CREATE TRIGGER reject_transfer_claim BEFORE INSERT ON transfer_nonce_reservations BEGIN SELECT RAISE(ABORT, 'synthetic write failure'); END;`);
    try {
      await expect(s.repository().reserve(s.accountId, b)).rejects.toThrow();
      expect((await rows()).results.map(r => r.state)).toEqual(['held']);
    } finally { await env.WALLET_DB.exec('DROP TRIGGER reject_transfer_claim'); }
    await expect(s.repository().reserve(s.accountId, b)).resolves.toMatchObject({ state: 'held' });
  });
  it.each(['foreign', 'revoked', 'archived', 'pin'])('rejects a changed access context: %s', async fault => {
    const s = await setup(), a = await s.signed();
    let repository = s.repository();
    if (fault === 'foreign') repository = new TransferNonceReservationRepository(env.WALLET_DB, { ...s.identity, userId: 'other' });
    if (fault === 'revoked') await env.WALLET_DB.prepare('UPDATE users SET auth_not_before = ? WHERE id = ?')
      .bind(s.f.now, s.session.user_id).run();
    if (fault === 'archived') await env.WALLET_DB.prepare("UPDATE wallets SET status = 'archived' WHERE id = ?").bind(s.f.request.wallet_id).run();
    if (fault === 'pin') await env.WALLET_DB.prepare('UPDATE wallet_accounts SET deployment_manifest_sha256 = ?')
      .bind(`0x${'ee'.repeat(32)}`).run();
    await expect(repository.reserve(s.accountId, a)).rejects.toThrow();
    expect((await rows()).results).toHaveLength(0);
  });
  it('rejects a consent that expires during the D1 round trip', async () => {
    const s = await setup(), a = await s.signed();
    const original = WalletRepository.prototype.ownedAccount;
    let reads = 0;
    vi.spyOn(WalletRepository.prototype, 'ownedAccount').mockImplementation(async function (this: WalletRepository, ...args) {
      const result = await original.apply(this, args);
      if (++reads === 2) s.clock.mockReturnValue(a.plan.validUntil * 1000);
      return result;
    });
    await expect(s.repository().reserve(s.accountId, a)).rejects.toThrow('TRANSFER_RESERVATION_INVALID');
  });
  it('withholds the locator when identity is revoked concurrently with insertion', async () => {
    const s = await setup(), a = await s.signed();
    await env.WALLET_DB.exec(`CREATE TRIGGER revoke_transfer_owner AFTER INSERT ON transfer_nonce_reservations BEGIN UPDATE users SET disabled_at = 1; END;`);
    try {
      await expect(s.repository().reserve(s.accountId, a)).rejects.toThrow();
      // The claim has no send authority and retains history even when access is revoked.
      expect((await rows()).results).toHaveLength(1);
    } finally { await env.WALLET_DB.exec('DROP TRIGGER revoke_transfer_owner'); }
  });
  it.each(['unsigned', 'nonce', 'expired'])('refuses an invalid private candidate: %s', async fault => {
    const s = await setup(); let a = structuredClone(await s.signed());
    if (fault === 'unsigned') a = { ...a, operation: { ...a.operation, signature: '0x' } };
    if (fault === 'nonce') a = { ...a, operation: { ...a.operation, nonce: a.operation.nonce + 1n } };
    if (fault === 'expired') s.clock.mockReturnValue(a.plan.validUntil * 1000);
    await expect(s.repository().reserve(s.accountId, a)).rejects.toThrow('TRANSFER_RESERVATION_INVALID');
    expect((await rows()).results).toHaveLength(0);
  });
});
