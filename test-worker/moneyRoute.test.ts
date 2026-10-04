import { applyD1Migrations } from 'cloudflare:test';
import { env } from 'cloudflare:workers';
import { afterEach, beforeAll, beforeEach, describe, expect, it, vi } from 'vitest';
import { parseEnvironment } from '@gatopago/environment';
import manifests from '@gatopago/environment/environments.json';
import {
  clientMutationHeaders,
  CLIENT_RELEASE_ID,
  CLIENT_RELEASE_HEADERS,
} from '@gatopago/shared/v3/client-release';
import { serializeTransferConfirmation } from '@gatopago/shared/v3/transfer-wire';
import { createResourceId } from '@gatopago/shared/v3/primitives';
import { MoneyRepository } from '../src/money/moneyRepository';
import { createMoneyRoute } from '../src/money/moneyRoute';
import { readOwnedMoneyStatus } from '../src/money/moneyStatus';
import * as session from '../src/auth/session';
import * as preparation from '../src/money/moneyPreparation';
import * as confirmation from '../src/money/moneyConfirmation';
import * as delivery from '../src/money/moneyDelivery';
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
describe('Owner-only money HTTP commands and history', () => {
  it.each([
    'prepare',
    'prepare-retry',
    'read',
    'confirm',
    'deliver',
    'status',
    'origin',
    'query',
    'method',
    'options',
    'bad-cors',
    'version',
    'wallet',
    'account',
    'extra-fields',
    'size',
    'no-key',
    'foreign',
    'disabled',
    'digest',
    'confirm-release',
    'deliver-release',
  ])('enforces %s', async (fault) => {
    const s = await seedMoneyDelivery(env.WALLET_DB, false),
      f = s.f;
    if (fault === 'prepare')
      await env.WALLET_DB.exec('DELETE FROM money_operations; DELETE FROM wallet_spend_locks;');
    const config = parseEnvironment({
      ...manifests.production,
      status: 'provisioned',
      firebase_project_id: 'v3-runtime-test',
      wallet_enabled: [f.request.network_id],
    });
    vi.spyOn(session, 'verifyAppSession').mockResolvedValue(
      fault === 'foreign' ? { ...f.identity, userId: 'another-user' } : f.identity,
    );
    const profile = {
      ...s.profile,
      environment: 'production' as const,
      features:
        fault === 'disabled'
          ? { aave_supply: false, aave_withdraw: false, aave_withdraw_and_pay: false }
          : s.profile.features,
    };
    const block = {
      block_hash: f.context.checkpoint.block_hash,
      block_number: f.context.checkpoint.block_number,
      block_timestamp: String(f.now),
    };
    const resolve = vi.fn(async () => ({
      schema_version: 1 as const,
      status: 'finalized' as const,
      policy_sha256: profile.finalityPolicy.digest,
      mechanism: s.policy.mechanism,
      network_id: f.request.network_id,
      genesis_hash: s.market.genesis_hash,
      target: block,
      checkpoint: block,
      assessed_at: f.now,
      expires_at: f.now + 10,
    }));
    const route = createMoneyRoute({ profiles: [profile], resolvePreparation: resolve });
    const prepare = vi
      .spyOn(preparation, 'prepareOwnedMoney')
      .mockResolvedValue({
        candidate: f.candidate,
        review: f.review,
        evidence: {} as Awaited<ReturnType<typeof preparation.prepareOwnedMoney>>['evidence'],
        send_enabled: false,
      });
    const confirm = vi
      .spyOn(confirmation, 'confirmOwnedMoney')
      .mockResolvedValue({
        id: s.stored.id,
        preparation_id: s.stored.preparation_id,
        consent_digest: f.candidate.digest,
        state: 'authorized',
        expires_at: f.context.valid_until,
        send_enabled: false,
      });
    const deliver = vi
      .spyOn(delivery, 'deliverOwnedMoney')
      .mockResolvedValue({
        money_schema_version: 1,
        operation_id: s.stored.id,
        userop_hash: f.candidate.userOpHash,
        state: 'dispatch_pending',
        delivery: 'accepted',
        settlement: 'unconfirmed',
      });
    const root = `/app/v1/wallets/${f.walletId}/accounts/${f.accountId}`;
    let path = `${root}/money-preparations`,
      method = 'POST',
      body: unknown = f.request,
      key = 'prepare-another';
    if (fault === 'prepare-retry') key = 'prepare';
    if (fault === 'read') {
      path += `/${s.stored.preparation_id}`;
      method = 'GET';
    }
    if (fault.startsWith('confirm')) {
      path += `/${s.stored.preparation_id}/confirm`;
      key = 'confirm';
      body = {
        money_schema_version: 1,
        ...serializeTransferConfirmation(f.candidate.digest, [
          { signerIndex: 0, kind: 'webauthn', assertion: f.keys.assertion(f.candidate.digest) },
        ]),
      };
    }
    if (fault.startsWith('deliver') || fault === 'digest') {
      path = `${root}/money-operations/${s.stored.id}/deliver`;
      body = {
        money_schema_version: 1,
        consent_digest: fault === 'digest' ? f.hash : f.candidate.digest,
      };
    }
    if (fault === 'status') {
      path = `${root}/money-operations/${s.stored.id}`;
      method = 'GET';
    }
    if (fault === 'method') method = 'GET';
    if (['options', 'bad-cors'].includes(fault)) method = 'OPTIONS';
    if (fault === 'wallet') body = { ...f.request, wallet_id: createResourceId('wallet') };
    if (fault === 'account')
      body = { ...f.request, wallet_account_id: createResourceId('walletAccount') };
    if (fault === 'extra-fields') body = { ...f.request, calls: [] };
    const headers = new Headers({
      Origin: fault === 'origin' ? 'https://wrong.example' : config.web_origin,
      'Content-Type': 'application/json',
      'Idempotency-Key': key,
      Authorization: 'Bearer synthetic',
      ...clientMutationHeaders('production', {
        generation: '3',
        contract_manifest_version: f.keys.profile.deployment.manifest_id,
      }),
      'Access-Control-Request-Method': 'POST',
      'Access-Control-Request-Headers':
        fault === 'bad-cors' ? 'X-Arbitrary' : 'Authorization,Content-Type,Idempotency-Key',
    });
    if (fault === 'no-key') headers.delete('Idempotency-Key');
    headers.set(
      CLIENT_RELEASE_HEADERS.release,
      fault === 'version' || fault.endsWith('-release') ? 'outdated' : CLIENT_RELEASE_ID,
    );
    const response = await route(
      new Request(`${config.api_origin}${path}${fault === 'query' ? '?rpc=override' : ''}`, {
        method,
        headers,
        ...(method === 'POST'
          ? { body: fault === 'size' ? ' '.repeat(8193) : JSON.stringify(body) }
          : {}),
      }),
      { ...env, FIREBASE_PROJECT_ID: 'v3-runtime-test' },
      config,
    );
    const codes: Record<string, number> = {
      origin: 403,
      query: 404,
      method: 405,
      options: 200,
      'bad-cors': 403,
      version: 409,
      wallet: 400,
      account: 400,
      'extra-fields': 400,
      size: 413,
      'no-key': 400,
      foreign: 409,
      disabled: 503,
      digest: 409,
      'confirm-release': 409,
      'deliver-release': 409,
      deliver: 202,
    };
    expect(response.status).toBe(codes[fault] ?? 200);
    expect(response.headers.get('Cache-Control')).toBe('no-store');
    if (fault !== 'options') {
      const value = await response.json();
      if (fault === 'read' || fault === 'prepare-retry')
        expect(value).toMatchObject({ operation_id: s.stored.id });
      if (fault === 'prepare') expect(value).toMatchObject({ operation_id: null });
      expect(JSON.stringify(value)).not.toContain(s.stored.operation.signature);
      expect(JSON.stringify(value)).not.toContain('https://a.example');
      expect(JSON.stringify(value)).not.toContain('Bearer synthetic');
    }
    expect(prepare).toHaveBeenCalledTimes(fault === 'prepare' ? 1 : 0);
    expect(resolve).toHaveBeenCalledTimes(fault === 'prepare' ? 1 : 0);
    expect(confirm).toHaveBeenCalledTimes(fault === 'confirm' ? 1 : 0);
    expect(deliver).toHaveBeenCalledTimes(fault === 'deliver' ? 1 : 0);
  });
  it('restores owner-bound history after expiry without RPC, replay, signature exposure or releasing funds', async () => {
    const s = await seedMoneyDelivery(env.WALLET_DB),
      fetch = vi.spyOn(globalThis, 'fetch');
    vi.spyOn(Date, 'now').mockReturnValue((s.f.context.valid_until + 1) * 1000);
    const repository = new MoneyRepository(
      env.WALLET_DB,
      s.f.identity,
      s.f.keys.input.scope,
      s.f.pins,
    );
    const value = await readOwnedMoneyStatus(
      env.WALLET_DB,
      repository,
      s.f.walletId,
      s.f.accountId,
      s.stored.id,
    );
    expect(value).toMatchObject({
      state: 'dispatch_pending',
      funds_reserved: true,
      settlement: 'unconfirmed',
      send_enabled: false,
    });
    expect(JSON.parse(value.review_json).proofs).toEqual([]);
    expect(value.review_json).not.toContain(s.stored.operation.signature);
    expect(fetch).not.toHaveBeenCalled();
    expect(
      await repository.operationForPreparation(
        s.f.walletId,
        s.f.accountId,
        s.stored.preparation_id,
      ),
    ).toBe(s.stored.id);
    expect(await env.WALLET_DB.prepare('SELECT state FROM wallet_spend_locks').first()).toEqual({
      state: 'dispatch_pending',
    });
  });
});
