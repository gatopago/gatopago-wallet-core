import type { Environment } from '@gatopago/environment';
import { CLIENT_RELEASE_HEADERS } from '@gatopago/shared/v3/client-release';
import { loadPinnedDeploymentManifest } from '@gatopago/shared/v3/deployment';
import { loadAaveMarket } from '@gatopago/shared/v3/aave-market';
import type { FinalityAssessment } from '@gatopago/shared/v3/finality';
import { parseMoneyRequest } from '@gatopago/shared/v3/money-wire';
import { parseResourceId, type ResourceId } from '@gatopago/shared/v3/primitives';
import { readJsonBounded, ResponseBodyTooLargeError } from '@gatopago/shared/http';
import { WalletAccessError, WalletRepository } from '../accounts/repository';
import type { ReceivingProfiles } from '../accounts/profile';
import { validateIdentityConfig, type AuthBindings } from '../auth/config';
import { IdentityError } from '../auth/identity';
import { verifyAppSession } from '../auth/session';
import { requireCurrentProtocol } from '../clientProtocol';
import { withDeadline } from '../deadline';
import { allowMethods, isJsonRequest, v3Json } from '../http';
import { MoneyRepository, moneyIdempotencyKey } from './moneyRepository';
import { prepareOwnedMoney } from './moneyPreparation';
import { confirmOwnedMoney } from './moneyConfirmation';
import { deliverOwnedMoney } from './moneyDelivery';
import { readOwnedMoneyStatus } from './moneyStatus';
import { parseMoneyConfirmation, parseMoneyDelivery } from './moneyWire';
import type { MoneyDeliveryProfile } from './moneyPreflight';

const PATH = /^\/app\/v1\/wallets\/([^/]+)\/accounts\/([^/]+)\/(?:money-preparations(?:\/([^/]+)(\/confirm)?)?|money-operations\/([^/]+)(\/deliver)?)$(?![\s\S])/;
export const isMoneyCommandPath = (path: string) => PATH.test(path);
const headers = ['Authorization', 'Content-Type', 'Idempotency-Key', ...Object.values(CLIENT_RELEASE_HEADERS)];
type Profile = MoneyDeliveryProfile & { readonly environment: Environment['environment'] };

/** Owner/auth/release checks precede every RPC. Commands accept a closed recipe
 * and public assertion transport, never an account context or arbitrary calls. */
export function createMoneyRoute(dependencies: {
  readonly profiles: readonly Profile[]; readonly accessProfiles?: ReceivingProfiles; readonly relayerKey?: `0x${string}`;
  readonly resolvePreparation: (owned: Awaited<ReturnType<WalletRepository['ownedAccount']>>, profile: Profile, signal: AbortSignal) => Promise<FinalityAssessment>;
}) {
  const catalog = structuredClone(dependencies.profiles).map(profile => ({ profile,
    manifest: loadPinnedDeploymentManifest(profile.document, profile.digest), market: loadAaveMarket(profile.market) }));
  if (catalog.length > 32 || new Set(catalog.map(p => `${p.profile.environment}:${p.profile.digest}:${p.profile.market.digest}`)).size !== catalog.length) throw new Error('MONEY_PROFILE_CATALOG');
  return async function route(request: Request, env: AuthBindings, environment: Environment): Promise<Response> {
    let config: Environment;
    try { config = validateIdentityConfig(env, environment); } catch { return v3Json(503, { error_code: 'SERVICE_UNAVAILABLE' }); }
    const url = new URL(request.url), origin = request.headers.get('Origin');
    if (url.origin !== config.api_origin || origin !== config.web_origin || !config.webauthn_allowed_origins.includes(origin)) return v3Json(403, { error_code: 'ORIGIN_NOT_ALLOWED' });
    const respond = (status: number, body: object) => v3Json(status, body, origin), match = PATH.exec(url.pathname);
    if (!match || url.search) return respond(404, { error_code: 'NOT_FOUND' });
    let walletId: ResourceId<'wallet'>, accountId: ResourceId<'walletAccount'>;
    let preparationId: ResourceId<'operation'> | undefined, operationId: ResourceId<'operation'> | undefined;
    try {
      walletId = parseResourceId('wallet', match[1]); accountId = parseResourceId('walletAccount', match[2]);
      if (match[3]) preparationId = parseResourceId('operation', match[3]);
      if (match[5]) operationId = parseResourceId('operation', match[5]);
    } catch { return respond(404, { error_code: 'NOT_FOUND' }); }
    const reading = (!!preparationId && !match[4]) || (!!operationId && !match[6]);
    const methodResponse = allowMethods(request, origin, [reading ? 'GET' : 'POST'], headers); if (methodResponse) return methodResponse;
    if (!reading) {
      const incompatible = requireCurrentProtocol(request, config, 'account', catalog.map(p => p.manifest.manifest_id));
      if (incompatible) return incompatible;
      if (!isJsonRequest(request)) return respond(400, { error_code: 'INVALID_MONEY_REQUEST' });
    }
    try {
      return await withDeadline(request.signal, 45_000, async signal => {
        const scope = { rpId: config.webauthn_rp_id, origin }, identity = await verifyAppSession(request, env, scope, dependencies.accessProfiles);
        const owned = await new WalletRepository(env.WALLET_DB, identity).ownedAccount(walletId, accountId); signal.throwIfAborted();
        const matching = catalog.filter(p => p.profile.environment === config.environment && p.profile.digest === owned.deployment_manifest_sha256
          && p.manifest.network_id === owned.network_id && p.manifest.lifecycle_status === 'deployed');
        if (matching.length !== 1) return respond(503, { error_code: 'MONEY_PROFILE_UNAVAILABLE' });
        const { profile, manifest, market } = matching[0];
        if (!reading && (!config.wallet_enabled.includes(manifest.network_id)
          || request.headers.get(CLIENT_RELEASE_HEADERS.generation) !== String(manifest.generation)
          || request.headers.get(CLIENT_RELEASE_HEADERS.manifest) !== manifest.manifest_id)) return respond(503, { error_code: 'MONEY_PROFILE_UNAVAILABLE' });
        const repo = new MoneyRepository(env.WALLET_DB, identity, scope, [{ deployment: profile.digest, market: profile.market.digest }]);
        const view = async (stored: Awaited<ReturnType<MoneyRepository['readPreparation']>>) => ({ money_schema_version: 1,
          preparation_id: stored.id, wallet_id: walletId, wallet_account_id: accountId, state: stored.state,
          consent_digest: stored.candidate.digest, review_json: stored.record_json, review_sha256: stored.record_sha256,
          expires_at: stored.candidate.plan.validUntil, send_enabled: false,
          operation_id: await repo.operationForPreparation(walletId, accountId, stored.id) });
        if (reading) return respond(200, preparationId ? await view(await repo.readPreparationHistory(walletId, accountId, preparationId))
          : await readOwnedMoneyStatus(env.WALLET_DB, repo, walletId, accountId, operationId!));
        let command;
        try {
          const body = await readJsonBounded<unknown>(new Response(request.body, { headers: request.headers }), preparationId ? 98304 : 8192,
            AbortSignal.any([signal, AbortSignal.timeout(5000)]));
          command = preparationId ? { kind: 'confirm' as const, value: parseMoneyConfirmation(body), key: moneyIdempotencyKey(request.headers.get('Idempotency-Key')) }
            : operationId ? { kind: 'deliver' as const, value: parseMoneyDelivery(body) }
              : { kind: 'prepare' as const, value: parseMoneyRequest(body), key: moneyIdempotencyKey(request.headers.get('Idempotency-Key')) };
        } catch (error) { return respond(error instanceof ResponseBodyTooLargeError ? 413 : 400, { error_code: 'INVALID_MONEY_REQUEST' }); }
        signal.throwIfAborted();
        if (command.kind === 'prepare') {
          const r = command.value;
          if (r.wallet_id !== walletId || r.wallet_account_id !== accountId || r.network_id !== owned.network_id
            || r.client_release_id !== request.headers.get(CLIENT_RELEASE_HEADERS.release)) return respond(400, { error_code: 'INVALID_MONEY_REQUEST' });
          const prior = await repo.findPreparation(walletId, accountId, command.key, r); if (prior) return respond(200, await view(prior));
          const now = Math.floor(Date.now() / 1000);
          if (!profile.features[r.kind] || !profile.gasByKind[r.kind] || now < market.valid_from || now >= market.valid_until) return respond(503, { error_code: 'MONEY_CAPABILITY_UNAVAILABLE' });
          const finalityEvidence = await dependencies.resolvePreparation(structuredClone(owned), structuredClone(profile), signal);
          const prepared = await prepareOwnedMoney(env.WALLET_DB, identity, walletId, accountId, r, scope, [{ ...profile, finalityEvidence }], signal);
          return respond(200, await view(await repo.savePreparation(prepared, command.key)));
        }
        if (command.kind === 'confirm') {
          const prepared = await repo.readPreparation(walletId, accountId, preparationId!);
          if (prepared.candidate.request.client_release_id !== request.headers.get(CLIENT_RELEASE_HEADERS.release)) return respond(409, { error_code: 'MONEY_REVIEW_MISMATCH' });
          return respond(200, await confirmOwnedMoney(env.WALLET_DB, identity, walletId, accountId, preparationId!, command.value.consent_digest,
            command.value.proofs, command.key, scope, [profile], signal));
        }
        const stored = await repo.readOperation(walletId, accountId, operationId!);
        if (stored.candidate.digest !== command.value.consent_digest || stored.candidate.request.client_release_id !== request.headers.get(CLIENT_RELEASE_HEADERS.release)) return respond(409, { error_code: 'MONEY_REVIEW_MISMATCH' });
        return respond(202, await deliverOwnedMoney(env.WALLET_DB, identity, walletId, accountId, operationId!, scope, [profile], signal, dependencies.relayerKey));
      });
    } catch (error) {
      if (error instanceof IdentityError) return respond(error.code === 'UNAUTHENTICATED' ? 401 : 503, { error_code: error.code });
      if (error instanceof WalletAccessError) return respond({ UNAUTHENTICATED: 401, SESSION_REQUIRED: 409, NOT_FOUND: 404, WALLET_DATA_INVALID: 503 }[error.code], { error_code: error.code });
      const code = error instanceof Error ? error.message : '', known: Record<string, number> = {
        ACCOUNT_SPEND_BUSY: 409, MONEY_IDEMPOTENCY_CONFLICT: 409, MONEY_PREPARATION_NOT_FOUND: 404, MONEY_OPERATION_NOT_FOUND: 404,
        MONEY_REVIEW_MISMATCH: 409, MONEY_CONFIRMATION_CHANGED: 409, MONEY_DELIVERY_CHANGED: 409, MONEY_OPERATION_CHANGED: 409,
        MONEY_REVIEW_EXPIRED: 410, MONEY_CAPABILITY_UNAVAILABLE: 503, MONEY_PREFLIGHT_FAILED: 409,
        MONEY_PREFLIGHT_STALE_OR_CHANGED: 409, MONEY_PREPARATION_CAPACITY_OR_CHANGED: 429 };
      return Object.hasOwn(known, code) ? respond(known[code], { error_code: code }) : respond(503, { error_code: 'MONEY_UNAVAILABLE' });
    }
  };
}
