import type { GasSponsor } from '../sponsorship/service';
import type { Principal } from '../auth/principal';
import type { Environment } from '@gatopago/environment';
import { CLIENT_RELEASE_HEADERS } from '@gatopago/shared/v3/client-release';
import { loadPinnedDeploymentManifest } from '@gatopago/shared/v3/deployment';
import type { FinalityAssessment } from '@gatopago/shared/v3/finality';
import { parseResourceId, type ResourceId } from '@gatopago/shared/v3/primitives';
import { parseTransferRequest, type TransferRequest } from '@gatopago/shared/v3/transfer';
import { parseTransferConfirmation, parseTransferDelivery } from '@gatopago/shared/v3/transfer-wire';
import { readJsonBounded, ResponseBodyTooLargeError } from '@gatopago/shared/http';
import { validateIdentityConfig, type AuthBindings } from '../auth/config';
import { IdentityError } from '../auth/identity';
import { verifyAppSession } from '../auth/session';
import type { ReceivingProfiles } from '../accounts/profile';
import { requireCurrentProtocol } from '../clientProtocol';
import { withDeadline } from '../deadline';
import { allowMethods, isJsonRequest, v3Json } from '../http';
import { WalletAccessError, WalletRepository } from '../accounts/repository';
import { confirmOwnedTransfer } from './transferConfirmation';
import { deliverOwnedTransfer } from './transferDelivery';
import { TransferNonceReservationRepository } from './transferNonceReservation';
import { prepareOwnedTransfer, type TransferPreparationTerms } from './transferPreparation';
import { TransferPreparationRepository } from './transferPreparations';
import type { TransferPreflightProfile } from './transferPreflight';
import { writeTransferDraft } from '@gatopago/shared/v3/transfer-review-record';

const PATH = /^\/app\/v1\/wallets\/([^/]+)\/accounts\/([^/]+)\/(?:transfer-preparations(?:\/([^/]+)(\/confirm)?)?|transfers\/([^/]+)\/deliver)$(?![\s\S])/;
const allowedHeaders = ['Authorization', 'Content-Type', ...Object.values(CLIENT_RELEASE_HEADERS)];
export const isTransferCommandPath = (path: string) => PATH.test(path);
type Profile = TransferPreflightProfile & { readonly environment: Environment['environment'] };

/** App-only transport. Resolver is trusted server policy for actual estimation
 * and finality; no body/header can provide it. Empty default admission remains
 * closed. GET restores a draft without RPC; POST never accepts a financial context. */
export function createTransferRoute(dependencies: {
  readonly accessProfiles?: ReceivingProfiles;
  readonly relayerKey?: `0x${string}`;
  readonly profiles: readonly Profile[];
  readonly sponsor?: (profile: Profile, database: D1Database, identity: Principal, signal: AbortSignal) => GasSponsor | undefined;
  readonly resolvePreparation: (owned: Awaited<ReturnType<WalletRepository['ownedAccount']>>, request: TransferRequest,
    profile: Profile, signal: AbortSignal) => Promise<{ finalityEvidence: FinalityAssessment; terms: TransferPreparationTerms }>;
}) {
  const resolve = dependencies.resolvePreparation;
  const catalog = structuredClone(dependencies.profiles).map(profile => ({ profile,
    manifest: loadPinnedDeploymentManifest(profile.document, profile.digest) }));
  if (catalog.length > 32 || new Set(catalog.map(p => `${p.profile.environment}:${p.profile.digest}`)).size !== catalog.length) {
    throw new Error('TRANSFER_PROFILE_CATALOG');
  }
  return async function route(request: Request, env: AuthBindings, environment: Environment): Promise<Response> {
    let config: Environment;
    try { config = validateIdentityConfig(env, environment); }
    catch { return v3Json(503, { error_code: 'SERVICE_UNAVAILABLE' }); }
    const url = new URL(request.url), origin = request.headers.get('Origin');
    if (url.origin !== config.api_origin || origin !== config.web_origin || !config.webauthn_allowed_origins.includes(origin)) {
      return v3Json(403, { error_code: 'ORIGIN_NOT_ALLOWED' });
    }
    const respond = (status: number, body: object) => v3Json(status, body, origin);
    const match = PATH.exec(url.pathname);
    if (!match || url.search) return respond(404, { error_code: 'NOT_FOUND' });
    let walletId: ResourceId<'wallet'>, accountId: ResourceId<'walletAccount'>;
    let preparationId: ResourceId<'operation'> | undefined, operationId: ResourceId<'operation'> | undefined;
    try {
      walletId = parseResourceId('wallet', match[1]); accountId = parseResourceId('walletAccount', match[2]);
      if (match[3]) preparationId = parseResourceId('operation', match[3]);
      if (match[5]) operationId = parseResourceId('operation', match[5]);
    } catch { return respond(404, { error_code: 'NOT_FOUND' }); }
    const reading = !!preparationId && !match[4], method = reading ? 'GET' : 'POST';
    const methodResponse = allowMethods(request, origin, [method], allowedHeaders);
    if (methodResponse) return methodResponse;
    if (!reading) {
      const incompatible = requireCurrentProtocol(request, config, 'account', catalog.map(p => p.manifest.manifest_id));
      if (incompatible) return incompatible;
      if (!isJsonRequest(request)) {
        return respond(400, { error_code: 'INVALID_TRANSFER_REQUEST' });
      }
    }
    try {
      return await withDeadline(request.signal, 45_000, async signal => {
        const identity = await verifyAppSession(request, env, { rpId: config.webauthn_rp_id, origin: config.web_origin }, dependencies.accessProfiles);
        const owned = await new WalletRepository(env.WALLET_DB, identity).ownedAccount(walletId, accountId);
        signal.throwIfAborted();
        const matching = catalog.filter(p => p.profile.environment === config.environment && p.profile.digest === owned.deployment_manifest_sha256
          && p.manifest.network_id === owned.network_id && p.manifest.lifecycle_status === 'deployed');
        if (matching.length !== 1) return respond(503, { error_code: 'TRANSFER_PROFILE_UNAVAILABLE' });
        const { profile, manifest } = matching[0];
        if (!reading && (!config.wallet_enabled.includes(manifest.network_id)
          || request.headers.get(CLIENT_RELEASE_HEADERS.generation) !== String(manifest.generation)
          || request.headers.get(CLIENT_RELEASE_HEADERS.manifest) !== manifest.manifest_id)) {
          return respond(503, { error_code: 'TRANSFER_PROFILE_UNAVAILABLE' });
        }
        const scope = { rpId: config.webauthn_rp_id, origin };
        const drafts = new TransferPreparationRepository(env.WALLET_DB, identity, scope, [profile.digest]);
        const forAsset = (asset: string): Profile => {
          const natives = profile.assetIds.filter(id => id.split('/')[1]?.startsWith('slip44:'));
          if (natives.length !== 1 || !profile.assetIds.includes(asset)) throw new Error('TRANSFER_ASSET_UNAVAILABLE');
          const assetIds = [...new Set([asset, natives[0]])].sort();
          return { ...profile, assetIds, assetDisplay: Object.fromEntries(assetIds.map(id => [id, profile.assetDisplay[id]])) };
        };
        const view = (stored: Awaited<ReturnType<TransferPreparationRepository['readOwned']>>) => {
          const encoded = writeTransferDraft(stored.review);
          // Canonical public-key review bytes, no saved signatures/JWT/RPC URLs.
          return { schema_version: 1, preparation_id: stored.id, wallet_id: walletId, wallet_account_id: accountId,
            consent_digest: stored.candidate.digest, review_json: encoded.json, review_sha256: encoded.digest,
            expires_at: stored.candidate.plan.validUntil, send_enabled: false };
        };
        if (reading) return respond(200, view(await drafts.readOwned(walletId, accountId, preparationId!)));
        let command;
        try {
          const body = await readJsonBounded<unknown>(new Response(request.body, { headers: request.headers }),
            preparationId ? 98_304 : 8192, AbortSignal.any([signal, AbortSignal.timeout(5000)]));
          command = preparationId ? { kind: 'confirm' as const, value: parseTransferConfirmation(body) }
            : operationId ? { kind: 'deliver' as const, value: parseTransferDelivery(body) }
              : { kind: 'prepare' as const, value: parseTransferRequest(body) };
        } catch (error) {
          return respond(error instanceof ResponseBodyTooLargeError ? 413 : 400, { error_code: 'INVALID_TRANSFER_REQUEST' });
        }
        signal.throwIfAborted();
        if (command.kind === 'prepare') {
          if (command.value.wallet_id !== walletId || command.value.network_id !== owned.network_id
            || command.value.client_release_id !== request.headers.get(CLIENT_RELEASE_HEADERS.release)) {
            return respond(400, { error_code: 'INVALID_TRANSFER_REQUEST' });
          }
          const selected = forAsset(command.value.asset_id);
          const resolved = structuredClone(await resolve(structuredClone(owned), structuredClone(command.value), structuredClone(selected), signal));
          signal.throwIfAborted();
          const prepared = await prepareOwnedTransfer(env.WALLET_DB, identity, accountId, command.value, scope,
            [{ ...selected, finalityEvidence: resolved.finalityEvidence }], resolved.terms, signal, dependencies.sponsor?.(selected, env.WALLET_DB, identity, signal));
          return respond(200, view(await drafts.save(prepared)));
        }
        if (command.kind === 'confirm') {
          const reviewed = await drafts.readOwned(walletId, accountId, preparationId!);
          if (reviewed.candidate.request.client_release_id !== request.headers.get(CLIENT_RELEASE_HEADERS.release)) {
            return respond(409, { error_code: 'TRANSFER_REVIEW_MISMATCH' });
          }
          return respond(200, await confirmOwnedTransfer(env.WALLET_DB, identity, walletId, accountId,
            preparationId!, command.value.consent_digest, command.value.proofs, scope, [forAsset(reviewed.candidate.request.asset_id)], signal));
        }
        const stored = await new TransferNonceReservationRepository(env.WALLET_DB, identity).readOwned(walletId, accountId, operationId!);
        if (stored.candidate.digest !== command.value.consent_digest || stored.review.scope.origin !== scope.origin || stored.review.scope.rpId !== scope.rpId
          || stored.candidate.request.client_release_id !== request.headers.get(CLIENT_RELEASE_HEADERS.release)) {
          return respond(409, { error_code: 'TRANSFER_REVIEW_MISMATCH' });
        }
        return respond(202, await deliverOwnedTransfer(env.WALLET_DB, identity, walletId, accountId, operationId!, [forAsset(stored.candidate.request.asset_id)], signal, dependencies.relayerKey));
      });
    } catch (error) {
      if (error instanceof IdentityError) return respond(error.code === 'UNAUTHENTICATED' ? 401 : 503, { error_code: error.code });
      if (error instanceof WalletAccessError) return respond({ UNAUTHENTICATED: 401, SESSION_REQUIRED: 409, NOT_FOUND: 404, WALLET_DATA_INVALID: 503 }[error.code], { error_code: error.code });
      const code = error instanceof Error ? error.message : '';
      const known: Record<string, number> = { ACCOUNT_SPEND_BUSY: 409, SPONSOR_BUDGET_EXHAUSTED: 429, TRANSFER_PREPARATION_NOT_FOUND: 404, TRANSFER_RESERVATION_NOT_FOUND: 404,
        TRANSFER_PREPARATION_EXPIRED: 410, TRANSFER_CONSENT_EXPIRED: 410, TRANSFER_REVIEW_MISMATCH: 409,
        TRANSFER_FUNDS_CHANGED: 409, TRANSFER_CONFIRMATION_CHANGED: 409, TRANSFER_PREPARATION_CHANGED: 409,
        TRANSFER_RESERVATION_CONCURRENT_CHANGE: 409, TRANSFER_RESERVATION_CONFLICT: 409, TRANSFER_DELIVERY_ALREADY_CLAIMED: 409,
        TRANSFER_QUORUM_INVALID: 400, TRANSFER_SIGNATURE_INVALID: 400, TRANSFER_ASSET_UNAVAILABLE: 400 };
      if (Object.hasOwn(known, code)) return respond(known[code], { error_code: code });
      return respond(503, { error_code: 'TRANSFER_UNAVAILABLE' });
    }
  };
}
