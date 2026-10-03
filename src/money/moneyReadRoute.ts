import type { Environment } from '@gatopago/environment';
import { CLIENT_RELEASE_HEADERS } from '@gatopago/shared/v3/client-release';
import { loadAaveMarket } from '@gatopago/shared/v3/aave-market';
import { parseResourceId } from '@gatopago/shared/v3/primitives';
import { WalletRepository, WalletAccessError } from '../accounts/repository';
import type { ReceivingProfiles } from '../accounts/profile';
import { IdentityError } from '../auth/identity';
import { verifyAppSession } from '../auth/session';
import { validateIdentityConfig, type AuthBindings } from '../auth/config';
import { allowMethods, v3Json } from '../http';
import { withDeadline } from '../deadline';
import { inspectOwnedAavePosition, type AavePositionProfile } from '../portfolio/aavePosition';
import type { configureMoney } from '../runtime/moneyConfig';

const PATH = /^\/app\/v1\/wallets\/([^/]+)\/accounts\/([^/]+)\/(aave-position|money-capabilities)$(?![\s\S])/;
export const isMoneyReadPath = (path: string) => PATH.test(path);
export function createMoneyReadRoute(dependencies: {
  readonly configuration: ReturnType<typeof configureMoney> | null;
  readonly accessProfiles: ReceivingProfiles;
  readonly resolveProfiles: (owned: Awaited<ReturnType<WalletRepository['ownedAccount']>>, signal: AbortSignal) => Promise<readonly AavePositionProfile[]>;
}) {
  return async function route(request: Request, env: AuthBindings, manifest: Environment): Promise<Response> {
    let config: Environment;
    try { config = validateIdentityConfig(env, manifest); }
    catch { return v3Json(503, { error_code: 'SERVICE_UNAVAILABLE' }); }
    const url = new URL(request.url), origin = request.headers.get('Origin');
    if (url.origin !== config.api_origin || origin !== config.web_origin) return v3Json(403, { error_code: 'ORIGIN_NOT_ALLOWED' });
    const respond = (status: number, body: object) => v3Json(status, body, origin);
    const match = PATH.exec(url.pathname);
    if (!match || url.search) return respond(404, { error_code: 'NOT_FOUND' });
    const methodResponse = allowMethods(request, origin, ['GET'], ['Authorization', 'Content-Type', ...Object.values(CLIENT_RELEASE_HEADERS)]);
    if (methodResponse) return methodResponse;
    try {
      const walletId = parseResourceId('wallet', match[1]), accountId = parseResourceId('walletAccount', match[2]);
      const principal = await verifyAppSession(request, env, { rpId: config.webauthn_rp_id, origin: config.web_origin }, dependencies.accessProfiles);
      return await withDeadline(request.signal, 30000, async signal => {
        const repository = new WalletRepository(env.WALLET_DB, principal), owned = await repository.ownedAccount(walletId, accountId);
        signal.throwIfAborted();
        const configuration = dependencies.configuration;
        if (!configuration || configuration.network.transferProfile.digest !== owned.deployment_manifest_sha256
          || owned.network_id !== configuration.application.network_id) return respond(503, { error_code: 'MONEY_CAPABILITY_UNAVAILABLE' });
        if (match[3] === 'money-capabilities') {
          const market = loadAaveMarket(configuration.market), now = Math.floor(Date.now() / 1000);
          const admitted = now >= market.valid_from && now < market.valid_until;
          return respond(200, { schema_version: 1, money_schema_version: 1, wallet_id: walletId, wallet_account_id: accountId,
            network_id: market.network_id, market: configuration.market,
            features: Object.fromEntries(Object.entries(configuration.application.features).map(([kind, enabled]) => [kind,
              enabled && admitted && !!configuration.gasByKind[kind as keyof typeof configuration.gasByKind]])),
            observed_at: now, expires_at: Math.min(now + 30, market.valid_until), spend_readiness: 'not_assessed' });
        }
        const profiles = await dependencies.resolveProfiles(owned, signal);
        const value = await inspectOwnedAavePosition(repository, walletId, accountId, profiles, signal);
        signal.throwIfAborted();
        return respond(200, value);
      });
    } catch (error) {
      if (error instanceof IdentityError) return respond(error.code === 'UNAUTHENTICATED' ? 401 : 503, { error_code: error.code });
      if (error instanceof WalletAccessError) return respond({ UNAUTHENTICATED: 401, SESSION_REQUIRED: 409, NOT_FOUND: 404, WALLET_DATA_INVALID: 503 }[error.code], { error_code: error.code });
      return respond(503, { error_code: 'POSITION_UNAVAILABLE' });
    }
  };
}
