import type { Environment } from '@gatopago/environment';
import { parseResourceId, type ResourceKind } from '@gatopago/shared/v3/primitives';
import { CLIENT_RELEASE_HEADERS } from '@gatopago/shared/v3/client-release';
import { validateIdentityConfig, type AuthBindings } from '../auth/config';
import { IdentityError } from '../auth/identity';
import { verifyAppSession } from '../auth/session';
import type { ReceivingProfiles } from '../accounts/profile';
import { allowMethods, v3Json as json } from '../http';
import { WalletAccessError, WalletRepository } from './repository';
import { inspectOwnedWalletBalances, type BalanceProfile } from '../portfolio/balances';
import { readOwnedTransferStatus } from '../transfers/transferStatus';
import { restoreOwnedTransfer } from '../transfers/transferStatus';
import { requireHash } from '@gatopago/shared/v3/deployment';
import type { Hex } from 'viem';
import { readOwnedAccountContext, type AccountContextProfile } from './accountContext';

const SESSION_PATH = '/app/v1/session';
const WALLETS_PATH = '/app/v1/wallets';
const BALANCES_PATH = /^\/app\/v1\/wallets\/[^/]+\/accounts\/[^/]+\/balances$(?![\s\S])/;
const CONTEXT_PATH = /^\/app\/v1\/wallets\/[^/]+\/accounts\/[^/]+\/context$(?![\s\S])/;
const TRANSFER_PATH = /^\/app\/v1\/wallets\/[^/]+\/accounts\/[^/]+\/transfers\/[^/]+$(?![\s\S])/;
const TRANSFER_RESTORE_PATH =
  /^\/app\/v1\/wallets\/[^/]+\/accounts\/[^/]+\/transfer-consents\/[^/]+$(?![\s\S])/;
const allowedHeaders = ['Authorization', 'Content-Type', ...Object.values(CLIENT_RELEASE_HEADERS)];

export function isWalletReadPath(path: string): boolean {
  return (
    path === SESSION_PATH ||
    path === WALLETS_PATH ||
    /^\/app\/v1\/wallets\/[^/]+\/accounts$(?![\s\S])/.test(path) ||
    BALANCES_PATH.test(path) ||
    TRANSFER_PATH.test(path) ||
    TRANSFER_RESTORE_PATH.test(path) ||
    CONTEXT_PATH.test(path)
  );
}

function page(search: URLSearchParams, kind: ResourceKind) {
  if (
    [...search.keys()].some((key) => !['limit', 'after'].includes(key)) ||
    search.getAll('limit').length > 1 ||
    search.getAll('after').length > 1
  ) {
    throw new Error('Invalid pagination');
  }
  const limit = search.get('limit') ?? '20';
  if (!/^(?:[1-9]|[1-4][0-9]|50)$(?![\s\S])/.test(limit)) throw new Error('Invalid page size');
  return {
    limit: Number(limit),
    after: search.has('after') ? parseResourceId(kind, search.get('after')) : '',
  };
}

export async function walletReadRoute(
  request: Request,
  env: AuthBindings,
  manifest: Environment,
  resolveBalanceProfiles: (
    owned: Awaited<ReturnType<WalletRepository['ownedAccount']>>,
    signal: AbortSignal,
  ) => Promise<readonly BalanceProfile[]>,
  accessProfiles?: ReceivingProfiles,
  resolveAccountContextProfiles: () => readonly AccountContextProfile[] = () => [],
): Promise<Response> {
  let config: Environment;
  try {
    config = validateIdentityConfig(env, manifest);
  } catch {
    return json(503, { error_code: 'SERVICE_UNAVAILABLE' });
  }
  const url = new URL(request.url);
  const origin = request.headers.get('Origin');
  if (url.origin !== config.api_origin || origin !== config.web_origin)
    return json(403, { error_code: 'ORIGIN_NOT_ALLOWED' });
  const respond = (status: number, body: object) => json(status, body, config.web_origin);
  if (!isWalletReadPath(url.pathname)) return respond(404, { error_code: 'NOT_FOUND' });
  const isSession = url.pathname === SESSION_PATH;
  const isWallets = url.pathname === WALLETS_PATH;
  const isBalances = BALANCES_PATH.test(url.pathname);
  const isTransfer = TRANSFER_PATH.test(url.pathname);
  const isRestore = TRANSFER_RESTORE_PATH.test(url.pathname);
  const isContext = CONTEXT_PATH.test(url.pathname);
  let pagination: ReturnType<typeof page> = { limit: 20, after: '' };
  let walletId: ReturnType<typeof parseResourceId<'wallet'>> | undefined;
  let accountId: ReturnType<typeof parseResourceId<'walletAccount'>> | undefined;
  let operationId: ReturnType<typeof parseResourceId<'operation'>> | undefined;
  let consentDigest: Hex | undefined;
  try {
    if (isSession) {
      if (url.search) throw new Error('No session query');
    } else if (isBalances || isTransfer || isRestore || isContext) {
      if (url.search) throw new Error('No balance overrides');
      walletId = parseResourceId('wallet', url.pathname.split('/')[4]);
      accountId = parseResourceId('walletAccount', url.pathname.split('/')[6]);
      if (isTransfer) operationId = parseResourceId('operation', url.pathname.split('/')[8]);
      if (isRestore) {
        const digest = url.pathname.split('/')[8];
        requireHash(digest);
        consentDigest = digest;
      }
    } else {
      pagination = page(url.searchParams, isWallets ? 'wallet' : 'walletAccount');
      if (!isWallets) walletId = parseResourceId('wallet', url.pathname.split('/')[4]);
    }
  } catch {
    return respond(400, { error_code: 'INVALID_REQUEST' });
  }
  const methods = ['GET'];
  const methodResponse = allowMethods(request, config.web_origin, methods, allowedHeaders);
  if (methodResponse) return methodResponse;

  try {
    const principal = await verifyAppSession(
      request,
      env,
      { rpId: config.webauthn_rp_id, origin: config.web_origin },
      accessProfiles,
    );
    request.signal.throwIfAborted();
    const repository = new WalletRepository(env.WALLET_DB, principal);
    if (isSession) return respond(200, await repository.getSession());
    if (isRestore) {
      const restored = await restoreOwnedTransfer(
        env.WALLET_DB,
        principal,
        walletId!,
        accountId!,
        consentDigest!,
        resolveAccountContextProfiles,
      );
      request.signal.throwIfAborted();
      return respond(200, restored);
    }
    if (isTransfer)
      return respond(
        200,
        await readOwnedTransferStatus(
          env.WALLET_DB,
          principal,
          walletId!,
          accountId!,
          operationId!,
        ),
      );
    if (isContext) {
      await repository.ownedAccount(walletId!, accountId!);

      return respond(
        200,
        await readOwnedAccountContext(
          repository,
          walletId!,
          accountId!,
          resolveAccountContextProfiles(),
          request.signal,
        ),
      );
    }
    const balanceProfiles = isBalances
      ? await resolveBalanceProfiles(
          await repository.ownedAccount(walletId!, accountId!),
          request.signal,
        )
      : [];
    if (isBalances)
      return respond(
        200,
        await inspectOwnedWalletBalances(
          repository,
          walletId!,
          accountId!,
          balanceProfiles,
          request.signal,
        ),
      );
    return respond(
      200,
      isWallets
        ? await repository.listWallets(pagination)
        : await repository.listAccounts(walletId!, pagination),
    );
  } catch (error) {
    if (error instanceof IdentityError)
      return respond(error.code === 'UNAUTHENTICATED' ? 401 : 503, { error_code: error.code });
    if (error instanceof WalletAccessError) {
      const status = {
        UNAUTHENTICATED: 401,
        SESSION_REQUIRED: 409,
        NOT_FOUND: 404,
        WALLET_DATA_INVALID: 503,
      }[error.code];
      return respond(status, { error_code: error.code });
    }

    return respond(503, { error_code: 'SERVICE_UNAVAILABLE' });
  }
}
