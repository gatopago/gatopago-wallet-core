import { abortable } from '../deadline';
import type { Environment } from '@gatopago/environment';
import { CLIENT_RELEASE_HEADERS } from '@gatopago/shared/v3/client-release';
import { deploymentDocumentDigest } from '@gatopago/shared/v3/deployment';
import { loadPinnedCreationProfile } from '@gatopago/shared/v3/initialization';
import { parseInitializationProof } from '@gatopago/shared/v3/initialization-wire';
import { parseResourceId } from '@gatopago/shared/v3/primitives';
import { readJsonBounded, ResponseBodyTooLargeError } from '@gatopago/shared/http';
import { validateIdentityConfig, type AuthBindings } from '../auth/config';
import { IdentityError } from '../auth/identity';
import { verifyAppSession } from '../auth/session';
import type { ReceivingProfiles } from '../accounts/profile';
import { requireCurrentProtocol } from '../clientProtocol';
import { allowMethods, isJsonRequest, v3Json } from '../http';
import { BackupError, BackupRepository, type BackupProfiles } from './backup';
import { BackupStatusRepository } from './backupStatus';
import {
  parseBackupAuthorization,
  parseBackupCommitRequest,
  parseBackupRequest,
} from './backupWire';
import { InitializationError, type CreationProfilePin } from '../creation/initialization';
import { WalletAccessError, WalletRepository } from '../accounts/repository';

const ROOT = '/app/v1/account-backups';
const PATH =
  /^\/app\/v1\/account-backups(?:\/([^/]+)(?:(\/authorize)|\/commits(?:\/([^/]+)(\/authorize)?)?)?)?$(?![\s\S])/;
const STATUS_PATH =
  /^\/app\/v1\/account-backups\/([^/]+)(?:\/commits\/([^/]+))?\/status$(?![\s\S])/;
const allowedHeaders = ['Authorization', 'Content-Type', ...Object.values(CLIENT_RELEASE_HEADERS)];
export const isBackupPath = (path: string) => PATH.test(path) || STATUS_PATH.test(path);

export function createBackupRoute(dependencies: {
  readonly accessProfiles?: ReceivingProfiles;
  readonly profiles: readonly (CreationProfilePin & {
    readonly environment: Environment['environment'];
  })[];
  readonly resolveProfiles: BackupProfiles;
}) {
  const resolve = dependencies.resolveProfiles;
  const profiles = dependencies.profiles.map((p) => {
    const deployment = loadPinnedCreationProfile(p.document, p.digest).deployment;
    return Object.freeze({
      pin: Object.freeze({ document: p.document, digest: p.digest }),
      environment: p.environment,
      deployment,
      deploymentDigest: deploymentDocumentDigest(JSON.stringify(deployment)),
    });
  });
  if (
    profiles.length > 32 ||
    new Set(profiles.map((p) => `${p.environment}:${p.pin.digest}`)).size !== profiles.length
  )
    throw new Error('Invalid backup catalog');
  return async function route(
    request: Request,
    env: AuthBindings,
    manifest: Environment,
  ): Promise<Response> {
    let config: Environment;
    try {
      config = validateIdentityConfig(env, manifest);
    } catch {
      return v3Json(503, { error_code: 'SERVICE_UNAVAILABLE' });
    }
    const url = new URL(request.url),
      origin = request.headers.get('Origin');
    if (
      url.origin !== config.api_origin ||
      origin !== config.web_origin ||
      !config.webauthn_allowed_origins.includes(origin)
    )
      return v3Json(403, { error_code: 'ORIGIN_NOT_ALLOWED' });
    const respond = (status: number, body: object) => v3Json(status, body, origin);
    const statusMatch = STATUS_PATH.exec(url.pathname),
      match = PATH.exec(url.pathname);
    if ((!match && !statusMatch) || url.search) return respond(404, { error_code: 'NOT_FOUND' });
    let backupId, commitId;
    try {
      const parent = statusMatch?.[1] ?? match?.[1],
        child = statusMatch?.[2] ?? match?.[3];
      if (parent) backupId = parseResourceId('operation', parent);
      if (child) commitId = parseResourceId('operation', child);
    } catch {
      return respond(404, { error_code: 'NOT_FOUND' });
    }
    const create = url.pathname === ROOT,
      commits = url.pathname.endsWith('/commits'),
      authorize = !!(match?.[2] || match?.[4]);
    const methods = create || commits || authorize ? ['POST'] : ['GET'];
    const methodResponse = allowMethods(request, origin, methods, allowedHeaders);
    if (methodResponse) return methodResponse;
    const reading = request.method === 'GET';
    const incompatible = requireCurrentProtocol(
      request,
      config,
      reading ? 'identity' : 'account',
      profiles.map((p) => p.deployment.manifest_id),
    );
    if (incompatible) return incompatible;
    if (!reading && !isJsonRequest(request))
      return respond(400, { error_code: 'INVALID_BACKUP_REQUEST' });
    const available = profiles.filter(
      (p) =>
        p.environment === config.environment &&
        (reading ||
          (config.wallet_enabled.includes(p.deployment.network_id) &&
            request.headers.get(CLIENT_RELEASE_HEADERS.generation) ===
              String(p.deployment.generation) &&
            request.headers.get(CLIENT_RELEASE_HEADERS.manifest) === p.deployment.manifest_id)),
    );
    if (!reading && !available.length)
      return respond(503, { error_code: 'BACKUP_PROFILE_UNAVAILABLE' });
    const signal = AbortSignal.any([request.signal, AbortSignal.timeout(15_000)]);
    try {
      signal.throwIfAborted();
      const principal = await verifyAppSession(
        request,
        env,
        { rpId: config.webauthn_rp_id, origin: config.web_origin },
        dependencies.accessProfiles,
      );
      await new WalletRepository(env.WALLET_DB, principal).getSession();
      signal.throwIfAborted();
      if (statusMatch) {
        const result = await new BackupStatusRepository(
          env.WALLET_DB,
          principal,
          { rpId: config.webauthn_rp_id, origin },
          available.map((p) => p.pin),
        ).read(backupId!, commitId);
        signal.throwIfAborted();
        return respond(200, result);
      }
      const resolver: BackupProfiles = async (owned, childSignal) => {
        const matching = available.filter(
          (p) =>
            p.deployment.network_id === owned.network_id &&
            p.deploymentDigest === owned.deployment_manifest_sha256,
        );
        if (matching.length !== 1) throw new BackupError('BACKUP_PROFILE_UNAVAILABLE');
        const result = structuredClone(
          await abortable(resolve(structuredClone(owned), childSignal), childSignal),
        );
        childSignal.throwIfAborted();
        if (result.length !== 1 || result[0].digest !== matching[0].deploymentDigest)
          throw new BackupError('BACKUP_PROFILE_UNAVAILABLE');
        return result;
      };
      const repo = new BackupRepository(
        env.WALLET_DB,
        principal,
        { rpId: config.webauthn_rp_id, origin },
        available.map((p) => p.pin),
        resolver,
      );

      if (commitId) {
        const record = await repo.readCommit(commitId);
        signal.throwIfAborted();
        if (record.backup_id !== backupId) throw new WalletAccessError('NOT_FOUND');
        if (reading) return respond(200, record);
      } else if (reading) {
        const record = await repo.read(backupId!);
        signal.throwIfAborted();
        return respond(200, record);
      }
      let body: unknown;
      try {
        body = await readJsonBounded<unknown>(
          new Response(request.body, { headers: request.headers }),
          authorize ? 98_304 : 16_384,
          AbortSignal.any([signal, AbortSignal.timeout(5000)]),
        );
      } catch (error) {
        return respond(error instanceof ResponseBodyTooLargeError ? 413 : 400, {
          error_code: 'INVALID_BACKUP_REQUEST',
        });
      }

      let command;
      try {
        if (create) command = { kind: 'prepare' as const, value: parseBackupRequest(body) };
        else if (commits)
          command = { kind: 'commit' as const, value: parseBackupCommitRequest(body) };
        else if (commitId)
          command = { kind: 'commit_authorize' as const, value: parseInitializationProof(body) };
        else command = { kind: 'authorize' as const, value: parseBackupAuthorization(body) };
      } catch {
        return respond(400, { error_code: 'INVALID_BACKUP_REQUEST' });
      }
      signal.throwIfAborted();
      const result =
        command.kind === 'prepare'
          ? await repo.prepare(command.value, signal)
          : command.kind === 'commit'
            ? await repo.prepareCommit(command.value, backupId!, signal)
            : command.kind === 'commit_authorize'
              ? await repo.authorizeCommit(commitId!, command.value, signal)
              : await repo.authorize(
                  backupId!,
                  command.value.owner,
                  command.value.enrollments,
                  signal,
                );
      signal.throwIfAborted();
      return respond(200, result);
    } catch (error) {
      if (error instanceof BackupError)
        return respond(
          {
            BACKUP_EXPIRED: 410,
            BACKUP_CONFLICT: 409,
            BACKUP_LIMIT: 429,
            BACKUP_PROFILE_UNAVAILABLE: 503,
            BACKUP_STATE_CHANGED: 409,
            BACKUP_REQUIRED: 409,
            INVALID_BACKUP_PROOF: 400,
          }[error.code],
          { error_code: error.code },
        );
      if (error instanceof InitializationError)
        return respond(
          {
            PROFILE_UNAVAILABLE: 503,
            INITIALIZATION_EXPIRED: 410,
            INITIALIZATION_CONFLICT: 409,
            INITIALIZATION_LIMIT: 429,
            INITIALIZATION_REQUIRED: 409,
            INVALID_INITIALIZATION_ASSERTION: 400,
          }[error.code],
          { error_code: error.code },
        );
      if (error instanceof IdentityError)
        return respond(error.code === 'UNAUTHENTICATED' ? 401 : 503, { error_code: error.code });
      if (error instanceof WalletAccessError)
        return respond(
          { UNAUTHENTICATED: 401, SESSION_REQUIRED: 409, NOT_FOUND: 404, WALLET_DATA_INVALID: 503 }[
            error.code
          ],
          { error_code: error.code },
        );

      if (
        error instanceof Error &&
        [
          'BACKUP_PROPOSAL_WINDOW_INVALID',
          'BACKUP_MUST_RETAIN_INITIAL_FACTOR',
          'BACKUP_SIGNER_TRANSPORT_UNSUPPORTED',
          'BACKUP_VERIFIER_MISMATCH',
        ].includes(error.message)
      )
        return respond(400, { error_code: error.message });
      if (
        error instanceof Error &&
        [
          'BACKUP_STATE_MISMATCH',
          'BACKUP_PROPOSAL_PENDING',
          'BACKUP_PENDING_MISMATCH',
          'BACKUP_NONCE_EXHAUSTED',
        ].includes(error.message)
      )
        return respond(409, { error_code: error.message });
      return respond(503, { error_code: 'BACKUP_UNAVAILABLE' });
    }
  };
}
