import type { WebAuthnScope } from '@gatopago/shared/v3/webauthn';
import type { ReceivingProfiles } from '../accounts/profile';
import { WalletRepository } from '../accounts/repository';
import type { AuthBindings } from './config';
import { refreshUserAccess } from './access';
import { IdentityError, verifyConsumerIdentity } from './identity';
import { withDeadline } from '../deadline';

export const unavailableAccessProfiles: ReceivingProfiles = async () => {
  throw new IdentityError('IDENTITY_UNAVAILABLE');
};

export async function verifyAppSession(
  request: Request,
  env: Pick<AuthBindings, 'WALLET_DB' | 'FIREBASE_PROJECT_ID' | 'GATOPAGO_ENVIRONMENT'>,
  scope: WebAuthnScope,
  profiles: ReceivingProfiles = unavailableAccessProfiles,
) {
  if (env.GATOPAGO_ENVIRONMENT !== 'production') throw new IdentityError('IDENTITY_UNAVAILABLE');
  const identity = await verifyConsumerIdentity(
    request,
    env.FIREBASE_PROJECT_ID,
    env.GATOPAGO_ENVIRONMENT,
  );
  await new WalletRepository(env.WALLET_DB, identity).getSession();
  const access = await withDeadline(request.signal, 15_000, (signal) =>
    refreshUserAccess(
      env.WALLET_DB,
      identity.userId,
      identity.environment,
      scope,
      profiles,
      signal,
    ),
  );
  const bounded = Object.freeze({
    ...identity,
    expiresAt: Math.min(identity.expiresAt, access.expiresAt),
  });
  await new WalletRepository(env.WALLET_DB, bounded).getSession();
  return bounded;
}
