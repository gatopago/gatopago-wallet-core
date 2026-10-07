import { SignJWT, importJWK, jwtVerify } from 'jose';
import { getAddress, type Address } from 'viem';
import type { Config } from './config';
import { HttpError } from './http';

export interface Session {
  readonly userId: string;
  readonly address: Address;
  readonly expiresAt: number;
}

const ISSUER = 'gatopago-wallet-core';
const LIFETIME_SECONDS = { wallet: 24 * 3600, business: 12 * 3600 };

/**
 * A `business` session (GatoPago Business, the merchant console) is accepted by Flow and refused
 * by the wallet's own endpoints.
 */
export async function issueSession(
  config: Config,
  member: { id: string; address: string },
  scope: 'wallet' | 'business' = 'wallet',
) {
  const expiresAt = Math.floor(Date.now() / 1000) + LIFETIME_SECONDS[scope];
  const token = await new SignJWT(
    scope === 'business' ? { address: member.address, scope } : { address: member.address },
  )
    .setProtectedHeader({ alg: 'ES256' })
    .setIssuer(ISSUER)
    .setSubject(member.id)
    .setIssuedAt()
    .setExpirationTime(expiresAt)
    .sign(await importJWK(config.sessionJwk, 'ES256'));
  return { token, expiresAt };
}

/** The session in `Authorization: Bearer <token>`; Business sessions only where `business` allows. */
export async function authenticate(
  request: Request,
  config: Config,
  { business = false }: { business?: boolean } = {},
): Promise<Session> {
  const token = /^Bearer (\S+)$/.exec(request.headers.get('Authorization') ?? '')?.[1];
  if (!token) throw new HttpError(401, 'UNAUTHENTICATED');
  const { kty, crv, x, y } = config.sessionJwk;
  try {
    const { payload } = await jwtVerify(token, await importJWK({ kty, crv, x, y }, 'ES256'), {
      issuer: ISSUER,
      algorithms: ['ES256'],
    });
    if (payload.scope === 'business' && !business) throw new Error('Business session');
    return {
      userId: String(payload.sub),
      address: getAddress(String(payload.address)),
      expiresAt: Number(payload.exp),
    };
  } catch {
    throw new HttpError(401, 'UNAUTHENTICATED');
  }
}
