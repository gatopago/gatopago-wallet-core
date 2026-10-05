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
const LIFETIME_SECONDS = 24 * 3600;

export async function issueSession(config: Config, member: { id: string; address: string }) {
  const expiresAt = Math.floor(Date.now() / 1000) + LIFETIME_SECONDS;
  const token = await new SignJWT({ address: member.address })
    .setProtectedHeader({ alg: 'ES256' })
    .setIssuer(ISSUER)
    .setSubject(member.id)
    .setIssuedAt()
    .setExpirationTime(expiresAt)
    .sign(await importJWK(config.sessionJwk, 'ES256'));
  return { token, expiresAt };
}

/** The session in `Authorization: Bearer <token>`. */
export async function authenticate(request: Request, config: Config): Promise<Session> {
  const token = /^Bearer (\S+)$/.exec(request.headers.get('Authorization') ?? '')?.[1];
  if (!token) throw new HttpError(401, 'UNAUTHENTICATED');
  const { kty, crv, x, y } = config.sessionJwk;
  try {
    const { payload } = await jwtVerify(token, await importJWK({ kty, crv, x, y }, 'ES256'), {
      issuer: ISSUER,
      algorithms: ['ES256'],
    });
    return {
      userId: String(payload.sub),
      address: getAddress(String(payload.address)),
      expiresAt: Number(payload.exp),
    };
  } catch {
    throw new HttpError(401, 'UNAUTHENTICATED');
  }
}
