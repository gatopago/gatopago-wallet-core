import { createHash, generateKeyPairSync, sign } from 'node:crypto';
import { isoCBOR } from '@simplewebauthn/server/helpers';
import { hexToBytes, type Hex } from 'viem';
import { base64url } from '../src/enrollment/verification';

type Key = ReturnType<typeof generateKey>;
export const generateKey = () => generateKeyPairSync('ec', { namedCurve: 'prime256v1' });
const decode = (value: string) => Uint8Array.from(Buffer.from(value, 'base64url'));
const text = (value: string) => new TextEncoder().encode(value);
const hash = (value: string | Uint8Array) => Uint8Array.from(createHash('sha256').update(value).digest());
const join = (...parts: Uint8Array[]) => Uint8Array.from(parts.flatMap((part) => [...part]));

/** Real ephemeral OpenSSL P-256 keys/DER signatures plus FIDO none CBOR. No
 * mocking verifyRegistrationResponse, the Account V3 codec, D1, or JWT crypto.
 */
export function credential(attempt: { scope: { rpId: string; origin: string }; options: { challenge: string }; proof_challenge: Hex }, options: {
	key?: Key; proofKey?: Key; createChallenge?: string; proofChallenge?: string;
	createOrigin?: string; proofOrigin?: string; rp?: string; id?: Uint8Array;
	createFlags?: number; proofFlags?: number; createCount?: number; proofCount?: number;
	alg?: number; fmt?: string; crossOrigin?: boolean;
} = {}) {
	const key = options.key ?? generateKey(), jwk = key.publicKey.export({ format: 'jwk' });
	const id = options.id ?? crypto.getRandomValues(new Uint8Array(32));
	const cose = isoCBOR.encode(new Map<number, number | Uint8Array>([
		[1, 2], [3, options.alg ?? -7], [-1, 1], [-2, decode(jwk.x!)], [-3, decode(jwk.y!)],
	]));
	const auth = (flags: number, count: number) => {
		const data = new Uint8Array(37); data.set(hash(options.rp ?? attempt.scope.rpId)); data[32] = flags;
		new DataView(data.buffer).setUint32(33, count, false); return data;
	};
	const length = new Uint8Array(2); new DataView(length.buffer).setUint16(0, id.length, false);
	const creationData = join(auth(options.createFlags ?? 0x45, options.createCount ?? 0), new Uint8Array(16), length, id, cose);
	const attestation = isoCBOR.encode(new Map<string, string | Uint8Array | Map<string, string>>([
		['fmt', options.fmt ?? 'none'], ['attStmt', new Map()], ['authData', creationData],
	]));
	const creationJson = JSON.stringify({ type: 'webauthn.create', challenge: options.createChallenge ?? attempt.options.challenge,
		origin: options.createOrigin ?? attempt.scope.origin, crossOrigin: options.crossOrigin ?? false });
	const proofJson = JSON.stringify({ type: 'webauthn.get', challenge: options.proofChallenge ?? base64url(hexToBytes(attempt.proof_challenge)),
		origin: options.proofOrigin ?? attempt.scope.origin, crossOrigin: false });
	const authData = auth(options.proofFlags ?? 5, options.proofCount ?? 1);
	return { credential_id: base64url(id), client_data: base64url(text(creationJson)), attestation: base64url(attestation),
		transports: ['internal'], proof: { authenticator_data: base64url(authData), client_data: base64url(text(proofJson)),
			signature: base64url(sign('sha256', join(authData, hash(proofJson)), options.proofKey?.privateKey ?? key.privateKey)) } };
}

export function authentication(attempt: { scope: { rpId: string; origin: string }; options: { challenge: string } },
  key: Key, credentialId: string, userHandle: string, options: { count?: number; flags?: number; origin?: string; challenge?: string; rp?: string } = {}) {
  const authData = new Uint8Array(37);
  authData.set(hash(options.rp ?? attempt.scope.rpId)); authData[32] = options.flags ?? 5;
  new DataView(authData.buffer).setUint32(33, options.count ?? 2, false);
  const json = JSON.stringify({ type: 'webauthn.get', challenge: options.challenge ?? attempt.options.challenge,
    origin: options.origin ?? attempt.scope.origin, crossOrigin: false });
  return { credential_id: credentialId, authenticator_data: base64url(authData), client_data: base64url(text(json)),
    signature: base64url(sign('sha256', join(authData, hash(json)), key.privateKey)), user_handle: userHandle };
}
