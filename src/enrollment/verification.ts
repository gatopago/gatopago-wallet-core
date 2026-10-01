import { verifyRegistrationResponse, type RegistrationResponseJSON } from '@simplewebauthn/server';
import { cose, decodeAttestationObject, decodeCredentialPublicKey } from '@simplewebauthn/server/helpers';
import { bytesToHex, concatHex, hexToBytes, sha256, stringToHex, type Hex } from 'viem';
import { assertWebAuthnKey, encodeWebAuthnAssertion, type WebAuthnScope } from '@gatopago/shared/v3/webauthn';

export class EnrollmentError extends Error {
	constructor(readonly code: 'INVALID_ENROLLMENT' | 'ENROLLMENT_EXPIRED' | 'ENROLLMENT_CONFLICT' | 'ENROLLMENT_LIMIT') {
		super(code); this.name = 'EnrollmentError';
	}
}
const invalid = (): never => { throw new EnrollmentError('INVALID_ENROLLMENT'); };
const transports = ['ble', 'cable', 'hybrid', 'internal', 'nfc', 'smart-card', 'usb'] as const;

export function base64url(bytes: Uint8Array): string {
	return btoa(String.fromCharCode(...bytes)).replaceAll('+', '-').replaceAll('/', '_').replace(/=+$/, '');
}
export function webAuthnBytes(value: unknown, max: number): Uint8Array<ArrayBuffer> {
	if (typeof value !== 'string' || value.length > Math.ceil(max * 4 / 3) || !/^[A-Za-z0-9_-]+$/.test(value)) return invalid();
	try {
		const bytes = Uint8Array.from(atob(value.replaceAll('-', '+').replaceAll('_', '/')), (char) => char.charCodeAt(0));
		if (!bytes.length || bytes.length > max || base64url(bytes) !== value) return invalid();
		return bytes;
	} catch { return invalid(); }
}
function object(input: unknown, fields: string[]): Record<string, unknown> {
	if (!input || typeof input !== 'object' || Array.isArray(input) || Object.keys(input).length !== fields.length
		|| !fields.every((field) => Object.hasOwn(input, field))) return invalid();
	return input as Record<string, unknown>;
}

/** Only the none/ES256 profile requested by Consumer. No remote attestation/MDS
 * fetch, trust in a client-supplied SPKI, or authenticator/vendor assertion.
 * Proof-of-possession uses the same codec and signature checks as Account V3.
 */
export async function verifyEnrollment(input: unknown, expected: {
	scope: WebAuthnScope; challenge: Hex; proofChallenge: Hex;
}) {
	try {
		const body = object(input, ['credential_id', 'client_data', 'attestation', 'transports', 'proof']);
		const credentialId = base64url(webAuthnBytes(body.credential_id, 1024));
		const clientData = webAuthnBytes(body.client_data, 2048);
		const attestation = webAuthnBytes(body.attestation, 8192);
		const proof = object(body.proof, ['authenticator_data', 'client_data', 'signature']);
		const assertion = { authenticatorData: webAuthnBytes(proof.authenticator_data, 1024),
			clientDataJSON: webAuthnBytes(proof.client_data, 2048), signatureDER: webAuthnBytes(proof.signature, 72) };
		if (!Array.isArray(body.transports) || body.transports.length > transports.length ||
			!body.transports.every((item): item is typeof transports[number] => transports.some((value) => value === item)) ||
			new Set(body.transports).size !== body.transports.length) return invalid();
		const selectedTransports = [...body.transports].sort();
		const json: unknown = JSON.parse(new TextDecoder('utf-8', { fatal: true }).decode(clientData));
		if (!json || typeof json !== 'object' || !('crossOrigin' in json) || json.crossOrigin !== false || 'topOrigin' in json) return invalid();
		const decoded = decodeAttestationObject(attestation);
		if (decoded.get('fmt') !== 'none' || decoded.get('attStmt').size !== 0) return invalid();
		const registration: RegistrationResponseJSON = { id: credentialId, rawId: credentialId, type: 'public-key',
			clientExtensionResults: {}, response: { clientDataJSON: base64url(clientData), attestationObject: base64url(attestation), transports: selectedTransports } };
		const result = await verifyRegistrationResponse({ response: registration, expectedOrigin: expected.scope.origin,
			expectedRPID: expected.scope.rpId, expectedChallenge: base64url(hexToBytes(expected.challenge)),
			requireUserPresence: true, requireUserVerification: true, supportedAlgorithmIDs: [-7] });
		if (!result.verified || result.registrationInfo.credential.id !== credentialId) return invalid();
		const info = result.registrationInfo;
		const key = decodeCredentialPublicKey(info.credential.publicKey);
		if (!cose.isCOSEPublicKeyEC2(key) || key.get(cose.COSEKEYS.alg) !== -7 || key.get(cose.COSEKEYS.crv) !== 1) return invalid();
		const x = key.get(cose.COSEKEYS.x), y = key.get(cose.COSEKEYS.y);
		if (!(x instanceof Uint8Array) || !(y instanceof Uint8Array) || x.length !== 32 || y.length !== 32) return invalid();
		const publicKey = concatHex([sha256(stringToHex(expected.scope.rpId)), sha256(stringToHex(expected.scope.origin)), bytesToHex(x), bytesToHex(y)]);
		assertWebAuthnKey(expected.scope, publicKey);
		encodeWebAuthnAssertion({ scope: expected.scope, key: publicKey, challenge: expected.proofChallenge, response: assertion });
		// A backup-capable credential cannot change its eligibility between these two ceremonies.
		const backupEligible = (assertion.authenticatorData[32] & 8) !== 0;
		if (backupEligible !== (info.credentialDeviceType === 'multiDevice')) return invalid();
		const signCount = new DataView(assertion.authenticatorData.buffer).getUint32(33, false);
		if ((signCount !== 0 || info.credential.counter !== 0) && signCount <= info.credential.counter) return invalid();
		// Stable field order gives retries a content identity; caller JSON ordering is irrelevant.
		const responseHash = sha256(stringToHex(JSON.stringify([credentialId, base64url(clientData), base64url(attestation),
			selectedTransports, base64url(assertion.authenticatorData), base64url(assertion.clientDataJSON), base64url(assertion.signatureDER)])));
		return Object.freeze({ credentialId, publicKey, transports: selectedTransports, aaguid: info.aaguid,
			backupEligible, backedUp: (assertion.authenticatorData[32] & 16) !== 0, signCount, responseHash });
	} catch (error) { if (error instanceof EnrollmentError) throw error; return invalid(); }
}
