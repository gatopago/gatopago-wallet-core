import { decodeFunctionData, type Hex } from 'viem';
import { describe, expect, it } from 'vitest';
import { accountCreationAbi, authorizeInitialization, loadPinnedCreationProfile, prepareInitialization } from '@gatopago/shared/v3/initialization';
import { deploymentDocumentDigest } from '@gatopago/shared/v3/deployment';
import { fixtureAddress, fixtureHash, fixtureManifest } from '@gatopago/test-fixtures/v3-inspection';
import { initializationFixture } from '@gatopago/test-fixtures/v3-initialization';

describe('V3 explicit initialization consent', () => {
	it('binds the single-passkey consumer policy, original CREATE2 composition and short chain-specific typed approval', () => {
		const fixture = initializationFixture(), prepared = prepareInitialization(fixture.input);
		expect(prepared.policy).toMatchObject({ mode: 'active', spendThreshold: 1, adminThreshold: 1 });
		expect(prepared.policy.signers).toEqual([{ kind: 1, verifier: fixture.profile.webauthn_verifier.address,
			verifierCodeHash: fixture.profile.webauthn_verifier.runtime_code_hash, key: fixture.input.publicKey, roles: 3 }]);
		expect(prepared.message).toMatchObject({ generation: 3, factory: fixture.profile.deployment.components.factory.address,
			entryPoint: fixture.profile.deployment.entry_point, nonce: 0n });
		expect(prepared.chains).toEqual([84532n]);
		expect(Object.isFrozen(prepared.policy.signers[0])).toBe(true);
		expect(Object.isFrozen(prepared.profile.webauthn_verifier.compiler)).toBe(true);
	});
	it('encodes a real P-256 approval into the precise factory ABI (not a directly broadcast transaction)', () => {
		const f = initializationFixture(), prepared = prepareInitialization(f.input);
		const proof = authorizeInitialization(f.input, f.assertion(), f.input.validAfter);
		const decoded = decodeFunctionData({ abi: accountCreationAbi, data: proof.factoryData });
		expect(decoded.functionName).toBe('createAccount');
		expect(decoded.args[0]).toEqual(prepared.message);
		expect({ ...decoded.args[1], signers: decoded.args[1].signers.map((signer) => ({ ...signer, verifier: signer.verifier.toLowerCase() })) })
			.toEqual({ ...prepared.policy, mode: 1 });
		expect(decoded.args[2]).toEqual(prepared.chains);
		expect(decoded.args[3]).toEqual([{ signerIndex: 0, signature: proof.signature }]);
		expect(proof.initCode).toBe(`${proof.factory}${proof.factoryData.slice(2)}`);
		expect(proof.account).toBe(prepared.account);
	});
	it('cannot reinterpret the inspection-only profile as permission for creation', () => {
		const document = JSON.stringify(fixtureManifest());
		expect(() => loadPinnedCreationProfile(document, deploymentDocumentDigest(document))).toThrow('schema');
	});
	it('rejects a byte change without a reviewed new pin', () => {
		const f = initializationFixture();
		expect(() => loadPinnedCreationProfile(`${f.input.document} `, f.input.expectedDigest)).toThrow('pin');
	});
	it.each(['implementation', 'proxy_creation_code', 'candidate', 'verifier', 'entrypoint', 'extra'])('rejects inconsistent creation composition: %s', (kind) => {
		const f = initializationFixture();
		const profile = structuredClone(f.profile);
		const document = JSON.stringify(kind === 'implementation' ? { ...profile, deployment: { ...profile.deployment, components: {
			...profile.deployment.components, implementation: { ...profile.deployment.components.implementation, address: fixtureAddress('f') } } } }
			: kind === 'proxy_creation_code' ? { ...profile, proxy_creation_code: '0x60ff' }
			: kind === 'candidate' ? { ...profile, deployment: { ...profile.deployment, lifecycle_status: 'candidate' } }
			: kind === 'verifier' ? { ...profile, webauthn_verifier: { ...profile.webauthn_verifier, address: profile.deployment.entry_point } }
			: kind === 'entrypoint' ? { ...profile, entry_point_code_hash: `0x${'0'.repeat(64)}` }
			: { ...profile, enabled: true });
		expect(() => loadPinnedCreationProfile(document, deploymentDocumentDigest(document))).toThrow();
	});
	it.each(['salt', 'time', 'key', 'scope'])('a changed %s invalidates possession approval', (kind) => {
		const f = initializationFixture(), second = initializationFixture(), assertion = f.assertion();
		const input = { ...f.input, ...(kind === 'salt' ? { userSaltCommitment: fixtureHash('e') } : kind === 'time'
			? { validAfter: f.input.validAfter + 1, validUntil: f.input.validUntil + 1 } : kind === 'key'
				? { publicKey: second.input.publicKey } : { scope: { ...f.input.scope, origin: 'https://other.gatopago.com' } }) };
		expect(() => authorizeInitialization(input, assertion, f.input.validAfter + 1)).toThrow();
	});
	it.each(['factory', 'entrypoint', 'verifier_hash', 'network'])('validly repinned %s still needs fresh user consent', (kind) => {
		const f = initializationFixture(), p = f.profile;
		const document = JSON.stringify(kind === 'factory' ? { ...p, deployment: { ...p.deployment, components: {
			...p.deployment.components, factory: { ...p.deployment.components.factory, address: fixtureAddress('f') } } } }
			: kind === 'entrypoint' ? { ...p, deployment: { ...p.deployment, entry_point: fixtureAddress('f') } }
			: kind === 'network' ? { ...p, deployment: { ...p.deployment, network_id: 'eip155:421614' } }
			: { ...p, webauthn_verifier: { ...p.webauthn_verifier, runtime_code_hash: fixtureHash('e') } });
		expect(() => authorizeInitialization({ ...f.input, document, expectedDigest: deploymentDocumentDigest(document) },
			f.assertion(), f.input.validAfter)).toThrow();
	});
	it.each([-1, 300, 301])('respects the half-open signed window at offset %d', (offset) => {
		const f = initializationFixture();
		expect(() => authorizeInitialization(f.input, f.assertion(), f.input.validAfter + offset)).toThrow('expired');
	});
	it('refuses missing UV, wrong origin, another key, enrollment challenge and malformed proofs', () => {
		const f = initializationFixture();
		for (const assertion of [f.assertion(undefined, { flags: 1 }), f.assertion(undefined, { origin: 'https://evil.example' }),
			initializationFixture().assertion(prepareInitialization(f.input).digest), f.assertion(fixtureHash('a')),
			{ ...f.assertion(), signatureDER: new Uint8Array(10) }]) {
			expect(() => authorizeInitialization(f.input, assertion, f.input.validAfter)).toThrow();
		}
	});
	it('rejects zero salt, unbounded validity and oversized documents', () => {
		const f = initializationFixture();
		expect(() => prepareInitialization({ ...f.input, userSaltCommitment: `0x${'0'.repeat(64)}` as Hex })).toThrow();
		expect(() => prepareInitialization({ ...f.input, validUntil: f.input.validAfter + 301 })).toThrow();
		expect(() => loadPinnedCreationProfile(' '.repeat(65537), f.input.expectedDigest)).toThrow('64 KiB');
	});
});
