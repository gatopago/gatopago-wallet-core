import { readFileSync } from "node:fs";
import { describe, expect, it } from "vitest";
import { decodeAbiParameters, encodeFunctionData, getAddress, size, type Abi, type Hex } from "viem";
import vectors from "@gatopago/shared/fixtures/v3-protocol.json";
import { ACCOUNT_SIGNATURE_TYPEHASH, MAX_ACCOUNT_SIGNATURE_BYTES, accountSignatureDigest, accountSignatureStructHash, accountSignatureParameters, accountInteropAbi, encodeAccountSignature, type AccountSignature } from "@gatopago/shared/v3/contract-signature";
import { authorizationTypes, authorizationTypeHash, type AuthorizationKind } from "@gatopago/shared/v3/authorizations";

const message: AccountSignature = { ...vectors.contractSignature.message, accountId: vectors.contractSignature.message.accountId as Hex, applicationHash: vectors.contractSignature.message.applicationHash as Hex, securityVersion: 1n };
const account = getAddress(vectors.identity.accountAddress);
const votes = [{ signerIndex: 0, signature: "0x1234" as const }];

describe("Account V3 contract signature transport", () => {
	it("matches cross-language type, struct, digest and ABI envelope vectors", () => {
		expect(ACCOUNT_SIGNATURE_TYPEHASH).toBe(vectors.contractSignature.expectedTypeHash);
		expect(accountSignatureStructHash(message)).toBe(vectors.contractSignature.expectedStructHash);
		expect(accountSignatureDigest(84532n, account, message)).toBe(vectors.contractSignature.expectedDigest);
		const encoded = encodeAccountSignature(message, votes);
		expect(encoded).toBe(vectors.contractSignature.envelope);
		expect(decodeAbiParameters(accountSignatureParameters, encoded)).toEqual([message, votes]);
	});
	it("keeps all nonce-consuming authorizations in distinct signature domains", () => {
		for (const kind of Object.keys(authorizationTypes) as AuthorizationKind[]) {
			expect(ACCOUNT_SIGNATURE_TYPEHASH).not.toBe(authorizationTypeHash(kind));
		}
		const digest = accountSignatureDigest(84532n, account, message);
		for (const changed of [{ accountId: `0x${"ab".repeat(32)}` as Hex }, { applicationHash: `0x${"cd".repeat(32)}` as Hex }, { securityVersion: 2n }]) {
			expect(accountSignatureDigest(84532n, account, { ...message, ...changed })).not.toBe(digest);
		}
		expect(accountSignatureDigest(43113n, account, message)).not.toBe(digest);
		expect(accountSignatureDigest(84532n, getAddress(`0x${"ef".repeat(20)}`), message)).not.toBe(digest);
	});
	it("rejects invalid identity/version and bounded vote profiles before asking for a signature", () => {
		for (const changed of [{ generation: 2 }, { securityVersion: 0n }, { securityVersion: 1n << 64n }]) {
			expect(() => encodeAccountSignature({ ...message, ...changed }, votes)).toThrow();
		}
		expect(() => accountSignatureDigest(0n, account, message)).toThrow();
		for (const invalid of [[], [votes[0], votes[0]], [{ signerIndex: 16, signature: "0x" as Hex }], [{ signerIndex: 0.5, signature: "0x" as Hex }], [{ signerIndex: 0, signature: `0x${"11".repeat(4097)}` as Hex }]]) {
			expect(() => encodeAccountSignature(message, invalid)).toThrow();
		}
		const maximum = Array.from({ length: 16 }, (_, signerIndex) => ({ signerIndex, signature: `0x${"11".repeat(4096)}` as Hex }));
		expect(size(encodeAccountSignature(message, maximum))).toBe(MAX_ACCOUNT_SIGNATURE_BYTES);
	});
	it("uses the standard deployed-contract verification interface without exposing signature internals to consumers", () => {
		const artifact = JSON.parse(readFileSync(new URL(import.meta.resolve('@gatopago/contract-artifacts/AccountV3Interop.json')), "utf8")) as { abi: Abi };
		const signature = encodeAccountSignature(message, votes);
		expect(encodeFunctionData({ abi: accountInteropAbi, functionName: "isValidSignature", args: [message.applicationHash, signature] }))
			.toBe(encodeFunctionData({ abi: artifact.abi, functionName: "isValidSignature", args: [message.applicationHash, signature] }));
	});
});
