import { readFileSync } from "node:fs";
import { describe, expect, it } from "vitest";
import { encodeFunctionData, getAddress, keccak256, zeroAddress, zeroHash, type Abi, type Hex } from "viem";
import { authorizationDigest, hashChainScope } from "@gatopago/shared/v3/authorizations";
import { accountUpgradeAbi, encodeUpgradeProposal, encodeUpgradeCommit, type UpgradeManifest, type UpgradeCommit } from "@gatopago/shared/v3/upgrade";

const account = getAddress(`0x${"11".repeat(20)}`);
const target = getAddress(`0x${"22".repeat(20)}`);
const hash = `0x${"ab".repeat(32)}` as Hex;
const chainId = 84532n;
const chains = [chainId];
const migration = "0x12345678" as Hex;
const proposal: UpgradeManifest = {
	accountId: hash, generation: 3, securityVersion: 1n, previousManifestHash: hash,
	implementation: target, runtimeCodeHash: hash, storageLayoutHash: hash,
	chainScopeHash: hashChainScope(chains), migrationCallHash: keccak256(migration),
	nonce: 0n, validAfter: 1, validUntil: 1_000_000,
};
const commit: UpgradeCommit = {
	accountId: hash, generation: 3, securityVersion: 1n, previousManifestHash: hash,
	proposalHash: authorizationDigest("UpgradeManifest", chainId, account, proposal),
	acknowledgementsHash: hash, chainScopeHash: proposal.chainScopeHash,
	nonce: 1n, validAfter: 300_000, validUntil: 400_000,
};
// Encoding fixtures, not valid cryptographic signatures. Solidity tests use real quorum signatures.
const votes = [{ signerIndex: 0, signature: "0x1234" as Hex }, { signerIndex: 1, signature: "0x5678" as Hex }];

describe("Account V3 typed upgrade transport", () => {
	it("matches the actual composed Account ABI and never encodes the unrestricted UUPS selector", () => {
		const artifact = JSON.parse(readFileSync(new URL(import.meta.resolve('@gatopago/contract-artifacts/AccountV3.json')), "utf8")) as { abi: Abi };
		expect(encodeUpgradeProposal(account, chainId, proposal, chains, votes)).toBe(encodeFunctionData({ abi: artifact.abi, functionName: "proposeUpgrade", args: [proposal, chains, votes] }));
		expect(encodeUpgradeCommit(account, chainId, proposal, commit, migration, votes)).toBe(encodeFunctionData({ abi: artifact.abi, functionName: "commitUpgrade", args: [commit, migration, votes] }));
		expect(accountUpgradeAbi.some((item) => item.type === "function" && item.name as string === "upgradeToAndCall")).toBe(false);
	});
	it("binds proposal, account, chain, version, acknowledgements, nonce and exact migration", () => {
		for (const changed of [{ proposalHash: zeroHash }, { accountId: zeroHash }, { securityVersion: 2n },
			{ previousManifestHash: zeroHash }, { acknowledgementsHash: zeroHash }, { chainScopeHash: zeroHash }, { nonce: 0n }]) {
			expect(() => encodeUpgradeCommit(account, chainId, proposal, { ...commit, ...changed }, migration, votes)).toThrow();
		}
		expect(() => encodeUpgradeCommit(account, chainId, proposal, commit, "0x", votes)).toThrow();
		expect(() => encodeUpgradeCommit(target, chainId, proposal, commit, migration, votes)).toThrow();
		expect(() => encodeUpgradeCommit(account, 43113n, proposal, commit, migration, votes)).toThrow();
		expect(authorizationDigest("CommitProposal", chainId, account, commit)).not.toBe(commit.proposalHash);
	});
	it("rejects invalid scope, zero targets, stale generations and ambiguous vote sets", () => {
		for (const changed of [{ generation: 2 }, { securityVersion: 0n }, { securityVersion: 1n << 64n },
			{ implementation: zeroAddress }, { implementation: account }, { runtimeCodeHash: zeroHash }, { storageLayoutHash: zeroHash }]) {
			expect(() => encodeUpgradeProposal(account, chainId, { ...proposal, ...changed }, chains, votes)).toThrow();
		}
		for (const scope of [[], [chainId, chainId], [43113n], [chainId, 1n]]) {
			expect(() => encodeUpgradeProposal(account, chainId, proposal, scope, votes)).toThrow();
		}
		for (const invalid of [[], votes.slice(0, 1), [votes[0], votes[0]], [votes[0], { signerIndex: 16, signature: "0x" as Hex }],
			[votes[0], { signerIndex: 1, signature: `0x${"11".repeat(4097)}` as Hex }]]) {
			expect(() => encodeUpgradeProposal(account, chainId, proposal, chains, invalid)).toThrow();
			expect(() => encodeUpgradeCommit(account, chainId, proposal, commit, migration, invalid)).toThrow();
		}
	});
});
