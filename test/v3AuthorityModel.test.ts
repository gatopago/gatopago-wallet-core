import { describe, expect, it } from "vitest";
import { keccak256, type Address, type Hex } from "viem";
import vectors from "@gatopago/shared/fixtures/v3-protocol.json";
import { authorizationDigest, deriveAccountId, hashChainScope, predictAccountAddress, type AuthorizationKind, type AuthorizationMessages } from "@gatopago/shared/v3/authorizations";
import { hashSecurityPolicy, Role, signerId, validateSecurityPolicy, type SecurityPolicy, type SignerDescriptor } from "@gatopago/shared/v3/security-policy";
import { initializeAuthorityModel, transitionAuthorityModel, type AuthorityModelState, type ModelAction, type ModelConfig, type ModelWitness } from "./models/v3AuthorityModel";

const h = (byte: string): Hex => `0x${byte.repeat(32)}`;
const a = (byte: string): Address => `0x${byte.repeat(20)}`;
const NOW = 1_800_000_000;
const DELAY = 259200;
const COMPLETION = 7 * 86400;
const chains = [43113n, 84532n, 421614n];
const initialPolicy = vectors.initialPolicy as SecurityPolicy;
const activePolicy = vectors.activePolicy as SecurityPolicy;

function ecdsa(byte: string, roles = 3): SignerDescriptor {
	return { kind: 0, verifier: a("00"), verifierCodeHash: h("00"), key: a(byte), roles };
}

function sorted(policy: SecurityPolicy): SecurityPolicy {
	return { ...policy, signers: [...policy.signers].sort((x, y) => signerId(x).localeCompare(signerId(y))) };
}

function replacement(): SecurityPolicy {
	return sorted({ ...activePolicy, signers: [ecdsa("33"), ecdsa("44")] });
}

function initial(policy = initialPolicy, chainId = 84532n) {
	const initialSecurityCommitment = hashSecurityPolicy(policy);
	const userSaltCommitment = h("22");
	const accountId = deriveAccountId(initialSecurityCommitment, userSaltCommitment);
	const config: ModelConfig = { chainId, account: predictAccountAddress(a("33"), accountId, h("44")), factory: a("33"), senderCreator: a("88"), entryPoint: a("99"), proxyInitCodeHash: h("44"), implementation: a("ab"), runtimeCodeHash: h("cd"), storageLayoutHash: h("ee") };
	const message: AuthorizationMessages["InitializationApproval"] = { accountId, generation: 3, initialSecurityCommitment, userSaltCommitment, factory: config.factory, entryPoint: config.entryPoint, chainScopeHash: hashChainScope(chains), nonce: 0n, validAfter: NOW, validUntil: NOW + 600 };
	const digest = authorizationDigest("InitializationApproval", chainId, config.account, message);
	const witnesses = policy.signers.map((signer) => ({ signerId: signerId(signer), digest }));
	return { config, message, witnesses, policy };
}

function initialized(policy = initialPolicy, chainId = 84532n): AuthorityModelState {
	const i = initial(policy, chainId);
	return initializeAuthorityModel(i.config, i.message, i.policy, chains, i.witnesses, i.config.senderCreator, NOW);
}

function base(state: AuthorityModelState, now = NOW) {
	return { accountId: state.accountId, generation: 3, securityVersion: state.securityVersion, previousManifestHash: state.manifestHash,
		chainScopeHash: hashChainScope(chains), nonce: state.nonces.admin, validAfter: now, validUntil: now + 2 * DELAY };
}

/** Synthetic already-verified facts for the specification; these are NOT signatures. */
function witnesses<K extends AuthorizationKind>(state: AuthorityModelState, kind: K, message: AuthorizationMessages[K], ids = state.policy.signers.map(signerId)): ModelWitness[] {
	const digest = authorizationDigest(kind, state.config.chainId, state.config.account, message);
	return ids.map((id) => ({ signerId: id, digest }));
}

type ChangeAction = Extract<ModelAction, { nextPolicy: SecurityPolicy }>;
function change(state: AuthorityModelState, type: ChangeAction["type"], nextPolicy: SecurityPolicy, now = NOW): ChangeAction {
	const kind = "SecurityChange";
	const message = { ...base(state, now), nonce: state.nonces.admin,
		nextPolicyHash: hashSecurityPolicy(nextPolicy), validUntil: now + 300,
		proposalValidUntil: now + COMPLETION };
	const authorizations = witnesses(state, kind, message);
	const contextHash = authorizations[0].digest;
	const enrollments = nextPolicy.signers.filter((signer) => {
		const old = state.policy.signers.find((candidate) => signerId(candidate) === signerId(signer));
		return !old || old.roles !== signer.roles;
	}).map((signer) => witnesses(state, "EnrollmentProof", {
		...message, signerId: signerId(signer), contextHash,
	}, [signerId(signer)])[0]);
	return { type, message, nextPolicy, witnesses: authorizations, chains, enrollments };
}

function upgrade(state: AuthorityModelState, now = NOW): Extract<ModelAction, { type: "proposeUpgrade" }> {
	const message = { ...base(state, now), implementation: a("ac"), runtimeCodeHash: h("ad"), storageLayoutHash: h("ae"), migrationCallHash: keccak256("0x1234") };
	return { type: "proposeUpgrade", message, chains, witnesses: witnesses(state, "UpgradeManifest", message) };
}

function commit(state: AuthorityModelState, now = NOW): Extract<ModelAction, { type: "commit" }> {
	if (!state.pending) throw new Error("Test requires pending proposal");
	const message = { ...base(state, now), proposalHash: state.pending.hash, chainScopeHash: state.pending.chainScopeHash, acknowledgementsHash: h("fa") };
	if (state.pending.kind !== "upgrade") {
		message.validUntil = state.pending.validUntil > now ? Math.min(now + 300, state.pending.validUntil) : now + 300;
	}
	return { type: "commit", message, witnesses: witnesses(state, "CommitProposal", message), observedCodeHash: h("ad"), migrationCall: "0x1234" };
}

function freeze(state: AuthorityModelState, now = NOW): Extract<ModelAction, { type: "freeze" }> {
	const message = base(state, now);
	return { type: "freeze", message, chains, witnesses: witnesses(state, "FreezeUpgrades", message) };
}

function cancel(state: AuthorityModelState, now = NOW): Extract<ModelAction, { type: "cancel" }> {
	if (!state.pending) throw new Error("Test requires pending proposal");
	const message = { ...base(state, now), validUntil: now + 300, proposalHash: state.pending.hash, nonce: state.nonces.admin };
	return { type: "cancel", message, witnesses: witnesses(state, "CancelProposal", message) };
}

function spend(state: AuthorityModelState, now = NOW): Extract<ModelAction, { type: "spend" }> {
	const message = { ...base(state, now), nonce: state.nonces.spend, executionMode: 0, entryPoint: state.config.entryPoint, userOpHash: h("11"), callsHash: h("12"), assetLimitsHash: h("13"), feePolicyHash: h("14"), paymaster: a("15"), previewHash: h("16") };
	return { type: "spend", message, witnesses: witnesses(state, "ExecutionPlan", message, state.policy.signers.filter((s) => (s.roles & Role.SPEND) !== 0).map(signerId)) };
}

function active(): AuthorityModelState {
	const initialState = initialized();
	const prepared = transitionAuthorityModel(initialState, change(initialState, "prepareSecurity", activePolicy), NOW);
	return transitionAuthorityModel(prepared, commit(prepared), NOW);
}

function reject(state: AuthorityModelState, action: ModelAction, reason: string, now = NOW): void {
	const before = structuredClone(state);
	expect(() => transitionAuthorityModel(state, action, now)).toThrow(reason);
	expect(state).toEqual(before);
}

describe("V3 authority state specification — not a deployed contract or cryptographic verifier", () => {
	it("initialization binds factory, caller, chain, commitment, address and initial possession", () => {
		const i = initial();
		const run = (config = i.config, message = i.message, proofs = i.witnesses, caller = i.config.senderCreator, scope = chains) => initializeAuthorityModel(config, message, i.policy, scope, proofs, caller, NOW);
		expect(run().policy.mode).toBe("active");
		expect(() => run(i.config, i.message, [], i.config.senderCreator)).toThrow("MISSING_INITIAL_POSSESSION");
		expect(() => run(i.config, i.message, i.witnesses, a("77"))).toThrow("WRONG_INITIALIZATION_CALLER");
		expect(() => run({ ...i.config, account: a("77") })).toThrow("WRONG_PREDICTED_ADDRESS");
		expect(() => run(i.config, { ...i.message, factory: a("77") })).toThrow("WRONG_INITIALIZATION_DEPLOYMENT");
		expect(() => run(i.config, { ...i.message, initialSecurityCommitment: h("77") })).toThrow("WRONG_INITIAL_POLICY");
		expect(() => run(i.config, { ...i.message, userSaltCommitment: h("77") })).toThrow("WRONG_INITIAL_IDENTITY");
		expect(() => run(i.config, { ...i.message, nonce: 1n })).toThrow("WRONG_INITIALIZATION_VERSION");
		expect(() => run(i.config, i.message, i.witnesses, i.config.senderCreator, [43113n])).toThrow("WRONG_CHAIN_SCOPE");
		expect(() => run({ ...i.config, chainId: 43113n })).toThrow("WRONG_INITIAL_POSSESSION");
	});


	it("optional enrollment proves the old and new factors, stages the change, then needs a fresh commit", () => {
		const state = initialized();
		const request = change(state, "prepareSecurity", activePolicy);
		reject(state, { ...request, witnesses: [] }, "QUORUM_NOT_REACHED");
		reject(state, { ...request, enrollments: [] }, "MISSING_ENROLLMENT");
		const prepared = transitionAuthorityModel(state, request, NOW);
		expect(prepared.policy).toEqual(state.policy);
		expect(prepared.securityVersion).toBe(1n);
		expect(prepared.nonces).toEqual({ spend: 0n, admin: 1n });
		const confirmation = commit(prepared);
		reject(prepared, { ...confirmation, witnesses: request.witnesses }, "INVALID_OR_DUPLICATE_WITNESS");
		const promoted = transitionAuthorityModel(prepared, confirmation, NOW);
		expect(promoted.policy).toEqual(activePolicy);
		expect(promoted.securityVersion).toBe(2n);
		expect(promoted.manifestHash).not.toBe(state.manifestHash);
		expect(promoted.pending).toBeNull();
		reject(promoted, request, "STALE_SECURITY_VERSION");
	});

	it.each(["prepareSecurity"] as const)("%s accepts short consent and completes after finality with a fresh bounded commit", (type) => {
		const state = type === "prepareSecurity" ? initialized() : active();
		const policy = type === "prepareSecurity" ? activePolicy : replacement();
		const request = change(state, type, policy);
		reject(state, request, "OUTSIDE_VALIDITY", request.message.validUntil);
		const queued = transitionAuthorityModel(state, request, NOW);
		expect(queued.pending?.validUntil).toBe(request.message.proposalValidUntil);
		expect(queued.pending?.validUntil).toBeGreaterThan(request.message.validUntil);
		const later = NOW + 3600;
		const fresh = commit(queued, later);
		reject(queued, { ...fresh, witnesses: request.witnesses }, "INVALID_OR_DUPLICATE_WITNESS", later);
		reject(queued, { ...fresh, message: { ...fresh.message, validUntil: later + 301 } }, "OUTSIDE_VALIDITY", later);
		const installed = transitionAuthorityModel(queued, fresh, later);
		expect(installed.policy).toEqual(policy);
		expect(installed.accountId).toBe(state.accountId);
		expect(queued.pending?.validUntil).toBe(request.message.proposalValidUntil);
		const lastMinute = queued.pending!.validUntil - 60;
		const nearExpiry = commit(queued, lastMinute);
		reject(queued, { ...nearExpiry, message: { ...nearExpiry.message, validUntil: queued.pending!.validUntil + 1 } }, "OUTSIDE_VALIDITY", lastMinute);
		reject(queued, commit(queued, queued.pending!.validUntil), "PROPOSAL_NOT_READY", queued.pending!.validUntil);
	});

	it.each(["prepareSecurity"] as const)("%s binds bounded proposal lifetime into old-factor consent and new-factor enrollment", (type) => {
		const state = type === "prepareSecurity" ? initialized() : active();
		const request = change(state, type, type === "prepareSecurity" ? activePolicy : replacement());
		for (const proposalValidUntil of [request.message.validUntil, request.message.proposalValidUntil + 1]) {
			reject(state, { ...request, message: { ...request.message, proposalValidUntil } }, "INVALID_PROPOSAL_LIFETIME");
		}
		for (const proposalValidUntil of [NaN, Infinity, -1, NOW + 0.5, 2 ** 48]) {
			reject(state, { ...request, message: { ...request.message, proposalValidUntil } }, "INVALID_TIME");
		}
		reject(state, { ...request, message: { ...request.message, validUntil: NOW + 301 } }, "OUTSIDE_VALIDITY");
		const shorter = { ...request, message: { ...request.message, proposalValidUntil: request.message.proposalValidUntil - 1 } };
		reject(state, shorter, "INVALID_OR_DUPLICATE_WITNESS");
		const kind = "SecurityChange";
		reject(state, { ...shorter, witnesses: witnesses(state, kind, shorter.message) }, "WRONG_ENROLLMENT_CONTEXT");
	});


	it("new key possession cannot be borrowed from another account, chain, purpose or proposal", () => {
		const state = initialized();
		const request = change(state, "prepareSecurity", activePolicy);
		const wrongContext = change({ ...state, nonces: { ...state.nonces, admin: 9n } }, "prepareSecurity", activePolicy);
		const otherChain = change({ ...state, config: { ...state.config, chainId: 43113n } }, "prepareSecurity", activePolicy);
		const otherAccount = change({ ...state, accountId: h("ff") }, "prepareSecurity", activePolicy);
		for (const borrowed of [wrongContext, otherChain, otherAccount]) reject(state, { ...request, enrollments: borrowed.enrollments }, "WRONG_ENROLLMENT_CONTEXT");
		const duplicate = [request.enrollments[0], request.enrollments[0]];
		reject(state, { ...request, enrollments: duplicate }, "MISSING_ENROLLMENT");
	});

	it("an active consumer policy replacement requires current admin consent", () => {
		const state = active();
		const request = change(state, "prepareSecurity", replacement());
		reject(state, { ...request, witnesses: [] }, "QUORUM_NOT_REACHED");
		reject(state, { ...request, witnesses: [request.witnesses[0], request.witnesses[0]] }, "INVALID_OR_DUPLICATE_WITNESS");
		const prepared = transitionAuthorityModel(state, request, NOW);
		reject(prepared, change(prepared, "prepareSecurity", replacement()), "PROPOSAL_ALREADY_PENDING");
		const confirmation = commit(prepared);
		reject(prepared, { ...confirmation, message: { ...confirmation.message, acknowledgementsHash: h("00") } }, "MISSING_ACKNOWLEDGEMENTS");
		reject(prepared, { ...confirmation, message: { ...confirmation.message, acknowledgementsHash: h("01") } }, "INVALID_OR_DUPLICATE_WITNESS");
		const updated = transitionAuthorityModel(prepared, confirmation, NOW);
		expect(updated.policy).toEqual(replacement());
		expect(updated.securityVersion).toBe(state.securityVersion + 1n);
		expect(updated.nonces.spend).toBe(state.nonces.spend);
		reject(updated, spend(state), "STALE_SECURITY_VERSION");
		const oldSigners = witnesses(updated, "ExecutionPlan", spend(updated).message, state.policy.signers.map(signerId));
		reject(updated, { ...spend(updated), witnesses: oldSigners }, "WRONG_AUTHORITY");
	});

	it("uses independent spend/admin/rotation nonce domains and prevents spend replay", () => {
		const state = active();
		const request = spend(state);
		const sent = transitionAuthorityModel(state, request, NOW);
		expect(sent.nonces).toEqual({ ...state.nonces, spend: 1n });
		reject(sent, request, "WRONG_NONCE");
		const queued = transitionAuthorityModel(sent, change(sent, "prepareSecurity", replacement()), NOW);
		expect(queued.nonces).toEqual({ ...sent.nonces, admin: sent.nonces.admin + 1n });
		const adminSignature = witnesses(sent, "FreezeUpgrades", change(sent, "prepareSecurity", replacement()).message);
		reject(sent, { ...change(sent, "prepareSecurity", replacement()), witnesses: adminSignature }, "INVALID_OR_DUPLICATE_WITNESS");
	});




	it.each(["prepareSecurity", "proposeUpgrade"] as const)("current ADMIN can cancel %s with its configured threshold", (type) => {
		const state = active();
		const action = type === "proposeUpgrade" ? upgrade(state) : change(state, type, replacement());
		const queued = transitionAuthorityModel(state, action, NOW);
		const cancellation = cancel(queued);
		const canceled = transitionAuthorityModel(queued, cancellation, NOW);
		expect(canceled.pending).toBeNull();
		expect(canceled.policy).toEqual(state.policy);
		expect(canceled.nonces).toEqual({ ...queued.nonces, admin: queued.nonces.admin + 1n });
		reject(canceled, action, "WRONG_NONCE");
		const again = transitionAuthorityModel(canceled, type === "proposeUpgrade" ? upgrade(canceled) : change(canceled, type, replacement()), NOW);
		reject(again, cancellation, "WRONG_PROPOSAL");
		const fresh = cancel(again);
		reject(again, { ...fresh, message: { ...fresh.message, nonce: 0n } }, "WRONG_NONCE");
	});


	it("upgrade requires 72h, a fresh admin commit, the pinned code and exact migration bytes", () => {
		const state = active();
		const queued = transitionAuthorityModel(state, upgrade(state), NOW);
		reject(queued, commit(queued), "PROPOSAL_NOT_READY");
		const confirmation = commit(queued, NOW + DELAY);
		reject(queued, { ...confirmation, witnesses: [] }, "QUORUM_NOT_REACHED", NOW + DELAY);
		reject(queued, { ...confirmation, observedCodeHash: h("00") }, "UPGRADE_CODEHASH_MISMATCH", NOW + DELAY);
		reject(queued, { ...confirmation, migrationCall: "0x12" }, "UPGRADE_MIGRATION_MISMATCH", NOW + DELAY);
		const updated = transitionAuthorityModel(queued, confirmation, NOW + DELAY);
		expect(updated.config.implementation).toBe(a("ac"));
		expect(updated.policy).toEqual(state.policy);
		expect(updated.securityVersion).toBe(state.securityVersion + 1n);
		expect(updated.nonces).toEqual({ ...state.nonces, admin: state.nonces.admin + 2n });
		expect(updated.spendAuthorizations).toBe(state.spendAuthorizations);
	});

	it("freeze cancels an upgrade irreversibly and rotation cannot thaw it", () => {
		const state = active();
		const upgrading = transitionAuthorityModel(state, upgrade(state), NOW);
		const frozen = transitionAuthorityModel(upgrading, freeze(upgrading), NOW);
		expect(frozen.upgradesFrozen).toBe(true);
		expect(frozen.pending).toBeNull();
		reject(frozen, upgrade(frozen), "UPGRADES_DISABLED");
		const recovering = transitionAuthorityModel(frozen, change(frozen, "prepareSecurity", replacement()), NOW);
		const recovered = transitionAuthorityModel(recovering, commit(recovering, NOW + DELAY), NOW + DELAY);
		expect(recovered.upgradesFrozen).toBe(true);
		reject(recovered, upgrade(recovered, NOW + DELAY), "UPGRADES_DISABLED", NOW + DELAY);
		expect(transitionAuthorityModel(recovered, spend(recovered, NOW + DELAY), NOW + DELAY).spendAuthorizations).toBe(1n);
	});

	it("freeze remains available during rotation without erasing the rotation or its wait", () => {
		const state = active();
		const queued = transitionAuthorityModel(state, change(state, "prepareSecurity", replacement()), NOW);
		const frozen = transitionAuthorityModel(queued, freeze(queued), NOW);
		expect(frozen.pending).toEqual(queued.pending);
		expect(frozen.upgradesFrozen).toBe(true);
	});

	it("expiry is permissionless, exclusive at validUntil, and does not recycle consumed nonces", () => {
		const state = active();
		const request = change(state, "prepareSecurity", replacement());
		const queued = transitionAuthorityModel(state, request, NOW);
		const expiry = queued.pending!.validUntil;
		reject(queued, { type: "expire", proposalHash: queued.pending!.hash }, "PROPOSAL_NOT_EXPIRED", expiry - 1);
		reject(queued, commit(queued, expiry), "PROPOSAL_NOT_READY", expiry);
		const expired = transitionAuthorityModel(queued, { type: "expire", proposalHash: queued.pending!.hash }, expiry);
		expect(expired.pending).toBeNull();
		expect(expired.nonces.admin).toBe(state.nonces.admin + 1n);
		expect(expired.policy).toEqual(state.policy);
	});


	it("rejects wrong predecessors, unsupported execution modes, nonces at exhaustion and invalid clocks", () => {
		const state = active();
		const request = change(state, "prepareSecurity", replacement());
		reject(state, { ...request, message: { ...request.message, previousManifestHash: h("fe") } }, "WRONG_PREDECESSOR");
		const daily = spend(state);
		reject(state, { ...daily, message: { ...daily.message, executionMode: 1 } }, "UNSUPPORTED_EXECUTION");
		reject(state, { ...daily, message: { ...daily.message, entryPoint: a("ff") } }, "UNSUPPORTED_EXECUTION");
		for (const clock of [NaN, Infinity, -1, NOW + 0.5, 2 ** 48]) reject(state, daily, "INVALID_TIME", clock);
		reject(state, daily, "OUTSIDE_VALIDITY", NOW - 1);
		const exhausted = { ...state, nonces: { ...state.nonces, spend: (1n << 256n) - 1n } };
		reject(exhausted, spend(exhausted), "NONCE_EXHAUSTED");
		const finalVersion = { ...state, securityVersion: (1n << 64n) - 1n };
		const queued = transitionAuthorityModel(finalVersion, change(finalVersion, "prepareSecurity", replacement()), NOW);
		reject(queued, commit(queued), "VERSION_EXHAUSTED");
	});

	it("same security transition converges across three chains despite different local admin nonces", () => {
		const manifests = chains.map((chainId, index) => {
			const state = initialized(initialPolicy, chainId);
			// A prior canceled proposal advances only that chain's nonce, not its manifest.
			let prior = state;
			for (let n = 0; n < index; n++) {
				const prepared = transitionAuthorityModel(prior, change(prior, "prepareSecurity", activePolicy), NOW);
				prior = transitionAuthorityModel(prepared, cancel(prepared), NOW);
			}
			const queued = transitionAuthorityModel(prior, change(prior, "prepareSecurity", activePolicy), NOW);
			return transitionAuthorityModel(queued, commit(queued), NOW);
		});
		expect(new Set(manifests.map((state) => state.manifestHash)).size).toBe(1);
		expect(new Set(manifests.map((state) => state.nonces.admin)).size).toBe(3);
		expect(new Set(manifests.map((state) => state.config.account)).size).toBe(1);
	});

	it("bounded transition walks preserve identity, monotone nonces, sticky freeze and separation of effects", () => {
		const successful = new Set<ModelAction["type"]>();
		for (let seed = 1; seed <= 32; seed++) {
			let state = active();
			let clock = NOW;
			let random = seed;
			for (let step = 0; step < 48; step++) {
				random = (Math.imul(random, 1664525) + 1013904223) >>> 0;
				clock += random % 3 === 0 ? COMPLETION + 1 : 1;
				// Hash only the selected action. Coverage/seed/depth stay identical under full-suite contention.
				const candidates: Array<() => ModelAction> = [() => spend(state, clock), () => freeze(state, clock), () => upgrade(state, clock),
					() => change(state, "prepareSecurity", state.policy.signers.some((s) => s.key === a("33")) ? activePolicy : replacement(), clock)];
				if (state.pending) candidates.push(() => commit(state, clock), () => cancel(state, clock), () => ({ type: "expire", proposalHash: state.pending!.hash }));
				const action = candidates[random % candidates.length]();
				const before = structuredClone(state);
				try {
					state = transitionAuthorityModel(state, action, clock);
					successful.add(action.type);
				} catch (error) {
					expect(error).toBeInstanceOf(Error);
					expect(state).toEqual(before);
					continue;
				}
				expect(state.accountId).toBe(before.accountId);
				expect(state.config.account).toBe(before.config.account);
				expect(state.config.entryPoint).toBe(before.config.entryPoint);
				for (const space of ["spend", "admin"] as const) expect(state.nonces[space]).toBeGreaterThanOrEqual(before.nonces[space]);
				expect(state.securityVersion >= before.securityVersion && state.securityVersion <= before.securityVersion + 1n).toBe(true);
				if (before.upgradesFrozen) expect(state.upgradesFrozen).toBe(true);
				if (action.type !== "spend") expect(state.spendAuthorizations).toBe(before.spendAuthorizations);
				if (action.type !== "commit") expect(state.config).toEqual(before.config);
				expect(() => validateSecurityPolicy(state.policy)).not.toThrow();
			}
		}
		expect([...successful]).toEqual(expect.arrayContaining(["spend", "freeze", "prepareSecurity", "proposeUpgrade", "commit", "cancel", "expire"]));
	}, 15_000);
});
