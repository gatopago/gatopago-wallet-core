import { type Address, type Hex, keccak256 } from 'viem';
import {
  ACCOUNT_GENERATION,
  authorizationDigest,
  deriveAccountId,
  hashChainScope,
  hashSecurityManifest,
  predictAccountAddress,
  type AuthorizationKind,
  type AuthorizationMessages,
} from '@gatopago/shared/v3/authorizations';
import {
  hashSecurityPolicy,
  Role,
  signerId,
  validateSecurityPolicy,
  type SecurityPolicy,
} from '@gatopago/shared/v3/security-policy';

const ZERO_HASH = `0x${'00'.repeat(32)}` as Hex;
const ZERO_ADDRESS = `0x${'00'.repeat(20)}` as Address;
const MAX_NONCE = (1n << 256n) - 1n;
const MAX_VERSION = (1n << 64n) - 1n;

const MAX_CONSENT_SECONDS = 5 * 60;
const MAX_COMPLETION_SECONDS = 7 * 24 * 60 * 60;
type NonceSpace = 'spend' | 'admin';
type ChangeMessage = AuthorizationMessages['SecurityChange'];
type VersionedMessage = Exclude<
  AuthorizationMessages[AuthorizationKind],
  AuthorizationMessages['InitializationApproval']
>;

export interface ModelWitness {
  signerId: Hex;
  digest: Hex;
}
export interface ModelConfig {
  chainId: bigint;
  account: Address;
  factory: Address;
  senderCreator: Address;
  entryPoint: Address;
  proxyInitCodeHash: Hex;
  implementation: Address;
  runtimeCodeHash: Hex;
  storageLayoutHash: Hex;
}

interface ProposalBase {
  hash: Hex;
  securityVersion: bigint;
  previousManifestHash: Hex;
  chainScopeHash: Hex;
  readyAt: number;
  validUntil: number;
}
type PendingProposal =
  | (ProposalBase & { kind: 'security'; nextPolicy: SecurityPolicy })
  | (ProposalBase & { kind: 'upgrade'; upgrade: AuthorizationMessages['UpgradeManifest'] });

export interface AuthorityModelState {
  config: ModelConfig;
  accountId: Hex;
  policy: SecurityPolicy;
  securityVersion: bigint;
  manifestHash: Hex;
  chainScopeHash: Hex;
  nonces: Record<NonceSpace, bigint>;
  upgradesFrozen: boolean;
  pending: PendingProposal | null;

  spendAuthorizations: bigint;
}

export type ModelAction =
  | {
      type: 'prepareSecurity';
      message: ChangeMessage;
      nextPolicy: SecurityPolicy;
      chains: readonly bigint[];
      witnesses: readonly ModelWitness[];
      enrollments: readonly ModelWitness[];
    }
  | {
      type: 'proposeUpgrade';
      message: AuthorizationMessages['UpgradeManifest'];
      chains: readonly bigint[];
      witnesses: readonly ModelWitness[];
    }
  | {
      type: 'commit';
      message: AuthorizationMessages['CommitProposal'];
      witnesses: readonly ModelWitness[];
      observedCodeHash?: Hex;
      migrationCall?: Hex;
    }
  | {
      type: 'cancel';
      message: AuthorizationMessages['CancelProposal'];
      witnesses: readonly ModelWitness[];
    }
  | {
      type: 'freeze';
      message: AuthorizationMessages['FreezeUpgrades'];
      chains: readonly bigint[];
      witnesses: readonly ModelWitness[];
    }
  | {
      type: 'spend';
      message: AuthorizationMessages['ExecutionPlan'];
      witnesses: readonly ModelWitness[];
    }
  | { type: 'expire'; proposalHash: Hex };

function requireModel(condition: boolean, reason: string): asserts condition {
  if (!condition) throw new Error(reason);
}

function validWindow(message: { validAfter: number; validUntil: number }, now: number): void {
  for (const value of [now, message.validAfter, message.validUntil])
    requireModel(Number.isSafeInteger(value) && value >= 0 && value < 2 ** 48, 'INVALID_TIME');
  requireModel(
    message.validUntil > message.validAfter &&
      now >= message.validAfter &&
      now < message.validUntil,
    'OUTSIDE_VALIDITY',
  );
}

function shortConsent(message: { validAfter: number; validUntil: number }): void {
  requireModel(
    message.validAfter > 0 && message.validUntil - message.validAfter <= MAX_CONSENT_SECONDS,
    'OUTSIDE_VALIDITY',
  );
}

function requireScope(chainId: bigint, chainScopeHash: Hex, chains: readonly bigint[]): void {
  requireModel(
    chains.includes(chainId) && hashChainScope(chains) === chainScopeHash,
    'WRONG_CHAIN_SCOPE',
  );
}

function consume(state: AuthorityModelState, space: NonceSpace): void {
  requireModel(state.nonces[space] < MAX_NONCE, 'NONCE_EXHAUSTED');
  state.nonces[space]++;
}

function checkVersion(state: AuthorityModelState, message: VersionedMessage, now: number): void {
  validWindow(message, now);
  requireModel(
    message.accountId === state.accountId && message.generation === ACCOUNT_GENERATION,
    'WRONG_ACCOUNT',
  );
  requireModel(message.securityVersion === state.securityVersion, 'STALE_SECURITY_VERSION');
  if ('previousManifestHash' in message)
    requireModel(message.previousManifestHash === state.manifestHash, 'WRONG_PREDECESSOR');
}

function consent<K extends AuthorizationKind>(
  state: AuthorityModelState,
  kind: K,
  message: AuthorizationMessages[K],
): Hex {
  return authorizationDigest(kind, state.config.chainId, state.config.account, message);
}

function quorum(
  state: AuthorityModelState,
  digest: Hex,
  witnesses: readonly ModelWitness[],
  role: number,
  threshold: number,
): void {
  requireModel(
    threshold > 0 &&
      witnesses.length >= threshold &&
      witnesses.length <= state.policy.signers.length,
    'QUORUM_NOT_REACHED',
  );
  const seen = new Set<Hex>();
  for (const witness of witnesses) {
    const member = state.policy.signers.find((signer) => signerId(signer) === witness.signerId);
    requireModel(member !== undefined && (member.roles & role) !== 0, 'WRONG_AUTHORITY');
    requireModel(
      witness.digest === digest && !seen.has(witness.signerId),
      'INVALID_OR_DUPLICATE_WITNESS',
    );
    seen.add(witness.signerId);
  }
}

function checkNonce(
  state: AuthorityModelState,
  message: { nonce: bigint },
  space: NonceSpace,
): void {
  requireModel(message.nonce === state.nonces[space], 'WRONG_NONCE');
}

function enrollment(
  state: AuthorityModelState,
  message: ChangeMessage,
  nextPolicy: SecurityPolicy,
  contextHash: Hex,
  witnesses: readonly ModelWitness[],
): void {
  const changed = nextPolicy.signers.filter((signer) => {
    const previous = state.policy.signers.find((old) => signerId(old) === signerId(signer));
    return !previous || previous.roles !== signer.roles;
  });
  requireModel(witnesses.length === changed.length, 'MISSING_ENROLLMENT');
  const seen = new Set<Hex>();
  for (const witness of witnesses) {
    requireModel(
      changed.some((signer) => signerId(signer) === witness.signerId) &&
        !seen.has(witness.signerId),
      'WRONG_ENROLLMENT_SIGNER',
    );
    const proof: AuthorizationMessages['EnrollmentProof'] = {
      accountId: state.accountId,
      generation: ACCOUNT_GENERATION,
      securityVersion: state.securityVersion,
      signerId: witness.signerId,
      nextPolicyHash: message.nextPolicyHash,
      contextHash,
      nonce: message.nonce,
      validAfter: message.validAfter,
      validUntil: message.validUntil,
    };
    requireModel(
      witness.digest === consent(state, 'EnrollmentProof', proof),
      'WRONG_ENROLLMENT_CONTEXT',
    );
    seen.add(witness.signerId);
  }
}

function installPolicy(
  state: AuthorityModelState,
  proposal: ProposalBase & { nextPolicy: SecurityPolicy },
): void {
  requireModel(state.securityVersion < MAX_VERSION, 'VERSION_EXHAUSTED');
  state.securityVersion++;
  state.policy = structuredClone(proposal.nextPolicy);
  state.chainScopeHash = proposal.chainScopeHash;
  state.manifestHash = hashSecurityManifest({
    accountId: state.accountId,
    generation: ACCOUNT_GENERATION,
    securityVersion: state.securityVersion,
    previousManifestHash: state.manifestHash,
    policyHash: hashSecurityPolicy(state.policy),
    chainScopeHash: state.chainScopeHash,
  });
  state.pending = null;
}

export function initializeAuthorityModel(
  config: ModelConfig,
  message: AuthorizationMessages['InitializationApproval'],
  policy: SecurityPolicy,
  chains: readonly bigint[],
  witnesses: readonly ModelWitness[],
  caller: Address,
  now: number,
): AuthorityModelState {
  validWindow(message, now);
  requireModel(
    config.senderCreator !== ZERO_ADDRESS && caller === config.senderCreator,
    'WRONG_INITIALIZATION_CALLER',
  );
  requireModel(
    config.factory !== ZERO_ADDRESS &&
      config.entryPoint !== ZERO_ADDRESS &&
      config.implementation !== ZERO_ADDRESS &&
      config.runtimeCodeHash !== ZERO_HASH &&
      config.storageLayoutHash !== ZERO_HASH &&
      config.proxyInitCodeHash !== ZERO_HASH,
    'INVALID_DEPLOYMENT_CONFIG',
  );
  requireModel(
    message.generation === ACCOUNT_GENERATION && message.nonce === 0n,
    'WRONG_INITIALIZATION_VERSION',
  );
  requireModel(
    message.factory === config.factory && message.entryPoint === config.entryPoint,
    'WRONG_INITIALIZATION_DEPLOYMENT',
  );
  requireModel(
    hashSecurityPolicy(policy) === message.initialSecurityCommitment,
    'WRONG_INITIAL_POLICY',
  );
  requireModel(
    deriveAccountId(message.initialSecurityCommitment, message.userSaltCommitment) ===
      message.accountId,
    'WRONG_INITIAL_IDENTITY',
  );
  requireModel(
    predictAccountAddress(
      config.factory,
      message.accountId,
      config.proxyInitCodeHash,
    ).toLowerCase() === config.account.toLowerCase(),
    'WRONG_PREDICTED_ADDRESS',
  );
  requireScope(config.chainId, message.chainScopeHash, chains);
  const digest = authorizationDigest(
    'InitializationApproval',
    config.chainId,
    config.account,
    message,
  );
  requireModel(
    witnesses.length === policy.signers.length &&
      new Set(witnesses.map((w) => w.signerId)).size === witnesses.length,
    'MISSING_INITIAL_POSSESSION',
  );
  for (const witness of witnesses)
    requireModel(
      witness.digest === digest &&
        policy.signers.some((signer) => signerId(signer) === witness.signerId),
      'WRONG_INITIAL_POSSESSION',
    );
  const manifestHash = hashSecurityManifest({
    accountId: message.accountId,
    generation: ACCOUNT_GENERATION,
    securityVersion: 1n,
    previousManifestHash: ZERO_HASH,
    policyHash: message.initialSecurityCommitment,
    chainScopeHash: message.chainScopeHash,
  });
  return {
    config: structuredClone(config),
    accountId: message.accountId,
    policy: structuredClone(policy),
    securityVersion: 1n,
    manifestHash,
    chainScopeHash: message.chainScopeHash,
    nonces: { spend: 0n, admin: 0n },
    upgradesFrozen: false,
    pending: null,
    spendAuthorizations: 0n,
  };
}

export function transitionAuthorityModel(
  original: AuthorityModelState,
  action: ModelAction,
  now: number,
): AuthorityModelState {
  const state = structuredClone(original);
  requireModel(Number.isSafeInteger(now) && now >= 0 && now < 2 ** 48, 'INVALID_TIME');
  switch (action.type) {
    case 'prepareSecurity': {
      const { message, nextPolicy, witnesses, chains, enrollments } = action;
      checkVersion(state, message, now);
      requireScope(state.config.chainId, message.chainScopeHash, chains);
      validateSecurityPolicy(nextPolicy);
      requireModel(
        nextPolicy.mode === 'active' && hashSecurityPolicy(nextPolicy) === message.nextPolicyHash,
        'WRONG_NEXT_POLICY',
      );
      requireModel(message.nextPolicyHash !== hashSecurityPolicy(state.policy), 'UNCHANGED_POLICY');
      shortConsent(message);
      requireModel(
        Number.isSafeInteger(message.proposalValidUntil) &&
          message.proposalValidUntil >= 0 &&
          message.proposalValidUntil < 2 ** 48,
        'INVALID_TIME',
      );
      const maximumLifetime = MAX_COMPLETION_SECONDS;
      requireModel(
        message.proposalValidUntil > message.validUntil &&
          message.proposalValidUntil - message.validAfter <= maximumLifetime,
        'INVALID_PROPOSAL_LIFETIME',
      );
      requireModel(state.policy.mode === 'active', 'WRONG_ACCOUNT_MODE');

      requireModel(!state.pending, 'PROPOSAL_ALREADY_PENDING');
      const space = 'admin';
      checkNonce(state, message, space);
      const kind = 'SecurityChange';
      const digest = consent(state, kind, message);
      quorum(state, digest, witnesses, Role.ADMIN, state.policy.adminThreshold);
      enrollment(state, message, nextPolicy, digest, enrollments);
      const readyAt = now;
      requireModel(readyAt < message.proposalValidUntil, 'TIMELOCK_EXCEEDS_VALIDITY');
      consume(state, space);
      state.pending = {
        kind: 'security',
        hash: digest,
        securityVersion: state.securityVersion,
        previousManifestHash: state.manifestHash,
        chainScopeHash: message.chainScopeHash,
        readyAt,
        validUntil: message.proposalValidUntil,
        nextPolicy: structuredClone(nextPolicy),
      };
      return state;
    }
    case 'proposeUpgrade': {
      const { message, chains, witnesses } = action;
      checkVersion(state, message, now);
      requireScope(state.config.chainId, message.chainScopeHash, chains);
      requireModel(state.policy.mode === 'active' && !state.upgradesFrozen, 'UPGRADES_DISABLED');
      requireModel(!state.pending, 'PROPOSAL_ALREADY_PENDING');
      checkNonce(state, message, 'admin');
      requireModel(
        message.implementation !== ZERO_ADDRESS &&
          message.implementation !== state.config.implementation &&
          message.runtimeCodeHash !== ZERO_HASH &&
          message.storageLayoutHash !== ZERO_HASH,
        'INVALID_UPGRADE_TARGET',
      );
      const digest = consent(state, 'UpgradeManifest', message);
      quorum(state, digest, witnesses, Role.ADMIN, state.policy.adminThreshold);
      const readyAt = now + state.policy.upgradeDelaySeconds;
      requireModel(readyAt < message.validUntil, 'TIMELOCK_EXCEEDS_VALIDITY');
      consume(state, 'admin');
      state.pending = {
        kind: 'upgrade',
        hash: digest,
        securityVersion: state.securityVersion,
        previousManifestHash: state.manifestHash,
        chainScopeHash: message.chainScopeHash,
        readyAt,
        validUntil: message.validUntil,
        upgrade: structuredClone(message),
      };
      return state;
    }
    case 'commit': {
      const { message, witnesses } = action;
      checkVersion(state, message, now);
      const pending = state.pending;
      requireModel(!!pending, 'NO_ADMIN_PROPOSAL');
      requireModel(
        pending.securityVersion === state.securityVersion &&
          pending.previousManifestHash === state.manifestHash,
        'STALE_PROPOSAL',
      );
      requireModel(
        pending.hash === message.proposalHash && pending.chainScopeHash === message.chainScopeHash,
        'WRONG_PROPOSAL',
      );
      requireModel(now >= pending.readyAt && now < pending.validUntil, 'PROPOSAL_NOT_READY');

      if (pending.kind !== 'upgrade') {
        shortConsent(message);
        requireModel(message.validUntil <= pending.validUntil, 'OUTSIDE_VALIDITY');
      }

      requireModel(message.acknowledgementsHash !== ZERO_HASH, 'MISSING_ACKNOWLEDGEMENTS');
      checkNonce(state, message, 'admin');
      quorum(
        state,
        consent(state, 'CommitProposal', message),
        witnesses,
        Role.ADMIN,
        state.policy.adminThreshold,
      );
      consume(state, 'admin');
      if (pending.kind === 'upgrade') {
        requireModel(!state.upgradesFrozen, 'UPGRADES_DISABLED');
        requireModel(
          action.observedCodeHash === pending.upgrade.runtimeCodeHash,
          'UPGRADE_CODEHASH_MISMATCH',
        );
        requireModel(
          action.migrationCall !== undefined &&
            keccak256(action.migrationCall) === pending.upgrade.migrationCallHash,
          'UPGRADE_MIGRATION_MISMATCH',
        );
        state.config.implementation = pending.upgrade.implementation;
        state.config.runtimeCodeHash = pending.upgrade.runtimeCodeHash;
        state.config.storageLayoutHash = pending.upgrade.storageLayoutHash;
        installPolicy(state, { ...pending, nextPolicy: state.policy });
      } else installPolicy(state, pending);
      return state;
    }
    case 'cancel': {
      const { message, witnesses } = action;
      checkVersion(state, message, now);
      shortConsent(message);
      requireModel(
        !!state.pending && state.pending.hash === message.proposalHash,
        'WRONG_PROPOSAL',
      );
      checkNonce(state, message, 'admin');
      quorum(
        state,
        consent(state, 'CancelProposal', message),
        witnesses,
        Role.ADMIN,
        state.policy.adminThreshold,
      );
      consume(state, 'admin');
      state.pending = null;
      return state;
    }
    case 'freeze': {
      const { message, witnesses, chains } = action;
      checkVersion(state, message, now);
      requireScope(state.config.chainId, message.chainScopeHash, chains);
      requireModel(state.policy.mode === 'active' && !state.upgradesFrozen, 'UPGRADES_DISABLED');
      checkNonce(state, message, 'admin');
      quorum(
        state,
        consent(state, 'FreezeUpgrades', message),
        witnesses,
        Role.ADMIN,
        state.policy.adminThreshold,
      );
      consume(state, 'admin');
      state.upgradesFrozen = true;
      if (state.pending?.kind === 'upgrade') state.pending = null;
      return state;
    }
    case 'spend': {
      const { message, witnesses } = action;
      checkVersion(state, message, now);
      requireModel(state.policy.mode === 'active', 'SPENDING_DISABLED');
      requireModel(
        message.entryPoint === state.config.entryPoint && message.executionMode === 0,
        'UNSUPPORTED_EXECUTION',
      );
      checkNonce(state, message, 'spend');
      quorum(
        state,
        consent(state, 'ExecutionPlan', message),
        witnesses,
        Role.SPEND,
        state.policy.spendThreshold,
      );
      consume(state, 'spend');
      state.spendAuthorizations++;
      return state;
    }
    case 'expire':
      requireModel(!!state.pending && state.pending.hash === action.proposalHash, 'WRONG_PROPOSAL');
      requireModel(now >= state.pending.validUntil, 'PROPOSAL_NOT_EXPIRED');
      state.pending = null;
      return state;
  }
}
