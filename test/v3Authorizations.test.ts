import { describe, expect, it } from 'vitest';
import { type Address, type Hex } from 'viem';
import vectors from '@gatopago/shared/fixtures/v3-protocol.json';
import {
  ACCOUNT_GENERATION,
  authorizationDigest,
  authorizationStructHash,
  authorizationTypeHash,
  authorizationTypes,
  deriveAccountId,
  hashCalls,
  hashChainScope,
  hashSecurityManifest,
  MIN_UPGRADE_DELAY_SECONDS,
  predictAccountAddress,
  type AuthorizationKind,
  type AuthorizationMessages,
  type ExecutionPlan,
} from '@gatopago/shared/v3/authorizations';

const account = vectors.identity.accountAddress as Address;
const plan: ExecutionPlan = {
  ...vectors.authorizations.ExecutionPlan.message,
  accountId: vectors.identity.accountId as Hex,
  securityVersion: BigInt(vectors.authorizations.ExecutionPlan.message.securityVersion),
  nonce: BigInt(vectors.authorizations.ExecutionPlan.message.nonce),
  entryPoint: vectors.authorizations.ExecutionPlan.message.entryPoint as Address,
  paymaster: vectors.authorizations.ExecutionPlan.message.paymaster as Address,
  userOpHash: vectors.authorizations.ExecutionPlan.message.userOpHash as Hex,
  callsHash: vectors.callsHash as Hex,
  assetLimitsHash: vectors.authorizations.ExecutionPlan.message.assetLimitsHash as Hex,
  feePolicyHash: vectors.authorizations.ExecutionPlan.message.feePolicyHash as Hex,
  previewHash: vectors.authorizations.ExecutionPlan.message.previewHash as Hex,
};

describe('V3 consent, identity and domain separation', () => {
  for (const kind of Object.keys(authorizationTypes) as AuthorizationKind[]) {
    it(`${kind}: Solidity fixture parity, every field and both domain boundaries`, () => {
      const fixture = vectors.authorizations[kind];
      const raw: Record<string, string | number> = fixture.message;
      const message = Object.fromEntries(
        authorizationTypes[kind].map((field) => [
          field.name,
          field.type === 'uint64' || field.type === 'uint256'
            ? BigInt(raw[field.name])
            : raw[field.name],
        ]),
      ) as AuthorizationMessages[typeof kind];
      const original = authorizationDigest(kind, 84532n, account, message);
      expect(authorizationTypeHash(kind)).toBe(fixture.expectedTypeHash);
      expect(authorizationStructHash(kind, message)).toBe(fixture.expectedStructHash);
      expect(original).toBe(fixture.expectedDigest);
      for (const [key, value] of Object.entries(message)) {
        const changed =
          typeof value === 'bigint'
            ? value + 1n
            : typeof value === 'number'
              ? value + 1
              : `${value.slice(0, -1)}${value.endsWith('0') ? '1' : '0'}`;
        const substituted = { ...message, [key]: changed };
        if (key === 'generation')
          expect(() => authorizationDigest(kind, 84532n, account, substituted)).toThrow();
        else
          expect(authorizationDigest(kind, 84532n, account, substituted), key).not.toBe(original);
      }
      expect(authorizationDigest(kind, 43113n, account, message)).not.toBe(original);
      expect(authorizationDigest(kind, 84532n, `0x${'fe'.repeat(20)}`, message)).not.toBe(original);
    });
  }

  it('keeps all eight ceremony purposes distinct', () => {
    const hashes = Object.keys(authorizationTypes).map((kind) =>
      authorizationTypeHash(kind as AuthorizationKind),
    );
    expect(hashes).toHaveLength(8);
    expect(new Set(hashes).size).toBe(hashes.length);
  });

  it('initial consent has no UserOp/signature cycle and the common manifest excludes local nonces', () => {
    expect(authorizationTypes.InitializationApproval.map((field) => field.name)).not.toContain(
      'userOpHash',
    );
    const raw = vectors.securityManifest;
    const manifest = {
      ...raw,
      accountId: raw.accountId as Hex,
      securityVersion: BigInt(raw.securityVersion),
      previousManifestHash: raw.previousManifestHash as Hex,
      policyHash: raw.policyHash as Hex,
      chainScopeHash: raw.chainScopeHash as Hex,
    };
    expect(hashSecurityManifest(manifest)).toBe(vectors.securityManifestHash);
    expect(hashSecurityManifest({ ...manifest, securityVersion: 3n })).not.toBe(
      vectors.securityManifestHash,
    );
    expect(() => hashSecurityManifest({ ...manifest, generation: 2 })).toThrow();
    expect(() => hashSecurityManifest({ ...manifest, securityVersion: 0n })).toThrow();
  });
  it('matches the same execution vector exercised independently in Solidity', () => {
    expect(authorizationTypeHash('ExecutionPlan')).toBe(
      vectors.authorizations.ExecutionPlan.expectedTypeHash,
    );
    expect(authorizationStructHash('ExecutionPlan', plan)).toBe(
      vectors.authorizations.ExecutionPlan.expectedStructHash,
    );
    expect(authorizationDigest('ExecutionPlan', 84532n, account, plan)).toBe(
      vectors.authorizations.ExecutionPlan.expectedDigest,
    );
  });

  it('does not derive identity from a home chain or login identity', () => {
    const id = deriveAccountId(
      vectors.identity.initialSecurityCommitment as Hex,
      vectors.identity.userSaltCommitment as Hex,
    );
    expect(id).toBe(vectors.identity.accountId);
    expect(
      predictAccountAddress(
        vectors.identity.factory as Address,
        id,
        vectors.identity.proxyInitCodeHash as Hex,
      ),
    ).toBe(account);
    expect(
      deriveAccountId(`0x${'ff'.repeat(32)}`, vectors.identity.userSaltCommitment as Hex),
    ).not.toBe(id);
  });

  it('binds every execution field, including gas sponsorship, fees and preview', () => {
    const initial = authorizationDigest('ExecutionPlan', 84532n, account, plan);
    for (const key of Object.keys(plan) as (keyof ExecutionPlan)[]) {
      const old = plan[key];
      const changed =
        typeof old === 'bigint'
          ? old + 1n
          : typeof old === 'number'
            ? old + 1
            : `${old.slice(0, -1)}${old.endsWith('0') ? '1' : '0'}`;
      if (key === 'generation') {
        expect(() =>
          authorizationDigest('ExecutionPlan', 84532n, account, { ...plan, generation: 2 }),
        ).toThrow();
      } else {
        expect(
          authorizationDigest('ExecutionPlan', 84532n, account, { ...plan, [key]: changed }),
          key,
        ).not.toBe(initial);
      }
    }
    expect(authorizationDigest('ExecutionPlan', 43113n, account, plan)).not.toBe(initial);
    expect(authorizationDigest('ExecutionPlan', 84532n, `0x${'ff'.repeat(20)}`, plan)).not.toBe(
      initial,
    );
  });

  it('does not publish retired bootstrap, recovery or veto purposes', () => {
    for (const kind of ['BackupEnrollment', 'RecoveryProposal', 'VetoProposal'])
      expect(authorizationTypes).not.toHaveProperty(kind);
  });
  it('commits to the ordered batch and exact calldata', () => {
    const calls = vectors.calls.map((call) => ({
      target: call.target as Address,
      value: BigInt(call.value),
      data: call.data as Hex,
    }));
    expect(hashCalls(calls)).toBe(vectors.callsHash);
    expect(hashCalls([...calls].reverse())).not.toBe(vectors.callsHash);
    expect(hashCalls([{ ...calls[0], data: '0x00' }, calls[1]])).not.toBe(vectors.callsHash);
    expect(() => hashCalls([])).toThrow();
    expect(() => hashCalls(Array.from({ length: 33 }, () => calls[0]))).toThrow();
  });

  it('requires explicit, canonical chain scope and finite authorization windows', () => {
    expect(hashChainScope(vectors.chains.map(BigInt))).toBe(vectors.chainScopeHash);
    for (const scope of [[], [0n], [84532n, 43113n], [43113n, 43113n]])
      expect(() => hashChainScope(scope)).toThrow();
    expect(() => authorizationDigest('ExecutionPlan', 0n, account, plan)).toThrow();
    expect(() =>
      authorizationDigest('ExecutionPlan', 84532n, account, {
        ...plan,
        validUntil: plan.validAfter,
      }),
    ).toThrow();
    expect(ACCOUNT_GENERATION).toBe(3);
    expect(MIN_UPGRADE_DELAY_SECONDS).toBe(259200);
  });
  for (const kind of ['InitializationApproval', 'ExecutionPlan'] as const) {
    it(`${kind}: refuses zero/infinite/block-range timestamps before signing`, () => {
      const fixture = vectors.authorizations[kind].message;
      const message = {
        ...fixture,
        accountId: fixture.accountId as Hex,
        nonce: BigInt(fixture.nonce),
        ...('securityVersion' in fixture
          ? { securityVersion: BigInt(fixture.securityVersion) }
          : {}),
      } as AuthorizationMessages[typeof kind];
      for (const [validAfter, validUntil] of [
        [0, 10],
        [1, 0],
        [2, 2],
        [1, 0x800000000000],
      ]) {
        expect(() =>
          authorizationDigest(kind, 84532n, account, { ...message, validAfter, validUntil }),
        ).toThrow();
      }
      for (const [validAfter, validUntil] of [
        [1, 2],
        [0x7ffffffffffe, 0x7fffffffffff],
      ]) {
        expect(
          authorizationDigest(kind, 84532n, account, { ...message, validAfter, validUntil }),
        ).toMatch(/^0x[0-9a-f]{64}$/);
      }
    });
  }
});
