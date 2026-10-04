import { readFileSync } from 'node:fs';
import { describe, expect, it } from 'vitest';
import {
  encodeFunctionData,
  encodeFunctionResult,
  keccak256,
  zeroHash,
  type Abi,
  type Hex,
} from 'viem';
import {
  accountSecurityInspectionAbi,
  inspectAccountSecurity,
} from '@gatopago/shared/v3/security-inspection';
import { signerId } from '@gatopago/shared/v3/security-policy';
import { checkpoint, fixtureAddress, fixtureHash } from '@gatopago/test-fixtures/v3-inspection';
import { securityInspectionScenario } from '@gatopago/test-fixtures/v3-security-inspection';

const snapshotSelector = encodeFunctionData({
  abi: accountSecurityInspectionAbi,
  functionName: 'securitySnapshot',
});
const policySelector = encodeFunctionData({
  abi: accountSecurityInspectionAbi,
  functionName: 'securityPolicy',
});
function pending(test: ReturnType<typeof securityInspectionScenario>, kind = 1) {
  Object.assign(test.security, {
    pendingKind: BigInt(kind),
    pendingHash: fixtureHash('f'),
    pendingVersion: 2n,
    pendingPreviousManifestHash: test.security.manifestHash,
    pendingChainScopeHash: fixtureHash('f'),
    pendingReadyAt: 1n,
    pendingValidUntil: 2n,
  });
}

describe('Current Account V3 security inspection', () => {
  it('matches compiled production getter ABIs, preserves large nonces and grants no spend authority', async () => {
    const test = securityInspectionScenario();
    test.security.spendNonce = 2n ** 255n;
    const artifact = JSON.parse(
      readFileSync(
        new URL(import.meta.resolve('@gatopago/contract-artifacts/AccountV3.json')),
        'utf8',
      ),
    ) as { abi: Abi };
    const result = await inspectAccountSecurity(test.client, test.input);
    expect(result).toMatchObject({
      status: 'recognized',
      spend_readiness: 'not_assessed',
      checkpoint,
      security: {
        phase: 'active_policy',
        policy: test.policy,
        pending: null,
        nonces: { spend: (2n ** 255n).toString() },
      },
    });
    for (const [name, value] of [
      ['securitySnapshot', test.words()],
      ['securityPolicy', test.wirePolicy],
    ] as const) {
      expect(encodeFunctionData({ abi: artifact.abi, functionName: name })).toBe(
        encodeFunctionData({ abi: accountSecurityInspectionAbi, functionName: name }),
      );
      expect(encodeFunctionResult({ abi: artifact.abi, functionName: name, result: value })).toBe(
        encodeFunctionResult({
          abi: accountSecurityInspectionAbi,
          functionName: name,
          result: value,
        }),
      );
    }
  });
  it('checks every state read at the same canonical hash and never performs a write', async () => {
    const test = securityInspectionScenario();
    await inspectAccountSecurity(test.client, test.input);
    expect(test.request).toHaveBeenCalledTimes(16);
    for (const [req] of test.request.mock.calls) {
      expect(['eth_chainId', 'eth_getBlockByNumber', 'eth_call', 'eth_getCode']).toContain(
        req.method,
      );
      if (req.method === 'eth_call' || req.method === 'eth_getCode')
        expect(req.params?.[1]).toEqual({
          blockHash: checkpoint.block_hash,
          requireCanonical: true,
        });
    }
  });
  it('does not call a security getter for undeployed or unrecognized code', async () => {
    for (const deployed of [false, true]) {
      const test = securityInspectionScenario();
      test.state.deployed = deployed;
      if (deployed) test.state.target = fixtureAddress('f');
      if (deployed)
        await expect(inspectAccountSecurity(test.client, test.input)).rejects.toThrow(
          'UNEXPECTED_IMPLEMENTATION',
        );
      else
        expect((await inspectAccountSecurity(test.client, test.input)).status).toBe('not_deployed');
      expect(
        test.request.mock.calls.some(([r]) => JSON.stringify(r).includes(snapshotSelector)),
      ).toBe(false);
    }
  });
  it('reports an administrative proposal pending even if its time window elapsed, without auto-expiring it', async () => {
    const test = securityInspectionScenario();
    pending(test);
    test.security.flags = 3n;
    const result = await inspectAccountSecurity(test.client, test.input);
    expect(result).toMatchObject({
      spend_readiness: 'not_assessed',
      security: {
        phase: 'active_policy',
        upgrades_frozen: true,
        pending: { kind: 1, ready_at: 1, valid_until: 2 },
      },
    });
  });
  it.each([1, 2])(
    'preserves pending change kind %i without treating it as recovery',
    async (kind) => {
      const test = securityInspectionScenario();
      pending(test, kind);
      expect(await inspectAccountSecurity(test.client, test.input)).toMatchObject({
        security: { phase: 'active_policy', pending: { kind } },
      });
    },
  );
  it('rejects retired proposal kind on an active policy and pending upgrade after a freeze', async () => {
    const test = securityInspectionScenario();
    pending(test, 3);
    await expect(inspectAccountSecurity(test.client, test.input)).rejects.toThrow(
      'IDENTITY_MISMATCH',
    );
    pending(test, 2);
    test.security.flags = 3n;
    await expect(inspectAccountSecurity(test.client, test.input)).rejects.toThrow(
      'IDENTITY_MISMATCH',
    );
  });
  it('reports creation pending without equating an initialized proxy with completed creation', async () => {
    const test = securityInspectionScenario();
    test.security.creationValidAfter = 10n;
    test.security.creationValidUntil = 20n;
    expect(await inspectAccountSecurity(test.client, test.input)).toMatchObject({
      security: { phase: 'creation_pending' },
      spend_readiness: 'not_assessed',
    });
  });
  it('reports a single active passkey and verifies the live code of its WebAuthn validator', async () => {
    const test = securityInspectionScenario(),
      verifier = fixtureAddress('f'),
      code = '0x6060' as const;
    test.wirePolicy.adminThreshold = 1;
    test.wirePolicy.signers = [
      {
        kind: 1,
        verifier,
        verifierCodeHash: keccak256(code),
        key: `0x${'ab'.repeat(128)}`,
        roles: 3,
      },
    ];
    test.state.codes.set(verifier, code);
    expect(await inspectAccountSecurity(test.client, test.input)).toMatchObject({
      security: { phase: 'active_policy' },
      spend_readiness: 'not_assessed',
    });
    test.state.codes.set(verifier, '0x');
    await expect(inspectAccountSecurity(test.client, test.input)).rejects.toThrow(
      'UNEXPECTED_CODE',
    );
  });
  it('deduplicates contract-code reads while enforcing every signer pin', async () => {
    const test = securityInspectionScenario(),
      verifier = fixtureAddress('f'),
      code = '0x6060' as const;
    test.wirePolicy.signers = ['ab', 'cd']
      .map((key) => ({
        kind: 1 as const,
        verifier,
        verifierCodeHash: keccak256(code),
        key: `0x${key.repeat(128)}` as Hex,
        roles: 3,
      }))
      .sort((a, b) => signerId(a).localeCompare(signerId(b)));
    test.state.codes.set(verifier, code);
    await inspectAccountSecurity(test.client, test.input);
    expect(
      test.request.mock.calls.filter(
        ([r]) => r.method === 'eth_getCode' && r.params?.[0] === verifier,
      ),
    ).toHaveLength(1);
  });
  it.each([
    { wireRevision: 0n },
    { flags: 0n },
    { securityVersion: 1n },
    { manifestHash: zeroHash },
    { chainScopeHash: zeroHash },
    { flags: 5n },
    { pendingKind: 5n },
    { flags: 9n },
    { pendingVersion: 2n ** 64n },
    { creationValidUntil: 2n ** 48n },
    { creationValidAfter: 1 },
    { creationValidAfter: 2, creationValidUntil: 1 },
    { pendingHash: fixtureHash('f') },
    { pendingVersion: 1n },
    { pendingPreviousManifestHash: fixtureHash('f') },
    { pendingChainScopeHash: fixtureHash('f') },
    { pendingReadyAt: 1 },
    { pendingValidUntil: 1 },
  ])('rejects inconsistent current security case %#', async (patch) => {
    const test = securityInspectionScenario();
    Object.assign(test.security, patch);
    await expect(inspectAccountSecurity(test.client, test.input)).rejects.toThrow(
      'IDENTITY_MISMATCH',
    );
  });
  it.each([
    { pendingHash: zeroHash },
    { pendingVersion: 1n },
    { pendingPreviousManifestHash: fixtureHash('c') },
    { pendingChainScopeHash: zeroHash },
    { pendingReadyAt: 2 },
    { creationValidAfter: 1, creationValidUntil: 3 },
  ])('rejects inconsistent pending metadata case %#', async (patch) => {
    const test = securityInspectionScenario();
    pending(test);
    Object.assign(test.security, patch);
    await expect(inspectAccountSecurity(test.client, test.input)).rejects.toThrow(
      'IDENTITY_MISMATCH',
    );
  });
  it('does not trust a version-one manifest with unrelated initial policy', async () => {
    const test = securityInspectionScenario();
    test.security.securityVersion = 1n;
    test.state.observation.securityVersion = 1n;
    await expect(inspectAccountSecurity(test.client, test.input)).rejects.toThrow(
      'IDENTITY_MISMATCH',
    );
  });
  it.each([null, '0x', '0x0', '0xgg', `0x${'00'.repeat(6433)}`])(
    'rejects malformed or oversized policy output %s',
    async (invalid) => {
      const test = securityInspectionScenario(),
        original = test.request.getMockImplementation()!;
      test.request.mockImplementation(async (req) =>
        JSON.stringify(req).includes(policySelector) ? invalid : original(req),
      );
      await expect(inspectAccountSecurity(test.client, test.input)).rejects.toThrow();
    },
  );
  it.each([0, 1, 2, 3])(
    'rejects noncanonical/trailing ABI, invalid mode or duplicate keys (%i)',
    async (variant) => {
      const test = securityInspectionScenario(),
        original = test.request.getMockImplementation()!;
      if (variant === 2) test.wirePolicy.mode = 2;
      if (variant === 3) test.wirePolicy.signers[1] = test.wirePolicy.signers[0];
      if (variant < 2)
        test.request.mockImplementation(async (req) => {
          const value = await original(req);
          return JSON.stringify(req).includes(variant === 0 ? snapshotSelector : policySelector)
            ? `${String(value)}00`
            : value;
        });
      await expect(inspectAccountSecurity(test.client, test.input)).rejects.toThrow();
    },
  );
  it('rechecks canonicality after security getters, not only after deployment metadata', async () => {
    const test = securityInspectionScenario(),
      original = test.request.getMockImplementation()!;
    test.request.mockImplementation(async (req) => {
      const value = await original(req);
      if (JSON.stringify(req).includes(policySelector)) test.state.blockHash = fixtureHash('e');
      return value;
    });
    await expect(inspectAccountSecurity(test.client, test.input)).rejects.toThrow(
      'CHECKPOINT_MISMATCH',
    );
  });
  it('pins the input throughout asynchronous inspection and redacts provider failure', async () => {
    const test = securityInspectionScenario();
    const operation = inspectAccountSecurity(test.client, test.input);
    Object.assign(test.input.checkpoint, { block_hash: fixtureHash('f'), block_number: '99' });
    expect((await operation).checkpoint).toEqual(checkpoint);
    const other = securityInspectionScenario(),
      original = other.request.getMockImplementation()!;
    other.request.mockImplementation(async (req) => {
      if (
        req.method === 'eth_call' &&
        (req.params?.[0] as { data: Hex }).data === snapshotSelector
      ) {
        throw new Error('https://provider.test?secret=do-not-show');
      }
      return original(req);
    });
    await expect(inspectAccountSecurity(other.client, other.input)).rejects.toThrow(
      'RPC_UNAVAILABLE',
    );
  });
});
