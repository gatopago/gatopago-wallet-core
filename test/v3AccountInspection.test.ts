import { readFileSync } from 'node:fs';
import { describe, expect, it } from 'vitest';
import {
  decodeFunctionData,
  encodeFunctionData,
  encodeFunctionResult,
  toHex,
  zeroHash,
  type Abi,
} from 'viem';
import {
  accountInspectionAbi,
  inspectAccountDeployment,
} from '@gatopago/shared/v3/account-inspection';
import { deploymentDocumentDigest } from '@gatopago/shared/v3/deployment';
import {
  checkpoint,
  fixtureAddress,
  fixtureHash,
  inspectionScenario,
} from '@gatopago/test-fixtures/v3-inspection';

describe('Account V3 pinned read-only inspection', () => {
  it('matches the compiled factory ABI and checks the exact expected composition', async () => {
    const test = inspectionScenario();
    const artifact = JSON.parse(
      readFileSync(
        new URL(import.meta.resolve('@gatopago/contract-artifacts/AccountFactoryV3.json')),
        'utf8',
      ),
    ) as { abi: Abi };
    const result = await inspectAccountDeployment(test.client, test.input);
    expect(result).toMatchObject({
      account: test.account,
      status: 'recognized',
      security_version: '2',
      spend_readiness: 'not_assessed',
      checkpoint,
    });
    const contractCalls = test.request.mock.calls.filter(([req]) => req.method === 'eth_call');
    let found = false;
    for (const [req] of contractCalls) {
      const call = req.params?.[0] as { to: string; data: `0x${string}` };
      const decoded = decodeFunctionData({ abi: accountInspectionAbi, data: call.data });
      if (decoded.functionName !== 'inspectAccount') continue;
      found = true;
      expect(call.data).toBe(
        encodeFunctionData({
          abi: artifact.abi,
          functionName: decoded.functionName,
          args: decoded.args,
        }),
      );
      expect(decoded.args[2]).toEqual({
        implementation: test.manifest.components.implementation.address,
        runtimeCodeHash: test.manifest.components.implementation.runtime_code_hash,
        storageLayoutHash: test.manifest.storage_layout_hash,
        securityModule: test.manifest.components.security_module.address,
        securityModuleCodeHash: test.manifest.components.security_module.runtime_code_hash,
        upgradeModule: test.manifest.components.upgrade_module.address,
        upgradeModuleCodeHash: test.manifest.components.upgrade_module.runtime_code_hash,
      });
      expect(
        encodeFunctionResult({
          abi: artifact.abi,
          functionName: 'inspectAccount',
          result: test.state.observation,
        }),
      ).toBe(
        encodeFunctionResult({
          abi: accountInspectionAbi,
          functionName: 'inspectAccount',
          result: test.state.observation,
        }),
      );
    }
    expect(found).toBe(true);
  });
  it('pins all code and call reads to one canonical hash, without latest or mutation methods', async () => {
    const test = inspectionScenario();
    await inspectAccountDeployment(test.client, test.input);
    for (const [req] of test.request.mock.calls) {
      expect(['eth_chainId', 'eth_getBlockByNumber', 'eth_getCode', 'eth_call']).toContain(
        req.method,
      );
      if (req.method === 'eth_call' || req.method === 'eth_getCode')
        expect(req.params?.[1]).toEqual({
          blockHash: checkpoint.block_hash,
          requireCanonical: true,
        });
      expect(JSON.stringify(req)).not.toContain('latest');
    }
  });
  it('reports an undeployed address without inspecting or creating the implementation', async () => {
    const test = inspectionScenario();
    test.state.deployed = false;
    const result = await inspectAccountDeployment(test.client, test.input);
    expect(result.status).toBe('not_deployed');
    expect(result.spend_readiness).toBe('not_assessed');
    expect(test.request.mock.calls.filter(([r]) => r.method === 'eth_call')).toHaveLength(2);
  });
  it.each(['candidate', 'retired'])(
    'rejects %s profiles before any RPC I/O',
    async (lifecycle_status) => {
      const test = inspectionScenario();
      const document = JSON.stringify({ ...test.manifest, lifecycle_status });
      await expect(
        inspectAccountDeployment(test.client, {
          ...test.input,
          document,
          expectedDigest: deploymentDocumentDigest(document),
        }),
      ).rejects.toThrow('not deployed');
      expect(test.request).not.toHaveBeenCalled();
    },
  );
  it('rejects a mismatched file, invalid identity and pre-deployment checkpoint without RPC', async () => {
    const test = inspectionScenario();
    for (const patch of [
      { expectedDigest: fixtureHash('f') },
      { initialSecurityCommitment: zeroHash },
      { checkpoint: { ...checkpoint, block_number: '9' } },
      { checkpoint: { ...checkpoint, block_number: '01' } },
    ]) {
      await expect(
        inspectAccountDeployment(test.client, { ...test.input, ...patch }),
      ).rejects.toThrow();
    }
    expect(test.request).not.toHaveBeenCalled();
  });
  it('fails on wrong chain, genesis or fork before querying any contract', async () => {
    for (const patch of [
      { chainId: toHex(1) },
      { genesis: fixtureHash('9') },
      { blockHash: fixtureHash('9') },
    ]) {
      const test = inspectionScenario();
      Object.assign(test.state, patch);
      await expect(inspectAccountDeployment(test.client, test.input)).rejects.toThrow();
      expect(test.request.mock.calls.some(([r]) => r.method === 'eth_call')).toBe(false);
    }
  });
  it('rejects a reorg at the closing checkpoint even if preceding state calls succeeded', async () => {
    const test = inspectionScenario();
    const original = test.request.getMockImplementation()!;
    let checkpointReads = 0;
    test.request.mockImplementation(async (req) => {
      if (
        req.method === 'eth_getBlockByNumber' &&
        req.params?.[0] === '0x64' &&
        ++checkpointReads === 2
      )
        test.state.blockHash = fixtureHash('e');
      return original(req);
    });
    await expect(inspectAccountDeployment(test.client, test.input)).rejects.toThrow(
      'CHECKPOINT_MISMATCH',
    );
  });
  it('does not fall back when EIP-1898 is unavailable and redacts upstream diagnostics', async () => {
    const test = inspectionScenario();
    const original = test.request.getMockImplementation()!;
    test.request.mockImplementation((req) => {
      if (req.method === 'eth_getCode')
        throw new Error('Unsupported blockHash at https://rpc.example?secret=abc');
      return original(req);
    });
    await expect(inspectAccountDeployment(test.client, test.input)).rejects.toMatchObject({
      message: 'RPC_UNAVAILABLE',
    });
    expect(test.request.mock.calls.filter(([r]) => r.method === 'eth_getCode')).toHaveLength(1);
  });
  it('verifies factory code before any getters and rejects proxy/dependency substitution', async () => {
    for (const role of [
      'factory',
      'implementation',
      'security_module',
      'upgrade_module',
      'proxy',
    ] as const) {
      const test = inspectionScenario();
      test.state.codes.set(
        role === 'proxy' ? test.account : test.manifest.components[role].address,
        '0x',
      );
      // Empty account code specifically means not deployed; nonempty unexpected proxy must fail.
      if (role === 'proxy') test.state.codes.set(test.account, '0x6060');
      await expect(inspectAccountDeployment(test.client, test.input)).rejects.toThrow(
        'UNEXPECTED_CODE',
      );
      if (role === 'factory')
        expect(test.request.mock.calls.some(([r]) => r.method === 'eth_call')).toBe(false);
    }
  });
  it('does not call unknown implementations and does not reinterpret them as undeployed accounts', async () => {
    const test = inspectionScenario();
    test.state.target = fixtureAddress('f');
    await expect(inspectAccountDeployment(test.client, test.input)).rejects.toThrow(
      'UNEXPECTED_IMPLEMENTATION',
    );
    expect(test.request.mock.calls.filter(([r]) => r.method === 'eth_call')).toHaveLength(3);
  });
  it('binds factory recipe, EntryPoint identity and each returned account field', async () => {
    for (const patch of [{ initHash: fixtureHash('f') }, { entryPoint: fixtureAddress('f') }]) {
      const test = inspectionScenario();
      Object.assign(test.state, patch);
      await expect(inspectAccountDeployment(test.client, test.input)).rejects.toThrow(
        'IDENTITY_MISMATCH',
      );
    }
    for (const patch of [
      { account: fixtureAddress('f') },
      { accountId: fixtureHash('f') },
      { implementation: fixtureAddress('f') },
      { securityVersion: 0n },
      { storageLayoutHash: fixtureHash('f') },
    ]) {
      const test = inspectionScenario();
      Object.assign(test.state.observation, patch);
      await expect(inspectAccountDeployment(test.client, test.input)).rejects.toThrow(
        'IDENTITY_MISMATCH',
      );
    }
  });
  it('recognizes an independently pinned new revision without requiring original libraries or a live EntryPoint', async () => {
    const test = inspectionScenario();
    // Different current target/modules, unchanged factory/proxy CREATE2 recipe.
    for (const [role, digit] of [
      ['implementation', 'a'],
      ['security_module', 'b'],
      ['upgrade_module', 'c'],
    ] as const) {
      const old = test.manifest.components[role].address;
      const code = test.state.codes.get(old)!;
      test.state.codes.delete(old);
      test.manifest.components[role].address = fixtureAddress(digit);
      test.state.codes.set(fixtureAddress(digit), code);
    }
    test.state.target = test.manifest.components.implementation.address;
    test.state.observation.implementation = test.state.target;
    test.state.observation.securityVersion = 3n;
    const document = JSON.stringify(test.manifest);
    const result = await inspectAccountDeployment(test.client, {
      ...test.input,
      document,
      expectedDigest: deploymentDocumentDigest(document),
    });
    expect(result).toMatchObject({
      status: 'recognized',
      account: test.account,
      security_version: '3',
    });
    expect(test.request.mock.calls.some(([r]) => r.params?.[0] === test.manifest.entry_point)).toBe(
      false,
    );
  });
  it('rejects malformed, excessive and ambiguous RPC results', async () => {
    for (const invalid of [null, '0x0', '0xgg', `0x${'00'.repeat(24_577)}`, '0x6001\n']) {
      const test = inspectionScenario();
      const original = test.request.getMockImplementation()!;
      test.request.mockImplementation(async (req) =>
        req.method === 'eth_getCode' ? invalid : original(req),
      );
      await expect(inspectAccountDeployment(test.client, test.input)).rejects.toThrow(
        'INVALID_RPC_DATA',
      );
    }
  });
  it('retains its input snapshot if the caller mutates the checkpoint while I/O is pending', async () => {
    const test = inspectionScenario();
    const operation = inspectAccountDeployment(test.client, test.input);
    Object.assign(test.input.checkpoint, { block_hash: fixtureHash('f'), block_number: '99' });
    expect((await operation).checkpoint).toEqual(checkpoint);
  });
});
