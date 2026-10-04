import { describe, expect, it } from 'vitest';
import { getContractAddress, zeroAddress, zeroHash } from 'viem';
import {
  deploymentDocumentDigest,
  loadPinnedDeploymentManifest,
} from '@gatopago/shared/v3/deployment';
import { validateDeploymentShape } from '@gatopago/shared/v3/wire-validators';
import { fixtureManifest, fixtureInput, fixtureHash } from '@gatopago/test-fixtures/v3-inspection';

describe('V3 pinned deployment profile', () => {
  it('requires an out-of-band exact byte pin, not an embedded approved flag', () => {
    const { document, expectedDigest } = fixtureInput();
    expect(loadPinnedDeploymentManifest(document, expectedDigest).generation).toBe(3);
    expect(() => loadPinnedDeploymentManifest(document, fixtureHash('9'))).toThrow('pin mismatch');
    expect(() => loadPinnedDeploymentManifest(document + '\n', expectedDigest)).toThrow(
      'pin mismatch',
    );
    expect(() => loadPinnedDeploymentManifest(document, zeroHash)).toThrow();
    const embedded = JSON.stringify({ ...fixtureManifest(), approved: true });
    expect(() =>
      loadPinnedDeploymentManifest(embedded, deploymentDocumentDigest(embedded)),
    ).toThrow('schema');
  });
  it('enforces schema own fields, generation, bounded strings and strict nested fields', () => {
    expect(validateDeploymentShape(Object.create(fixtureManifest()))).toBe(false);
    for (const changed of [
      { generation: 2 },
      { schema_version: 2 },
      { network_id: 'eip155:084532' },
      { genesis_hash: fixtureHash('a') + '\n' },
      { entry_point: zeroAddress + '\n' },
      { lifecycle_status: 'approved' },
    ]) {
      const doc = JSON.stringify({ ...fixtureManifest(), ...changed });
      expect(() => loadPinnedDeploymentManifest(doc, deploymentDocumentDigest(doc))).toThrow();
    }
    const nested = fixtureManifest();
    Object.assign(nested.components.factory.compiler, { unsafe: true });
    const doc = JSON.stringify(nested);
    expect(() => loadPinnedDeploymentManifest(doc, deploymentDocumentDigest(doc))).toThrow(
      'schema',
    );
  });
  it('rejects zero artifact fields, missing provenance, role collisions and invalid block quantities', () => {
    for (const field of [
      'creation_code_hash',
      'runtime_code_hash',
      'abi_sha256',
      'source_tree_sha256',
      'dependency_lock_sha256',
      'build_info_sha256',
      'deployment_tx',
    ]) {
      const manifest = fixtureManifest();
      Object.assign(manifest.components.implementation, { [field]: zeroHash });
      const input = fixtureInput(manifest);
      expect(() => loadPinnedDeploymentManifest(input.document, input.expectedDigest)).toThrow();
    }
    for (const changed of [
      { source_commit: '0'.repeat(40) },
      { address: zeroAddress },
      { address: fixtureManifest().components.factory.address },
      { deployed_block: (1n << 256n).toString() },
      { deployed_block: '10\n' },
    ]) {
      const manifest = fixtureManifest();
      Object.assign(manifest.components.implementation, changed);
      const input = fixtureInput(manifest);
      expect(() => loadPinnedDeploymentManifest(input.document, input.expectedDigest)).toThrow();
    }
  });
  it('does not fetch verification URLs or accept credential-bearing URLs', () => {
    for (const url of [
      'http://example.com',
      'https://secret@example.com',
      'https://example.com?key=secret',
      'https://example.com#fragment',
      'https://example.com/' + 'x'.repeat(2048),
    ]) {
      const manifest = fixtureManifest();
      manifest.components.factory.verification_url = url;
      const input = fixtureInput(manifest);
      expect(() => loadPinnedDeploymentManifest(input.document, input.expectedDigest)).toThrow();
    }
  });
  it('checks a declared CREATE2 recipe, including a valid zero salt', () => {
    const manifest = fixtureManifest();
    const component = { ...manifest.components.factory, salt: zeroHash };
    const validAddress = getContractAddress({
      from: component.deployer,
      opcode: 'CREATE2',
      salt: zeroHash,
      bytecodeHash: component.creation_code_hash,
    }).toLowerCase();
    const doc = (address: string) =>
      JSON.stringify({
        ...manifest,
        components: { ...manifest.components, factory: { ...component, address } },
      });
    const valid = doc(validAddress);
    expect(
      loadPinnedDeploymentManifest(valid, deploymentDocumentDigest(valid)).components.factory
        .address,
    ).toBe(validAddress);
    const invalid = doc(component.address);
    expect(() => loadPinnedDeploymentManifest(invalid, deploymentDocumentDigest(invalid))).toThrow(
      'CREATE2',
    );
  });
  it('bounds UTF-8 before hashing/parsing and returns a detached deeply frozen document', () => {
    expect(() => deploymentDocumentDigest('x'.repeat(65_537))).toThrow('64 KiB');
    expect(() => deploymentDocumentDigest('é'.repeat(40_000))).toThrow('64 KiB');
    const input = fixtureInput();
    const loaded = loadPinnedDeploymentManifest(input.document, input.expectedDigest);
    expect(() => Object.assign(loaded.components.factory, { address: zeroAddress })).toThrow();
    expect(() =>
      Object.assign(loaded.components.factory.compiler, { optimizer_runs: 1 }),
    ).toThrow();
    expect(Object.isFrozen(loaded.proxy)).toBe(true);
    expect(Object.isFrozen(loaded.components)).toBe(true);
  });
});
