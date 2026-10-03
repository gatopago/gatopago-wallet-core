import assert from 'node:assert/strict';
import { createECDH, createHash, createPrivateKey, sign, verify } from 'node:crypto';
import { readFileSync, writeFileSync } from 'node:fs';
import { resolve } from 'node:path';
import { createPublicClient, decodeErrorResult, encodeFunctionData, http, keccak256, parseAbi, stringToHex, toFunctionSelector, toHex } from 'viem';
import { entryPoint09Abi } from 'viem/account-abstraction';
import { arbitrumSepolia } from 'viem/chains';
import { loadPinnedCreationProfile, prepareInitialization } from '@gatopago/shared/v3/initialization';
import { authorizeCreationOperation, prepareCreationOperation } from '@gatopago/shared/v3/creation-operation';
import { deploymentDocumentDigest } from '@gatopago/shared/v3/deployment';
import { ARBITRUM_SEPOLIA_CREATION } from '@gatopago/shared/v3/wallet-release';
import { encodeWebAuthnAssertion, normalizeWebAuthnSignature } from '@gatopago/shared/v3/webauthn';

// Read-only public vector: scalar 1 is not a user's key or a login credential.
// The creation UserOperation exists only in eth_call with synthetic balances.
// This script never enrolls a credential, creates a public account or broadcasts.
const root = resolve(import.meta.dirname, '..');
const output = resolve(root, '../protocol/docs/arbitrum-delivery/passkey-runtime-readonly.json');
const profile = loadPinnedCreationProfile(ARBITRUM_SEPOLIA_CREATION.document, ARBITRUM_SEPOLIA_CREATION.digest);
const peers = [
  ['offchain-labs', 'https://sepolia-rollup.arbitrum.io/rpc'],
  ['tenderly', 'https://arbitrum-sepolia.gateway.tenderly.co'],
].map(([operator, url]) => ({ operator, client: createPublicClient({ chain: arbitrumSepolia,
  transport: http(url, { timeout: 15_000, retryCount: 0 }) }) }));
const hash = bytes => createHash('sha256').update(bytes).digest();
const hex = bytes => `0x${bytes.toString('hex')}`;
const scalar = Buffer.alloc(32); scalar[31] = 1;
const curve = createECDH('prime256v1'); curve.setPrivateKey(scalar);
const publicKey = curve.getPublicKey(null, 'uncompressed');
const signer = createPrivateKey({ key: { kty: 'EC', crv: 'P-256', d: scalar.toString('base64url'),
  x: publicKey.subarray(1, 33).toString('base64url'), y: publicKey.subarray(33).toString('base64url') }, format: 'jwk' });
const challenge = hash(Buffer.from('GatoPago R1 read-only deployed passkey verifier inspection'));
const clientData = JSON.stringify({ type: 'webauthn.get', challenge: challenge.toString('base64url'),
  origin: 'https://gatopago.com', crossOrigin: false });
const rpIdHash = hash(Buffer.from('gatopago.com'));
const authenticatorData = Buffer.concat([rpIdHash, Buffer.from([5, 0, 0, 0, 0])]);
const signed = Buffer.concat([authenticatorData, hash(Buffer.from(clientData))]);
const signatureDER = sign('sha256', signed, { key: signer, dsaEncoding: 'der' });
assert(verify('sha256', signed, signer, signatureDER));
const { r, s } = normalizeWebAuthnSignature(signatureDER);
const normalized = Buffer.from(`${r.slice(2)}${s.slice(2)}`, 'hex');
assert(verify('sha256', signed, { key: signer, dsaEncoding: 'ieee-p1363' }, normalized));
const nativeData = hex(Buffer.concat([hash(signed), normalized, publicKey.subarray(1)]));
const wrongNative = `${nativeData.slice(0, -2)}${nativeData.endsWith('00') ? '01' : '00'}`;
const key = hex(Buffer.concat([rpIdHash, hash(Buffer.from('https://gatopago.com')), publicKey.subarray(1)]));
const encoded = encodeWebAuthnAssertion({ scope: { rpId: 'gatopago.com', origin: 'https://gatopago.com' },
  key, challenge: hex(challenge), response: { authenticatorData, clientDataJSON: Buffer.from(clientData), signatureDER } });
const verifier = profile.webauthn_verifier.address;
const abi = parseAbi(['function verify(bytes key, bytes32 hash, bytes signature) view returns (bytes4)']);
const heads = await Promise.all(peers.map(async ({ client }) => {
  assert.equal(await client.getChainId(), 421614);
  assert.equal((await client.getBlock({ blockNumber: 0n })).hash, profile.deployment.genesis_hash);
  return client.getBlockNumber();
}));
const blockNumber = heads.reduce((a, b) => a < b ? a : b);
const blockTag = `0x${blockNumber.toString(16)}`;
const observations = await Promise.all(peers.map(async ({ operator, client }) => {
  const block = await client.getBlock({ blockNumber });
  const bytecode = await client.getCode({ address: verifier, blockNumber });
  assert(bytecode && bytecode !== '0x');
  assert.equal(keccak256(bytecode), profile.webauthn_verifier.runtime_code_hash);
  const native = data => client.request({ method: 'eth_call', params: [
    { to: '0x0000000000000000000000000000000000000100', data }, blockTag,
  ] });
  const valid = await native(nativeData), invalid = await native(wrongNative);
  assert.equal(valid, `0x${'0'.repeat(63)}1`);
  assert(['0x', `0x${'0'.repeat(64)}`].includes(invalid));
  const accepted = await client.readContract({ address: verifier, abi, functionName: 'verify',
    args: [key, hex(challenge), encoded], blockNumber });
  assert.equal(accepted, toFunctionSelector('verify(bytes,bytes32,bytes)'));
  const rejected = await client.readContract({ address: verifier, abi, functionName: 'verify',
    args: [key, `0x${'00'.repeat(32)}`, encoded], blockNumber });
  assert.equal(rejected, '0xffffffff');
  assert.equal((await client.getBlock({ blockNumber })).hash, block.hash, 'Checkpoint changed during inspection');
  return { operator, block_hash: block.hash, native_valid: valid, native_invalid: invalid,
    deployed_verifier_valid: accepted, deployed_verifier_wrong_challenge: rejected };
}));
assert.equal(observations[0].block_hash, observations[1].block_hash);
const checkpoint = await peers[0].client.getBlock({ blockNumber });
const now = Number(checkpoint.timestamp);
const scope = { rpId: 'gatopago.com', origin: 'https://gatopago.com' };
function assertion(challengeHash) {
  const json = JSON.stringify({ type: 'webauthn.get', challenge: Buffer.from(challengeHash.slice(2), 'hex').toString('base64url'),
    origin: scope.origin, crossOrigin: false });
  const payload = Buffer.concat([authenticatorData, hash(Buffer.from(json))]);
  return { authenticatorData, clientDataJSON: Buffer.from(json),
    signatureDER: sign('sha256', payload, { key: signer, dsaEncoding: 'der' }) };
}
const input = { document: ARBITRUM_SEPOLIA_CREATION.document, expectedDigest: ARBITRUM_SEPOLIA_CREATION.digest,
  scope, publicKey: key, userSaltCommitment: keccak256(stringToHex(`GatoPago read-only native creation ${blockNumber}`)),
  validAfter: now, validUntil: now + 300 };
const initial = prepareInitialization(input), initialProof = assertion(initial.digest);
const gas = { verificationGasLimit: 750000n, callGasLimit: 100000n, preVerificationGas: 150000n,
  maxFeePerGas: 100000000n, maxPriorityFeePerGas: 0n };
const catalogSource = readFileSync(resolve(root, 'src/runtime/catalog.ts'), 'utf8');
const budgetSource = catalogSource.match(/creationGas:\s*\{([^}]+)\}/)?.[1];
assert(budgetSource, 'Missing reviewed creation gas catalog');
for (const [name, amount] of Object.entries(gas)) {
  assert.match(budgetSource, new RegExp(`\\b${name}:\\s*'${amount}'`), 'Creation budget differs from the reviewed catalog');
}
const terms = { ...gas, maximumGasCharge: (gas.verificationGasLimit + gas.callGasLimit + gas.preVerificationGas) * gas.maxFeePerGas };
const candidate = prepareCreationOperation(input, initialProof, terms, now);
const authorized = authorizeCreationOperation(input, initialProof, terms, assertion(candidate.digest), now);
const operator = '0x000000000000000000000000000000000000dEaD';
const data = encodeFunctionData({ abi: entryPoint09Abi, functionName: 'handleOps', args: [[authorized.packed], operator] });
const call = { from: operator, to: profile.deployment.entry_point, data, gas: toHex(2000000n),
  maxFeePerGas: toHex(gas.maxFeePerGas), maxPriorityFeePerGas: toHex(gas.maxPriorityFeePerGas) };
const overrides = { [authorized.prepared.account]: { balance: toHex(10n ** 19n) }, [operator]: { balance: toHex(10n ** 19n) } };
await Promise.all(peers.map(async ({ client }) => {
  const codeBefore = await client.getCode({ address: authorized.prepared.account, blockNumber });
  assert(!codeBefore || codeBefore === '0x', 'Synthetic vector account already exists');
  const pins = [profile.deployment.components.factory, profile.deployment.components.implementation,
    profile.deployment.components.security_module, profile.deployment.components.upgrade_module,
    { address: profile.deployment.entry_point, runtime_code_hash: profile.entry_point_code_hash }, profile.sender_creator];
  await Promise.all(pins.map(async pin => {
    const code = await client.getCode({ address: pin.address, blockNumber });
    assert(code && code !== '0x'); assert.equal(keccak256(code), pin.runtime_code_hash);
  }));
}));
const creation = [];
for (const verificationGasLimit of [gas.verificationGasLimit, 1000000n, 1250000n, 1500000n]) {
  // Every diagnostic budget has its own newly compiled and signed public vector.
  // These are not user authorizations, repriced operations or runtime admission.
  const diagnosticTerms = { ...terms, verificationGasLimit,
    maximumGasCharge: (verificationGasLimit + gas.callGasLimit + gas.preVerificationGas) * gas.maxFeePerGas };
  const prepared = prepareCreationOperation(input, initialProof, diagnosticTerms, now);
  const signedOperation = authorizeCreationOperation(input, initialProof, diagnosticTerms, assertion(prepared.digest), now);
  const diagnosticCall = { ...call, data: encodeFunctionData({ abi: entryPoint09Abi, functionName: 'handleOps',
    args: [[signedOperation.packed], operator] }) };
  const results = await Promise.all(peers.map(async ({ operator: rpcOperator, client }) => {
    try {
      const result = await client.request({ method: 'eth_call', params: [diagnosticCall, blockTag, overrides] });
      assert.equal(result, '0x', 'Unexpected handleOps response');
      return { operator: rpcOperator, exact_handle_ops_eth_call: 'passed' };
    } catch (error) {
      const data = error?.data ?? error?.cause?.data;
      let reason = 'RPC_ERROR';
      if (typeof data === 'string' && data.startsWith('0x')) {
        try { const decoded = decodeErrorResult({ abi: entryPoint09Abi, data });
          reason = decoded.errorName === 'FailedOp' ? decoded.args[1] : decoded.errorName;
        } catch { reason = 'UNRECOGNIZED_REVERT'; }
      }
      return { operator: rpcOperator, exact_handle_ops_eth_call: 'failed', reason };
    }
  }));
  creation.push({ verification_gas_limit: verificationGasLimit.toString(), runtime_budget: verificationGasLimit === gas.verificationGasLimit,
    user_op_hash: signedOperation.userOpHash, observations: results });
  if (results.every(value => value.exact_handle_ops_eth_call === 'passed')) break;
}
await Promise.all(peers.map(async ({ client }) => {
  const codeAfter = await client.getCode({ address: authorized.prepared.account, blockNumber });
  assert(!codeAfter || codeAfter === '0x', 'Read-only simulation changed public account code');
  assert.equal((await client.getBlock({ blockNumber })).hash, checkpoint.hash, 'Checkpoint changed during creation inspection');
}));
const runtimePassed = creation[0].observations.every(value => value.exact_handle_ops_eth_call === 'passed');
const evidence = { schema_version: 1, observed_at: new Date().toISOString(), status: runtimePassed
  ? 'readonly_verifier_and_creation_simulation_passed' : 'readonly_verifier_passed_creation_budget_unproven',
  network_id: profile.deployment.network_id, block_number: blockNumber.toString(), block_hash: observations[0].block_hash,
  creation_profile_sha256: ARBITRUM_SEPOLIA_CREATION.digest, deployment_sha256: deploymentDocumentDigest(JSON.stringify(profile.deployment)),
  verifier, verifier_code_hash: profile.webauthn_verifier.runtime_code_hash,
  vector: 'real Node P256 signature using public scalar 1; synthetic WebAuthn data', observations,
  creation_simulation: { account: authorized.prepared.account, user_op_hash: authorized.userOpHash,
    signed_verification_gas_limit: gas.verificationGasLimit.toString(), signed_call_gas_limit: gas.callGasLimit.toString(),
    signed_pre_verification_gas: gas.preVerificationGas.toString(), signed_max_fee_per_gas: gas.maxFeePerGas.toString(),
    signed_max_priority_fee_per_gas: gas.maxPriorityFeePerGas.toString(), outer_gas_limit: '2000000',
    funding: 'eth_call state overrides only; 10 synthetic ETH each for vector account and caller',
    public_account_code_unchanged: true, budgets: creation },
  catalog_source_sha256: createHash('sha256').update(catalogSource).digest('hex'),
  script_sha256: createHash('sha256').update(readFileSync(import.meta.filename)).digest('hex'),
  account_created: false, hardware_passkey: false, login_completed: false, public_transactions: false,
  limits: ['Latest common checkpoint is not a finality proof.',
    'Budget diagnostics are synthetic signatures, not accepted runtime limits; no real funding, hardware passkey, broadcast or receipt is demonstrated.',
    'An empty handleOps return is not proof of its inner execution outcome or a complete public creation workflow.',
    'No account, credential, reusable user assertion, session or financial transaction is produced.'] };
writeFileSync(output, `${JSON.stringify(evidence, null, 2)}\n`);
console.log(JSON.stringify({ status: evidence.status, block_number: evidence.block_number, verifier,
  creation_budgets: creation, operators: observations.map(value => value.operator),
  output: 'protocol/docs/arbitrum-delivery/passkey-runtime-readonly.json' }));
