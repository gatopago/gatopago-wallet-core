import { env } from 'cloudflare:workers';
import { vi } from 'vitest';
import { decodeFunctionData, encodeFunctionResult, toHex, type Hex } from 'viem';
import { deploymentDocumentDigest } from '@gatopago/shared/v3/deployment';
import type { FinalityAssessment } from '@gatopago/shared/v3/finality';
import { accountSecurityInspectionAbi } from '@gatopago/shared/v3/security-inspection';
import { BackupRepository, type BackupProfiles } from '../src/security/backup';
import { fixtureHash } from '@gatopago/test-fixtures/v3-inspection';
import { backupScenario } from './backup.fixture';
import { deliveryNow } from './creationDelivery.fixture';
const signal = () => new AbortController().signal;

/** Advances the synthetic chain, while retaining actual EIP-1898/finality transports and
 * P-256/ECDSA verification in workerd. No broadcast, real admission or secret is involved. */
export async function backupCommitScenario() {
  const f = await backupScenario(),
    request = f.request(),
    backup = await f.repository().prepare(request, signal());
  await f
    .repository()
    .authorize(
      request.id,
      f.f.assertion(backup.proposal_hash),
      await f.proofs(backup.input),
      signal(),
    );
  const original = f.reply.getMockImplementation()!,
    deployment = f.prepared.profile.deployment,
    network = f.configuration.networks[0];
  const blocks = new Map<
    number,
    { block_number: string; block_hash: Hex; block_timestamp: string }
  >([
    [
      100,
      {
        ...backup.input.observation.checkpoint,
        block_timestamp: f.evidence.state.timestamp.toString(),
      },
    ],
    [
      101,
      { block_number: '101', block_hash: fixtureHash('d'), block_timestamp: String(deliveryNow()) },
    ],
    [
      102,
      { block_number: '102', block_hash: fixtureHash('e'), block_timestamp: String(deliveryNow()) },
    ],
  ]);
  const state = {
    head: 101,
    pending: true,
    nonce: 1n,
    proposal: backup.proposal_hash,
    readyAt: backup.valid_after,
    validUntil: backup.proposal_valid_until,
  };
  const head = () => {
    const block = blocks.get(state.head);
    if (!block) throw new Error('Missing fixture block');
    return block;
  };
  f.state.adminNonce = 1n;
  f.reply.mockImplementation(async (method, params) => {
    if (method === 'eth_getBlockByNumber' && params[0] !== '0x0') {
      const number =
        params[0] === 'latest' || params[0] === 'finalized'
          ? state.head
          : Number(BigInt(String(params[0])));
      const block = blocks.get(number);
      if (!block) throw new Error('Unknown synthetic block');
      return {
        number: toHex(BigInt(block.block_number)),
        hash: block.block_hash,
        timestamp: toHex(BigInt(block.block_timestamp)),
      };
    }
    if (method === 'eth_call') {
      let name;
      try {
        name = decodeFunctionData({
          abi: accountSecurityInspectionAbi,
          data: (params[0] as { data: Hex }).data,
        }).functionName;
      } catch {
        /* Another ABI. */
      }
      if (name === 'securitySnapshot')
        return encodeFunctionResult({
          abi: accountSecurityInspectionAbi,
          functionName: name,
          result: [
            f.state.flags,
            f.state.version,
            BigInt(f.state.manifestHash),
            BigInt(f.state.scope),
            0n,
            0n,
            0n,
            state.nonce,
            1n,
            state.pending ? 1n : 0n,
            state.pending ? BigInt(state.proposal) : 0n,
            state.pending ? 1n : 0n,
            state.pending ? BigInt(f.state.manifestHash) : 0n,
            state.pending ? BigInt(f.state.scope) : 0n,
            state.pending ? BigInt(state.readyAt) : 0n,
            state.pending ? BigInt(state.validUntil) : 0n,
          ],
        });
    }
    return original(method, params);
  });
  const profiles: BackupProfiles = vi.fn(async () => {
    const time = deliveryNow(),
      checkpoint = { ...head() };
    const finalityEvidence: FinalityAssessment = {
      schema_version: 1,
      status: 'finalized',
      policy_sha256: network.finalityPolicy.digest,
      mechanism: 'op_stack_l1_data_finalized',
      network_id: deployment.network_id,
      genesis_hash: deployment.genesis_hash,
      target: checkpoint,
      checkpoint,
      assessed_at: time,
      expires_at: time + 30,
    };
    const document = JSON.stringify(deployment);
    return [
      {
        document,
        digest: deploymentDocumentDigest(document),
        rpcUrls: [network.providers[0].url, network.providers[1].url] as const,
        finalityPolicy: network.finalityPolicy,
        finalityEvidence,
      },
    ];
  });
  const repository = (identity = f.principal, resolver: BackupProfiles | undefined = profiles) =>
    new BackupRepository(
      env.WALLET_DB,
      identity,
      f.configuration.scope,
      f.configuration.profiles,
      resolver,
    );
  f.fetch.mockClear();
  return { ...f, backup, request, state, blocks, profiles, repository };
}
