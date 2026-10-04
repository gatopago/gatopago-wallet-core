import { env } from 'cloudflare:workers';
import {
  encodeAbiParameters,
  encodeEventTopics,
  parseAbi,
  parseTransaction,
  toHex,
  type Hex,
} from 'viem';
import { generatePrivateKey, privateKeyToAccount } from 'viem/accounts';
import { createResourceId } from '@gatopago/shared/v3/primitives';
import { BackupDeliveryRepository } from '../src/security/backupDelivery';
import { BackupObservationJournal } from '../src/security/backupObservationJournal';
import { processBackupObservation } from '../src/security/processBackupObservation';
import { backupCommitScenario } from './backupCommit.fixture';
import { cleanCreationDelivery, deliveryNow } from './creationDelivery.fixture';

const signal = () => new AbortController().signal;
// Independently spelled ABI from AccountV3Security's emitted events.
const events = parseAbi([
  'event PolicyProposed(bytes32 indexed proposalHash,uint8 kind,uint64 securityVersion,bytes32 nextPolicyHash,bytes32 chainScopeHash,uint48 readyAt,uint48 validUntil)',
  'event PolicyInstalled(bytes32 indexed proposalHash,bytes32 indexed manifestHash,uint64 securityVersion)',
  'event ProposalCommitted(bytes32 indexed proposalHash,bytes32 acknowledgementsHash)',
]);
export async function cleanBackupObservations() {
  await env.WALLET_DB.exec(`DROP TRIGGER IF EXISTS backup_observation_fail;
  DELETE FROM account_backup_observations; DELETE FROM account_backup_observation_jobs;
  DELETE FROM account_backup_transactions; DELETE FROM account_backup_outbox;
  DELETE FROM account_backup_commits; DELETE FROM account_backups;`);
  await cleanCreationDelivery();
}

/** Actual D1 consent, P-256/ECDSA and local transaction signatures; RPC is synthetic. */
export async function backupObservationScenario(kind: 'prepare' | 'commit' = 'prepare') {
  const f = await backupCommitScenario();
  let id = f.request.id;
  if (kind === 'commit') {
    id = createResourceId('operation');
    const commit = await f.repository().prepareCommit(id, f.request.id, signal());
    await f.repository().authorizeCommit(id, f.f.assertion(commit.commit_digest), signal());
  }
  const delivery = new BackupDeliveryRepository(env.WALLET_DB, f.configuration);
  const claim = await delivery.claim(id);
  if (!claim) throw new Error('Expected local grant');
  const operator = privateKeyToAccount(generatePrivateKey());
  const policy = {
    networkId: f.prepared.profile.deployment.network_id,
    operator: operator.address,
    maxGas: 800_000n,
    maxFeePerGas: 10n,
    maxPriorityFeePerGas: 1n,
    maxExecutionFee: 8_000_000n,
  };
  const prepared = await delivery.reserveTransaction(claim, policy, {
    nonce: 0,
    gas: 800_000n,
    maxFeePerGas: 10n,
    maxPriorityFeePerGas: 1n,
  });
  if (!prepared) throw new Error('Expected local reservation');
  const raw = await operator.signTransaction(prepared.request);
  if (!(await delivery.beginSend(claim, policy, raw, deliveryNow() + 30)))
    throw new Error('Expected local send marker');
  await delivery.uncertain(claim);
  const grant = await delivery.observationGrant(id);
  if (!grant) throw new Error('Expected local observation grant');
  const height = kind === 'prepare' ? 101 : 102;
  f.state.head = height;
  const block = f.blocks.get(height)!,
    signature = parseTransaction(raw);
  // The synthetic inclusion block is produced AFTER the consent, never at the
  // earlier timestamp captured while the scenario was still preparing its keys.
  if (kind === 'commit') block.block_timestamp = String(deliveryNow());
  const tx = {
    hash: grant.transactionHash,
    from: prepared.operator,
    to: prepared.request.to,
    input: prepared.request.data,
    value: '0x0',
    chainId: toHex(prepared.request.chainId),
    nonce: '0x0',
    gas: toHex(800_000),
    maxFeePerGas: '0xa',
    maxPriorityFeePerGas: '0x1',
    type: '0x2',
    r: signature.r!,
    s: signature.s!,
    yParity: toHex(signature.yParity!),
    blockNumber: toHex(height),
    blockHash: block.block_hash,
    transactionIndex: '0x2',
  };
  const log = (topics: readonly unknown[], data: Hex, index: number) => ({
    address: prepared.request.to,
    topics: [...topics] as Hex[],
    data,
    logIndex: toHex(index),
    transactionHash: grant.transactionHash,
    transactionIndex: '0x2',
    blockNumber: toHex(height),
    blockHash: block.block_hash,
    removed: false,
  });
  const m = grant.backup.message;
  const logs =
    kind === 'prepare'
      ? [
          log(
            encodeEventTopics({
              abi: events,
              eventName: 'PolicyProposed',
              args: { proposalHash: grant.signed.proposalHash },
            }),
            encodeAbiParameters(
              [
                { type: 'uint8' },
                { type: 'uint64' },
                { type: 'bytes32' },
                { type: 'bytes32' },
                { type: 'uint48' },
                { type: 'uint48' },
              ],
              [
                1,
                1n,
                m.nextPolicyHash,
                m.chainScopeHash,
                Number(block.block_timestamp),
                m.proposalValidUntil,
              ],
            ),
            4,
          ),
        ]
      : [
          log(
            encodeEventTopics({
              abi: events,
              eventName: 'PolicyInstalled',
              args: {
                proposalHash: grant.signed.proposalHash,
                manifestHash: grant.signed.expectedManifestHash,
              },
            }),
            encodeAbiParameters([{ type: 'uint64' }], [2n]),
            4,
          ),
          log(
            encodeEventTopics({
              abi: events,
              eventName: 'ProposalCommitted',
              args: { proposalHash: grant.signed.proposalHash },
            }),
            grant.commit!.message.acknowledgementsHash,
            5,
          ),
        ];
  const receipt = {
    status: '0x1',
    type: '0x2',
    transactionHash: grant.transactionHash,
    transactionIndex: '0x2',
    blockNumber: toHex(height),
    blockHash: block.block_hash,
    from: prepared.operator,
    to: prepared.request.to,
    contractAddress: null,
    gasUsed: toHex(200_000),
    effectiveGasPrice: '0x5',
    logs,
  };
  const state = { receipt, tx, missing: false, missingTransaction: false };
  const original = f.reply.getMockImplementation()!;
  f.reply.mockImplementation(async (method, params) => {
    if (method === 'eth_getTransactionReceipt' && params[0] === grant.transactionHash)
      return state.missing ? null : state.receipt;
    if (method === 'eth_getTransactionByHash' && params[0] === grant.transactionHash)
      return state.missingTransaction ? null : state.tx;
    return original(method, params);
  });
  const configuration = {
    ...f.configuration,
    networks: f.configuration.networks.map((n) => ({
      ...n,
      providers: n.providers.map((p) => ({ ...p, operatorId: p.operatorId.replaceAll('_', '-') })),
    })),
  };
  const journal = () => new BackupObservationJournal(env.WALLET_DB, configuration);
  f.fetch.mockClear();
  f.reply.mockClear();
  return {
    ...f,
    id,
    grant,
    delivery,
    state,
    configuration,
    journal,
    block,
    run: (abort = signal()) => processBackupObservation(env.WALLET_DB, id, configuration, abort),
  };
}
