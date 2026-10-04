import {
  encodeAbiParameters,
  encodeEventTopics,
  isAddress,
  parseAbi,
  serializeTransaction,
  toHex,
  type Hex,
  type PublicClient,
} from 'viem';
import { inspectAccountDeployment } from '@gatopago/shared/v3/account-inspection';
import { inspectCreationDeployment } from '@gatopago/shared/v3/creation-inspection';
import { deploymentDocumentDigest, requireHash } from '@gatopago/shared/v3/deployment';
import { parseAtomicAmount } from '@gatopago/shared/v3/primitives';
import type { BackupObservationGrant } from './backupDelivery';

type Row = Record<string, unknown>;
const invalid = () => new Error('BACKUP_RECEIPT_INVALID');
const abi = parseAbi([
  'event PolicyProposed(bytes32 indexed proposalHash, uint8 kind, uint64 securityVersion, bytes32 nextPolicyHash, bytes32 chainScopeHash, uint48 readyAt, uint48 validUntil)',
  'event PolicyInstalled(bytes32 indexed proposalHash, bytes32 indexed manifestHash, uint64 securityVersion)',
  'event ProposalCommitted(bytes32 indexed proposalHash, bytes32 acknowledgementsHash)',
]);
function row(value: unknown): Row {
  if (!value || typeof value !== 'object' || Array.isArray(value)) throw invalid();
  return value as Row;
}
function quantity(value: unknown): bigint {
  if (typeof value !== 'string' || !/^0x(?:0|[1-9a-f][0-9a-f]{0,63})$(?![\s\S])/.test(value))
    throw invalid();
  return BigInt(value);
}
function hash(value: unknown): Hex {
  requireHash(value);
  return value;
}
function address(value: unknown): Hex {
  if (typeof value !== 'string' || !isAddress(value, { strict: false })) throw invalid();
  return value.toLowerCase() as Hex;
}
function bytes(value: unknown, maxBytes: number): Hex {
  if (
    typeof value !== 'string' ||
    value.length > 2 + 2 * maxBytes ||
    !/^0x(?:[0-9a-fA-F]{2})*$(?![\s\S])/.test(value)
  )
    throw invalid();
  return value.toLowerCase() as Hex;
}

export function verifyBackupReceipt(
  grant: BackupObservationGrant,
  rawTransaction: unknown,
  rawReceipt: unknown,
  blockTimestamp: string,
) {
  try {
    const tx = row(rawTransaction),
      receipt = row(rawReceipt),
      expected = grant.transaction.request;
    const blockHash = hash(receipt.blockHash),
      blockNumber = quantity(receipt.blockNumber),
      index = quantity(receipt.transactionIndex);
    const time = BigInt(parseAtomicAmount(blockTimestamp)),
      gas = quantity(receipt.gasUsed),
      price = quantity(receipt.effectiveGasPrice);
    if (
      blockNumber <= BigInt(grant.afterCheckpoint) ||
      receipt.type !== '0x2' ||
      tx.type !== '0x2' ||
      (receipt.status !== '0x0' && receipt.status !== '0x1') ||
      hash(tx.hash) !== grant.transactionHash ||
      hash(receipt.transactionHash) !== grant.transactionHash ||
      hash(tx.blockHash) !== blockHash ||
      quantity(tx.blockNumber) !== blockNumber ||
      quantity(tx.transactionIndex) !== index ||
      address(tx.from) !== grant.transaction.operator ||
      address(receipt.from) !== grant.transaction.operator ||
      address(tx.to) !== expected.to ||
      address(receipt.to) !== expected.to ||
      receipt.contractAddress !== null ||
      quantity(tx.chainId) !== BigInt(expected.chainId) ||
      quantity(tx.nonce) !== BigInt(expected.nonce) ||
      quantity(tx.value) !== 0n ||
      quantity(tx.gas) !== expected.gas ||
      quantity(tx.maxFeePerGas) !== expected.maxFeePerGas ||
      quantity(tx.maxPriorityFeePerGas) !== expected.maxPriorityFeePerGas ||
      bytes(tx.input, 50_000) !== expected.data ||
      gas === 0n ||
      gas > expected.gas ||
      price > expected.maxFeePerGas ||
      (tx.gasPrice !== undefined && quantity(tx.gasPrice) !== price) ||
      (tx.accessList !== undefined &&
        (!Array.isArray(tx.accessList) || tx.accessList.length !== 0)) ||
      tx.authorizationList !== undefined ||
      tx.blobVersionedHashes !== undefined ||
      tx.maxFeePerBlobGas !== undefined
    )
      throw invalid();
    const parity = quantity(tx.yParity ?? tx.v);
    if (parity > 1n || (tx.v !== undefined && quantity(tx.v) !== parity)) throw invalid();
    const r = hash(tx.r),
      s = hash(tx.s);
    if (
      serializeTransaction(expected, { r, s, yParity: Number(parity) }) !==
      grant.serializedTransaction
    )
      throw invalid();
    const success = receipt.status === '0x1',
      message = grant.commit?.message ?? grant.backup.message;
    if (
      success &&
      (time < BigInt(message.validAfter) ||
        time >= BigInt(message.validUntil) ||
        (grant.commit &&
          (time < BigInt(grant.commit.readyAt) ||
            time >= BigInt(grant.backup.message.proposalValidUntil))))
    )
      throw invalid();
    if (
      !Array.isArray(receipt.logs) ||
      receipt.logs.length !== (success ? (grant.kind === 'prepare' ? 1 : 2) : 0)
    )
      throw invalid();
    let previous = -1n;
    const logs = receipt.logs.map((raw: unknown) => {
      const log = row(raw),
        logIndex = quantity(log.logIndex);
      if (
        address(log.address) !== expected.to ||
        hash(log.transactionHash) !== grant.transactionHash ||
        hash(log.blockHash) !== blockHash ||
        quantity(log.blockNumber) !== blockNumber ||
        quantity(log.transactionIndex) !== index ||
        log.removed !== false ||
        logIndex <= previous ||
        !Array.isArray(log.topics) ||
        log.topics.length > 3
      )
        throw invalid();
      previous = logIndex;
      return {
        index: logIndex.toString(),
        topics: log.topics.map(hash),
        data: bytes(log.data, 192),
      };
    });
    function event(at: number, name: (typeof abi)[number]['name'], data: Hex, manifestHash?: Hex) {
      const topics = [
        encodeEventTopics({ abi, eventName: name })[0],
        grant.signed.proposalHash,
        ...(manifestHash ? [manifestHash] : []),
      ];
      if (JSON.stringify(logs[at].topics) !== JSON.stringify(topics) || logs[at].data !== data)
        throw invalid();
    }
    if (success && grant.kind === 'prepare') {
      const m = grant.backup.message;
      event(
        0,
        'PolicyProposed',
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
            m.securityVersion,
            m.nextPolicyHash,
            m.chainScopeHash,
            Number(time),
            m.proposalValidUntil,
          ],
        ),
      );
    } else if (success) {
      if (!grant.commit) throw invalid();
      event(
        0,
        'PolicyInstalled',
        encodeAbiParameters([{ type: 'uint64' }], [2n]),
        grant.signed.expectedManifestHash,
      );
      event(1, 'ProposalCommitted', grant.commit.message.acknowledgementsHash);
    }
    return Object.freeze({
      schema_version: 1 as const,
      operation_id: grant.id,
      backup_id: grant.backupId,
      kind: grant.kind,
      network_id: grant.networkId,
      profile_sha256: grant.profileDigest,
      transaction_hash: grant.transactionHash,
      block_hash: blockHash,
      block_number: blockNumber.toString(),
      block_timestamp: time.toString(),
      transaction_index: index.toString(),
      account: expected.to,
      operator: grant.transaction.operator,
      proposal_hash: grant.signed.proposalHash,
      outcome: !success
        ? ('execution_reverted' as const)
        : grant.kind === 'prepare'
          ? ('proposal_prepared' as const)
          : ('backup_committed' as const),
      installed_manifest_hash:
        success && grant.kind === 'commit' ? grant.signed.expectedManifestHash : null,
      gas_used: gas.toString(),
      effective_gas_price: price.toString(),
      execution_gas_cost: (gas * price).toString(),
      log_indexes: Object.freeze(logs.map((log) => log.index)),
      finality: 'not_assessed' as const,
      account_readiness: 'not_assessed' as const,
    });
  } catch {
    throw invalid();
  }
}

export async function observeBackupReceipt(
  client: PublicClient,
  grant: BackupObservationGrant,
  document: string,
) {
  const options = { dedupe: false, retryCount: 0 } as const;
  try {
    const receipt = await client.request(
      { method: 'eth_getTransactionReceipt', params: [grant.transactionHash] },
      options,
    );
    if (receipt === null) return null;
    const candidate = row(receipt),
      height = toHex(quantity(candidate.blockNumber));
    const block = row(
      await client.request({ method: 'eth_getBlockByNumber', params: [height, false] }, options),
    );
    const transaction = await client.request(
      { method: 'eth_getTransactionByHash', params: [grant.transactionHash] },
      options,
    );
    const observed = verifyBackupReceipt(
      grant,
      transaction,
      receipt,
      quantity(block.timestamp).toString(),
    );
    if (
      hash(block.hash) !== observed.block_hash ||
      quantity(block.number).toString() !== observed.block_number
    )
      throw invalid();
    const checkpoint = { block_hash: observed.block_hash, block_number: observed.block_number };
    await inspectCreationDeployment(client, {
      document,
      expectedDigest: grant.profileDigest,
      checkpoint,
    });
    const deploymentDocument = JSON.stringify(grant.initial.profile.deployment);
    const account = await inspectAccountDeployment(client, {
      document: deploymentDocument,
      expectedDigest: deploymentDocumentDigest(deploymentDocument),
      initialSecurityCommitment: grant.initial.message.initialSecurityCommitment,
      userSaltCommitment: grant.initial.message.userSaltCommitment,
      checkpoint,
    });
    if (account.status !== 'recognized') throw invalid();
    const end = row(
      await client.request({ method: 'eth_getBlockByNumber', params: [height, false] }, options),
    );
    if (
      hash(end.hash) !== observed.block_hash ||
      quantity(end.number).toString() !== observed.block_number ||
      quantity(end.timestamp).toString() !== observed.block_timestamp
    )
      throw invalid();
    return observed;
  } catch {
    throw invalid();
  }
}
