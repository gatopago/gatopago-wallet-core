import type { OperationTransport } from '../execution/operationTransport';
import { rpcEndpoint } from '../chainProviders';
import type { InspectionCheckpoint } from '@gatopago/shared/v3/account-inspection';
import { requireHash } from '@gatopago/shared/v3/deployment';
import { parseAtomicAmount, type ResourceId } from '@gatopago/shared/v3/primitives';
import { inspectWalletCreationProfile } from '../chainInspection';
import { simulateOperation, sendOperation } from '../execution/operationTransport';
import { evmChainId } from '@gatopago/shared/v3/primitives';
import { CreationDeliveryRepository, type CreationDeliveryConfiguration } from './creationDelivery';
import type { CreationProfilePin } from './initialization';

interface DeliveryNetwork extends CreationProfilePin {
  readonly checkpoint: InspectionCheckpoint;
  readonly rpcUrl: string;
  readonly transport: OperationTransport;
}
interface Configuration extends Omit<CreationDeliveryConfiguration, 'profiles'> {
  readonly networks: readonly DeliveryNetwork[];
  readonly relayerKey?: `0x${string}`;
}

export async function processCreationDelivery(
  database: D1Database,
  id: ResourceId<'operation'>,
  configuration: Configuration,
  signal: AbortSignal,
) {
  const networks = configuration.networks.map((network) => {
    requireHash(network.checkpoint.block_hash);
    parseAtomicAmount(network.checkpoint.block_number);
    return Object.freeze({
      document: network.document,
      digest: network.digest,
      checkpoint: Object.freeze({ ...network.checkpoint }),
      rpcUrl: rpcEndpoint(network.rpcUrl),
      transport: structuredClone(network.transport),
    });
  });
  const repository = new CreationDeliveryRepository(database, {
    ...configuration,
    profiles: networks,
  });
  signal.throwIfAborted();
  const claim = await repository.claim(id);
  if (!claim) return 'idle' as const;
  const network = networks.find(
    (item) => item.digest === claim.record.initial.input.expectedDigest,
  )!;
  const deadline = AbortSignal.any([
    signal,
    AbortSignal.timeout(Math.max(1, Math.min(35_000, claim.until * 1000 - Date.now()))),
  ]);
  const signed = claim.record.signed;
  const operation = {
    operation: signed.operation,
    userOpHash: signed.userOpHash,
    networkId: `eip155:${signed.prepared.chainId}` as const,
    entryPoint: signed.prepared.message.entryPoint,
    validUntil: Number(signed.prepared.message.validUntil),
  };
  evmChainId(operation.networkId);
  try {
    await inspectWalletCreationProfile(
      {
        document: network.document,
        expectedDigest: network.digest,
        checkpoint: network.checkpoint,
      },
      network.rpcUrl,
      deadline,
    );
    await simulateOperation(network.transport, operation, deadline);
    deadline.throwIfAborted();
  } catch {
    await repository.retryBeforeSend(claim);
    return 'deferred' as const;
  }

  if (!(await repository.beginSend(claim))) {
    await repository.retryBeforeSend(claim);
    return 'lease_lost' as const;
  }
  try {
    const hash = await sendOperation(
      database,
      network.transport,
      operation,
      deadline,
      configuration.relayerKey,
    );
    if (await repository.accepted(claim, hash)) return 'accepted' as const;
  } catch {
    // Failure leaves durable claim uncertain
  }
  await repository.uncertain(claim);
  return 'uncertain' as const;
}
