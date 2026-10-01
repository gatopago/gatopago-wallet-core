import { assessCheckpointFinality } from '@gatopago/shared/v3/finality';
import { requireHash } from '@gatopago/shared/v3/deployment';
import { createInspectionClient, inspectWalletCreationProfile } from '../chainInspection';
import type { WalletNetwork } from './config';

/** Select a common finalized block, then independently validate its chain, age and
 * ancestry with both observers. All evidence is scoped to this invocation. */
export async function networkFinality(network: Pick<WalletNetwork, 'providers' | 'deployment' | 'finalityPolicy'>, signal: AbortSignal) {
  const clients = network.providers.map(p => createInspectionClient(p.url, signal));
  const results = await Promise.allSettled(clients.map(client => client.request({
    method: 'eth_getBlockByNumber', params: ['finalized', false],
  }, { retryCount: 0, dedupe: false })));
  signal.throwIfAborted();
  const blocks = results.map(result => {
    if (result.status !== 'fulfilled' || !result.value) throw new Error('RUNTIME_FINALITY_UNAVAILABLE');
    const block = result.value;
    requireHash(block.hash);
    if (![block.number, block.timestamp].every(v => typeof v === 'string' && /^0x(?:0|[1-9a-f][0-9a-f]{0,63})$/.test(v))) {
      throw new Error('RUNTIME_FINALITY_UNAVAILABLE');
    }
    return { block_hash: block.hash, block_number: BigInt(block.number!).toString(), block_timestamp: BigInt(block.timestamp).toString() };
  });
  const target = BigInt(blocks[0].block_number) <= BigInt(blocks[1].block_number) ? blocks[0] : blocks[1];
  const evidence = await assessCheckpointFinality(clients, { ...target, network_id: network.deployment.network_id,
    genesis_hash: network.deployment.genesis_hash }, network.finalityPolicy, signal);
  if (evidence.status !== 'finalized' || !evidence.checkpoint) throw new Error('RUNTIME_FINALITY_UNAVAILABLE');
  return evidence;
}

export async function requireFreshCreationDeployment(network: WalletNetwork, signal: AbortSignal) {
  const evidence = await networkFinality(network, signal), checkpoint = evidence.checkpoint!;
  const results = await Promise.allSettled(network.providers.map(p => inspectWalletCreationProfile({ document: network.document,
    expectedDigest: network.digest, checkpoint }, p.url, signal)));
  signal.throwIfAborted();
  if (results.some(r => r.status !== 'fulfilled' || r.value.status !== 'composition_matches')
    || Math.floor(Date.now() / 1000) >= evidence.expires_at) throw new Error('RUNTIME_DEPLOYMENT_UNAVAILABLE');
}
