import { readFile, writeFile, mkdir } from 'node:fs/promises';
import { resolve, dirname } from 'node:path';
import { fileURLToPath } from 'node:url';
import { createPublicClient, getAddress, http } from 'viem';
import { deploymentDocumentDigest } from '@gatopago/shared/v3/deployment';
import { observeAavePosition } from '../.wrangler/aave-position-reader.mjs';

// Build the actual production reader before this read-only inspection. No .env,
// signer or app session is loaded; the account is an explicit public address.
const root = resolve(dirname(fileURLToPath(import.meta.url)), '..');
const args = process.argv.slice(2);
if (args.length !== 2 || args[0] !== '--account') throw new Error('INSPECTION_ACCOUNT_REQUIRED');
const account = getAddress(args[1]);
const market = JSON.parse(await readFile(resolve(root, 'config/markets/aave-v3-arbitrum-sepolia-usdc.json'), 'utf8'));
const document = JSON.stringify(market), digest = deploymentDocumentDigest(document);
const peers = [{ operatorId: 'offchain-labs', url: 'https://sepolia-rollup.arbitrum.io/rpc' },
  { operatorId: 'tenderly', url: 'https://arbitrum-sepolia.gateway.tenderly.co' }];
const clients = peers.map(peer => createPublicClient({ transport: http(peer.url, { timeout: 10000, retryCount: 0 }) }));
const headers = await Promise.all(clients.map(client => client.getBlock({ blockTag: 'finalized' })));
const number = headers.reduce((low, header) => header.number < low ? header.number : low, headers[0].number);
const matching = await Promise.all(clients.map(client => client.getBlock({ blockNumber: number })));
if (matching[0].hash !== matching[1].hash) throw new Error('POSITION_CHECKPOINT_MISMATCH');
const checkpoint = { block_number: number.toString(), block_hash: matching[0].hash };
const observation = await observeAavePosition({ account, market: { document, digest }, checkpoint }, peers, AbortSignal.timeout(30000));
const report = { schema_version: 1, status: 'readonly_position_observed', observed_at: new Date().toISOString(),
  ownership: 'not_verified', operations_executed: false, operators: peers.map(peer => peer.operatorId), observation };
const directory = resolve(root, '../protocol/docs/arbitrum-delivery');
await mkdir(directory, { recursive: true });
await writeFile(resolve(directory, 'position-readonly.json'), `${JSON.stringify(report, null, 2)}\n`);
console.log(JSON.stringify({ status: report.status, checkpoint, active: observation.active, frozen: observation.frozen, paused: observation.paused,
  debt_base_atomic: observation.debt_base_atomic, position_balance_atomic: observation.position_balance_atomic, ownership: report.ownership }));
