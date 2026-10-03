import { readFile, writeFile, mkdir } from 'node:fs/promises';
import { fileURLToPath } from 'node:url';
import { resolve, dirname } from 'node:path';
import { getAddress, zeroAddress } from 'viem';
import { deploymentDocumentDigest } from '@gatopago/shared/v3/deployment';
import { parseAaveMarket } from '@gatopago/shared/v3/aave-market';
import { aaveReadAbiDigest } from '../src/portfolio/aaveReadAbi.ts';

const root = resolve(dirname(fileURLToPath(import.meta.url)), '..');
const evidencePath = resolve(root, '../protocol/docs/arbitrum-delivery/market-admission.json');
const evidence = JSON.parse(await readFile(evidencePath, 'utf8'));
const observed = Math.floor(Date.parse(evidence.observed_at) / 1000), now = Math.floor(Date.now() / 1000);
if (evidence.status !== 'market_observed' || !Number.isSafeInteger(observed) || now < observed || now - observed > 86400
  || evidence.network_id !== 'eip155:421614' || !evidence.observation?.contracts) throw new Error('MARKET_EVIDENCE_INVALID');
const data = evidence.observation;
const document = parseAaveMarket({ schema_version: 1, market_id: evidence.market_id, network_id: evidence.network_id,
  asset_id: `eip155:421614/erc20:${evidence.addresses.token.toLowerCase()}`, decimals: 6,
  provider: getAddress(evidence.addresses.provider), pool: getAddress(evidence.addresses.pool), a_token: getAddress(evidence.addresses.a_token),
  genesis_hash: evidence.checkpoint.genesis_hash, abi_sha256: aaveReadAbiDigest,
  admitted_block_number: evidence.checkpoint.block_number, admitted_block_hash: evidence.checkpoint.block_hash,
  valid_from: observed, valid_until: observed + 30 * 86400, max_observation_age_seconds: 30,
  contracts: data.contracts.map(contract => ({ name: contract.name, address: getAddress(contract.address), code_hash: contract.code_hash,
    implementation: contract.eip1967_implementation === zeroAddress ? null : getAddress(contract.eip1967_implementation),
    implementation_code_hash: contract.implementation_code_hash })) });
const directory = resolve(root, 'config/markets');
await mkdir(directory, { recursive: true });
await writeFile(resolve(directory, `${document.market_id}.json`), `${JSON.stringify(document, null, 2)}\n`);
await writeFile(resolve(directory, `${document.market_id}.provenance.json`), `${JSON.stringify({
  schema_version: 1, market_document_digest: deploymentDocumentDigest(JSON.stringify(document)),
  observation_sha256: deploymentDocumentDigest(await readFile(evidencePath, 'utf8')), source: evidence.source,
  inspection_abi_sha256: evidence.abi_sha256, position_read_abi_sha256: aaveReadAbiDigest,
  observed_at: evidence.observed_at, status: 'observed_disabled_pending_execution_tests',
}, null, 2)}\n`);
console.log(JSON.stringify({ market_id: document.market_id, digest: deploymentDocumentDigest(JSON.stringify(document)), status: 'configuration_generated_disabled' }));
