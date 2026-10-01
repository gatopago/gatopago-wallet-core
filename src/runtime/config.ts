import type { OperationTransport } from '../execution/operationTransport';
import type { SponsorPolicy } from '../sponsorship/service';
import { parsePaymasterTerms, sponsorshipData } from '@gatopago/shared/v3/paymaster';
import { getAddress } from 'viem';
import { isAddress, type Hex } from 'viem';
import { privateKeyToAccount } from 'viem/accounts';
import type { Environment } from '@gatopago/environment';
import { deploymentDocumentDigest, requireHash } from '@gatopago/shared/v3/deployment';
import { loadPinnedCreationProfile } from '@gatopago/shared/v3/initialization';
import { loadPinnedFinalityPolicy, type FinalityPolicyPin } from '@gatopago/shared/v3/finality';
import { assertAssetNetwork, parseAtomicAmount } from '@gatopago/shared/v3/primitives';
import type { CreationGasTerms } from '@gatopago/shared/v3/creation-operation';
import { rpcEndpoint, validateRpcProviders } from '../chainProviders';
import { localBackupSigner } from '../security/backupSigner';
import type { BackupSponsorPolicy } from '../security/backupTransaction';
import type { CreationProfilePin } from '../creation/initialization';

const invalid = () => new Error('WALLET_RUNTIME_CONFIGURATION_INVALID');
function object(value: unknown): Record<string, unknown> {
  if (!value || typeof value !== 'object' || Array.isArray(value)) throw invalid();
  return value as Record<string, unknown>;
}
function fields(value: unknown, names: readonly string[]) {
  const record = object(value);
  if (Object.keys(record).length !== names.length || names.some(name => !Object.hasOwn(record, name))) throw invalid();
  return record;
}
function text(value: unknown, max = 131_072) {
  if (typeof value !== 'string' || !value.length || value.length > max) throw invalid();
  return value;
}
function pin(value: unknown): CreationProfilePin {
  const source = fields(value, ['document', 'digest']);
  requireHash(source.digest);
  return { document: text(source.document), digest: source.digest };
}
function amount(value: unknown, positive = true) {
  const n = BigInt(parseAtomicAmount(value));
  if (positive && n === 0n) throw invalid();
  return n;
}
function gas(value: unknown): Omit<CreationGasTerms, 'maximumGasCharge'> {
  const v = fields(value, ['verificationGasLimit', 'callGasLimit', 'preVerificationGas', 'maxFeePerGas', 'maxPriorityFeePerGas']);
  const result = { verificationGasLimit: amount(v.verificationGasLimit), callGasLimit: amount(v.callGasLimit),
    preVerificationGas: amount(v.preVerificationGas), maxFeePerGas: amount(v.maxFeePerGas),
    maxPriorityFeePerGas: amount(v.maxPriorityFeePerGas, false) };
  if (Object.values(result).some(n => n >= 1n << 120n) || result.maxPriorityFeePerGas > result.maxFeePerGas) throw invalid();
  return Object.freeze(result);
}
export function maximumGasCharge(terms: Omit<CreationGasTerms, 'maximumGasCharge'>) {
  return (terms.verificationGasLimit + terms.callGasLimit + terms.preVerificationGas) * terms.maxFeePerGas;
}

/** Public, reviewed catalog selects contracts, assets and budgets. Secret bindings
 * supply only endpoint credentials and the optional gas sponsor's signing key. */
export function configureWalletNetworks(catalog: unknown, environment: Environment,
  bindings: Pick<WalletCoreV3Bindings, 'WALLET_RPC_ENDPOINTS' | 'WALLET_BACKUP_SIGNER_KEY'> & { PRIVATE_KEY?: string; WALLET_PAYMASTER_SIGNER_KEY?: string }) {
  try {
    const source = fields(catalog, ['schema_version', 'staging', 'production']);
    if (source.schema_version !== 1 || !Array.isArray(source.staging) || !Array.isArray(source.production)) throw invalid();
    const inputs = source[environment.environment];
    if (!Array.isArray(inputs) || inputs.length > 8 || (inputs.length && environment.status !== 'provisioned')) throw invalid();
    const endpoints = object(JSON.parse(bindings.WALLET_RPC_ENDPOINTS || '{}'));
    const endpoint = (name: unknown) => {
      const key = text(name, 64);
      if (!/^[a-z][a-z0-9_-]*$/.test(key) || !Object.hasOwn(endpoints, key)) throw invalid();
      return rpcEndpoint(text(endpoints[key], 4096));
    };
    const key = bindings.WALLET_BACKUP_SIGNER_KEY;
    if (key && !/^0x[0-9a-fA-F]{64}$/.test(key)) throw invalid();
    const signer = key ? localBackupSigner(privateKeyToAccount(key as Hex)) : undefined;
    const networks = inputs.map(input => {
      const item = fields(input, ['creationProfile', 'finalityPolicy', 'rpc', 'transport', 'assets', 'creationGas', 'transferGas', 'backupSponsor', ...(input && typeof input === 'object' && Object.hasOwn(input, 'paymaster') ? ['paymaster'] : [])]);
      const creationProfile = pin(item.creationProfile), profile = loadPinnedCreationProfile(creationProfile.document, creationProfile.digest);
      const deployment = profile.deployment;
      if (deployment.lifecycle_status !== 'deployed' || !environment.wallet_enabled.includes(deployment.network_id)) throw invalid();
      const finalityPolicy: FinalityPolicyPin = pin(item.finalityPolicy);
      const policy = loadPinnedFinalityPolicy(finalityPolicy, deployment), now = Math.floor(Date.now() / 1000);
      if (now < policy.valid_from || now >= policy.valid_until) throw invalid();
      if (!Array.isArray(item.rpc)) throw invalid();
      const providers = validateRpcProviders(item.rpc.map(value => {
        const p = fields(value, ['operatorId', 'endpoint']);
        return { operatorId: text(p.operatorId, 64), url: endpoint(p.endpoint) };
      }));
      const selected = object(item.transport);
      let transport: OperationTransport;
      if (selected.kind === 'bundler') {
        fields(selected, ['kind', 'endpoint']);
        transport = { kind: 'bundler', url: endpoint(selected.endpoint) };
      } else if (selected.kind === 'self') {
        fields(selected, ['kind', 'endpoint', 'maxGas', 'maxFeePerGas', 'maxPriorityFeePerGas']);
        const relayKey = bindings.PRIVATE_KEY;
        if (!relayKey || !/^0x[0-9a-fA-F]{64}$/.test(relayKey) || relayKey.toLowerCase() === key?.toLowerCase()
          || relayKey.toLowerCase() === bindings.WALLET_PAYMASTER_SIGNER_KEY?.toLowerCase()) throw invalid();
        const operator = privateKeyToAccount(relayKey as Hex).address;
        const maxGas = amount(selected.maxGas), maxFeePerGas = amount(selected.maxFeePerGas);
        const maxPriorityFeePerGas = amount(selected.maxPriorityFeePerGas, false);
        if (maxGas > 30_000_000n || maxFeePerGas >= 1n << 120n || maxPriorityFeePerGas > maxFeePerGas) throw invalid();
        const url = endpoint(selected.endpoint);
        if (!providers.some(p => p.url === url)) throw invalid();
        transport = { kind: 'self', url, providers, policy: { networkId: deployment.network_id,
          operator, maxGas, maxFeePerGas, maxPriorityFeePerGas, maxExecutionFee: maxGas * maxFeePerGas } };
      } else throw invalid();
      const assetDisplay = Object.fromEntries(Object.entries(object(item.assets)).map(([id, value]) => {
        assertAssetNetwork(id, deployment.network_id);
        const asset = fields(value, ['symbol', 'decimals']);
        if (!/^[A-Za-z0-9][A-Za-z0-9._-]{0,15}$/.test(text(asset.symbol, 16)) || typeof asset.decimals !== 'number'
          || !Number.isInteger(asset.decimals) || asset.decimals < 0 || asset.decimals > 255) throw invalid();
        return [id, { symbol: asset.symbol as string, decimals: asset.decimals }];
      }));
      const assetIds = Object.keys(assetDisplay), natives = assetIds.filter(id => id.split('/')[1]?.startsWith('slip44:'));
      if (!assetIds.length || assetIds.length > 32 || natives.length !== 1) throw invalid();
      const document = JSON.stringify(deployment), digest = deploymentDocumentDigest(document);
      let backup;
      if (item.backupSponsor !== null) {
        const sponsor = fields(item.backupSponsor, ['operator', 'maxGas', 'maxFeePerGas', 'maxPriorityFeePerGas', 'maxExecutionFee']);
        const operator = text(sponsor.operator, 42);
        if (!isAddress(operator) || /^0x0{40}$/i.test(operator)) throw invalid();
        const policy: BackupSponsorPolicy = { networkId: deployment.network_id, operator: operator as Hex,
          maxGas: amount(sponsor.maxGas), maxFeePerGas: amount(sponsor.maxFeePerGas),
          maxPriorityFeePerGas: amount(sponsor.maxPriorityFeePerGas, false), maxExecutionFee: amount(sponsor.maxExecutionFee) };
        if (policy.maxPriorityFeePerGas > policy.maxFeePerGas || (signer && signer.operator.toLowerCase() !== operator.toLowerCase())) throw invalid();
        if (signer) backup = { sponsor: policy, signer };
      }
      let paymaster: SponsorPolicy | undefined;
      if (item.paymaster !== undefined && item.paymaster !== null) {
        const p = fields(item.paymaster, ['address','codeHash','signer','verificationGasLimit','postOpGasLimit',
          'maximumCostWei','dailyGwei','userDailyGwei','userDailyOperations']);
        requireHash(p.codeHash);
        const parsed = parsePaymasterTerms({ address: p.address, verificationGasLimit: p.verificationGasLimit,
          postOpGasLimit: p.postOpGasLimit, data: sponsorshipData(1, 2, `0x${'ff'.repeat(65)}`) });
        const limit = (name: string) => { const n = p[name]; if (typeof n !== 'number' || !Number.isSafeInteger(n) || n <= 0) throw invalid(); return n; };
        paymaster = { address: parsed.address, codeHash: p.codeHash, signer: getAddress(text(p.signer, 42)),
          verificationGasLimit: parsed.verificationGasLimit, postOpGasLimit: parsed.postOpGasLimit,
          maximumCostWei: amount(p.maximumCostWei).toString(), dailyGwei: limit('dailyGwei'),
          userDailyGwei: limit('userDailyGwei'), userDailyOperations: limit('userDailyOperations') };
        if (/^0x0{40}$/i.test(paymaster.signer) || /^0x0{64}$/.test(paymaster.codeHash)
          || paymaster.userDailyGwei > paymaster.dailyGwei
          || BigInt(paymaster.maximumCostWei) > BigInt(paymaster.userDailyGwei) * 1_000_000_000n) throw invalid();
      }
      return { ...creationProfile, paymaster, environment: environment.environment, deployment, finalityPolicy, providers,
        transport, creationGas: gas(item.creationGas), transferGas: gas(item.transferGas),
        nativeAssetId: natives[0], backup,
        transferProfile: { document, digest, finalityPolicy, providers, assetIds, assetDisplay,
          entryPointCodeHash: profile.entry_point_code_hash, transport, environment: environment.environment } };
    });
    if (new Set(networks.map(n => n.deployment.network_id)).size !== networks.length
      || environment.wallet_enabled.some(id => !networks.some(n => n.deployment.network_id === id))) throw invalid();
    return networks;
  } catch { throw invalid(); }
}
export type WalletNetwork = ReturnType<typeof configureWalletNetworks>[number];
