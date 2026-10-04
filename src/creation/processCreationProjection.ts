import { rpcEndpoint } from '../chainProviders';
import { zeroHash } from 'viem';
import { hashSecurityManifest } from '@gatopago/shared/v3/authorizations';
import { deploymentDocumentDigest } from '@gatopago/shared/v3/deployment';
import { loadPinnedFinalityPolicy, type FinalityPolicyPin } from '@gatopago/shared/v3/finality';
import { loadPinnedCreationProfile } from '@gatopago/shared/v3/initialization';
import { createResourceId, parseResourceId, type ResourceId } from '@gatopago/shared/v3/primitives';
import { inspectFinalizedWalletSecurity } from '../finalizedSecurityInspection';

import { CreationDeliveryRepository, type CreationDeliveryConfiguration } from './creationDelivery';
import { CreationObservationJournal } from './creationObservationJournal';
import type { CreationProfilePin } from './initialization';
import { WalletAccessError } from '../accounts/repository';

interface Network extends CreationProfilePin {
  readonly finalityPolicy: FinalityPolicyPin;
  readonly providers: readonly { readonly operatorId: string; readonly url: string }[];
}
interface Configuration extends Omit<CreationDeliveryConfiguration, 'profiles'> {
  readonly networks: readonly Network[];
}
type Row = Record<string, unknown>;
const invalid = () => new WalletAccessError('WALLET_DATA_INVALID');

export async function processCreationProjection(
  database: D1Database,
  id: ResourceId<'operation'>,
  configuration: Configuration,
  signal: AbortSignal,
) {
  parseResourceId('operation', id);
  if (configuration.networks.length > 32) throw new Error('Too many projection networks');
  const networks = configuration.networks.map((network) => {
    const profile = loadPinnedCreationProfile(network.document, network.digest);
    const finalityPolicy = Object.freeze({ ...network.finalityPolicy });
    loadPinnedFinalityPolicy(finalityPolicy, profile.deployment);
    if (network.providers.length !== 2)
      throw new Error('Exactly two projection observers required');
    const providers = network.providers.map((p) => {
      if (!/^[a-z][a-z0-9_-]{1,63}$(?![\s\S])/.test(p.operatorId))
        throw new Error('Invalid projection observer');
      return Object.freeze({ operatorId: p.operatorId, url: rpcEndpoint(p.url) });
    });
    if (
      new Set(providers.map((p) => p.operatorId)).size !== 2 ||
      new Set(providers.map((p) => new URL(p.url).hostname)).size !== 2
    )
      throw new Error('Projection observers overlap');
    return Object.freeze({
      document: network.document,
      digest: network.digest,
      finalityPolicy,
      providers: Object.freeze(providers),
    });
  });
  const config = Object.freeze({
    environment: configuration.environment,
    scope: Object.freeze({ ...configuration.scope }),
    profiles: Object.freeze(networks),
  });
  const grants = new CreationDeliveryRepository(database, config),
    journal = new CreationObservationJournal(database, config);
  const db = database.withSession('first-primary');
  signal.throwIfAborted();
  const grant = await grants.observationGrant(id);
  if (!grant) return 'pending' as const;
  const prepared = grant.signed.prepared,
    message = prepared.message;
  const network = networks.find((n) => n.digest === prepared.profileDigest);
  if (!network) throw invalid();
  const address = prepared.account.toLowerCase(),
    networkId = prepared.profile.deployment.network_id;
  const deployment = JSON.stringify(prepared.profile.deployment),
    deploymentDigest = deploymentDocumentDigest(deployment);
  async function existing() {
    const row = await db
      .prepare(
        `SELECT x.*, a.wallet_id AS actual_wallet,
			a.network_id, w.account_id, w.canonical_address, w.user_id, i.user_id AS initial_user
			FROM account_creation_projections x JOIN wallet_accounts a ON a.id = x.wallet_account_id
			JOIN wallets w ON w.id = a.wallet_id
			JOIN account_initializations i ON i.id = x.initialization_id
			WHERE x.initialization_id = ?`,
      )
      .bind(id)
      .first<Row>();
    if (!row) return false;
    if (
      row.wallet_id !== row.actual_wallet ||
      row.user_id !== row.initial_user ||
      row.network_id !== networkId ||
      row.account_id !== message.accountId ||
      row.canonical_address !== address ||
      typeof row.security_json !== 'string' ||
      deploymentDocumentDigest(row.security_json) !== row.security_sha256
    )
      throw invalid();
    return true;
  }
  if (await existing()) return 'already_projected' as const;
  const source = await journal.latest(id);
  if (
    !source ||
    source.result.status !== 'observed' ||
    source.result.finality !== 'finalized' ||
    source.result.observation.outcome !== 'creation_succeeded'
  )
    return 'pending' as const;
  const expectedManifest = hashSecurityManifest({
    accountId: message.accountId,
    generation: 3,
    securityVersion: 1n,
    previousManifestHash: zeroHash,
    policyHash: message.initialSecurityCommitment,
    chainScopeHash: message.chainScopeHash,
  });
  if (
    source.result.observation.initial_manifest_hash !== expectedManifest ||
    [...source.result.provider_ids].sort().join(',') !==
      network.providers
        .map((p) => p.operatorId)
        .sort()
        .join(',')
  )
    throw invalid();
  const security = await inspectFinalizedWalletSecurity(
    {
      document: deployment,
      expectedDigest: deploymentDigest,
      initialSecurityCommitment: message.initialSecurityCommitment,
      userSaltCommitment: message.userSaltCommitment,
      rpcUrls: network.providers.map((p) => p.url),
      finalityPolicy: network.finalityPolicy,
      finalityEvidence: source.result.finality_evidence,
    },
    signal,
  );
  if (
    !('security' in security) ||
    security.status !== 'recognized' ||
    security.security_version !== '1' ||
    security.security.phase !== 'active_policy' ||
    security.security.manifest_hash !== expectedManifest ||
    security.security.policy_hash !== message.initialSecurityCommitment ||
    security.security.chain_scope_hash !== message.chainScopeHash ||
    security.security.pending !== null ||
    security.security.upgrades_frozen ||
    Object.values(security.security.nonces).some((nonce) => nonce !== '0')
  )
    throw new Error('CREATION_SECURITY_CHANGED');

  const currentGrant = await grants.observationGrant(id);
  if (
    !currentGrant ||
    currentGrant.signed.digest !== grant.signed.digest ||
    currentGrant.signed.operation.signature !== grant.signed.operation.signature
  )
    throw invalid();
  const owner = await db
    .prepare(
      `SELECT w.*, u.id AS owner_id
		FROM account_initializations i JOIN users u ON u.id = i.user_id
		LEFT JOIN wallets w ON w.account_id = ?
		WHERE i.id = ? AND u.environment = ?`,
    )
    .bind(message.accountId, id, config.environment)
    .first<Row>();
  if (!owner) throw invalid();
  const userId = parseResourceId('user', owner.owner_id);
  if (
    owner.id !== null &&
    (owner.user_id !== userId ||
      owner.status !== 'active' ||
      owner.canonical_address !== address ||
      owner.initial_security_commitment !== message.initialSecurityCommitment ||
      owner.user_salt_commitment !== message.userSaltCommitment)
  )
    throw invalid();

  const walletId =
    owner.id === null ? createResourceId('wallet') : parseResourceId('wallet', owner.id);
  const accountId = createResourceId('walletAccount');
  const now = Math.floor(Date.now() / 1000),
    expires = security.security_expires_at;
  signal.throwIfAborted();
  if (now >= expires) throw new Error('SECURITY_FINALITY_UNUSABLE');
  const sourceJson = JSON.stringify(source.result),
    sourceDigest = deploymentDocumentDigest(sourceJson);
  const securityJson = JSON.stringify(security);
  if (securityJson.length > 16384) throw invalid();

  const from = `FROM account_initializations i JOIN users u ON u.id = i.user_id
		JOIN account_creation_operations o ON o.initialization_id = i.id
		JOIN account_creation_observation_jobs j ON j.initialization_id = i.id
		JOIN account_creation_observations r ON r.initialization_id = i.id AND r.lease_epoch = j.latest_epoch
		WHERE i.id = ? AND u.environment = ? AND u.id = ? AND o.user_op_hash = ? AND o.operation_signature = ?
		AND i.approval_digest = ? AND i.profile_sha256 = ? AND i.public_key = ? AND i.user_salt_commitment = ?
		AND o.operation_digest = ? AND j.latest_epoch = ? AND j.lease_token IS NULL AND r.result_json = ? AND r.result_sha256 = ?
		AND unixepoch() < ? AND NOT EXISTS (SELECT 1 FROM account_creation_projections x WHERE x.initialization_id = i.id)
		AND NOT EXISTS (SELECT 1 FROM wallets w WHERE w.account_id = ? AND w.id <> ?)
		AND NOT EXISTS (SELECT 1 FROM wallets w WHERE w.id = ? AND (w.user_id <> u.id OR w.status <> 'active'))`;
  const conditions = [
    id,
    config.environment,
    userId,
    grant.signed.userOpHash,
    grant.signed.operation.signature,
    prepared.digest,
    prepared.profileDigest,
    prepared.policy.signers[0].key,
    message.userSaltCommitment,
    grant.signed.digest,
    source.epoch,
    sourceJson,
    sourceDigest,
    expires,
    message.accountId,
    walletId,
    walletId,
  ] as const;
  const writes = await db.batch([
    db
      .prepare(
        `INSERT INTO wallets(id,user_id,status,account_id,initial_security_commitment,user_salt_commitment,canonical_address,created_at)
			SELECT ?,u.id,'active',?,?,?,?,? ${from} ON CONFLICT(id) DO NOTHING`,
      )
      .bind(
        walletId,
        message.accountId,
        message.initialSecurityCommitment,
        message.userSaltCommitment,
        address,
        now,
        ...conditions,
      ),
    db
      .prepare(
        `INSERT INTO wallet_accounts(id,wallet_id,network_id,address,deployment_manifest_sha256,deployment_state,created_at)
			SELECT ?,?,?,?,?,'active',? ${from}`,
      )
      .bind(accountId, walletId, networkId, address, deploymentDigest, now, ...conditions),
    db
      .prepare(
        `INSERT INTO account_creation_projections(initialization_id,source_epoch,source_sha256,wallet_id,
			wallet_account_id,security_json,security_sha256,projected_at,evidence_expires_at)
			SELECT i.id,?,?,?,?,?,?,?,? ${from}`,
      )
      .bind(
        source.epoch,
        sourceDigest,
        walletId,
        accountId,
        securityJson,
        deploymentDocumentDigest(securityJson),
        now,
        expires,
        ...conditions,
      ),
  ]);
  if (writes.length !== 3 || writes.some((r) => !r.success || ![0, 1].includes(r.meta.changes)))
    throw invalid();
  if (writes[2].meta.changes === 1) return 'projected' as const;
  if (writes.some((r) => r.meta.changes !== 0)) throw invalid();
  return (await existing()) ? ('already_projected' as const) : ('superseded' as const);
}
