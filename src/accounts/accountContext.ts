import { isAddressEqual } from 'viem';
import { predictAccountAddress } from '@gatopago/shared/v3/authorizations';
import { loadPinnedDeploymentManifest, requireHash } from '@gatopago/shared/v3/deployment';
import type { ResourceId } from '@gatopago/shared/v3/primitives';
import { WalletAccessError, type WalletRepository } from './repository';

/** Owner-only identity projection for Consumer selection. A trusted server release
 * supplies the public deployment documents. Never serialize a provider profile or
 * commitments. This does not inspect chain state or grant receive/spend authority. */
export async function readOwnedAccountContext(repository: Pick<WalletRepository, 'ownedAccount'>,
 walletId: ResourceId<'wallet'>, accountId: ResourceId<'walletAccount'>,
 profilesInput: readonly { readonly document: string; readonly digest: string }[], signal: AbortSignal) {
 if (profilesInput.length > 32) throw new Error('ACCOUNT_PROFILE_UNAVAILABLE');
 const profiles = profilesInput.map(({ document, digest }) => ({ document, digest }));
 signal.throwIfAborted();
 const owned = await repository.ownedAccount(walletId, accountId);
 signal.throwIfAborted();
 const matches = profiles.filter(profile => profile.digest === owned.deployment_manifest_sha256);
 if (matches.length !== 1) throw new Error('ACCOUNT_PROFILE_UNAVAILABLE');
 const profile = matches[0];
 requireHash(profile.digest);
 const manifest = loadPinnedDeploymentManifest(profile.document, profile.digest);
 if (manifest.generation !== 3 || manifest.lifecycle_status !== 'deployed' || manifest.network_id !== owned.network_id
  || !isAddressEqual(predictAccountAddress(manifest.components.factory.address, owned.account_id, manifest.proxy.init_code_hash), owned.address)) {
  throw new WalletAccessError('WALLET_DATA_INVALID');
 }
 return { schema_version: 1 as const, wallet_id: walletId, wallet_account_id: accountId,
  network_id: owned.network_id, account_id: owned.account_id, address: owned.address,
  deployment: profile, spend_readiness: 'not_assessed' as const, receive_enabled: false as const, send_enabled: false as const };
}
