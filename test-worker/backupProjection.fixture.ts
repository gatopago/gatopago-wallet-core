import { env } from 'cloudflare:workers';
import { decodeFunctionData, encodeFunctionResult, type Hex } from 'viem';
import { accountInspectionAbi } from '@gatopago/shared/v3/account-inspection';
import { accountSecurityInspectionAbi } from '@gatopago/shared/v3/security-inspection';
import { processBackupProjection } from '../src/security/processBackupProjection';
import { WalletRepository } from '../src/accounts/repository';
import type { CreationProfilePin } from '../src/creation/initialization';
import { backupObservationScenario } from './backupObservation.fixture';

export async function backupProjectionScenario() {
 const f = await backupObservationScenario('commit'); await f.run();
 const policy = f.grant.backup.nextPolicy;
 const state = { version: 2n, manifest: f.grant.signed.expectedManifestHash, scope: f.grant.backup.message.chainScopeHash,
  adminNonce: f.grant.commit!.message.nonce + 1n, pending: false, flags: 1n, policy };
 const original = f.reply.getMockImplementation()!;
 f.reply.mockImplementation(async (method, params) => {
  if (method === 'eth_call') {
   const data = (params[0] as { data: Hex }).data;
   let securityMethod; let accountMethod;
   try { securityMethod = decodeFunctionData({ abi: accountSecurityInspectionAbi, data }).functionName; } catch { /* Other ABI. */ }
   try { accountMethod = decodeFunctionData({ abi: accountInspectionAbi, data }).functionName; } catch { /* Other ABI. */ }
   if (accountMethod === 'inspectAccount') return encodeFunctionResult({ abi: accountInspectionAbi, functionName: accountMethod,
    result: { account: f.grant.initial.account, accountId: f.grant.initial.message.accountId,
     implementation: f.grant.initial.profile.deployment.components.implementation.address,
     securityVersion: state.version, storageLayoutHash: f.grant.initial.profile.deployment.storage_layout_hash } });
   if (securityMethod === 'securitySnapshot') return encodeFunctionResult({ abi: accountSecurityInspectionAbi, functionName: securityMethod,
    result: [state.flags, state.version, BigInt(state.manifest), BigInt(state.scope), 0n, 0n, 0n, state.adminNonce, 1n,
     state.pending ? 1n : 0n, state.pending ? BigInt(f.grant.signed.proposalHash) : 0n, state.pending ? state.version : 0n,
     state.pending ? BigInt(state.manifest) : 0n, state.pending ? BigInt(state.scope) : 0n,
     state.pending ? 1n : 0n, state.pending ? 2n : 0n] });
   if (securityMethod === 'securityPolicy') return encodeFunctionResult({ abi: accountSecurityInspectionAbi, functionName: securityMethod,
    result: { ...state.policy, mode: state.policy.mode === 'active' ? 1 : 0, signers: [...state.policy.signers] } });
  }
  return original(method, params);
 });
 const owned = await new WalletRepository(env.WALLET_DB, f.principal).ownedAccount(f.walletId, f.walletAccountId);
 const finality = async (_pin: CreationProfilePin, signal: AbortSignal) => (await f.profiles(owned, signal))[0].finalityEvidence;
 const configuration = { ...f.configuration, finality };
 return { ...f, active: state, configuration,
  project: (signal = new AbortController().signal) => processBackupProjection(env.WALLET_DB, f.id, configuration, signal) };
}
