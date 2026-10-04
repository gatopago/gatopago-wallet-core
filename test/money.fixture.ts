import { getAddress, type Hex } from 'viem';
import { createResourceId } from '@gatopago/shared/v3/primitives';
import { deploymentDocumentDigest } from '@gatopago/shared/v3/deployment';
import { prepareInitialization } from '@gatopago/shared/v3/initialization';
import { initializationFixture } from '@gatopago/test-fixtures/v3-initialization';
import { hashSecurityPolicy, type SecurityPolicy } from '@gatopago/shared/v3/security-policy';
import {
  prepareMoneyOperation,
  type MoneyOperationContext,
} from '@gatopago/shared/v3/money-operation';
import { loadAaveMarket } from '@gatopago/shared/v3/aave-market';
import type { MoneyKind } from '@gatopago/shared/v3/money-wire';
import { CLIENT_RELEASE_ID } from '@gatopago/shared/v3/client-release';
import marketJson from '../config/markets/aave-v3-arbitrum-sepolia-usdc.json';

export function createMoneyFixture(kind: MoneyKind = 'aave_supply') {
  const keys = initializationFixture(),
    initial = prepareInitialization(keys.input),
    now = Math.floor(Date.now() / 1000);
  const walletId = createResourceId('wallet'),
    accountId = createResourceId('walletAccount');
  const deploymentDocument = JSON.stringify({
    ...keys.profile.deployment,
    network_id: 'eip155:421614',
    genesis_hash: marketJson.genesis_hash,
  });
  const deployment = deploymentDocumentDigest(deploymentDocument);
  const policy: SecurityPolicy = {
    mode: 'active',
    spendThreshold: 1,
    adminThreshold: 1,
    upgradeDelaySeconds: 259200,
    signers: [
      {
        kind: 1,
        verifier: keys.profile.webauthn_verifier.address,
        verifierCodeHash: keys.profile.webauthn_verifier.runtime_code_hash,
        key: keys.input.publicKey,
        roles: 3,
      },
    ],
  };
  const marketDocument = JSON.stringify({
    ...marketJson,
    valid_from: now - 100,
    valid_until: now + 3600,
  });
  const market = { document: marketDocument, digest: deploymentDocumentDigest(marketDocument) },
    admitted = loadAaveMarket(market);
  const request = {
    schema_version: 1 as const,
    kind,
    wallet_id: walletId,
    wallet_account_id: accountId,
    network_id: 'eip155:421614' as const,
    market_id: 'aave-v3-arbitrum-sepolia-usdc' as const,
    asset_id: marketJson.asset_id,
    amount_atomic: '20000000',
    client_release_id: CLIENT_RELEASE_ID,
    ...(kind === 'aave_withdraw_and_pay'
      ? { recipient_address: getAddress(`0x${'66'.repeat(20)}`) }
      : {}),
  };
  const context: MoneyOperationContext = {
    account: initial.account,
    wallet_account_id: accountId,
    account_id: initial.message.accountId,
    deployment_digest: deployment,
    policy_hash: hashSecurityPolicy(policy),
    security_version: 1n,
    entry_point: keys.profile.deployment.entry_point,
    nonce: 0n,
    market,
    native_asset_id: 'eip155:421614/slip44:60',
    gas: {
      verificationGasLimit: 100n,
      callGasLimit: 100n,
      preVerificationGas: 100n,
      maxFeePerGas: 1n,
      maxPriorityFeePerGas: 0n,
    },
    budget: {
      usdc_available_atomic: '100000000',
      position_available_atomic: '100000000',
      native_available_atomic: '1000000',
      maximum_native_gas_atomic: '300',
      debt_base_atomic: '0',
      liquidity_atomic: '100000000',
      supply_capacity_atomic: null,
    },
    checkpoint: {
      block_number: admitted.admitted_block_number,
      block_hash: admitted.admitted_block_hash,
      observed_at: now,
      expires_at: now + 30,
    },
    valid_until: now + 30,
  };
  const candidate = prepareMoneyOperation(request, context, now),
    review = { request, context, policy, scope: keys.input.scope, prepared_at: now };
  return {
    keys,
    initial,
    deployment,
    deploymentDocument,
    walletId,
    accountId,
    now,
    context,
    request,
    candidate,
    review,
    pins: [{ deployment, market: market.digest }],
    hash: `0x${'11'.repeat(32)}` as Hex,
  };
}
