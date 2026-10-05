import { isAddressEqual, numberToHex, type Address } from 'viem';
import {
  entryPoint09Address,
  formatUserOperation,
  type RpcUserOperation,
  type UserOperation,
} from 'viem/account-abstraction';
import { gatopagoGasConfig } from '@gatopago/shared/bundler';
import { walletContracts } from '@gatopago/shared/networks';
import { sponsorshipPaymasterData, sponsorshipTypedData } from '@gatopago/shared/wallet';
import type { Config, Network } from './config';
import { enabledNetwork, HttpError, json, readJson } from './http';
import { authenticate } from './session';

/** Ceiling on the gas a single sponsored operation may declare (deployment and batches fit). */
const MAX_SPONSORED_GAS = 3_000_000n;
const SPONSORSHIP_SECONDS = 300;
const paymasterGas = {
  paymasterVerificationGasLimit: gatopagoGasConfig.paymasterVerificationGasLimit,
  paymasterPostOpGasLimit: gatopagoGasConfig.paymasterPostOpGasLimit,
};
const paymasterFields = (paymasterData: `0x${string}`) => ({
  paymaster: walletContracts.paymaster,
  paymasterData,
  paymasterVerificationGasLimit: numberToHex(paymasterGas.paymasterVerificationGasLimit),
  paymasterPostOpGasLimit: numberToHex(paymasterGas.paymasterPostOpGasLimit),
});

/**
 * `POST /app/v1/paymaster/:network`: ERC-7677 paymaster web service. Sponsors operations of the
 * signed-in account only, within per-operation gas ceilings and a daily operation budget.
 */
export async function sponsor(
  request: Request,
  env: Env,
  config: Config,
  networkId: string,
): Promise<Response> {
  const network = enabledNetwork(config, networkId);
  const session = await authenticate(request, config);
  const body = await readJson<{ id?: unknown; method?: string; params?: unknown[] }>(request);
  const [rpcOperation, entryPoint, chainId] = body.params ?? [];
  if (
    typeof entryPoint !== 'string' ||
    !isAddressEqual(entryPoint as Address, entryPoint09Address) ||
    Number(chainId) !== network.chain.id
  )
    throw new HttpError(400, 'INVALID_REQUEST');
  const operation = formatUserOperation(rpcOperation as RpcUserOperation) as UserOperation<'0.9'>;
  if (!isAddressEqual(operation.sender, session.address))
    throw new HttpError(403, 'NOT_ACCOUNT_OWNER');
  const reply = (result: object) => json({ jsonrpc: '2.0', id: body.id ?? null, result });

  if (body.method === 'pm_getPaymasterStubData')
    return reply({
      ...paymasterFields(sponsorshipPaymasterData(0, 0, `0x${'00'.repeat(65)}`)),
      isFinal: false,
    });
  if (body.method !== 'pm_getPaymasterData') throw new HttpError(400, 'METHOD_NOT_SUPPORTED');

  await assertReasonableGas(operation, network);
  await consumeDailyBudget(env, config, session.address);
  const validUntil = Math.floor(Date.now() / 1000) + SPONSORSHIP_SECONDS;
  const signature = await config.sponsor.signTypedData(
    sponsorshipTypedData({
      chainId: network.chain.id,
      paymaster: walletContracts.paymaster,
      userOperation: { ...operation, ...paymasterGas },
      validAfter: 0,
      validUntil,
    }),
  );
  return reply(paymasterFields(sponsorshipPaymasterData(0, validUntil, signature)));
}

async function assertReasonableGas(operation: UserOperation<'0.9'>, network: Network) {
  const gas =
    operation.verificationGasLimit +
    operation.callGasLimit +
    operation.preVerificationGas +
    paymasterGas.paymasterVerificationGasLimit +
    paymasterGas.paymasterPostOpGasLimit;
  const price = await network.client.getGasPrice();
  if (gas > MAX_SPONSORED_GAS || operation.maxFeePerGas > price * 3n)
    throw new HttpError(400, 'GAS_NOT_SPONSORED');
}

async function consumeDailyBudget(env: Env, config: Config, account: Address) {
  const result = await env.WALLET_DB.prepare(
    `INSERT INTO sponsorship_usage (account, day, operations) VALUES (?, ?, 1)
     ON CONFLICT (account, day) DO UPDATE SET operations = operations + 1 WHERE operations < ?`,
  )
    .bind(
      account.toLowerCase(),
      Math.floor(Date.now() / 86_400_000),
      config.sponsoredOperationsPerDay,
    )
    .run();
  if (result.meta.changes !== 1) throw new HttpError(429, 'SPONSORSHIP_LIMIT_REACHED');
}
