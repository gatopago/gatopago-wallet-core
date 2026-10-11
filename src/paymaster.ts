import { isAddressEqual, numberToHex, type Address } from 'viem';
import {
  entryPoint09Address,
  formatUserOperation,
  type RpcUserOperation,
  type UserOperation,
} from 'viem/account-abstraction';
import { gatopagoGasConfig } from '@gatopago/shared/bundler';
import { walletContracts } from '@gatopago/shared/networks';
import {
  SPONSORSHIP_SECONDS,
  sponsorshipPaymasterData,
  sponsorshipTypedData,
} from '@gatopago/shared/wallet';
import { MAX_SPONSORED_GAS, type Config, type Network } from './config';
import { enabledNetwork, HttpError, json, readJson } from './http';
import { signedInMember } from './profile';

/**
 * Stand-in paymaster data for estimation (ERC-7677): as long as the signed data and with no more
 * zero bytes, so the `preVerificationGas` estimated with it covers the final calldata.
 */
const STUB_PAYMASTER_DATA = sponsorshipPaymasterData(0, 2 ** 48 - 1, `0x${'ff'.repeat(65)}`);
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
  const member = await signedInMember(request, env, config);
  const body = await readJson<{ id?: unknown; method?: string; params?: unknown[] }>(request);
  const [rpcOperation, entryPoint, chainId] = body.params ?? [];
  if (
    typeof entryPoint !== 'string' ||
    !isAddressEqual(entryPoint as Address, entryPoint09Address) ||
    Number(chainId) !== network.chain.id
  )
    throw new HttpError(400, 'INVALID_REQUEST');
  const operation = formatUserOperation(rpcOperation as RpcUserOperation) as UserOperation<'0.9'>;
  if (!isAddressEqual(operation.sender, member.address))
    throw new HttpError(403, 'NOT_ACCOUNT_OWNER');
  const reply = (result: object) => json({ jsonrpc: '2.0', id: body.id ?? null, result });

  if (body.method === 'pm_getPaymasterStubData')
    return reply({ ...paymasterFields(STUB_PAYMASTER_DATA), isFinal: false });
  if (body.method !== 'pm_getPaymasterData') throw new HttpError(400, 'METHOD_NOT_SUPPORTED');

  await consumeDailyBudget(env, config, member.address, await declaredGas(operation, network));
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

/** The gas the operation may use (its limits), within the per-operation ceiling and price. */
async function declaredGas(operation: UserOperation<'0.9'>, network: Network) {
  const gas =
    operation.verificationGasLimit +
    operation.callGasLimit +
    operation.preVerificationGas +
    paymasterGas.paymasterVerificationGasLimit +
    paymasterGas.paymasterPostOpGasLimit;
  const price = await network.client.getGasPrice();
  if (gas > BigInt(MAX_SPONSORED_GAS) || operation.maxFeePerGas > price * 3n)
    throw new HttpError(400, 'GAS_NOT_SPONSORED');
  return Number(gas);
}

/**
 * Counts one sponsored operation (any network) and the gas it declares (EVM; none on Stellar)
 * against the account's daily budget.
 */
export async function consumeDailyBudget(env: Env, config: Config, account: Address, gas = 0) {
  const result = await env.WALLET_DB.prepare(
    `INSERT INTO sponsorship_usage (account, day, operations, gas) VALUES (?1, ?2, 1, ?3)
     ON CONFLICT (account, day) DO UPDATE SET operations = operations + 1, gas = gas + ?3
     WHERE operations < ?4 AND gas + ?3 <= ?5`,
  )
    .bind(
      account.toLowerCase(),
      Math.floor(Date.now() / 86_400_000),
      gas,
      config.sponsoredOperationsPerDay,
      config.sponsoredGasPerDay,
    )
    .run();
  if (result.meta.changes !== 1) throw new HttpError(429, 'SPONSORSHIP_LIMIT_REACHED');
}
