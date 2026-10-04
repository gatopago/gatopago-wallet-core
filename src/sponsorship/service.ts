import {
  createPublicClient,
  getAddress,
  http,
  keccak256,
  parseAbi,
  type Address,
  type Hex,
} from 'viem';
import { getUserOperationHash, type UserOperation } from 'viem/account-abstraction';
import { privateKeyToAccount } from 'viem/accounts';
import {
  maximumOperationGasCost,
  paymasterFields,
  paymasterSponsorDigest,
  sponsorshipData,
  type PaymasterTerms,
} from '@gatopago/shared/v3/paymaster';
import type { Principal } from '../auth/principal';
import { SponsorshipBudget } from './budget';

export interface SponsorPolicy {
  address: Address;
  codeHash: Hex;
  signer: Address;
  verificationGasLimit: string;
  postOpGasLimit: string;
  maximumCostWei: string;
  dailyGwei: number;
  userDailyGwei: number;
  userDailyOperations: number;
}
export interface GasSponsor {
  terms(validAfter: number, validUntil: number): PaymasterTerms;
  authorize(
    operation: UserOperation<'0.9'>,
    validAfter: number,
    validUntil: number,
  ): Promise<PaymasterTerms>;
}
const abi = parseAbi([
  'function ENTRY_POINT() view returns (address)',
  'function sponsorSigner() view returns (address)',
  'function maxSponsoredGasCost() view returns (uint256)',
  'function getDeposit() view returns (uint256)',
]);

/** Private service: routes supply owned, locally compiled operations, never visitor calldata.
 * The key authorizes gas only; it is not an account signer or a bundler executor key. */
export function createGasSponsor(
  database: D1Database,
  identity: Principal,
  policy: SponsorPolicy,
  key: Hex,
  chainId: bigint,
  entryPoint: Address,
  rpcUrls: readonly string[],
  signal: AbortSignal,
): GasSponsor {
  const signer = privateKeyToAccount(key),
    budget = new SponsorshipBudget(database);
  if (getAddress(policy.signer) !== signer.address || rpcUrls.length !== 2)
    throw new Error('SPONSOR_CONFIGURATION_INVALID');
  // EntryPoint v0.9 excludes validAfter itself; cover the account window from one second earlier.
  const terms = (validAfter: number, validUntil: number) => ({
    address: policy.address,
    verificationGasLimit: policy.verificationGasLimit,
    postOpGasLimit: policy.postOpGasLimit,
    data: sponsorshipData(Math.max(0, validAfter - 1), validUntil, `0x${'ff'.repeat(65)}`),
  });
  return {
    terms,
    async authorize(operation, validAfter, validUntil) {
      signal.throwIfAborted();
      const now = Math.floor(Date.now() / 1000);
      if (
        identity.expiresAt <= now ||
        validAfter > now ||
        validUntil <= now ||
        validUntil > now + 600
      )
        throw new Error('SPONSOR_WINDOW_INVALID');
      const stub = terms(validAfter, validUntil),
        sponsored = { ...operation, ...paymasterFields(stub, { validAfter, validUntil }) };
      const maximumWei = maximumOperationGasCost(sponsored);
      if (maximumWei <= 0n || maximumWei > BigInt(policy.maximumCostWei))
        throw new Error('SPONSOR_COST_EXCEEDED');
      const checks = await Promise.allSettled(
        rpcUrls.map(async (url) => {
          const client = createPublicClient({
            transport: http(url, { retryCount: 0, timeout: 5000, fetchOptions: { signal } }),
          });
          const block = await client.getBlock({ blockTag: 'latest' });
          const [network, code, ep, authorizer, cap, deposit] = await Promise.all([
            client.getChainId(),
            client.getCode({ address: policy.address, blockNumber: block.number }),
            ...(['ENTRY_POINT', 'sponsorSigner', 'maxSponsoredGasCost', 'getDeposit'] as const).map(
              (functionName) =>
                client.readContract({
                  address: policy.address,
                  abi,
                  functionName,
                  blockNumber: block.number,
                }),
            ),
          ]);
          if (
            BigInt(network) !== chainId ||
            !code ||
            keccak256(code) !== policy.codeHash ||
            typeof ep !== 'string' ||
            getAddress(ep) !== getAddress(entryPoint) ||
            authorizer !== signer.address ||
            typeof cap !== 'bigint' ||
            cap === 0n ||
            maximumWei > cap ||
            typeof deposit !== 'bigint' ||
            deposit < maximumWei
          )
            throw new Error('SPONSOR_CHAIN_UNAVAILABLE');
        }),
      );
      if (checks.some((c) => c.status === 'rejected')) throw new Error('SPONSOR_CHAIN_UNAVAILABLE');
      signal.throwIfAborted();
      const digest = paymasterSponsorDigest(chainId, sponsored);
      await budget.reserve({
        digest,
        scope: `${chainId}:${policy.address.toLowerCase()}`,
        userId: identity.userId,
        maximumWei,
        validUntil,
        dailyGwei: policy.dailyGwei,
        userDailyGwei: policy.userDailyGwei,
        userDailyOperations: policy.userDailyOperations,
      });
      const signature = await signer.signMessage({ message: { raw: digest } });
      const result = {
        ...stub,
        data: sponsorshipData(Math.max(0, validAfter - 1), validUntil, signature),
      };
      const hash = getUserOperationHash({
        chainId: Number(chainId),
        entryPointAddress: entryPoint,
        entryPointVersion: '0.9',
        userOperation: { ...sponsored, ...paymasterFields(result) },
      });
      await budget.bind(digest, hash);
      signal.throwIfAborted();
      return result;
    },
  };
}
