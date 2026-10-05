import { spawn } from 'node:child_process';
import { createTestClient, http, parseAbi, parseEther, publicActions, walletActions } from 'viem';
import { privateKeyToAccount } from 'viem/accounts';
import { arbitrumSepolia } from 'viem/chains';
import { walletContracts } from '@gatopago/shared/networks';

export const FORK_RPC = 'http://127.0.0.1:8711';
/** Anvil's default keys: relayer and sponsor signer of the forked paymaster. */
export const RELAYER_KEY = '0xac0974bec39a17e36ba4a846b8f9e6d0f2a4cf0b8ba3c9ec2a1fe8a7d6a5f1a7';
export const SPONSOR_KEY = '0x59c6995e998f97a5a0044966f0945389dc9e86dae88c7a8412f4603b6b78690d';
const PAYMASTER_OWNER = '0x75464f762bc50d0A0B127ab5a085504BF102Bb88';

/**
 * Vitest global setup: a fork of Arbitrum Sepolia, where GatoPago's contracts are deployed, with
 * the paymaster's sponsor signer set to a test key. Osaka provides the P256 precompile.
 */
export default async function setup() {
  const anvil = spawn(
    'anvil',
    [
      '--fork-url',
      process.env.ARBITRUM_SEPOLIA_RPC ?? 'https://sepolia-rollup.arbitrum.io/rpc',
      '--port',
      '8711',
      '--hardfork',
      'osaka',
      '--silent',
    ],
    { stdio: 'ignore' },
  );
  const client = createTestClient({
    chain: arbitrumSepolia,
    mode: 'anvil',
    transport: http(FORK_RPC),
  })
    .extend(publicActions)
    .extend(walletActions);
  for (let attempt = 0; ; attempt++) {
    try {
      await client.getChainId();
      break;
    } catch (error) {
      if (attempt > 150) throw error;
      await new Promise((resolve) => setTimeout(resolve, 200));
    }
  }
  await client.setBalance({
    address: privateKeyToAccount(RELAYER_KEY).address,
    value: parseEther('100'),
  });
  await client.setBalance({ address: PAYMASTER_OWNER, value: parseEther('100') });
  // Arbitrum's NodeInterface only exists in Arbitrum nodes: return a fixed L1 gas estimate (1000).
  await client.setCode({
    address: '0x00000000000000000000000000000000000000C8',
    bytecode: '0x6103e860005260606000f3',
  });
  await client.impersonateAccount({ address: PAYMASTER_OWNER });
  const paymasterAbi = parseAbi([
    'function setSponsorSigner(address)',
    'function deposit() payable',
  ]);
  for (const request of [
    { functionName: 'setSponsorSigner', args: [privateKeyToAccount(SPONSOR_KEY).address] },
    { functionName: 'deposit', value: parseEther('10') },
  ] as const) {
    const hash = await client.writeContract({
      account: PAYMASTER_OWNER,
      address: walletContracts.paymaster,
      abi: paymasterAbi,
      ...request,
    } as never);
    await client.waitForTransactionReceipt({ hash });
  }
  return () => void anvil.kill();
}
