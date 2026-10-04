import { erc20Abi, parseAbi } from 'viem';
import { aavePoolAbi, aaveProviderAbi, aaveTokenAbi } from '@gatopago/shared/v3/aave-market';
import { deploymentDocumentDigest } from '@gatopago/shared/v3/deployment';

export const aavePositionExtraAbi = parseAbi([
  'function getReserveNormalizedIncome(address asset) view returns (uint256)',
  'function scaledTotalSupply() view returns (uint256)',
]);
export const aaveReadAbiDigest = deploymentDocumentDigest(
  JSON.stringify([aavePoolAbi, aaveProviderAbi, aaveTokenAbi, erc20Abi, aavePositionExtraAbi]),
);
