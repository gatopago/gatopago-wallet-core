import { afterEach, describe, expect, it, vi } from 'vitest';
import { deploymentDocumentDigest } from '@gatopago/shared/v3/deployment';
import { loadMoneyGas } from '../src/runtime/moneyGas';
import marketJson from '../config/markets/aave-v3-arbitrum-sepolia-usdc.json';
import policyJson from '../config/money-gas.json';

const document = JSON.stringify(marketJson),
  market = { document, digest: deploymentDocumentDigest(document) };
const deployment = policyJson.deployment_sha256 as `0x${string}`;
afterEach(() => vi.restoreAllMocks());
describe('Measured money gas admission', () => {
  it('loads separate fork-tested caps and does not mutate the JSON', () => {
    vi.spyOn(Date, 'now').mockReturnValue((policyJson.valid_from + 1) * 1000);
    const gas = loadMoneyGas(policyJson, market, deployment);
    expect(gas.aave_supply?.callGasLimit).toBe(400000n);
    expect(gas.aave_withdraw?.callGasLimit).toBe(200000n);
    expect(gas.aave_withdraw_and_pay?.callGasLimit).toBe(250000n);
    expect(gas.aave_supply?.verificationGasLimit).toBe(496000n);
    expect(policyJson.limits.aave_supply.callGasLimit).toBe('400000');
  });
  it.each([
    'market',
    'deployment',
    'unknown',
    'zero-gas',
    'overlarge',
    'priority',
    'no-evidence',
    'long-window',
    'schema',
  ])('rejects %s admission', (fault) => {
    const p = structuredClone(policyJson);
    if (fault === 'market') p.market_sha256 = `0x${'11'.repeat(32)}`;
    if (fault === 'deployment') p.deployment_sha256 = `0x${'11'.repeat(32)}`;
    if (fault === 'unknown') Object.assign(p.limits.aave_supply, { paymaster: 'arbitrary' });
    if (fault === 'zero-gas') p.limits.aave_supply.callGasLimit = '0';
    if (fault === 'overlarge') p.limits.aave_supply.callGasLimit = (1n << 120n).toString();
    if (fault === 'priority') p.limits.aave_supply.maxPriorityFeePerGas = '100000001';
    if (fault === 'no-evidence') p.evidence_sha256 = '';
    if (fault === 'long-window') p.valid_until += 1;
    if (fault === 'schema') p.money_schema_version = 2;
    expect(() => loadMoneyGas(p, market, deployment)).toThrow();
  });
  it.each(['absent', 'early', 'expired'])('closes all recipes when %s', (state) => {
    vi.spyOn(Date, 'now').mockReturnValue(
      (state === 'expired' ? policyJson.valid_until : policyJson.valid_from - 1) * 1000,
    );
    expect(loadMoneyGas(state === 'absent' ? null : policyJson, market, deployment)).toEqual({
      aave_supply: null,
      aave_withdraw: null,
      aave_withdraw_and_pay: null,
    });
  });
});
