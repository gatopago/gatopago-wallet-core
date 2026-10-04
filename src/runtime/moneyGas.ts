import { loadAaveMarket, type AaveMarketPin } from '@gatopago/shared/v3/aave-market';
import { requireHash } from '@gatopago/shared/v3/deployment';
import { moneyFields } from '@gatopago/shared/v3/money-wire';
import type { MoneyOperationContext } from '@gatopago/shared/v3/money-operation';
import { parseAtomicAmount } from '@gatopago/shared/v3/primitives';
import type { Hex } from 'viem';

const kinds = ['aave_supply', 'aave_withdraw', 'aave_withdraw_and_pay'] as const;
/** Reviewed per-recipe caps, not a gas estimate or permission to change signed
 * fields. Admission is pinned to the tested market, account release and period. */
export function loadMoneyGas(input: unknown, marketPin: AaveMarketPin, deployment: Hex) {
  const absent = { aave_supply: null, aave_withdraw: null, aave_withdraw_and_pay: null } as const;
  if (input === null) return absent;
  const p = moneyFields(input, [
      'schema_version',
      'money_schema_version',
      'network_id',
      'market_sha256',
      'deployment_sha256',
      'evidence_sha256',
      'valid_from',
      'valid_until',
      'limits',
    ]),
    market = loadAaveMarket(marketPin);
  requireHash(p.evidence_sha256);
  if (
    p.schema_version !== 1 ||
    p.money_schema_version !== 1 ||
    p.network_id !== market.network_id ||
    p.market_sha256 !== marketPin.digest ||
    p.deployment_sha256 !== deployment ||
    typeof p.valid_from !== 'number' ||
    typeof p.valid_until !== 'number' ||
    !Number.isSafeInteger(p.valid_from) ||
    !Number.isSafeInteger(p.valid_until) ||
    p.valid_from < market.valid_from ||
    p.valid_until > market.valid_until ||
    p.valid_until <= p.valid_from
  )
    throw new Error('MONEY_GAS_CONFIGURATION_INVALID');
  const limits = moneyFields(p.limits, kinds),
    values: Record<(typeof kinds)[number], MoneyOperationContext['gas']> = {} as Record<
      (typeof kinds)[number],
      MoneyOperationContext['gas']
    >;
  const gasKeys = [
    'verificationGasLimit',
    'callGasLimit',
    'preVerificationGas',
    'maxFeePerGas',
    'maxPriorityFeePerGas',
  ] as const;
  for (const kind of kinds) {
    const raw = moneyFields(limits[kind], gasKeys),
      gas = {} as MoneyOperationContext['gas'];
    for (const key of gasKeys) {
      gas[key] = BigInt(parseAtomicAmount(raw[key]));
      if (gas[key] >= 1n << 120n || (key !== 'maxPriorityFeePerGas' && gas[key] === 0n))
        throw new Error('MONEY_GAS_CONFIGURATION_INVALID');
    }
    if (gas.maxPriorityFeePerGas > gas.maxFeePerGas)
      throw new Error('MONEY_GAS_CONFIGURATION_INVALID');
    values[kind] = Object.freeze(gas);
  }
  const now = Math.floor(Date.now() / 1000);
  return now < p.valid_from || now >= p.valid_until ? absent : Object.freeze(values);
}
