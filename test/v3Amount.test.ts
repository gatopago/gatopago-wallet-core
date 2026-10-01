import { describe, expect, it } from 'vitest';
import { atomicToDecimal, decimalToAtomic } from '@gatopago/shared/v3/amount';
import { UINT256_MAX } from '@gatopago/shared/v3/primitives';

describe('V3 exact monetary display and input', () => {
  it('preserves a full token balance and comma decimal input', () => {
    expect(decimalToAtomic('12345.987654', 6)).toBe('12345987654');
    expect(decimalToAtomic('12345,987654', 6)).toBe('12345987654');
    expect(atomicToDecimal('12345987654', 6)).toBe('12345.987654');
  });
  it.each([0, 6, 7, 18, 77, 78, 255])('round trips all uint256 boundaries at %i decimals', (decimals) => {
    for (const value of ['0', '1', '9007199254740993', (UINT256_MAX - 1n).toString(), UINT256_MAX.toString()]) {
      expect(decimalToAtomic(atomicToDecimal(value, decimals), decimals)).toBe(value);
    }
  });
  it.each(['1e6', '-1', '+1', ' 1', '1 ', '1\n', '01', '.1', '1.', '1,000.00', '1.000,00', '1_000', 'Infinity', 'NaN', '', '１'])('rejects ambiguous input %j', (value) => {
    expect(() => decimalToAtomic(value, 6)).toThrow();
  });
  it('does not round extra precision, including trailing zeroes', () => {
    expect(() => decimalToAtomic('1.0000001', 6)).toThrow();
    expect(() => decimalToAtomic('1.0000000', 6)).toThrow();
    expect(() => decimalToAtomic('1.0', 0)).toThrow();
    expect(() => decimalToAtomic((UINT256_MAX + 1n).toString(), 0)).toThrow();
    expect(() => decimalToAtomic(1, 6)).toThrow();
  });
  it.each([-1, 256, 1.5, NaN, Infinity])('rejects invalid metadata precision %s', (decimals) => {
    expect(() => decimalToAtomic('1', decimals)).toThrow();
    expect(() => atomicToDecimal('1', decimals)).toThrow();
  });
});
