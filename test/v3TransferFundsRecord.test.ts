import { describe, expect, it } from 'vitest';
import { readTransferFunds, writeTransferFunds } from '../src/transfers/transferFundsRecord';
const network = 'eip155:84532';
const row = () => ({ asset_id: `${network}/slip44:60`, observed_atomic: ((1n << 256n) - 1n).toString(),
  reserved_atomic: '1', debit_atomic: ((1n << 256n) - 2n).toString() });
describe('Canonical transfer funds snapshot', () => {
  it('round trips uint256 quantities without floating point or truncation', () => {
    const funds = [row()], record = writeTransferFunds(funds, network);
    expect(readTransferFunds(record.json, record.digest, network)).toEqual(funds);
  });
  it.each(['duplicate', 'overbooked', 'zero', 'wrong-network', 'overflow', 'negative'])(
    'rejects inconsistent funds: %s', fault => {
      const funds = [row()];
      if (fault === 'duplicate') funds.push(row());
      if (fault === 'overbooked') funds[0].debit_atomic = funds[0].observed_atomic;
      if (fault === 'zero') funds[0].debit_atomic = '0';
      if (fault === 'wrong-network') funds[0].asset_id = 'eip155:1/slip44:60';
      if (fault === 'overflow') funds[0].observed_atomic = (1n << 256n).toString();
      if (fault === 'negative') funds[0].reserved_atomic = '-1';
      expect(() => writeTransferFunds(funds, network)).toThrow();
    });
  it('rejects mismatched checksums and oversized input', () => {
    const record = writeTransferFunds([row()], network);
    expect(() => readTransferFunds(record.json, `0x${'ee'.repeat(32)}`, network)).toThrow();
    expect(() => readTransferFunds(' '.repeat(2049), record.digest, network)).toThrow();
  });
});
