import {
  assertAssetNetwork,
  parseAtomicAmount,
  parseNetworkId,
} from '@gatopago/shared/v3/primitives';
import { deploymentDocumentDigest, requireHash } from '@gatopago/shared/v3/deployment';

export type TransferFunds = readonly Readonly<{
  asset_id: string;
  observed_atomic: string;
  reserved_atomic: string;
  debit_atomic: string;
}>[];

export function writeTransferFunds(funds: TransferFunds, network: string) {
  if (funds.length < 1 || funds.length > 2) throw new Error('TRANSFER_FUNDS_INVALID');
  const rows = funds
    .map((row) => {
      assertAssetNetwork(row.asset_id, parseNetworkId(network));
      if (!/\/(?:slip44:|erc20:)/.test(row.asset_id)) throw new Error('TRANSFER_FUNDS_INVALID');
      const observed = BigInt(parseAtomicAmount(row.observed_atomic)),
        reserved = BigInt(parseAtomicAmount(row.reserved_atomic));
      const debit = BigInt(parseAtomicAmount(row.debit_atomic));
      if (reserved > observed || debit === 0n || debit > observed - reserved)
        throw new Error('TRANSFER_FUNDS_INVALID');
      return {
        asset_id: row.asset_id,
        observed_atomic: row.observed_atomic,
        reserved_atomic: row.reserved_atomic,
        debit_atomic: row.debit_atomic,
      };
    })
    .sort((a, b) => a.asset_id.localeCompare(b.asset_id));
  if (new Set(rows.map((row) => row.asset_id)).size !== rows.length)
    throw new Error('TRANSFER_FUNDS_INVALID');
  const json = JSON.stringify(rows);
  return { json, digest: deploymentDocumentDigest(json), rows };
}
export function readTransferFunds(json: unknown, digest: unknown, network: string) {
  requireHash(digest);
  if (typeof json !== 'string' || json.length > 2048 || deploymentDocumentDigest(json) !== digest)
    throw new Error('TRANSFER_FUNDS_INVALID');
  const raw: unknown = JSON.parse(json);
  if (!Array.isArray(raw)) throw new Error('TRANSFER_FUNDS_INVALID');
  const rows = raw.map((row: unknown) => {
    if (!row || typeof row !== 'object' || Array.isArray(row) || Object.keys(row).length !== 4)
      throw new Error('TRANSFER_FUNDS_INVALID');
    const asset_id: unknown = Reflect.get(row, 'asset_id');
    if (typeof asset_id !== 'string') throw new Error('TRANSFER_FUNDS_INVALID');
    return {
      asset_id,
      observed_atomic: parseAtomicAmount(Reflect.get(row, 'observed_atomic')),
      reserved_atomic: parseAtomicAmount(Reflect.get(row, 'reserved_atomic')),
      debit_atomic: parseAtomicAmount(Reflect.get(row, 'debit_atomic')),
    };
  });
  const result = writeTransferFunds(rows, network);
  if (result.json !== json) throw new Error('TRANSFER_FUNDS_INVALID');
  return result.rows;
}
