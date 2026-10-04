import type { Hex } from 'viem';
import type { ResourceId } from '@gatopago/shared/v3/primitives';

// Canonical decimal strings compare by length, then lexically. Never cast a
// uint256 balance or block quantity to SQLite REAL or signed-64-bit arithmetic.
export const BALANCE_FLOOR_CURRENT = `NOT EXISTS (SELECT 1 FROM wallet_balance_floors f WHERE f.wallet_account_id = ?
  AND (length(f.block_number) > length(?) OR (length(f.block_number) = length(?) AND f.block_number > ?)
    OR (f.block_number = ? AND f.block_hash != ?)))`;
export const floorValues = (
  id: ResourceId<'walletAccount'>,
  checkpoint: { block_number: string; block_hash: Hex },
) =>
  [
    id,
    checkpoint.block_number,
    checkpoint.block_number,
    checkpoint.block_number,
    checkpoint.block_number,
    checkpoint.block_hash,
  ] as const;
