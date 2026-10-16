-- A member's Stellar call is recorded before its transaction is broadcast, so a lost answer always
-- finds it: 'pending' until the network answers, then 'confirmed' or 'failed'. Rows from before
-- were written once confirmed.
ALTER TABLE stellar_submissions
  ADD COLUMN status TEXT NOT NULL DEFAULT 'confirmed'
  CHECK (status IN ('pending', 'confirmed', 'failed'));
