-- Gas the sponsored EVM operations of an account declared that day (the sum of their limits),
-- capped by SPONSORED_GAS_PER_DAY. Counting operations alone let a member ask for 50 a day of up
-- to 3,000,000 gas each.
ALTER TABLE sponsorship_usage ADD COLUMN gas INTEGER NOT NULL DEFAULT 0;
