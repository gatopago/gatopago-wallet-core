-- Which coin each movement moved: USDC, or another token the network configures (AUSD on Monad).
-- Rows from before are USDC, the only coin indexed until now.
ALTER TABLE transfers ADD COLUMN token TEXT NOT NULL DEFAULT 'USDC';
