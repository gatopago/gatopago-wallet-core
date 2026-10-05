-- Members' USDC movements: Alchemy Address Activity webhooks deliver them as they happen, and a
-- reconciliation reads each network's Transfer events for anything a webhook missed. A cache:
-- every row can be read again from the chain, so losing it loses no money and no history.
CREATE TABLE transfers (
  network TEXT NOT NULL,
  transaction_hash TEXT NOT NULL,
  log_index INTEGER NOT NULL,
  block_number INTEGER NOT NULL,
  timestamp INTEGER NOT NULL,
  from_address TEXT NOT NULL,
  to_address TEXT NOT NULL,
  amount TEXT NOT NULL,
  -- 'transfer', 'crosschain' (CCTP burn or mint), 'payment' (through the payment router), 'earn'
  -- (to or from Aave) or 'swap' (with a Uniswap pool).
  kind TEXT NOT NULL,
  PRIMARY KEY (network, transaction_hash, log_index)
) STRICT;

CREATE INDEX transfers_from ON transfers (from_address, timestamp);
CREATE INDEX transfers_to ON transfers (to_address, timestamp);

-- Last block the reconciliation read per network.
CREATE TABLE index_cursors (
  network TEXT PRIMARY KEY,
  block INTEGER NOT NULL
) STRICT;

-- Set once a member's address is added to the Alchemy webhooks.
ALTER TABLE members ADD COLUMN watched INTEGER NOT NULL DEFAULT 0;
