-- Members' Stellar accounts on the configured Stellar network, so its USDC transfers can be matched
-- to members (kept in `transfers` with `block_number` = ledger and amounts in 6 decimals, like
-- every network). A cache: each address derives from the deployer key and the member's EVM address.
CREATE TABLE stellar_accounts (
  -- Unique across networks: the network passphrase is part of every contract address.
  address TEXT PRIMARY KEY,
  network TEXT NOT NULL,
  member_address TEXT NOT NULL REFERENCES members (address)
) STRICT;

CREATE UNIQUE INDEX stellar_accounts_member ON stellar_accounts (member_address, network);

-- Members' CCTP burns toward Stellar, until the relayer mints them there (Circle's Forwarding
-- Service does not reach Stellar). Anyone can mint an attested message: losing a row loses no money.
-- Keyed by member too, so reporting someone else's burn cannot hold back theirs.
CREATE TABLE stellar_relays (
  source_network TEXT NOT NULL,
  transaction_hash TEXT NOT NULL,
  member_address TEXT NOT NULL REFERENCES members (address),
  created_at INTEGER NOT NULL,
  relayed_hash TEXT,
  PRIMARY KEY (source_network, transaction_hash, member_address)
) STRICT;

CREATE INDEX stellar_relays_pending ON stellar_relays (relayed_hash, created_at);
