-- Coverage per network instead of one flag per member: a webhook or a network configured later
-- catches up the members who were already there.
CREATE TABLE member_networks (
  address TEXT NOT NULL REFERENCES members (address),
  network TEXT NOT NULL,
  -- The Alchemy webhook the address was added to; another one configured later adds it again.
  webhook TEXT,
  -- Whether the history from before the member joined was read on this network (HyperSync).
  history_read INTEGER NOT NULL DEFAULT 0,
  PRIMARY KEY (address, network)
) STRICT;

-- Every member is added to the webhooks again (adding an address twice changes nothing) and its
-- earlier history goes on from where it was read (the `history:` cursors): a few requests, once.
ALTER TABLE members DROP COLUMN watched;
ALTER TABLE members DROP COLUMN history_read;

-- When each reader last moved and last failed: the health check tells which one stopped.
ALTER TABLE index_cursors ADD COLUMN updated_at INTEGER;
CREATE TABLE index_failures (
  reader TEXT PRIMARY KEY,
  failed_at INTEGER NOT NULL
) STRICT;
