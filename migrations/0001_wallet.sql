-- Accounts live onchain; this database only gates sign-up and keeps conveniences.

CREATE TABLE invites (
  code TEXT PRIMARY KEY,
  issued_by TEXT NOT NULL,
  created_at INTEGER NOT NULL,
  expires_at INTEGER NOT NULL,
  consumed_by TEXT,
  revoked_at INTEGER
) STRICT;

-- GatoPago users: an onchain account admitted with an invitation, and its public profile.
CREATE TABLE members (
  id TEXT PRIMARY KEY,
  address TEXT NOT NULL UNIQUE,
  invite_code TEXT NOT NULL UNIQUE REFERENCES invites (code),
  initial_owners TEXT,
  username TEXT UNIQUE,
  display_name TEXT,
  joined_at INTEGER NOT NULL
) STRICT;

CREATE TABLE siwe_nonces (
  nonce TEXT PRIMARY KEY,
  expires_at INTEGER NOT NULL
) STRICT;

-- Signed owner approvals, replayable on every network; also recoverable from onchain events.
CREATE TABLE approvals (
  account TEXT NOT NULL REFERENCES members (address),
  sequence INTEGER NOT NULL,
  call TEXT NOT NULL,
  signature TEXT NOT NULL,
  created_at INTEGER NOT NULL,
  PRIMARY KEY (account, sequence)
) STRICT;

CREATE TABLE sponsorship_usage (
  account TEXT NOT NULL,
  day INTEGER NOT NULL,
  operations INTEGER NOT NULL,
  PRIMARY KEY (account, day)
) STRICT;
