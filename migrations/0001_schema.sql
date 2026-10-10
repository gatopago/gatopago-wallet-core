-- Accounts live onchain; this database only gates sign-up and keeps conveniences and caches.
-- Losing it loses no money and no access.

-- Invitations: they gate sign-up with `INVITE_ONLY` on and count who joined with each member's.
CREATE TABLE invites (
  code TEXT PRIMARY KEY,
  issued_by TEXT NOT NULL,
  created_at INTEGER NOT NULL,
  expires_at INTEGER NOT NULL,
  consumed_by TEXT,
  revoked_at INTEGER
) STRICT;

CREATE INDEX invites_issued_by ON invites (issued_by);

-- GatoPago users: an onchain account and its public profile.
CREATE TABLE members (
  id TEXT PRIMARY KEY,
  address TEXT NOT NULL UNIQUE,
  invite_code TEXT NOT NULL UNIQUE REFERENCES invites (code),
  initial_owners TEXT,
  username TEXT UNIQUE,
  display_name TEXT,
  -- A link to the member's social profile, shown on their public payment page.
  social_url TEXT,
  joined_at INTEGER NOT NULL,
  -- Set once the address is added to the Alchemy webhooks.
  watched INTEGER NOT NULL DEFAULT 0,
  -- Whether the history from before they joined was read (Envio HyperSync, when configured).
  history_read INTEGER NOT NULL DEFAULT 0,
  -- Wallet sessions carry the generation they were issued in. Removing an owner moves it on, so no
  -- session issued before (it may be the removed passkey's) stays valid.
  session_generation INTEGER NOT NULL DEFAULT 0,
  -- The member's account on the configured Stellar network (null until the cron writes it). It
  -- derives from the sponsor key and the EVM address, so the indexer and the notices find members
  -- by it; another Stellar network or sponsor key means clearing it.
  stellar_address TEXT UNIQUE
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

-- Members' movements on every network: Alchemy webhooks deliver them as they happen, and a
-- reconciliation (RPC or HyperSync) and the Stellar indexer read what they missed. A cache: every
-- row can be read again from the chain. Stellar rows keep the ledger in `block_number` and amounts
-- in 6 decimals; native coins have `log_index` -1.
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
  -- USDC, or another coin the network configures (AUSD on Monad, XLM on Stellar).
  token TEXT NOT NULL DEFAULT 'USDC',
  -- A notification still to be sent: due at `notify_at`, after `notify_attempts` failed sends. Set
  -- by the statement that stores the movement, so a run that stops halfway loses no notification
  -- and a movement stored twice is notified once.
  notify_at INTEGER,
  notify_attempts INTEGER NOT NULL DEFAULT 0,
  PRIMARY KEY (network, transaction_hash, log_index)
) STRICT;

CREATE INDEX transfers_from ON transfers (from_address, timestamp);
CREATE INDEX transfers_to ON transfers (to_address, timestamp);
CREATE INDEX transfers_notify ON transfers (notify_at) WHERE notify_at IS NOT NULL;

-- Where each reader stopped: blocks per network, ledgers on Stellar, and resumable windows.
CREATE TABLE index_cursors (
  network TEXT PRIMARY KEY,
  block INTEGER NOT NULL
) STRICT;

-- Devices that receive a member's notifications (Firebase Cloud Messaging tokens).
CREATE TABLE push_tokens (
  token TEXT PRIMARY KEY,
  member_id TEXT NOT NULL REFERENCES members (id),
  language TEXT NOT NULL,
  created_at INTEGER NOT NULL
) STRICT;

CREATE INDEX push_tokens_member ON push_tokens (member_id);

-- People a member saved to pay in one tap.
CREATE TABLE contacts (
  member_id TEXT NOT NULL REFERENCES members (id),
  contact_id TEXT NOT NULL REFERENCES members (id),
  created_at INTEGER NOT NULL,
  PRIMARY KEY (member_id, contact_id)
) STRICT;

-- Early-access survey for a future GatoPago Card (the waitlist). Not an application for a card.
CREATE TABLE card_interest (
  member_id TEXT PRIMARY KEY REFERENCES members (id),
  country TEXT NOT NULL,
  use_case TEXT NOT NULL,
  monthly_spend TEXT NOT NULL,
  card_preference TEXT NOT NULL,
  wallet_pay TEXT NOT NULL,
  updated_at INTEGER NOT NULL
) STRICT;

-- Groups a member saved in "Group payment": who is in each (JSON, as the app's form keeps them).
CREATE TABLE member_groups (
  member_id TEXT NOT NULL REFERENCES members (id),
  name TEXT NOT NULL COLLATE NOCASE,
  members TEXT NOT NULL,
  PRIMARY KEY (member_id, name)
) STRICT;

-- Sign-ins to GatoPago Business approved from the app: the console shows `id` as a QR, a signed-in
-- member approves it with their passkey, and only the console, holding the secret, collects the
-- session. Each request lasts a couple of minutes and is collected once.
CREATE TABLE business_logins (
  id TEXT PRIMARY KEY,
  secret_hash TEXT NOT NULL,
  -- What the member sees before approving: the console's browser and approximate place.
  device TEXT NOT NULL,
  place TEXT,
  expires_at INTEGER NOT NULL,
  member_id TEXT REFERENCES members (id),
  address TEXT,
  collected INTEGER NOT NULL DEFAULT 0
) STRICT;

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

-- Stellar calls Wallet Core sent for members, by the nonce of their signed authorization. The app
-- asks after an answer it lost (closed tab, timeout): the network forgets a nonce once its signature
-- expires, this does not, so a sent payment is never paid again.
CREATE TABLE stellar_submissions (
  member_address TEXT NOT NULL REFERENCES members (address),
  nonce TEXT NOT NULL,
  transaction_hash TEXT NOT NULL,
  created_at INTEGER NOT NULL,
  PRIMARY KEY (member_address, nonce)
) STRICT;

CREATE INDEX stellar_submissions_created ON stellar_submissions (created_at);

-- Ed25519 keys that also sign for members' Stellar accounts: the keys Mera derives from a passkey.
-- An owner key of the EVM account approves each one (`stellarKeyApproval`, valid until
-- `expires_at`), kept here so the app verifies it too; it counts only while that owner still owns
-- the account. Losing a row means approving the key again.
CREATE TABLE stellar_keys (
  member_address TEXT NOT NULL REFERENCES members (address),
  public_key TEXT NOT NULL,
  owner TEXT NOT NULL,
  signature TEXT NOT NULL,
  expires_at INTEGER NOT NULL,
  created_at INTEGER NOT NULL,
  PRIMARY KEY (member_address, public_key)
) STRICT;
