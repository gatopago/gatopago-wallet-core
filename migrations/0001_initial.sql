-- Initial Wallet Core V3 schema. Fresh databases only.
-- Index creation order preserves the established SQLite query plans.
PRAGMA foreign_keys = ON;

CREATE TABLE auth_limits (
  scope TEXT NOT NULL CHECK (scope IN ('ip', 'global')),
  key_hash TEXT NOT NULL,
  count INTEGER NOT NULL CHECK (count > 0),
  reset_at INTEGER NOT NULL,
  PRIMARY KEY (scope, key_hash)
) STRICT;

CREATE TABLE users (
  id TEXT PRIMARY KEY CHECK (length(id) = 40 AND id GLOB 'usr_*'),
  environment TEXT NOT NULL CHECK (environment IN ('staging','production')),
  display_name TEXT NOT NULL DEFAULT '' CHECK (length(display_name) <= 80),
  username TEXT UNIQUE CHECK (username IS NULL OR (
    length(username) BETWEEN 5 AND 30 AND substr(username,1,1) GLOB '[a-z]'
    AND username NOT GLOB '*[^a-z0-9_]*')),
  username_reserved_until INTEGER,
  username_published_at INTEGER,
  receiving_wallet_id TEXT REFERENCES wallets(id) ON DELETE RESTRICT,
  auth_not_before INTEGER NOT NULL DEFAULT 0 CHECK (auth_not_before >= 0),
  access_snapshot_json TEXT CHECK (access_snapshot_json IS NULL OR
    (length(access_snapshot_json) <= 65536 AND json_valid(access_snapshot_json))),
  disabled_at INTEGER,
  created_at INTEGER NOT NULL CHECK (created_at > 0),
  CHECK ((username IS NULL AND username_reserved_until IS NULL AND username_published_at IS NULL)
    OR (username IS NOT NULL AND username_reserved_until IS NOT NULL AND username_reserved_until > 0 AND username_published_at IS NULL)
    OR (username IS NOT NULL AND username_reserved_until IS NULL AND username_published_at IS NOT NULL AND username_published_at > 0)),
  CHECK (username_published_at IS NULL OR receiving_wallet_id IS NOT NULL)
) STRICT;

CREATE TABLE wallets (
  id TEXT PRIMARY KEY CHECK (length(id) = 40 AND id GLOB 'wal_*'),
  user_id TEXT NOT NULL REFERENCES users(id) ON DELETE RESTRICT,
  status TEXT NOT NULL CHECK (status IN ('active', 'archived')),
  account_id TEXT NOT NULL UNIQUE CHECK (length(account_id) = 66 AND substr(account_id,1,2) = '0x' AND substr(account_id,3) NOT GLOB '*[^0-9a-f]*'),
  initial_security_commitment TEXT NOT NULL CHECK (length(initial_security_commitment) = 66 AND substr(initial_security_commitment,1,2) = '0x' AND substr(initial_security_commitment,3) NOT GLOB '*[^0-9a-f]*'),
  user_salt_commitment TEXT NOT NULL CHECK (length(user_salt_commitment) = 66 AND substr(user_salt_commitment,1,2) = '0x' AND substr(user_salt_commitment,3) NOT GLOB '*[^0-9a-f]*'),
  canonical_address TEXT NOT NULL CHECK (length(canonical_address) = 42 AND substr(canonical_address,1,2) = '0x' AND substr(canonical_address,3) NOT GLOB '*[^0-9a-f]*'),
  created_at INTEGER NOT NULL CHECK (created_at > 0),
  UNIQUE(id, canonical_address)
) STRICT;

CREATE TABLE wallet_accounts (
  id TEXT PRIMARY KEY CHECK (length(id) = 40 AND id GLOB 'wac_*'),
  wallet_id TEXT NOT NULL REFERENCES wallets(id) ON DELETE RESTRICT,
  network_id TEXT NOT NULL CHECK (network_id GLOB 'eip155:[1-9]*' AND substr(network_id,8) NOT GLOB '*[^0-9]*'),
  address TEXT NOT NULL,
  deployment_manifest_sha256 TEXT NOT NULL CHECK (length(deployment_manifest_sha256) = 66 AND substr(deployment_manifest_sha256,1,2) = '0x' AND substr(deployment_manifest_sha256,3) NOT GLOB '*[^0-9a-f]*'),
  deployment_state TEXT NOT NULL CHECK (deployment_state IN ('counterfactual', 'deploying', 'active', 'needs_security_sync', 'unsupported', 'retired')),
  created_at INTEGER NOT NULL CHECK (created_at > 0),
  UNIQUE(wallet_id, network_id),
  UNIQUE(network_id, address),
  FOREIGN KEY(wallet_id, address) REFERENCES wallets(id, canonical_address) ON DELETE RESTRICT
) STRICT;

CREATE TABLE webauthn_enrollments (
  id TEXT PRIMARY KEY CHECK (length(id) = 39 AND id GLOB 'op_*'),
  user_id TEXT NOT NULL REFERENCES users(id) ON DELETE RESTRICT,
  rp_id TEXT NOT NULL,
  origin TEXT NOT NULL,
  challenge TEXT NOT NULL UNIQUE,
  proof_challenge TEXT NOT NULL UNIQUE,
  created_at INTEGER NOT NULL,
  expires_at INTEGER NOT NULL CHECK (expires_at = created_at + 300),
  completed_at INTEGER,
  response_hash TEXT,
  CHECK ((completed_at IS NULL AND response_hash IS NULL) OR
    (completed_at >= created_at AND completed_at < expires_at AND length(response_hash) = 66))
) STRICT;

CREATE TABLE webauthn_credentials (
  id TEXT PRIMARY KEY CHECK (length(id) = 39 AND id GLOB 'op_*'),
  user_id TEXT NOT NULL REFERENCES users(id) ON DELETE RESTRICT,
  rp_id TEXT NOT NULL,
  origin TEXT NOT NULL,
  credential_id TEXT NOT NULL CHECK (length(credential_id) BETWEEN 1 AND 1366),
  public_key TEXT NOT NULL CHECK (length(public_key) = 258 AND substr(public_key,1,2) = '0x' AND substr(public_key,3) NOT GLOB '*[^0-9a-f]*'),
  transports_json TEXT NOT NULL CHECK (json_valid(transports_json)),
  aaguid TEXT NOT NULL,
  backup_eligible INTEGER NOT NULL CHECK (backup_eligible IN (0,1)),
  backed_up INTEGER NOT NULL CHECK (backed_up IN (0,1) AND backed_up <= backup_eligible),
  sign_count INTEGER NOT NULL CHECK (sign_count BETWEEN 0 AND 4294967295),
  response_hash TEXT NOT NULL CHECK (length(response_hash) = 66),
  created_at INTEGER NOT NULL,
  login_enabled INTEGER NOT NULL DEFAULT 0 CHECK (login_enabled IN (0,1)),
  access_version INTEGER NOT NULL DEFAULT 1 CHECK (access_version > 0),
  revoked_at INTEGER,
  UNIQUE(rp_id, credential_id),
  UNIQUE(rp_id, public_key)
) STRICT;

CREATE TABLE signup_invites (
  token_hash TEXT PRIMARY KEY CHECK (length(token_hash) = 66 AND substr(token_hash,1,2) = '0x'
    AND substr(token_hash,3) NOT GLOB '*[^0-9a-f]*'),
  issued_by TEXT NOT NULL CHECK (length(issued_by) BETWEEN 1 AND 128),
  created_at INTEGER NOT NULL CHECK (created_at > 0),
  expires_at INTEGER NOT NULL CHECK (expires_at > created_at),
  revoked_at INTEGER,
  consumed_by TEXT UNIQUE REFERENCES users(id) ON DELETE RESTRICT,
  consumed_at INTEGER,
  CHECK ((consumed_by IS NULL AND consumed_at IS NULL) OR
    (consumed_by IS NOT NULL AND consumed_at >= created_at AND consumed_at < expires_at))
) STRICT;

CREATE TABLE auth_challenges (
  id TEXT PRIMARY KEY CHECK (length(id) = 39 AND id GLOB 'op_*'),
  purpose TEXT NOT NULL CHECK (purpose IN ('register','login')),
  challenge TEXT NOT NULL UNIQUE CHECK (length(challenge) = 66),
  proof_challenge TEXT UNIQUE,
  rp_id TEXT NOT NULL,
  origin TEXT NOT NULL,
  proposed_user_id TEXT UNIQUE,
  invite_hash TEXT REFERENCES signup_invites(token_hash) ON DELETE RESTRICT,
  display_name TEXT,
  username TEXT,
  created_at INTEGER NOT NULL CHECK (created_at > 0),
  expires_at INTEGER NOT NULL CHECK (expires_at = created_at + 300),
  consumed_at INTEGER CHECK (consumed_at IS NULL OR (consumed_at >= created_at AND consumed_at < expires_at)),
  CHECK ((purpose = 'login' AND proof_challenge IS NULL AND proposed_user_id IS NULL
    AND invite_hash IS NULL AND display_name IS NULL AND username IS NULL)
    OR (purpose = 'register' AND proof_challenge IS NOT NULL AND proposed_user_id IS NOT NULL
      AND display_name IS NOT NULL AND username IS NOT NULL AND length(proof_challenge) = 66 AND length(proposed_user_id) = 40
      AND invite_hash IS NOT NULL AND length(display_name) BETWEEN 1 AND 80
      AND length(username) BETWEEN 5 AND 30))
) STRICT;

CREATE INDEX auth_challenges_expiry ON auth_challenges(expires_at);
CREATE INDEX auth_challenges_invite ON auth_challenges(invite_hash) WHERE invite_hash IS NOT NULL;
CREATE INDEX signup_invites_expiry ON signup_invites(consumed_by, expires_at) WHERE consumed_by IS NULL;
CREATE INDEX users_username_reservation ON users(username_reserved_until) WHERE username_reserved_until IS NOT NULL;

CREATE TABLE account_initializations (
  id TEXT PRIMARY KEY CHECK (length(id) = 39 AND id GLOB 'op_*'),
  user_id TEXT NOT NULL REFERENCES users(id) ON DELETE RESTRICT,
  credential_ref TEXT NOT NULL REFERENCES webauthn_credentials(id) ON DELETE RESTRICT,
  profile_sha256 TEXT NOT NULL CHECK (length(profile_sha256) = 66),
  user_salt_commitment TEXT NOT NULL CHECK (length(user_salt_commitment) = 66),
  public_key TEXT NOT NULL CHECK (length(public_key) = 258),
  approval_digest TEXT NOT NULL CHECK (length(approval_digest) = 66),
  expected_address TEXT NOT NULL CHECK (length(expected_address) = 42),
  created_at INTEGER NOT NULL CHECK (created_at > 0),
  expires_at INTEGER NOT NULL CHECK (expires_at = created_at + 300),
  authorized_at INTEGER,
  assertion_signature TEXT,
  assertion_body TEXT,
  CHECK ((authorized_at IS NULL AND assertion_signature IS NULL AND assertion_body IS NULL) OR
    (authorized_at IS NOT NULL AND authorized_at >= created_at AND authorized_at < expires_at AND assertion_signature IS NOT NULL
      AND length(assertion_signature) BETWEEN 2 AND 8194
      AND assertion_body IS NOT NULL AND length(assertion_body) <= 7000 AND json_valid(assertion_body)))
) STRICT;

CREATE TABLE account_creation_operations (
  initialization_id TEXT PRIMARY KEY REFERENCES account_initializations(id) ON DELETE RESTRICT,
  gas_terms_json TEXT NOT NULL CHECK (length(gas_terms_json) <= 1024 AND json_valid(gas_terms_json)),
  user_op_hash TEXT NOT NULL CHECK (length(user_op_hash) = 66),
  operation_digest TEXT NOT NULL CHECK (length(operation_digest) = 66),
  created_at INTEGER NOT NULL CHECK (created_at > 0),
  expires_at INTEGER NOT NULL CHECK (expires_at > created_at AND expires_at <= created_at + 300),
  authorized_at INTEGER,
  authorized_auth_time INTEGER,
  assertion_body TEXT,
  operation_signature TEXT,
  CHECK ((authorized_at IS NULL AND authorized_auth_time IS NULL AND assertion_body IS NULL AND operation_signature IS NULL) OR
    (authorized_at IS NOT NULL AND authorized_at >= created_at AND authorized_at < expires_at
      AND authorized_auth_time IS NOT NULL AND authorized_auth_time >= 0
      AND assertion_body IS NOT NULL AND length(assertion_body) <= 7000 AND json_valid(assertion_body)
      AND operation_signature IS NOT NULL AND length(operation_signature) BETWEEN 2 AND 16386))
) STRICT;

CREATE TABLE account_creation_outbox (
  initialization_id TEXT PRIMARY KEY REFERENCES account_creation_operations(initialization_id) ON DELETE RESTRICT,
  user_op_hash TEXT NOT NULL CHECK (length(user_op_hash) = 66),
  state TEXT NOT NULL CHECK (state IN ('pending','sending','uncertain','accepted','expired')),
  created_at INTEGER NOT NULL CHECK (created_at > 0),
  expires_at INTEGER NOT NULL CHECK (expires_at > created_at AND expires_at <= created_at + 300),
  lease_token TEXT,
  lease_expires_at INTEGER,
  attempt_count INTEGER NOT NULL DEFAULT 0 CHECK (attempt_count BETWEEN 0 AND 32),
  next_attempt_at INTEGER NOT NULL DEFAULT 0 CHECK (next_attempt_at >= 0),
  send_started_at INTEGER,
  accepted_at INTEGER,
  CHECK ((lease_token IS NULL AND lease_expires_at IS NULL) OR
    (lease_token IS NOT NULL AND length(lease_token) = 39 AND lease_expires_at IS NOT NULL
      AND lease_expires_at > created_at AND lease_expires_at <= expires_at AND state IN ('pending','sending'))),
  CHECK ((state IN ('sending','uncertain','accepted') AND send_started_at IS NOT NULL
    AND send_started_at >= created_at AND send_started_at < expires_at AND attempt_count >= 1) OR
    (state IN ('pending','expired') AND send_started_at IS NULL)),
  CHECK (state <> 'sending' OR lease_token IS NOT NULL),
  CHECK ((state = 'accepted' AND accepted_at IS NOT NULL AND accepted_at >= send_started_at) OR
    (state <> 'accepted' AND accepted_at IS NULL))
) STRICT;

CREATE TABLE account_creation_observation_jobs (
  initialization_id TEXT PRIMARY KEY REFERENCES account_creation_operations(initialization_id) ON DELETE RESTRICT,
  lease_epoch INTEGER NOT NULL DEFAULT 0 CHECK (lease_epoch >= 0),
  lease_token TEXT,
  lease_started_at INTEGER,
  lease_expires_at INTEGER,
  next_poll_at INTEGER NOT NULL DEFAULT 0 CHECK (next_poll_at >= 0),
  latest_epoch INTEGER NOT NULL DEFAULT 0 CHECK (latest_epoch >= 0 AND latest_epoch <= lease_epoch),
  CHECK ((lease_token IS NULL AND lease_started_at IS NULL AND lease_expires_at IS NULL) OR
    (lease_token IS NOT NULL AND length(lease_token) = 39 AND lease_started_at IS NOT NULL
      AND lease_started_at > 0 AND lease_expires_at = lease_started_at + 60))
) STRICT;

CREATE TABLE account_creation_observations (
  initialization_id TEXT NOT NULL REFERENCES account_creation_observation_jobs(initialization_id) ON DELETE RESTRICT,
  lease_epoch INTEGER NOT NULL CHECK (lease_epoch > 0),
  lease_token TEXT NOT NULL UNIQUE CHECK (length(lease_token) = 39),
  started_at INTEGER NOT NULL CHECK (started_at > 0),
  observed_at INTEGER NOT NULL CHECK (observed_at >= started_at AND observed_at < started_at + 60),
  user_op_hash TEXT NOT NULL CHECK (length(user_op_hash) = 66),
  status TEXT NOT NULL CHECK (status IN ('observed','not_observed','unavailable','disagreement')),
  transaction_hash TEXT CHECK (transaction_hash IS NULL OR length(transaction_hash) = 66),
  result_json TEXT NOT NULL CHECK (length(result_json) <= 8192 AND json_valid(result_json)),
  result_sha256 TEXT NOT NULL CHECK (length(result_sha256) = 66),
  CHECK (json_extract(result_json, '$.status') IS status),
  CHECK (json_extract(result_json, '$.transaction_hash') IS transaction_hash),
  CHECK (json_extract(result_json, '$.finality') IS NOT NULL AND json_extract(result_json, '$.finality') IN ('not_assessed','finalized','pending','stale','disagreement','reorg_detected','unavailable')),
  CHECK (json_extract(result_json, '$.finality') IS 'not_assessed' OR
    (status = 'observed' AND json_extract(result_json, '$.finality_evidence.status') IS json_extract(result_json, '$.finality'))),
  CHECK (json_extract(result_json, '$.account_readiness') IS 'not_assessed'),
  CHECK (status <> 'observed' OR (transaction_hash IS NOT NULL
    AND json_extract(result_json, '$.observation.user_op_hash') IS user_op_hash)),
  PRIMARY KEY (initialization_id, lease_epoch)
) STRICT;

CREATE TABLE account_creation_projections (
  initialization_id TEXT PRIMARY KEY REFERENCES account_initializations(id) ON DELETE RESTRICT,
  source_epoch INTEGER NOT NULL,
  source_sha256 TEXT NOT NULL CHECK (length(source_sha256) = 66),
  wallet_id TEXT NOT NULL REFERENCES wallets(id) ON DELETE RESTRICT,
  wallet_account_id TEXT NOT NULL UNIQUE REFERENCES wallet_accounts(id) ON DELETE RESTRICT,
  security_json TEXT NOT NULL CHECK (length(security_json) <= 16384 AND json_valid(security_json)),
  security_sha256 TEXT NOT NULL CHECK (length(security_sha256) = 66),
  projected_at INTEGER NOT NULL CHECK (projected_at > 0),
  evidence_expires_at INTEGER NOT NULL CHECK (evidence_expires_at > projected_at),
  -- Clean, undeployed V3 baseline: initial policy is active after verified creation.
  -- Existing development databases must be recreated explicitly; this is not an in-place upgrade.
  CHECK (json_extract(security_json, '$.security.phase') IS 'active_policy'),
  CHECK (json_extract(security_json, '$.finality') IS 'finalized'),
  CHECK (json_extract(security_json, '$.spend_readiness') IS 'not_assessed'),
  CHECK (json_extract(security_json, '$.security_version') IS '1'),
  CHECK (json_extract(security_json, '$.security_expires_at') IS evidence_expires_at),
  CHECK (projected_at >= json_extract(security_json, '$.security_observed_at')),
  FOREIGN KEY (initialization_id, source_epoch)
    REFERENCES account_creation_observations(initialization_id, lease_epoch) ON DELETE RESTRICT
) STRICT;

CREATE TABLE account_creation_jobs (
  initialization_id TEXT PRIMARY KEY REFERENCES account_creation_outbox(initialization_id) ON DELETE CASCADE,
  state TEXT NOT NULL DEFAULT 'ready' CHECK (state IN ('ready','queued','running','complete','review')),
  next_attempt_at INTEGER NOT NULL DEFAULT 0 CHECK (next_attempt_at >= 0),
  lease_token TEXT,
  lease_expires_at INTEGER,
  failures INTEGER NOT NULL DEFAULT 0 CHECK (failures BETWEEN 0 AND 8),
  reason TEXT CHECK (reason IN ('projected','expired','revoked','execution_reverted','observation_timeout','processing_error')),
  CHECK ((state IN ('queued','running') AND lease_token IS NOT NULL AND length(lease_token) = 39 AND lease_expires_at IS NOT NULL AND lease_expires_at > 0)
    OR (state NOT IN ('queued','running') AND lease_token IS NULL AND lease_expires_at IS NULL)),
  CHECK ((state IN ('complete','review') AND reason IS NOT NULL) OR (state NOT IN ('complete','review') AND reason IS NULL))
) STRICT;

CREATE TABLE account_backups (
  id TEXT PRIMARY KEY CHECK (length(id) = 39 AND id GLOB 'op_*'),
  user_id TEXT NOT NULL REFERENCES users(id) ON DELETE RESTRICT,
  initialization_id TEXT NOT NULL REFERENCES account_initializations(id) ON DELETE RESTRICT,
  wallet_id TEXT NOT NULL REFERENCES wallets(id) ON DELETE RESTRICT,
  wallet_account_id TEXT NOT NULL REFERENCES wallet_accounts(id) ON DELETE RESTRICT,
  policy_json TEXT NOT NULL CHECK (length(policy_json) <= 12288 AND json_valid(policy_json)),
  snapshot_json TEXT NOT NULL CHECK (length(snapshot_json) <= 8192 AND json_valid(snapshot_json)),
  proposal_hash TEXT NOT NULL CHECK (length(proposal_hash) = 66),
  expected_manifest_hash TEXT NOT NULL CHECK (length(expected_manifest_hash) = 66),
  created_at INTEGER NOT NULL CHECK (created_at > 0),
  expires_at INTEGER NOT NULL CHECK (expires_at = created_at + 300),
  -- Independently signed completion deadline, never renewed by a read/retry.
  proposal_expires_at INTEGER NOT NULL CHECK (proposal_expires_at > expires_at AND proposal_expires_at - created_at <= 604800 AND proposal_expires_at < 281474976710656),
  authorized_at INTEGER,
  authorization_json TEXT CHECK (length(authorization_json) <= 120000 AND json_valid(authorization_json)),
  authorization_snapshot_json TEXT CHECK (length(authorization_snapshot_json) <= 8192 AND json_valid(authorization_snapshot_json)),
  calldata_sha256 TEXT CHECK (length(calldata_sha256) = 66), authorized_auth_time INTEGER CHECK (authorized_auth_time > 0),
  CHECK ((authorized_at IS NULL AND authorization_json IS NULL AND authorization_snapshot_json IS NULL AND calldata_sha256 IS NULL)
    OR (authorized_at IS NOT NULL AND authorized_at >= created_at AND authorized_at < expires_at
      AND authorization_json IS NOT NULL AND authorization_snapshot_json IS NOT NULL AND calldata_sha256 IS NOT NULL))
) STRICT;

CREATE TABLE account_backup_commits (
 id TEXT PRIMARY KEY CHECK (length(id) = 39 AND id GLOB 'op_*'),
 backup_id TEXT NOT NULL REFERENCES account_backups(id) ON DELETE RESTRICT,
 snapshot_json TEXT NOT NULL CHECK (length(snapshot_json) <= 12288 AND json_valid(snapshot_json)),
 commit_digest TEXT NOT NULL CHECK (length(commit_digest) = 66),
 valid_after INTEGER NOT NULL CHECK (valid_after > 0),
 valid_until INTEGER NOT NULL CHECK (valid_until > valid_after AND valid_until <= valid_after + 300),
 authorized_at INTEGER,
 assertion_body TEXT CHECK (length(assertion_body) <= 7000 AND json_valid(assertion_body)),
 confirmation_json TEXT CHECK (length(confirmation_json) <= 16384 AND json_valid(confirmation_json)),
 calldata_sha256 TEXT CHECK (length(calldata_sha256) = 66), authorized_auth_time INTEGER CHECK (authorized_auth_time > 0),
 CHECK ((authorized_at IS NULL AND assertion_body IS NULL AND confirmation_json IS NULL AND calldata_sha256 IS NULL)
  OR (authorized_at IS NOT NULL AND authorized_at >= valid_after AND authorized_at < valid_until
   AND assertion_body IS NOT NULL AND confirmation_json IS NOT NULL AND calldata_sha256 IS NOT NULL))
) STRICT;

CREATE TABLE account_backup_outbox (
 operation_id TEXT PRIMARY KEY CHECK (length(operation_id) = 39 AND operation_id GLOB 'op_*'),
 backup_id TEXT NOT NULL REFERENCES account_backups(id) ON DELETE RESTRICT,
 commit_id TEXT UNIQUE REFERENCES account_backup_commits(id) ON DELETE RESTRICT,
 kind TEXT NOT NULL CHECK (kind IN ('prepare','commit')),
 calldata_sha256 TEXT NOT NULL CHECK (length(calldata_sha256) = 66),
 authorized_auth_time INTEGER NOT NULL CHECK (authorized_auth_time > 0),
 created_at INTEGER NOT NULL CHECK (created_at >= authorized_auth_time),
 expires_at INTEGER NOT NULL CHECK (expires_at > created_at),
 state TEXT NOT NULL DEFAULT 'pending' CHECK (state IN ('pending','sending','uncertain','accepted','expired')),
 attempt_count INTEGER NOT NULL DEFAULT 0 CHECK (attempt_count BETWEEN 0 AND 32),
 next_attempt_at INTEGER NOT NULL CHECK (next_attempt_at >= created_at),
 lease_token TEXT,
 lease_expires_at INTEGER,
 send_started_at INTEGER,
 transaction_hash TEXT CHECK (transaction_hash IS NULL OR (length(transaction_hash) = 66 AND substr(transaction_hash,1,2) = '0x' AND substr(transaction_hash,3) NOT GLOB '*[^0-9a-f]*')),
 accepted_at INTEGER,
 CHECK ((kind = 'prepare' AND commit_id IS NULL AND operation_id = backup_id)
  OR (kind = 'commit' AND commit_id IS NOT NULL AND operation_id = commit_id)),
 CHECK ((lease_token IS NULL AND lease_expires_at IS NULL)
  OR (lease_token IS NOT NULL AND lease_expires_at IS NOT NULL AND length(lease_token) = 39 AND lease_token GLOB 'op_*' AND lease_expires_at > 0)),
 CHECK ((state IN ('pending','expired') AND send_started_at IS NULL AND transaction_hash IS NULL AND accepted_at IS NULL)
  OR (state = 'sending' AND send_started_at IS NOT NULL AND lease_token IS NOT NULL AND accepted_at IS NULL)
  OR (state = 'uncertain' AND send_started_at IS NOT NULL AND lease_token IS NULL AND accepted_at IS NULL)
  OR (state = 'accepted' AND send_started_at IS NOT NULL AND transaction_hash IS NOT NULL AND accepted_at IS NOT NULL AND lease_token IS NULL)),
 CHECK (state != 'expired' OR lease_token IS NULL)
) STRICT;

CREATE TABLE account_backup_transactions (
 operation_id TEXT PRIMARY KEY REFERENCES account_backup_outbox(operation_id) ON DELETE RESTRICT,
 network_id TEXT NOT NULL CHECK (network_id GLOB 'eip155:[1-9]*'),
 operator_address TEXT NOT NULL CHECK (length(operator_address) = 42 AND substr(operator_address,1,2) = '0x' AND substr(operator_address,3) NOT GLOB '*[^0-9a-f]*'),
 nonce INTEGER NOT NULL CHECK (nonce BETWEEN 0 AND 9007199254740991),
 unsigned_transaction TEXT NOT NULL CHECK (length(unsigned_transaction) BETWEEN 4 AND 100002 AND length(unsigned_transaction) % 2 = 0 AND substr(unsigned_transaction,1,4) = '0x02' AND substr(unsigned_transaction,3) NOT GLOB '*[^0-9a-f]*'),
 unsigned_hash TEXT NOT NULL CHECK (length(unsigned_hash) = 66 AND substr(unsigned_hash,1,2) = '0x' AND substr(unsigned_hash,3) NOT GLOB '*[^0-9a-f]*'),
 created_at INTEGER NOT NULL CHECK (created_at > 0),
 serialized_transaction TEXT,
 transaction_hash TEXT,
 UNIQUE(network_id,operator_address,nonce),
 CHECK ((serialized_transaction IS NULL AND transaction_hash IS NULL) OR
  (serialized_transaction IS NOT NULL AND transaction_hash IS NOT NULL
   AND length(serialized_transaction) BETWEEN 4 AND 100002 AND length(serialized_transaction) % 2 = 0
   AND substr(serialized_transaction,1,4) = '0x02' AND substr(serialized_transaction,3) NOT GLOB '*[^0-9a-f]*'
   AND length(transaction_hash) = 66 AND substr(transaction_hash,1,2) = '0x' AND substr(transaction_hash,3) NOT GLOB '*[^0-9a-f]*'))
) STRICT;

CREATE TABLE account_backup_observation_jobs (
 operation_id TEXT PRIMARY KEY REFERENCES account_backup_transactions(operation_id) ON DELETE RESTRICT,
 lease_epoch INTEGER NOT NULL DEFAULT 0 CHECK (lease_epoch >= 0),
 lease_token TEXT,
 lease_started_at INTEGER,
 lease_expires_at INTEGER,
 next_poll_at INTEGER NOT NULL DEFAULT 0 CHECK (next_poll_at >= 0),
 latest_epoch INTEGER NOT NULL DEFAULT 0 CHECK (latest_epoch >= 0 AND latest_epoch <= lease_epoch),
 CHECK ((lease_token IS NULL AND lease_started_at IS NULL AND lease_expires_at IS NULL) OR
  (lease_token IS NOT NULL AND length(lease_token) = 39 AND lease_started_at IS NOT NULL
   AND lease_started_at > 0 AND lease_expires_at = lease_started_at + 60))
) STRICT;

CREATE TABLE account_backup_observations (
 operation_id TEXT NOT NULL REFERENCES account_backup_observation_jobs(operation_id) ON DELETE RESTRICT,
 lease_epoch INTEGER NOT NULL CHECK (lease_epoch > 0),
 lease_token TEXT NOT NULL UNIQUE CHECK (length(lease_token) = 39),
 started_at INTEGER NOT NULL CHECK (started_at > 0),
 observed_at INTEGER NOT NULL CHECK (observed_at >= started_at AND observed_at < started_at + 60),
 transaction_hash TEXT NOT NULL CHECK (length(transaction_hash) = 66),
 status TEXT NOT NULL CHECK (status IN ('observed','not_observed','unavailable','disagreement')),
 result_json TEXT NOT NULL CHECK (length(result_json) <= 8192 AND json_valid(result_json)),
 result_sha256 TEXT NOT NULL CHECK (length(result_sha256) = 66),
 CHECK (json_extract(result_json, '$.status') IS status),
 CHECK (json_extract(result_json, '$.transaction_hash') IS transaction_hash),
 CHECK (json_extract(result_json, '$.account_readiness') IS 'not_assessed'),
 CHECK (json_extract(result_json, '$.finality') IS NOT NULL AND json_extract(result_json, '$.finality') IN
  ('not_assessed','finalized','pending','stale','disagreement','reorg_detected','unavailable')),
 CHECK ((status <> 'observed' AND json_extract(result_json, '$.finality') IS 'not_assessed') OR
  (status = 'observed' AND json_extract(result_json, '$.observation.transaction_hash') IS transaction_hash
   AND json_extract(result_json, '$.observation.operation_id') IS operation_id
   AND json_extract(result_json, '$.finality_evidence.status') IS json_extract(result_json, '$.finality'))),
 PRIMARY KEY (operation_id, lease_epoch)
) STRICT;

CREATE TABLE account_backup_jobs (
 operation_id TEXT PRIMARY KEY REFERENCES account_backup_outbox(operation_id) ON DELETE CASCADE,
 state TEXT NOT NULL DEFAULT 'ready' CHECK (state IN ('ready','queued','running','observed','expired','review')),
 next_attempt_at INTEGER NOT NULL CHECK (next_attempt_at >= 0),
 lease_token TEXT,
 lease_expires_at INTEGER,
 failures INTEGER NOT NULL DEFAULT 0 CHECK (failures BETWEEN 0 AND 8),
 reason TEXT CHECK (reason IS NULL OR reason IN ('proposal_finalized','commit_finalized','consent_expired',
  'revoked','execution_reverted','observation_timeout','reorg_detected','delivery_exhausted','processing_error')),
 CHECK ((state IN ('queued','running') AND lease_token IS NOT NULL AND length(lease_token) = 39
  AND lease_token GLOB 'op_*' AND lease_expires_at IS NOT NULL AND lease_expires_at > 0)
  OR (state NOT IN ('queued','running') AND lease_token IS NULL AND lease_expires_at IS NULL)),
 CHECK ((state IN ('ready','queued','running') AND reason IS NULL)
  OR (state = 'observed' AND reason IS NOT NULL AND reason IN ('proposal_finalized','commit_finalized'))
  OR (state = 'expired' AND reason IS NOT NULL AND reason = 'consent_expired')
  OR (state = 'review' AND reason IS NOT NULL AND reason IN ('revoked','execution_reverted','observation_timeout','reorg_detected','delivery_exhausted','processing_error')))
) STRICT;

CREATE TABLE account_backup_projections (
 operation_id TEXT PRIMARY KEY REFERENCES account_backup_outbox(operation_id) ON DELETE CASCADE,
 backup_id TEXT NOT NULL REFERENCES account_backups(id) ON DELETE RESTRICT,
 source_epoch INTEGER NOT NULL CHECK (source_epoch > 0),
 source_sha256 TEXT NOT NULL CHECK (length(source_sha256) = 66),
 transaction_hash TEXT NOT NULL CHECK (length(transaction_hash) = 66),
 profile_sha256 TEXT NOT NULL CHECK (length(profile_sha256) = 66),
 manifest_hash TEXT NOT NULL CHECK (length(manifest_hash) = 66),
 security_json TEXT NOT NULL CHECK (json_valid(security_json) AND length(security_json) <= 16384),
 security_sha256 TEXT NOT NULL CHECK (length(security_sha256) = 66),
 projected_at INTEGER NOT NULL CHECK (projected_at > 0),
 evidence_expires_at INTEGER NOT NULL CHECK (evidence_expires_at > projected_at)
) STRICT;

CREATE TABLE transfer_nonce_reservations (
 id TEXT PRIMARY KEY CHECK (length(id) = 39 AND id GLOB 'op_*'),
 wallet_id TEXT NOT NULL REFERENCES wallets(id) ON DELETE RESTRICT,
 wallet_account_id TEXT NOT NULL REFERENCES wallet_accounts(id) ON DELETE RESTRICT,
 network_id TEXT NOT NULL,
 account_address TEXT NOT NULL CHECK (length(account_address) = 42),
 entry_point TEXT NOT NULL CHECK (length(entry_point) = 42),
 nonce TEXT NOT NULL CHECK (length(nonce) BETWEEN 1 AND 20 AND nonce NOT GLOB '*[^0-9]*' AND (nonce = '0' OR substr(nonce,1,1) != '0')),
 consent_digest TEXT NOT NULL CHECK (length(consent_digest) = 66),
 userop_hash TEXT NOT NULL CHECK (length(userop_hash) = 66),
 deployment_manifest_sha256 TEXT NOT NULL CHECK (length(deployment_manifest_sha256) = 66),
 operation_json TEXT NOT NULL CHECK (length(operation_json) BETWEEN 1 AND 180000),
 operation_sha256 TEXT NOT NULL CHECK (length(operation_sha256) = 66),
 review_json TEXT NOT NULL CHECK (length(review_json) BETWEEN 1 AND 150000),
 review_sha256 TEXT NOT NULL CHECK (length(review_sha256) = 66),
 funds_json TEXT NOT NULL CHECK (length(funds_json) BETWEEN 1 AND 2048),
 funds_sha256 TEXT NOT NULL CHECK (length(funds_sha256) = 66),
 authorized_auth_time INTEGER NOT NULL CHECK (authorized_auth_time >= 0),
 state TEXT NOT NULL CHECK (state IN ('held','expired','delivery_pending','reconciled')),
 delivery_token_sha256 TEXT CHECK (delivery_token_sha256 IS NULL OR length(delivery_token_sha256) = 66),
 delivery_started_at INTEGER,
 delivery_expires_at INTEGER,
 delivery_dispatched_at INTEGER,
 created_at INTEGER NOT NULL CHECK (created_at > 0),
 expires_at INTEGER NOT NULL CHECK (expires_at > created_at),
 UNIQUE(wallet_account_id,consent_digest),
 CHECK ((state IN ('delivery_pending','reconciled') AND delivery_token_sha256 IS NOT NULL AND delivery_started_at IS NOT NULL AND delivery_started_at > 0
     AND delivery_expires_at IS NOT NULL AND delivery_expires_at > delivery_started_at AND delivery_expires_at <= expires_at
     AND (delivery_dispatched_at IS NULL OR (delivery_dispatched_at >= delivery_started_at AND delivery_dispatched_at < delivery_expires_at)))
   OR (state NOT IN ('delivery_pending','reconciled') AND delivery_token_sha256 IS NULL AND delivery_started_at IS NULL AND delivery_expires_at IS NULL AND delivery_dispatched_at IS NULL))
) STRICT;

CREATE TABLE transfer_finality_journal (
 operation_id TEXT PRIMARY KEY REFERENCES transfer_nonce_reservations(id) ON DELETE RESTRICT,
 receipt_json TEXT NOT NULL CHECK (length(receipt_json) BETWEEN 1 AND 8192),
 receipt_sha256 TEXT NOT NULL CHECK (length(receipt_sha256) = 66),
 evidence_json TEXT NOT NULL CHECK (length(evidence_json) BETWEEN 1 AND 16384),
 evidence_sha256 TEXT NOT NULL CHECK (length(evidence_sha256) = 66),
 recorded_at INTEGER NOT NULL CHECK (recorded_at > 0)
) STRICT;

CREATE TABLE transfer_finality_conflicts (
 operation_id TEXT PRIMARY KEY REFERENCES transfer_finality_journal(operation_id) ON DELETE RESTRICT,
 receipt_json TEXT NOT NULL CHECK (length(receipt_json) BETWEEN 1 AND 8192),
 receipt_sha256 TEXT NOT NULL CHECK (length(receipt_sha256) = 66),
 evidence_json TEXT NOT NULL CHECK (length(evidence_json) BETWEEN 1 AND 16384),
 evidence_sha256 TEXT NOT NULL CHECK (length(evidence_sha256) = 66),
 recorded_at INTEGER NOT NULL CHECK (recorded_at > 0)
) STRICT;

CREATE TABLE wallet_balance_floors (
 wallet_account_id TEXT PRIMARY KEY REFERENCES wallet_accounts(id) ON DELETE RESTRICT,
 block_number TEXT NOT NULL CHECK (length(block_number) BETWEEN 1 AND 78
   AND block_number NOT GLOB '*[^0-9]*' AND (block_number = '0' OR substr(block_number,1,1) != '0')),
 block_hash TEXT NOT NULL CHECK (length(block_hash) = 66),
 recorded_at INTEGER NOT NULL CHECK (recorded_at > 0)
) STRICT;

CREATE TABLE transfer_reconciliations (
 operation_id TEXT PRIMARY KEY REFERENCES transfer_finality_journal(operation_id) ON DELETE RESTRICT,
 wallet_account_id TEXT NOT NULL REFERENCES wallet_accounts(id) ON DELETE RESTRICT,
 receipt_sha256 TEXT NOT NULL CHECK (length(receipt_sha256) = 66),
 block_number TEXT NOT NULL CHECK (length(block_number) BETWEEN 1 AND 78 AND block_number NOT GLOB '*[^0-9]*'
   AND (block_number = '0' OR substr(block_number,1,1) != '0')),
 block_hash TEXT NOT NULL CHECK (length(block_hash) = 66),
 proof_json TEXT NOT NULL CHECK (length(proof_json) BETWEEN 1 AND 32768),
 proof_sha256 TEXT NOT NULL CHECK (length(proof_sha256) = 66),
 recorded_at INTEGER NOT NULL CHECK (recorded_at > 0)
) STRICT;

CREATE TABLE transfer_jobs (
 operation_id TEXT PRIMARY KEY REFERENCES transfer_nonce_reservations(id) ON DELETE CASCADE,
 state TEXT NOT NULL CHECK (state IN ('ready','queued','running','reconciled','review')),
 next_attempt_at INTEGER NOT NULL CHECK (next_attempt_at >= 0),
 lease_token TEXT,
 lease_expires_at INTEGER,
 failures INTEGER NOT NULL DEFAULT 0 CHECK (failures BETWEEN 0 AND 8),
 reason TEXT CHECK (reason IS NULL OR reason IN ('processing_error','observation_timeout','conflicting_evidence')),
 CHECK ((state IN ('queued','running') AND lease_token IS NOT NULL AND length(lease_token) = 39
   AND lease_token GLOB 'op_*' AND lease_expires_at IS NOT NULL AND lease_expires_at > 0)
   OR (state NOT IN ('queued','running') AND lease_token IS NULL AND lease_expires_at IS NULL)),
 CHECK ((state = 'review' AND reason IS NOT NULL) OR (state != 'review' AND reason IS NULL))
) STRICT;

CREATE TABLE transfer_preparations (
 id TEXT PRIMARY KEY CHECK (length(id) = 39 AND id GLOB 'op_*'),
 wallet_id TEXT NOT NULL REFERENCES wallets(id) ON DELETE CASCADE,
 wallet_account_id TEXT NOT NULL REFERENCES wallet_accounts(id) ON DELETE CASCADE,
 consent_digest TEXT NOT NULL CHECK (length(consent_digest) = 66),
 deployment_manifest_sha256 TEXT NOT NULL CHECK (length(deployment_manifest_sha256) = 66),
 review_json TEXT NOT NULL CHECK (length(review_json) BETWEEN 1 AND 150000),
 review_sha256 TEXT NOT NULL CHECK (length(review_sha256) = 66),
 authorized_auth_time INTEGER NOT NULL CHECK (authorized_auth_time >= 0),
 created_at INTEGER NOT NULL CHECK (created_at > 0),
 expires_at INTEGER NOT NULL CHECK (expires_at > created_at),
 UNIQUE(wallet_account_id, consent_digest)
) STRICT;

CREATE INDEX auth_limits_expiry ON auth_limits(reset_at);

CREATE INDEX wallets_owner ON wallets(user_id, id);

CREATE INDEX webauthn_enrollments_owner_time ON webauthn_enrollments(user_id, created_at);
CREATE INDEX webauthn_enrollments_retention ON webauthn_enrollments(created_at);

CREATE INDEX webauthn_credentials_owner ON webauthn_credentials(user_id, rp_id, id);

CREATE INDEX account_initializations_owner_created ON account_initializations(user_id, created_at);

CREATE INDEX account_creation_outbox_pending ON account_creation_outbox(state, next_attempt_at, initialization_id);

CREATE INDEX account_creation_observation_due ON account_creation_observation_jobs(next_poll_at, initialization_id);

CREATE INDEX account_creation_finalized_history ON account_creation_observations
  (initialization_id, json_extract(result_json, '$.finality'), lease_epoch DESC);

CREATE INDEX account_creation_jobs_due ON account_creation_jobs(next_attempt_at, initialization_id)
  WHERE state IN ('ready','queued','running');

CREATE INDEX account_backups_owner_time ON account_backups(user_id, created_at, id);

CREATE INDEX account_backup_commits_parent ON account_backup_commits(backup_id, valid_after, id);

CREATE INDEX account_backup_outbox_due ON account_backup_outbox(state,next_attempt_at,operation_id);

CREATE INDEX account_backup_observation_due ON account_backup_observation_jobs(next_poll_at, operation_id);

CREATE INDEX account_backup_finalized_history ON account_backup_observations
 (operation_id, json_extract(result_json, '$.finality'), lease_epoch DESC);

CREATE INDEX account_backup_jobs_due ON account_backup_jobs(state,next_attempt_at,operation_id);

CREATE UNIQUE INDEX transfer_nonce_exclusive ON transfer_nonce_reservations(network_id,account_address,entry_point,nonce) WHERE state IN ('held','delivery_pending');

CREATE INDEX transfer_nonce_expiry ON transfer_nonce_reservations(state,expires_at);

CREATE INDEX transfer_jobs_due ON transfer_jobs(state,next_attempt_at,operation_id);

CREATE INDEX transfer_preparation_expiry ON transfer_preparations(wallet_account_id, expires_at);

CREATE TRIGGER account_creation_observations_no_update
BEFORE UPDATE ON account_creation_observations BEGIN
  SELECT RAISE(ABORT, 'Creation observations are append-only');
END;

CREATE TRIGGER account_creation_projections_no_update BEFORE UPDATE ON account_creation_projections BEGIN
  SELECT RAISE(ABORT, 'Creation projections are historical records');
END;

CREATE TRIGGER account_backups_immutable BEFORE UPDATE ON account_backups
WHEN NEW.id IS NOT OLD.id OR NEW.user_id IS NOT OLD.user_id
  OR NEW.initialization_id IS NOT OLD.initialization_id OR NEW.wallet_id IS NOT OLD.wallet_id
  OR NEW.wallet_account_id IS NOT OLD.wallet_account_id OR NEW.policy_json IS NOT OLD.policy_json
  OR NEW.snapshot_json IS NOT OLD.snapshot_json OR NEW.proposal_hash IS NOT OLD.proposal_hash
  OR NEW.expected_manifest_hash IS NOT OLD.expected_manifest_hash OR NEW.created_at IS NOT OLD.created_at
  OR NEW.expires_at IS NOT OLD.expires_at OR NEW.proposal_expires_at IS NOT OLD.proposal_expires_at OR OLD.authorized_at IS NOT NULL
BEGIN SELECT RAISE(ABORT, 'Backup consent is immutable'); END;

CREATE TRIGGER account_backup_commits_immutable BEFORE UPDATE ON account_backup_commits
WHEN NEW.id IS NOT OLD.id OR NEW.backup_id IS NOT OLD.backup_id OR NEW.snapshot_json IS NOT OLD.snapshot_json
 OR NEW.commit_digest IS NOT OLD.commit_digest OR NEW.valid_after IS NOT OLD.valid_after OR NEW.valid_until IS NOT OLD.valid_until
 OR OLD.authorized_at IS NOT NULL
BEGIN SELECT RAISE(ABORT, 'Backup confirmation is immutable'); END;

CREATE TRIGGER account_backup_outbox_identity BEFORE UPDATE ON account_backup_outbox
WHEN NEW.operation_id IS NOT OLD.operation_id OR NEW.backup_id IS NOT OLD.backup_id OR NEW.commit_id IS NOT OLD.commit_id
 OR NEW.kind IS NOT OLD.kind OR NEW.calldata_sha256 IS NOT OLD.calldata_sha256 OR NEW.authorized_auth_time IS NOT OLD.authorized_auth_time
 OR NEW.created_at IS NOT OLD.created_at OR NEW.expires_at IS NOT OLD.expires_at
 OR NEW.attempt_count < OLD.attempt_count
 OR (OLD.send_started_at IS NOT NULL AND NEW.send_started_at IS NOT OLD.send_started_at)
 OR (OLD.transaction_hash IS NOT NULL AND NEW.transaction_hash IS NOT OLD.transaction_hash)
 OR (OLD.accepted_at IS NOT NULL AND NEW.accepted_at IS NOT OLD.accepted_at)
 OR (OLD.state = 'pending' AND NEW.state NOT IN ('pending','sending','expired'))
 OR (OLD.state IN ('uncertain','accepted','expired') AND NEW.state IS NOT OLD.state)
 OR (OLD.state = 'sending' AND NEW.state NOT IN ('sending','uncertain','accepted'))
BEGIN SELECT RAISE(ABORT, 'Backup delivery identity/transition is immutable'); END;

CREATE TRIGGER account_backup_enqueue AFTER UPDATE ON account_backups
WHEN OLD.authorized_at IS NULL AND NEW.authorized_at IS NOT NULL
BEGIN
 INSERT INTO account_backup_outbox(operation_id,backup_id,kind,calldata_sha256,authorized_auth_time,created_at,expires_at,next_attempt_at)
 VALUES (NEW.id,NEW.id,'prepare',NEW.calldata_sha256,NEW.authorized_auth_time,NEW.authorized_at,NEW.expires_at,NEW.authorized_at);
END;

CREATE TRIGGER account_backup_commit_enqueue AFTER UPDATE ON account_backup_commits
WHEN OLD.authorized_at IS NULL AND NEW.authorized_at IS NOT NULL
BEGIN
 INSERT INTO account_backup_outbox(operation_id,backup_id,commit_id,kind,calldata_sha256,authorized_auth_time,created_at,expires_at,next_attempt_at)
 VALUES (NEW.id,NEW.backup_id,NEW.id,'commit',NEW.calldata_sha256,NEW.authorized_auth_time,NEW.authorized_at,NEW.valid_until,NEW.authorized_at);
END;

CREATE TRIGGER account_backup_transaction_immutable BEFORE UPDATE ON account_backup_transactions
WHEN NEW.operation_id IS NOT OLD.operation_id OR NEW.network_id IS NOT OLD.network_id
 OR NEW.operator_address IS NOT OLD.operator_address OR NEW.nonce IS NOT OLD.nonce
 OR NEW.unsigned_transaction IS NOT OLD.unsigned_transaction OR NEW.unsigned_hash IS NOT OLD.unsigned_hash
 OR NEW.created_at IS NOT OLD.created_at
 OR (OLD.serialized_transaction IS NOT NULL AND NEW.serialized_transaction IS NOT OLD.serialized_transaction)
 OR (OLD.transaction_hash IS NOT NULL AND NEW.transaction_hash IS NOT OLD.transaction_hash)
BEGIN SELECT RAISE(ABORT, 'Backup sponsor transaction is immutable'); END;

CREATE TRIGGER account_backup_send_requires_transaction BEFORE UPDATE ON account_backup_outbox
WHEN NEW.state IN ('sending','uncertain','accepted') AND (NEW.transaction_hash IS NULL OR NOT EXISTS (
 SELECT 1 FROM account_backup_transactions t WHERE t.operation_id = NEW.operation_id
 AND t.serialized_transaction IS NOT NULL AND t.transaction_hash = NEW.transaction_hash))
BEGIN SELECT RAISE(ABORT, 'Backup send requires its persisted transaction'); END;

CREATE TRIGGER account_backup_observations_no_update BEFORE UPDATE ON account_backup_observations BEGIN
 SELECT RAISE(ABORT, 'Backup observations are append-only');
END;

CREATE TRIGGER account_backup_job_enqueue AFTER INSERT ON account_backup_outbox
BEGIN
 INSERT INTO account_backup_jobs(operation_id,next_attempt_at) VALUES (NEW.operation_id,NEW.created_at);
END;

CREATE TRIGGER account_backup_projection_immutable BEFORE UPDATE ON account_backup_projections
BEGIN SELECT RAISE(ABORT, 'Backup projection is immutable'); END;

CREATE TRIGGER transfer_hold_terms_immutable BEFORE UPDATE OF funds_json,funds_sha256 ON transfer_nonce_reservations
WHEN NEW.funds_json != OLD.funds_json OR NEW.funds_sha256 != OLD.funds_sha256
BEGIN SELECT RAISE(ABORT, 'immutable transfer hold'); END;

CREATE TRIGGER transfer_finality_immutable BEFORE UPDATE ON transfer_finality_journal
BEGIN SELECT RAISE(ABORT, 'immutable transfer finality'); END;

CREATE TRIGGER transfer_conflict_immutable BEFORE UPDATE ON transfer_finality_conflicts
BEGIN SELECT RAISE(ABORT, 'immutable transfer conflict'); END;

CREATE TRIGGER wallet_balance_floor_monotonic BEFORE UPDATE ON wallet_balance_floors
WHEN NEW.wallet_account_id != OLD.wallet_account_id
  OR length(NEW.block_number) < length(OLD.block_number)
  OR (length(NEW.block_number) = length(OLD.block_number) AND NEW.block_number < OLD.block_number)
  OR (NEW.block_number = OLD.block_number AND NEW.block_hash != OLD.block_hash)
  OR NEW.recorded_at < OLD.recorded_at
BEGIN SELECT RAISE(ABORT, 'balance floor cannot regress'); END;

CREATE TRIGGER transfer_reconciliation_immutable BEFORE UPDATE ON transfer_reconciliations
BEGIN SELECT RAISE(ABORT, 'immutable transfer reconciliation'); END;

CREATE TRIGGER transfer_reconciled_requires_evidence BEFORE UPDATE OF state ON transfer_nonce_reservations
WHEN NEW.state = 'reconciled' AND (OLD.state != 'delivery_pending' OR NOT EXISTS
  (SELECT 1 FROM transfer_reconciliations e WHERE e.operation_id = NEW.id AND e.wallet_account_id = NEW.wallet_account_id))
BEGIN SELECT RAISE(ABORT, 'transfer reconciliation required'); END;

CREATE TRIGGER transfer_reconciled_terminal BEFORE UPDATE OF state ON transfer_nonce_reservations
WHEN OLD.state = 'reconciled' AND NEW.state != OLD.state
BEGIN SELECT RAISE(ABORT, 'terminal transfer reconciliation'); END;

CREATE TRIGGER transfer_reconciliation_commit AFTER INSERT ON transfer_reconciliations
BEGIN
 SELECT (CASE WHEN NOT EXISTS (SELECT 1 FROM transfer_nonce_reservations r
   JOIN transfer_finality_journal j ON j.operation_id = r.id
   WHERE r.id = NEW.operation_id AND r.wallet_account_id = NEW.wallet_account_id
     AND r.state = 'delivery_pending' AND j.receipt_sha256 = NEW.receipt_sha256
     AND NOT EXISTS (SELECT 1 FROM transfer_finality_conflicts c WHERE c.operation_id = r.id))
   THEN RAISE(ABORT, 'transfer reconciliation conflict') END);
 INSERT INTO wallet_balance_floors(wallet_account_id,block_number,block_hash,recorded_at)
 VALUES (NEW.wallet_account_id,NEW.block_number,NEW.block_hash,NEW.recorded_at)
 ON CONFLICT(wallet_account_id) DO UPDATE SET block_number = excluded.block_number,
   block_hash = excluded.block_hash, recorded_at = excluded.recorded_at;
 UPDATE transfer_nonce_reservations SET state = 'reconciled' WHERE id = NEW.operation_id AND state = 'delivery_pending';
END;

CREATE TRIGGER transfer_job_enqueue AFTER UPDATE OF state ON transfer_nonce_reservations
WHEN OLD.state = 'held' AND NEW.state = 'delivery_pending'
BEGIN
 INSERT INTO transfer_jobs(operation_id,state,next_attempt_at) VALUES (NEW.id,'ready',unixepoch());
END;

CREATE TRIGGER transfer_job_reconciled AFTER UPDATE OF state ON transfer_nonce_reservations
WHEN NEW.state = 'reconciled' AND OLD.state != NEW.state
BEGIN
 UPDATE transfer_jobs SET state = 'reconciled', lease_token = NULL, lease_expires_at = NULL, reason = NULL
 WHERE operation_id = NEW.id;
END;

CREATE TRIGGER transfer_preparation_immutable BEFORE UPDATE ON transfer_preparations
BEGIN SELECT RAISE(ABORT, 'immutable transfer preparation'); END;

-- Admission is charged at its maximum until finalized evidence proves actual cost.
-- Integer gwei is rounded up; canonical decimal wei remains the exact source.
CREATE TABLE sponsorship_reservations (
  digest TEXT PRIMARY KEY NOT NULL CHECK (length(digest) = 66 AND substr(digest,1,2) = '0x' AND substr(digest,3) NOT GLOB '*[^0-9a-f]*'),
  scope TEXT NOT NULL CHECK (instr(scope,':') BETWEEN 2 AND 79
    AND substr(scope,1,1) GLOB '[1-9]' AND substr(scope,1,instr(scope,':')-1) NOT GLOB '*[^0-9]*'
    AND length(substr(scope,instr(scope,':')+1)) = 42 AND substr(scope,instr(scope,':')+1,2) = '0x'
    AND substr(scope,instr(scope,':')+3) NOT GLOB '*[^0-9a-f]*'),
  user_id TEXT NOT NULL REFERENCES users(id) ON DELETE RESTRICT,
  day INTEGER NOT NULL CHECK (day >= 0),
  maximum_gwei INTEGER NOT NULL CHECK (maximum_gwei BETWEEN 1 AND 9007199254740991),
  charged_gwei INTEGER NOT NULL CHECK (charged_gwei BETWEEN 0 AND maximum_gwei),
  maximum_wei TEXT NOT NULL CHECK (length(maximum_wei) BETWEEN 1 AND 25
    AND substr(maximum_wei,1,1) GLOB '[1-9]' AND maximum_wei NOT GLOB '*[^0-9]*'
    AND (length(maximum_wei) < 25 OR maximum_wei <= '9007199254740991000000000')),
  userop_hash TEXT CHECK (userop_hash IS NULL OR (length(userop_hash) = 66 AND substr(userop_hash,1,2) = '0x' AND substr(userop_hash,3) NOT GLOB '*[^0-9a-f]*')),
  actual_wei TEXT CHECK (actual_wei IS NULL OR (actual_wei = '0' OR (
    length(actual_wei) BETWEEN 1 AND 25 AND substr(actual_wei,1,1) GLOB '[1-9]' AND actual_wei NOT GLOB '*[^0-9]*'))),
  transaction_hash TEXT CHECK (transaction_hash IS NULL OR (length(transaction_hash) = 66 AND substr(transaction_hash,1,2) = '0x' AND substr(transaction_hash,3) NOT GLOB '*[^0-9a-f]*')),
  valid_until INTEGER NOT NULL CHECK (valid_until BETWEEN 1 AND 9007199254740991
    AND day <= valid_until / 86400 AND valid_until - day * 86400 BETWEEN 1 AND 87000),
  CHECK (maximum_gwei = CASE WHEN length(maximum_wei) > 9 THEN CAST(substr(maximum_wei,1,length(maximum_wei)-9) AS INTEGER) ELSE 0 END
    + CASE WHEN CAST(substr(maximum_wei,-9) AS INTEGER) > 0 THEN 1 ELSE 0 END),
  CHECK ((actual_wei IS NULL AND transaction_hash IS NULL AND charged_gwei = maximum_gwei)
    OR (actual_wei IS NOT NULL AND transaction_hash IS NOT NULL AND userop_hash IS NOT NULL
      AND (length(actual_wei) < length(maximum_wei) OR (length(actual_wei) = length(maximum_wei) AND actual_wei <= maximum_wei))
      AND charged_gwei = CASE WHEN length(actual_wei) > 9 THEN CAST(substr(actual_wei,1,length(actual_wei)-9) AS INTEGER) ELSE 0 END
        + CASE WHEN CAST(substr(actual_wei,-9) AS INTEGER) > 0 THEN 1 ELSE 0 END))
) STRICT;
CREATE INDEX sponsorship_budget ON sponsorship_reservations(scope, day, user_id);
CREATE UNIQUE INDEX sponsorship_operation ON sponsorship_reservations(userop_hash) WHERE userop_hash IS NOT NULL;

-- Private transport journal: no user keys. Keep signed envelopes through unknown
-- outcomes; deleting a row could reuse a nonce or change the transport on retry.
CREATE TABLE user_operation_submissions (
 user_op_hash TEXT PRIMARY KEY CHECK (length(user_op_hash) = 66 AND substr(user_op_hash,1,2) = '0x' AND substr(user_op_hash,3) NOT GLOB '*[^0-9a-f]*'),
 payload_hash TEXT NOT NULL CHECK (length(payload_hash) = 66 AND substr(payload_hash,1,2) = '0x' AND substr(payload_hash,3) NOT GLOB '*[^0-9a-f]*'),
 kind TEXT NOT NULL CHECK (kind IN ('self','bundler')),
 endpoint TEXT NOT NULL CHECK (length(endpoint) BETWEEN 9 AND 4096 AND substr(endpoint,1,8) = 'https://'),
 network_id TEXT NOT NULL,
 operator TEXT,
 nonce INTEGER CHECK (nonce BETWEEN 0 AND 9007199254740991),
 raw_transaction TEXT,
 transaction_hash TEXT,
 valid_until INTEGER NOT NULL CHECK (valid_until > 0),
 UNIQUE(network_id,operator,nonce),
 CHECK ((kind = 'bundler' AND operator IS NULL AND nonce IS NULL AND raw_transaction IS NULL AND transaction_hash IS NULL)
  OR (kind = 'self' AND operator IS NOT NULL AND nonce IS NOT NULL AND raw_transaction IS NOT NULL AND transaction_hash IS NOT NULL
   AND length(operator) = 42 AND substr(operator,1,2) = '0x' AND substr(operator,3) NOT GLOB '*[^0-9a-f]*'
   AND length(raw_transaction) BETWEEN 4 AND 100002 AND length(raw_transaction) % 2 = 0
   AND substr(raw_transaction,1,4) = '0x02' AND substr(raw_transaction,3) NOT GLOB '*[^0-9a-f]*'
   AND length(transaction_hash) = 66 AND substr(transaction_hash,1,2) = '0x' AND substr(transaction_hash,3) NOT GLOB '*[^0-9a-f]*'))
) STRICT;
CREATE TRIGGER user_operation_submission_immutable BEFORE UPDATE ON user_operation_submissions
BEGIN SELECT RAISE(ABORT,'immutable operation submission'); END;
