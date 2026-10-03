-- Parenthesized CASE expressions avoid D1 remote compound-statement splitting.
-- https://github.com/cloudflare/workers-sdk/issues/4727
-- Additive money domain. Existing transfers and journals are preserved. Locks
-- coordinate this service only; they are never onchain spending permissions.
CREATE TABLE wallet_spend_locks (
  operation_id TEXT PRIMARY KEY CHECK (length(operation_id) = 39 AND operation_id GLOB 'op_*'),
  wallet_account_id TEXT NOT NULL REFERENCES wallet_accounts(id) ON DELETE CASCADE,
  network_id TEXT NOT NULL,
  account_address TEXT NOT NULL CHECK (length(account_address) = 42 AND account_address = lower(account_address)),
  entry_point TEXT NOT NULL CHECK (length(entry_point) = 42 AND entry_point = lower(entry_point)),
  nonce TEXT NOT NULL CHECK (length(nonce) BETWEEN 1 AND 20 AND nonce NOT GLOB '*[^0-9]*' AND (nonce = '0' OR substr(nonce,1,1) != '0')),
  consent_digest TEXT NOT NULL CHECK (length(consent_digest) = 66),
  domain TEXT NOT NULL CHECK (domain IN ('transfer','money')),
  state TEXT NOT NULL CHECK (state IN ('held','dispatch_pending','legacy_drain','released')),
  created_at INTEGER NOT NULL CHECK (created_at > 0),
  released_at INTEGER,
  release_reason TEXT CHECK (release_reason IS NULL OR release_reason IN ('expired_unsubmitted','reconciled','reverted_confirmed')),
  CHECK ((state = 'released' AND released_at IS NOT NULL AND released_at >= created_at AND release_reason IS NOT NULL)
    OR (state != 'released' AND released_at IS NULL AND release_reason IS NULL))
) STRICT;
CREATE UNIQUE INDEX wallet_spend_one_new_active ON wallet_spend_locks(network_id,account_address,entry_point)
  WHERE state IN ('held','dispatch_pending');
CREATE INDEX wallet_spend_active_account ON wallet_spend_locks(wallet_account_id,operation_id) WHERE released_at IS NULL;

-- Preserve every active legacy operation, including expired-but-still-held rows.
-- Multiple pre-migration holds enter a drain group; new admissions are blocked
-- until each existing hold finishes under its original rules. No row is canceled.
INSERT INTO wallet_spend_locks(operation_id,wallet_account_id,network_id,account_address,entry_point,nonce,consent_digest,domain,state,created_at)
SELECT r.id,r.wallet_account_id,r.network_id,r.account_address,r.entry_point,r.nonce,r.consent_digest,'transfer',
  (CASE WHEN (SELECT count(*) FROM transfer_nonce_reservations x WHERE x.wallet_account_id = r.wallet_account_id
    AND x.state IN ('held','delivery_pending')) > 1 THEN 'legacy_drain'
    WHEN r.state = 'delivery_pending' THEN 'dispatch_pending' ELSE 'held' END),r.created_at
FROM transfer_nonce_reservations r WHERE r.state IN ('held','delivery_pending');

CREATE TABLE money_preparations (
  id TEXT PRIMARY KEY CHECK (length(id) = 39 AND id GLOB 'op_*'),
  wallet_id TEXT NOT NULL REFERENCES wallets(id) ON DELETE CASCADE,
  wallet_account_id TEXT NOT NULL REFERENCES wallet_accounts(id) ON DELETE CASCADE,
  actor_id TEXT NOT NULL REFERENCES users(id) ON DELETE RESTRICT,
  idempotency_key TEXT NOT NULL CHECK (length(idempotency_key) BETWEEN 1 AND 128),
  request_sha256 TEXT NOT NULL CHECK (length(request_sha256) = 66),
  consent_digest TEXT NOT NULL CHECK (length(consent_digest) = 66),
  deployment_manifest_sha256 TEXT NOT NULL CHECK (length(deployment_manifest_sha256) = 66),
  market_sha256 TEXT NOT NULL CHECK (length(market_sha256) = 66),
  review_json TEXT NOT NULL CHECK (length(review_json) BETWEEN 1 AND 150000 AND json_valid(review_json)),
  review_sha256 TEXT NOT NULL CHECK (length(review_sha256) = 66),
  authorized_auth_time INTEGER NOT NULL CHECK (authorized_auth_time >= 0),
  created_at INTEGER NOT NULL CHECK (created_at > 0),
  expires_at INTEGER NOT NULL CHECK (expires_at > created_at),
  UNIQUE(actor_id,wallet_account_id,idempotency_key)
) STRICT;

CREATE TABLE money_operations (
  id TEXT PRIMARY KEY CHECK (length(id) = 39 AND id GLOB 'op_*'),
  preparation_id TEXT NOT NULL UNIQUE REFERENCES money_preparations(id) ON DELETE RESTRICT,
  wallet_id TEXT NOT NULL REFERENCES wallets(id) ON DELETE CASCADE,
  wallet_account_id TEXT NOT NULL REFERENCES wallet_accounts(id) ON DELETE CASCADE,
  actor_id TEXT NOT NULL REFERENCES users(id) ON DELETE RESTRICT,
  confirm_key TEXT NOT NULL CHECK (length(confirm_key) BETWEEN 1 AND 128),
  confirmation_sha256 TEXT NOT NULL CHECK (length(confirmation_sha256) = 66),
  network_id TEXT NOT NULL,
  account_address TEXT NOT NULL CHECK (length(account_address) = 42 AND account_address = lower(account_address)),
  entry_point TEXT NOT NULL CHECK (length(entry_point) = 42 AND entry_point = lower(entry_point)),
  nonce TEXT NOT NULL CHECK (length(nonce) BETWEEN 1 AND 20 AND nonce NOT GLOB '*[^0-9]*' AND (nonce = '0' OR substr(nonce,1,1) != '0')),
  consent_digest TEXT NOT NULL CHECK (length(consent_digest) = 66),
  userop_hash TEXT NOT NULL CHECK (length(userop_hash) = 66),
  deployment_manifest_sha256 TEXT NOT NULL CHECK (length(deployment_manifest_sha256) = 66),
  market_sha256 TEXT NOT NULL CHECK (length(market_sha256) = 66),
  review_json TEXT NOT NULL CHECK (length(review_json) BETWEEN 1 AND 150000 AND json_valid(review_json)),
  review_sha256 TEXT NOT NULL CHECK (length(review_sha256) = 66),
  funds_json TEXT NOT NULL CHECK (length(funds_json) BETWEEN 1 AND 2048 AND json_valid(funds_json)),
  funds_sha256 TEXT NOT NULL CHECK (length(funds_sha256) = 66),
  authorized_auth_time INTEGER NOT NULL CHECK (authorized_auth_time >= 0),
  state TEXT NOT NULL CHECK (state IN ('authorized','dispatch_pending','submitted','confirming','reconciled','reverted_confirmed','expired_unsubmitted','review_required')),
  dispatch_started_at INTEGER,
  created_at INTEGER NOT NULL CHECK (created_at > 0),
  expires_at INTEGER NOT NULL CHECK (expires_at > created_at),
  UNIQUE(actor_id,wallet_account_id,confirm_key),
  UNIQUE(wallet_account_id,consent_digest),
  UNIQUE(network_id,userop_hash),
  CHECK ((state IN ('authorized','expired_unsubmitted') AND dispatch_started_at IS NULL)
    OR (state IN ('dispatch_pending','submitted','confirming','reconciled','reverted_confirmed','review_required')
      AND dispatch_started_at IS NOT NULL AND dispatch_started_at >= created_at AND dispatch_started_at < expires_at))
) STRICT;
CREATE INDEX money_operations_account_state ON money_operations(wallet_account_id,state,id);
CREATE INDEX money_operations_unsubmitted_expiry ON money_operations(expires_at,id)
  WHERE state = 'authorized' AND dispatch_started_at IS NULL;

CREATE TABLE money_jobs (
  operation_id TEXT PRIMARY KEY REFERENCES money_operations(id) ON DELETE CASCADE,
  state TEXT NOT NULL CHECK (state IN ('ready','queued','running','reconciled','review')),
  next_attempt_at INTEGER NOT NULL CHECK (next_attempt_at >= 0),
  lease_token TEXT,
  lease_expires_at INTEGER,
  failures INTEGER NOT NULL DEFAULT 0 CHECK (failures BETWEEN 0 AND 8),
  reason TEXT CHECK (reason IS NULL OR reason IN ('processing_error','observation_timeout','conflicting_evidence')),
  CHECK ((state IN ('queued','running') AND lease_token IS NOT NULL AND length(lease_token) = 39 AND lease_expires_at > 0)
    OR (state NOT IN ('queued','running') AND lease_token IS NULL AND lease_expires_at IS NULL)),
  CHECK ((state = 'review' AND reason IS NOT NULL) OR (state != 'review' AND reason IS NULL))
) STRICT;
CREATE INDEX money_jobs_due ON money_jobs(next_attempt_at,operation_id)
  WHERE state IN ('ready','queued','running');
CREATE TABLE money_finality_journal (
  operation_id TEXT PRIMARY KEY REFERENCES money_operations(id) ON DELETE RESTRICT,
  receipt_json TEXT NOT NULL CHECK (length(receipt_json) BETWEEN 1 AND 16384 AND json_valid(receipt_json)),
  receipt_sha256 TEXT NOT NULL CHECK (length(receipt_sha256) = 66),
  finality_json TEXT NOT NULL CHECK (length(finality_json) BETWEEN 1 AND 16384 AND json_valid(finality_json)),
  finality_sha256 TEXT NOT NULL CHECK (length(finality_sha256) = 66),
  block_number TEXT NOT NULL CHECK (length(block_number) BETWEEN 1 AND 78 AND block_number NOT GLOB '*[^0-9]*' AND (block_number = '0' OR substr(block_number,1,1) != '0')),
  block_hash TEXT NOT NULL CHECK (length(block_hash) = 66),
  outcome TEXT NOT NULL CHECK (outcome IN ('reconciled','reverted_confirmed')),
  recorded_at INTEGER NOT NULL CHECK (recorded_at > 0)
) STRICT;
CREATE TABLE money_reconciliations (
  operation_id TEXT PRIMARY KEY REFERENCES money_finality_journal(operation_id) ON DELETE RESTRICT,
  wallet_account_id TEXT NOT NULL REFERENCES wallet_accounts(id) ON DELETE RESTRICT,
  receipt_sha256 TEXT NOT NULL CHECK (length(receipt_sha256) = 66),
  block_number TEXT NOT NULL CHECK (length(block_number) BETWEEN 1 AND 78 AND block_number NOT GLOB '*[^0-9]*' AND (block_number = '0' OR substr(block_number,1,1) != '0')),
  block_hash TEXT NOT NULL CHECK (length(block_hash) = 66),
  outcome TEXT NOT NULL CHECK (outcome IN ('reconciled','reverted_confirmed')),
  proof_json TEXT NOT NULL CHECK (length(proof_json) BETWEEN 1 AND 32768 AND json_valid(proof_json)),
  proof_sha256 TEXT NOT NULL CHECK (length(proof_sha256) = 66),
  recorded_at INTEGER NOT NULL CHECK (recorded_at > 0)
) STRICT;
CREATE TABLE money_finality_conflicts (
  operation_id TEXT PRIMARY KEY REFERENCES money_operations(id) ON DELETE RESTRICT,
  receipt_json TEXT NOT NULL CHECK (length(receipt_json) BETWEEN 1 AND 16384 AND json_valid(receipt_json)),
  receipt_sha256 TEXT NOT NULL CHECK (length(receipt_sha256) = 66),
  finality_json TEXT NOT NULL CHECK (length(finality_json) BETWEEN 1 AND 16384 AND json_valid(finality_json)),
  finality_sha256 TEXT NOT NULL CHECK (length(finality_sha256) = 66),
  recorded_at INTEGER NOT NULL CHECK (recorded_at > 0)
) STRICT;
CREATE TABLE money_expirations (
  operation_id TEXT PRIMARY KEY REFERENCES money_operations(id) ON DELETE RESTRICT,
  checkpoint_json TEXT NOT NULL CHECK (length(checkpoint_json) BETWEEN 1 AND 16384 AND json_valid(checkpoint_json)),
  checkpoint_sha256 TEXT NOT NULL CHECK (length(checkpoint_sha256) = 66),
  block_timestamp INTEGER NOT NULL CHECK (block_timestamp > 0),
  observed_nonce TEXT NOT NULL CHECK (length(observed_nonce) BETWEEN 1 AND 20 AND observed_nonce NOT GLOB '*[^0-9]*'),
  recorded_at INTEGER NOT NULL CHECK (recorded_at > 0)
) STRICT;

CREATE TRIGGER money_preparation_immutable BEFORE UPDATE ON money_preparations
BEGIN SELECT RAISE(ABORT, 'immutable money preparation'); END;
CREATE TRIGGER money_operation_identity BEFORE UPDATE ON money_operations
WHEN NEW.id IS NOT OLD.id OR NEW.preparation_id IS NOT OLD.preparation_id OR NEW.wallet_id IS NOT OLD.wallet_id
  OR NEW.wallet_account_id IS NOT OLD.wallet_account_id OR NEW.actor_id IS NOT OLD.actor_id OR NEW.confirm_key IS NOT OLD.confirm_key
  OR NEW.confirmation_sha256 IS NOT OLD.confirmation_sha256 OR NEW.network_id IS NOT OLD.network_id
  OR NEW.account_address IS NOT OLD.account_address OR NEW.entry_point IS NOT OLD.entry_point OR NEW.nonce IS NOT OLD.nonce
  OR NEW.consent_digest IS NOT OLD.consent_digest OR NEW.userop_hash IS NOT OLD.userop_hash
  OR NEW.deployment_manifest_sha256 IS NOT OLD.deployment_manifest_sha256 OR NEW.market_sha256 IS NOT OLD.market_sha256
  OR NEW.review_json IS NOT OLD.review_json OR NEW.review_sha256 IS NOT OLD.review_sha256
  OR NEW.funds_json IS NOT OLD.funds_json OR NEW.funds_sha256 IS NOT OLD.funds_sha256
  OR NEW.authorized_auth_time IS NOT OLD.authorized_auth_time OR NEW.created_at IS NOT OLD.created_at OR NEW.expires_at IS NOT OLD.expires_at
  OR (OLD.dispatch_started_at IS NOT NULL AND NEW.dispatch_started_at IS NOT OLD.dispatch_started_at)
BEGIN SELECT RAISE(ABORT, 'immutable money authorization'); END;
CREATE TRIGGER money_operation_transition BEFORE UPDATE OF state ON money_operations
WHEN NEW.state != OLD.state AND NOT (
  (OLD.state = 'authorized' AND NEW.state IN ('dispatch_pending','expired_unsubmitted'))
  OR (OLD.state = 'dispatch_pending' AND NEW.state IN ('submitted','confirming','review_required','reconciled','reverted_confirmed'))
  OR (OLD.state IN ('submitted','confirming','review_required') AND NEW.state IN ('confirming','review_required','reconciled','reverted_confirmed')))
BEGIN SELECT RAISE(ABORT, 'invalid money transition'); END;
CREATE TRIGGER money_expiry_no_dispatch BEFORE UPDATE OF state ON money_operations
WHEN NEW.state = 'expired_unsubmitted' AND (OLD.state != 'authorized' OR OLD.dispatch_started_at IS NOT NULL
  OR EXISTS (SELECT 1 FROM user_operation_submissions s WHERE s.user_op_hash = OLD.userop_hash)
  OR NOT EXISTS (SELECT 1 FROM money_expirations e WHERE e.operation_id = OLD.id
    AND e.block_timestamp > OLD.expires_at AND e.observed_nonce = OLD.nonce))
BEGIN SELECT RAISE(ABORT, 'uncertain money dispatch cannot expire'); END;
CREATE TRIGGER money_expiration_immutable BEFORE UPDATE ON money_expirations
BEGIN SELECT RAISE(ABORT, 'immutable money expiry evidence'); END;
CREATE TRIGGER money_finality_immutable BEFORE UPDATE ON money_finality_journal
BEGIN SELECT RAISE(ABORT, 'immutable money finality'); END;
CREATE TRIGGER money_finality_conflict_immutable BEFORE UPDATE ON money_finality_conflicts
BEGIN SELECT RAISE(ABORT, 'immutable money finality conflict'); END;
CREATE TRIGGER money_reconciliation_immutable BEFORE UPDATE ON money_reconciliations
BEGIN SELECT RAISE(ABORT, 'immutable money reconciliation'); END;
CREATE TRIGGER money_reconciled_evidence BEFORE UPDATE OF state ON money_operations
WHEN NEW.state IN ('reconciled','reverted_confirmed') AND NOT EXISTS (SELECT 1 FROM money_reconciliations r
  WHERE r.operation_id = NEW.id AND r.wallet_account_id = NEW.wallet_account_id AND r.outcome = NEW.state)
BEGIN SELECT RAISE(ABORT, 'money reconciliation required'); END;

-- BEFORE guards close races even if a future adapter forgets its conditional SQL.
CREATE TRIGGER transfer_spend_exclusion BEFORE INSERT ON transfer_nonce_reservations
WHEN NEW.state IN ('held','delivery_pending')
  AND NOT EXISTS (SELECT 1 FROM transfer_nonce_reservations r WHERE r.wallet_account_id = NEW.wallet_account_id AND r.consent_digest = NEW.consent_digest)
  AND EXISTS (SELECT 1 FROM wallet_spend_locks l WHERE l.wallet_account_id = NEW.wallet_account_id AND l.released_at IS NULL)
BEGIN SELECT RAISE(ABORT, 'ACCOUNT_SPEND_BUSY'); END;
CREATE TRIGGER transfer_spend_acquire AFTER INSERT ON transfer_nonce_reservations WHEN NEW.state IN ('held','delivery_pending')
BEGIN
  INSERT INTO wallet_spend_locks(operation_id,wallet_account_id,network_id,account_address,entry_point,nonce,consent_digest,domain,state,created_at)
  VALUES (NEW.id,NEW.wallet_account_id,NEW.network_id,NEW.account_address,NEW.entry_point,NEW.nonce,NEW.consent_digest,'transfer',
    (CASE WHEN NEW.state = 'held' THEN 'held' ELSE 'dispatch_pending' END),NEW.created_at);
END;
CREATE TRIGGER transfer_spend_dispatch AFTER UPDATE OF state ON transfer_nonce_reservations
WHEN OLD.state = 'held' AND NEW.state = 'delivery_pending'
BEGIN UPDATE wallet_spend_locks SET state = (CASE WHEN state = 'legacy_drain' THEN state ELSE 'dispatch_pending' END)
  WHERE operation_id = NEW.id AND domain = 'transfer' AND released_at IS NULL; END;
CREATE TRIGGER transfer_spend_release AFTER UPDATE OF state ON transfer_nonce_reservations
WHEN NEW.state IN ('expired','reconciled') AND OLD.state != NEW.state
BEGIN UPDATE wallet_spend_locks SET state = 'released',released_at = max(unixepoch(),created_at),
  release_reason = (CASE WHEN NEW.state = 'expired' THEN 'expired_unsubmitted' ELSE 'reconciled' END)
  WHERE operation_id = NEW.id AND domain = 'transfer' AND released_at IS NULL; END;

CREATE TRIGGER money_spend_exclusion BEFORE INSERT ON money_operations
WHEN NOT EXISTS (SELECT 1 FROM money_operations r WHERE r.wallet_account_id = NEW.wallet_account_id AND r.consent_digest = NEW.consent_digest)
  AND EXISTS (SELECT 1 FROM wallet_spend_locks l WHERE l.wallet_account_id = NEW.wallet_account_id AND l.released_at IS NULL)
BEGIN SELECT RAISE(ABORT, 'ACCOUNT_SPEND_BUSY'); END;
CREATE TRIGGER money_spend_acquire AFTER INSERT ON money_operations
BEGIN
  SELECT (CASE WHEN NEW.state != 'authorized' OR NEW.dispatch_started_at IS NOT NULL THEN RAISE(ABORT,'money starts authorized') END);
  INSERT INTO wallet_spend_locks(operation_id,wallet_account_id,network_id,account_address,entry_point,nonce,consent_digest,domain,state,created_at)
  VALUES (NEW.id,NEW.wallet_account_id,NEW.network_id,NEW.account_address,NEW.entry_point,NEW.nonce,NEW.consent_digest,'money','held',NEW.created_at);
END;
CREATE TRIGGER money_spend_dispatch AFTER UPDATE OF state ON money_operations WHEN OLD.state = 'authorized' AND NEW.state = 'dispatch_pending'
BEGIN
  UPDATE wallet_spend_locks SET state = 'dispatch_pending' WHERE operation_id = NEW.id AND domain = 'money' AND state = 'held';
  INSERT INTO money_jobs(operation_id,state,next_attempt_at) VALUES (NEW.id,'ready',unixepoch());
END;
CREATE TRIGGER money_spend_release AFTER UPDATE OF state ON money_operations
WHEN NEW.state IN ('expired_unsubmitted','reconciled','reverted_confirmed') AND OLD.state != NEW.state
BEGIN
  UPDATE wallet_spend_locks SET state = 'released',released_at = max(unixepoch(),created_at),release_reason = NEW.state
    WHERE operation_id = NEW.id AND domain = 'money' AND released_at IS NULL;
  UPDATE money_jobs SET state = 'reconciled',lease_token = NULL,lease_expires_at = NULL,reason = NULL WHERE operation_id = NEW.id;
END;
CREATE TRIGGER money_job_attention AFTER UPDATE OF state ON money_jobs
WHEN NEW.state = 'review' AND OLD.state != 'review'
BEGIN
  UPDATE money_operations SET state = 'review_required' WHERE id = NEW.operation_id
    AND state IN ('dispatch_pending','submitted','confirming');
END;
CREATE TRIGGER money_reconciliation_commit AFTER INSERT ON money_reconciliations
BEGIN
  SELECT (CASE WHEN NOT EXISTS (SELECT 1 FROM money_operations o JOIN money_finality_journal j ON j.operation_id = o.id
    WHERE o.id = NEW.operation_id AND o.wallet_account_id = NEW.wallet_account_id
      AND o.state IN ('dispatch_pending','submitted','confirming','review_required') AND j.receipt_sha256 = NEW.receipt_sha256
      AND j.block_number = NEW.block_number AND j.block_hash = NEW.block_hash AND j.outcome = NEW.outcome
      AND NOT EXISTS (SELECT 1 FROM money_finality_conflicts f WHERE f.operation_id = o.id))
    THEN RAISE(ABORT,'money reconciliation conflict') END);
  INSERT INTO wallet_balance_floors(wallet_account_id,block_number,block_hash,recorded_at)
  VALUES (NEW.wallet_account_id,NEW.block_number,NEW.block_hash,NEW.recorded_at)
  ON CONFLICT(wallet_account_id) DO UPDATE SET block_number = excluded.block_number,block_hash = excluded.block_hash,recorded_at = excluded.recorded_at;
  UPDATE money_operations SET state = NEW.outcome WHERE id = NEW.operation_id;
END;

CREATE TRIGGER wallet_spend_identity BEFORE UPDATE ON wallet_spend_locks
WHEN NEW.operation_id IS NOT OLD.operation_id OR NEW.wallet_account_id IS NOT OLD.wallet_account_id
  OR NEW.network_id IS NOT OLD.network_id OR NEW.account_address IS NOT OLD.account_address
  OR NEW.entry_point IS NOT OLD.entry_point OR NEW.nonce IS NOT OLD.nonce OR NEW.consent_digest IS NOT OLD.consent_digest
  OR NEW.domain IS NOT OLD.domain OR NEW.created_at IS NOT OLD.created_at OR OLD.released_at IS NOT NULL
BEGIN SELECT RAISE(ABORT,'immutable spend lock identity/history'); END;
CREATE TRIGGER wallet_spend_release_evidence BEFORE UPDATE OF state ON wallet_spend_locks
WHEN NEW.state = 'released' AND NOT (
  (OLD.domain = 'transfer' AND EXISTS (SELECT 1 FROM transfer_nonce_reservations r WHERE r.id = OLD.operation_id AND r.state IN ('expired','reconciled')))
  OR (OLD.domain = 'money' AND EXISTS (SELECT 1 FROM money_operations r WHERE r.id = OLD.operation_id AND r.state IN ('expired_unsubmitted','reconciled','reverted_confirmed'))))
BEGIN SELECT RAISE(ABORT,'spend lock release requires domain evidence'); END;
CREATE TRIGGER transfer_spend_dispatch_requires_lock BEFORE UPDATE OF state ON transfer_nonce_reservations
WHEN OLD.state = 'held' AND NEW.state = 'delivery_pending' AND NOT EXISTS (SELECT 1 FROM wallet_spend_locks l
  WHERE l.operation_id = NEW.id AND l.domain = 'transfer' AND l.wallet_account_id = NEW.wallet_account_id
    AND l.state IN ('held','legacy_drain') AND l.released_at IS NULL AND l.consent_digest = NEW.consent_digest)
BEGIN SELECT RAISE(ABORT,'transfer spend lock missing'); END;
CREATE TRIGGER money_spend_dispatch_requires_lock BEFORE UPDATE OF state ON money_operations
WHEN OLD.state = 'authorized' AND NEW.state = 'dispatch_pending' AND NOT EXISTS (SELECT 1 FROM wallet_spend_locks l
  WHERE l.operation_id = NEW.id AND l.domain = 'money' AND l.wallet_account_id = NEW.wallet_account_id
    AND l.state = 'held' AND l.released_at IS NULL AND l.consent_digest = NEW.consent_digest)
BEGIN SELECT RAISE(ABORT,'money spend lock missing'); END;
