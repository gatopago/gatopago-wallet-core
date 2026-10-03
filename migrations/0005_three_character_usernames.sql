-- Apply as one atomic D1 migration. Existing users, credentials, wallets,
-- invitations and challenges are preserved. Applied migrations stay unchanged.
PRAGMA defer_foreign_keys = ON;

-- Rebuilding a parent must not fire CASCADE/SET NULL on its children. All
-- current references are RESTRICT; stop if a future schema changes that.
CREATE TABLE _username_migration_guard (
  violations INTEGER NOT NULL CHECK (violations = 0)
) STRICT;
INSERT INTO _username_migration_guard
SELECT
  (SELECT COUNT(*) FROM pragma_foreign_key_list('wallets') WHERE "table" = 'users' AND on_delete <> 'RESTRICT')
  + (SELECT COUNT(*) FROM pragma_foreign_key_list('webauthn_enrollments') WHERE "table" = 'users' AND on_delete <> 'RESTRICT')
  + (SELECT COUNT(*) FROM pragma_foreign_key_list('webauthn_credentials') WHERE "table" = 'users' AND on_delete <> 'RESTRICT')
  + (SELECT COUNT(*) FROM pragma_foreign_key_list('signup_invites') WHERE "table" = 'users' AND on_delete <> 'RESTRICT')
  + (SELECT COUNT(*) FROM pragma_foreign_key_list('account_initializations') WHERE "table" = 'users' AND on_delete <> 'RESTRICT')
  + (SELECT COUNT(*) FROM pragma_foreign_key_list('sponsorship_reservations') WHERE "table" = 'users' AND on_delete <> 'RESTRICT')
  + (SELECT COUNT(*) FROM pragma_foreign_key_list('account_backups') WHERE "table" = 'users' AND on_delete <> 'RESTRICT')
  + (SELECT COUNT(*) FROM pragma_foreign_key_list('money_preparations') WHERE "table" = 'users' AND on_delete <> 'RESTRICT')
  + (SELECT COUNT(*) FROM pragma_foreign_key_list('money_operations') WHERE "table" = 'users' AND on_delete <> 'RESTRICT');
-- D1 authorizes constant PRAGMA table arguments, not dynamic schema iteration.
-- Fail closed if an unknown table mentions this parent: review its references
-- explicitly before extending the migration's known-child list.
INSERT INTO _username_migration_guard
SELECT COUNT(*) FROM sqlite_schema
WHERE type = 'table' AND lower(sql) LIKE '%users%'
  AND name NOT IN ('users', 'wallets', 'webauthn_enrollments',
    'webauthn_credentials', 'signup_invites', 'account_initializations',
    'sponsorship_reservations', 'account_backups',
    'money_preparations', 'money_operations');

CREATE TABLE _users_three_character (
  id TEXT PRIMARY KEY CHECK (length(id) = 40 AND id GLOB 'usr_*'),
  environment TEXT NOT NULL CHECK (environment = 'production'),
  display_name TEXT NOT NULL DEFAULT '' CHECK (length(display_name) <= 80),
  username TEXT UNIQUE CHECK (username IS NULL OR (
    length(username) BETWEEN 3 AND 30 AND substr(username,1,1) GLOB '[a-z]'
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

INSERT INTO _users_three_character SELECT * FROM users;
DROP TABLE users;
ALTER TABLE _users_three_character RENAME TO users;

CREATE INDEX users_username_reservation ON users(username_reserved_until) WHERE username_reserved_until IS NOT NULL;
CREATE TRIGGER users_production_namespace_insert
BEFORE INSERT ON users WHEN NEW.environment <> 'production'
BEGIN
  SELECT RAISE(ABORT, 'Only production identities are supported');
END;
CREATE TRIGGER users_production_namespace_update
BEFORE UPDATE OF environment ON users WHEN NEW.environment <> 'production'
BEGIN
  SELECT RAISE(ABORT, 'Only production identities are supported');
END;

CREATE TABLE _auth_challenges_three_character (
  id TEXT PRIMARY KEY CHECK (length(id) = 39 AND id GLOB 'op_*'),
  purpose TEXT NOT NULL CHECK (purpose IN ('register','login')),
  challenge TEXT NOT NULL UNIQUE CHECK (length(challenge) = 66),
  proof_challenge TEXT UNIQUE,
  rp_id TEXT NOT NULL,
  origin TEXT NOT NULL,
  proposed_user_id TEXT UNIQUE,
  invite_code TEXT REFERENCES signup_invites(code) ON DELETE RESTRICT,
  display_name TEXT,
  username TEXT,
  created_at INTEGER NOT NULL CHECK (created_at > 0),
  expires_at INTEGER NOT NULL CHECK (expires_at = created_at + 300),
  consumed_at INTEGER CHECK (consumed_at IS NULL OR (consumed_at >= created_at AND consumed_at < expires_at)),
  CHECK ((purpose = 'login' AND proof_challenge IS NULL AND proposed_user_id IS NULL
    AND invite_code IS NULL AND display_name IS NULL AND username IS NULL)
    OR (purpose = 'register' AND proof_challenge IS NOT NULL AND proposed_user_id IS NOT NULL
      AND invite_code IS NOT NULL AND length(display_name) BETWEEN 1 AND 80
      AND username IS NOT NULL AND length(username) BETWEEN 3 AND 30
      AND length(proof_challenge) = 66 AND length(proposed_user_id) = 40))
) STRICT;
INSERT INTO _auth_challenges_three_character SELECT * FROM auth_challenges;
DROP TABLE auth_challenges;
ALTER TABLE _auth_challenges_three_character RENAME TO auth_challenges;
CREATE INDEX auth_challenges_expiry ON auth_challenges(expires_at);
CREATE INDEX auth_challenges_invite ON auth_challenges(invite_code) WHERE invite_code IS NOT NULL;

-- Check actual references before ending deferral (not just SQLite's deferred
-- counter, which can retain references to the replaced parent table).
INSERT INTO _username_migration_guard SELECT COUNT(*) FROM pragma_foreign_key_check;
DROP TABLE _username_migration_guard;
PRAGMA defer_foreign_keys = OFF;
